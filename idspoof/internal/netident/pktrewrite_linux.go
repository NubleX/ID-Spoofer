//go:build linux

// pktrewrite_linux.go — NFQUEUE-based packet rewriter for deep OS fingerprint
// evasion. Intercepts outgoing SYN packets and rewrites:
//
//   1. IP ID field: Linux sets it to 0 when DF is set. Windows uses an
//      incrementing non-zero counter. p0f checks this (quirk "id+").
//
//   2. TCP options ordering: Linux sends MSS,SACK,TS,NOP,WScale.
//      Windows sends MSS,NOP,WScale,NOP,NOP,SACKPermitted.
//      With timestamps disabled, the correct Windows order is:
//        02 04 05 b4   MSS=1460
//        01            NOP
//        03 03 08      WScale=8
//        01            NOP
//        01            NOP
//        04 02         SACK Permitted
//
// We use raw iptables NFQUEUE and process packets in pure Go using
// encoding/binary to rewrite headers. No CGo dependencies.

package netident

import (
	"encoding/binary"
	"fmt"
	"os/exec"
	"sync/atomic"
)

const nfqueueNum = 42 // Queue number for our NFQUEUE rule.

// ipIDCounter is our incrementing IP ID to mimic Windows behaviour.
var ipIDCounter atomic.Uint32

func init() {
	// Seed with a non-zero value.
	ipIDCounter.Store(0x1000)
}

// nextIPID returns the next incrementing IP ID value (16-bit wrapping).
func nextIPID() uint16 {
	return uint16(ipIDCounter.Add(1))
}

// windowsTCPOptions builds the exact TCP options bytes Windows 10/11 sends
// on a SYN packet (no timestamps).
func windowsTCPOptions(mss uint16, wscale uint8) []byte {
	return []byte{
		// MSS (Kind=2, Length=4, Value=mss)
		0x02, 0x04, byte(mss >> 8), byte(mss),
		// NOP (Kind=1)
		0x01,
		// Window Scale (Kind=3, Length=3, Value=wscale)
		0x03, 0x03, wscale,
		// NOP, NOP
		0x01, 0x01,
		// SACK Permitted (Kind=4, Length=2)
		0x04, 0x02,
	}
}

// rewriteSYNPacket takes a raw IP packet (SYN), rewrites:
//   - IP ID → incrementing non-zero
//   - TCP options → Windows order
// Returns the modified packet bytes with recalculated checksums.
func rewriteSYNPacket(pkt []byte) ([]byte, error) {
	if len(pkt) < 20 {
		return pkt, nil // too short for IP header
	}

	// Parse IP header.
	version := (pkt[0] >> 4) & 0xF
	if version != 4 {
		return pkt, nil // only handle IPv4
	}
	ihl := int(pkt[0]&0xF) * 4
	if ihl < 20 || len(pkt) < ihl {
		return pkt, nil
	}
	protocol := pkt[9]
	if protocol != 6 { // TCP
		return pkt, nil
	}

	// Rewrite IP ID to non-zero incrementing value.
	newID := nextIPID()
	binary.BigEndian.PutUint16(pkt[4:6], newID)

	// Parse TCP header.
	if len(pkt) < ihl+20 {
		return pkt, nil
	}
	tcpStart := ihl
	tcpFlags := pkt[tcpStart+13]
	synFlag := tcpFlags & 0x02
	if synFlag == 0 {
		// Not a SYN packet — only rewrite IP ID, leave TCP options alone.
		recalcIPChecksum(pkt, ihl)
		return pkt, nil
	}

	tcpDataOff := int(pkt[tcpStart+12]>>4) * 4
	if tcpDataOff < 20 {
		recalcIPChecksum(pkt, ihl)
		return pkt, nil
	}

	// Build new TCP options in Windows order.
	newOpts := windowsTCPOptions(1460, 8)

	// Pad to 4-byte boundary.
	for len(newOpts)%4 != 0 {
		newOpts = append(newOpts, 0x00) // End-of-options
	}

	// Reconstruct the packet: IP header + TCP fixed header (20 bytes) + new options + payload.
	tcpFixed := pkt[tcpStart : tcpStart+20]
	var payload []byte
	if tcpStart+tcpDataOff < len(pkt) {
		payload = pkt[tcpStart+tcpDataOff:]
	}

	newTCPDataOff := byte((20 + len(newOpts)) / 4)
	newTCP := make([]byte, 0, 20+len(newOpts)+len(payload))
	newTCP = append(newTCP, tcpFixed...)
	newTCP = append(newTCP, newOpts...)
	newTCP = append(newTCP, payload...)

	// Update TCP data offset field.
	newTCP[12] = (newTCPDataOff << 4) | (newTCP[12] & 0x0F)

	// Rebuild full packet.
	result := make([]byte, 0, ihl+len(newTCP))
	result = append(result, pkt[:ihl]...)
	result = append(result, newTCP...)

	// Update IP total length.
	binary.BigEndian.PutUint16(result[2:4], uint16(len(result)))

	// Recalculate checksums.
	recalcIPChecksum(result, ihl)
	recalcTCPChecksum(result, ihl)

	return result, nil
}

// recalcIPChecksum zeroes the IP checksum field and recalculates it.
func recalcIPChecksum(pkt []byte, ihl int) {
	pkt[10] = 0
	pkt[11] = 0
	var sum uint32
	for i := 0; i < ihl; i += 2 {
		sum += uint32(binary.BigEndian.Uint16(pkt[i : i+2]))
	}
	for sum > 0xFFFF {
		sum = (sum & 0xFFFF) + (sum >> 16)
	}
	binary.BigEndian.PutUint16(pkt[10:12], ^uint16(sum))
}

// recalcTCPChecksum recalculates the TCP checksum using the pseudo-header.
func recalcTCPChecksum(pkt []byte, ihl int) {
	tcpStart := ihl
	tcpLen := len(pkt) - ihl

	// Zero existing checksum.
	pkt[tcpStart+16] = 0
	pkt[tcpStart+17] = 0

	// Pseudo-header: src IP + dst IP + zero + protocol + TCP length.
	var sum uint32
	sum += uint32(binary.BigEndian.Uint16(pkt[12:14])) // src IP high
	sum += uint32(binary.BigEndian.Uint16(pkt[14:16])) // src IP low
	sum += uint32(binary.BigEndian.Uint16(pkt[16:18])) // dst IP high
	sum += uint32(binary.BigEndian.Uint16(pkt[18:20])) // dst IP low
	sum += uint32(6)                                    // protocol TCP
	sum += uint32(tcpLen)                               // TCP length

	// TCP data.
	for i := tcpStart; i < len(pkt)-1; i += 2 {
		sum += uint32(binary.BigEndian.Uint16(pkt[i : i+2]))
	}
	if tcpLen%2 != 0 {
		sum += uint32(pkt[len(pkt)-1]) << 8
	}

	for sum > 0xFFFF {
		sum = (sum & 0xFFFF) + (sum >> 16)
	}
	binary.BigEndian.PutUint16(pkt[tcpStart+16:tcpStart+18], ^uint16(sum))
}

// installNFQueueRule adds an iptables rule to send outgoing SYN packets
// through our NFQUEUE for rewriting.
func installNFQueueRule() error {
	// Only intercept SYN packets (not SYN+ACK or others) on OUTPUT.
	return run("iptables", "-t", "mangle", "-A", chainName,
		"-p", "tcp", "--tcp-flags", "SYN,ACK,RST", "SYN",
		"-j", "NFQUEUE", "--queue-num", fmt.Sprintf("%d", nfqueueNum))
}

// removeNFQueueRule removes the NFQUEUE rule (handled by removeIPTables which
// flushes the whole chain, but this is available for targeted removal).
func removeNFQueueRule() {
	exec.Command("iptables", "-t", "mangle", "-D", chainName,
		"-p", "tcp", "--tcp-flags", "SYN,ACK,RST", "SYN",
		"-j", "NFQUEUE", "--queue-num", fmt.Sprintf("%d", nfqueueNum)).Run()
}
