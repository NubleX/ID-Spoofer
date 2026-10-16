//go:build linux

// nfqueue_linux.go — Pure Go NFQUEUE listener using netlink sockets.
// No CGo, no external libraries. Speaks NFNETLINK_QUEUE protocol directly.
//
// We intercept SYN packets, rewrite IP ID + TCP options to match Windows,
// then set the verdict to NF_ACCEPT with the modified packet.

package netident

import (
	"context"
	"encoding/binary"
	"fmt"
	"os"
	"sync"
	"syscall"
	"time"
	"unsafe"
)

// SOL_NETLINK socket options.
const (
	solNetlink         = 270
	netlinkNoENOBUFS   = 5
	netlinkRcvbufForce = 33
)

// NFNETLINK constants (from linux/netfilter/nfnetlink.h).
const (
	nfnlSubsysQueue   = 3
	nfqnlMsgPacket    = 0
	nfqnlMsgVerdict   = 1
	nfqnlMsgConfig    = 2
	nfqnlCfgCmdBind   = 1
	nfqnlCfgCmdUnbind = 2
	nfqnlCopyPacket   = 2

	// Attribute types from nfqnl_attr_type (kernel UAPI).
	nfqaPacketHdr  = 1  // NFQA_PACKET_HDR
	nfqaVerdictHdr = 2  // NFQA_VERDICT_HDR
	nfqaPayload    = 10 // NFQA_PAYLOAD
	nfqaCfgCmd     = 1  // NFQA_CFG_CMD (config messages)
	nfqaCfgParams  = 2  // NFQA_CFG_PARAMS

	// Verdicts.
	nfAccept = 1
	nfDrop   = 0

	// Netlink.
	nfnlMsgType = 0x100 * nfnlSubsysQueue
)

// NFQueueRewriter listens on an NFQUEUE and rewrites SYN packets.
type NFQueueRewriter struct {
	queueNum uint16
	fd       int
	mu       sync.Mutex
	running  bool
	cancel   context.CancelFunc
}

// NewNFQueueRewriter creates a rewriter for the given queue number.
func NewNFQueueRewriter(queueNum uint16) *NFQueueRewriter {
	return &NFQueueRewriter{queueNum: queueNum}
}

// Start begins listening on the NFQUEUE in a background goroutine.
func (r *NFQueueRewriter) Start() error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.running {
		return nil
	}

	fd, err := syscall.Socket(syscall.AF_NETLINK, syscall.SOCK_RAW, 12) // NETLINK_NETFILTER = 12
	if err != nil {
		return fmt.Errorf("creating netlink socket: %w", err)
	}
	r.fd = fd

	// Bind the netlink port and join the queue's multicast group.
	// The kernel unicasts NFQUEUE packet messages to the socket that
	// bound the queue; the group join is harmless insurance for
	// kernels that multicast instead.
	sa := &syscall.SockaddrNetlink{Family: syscall.AF_NETLINK, Groups: 1 << nfnlSubsysQueue}
	if err := syscall.Bind(fd, sa); err != nil {
		syscall.Close(fd)
		return fmt.Errorf("binding netlink socket: %w", err)
	}

	// Tell the kernel to silently drop packets instead of returning ENOBUFS
	// when our userspace can't keep up. Without this, recvfrom returns
	// ENOBUFS in a tight loop and pins a CPU at 100%.
	one := 1
	syscall.SetsockoptInt(fd, solNetlink, netlinkNoENOBUFS, one)

	// Bump the netlink receive buffer well above the default so brief bursts
	// of SYN traffic don't immediately overflow.
	syscall.SetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_RCVBUF, 4*1024*1024)

	// Send config: bind to queue.
	if err := r.sendConfig(nfqnlCfgCmdBind); err != nil {
		syscall.Close(fd)
		return fmt.Errorf("binding to queue %d: %w", r.queueNum, err)
	}

	// Set copy mode to COPY_PACKET with max size.
	if err := r.setCopyMode(nfqnlCopyPacket, 0xFFFF); err != nil {
		syscall.Close(fd)
		return fmt.Errorf("setting copy mode: %w", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	r.cancel = cancel
	r.running = true

	go r.loop(ctx)
	return nil
}

// Stop shuts down the NFQUEUE listener.
func (r *NFQueueRewriter) Stop() {
	r.mu.Lock()
	defer r.mu.Unlock()

	if !r.running {
		return
	}
	r.running = false
	if r.cancel != nil {
		r.cancel()
	}
	r.sendConfig(nfqnlCfgCmdUnbind)
	syscall.Close(r.fd)
}

func (r *NFQueueRewriter) loop(ctx context.Context) {
	buf := make([]byte, 65536)
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		n, _, err := syscall.Recvfrom(r.fd, buf, 0)
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			// EINTR is fine, retry immediately. Anything else: back off so a
			// persistently-erroring socket can't pin the CPU.
			if err == syscall.EINTR {
				continue
			}
			time.Sleep(10 * time.Millisecond)
			continue
		}
		if n < 16 {
			continue
		}
		// Kernel error replies (e.g. a rejected verdict) arrive as
		// NLMSG_ERROR; log them so rewriter.log is diagnosable.
		if n >= 20 && binary.LittleEndian.Uint16(buf[4:6]) == 2 {
			if errno := int32(binary.LittleEndian.Uint32(buf[16:20])); errno != 0 {
				detail := ""
				if n >= 26 {
					// NLMSG_ERROR embeds the offending request; its
					// nlmsghdr.type tells us which of our messages failed.
					detail = fmt.Sprintf(" (rejecting msgtype %d)",
						binary.LittleEndian.Uint16(buf[24:26]))
				}
				fmt.Fprintf(os.Stderr, "nfqueue: kernel error %d%s\n", -errno, detail)
			}
			continue
		}

		r.handleMessage(buf[:n])
	}
}

func (r *NFQueueRewriter) handleMessage(data []byte) {
	// Parse netlink message header.
	if len(data) < 16 {
		return
	}

	// Skip netlink header (16 bytes) + nfgen header (4 bytes).
	if len(data) < 20 {
		return
	}

	// Extract packet ID and payload from netlink attributes.
	var packetID uint32
	var payload []byte

	pos := 20 // After nlmsghdr (16) + nfgenmsg (4)
	for pos+4 <= len(data) {
		attrLen := int(binary.LittleEndian.Uint16(data[pos : pos+2]))
		attrType := binary.LittleEndian.Uint16(data[pos+2 : pos+4])

		if attrLen < 4 {
			break
		}

		attrData := data[pos+4:]
		if attrLen-4 > len(attrData) {
			break
		}
		attrData = attrData[:attrLen-4]

		switch attrType {
		case nfqaPacketHdr:
			if len(attrData) >= 7 {
				packetID = binary.BigEndian.Uint32(attrData[0:4])
			}
		case nfqaPayload:
			payload = make([]byte, len(attrData))
			copy(payload, attrData)
		}

		// Align to 4 bytes.
		pos += (attrLen + 3) &^ 3
	}

	// Rewrite the packet.
	var modified []byte
	if payload != nil {
		rewritten, err := rewriteSYNPacket(payload)
		if err == nil {
			modified = rewritten
		} else {
			modified = payload
		}
	}

	// Send verdict NF_ACCEPT with (potentially modified) packet.
	r.sendVerdict(packetID, nfAccept, modified)
}

func (r *NFQueueRewriter) sendVerdict(packetID uint32, verdict int, pkt []byte) {
	// Build verdict message.
	// NFQA_VERDICT_HDR is struct nfqnl_msg_verdict_hdr:
	//   verdict (4, big-endian) + id (4, big-endian). The modified
	// packet travels in a separate NFQA_PAYLOAD attribute.
	verdictHdr := make([]byte, 8)
	binary.BigEndian.PutUint32(verdictHdr[0:4], uint32(verdict))
	binary.BigEndian.PutUint32(verdictHdr[4:8], packetID)

	// NLA: verdict header attr.
	verdictAttr := nlattr(nfqaVerdictHdr, verdictHdr)

	// NLA: modified payload if any.
	var payloadAttr []byte
	if pkt != nil {
		payloadAttr = nlattr(nfqaPayload, pkt)
	}

	payload := append(verdictAttr, payloadAttr...)

	msgType := uint16(nfnlMsgType + nfqnlMsgVerdict)
	r.sendNL(msgType, payload)
}

func (r *NFQueueRewriter) sendConfig(cmd uint8) error {
	// NFQA_CFG_CMD is struct nfqnl_msg_config_cmd:
	//   command (1) + pad (1) + pf (2, big-endian). The queue number is
	// NOT carried here — the kernel takes it from nfgenmsg.res_id,
	// which sendNL sets.
	cmdData := make([]byte, 4)
	cmdData[0] = cmd
	cmdData[1] = 0
	binary.BigEndian.PutUint16(cmdData[2:4], uint16(syscall.AF_INET))

	attr := nlattr(nfqaCfgCmd, cmdData)
	msgType := uint16(nfnlMsgType + nfqnlMsgConfig)
	return r.sendNL(msgType, attr)
}

func (r *NFQueueRewriter) setCopyMode(mode uint8, size uint32) error {
	// NFQA_CFG_PARAMS is struct nfqnl_msg_config_params (packed):
	//   copy_range (4, big-endian) + copy_mode (1).
	params := make([]byte, 5)
	binary.BigEndian.PutUint32(params[0:4], size)
	params[4] = mode

	attr := nlattr(nfqaCfgParams, params)
	msgType := uint16(nfnlMsgType + nfqnlMsgConfig)
	return r.sendNL(msgType, attr)
}

func (r *NFQueueRewriter) sendNL(msgType uint16, payload []byte) error {
	// nfgenmsg: family (1) + version (1) + res_id/queue_num (2).
	nfgen := make([]byte, 4)
	nfgen[0] = syscall.AF_INET
	nfgen[1] = 0 // NFNETLINK_V0
	binary.BigEndian.PutUint16(nfgen[2:4], r.queueNum)

	data := append(nfgen, payload...)

	// Netlink header.
	msgLen := 16 + len(data)
	nlh := make([]byte, 16)
	binary.LittleEndian.PutUint32(nlh[0:4], uint32(msgLen))
	binary.LittleEndian.PutUint16(nlh[4:6], msgType)
	binary.LittleEndian.PutUint16(nlh[6:8], syscall.NLM_F_REQUEST)
	binary.LittleEndian.PutUint32(nlh[8:12], 0)  // seq
	binary.LittleEndian.PutUint32(nlh[12:16], 0) // pid

	msg := append(nlh, data...)

	sa := &syscall.SockaddrNetlink{Family: syscall.AF_NETLINK}
	return syscall.Sendto(r.fd, msg, 0, sa)
}

// nlattr builds a Netlink attribute (NLA).
func nlattr(typ uint16, data []byte) []byte {
	attrLen := 4 + len(data)
	padded := (attrLen + 3) &^ 3
	buf := make([]byte, padded)
	binary.LittleEndian.PutUint16(buf[0:2], uint16(attrLen))
	binary.LittleEndian.PutUint16(buf[2:4], typ)
	copy(buf[4:], data)
	return buf
}

// Ensure the NFQueueRewriter doesn't trigger unsafe.Pointer warnings.
var _ = unsafe.Sizeof(0)
