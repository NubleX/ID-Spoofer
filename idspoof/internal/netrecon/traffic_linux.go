//go:build linux

package netrecon

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

// readTraffic reads /proc/net/dev for per-interface byte/packet counters.
func readTraffic() (*TrafficSnapshot, error) {
	f, err := os.Open("/proc/net/dev")
	if err != nil {
		return nil, fmt.Errorf("open /proc/net/dev: %w", err)
	}
	defer f.Close()

	snap := &TrafficSnapshot{Timestamp: time.Now()}
	scanner := bufio.NewScanner(f)
	lineNo := 0
	for scanner.Scan() {
		lineNo++
		if lineNo <= 2 {
			continue // skip headers
		}
		line := scanner.Text()
		colonIdx := strings.Index(line, ":")
		if colonIdx < 0 {
			continue
		}
		name := strings.TrimSpace(line[:colonIdx])
		rest := strings.Fields(line[colonIdx+1:])
		if len(rest) < 16 {
			continue
		}

		it := IfaceTraffic{Name: name}
		it.RxBytes, _ = strconv.ParseUint(rest[0], 10, 64)
		it.RxPackets, _ = strconv.ParseUint(rest[1], 10, 64)
		it.RxErrors, _ = strconv.ParseUint(rest[2], 10, 64)
		it.TxBytes, _ = strconv.ParseUint(rest[8], 10, 64)
		it.TxPackets, _ = strconv.ParseUint(rest[9], 10, 64)
		it.TxErrors, _ = strconv.ParseUint(rest[10], 10, 64)

		snap.Interfaces = append(snap.Interfaces, it)
	}
	return snap, scanner.Err()
}

// readConnections reads /proc/net/tcp and /proc/net/tcp6 for active connections.
func readConnections() ([]ActiveConn, error) {
	var conns []ActiveConn
	for _, proto := range []struct {
		path string
		name string
	}{
		{"/proc/net/tcp", "tcp"},
		{"/proc/net/tcp6", "tcp6"},
	} {
		c, err := parseProcNetTCP(proto.path, proto.name)
		if err != nil {
			continue // non-fatal
		}
		conns = append(conns, c...)
	}
	return conns, nil
}

// parseProcNetTCP parses /proc/net/tcp or /proc/net/tcp6.
// Format: sl local_address rem_address st ...
func parseProcNetTCP(path, proto string) ([]ActiveConn, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var conns []ActiveConn
	scanner := bufio.NewScanner(f)
	first := true
	for scanner.Scan() {
		if first {
			first = false
			continue // skip header
		}
		fields := strings.Fields(scanner.Text())
		if len(fields) < 4 {
			continue
		}

		local := parseHexAddr(fields[1], proto)
		remote := parseHexAddr(fields[2], proto)
		stateHex := fields[3]
		state := tcpStateMap(stateHex)

		// Skip LISTEN and CLOSE states — we only want active connections.
		if state == "LISTEN" || state == "CLOSE" {
			continue
		}

		conns = append(conns, ActiveConn{
			Protocol: proto,
			Local:    local,
			Remote:   remote,
			State:    state,
		})
	}
	return conns, scanner.Err()
}

// parseHexAddr converts "0100007F:0050" → "127.0.0.1:80".
func parseHexAddr(hex, proto string) string {
	parts := strings.SplitN(hex, ":", 2)
	if len(parts) != 2 {
		return hex
	}

	portHex := parts[1]
	port, _ := strconv.ParseUint(portHex, 16, 16)

	if proto == "tcp6" {
		// IPv6 hex is 32 chars. Show abbreviated.
		return fmt.Sprintf("[ipv6]:%d", port)
	}

	// IPv4: hex is little-endian.
	ipHex := parts[0]
	if len(ipHex) != 8 {
		return fmt.Sprintf("%s:%d", ipHex, port)
	}
	b0, _ := strconv.ParseUint(ipHex[6:8], 16, 8)
	b1, _ := strconv.ParseUint(ipHex[4:6], 16, 8)
	b2, _ := strconv.ParseUint(ipHex[2:4], 16, 8)
	b3, _ := strconv.ParseUint(ipHex[0:2], 16, 8)

	return fmt.Sprintf("%d.%d.%d.%d:%d", b0, b1, b2, b3, port)
}

// tcpStateMap converts hex state to string.
func tcpStateMap(hex string) string {
	states := map[string]string{
		"01": "ESTABLISHED",
		"02": "SYN_SENT",
		"03": "SYN_RECV",
		"04": "FIN_WAIT1",
		"05": "FIN_WAIT2",
		"06": "TIME_WAIT",
		"07": "CLOSE",
		"08": "CLOSE_WAIT",
		"09": "LAST_ACK",
		"0A": "LISTEN",
		"0B": "CLOSING",
	}
	if s, ok := states[strings.ToUpper(hex)]; ok {
		return s
	}
	return hex
}
