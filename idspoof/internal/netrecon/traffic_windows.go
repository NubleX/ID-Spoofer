//go:build windows

package netrecon

import (
	"fmt"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

// readTraffic uses `netsh interface ipv4 show subinterfaces` on Windows.
func readTraffic() (*TrafficSnapshot, error) {
	out, err := exec.Command("netsh", "interface", "ipv4", "show", "subinterfaces").Output()
	if err != nil {
		return nil, fmt.Errorf("netsh: %w", err)
	}

	snap := &TrafficSnapshot{Timestamp: time.Now()}
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		fields := strings.Fields(line)
		// Format: MTU  MediaSenseState  Bytes In  Bytes Out  Interface
		if len(fields) < 5 {
			continue
		}
		// Skip header and separator lines.
		if fields[0] == "MTU" || strings.HasPrefix(fields[0], "-") {
			continue
		}
		bytesIn, err1 := strconv.ParseUint(fields[2], 10, 64)
		bytesOut, err2 := strconv.ParseUint(fields[3], 10, 64)
		if err1 != nil || err2 != nil {
			continue
		}
		name := strings.Join(fields[4:], " ")

		snap.Interfaces = append(snap.Interfaces, IfaceTraffic{
			Name:    name,
			RxBytes: bytesIn,
			TxBytes: bytesOut,
		})
	}
	return snap, nil
}

// readConnections uses `netstat -an` on Windows to list active TCP connections.
func readConnections() ([]ActiveConn, error) {
	out, err := exec.Command("netstat", "-an").Output()
	if err != nil {
		return nil, fmt.Errorf("netstat: %w", err)
	}

	var conns []ActiveConn
	for _, line := range strings.Split(string(out), "\n") {
		fields := strings.Fields(strings.TrimSpace(line))
		// Proto Local Foreign State
		if len(fields) < 4 {
			continue
		}
		if fields[0] != "TCP" {
			continue
		}
		state := fields[3]
		if state == "LISTENING" || state == "CLOSED" {
			continue
		}
		conns = append(conns, ActiveConn{
			Protocol: "tcp",
			Local:    fields[1],
			Remote:   fields[2],
			State:    state,
		})
	}
	return conns, nil
}
