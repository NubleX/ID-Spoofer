//go:build darwin

package netrecon

import (
	"fmt"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

// readTraffic uses `netstat -ib` to read per-interface byte counters on macOS.
func readTraffic() (*TrafficSnapshot, error) {
	out, err := exec.Command("netstat", "-ib").Output()
	if err != nil {
		return nil, fmt.Errorf("netstat -ib: %w", err)
	}

	snap := &TrafficSnapshot{Timestamp: time.Now()}
	seen := make(map[string]bool)

	for _, line := range strings.Split(string(out), "\n") {
		fields := strings.Fields(line)
		// Header: Name Mtu Network Address Ipkts Ierrs Ibytes Opkts Oerrs Obytes
		if len(fields) < 10 {
			continue
		}
		name := fields[0]
		if name == "Name" || seen[name] {
			continue
		}

		ibytes, _ := strconv.ParseUint(fields[6], 10, 64)
		obytes, _ := strconv.ParseUint(fields[9], 10, 64)
		ipkts, _ := strconv.ParseUint(fields[4], 10, 64)
		opkts, _ := strconv.ParseUint(fields[7], 10, 64)
		ierrs, _ := strconv.ParseUint(fields[5], 10, 64)
		oerrs, _ := strconv.ParseUint(fields[8], 10, 64)

		if ibytes == 0 && obytes == 0 {
			continue
		}

		snap.Interfaces = append(snap.Interfaces, IfaceTraffic{
			Name:      name,
			RxBytes:   ibytes,
			TxBytes:   obytes,
			RxPackets: ipkts,
			TxPackets: opkts,
			RxErrors:  ierrs,
			TxErrors:  oerrs,
		})
		seen[name] = true
	}
	return snap, nil
}

// readConnections uses `netstat -an -p tcp` on macOS.
func readConnections() ([]ActiveConn, error) {
	out, err := exec.Command("netstat", "-an", "-p", "tcp").Output()
	if err != nil {
		return nil, fmt.Errorf("netstat: %w", err)
	}

	var conns []ActiveConn
	for _, line := range strings.Split(string(out), "\n") {
		fields := strings.Fields(line)
		// Proto Recv-Q Send-Q Local Foreign State
		if len(fields) < 6 {
			continue
		}
		proto := fields[0]
		if proto != "tcp4" && proto != "tcp6" {
			continue
		}
		state := fields[5]
		if state == "LISTEN" || state == "CLOSED" {
			continue
		}
		p := "tcp"
		if proto == "tcp6" {
			p = "tcp6"
		}
		conns = append(conns, ActiveConn{
			Protocol: p,
			Local:    fields[3],
			Remote:   fields[4],
			State:    state,
		})
	}
	return conns, nil
}
