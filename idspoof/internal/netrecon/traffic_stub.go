//go:build !linux && !darwin && !windows

package netrecon

import "time"

func readTraffic() (*TrafficSnapshot, error) {
	return &TrafficSnapshot{Timestamp: time.Now()}, nil
}

func readConnections() ([]ActiveConn, error) {
	return nil, nil
}
