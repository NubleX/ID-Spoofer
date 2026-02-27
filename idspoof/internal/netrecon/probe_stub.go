//go:build !linux && !darwin && !windows

package netrecon

import "time"

func newProber() Prober { return &stubProber{} }

type stubProber struct{}

func (p *stubProber) Probe() (*NetworkState, error) {
	return &NetworkState{
		Warnings:  []string{"network probing not supported on this platform"},
		Timestamp: time.Now(),
	}, nil
}
