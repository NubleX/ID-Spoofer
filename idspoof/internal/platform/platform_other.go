//go:build !linux

package platform

import "fmt"

func newLinuxPlatform() Platform {
	panic("newLinuxPlatform called on non-Linux platform")
}

func newDarwinPlatform() (Platform, error) {
	return nil, fmt.Errorf("macOS platform not yet implemented")
}

func newWindowsPlatform() (Platform, error) {
	return nil, fmt.Errorf("Windows platform not yet implemented")
}
