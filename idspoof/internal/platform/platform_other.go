//go:build !darwin && !windows

// platform_other.go provides stub factory functions for the two non-native
// platforms on any OS that is NOT darwin or windows (i.e. Linux and unknown
// systems). The real implementations live in platform_darwin.go and
// platform_windows.go respectively.

package platform

import "fmt"

// newDarwinPlatform is a stub — returns an error on non-macOS systems.
// The real implementation is in platform_darwin.go (//go:build darwin).
func newDarwinPlatform() (Platform, error) {
	return nil, fmt.Errorf("macOS platform not available on this OS")
}

// newWindowsPlatform is a stub — returns an error on non-Windows systems.
// The real implementation is in platform_windows.go (//go:build windows).
func newWindowsPlatform() (Platform, error) {
	return nil, fmt.Errorf("Windows platform not available on this OS")
}
