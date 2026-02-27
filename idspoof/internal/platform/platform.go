// Package platform defines the abstraction layer for OS-specific operations.
package platform

import (
	"fmt"
	"runtime"

	"github.com/NubleX/idspoof/internal/mac"
	"github.com/NubleX/idspoof/internal/netident"
	"github.com/NubleX/idspoof/internal/sysinfo"
)

// Platform aggregates all OS-specific spoofers.
type Platform interface {
	Name() string
	MACSpoofer() mac.Spoofer
	NetIdentSpoofer() netident.Spoofer
	SystemInfoSpoofer() sysinfo.Spoofer
}

// DetectPlatform returns the Platform implementation for the current OS.
func DetectPlatform() (Platform, error) {
	switch runtime.GOOS {
	case "linux":
		return newLinuxPlatform(), nil
	case "darwin":
		return nil, fmt.Errorf("macOS platform not yet implemented")
	case "windows":
		return nil, fmt.Errorf("Windows platform not yet implemented")
	default:
		return nil, fmt.Errorf("unsupported platform: %s", runtime.GOOS)
	}
}
