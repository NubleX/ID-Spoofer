//go:build darwin

package platform

import (
	"github.com/NubleX/idspoof/internal/mac"
	"github.com/NubleX/idspoof/internal/netident"
	"github.com/NubleX/idspoof/internal/sysinfo"
)

// newLinuxPlatform is unreachable on Darwin but must be defined so
// DetectPlatform compiles (the Linux case is never hit on macOS).
func newLinuxPlatform() Platform { panic("newLinuxPlatform called on Darwin") }

// newWindowsPlatform is unreachable on Darwin — stub to satisfy the compiler.
func newWindowsPlatform() (Platform, error) { panic("newWindowsPlatform called on Darwin") }

type darwinPlatform struct{}

func newDarwinPlatform() (Platform, error) {
	return &darwinPlatform{}, nil
}

func (d *darwinPlatform) Name() string                      { return "darwin" }
func (d *darwinPlatform) MACSpoofer() mac.Spoofer           { return mac.NewDarwinSpoofer() }
func (d *darwinPlatform) NetIdentSpoofer() netident.Spoofer { return netident.NewDarwinSpoofer() }
func (d *darwinPlatform) SystemInfoSpoofer() sysinfo.Spoofer { return sysinfo.NewStubSpoofer() }
