//go:build windows

package platform

import (
	"github.com/NubleX/idspoof/internal/mac"
	"github.com/NubleX/idspoof/internal/netident"
	"github.com/NubleX/idspoof/internal/sysinfo"
)

// newLinuxPlatform is unreachable on Windows — stub to satisfy the compiler.
func newLinuxPlatform() Platform { panic("newLinuxPlatform called on Windows") }

// newDarwinPlatform is unreachable on Windows — stub to satisfy the compiler.
func newDarwinPlatform() (Platform, error) { panic("newDarwinPlatform called on Windows") }

type windowsPlatform struct{}

func newWindowsPlatform() (Platform, error) {
	return &windowsPlatform{}, nil
}

func (w *windowsPlatform) Name() string                      { return "windows" }
func (w *windowsPlatform) MACSpoofer() mac.Spoofer           { return mac.NewWindowsSpoofer() }
func (w *windowsPlatform) NetIdentSpoofer() netident.Spoofer { return netident.NewWindowsSpoofer() }
func (w *windowsPlatform) SystemInfoSpoofer() sysinfo.Spoofer { return sysinfo.NewStubSpoofer() }
