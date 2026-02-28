//go:build linux

package platform

import (
	"github.com/NubleX/ID-Spoofer/idspoof/internal/mac"
	"github.com/NubleX/ID-Spoofer/idspoof/internal/netident"
	"github.com/NubleX/ID-Spoofer/idspoof/internal/sysinfo"
)

type linuxPlatform struct{}

func newLinuxPlatform() Platform { return &linuxPlatform{} }

func (l *linuxPlatform) Name() string                        { return "linux" }
func (l *linuxPlatform) MACSpoofer() mac.Spoofer             { return mac.NewLinuxSpoofer() }
func (l *linuxPlatform) NetIdentSpoofer() netident.Spoofer   { return netident.NewLinuxSpoofer() }
func (l *linuxPlatform) SystemInfoSpoofer() sysinfo.Spoofer  { return sysinfo.NewStubSpoofer() }
