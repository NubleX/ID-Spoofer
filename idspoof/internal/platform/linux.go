//go:build linux

package platform

import (
	"github.com/NubleX/idspoof/internal/mac"
	"github.com/NubleX/idspoof/internal/netident"
	"github.com/NubleX/idspoof/internal/sysinfo"
)

type linuxPlatform struct{}

func newLinuxPlatform() Platform { return &linuxPlatform{} }

func (l *linuxPlatform) Name() string                        { return "linux" }
func (l *linuxPlatform) MACSpoofer() mac.Spoofer             { return mac.NewLinuxSpoofer() }
func (l *linuxPlatform) NetIdentSpoofer() netident.Spoofer   { return netident.NewLinuxSpoofer() }
func (l *linuxPlatform) SystemInfoSpoofer() sysinfo.Spoofer  { return sysinfo.NewStubSpoofer() }
