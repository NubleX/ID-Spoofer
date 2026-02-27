//go:build windows

package fingerprint

import (
	"fmt"

	"golang.org/x/sys/windows/registry"
)

const tcpipKey = `SYSTEM\CurrentControlSet\Services\Tcpip\Parameters`

type windowsSpoofer struct{}

func NewLinuxSpoofer() Spoofer    { return &windowsSpoofer{} }
func NewWindowsSpoofer() Spoofer  { return &windowsSpoofer{} }

func (s *windowsSpoofer) Current() (Parameters, error) {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, tcpipKey, registry.QUERY_VALUE)
	if err != nil {
		return Parameters{TTL: 128}, fmt.Errorf("open registry: %w", err)
	}
	defer k.Close()

	ttl, _, _ := k.GetIntegerValue("DefaultTTL")
	tcp1323, _, _ := k.GetIntegerValue("Tcp1323Opts")
	return Parameters{TTL: int(ttl), TCPTimestamps: int(tcp1323), TCPWindowScaling: -1}, nil
}

func (s *windowsSpoofer) Apply(p *Parameters) error {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, tcpipKey, registry.SET_VALUE)
	if err != nil {
		return fmt.Errorf("open registry for write: %w", err)
	}
	defer k.Close()
	k.SetDWordValue("DefaultTTL", uint32(p.TTL))
	return nil
}

func (s *windowsSpoofer) Restore(orig *Parameters) error { return s.Apply(orig) }
