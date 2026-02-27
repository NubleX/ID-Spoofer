package sysinfo

import "fmt"

// stubSpoofer generates and displays system info but cannot actually write to DMI.
// DMI/SMBIOS fields are read-only on all platforms without kernel modules.
type stubSpoofer struct{}

// NewStubSpoofer returns the display-only system info spoofer.
func NewStubSpoofer() Spoofer { return &stubSpoofer{} }

func (s *stubSpoofer) Generate() (Info, error) {
	return GenerateWindowsInfo(), nil
}

func (s *stubSpoofer) Apply(info Info) error {
	fmt.Printf("  System profile: %s %s (serial: %s)\n", info.Manufacturer, info.Product, info.Serial)
	fmt.Println("  Note: DMI fields are read-only; profile displayed for reference only.")
	return nil
}
