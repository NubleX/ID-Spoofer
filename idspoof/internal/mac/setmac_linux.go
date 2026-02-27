//go:build linux

package mac

import (
	"fmt"
	"net"
	"unsafe"

	"golang.org/x/sys/unix"
)

// setMAC sets the hardware address of iface using the SIOCSIFHWADDR ioctl.
// The interface must be brought down before calling this.
func setMAC(iface string, mac net.HardwareAddr) error {
	if len(mac) != 6 {
		return fmt.Errorf("invalid MAC length %d", len(mac))
	}

	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM, 0)
	if err != nil {
		return fmt.Errorf("socket: %w", err)
	}
	defer unix.Close(fd)

	// struct ifreq layout: 16-byte name + sockaddr (2-byte family + 14 bytes data).
	// Total size used by the kernel: IFNAMSIZ (16) + 16 = 32 bytes minimum.
	var ifr [40]byte
	copy(ifr[:unix.IFNAMSIZ], iface)
	// sa_family = ARPHRD_ETHER (1)
	ifr[unix.IFNAMSIZ] = 0x01
	ifr[unix.IFNAMSIZ+1] = 0x00
	copy(ifr[unix.IFNAMSIZ+2:], mac)

	_, _, errno := unix.Syscall(
		unix.SYS_IOCTL,
		uintptr(fd),
		unix.SIOCSIFHWADDR,
		uintptr(unsafe.Pointer(&ifr[0])),
	)
	if errno != 0 {
		return fmt.Errorf("SIOCSIFHWADDR %s: %w", iface, errno)
	}
	return nil
}
