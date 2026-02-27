package mac

import (
	"crypto/rand"
	"fmt"
)

// GenerateRandom generates a locally-administered unicast MAC address.
// The first octet is always 0x02 to set the locally-administered bit
// and clear the multicast bit, matching the bash random_mac() behaviour.
func GenerateRandom() string {
	b := make([]byte, 6)
	if _, err := rand.Read(b); err != nil {
		// Fallback: use all zeros with local bit set (should never happen).
		b = []byte{0x02, 0x00, 0x00, 0x00, 0x00, 0x00}
	}
	b[0] = (b[0] | 0x02) & 0xFE // locally administered, unicast
	return fmt.Sprintf("%02X:%02X:%02X:%02X:%02X:%02X", b[0], b[1], b[2], b[3], b[4], b[5])
}
