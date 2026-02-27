package mac

import (
	"net"
	"strings"
	"testing"
)

func TestGenerateRandom(t *testing.T) {
	for i := 0; i < 50; i++ {
		m := GenerateRandom()
		hw, err := net.ParseMAC(m)
		if err != nil {
			t.Fatalf("GenerateRandom() = %q, not a valid MAC: %v", m, err)
		}
		// First octet must have locally-administered bit set, multicast bit clear.
		if hw[0]&0x02 == 0 {
			t.Errorf("MAC %s missing locally-administered bit", m)
		}
		if hw[0]&0x01 != 0 {
			t.Errorf("MAC %s has multicast bit set", m)
		}
	}
}

func TestInterfaceStateRoundtrip(t *testing.T) {
	orig := []InterfaceMAC{
		{Name: "eth0", MAC: "02:aa:bb:cc:dd:ee"},
		{Name: "wlan0", MAC: "02:11:22:33:44:55"},
	}
	s := InterfacesToStateString(orig)
	got := InterfacesFromStateString(s)
	if len(got) != len(orig) {
		t.Fatalf("got %d entries, want %d", len(got), len(orig))
	}
	for i, g := range got {
		if g.Name != orig[i].Name {
			t.Errorf("entry %d name: got %q want %q", i, g.Name, orig[i].Name)
		}
		if !strings.EqualFold(g.MAC, orig[i].MAC) {
			t.Errorf("entry %d MAC: got %q want %q", i, g.MAC, orig[i].MAC)
		}
	}
}

func TestInterfacesFromStateStringEmpty(t *testing.T) {
	if got := InterfacesFromStateString(""); got != nil {
		t.Errorf("expected nil for empty string, got %v", got)
	}
}
