package hostname

import (
	"strings"
	"testing"
)

func TestGenerateRandom(t *testing.T) {
	for i := 0; i < 20; i++ {
		h := GenerateRandom()
		if !Validate(h) {
			t.Errorf("GenerateRandom() = %q, failed Validate()", h)
		}
		if !strings.ContainsRune(h, '-') {
			t.Errorf("GenerateRandom() = %q, expected a dash separator", h)
		}
	}
}

func TestValidate(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  bool
	}{
		{"valid simple", "WIN-ABC123", true},
		{"valid fqdn", "host.example.com", true},
		{"empty", "", false},
		{"too long", strings.Repeat("a", 254), false},
		{"leading hyphen", "-bad", false},
		{"trailing hyphen", "bad-", false},
		{"invalid chars", "bad_name!", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := Validate(tt.input); got != tt.want {
				t.Errorf("Validate(%q) = %v, want %v", tt.input, got, tt.want)
			}
		})
	}
}
