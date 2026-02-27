package state

import (
	"os"
	"testing"
)

func TestFileStateRoundtrip(t *testing.T) {
	dir := t.TempDir()
	fs, err := NewFileState(dir)
	if err != nil {
		t.Fatalf("NewFileState: %v", err)
	}

	// Set + Get.
	if err := fs.Set("FOO", "bar"); err != nil {
		t.Fatalf("Set: %v", err)
	}
	v, ok := fs.Get("FOO")
	if !ok || v != "bar" {
		t.Errorf("Get(FOO) = %q, %v; want bar, true", v, ok)
	}

	// Update existing key.
	if err := fs.Set("FOO", "baz"); err != nil {
		t.Fatalf("Set update: %v", err)
	}
	v, _ = fs.Get("FOO")
	if v != "baz" {
		t.Errorf("updated Get(FOO) = %q; want baz", v)
	}

	// Delete.
	if err := fs.Delete("FOO"); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	_, ok = fs.Get("FOO")
	if ok {
		t.Error("key still present after Delete")
	}
}

func TestFileStateAll(t *testing.T) {
	dir := t.TempDir()
	fs, _ := NewFileState(dir)
	fs.Set("A", "1")
	fs.Set("B", "2")

	m, err := fs.All()
	if err != nil {
		t.Fatalf("All: %v", err)
	}
	if m["A"] != "1" || m["B"] != "2" {
		t.Errorf("All() = %v, want A=1 B=2", m)
	}
}

func TestFileStateBashCompat(t *testing.T) {
	// Write a bash-style state.env file manually and read it back.
	dir := t.TempDir()
	content := "STATE_VERSION=1\nORIG_HOSTNAME=myhost\nORIG_MACS=eth0:02:aa:bb:cc:dd:ee\n"
	statePath := dir + "/state.env"
	if err := os.WriteFile(statePath, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	fs, _ := NewFileState(dir)
	v, ok := fs.Get("ORIG_HOSTNAME")
	if !ok || v != "myhost" {
		t.Errorf("bash compat: Get(ORIG_HOSTNAME) = %q, %v", v, ok)
	}
}
