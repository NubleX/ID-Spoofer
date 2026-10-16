package spoofer

import (
	"testing"

	"github.com/NubleX/ID-Spoofer/idspoof/internal/logging"
	"github.com/NubleX/ID-Spoofer/idspoof/internal/mac"
	"github.com/NubleX/ID-Spoofer/idspoof/internal/netident"
	"github.com/NubleX/ID-Spoofer/idspoof/internal/state"
	"github.com/NubleX/ID-Spoofer/idspoof/internal/sysinfo"
)

// fakeNetIdent is a scriptable netident.Spoofer: it reports whatever
// snapshot CurrentSnap describes and records what Apply/Restore received,
// so the orchestrator's baseline-state logic can be tested without
// touching a real kernel.
type fakeNetIdent struct {
	currentSnap *netident.Snapshot
	applied     netident.Persona
	restored    *netident.Snapshot
	stateDir    string
}

func (f *fakeNetIdent) Current() (*netident.Snapshot, error) { return f.currentSnap, nil }
func (f *fakeNetIdent) Apply(p netident.Persona) error      { f.applied = p; return nil }
func (f *fakeNetIdent) Restore(snap *netident.Snapshot) error {
	f.restored = snap
	return nil
}
func (f *fakeNetIdent) SetStateDir(dir string) { f.stateDir = dir }

type fakePlatform struct{ net *fakeNetIdent }

func (p *fakePlatform) Name() string                   { return "fake" }
func (p *fakePlatform) MACSpoofer() mac.Spoofer        { return nil }
func (p *fakePlatform) NetIdentSpoofer() netident.Spoofer { return p.net }
func (p *fakePlatform) SystemInfoSpoofer() sysinfo.Spoofer { return nil }

func newTestOrchestrator(t *testing.T, st state.Manager, net *fakeNetIdent) *Orchestrator {
	t.Helper()
	logger, err := logging.New(true, false, "")
	if err != nil {
		t.Fatalf("creating logger: %v", err)
	}
	return &Orchestrator{plat: &fakePlatform{net: net}, state: st, logger: logger}
}

// TestNetIdentBaselineLifecycle pins the sysctl baseline semantics:
// the baseline is captured on the first apply only (never clobbered by a
// re-apply while a persona is active) and is cleared on a successful
// restore, which must restore the saved baseline values.
func TestNetIdentBaselineLifecycle(t *testing.T) {
	st, err := state.NewFileState(t.TempDir())
	if err != nil {
		t.Fatalf("creating state: %v", err)
	}

	clean := &netident.Snapshot{
		TTL: 64, TCPTimestamps: 1, TCPWindowScaling: 1, TCPSACK: 1, TCPECN: 0,
		TCPRFC1337: 1, RmemDefault: 212992, RmemMax: 212992,
		WmemDefault: 212992, WmemMax: 212992,
	}

	net := &fakeNetIdent{currentSnap: clean}
	o := newTestOrchestrator(t, st, net)

	assertState := func(key, want string) {
		t.Helper()
		got, ok := st.Get(key)
		if !ok {
			t.Fatalf("%s not saved", key)
		}
		if got != want {
			t.Errorf("%s = %q, want %q", key, got, want)
		}
	}

	// 1. First apply from a clean system: the baseline is captured.
	if res := o.applyNetIdent(Options{NetIdent: true, Quiet: true}); res.Err != nil {
		t.Fatalf("first apply: %v", res.Err)
	}
	assertState("ORIG_TTL", "64")
	assertState("ORIG_TCP_TIMESTAMPS", "1")
	assertState("ORIG_TCP_RFC1337", "1")

	// 2. Re-apply while the persona is active: live values now match the
	// persona (128/0/0). The saved baseline must survive untouched.
	net.currentSnap = &netident.Snapshot{
		TTL: 128, TCPTimestamps: 0, TCPRFC1337: 0,
		RmemDefault: 65535, RmemMax: 16776960, WmemDefault: 65535, WmemMax: 16776960,
	}
	if res := o.applyNetIdent(Options{NetIdent: true, Quiet: true}); res.Err != nil {
		t.Fatalf("re-apply: %v", res.Err)
	}
	assertState("ORIG_TTL", "64")
	assertState("ORIG_TCP_TIMESTAMPS", "1")
	assertState("ORIG_TCP_RFC1337", "1")

	// 3. A successful restore hands the saved baseline back to the
	// spoofer and clears the baseline keys.
	if res := o.restoreNetIdent(true); res.Err != nil {
		t.Fatalf("restore: %v", res.Err)
	}
	if net.restored == nil {
		t.Fatal("spoofer Restore was not called")
	}
	if net.restored.TTL != 64 || net.restored.TCPTimestamps != 1 || net.restored.TCPRFC1337 != 1 {
		t.Errorf("restore snapshot = {TTL %d, TS %d, RFC1337 %d}, want {64, 1, 1}",
			net.restored.TTL, net.restored.TCPTimestamps, net.restored.TCPRFC1337)
	}
	if _, ok := st.Get("ORIG_TTL"); ok {
		t.Error("ORIG_TTL still present after successful restore")
	}
	if _, ok := st.Get("PERSONA_TYPE"); ok {
		t.Error("PERSONA_TYPE still present after successful restore")
	}

	// 4. Next apply after the restore re-captures a fresh baseline.
	net.currentSnap = clean
	if res := o.applyNetIdent(Options{NetIdent: true, Quiet: true}); res.Err != nil {
		t.Fatalf("post-restore apply: %v", res.Err)
	}
	assertState("ORIG_TTL", "64")
	assertState("ORIG_TCP_RFC1337", "1")
}
