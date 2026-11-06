package daemon

import (
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/NubleX/ID-Spoofer/idspoof/internal/boot"
	"github.com/NubleX/ID-Spoofer/idspoof/internal/profile"
	"github.com/NubleX/ID-Spoofer/idspoof/internal/spoofer"
	"github.com/NubleX/ID-Spoofer/idspoof/internal/tunnel"
)

type fakeEngine struct {
	mu        sync.Mutex
	calls     []string
	running   bool
	failStart int // number of tunnel starts that fail before one works
	applied   []spoofer.Options
}

func (f *fakeEngine) Apply(o spoofer.Options) []spoofer.Result {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.applied = append(f.applied, o)
	if o.Tunnel != "" {
		f.calls = append(f.calls, "apply-tunnel")
		if f.failStart > 0 {
			f.failStart--
			return []spoofer.Result{{Operation: spoofer.OpTunnel, Err: errors.New("proxy unreachable")}}
		}
		f.running = true
		return []spoofer.Result{{Operation: spoofer.OpTunnel, Success: true}}
	}
	f.calls = append(f.calls, "apply-identity")
	return []spoofer.Result{{Operation: spoofer.OpMAC, Success: true}}
}

func (f *fakeEngine) Restore(spoofer.Options) []spoofer.Result {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, "restore")
	f.running = false
	return nil
}

func (f *fakeEngine) TunnelStatus() tunnel.Status {
	f.mu.Lock()
	defer f.mu.Unlock()
	return tunnel.Status{Running: f.running}
}

func (f *fakeEngine) kill() { f.mu.Lock(); f.running = false; f.mu.Unlock() }
func (f *fakeEngine) log() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.calls...)
}

type nopLog struct{}

func (nopLog) Info(string, ...any)  {}
func (nopLog) Warn(string, ...any)  {}
func (nopLog) Error(string, ...any) {}

var fast = Timing{Poll: 5 * time.Millisecond, Retry: 5 * time.Millisecond, MaxRetry: 20 * time.Millisecond}

func lookupLab(name string) (profile.Profile, bool) {
	if name == "lab" {
		return profile.Profile{Name: "lab", Tunnel: "tun2socks", Mode: "transparent", ConfigPath: "/tmp/lab.yaml"}, true
	}
	return profile.Profile{}, false
}

func run(t *testing.T, e Engine, bc boot.Config) (stop func(), done chan error) {
	ctx, cancel := context.WithCancel(context.Background())
	done = make(chan error, 1)
	go func() { done <- Run(ctx, e, bc, lookupLab, fast, nopLog{}, nil) }()
	return cancel, done
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	for i := 0; i < 400; i++ {
		if cond() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

func TestNoBootProfileIdlesAndTouchesNothing(t *testing.T) {
	e := &fakeEngine{}
	stop, done := run(t, e, boot.Config{})
	time.Sleep(30 * time.Millisecond)
	stop()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if c := e.log(); len(c) != 0 {
		t.Errorf("idle daemon called the engine: %v", c)
	}
}

func TestIdentityThenTunnelThenRestoreOnStop(t *testing.T) {
	e := &fakeEngine{}
	stop, done := run(t, e, boot.Config{MAC: true, Tunnel: "tun2socks", Profile: "lab"})
	waitFor(t, "tunnel up", func() bool { return e.TunnelStatus().Running })
	stop()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	got := e.log()
	want := []string{"apply-identity", "apply-tunnel", "restore"}
	if len(got) != len(want) {
		t.Fatalf("calls = %v; want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("calls = %v; want %v", got, want)
		}
	}
	// The tunnel must be started with the resolved profile config.
	if last := e.applied[len(e.applied)-1]; last.TunnelCfg != "/tmp/lab.yaml" || last.TunnelMode != "transparent" {
		t.Errorf("tunnel options = %+v", last)
	}
}

func TestTunnelStartRetriesUntilItWorks(t *testing.T) {
	e := &fakeEngine{failStart: 3}
	stop, done := run(t, e, boot.Config{Tunnel: "tun2socks", Profile: "lab"})
	waitFor(t, "tunnel up after retries", func() bool { return e.TunnelStatus().Running })
	stop()
	<-done
	n := 0
	for _, c := range e.log() {
		if c == "apply-tunnel" {
			n++
		}
	}
	if n != 4 {
		t.Errorf("tunnel start attempts = %d; want 4 (3 failures + 1 success)", n)
	}
}

func TestDeadTunnelIsRestarted(t *testing.T) {
	e := &fakeEngine{}
	stop, done := run(t, e, boot.Config{Tunnel: "tun2socks", Profile: "lab"})
	waitFor(t, "first start", func() bool { return e.TunnelStatus().Running })
	e.kill()
	waitFor(t, "restart", func() bool {
		n := 0
		for _, c := range e.log() {
			if c == "apply-tunnel" {
				n++
			}
		}
		return n >= 2 && e.TunnelStatus().Running
	})
	stop()
	<-done
}

func TestMissingProfileFailsBeforeTouchingAnything(t *testing.T) {
	e := &fakeEngine{}
	err := Run(context.Background(), e, boot.Config{MAC: true, Tunnel: "tun2socks", Profile: "ghost"}, lookupLab, fast, nopLog{}, nil)
	if err == nil {
		t.Fatal("expected an error for a missing profile")
	}
	if c := e.log(); len(c) != 0 {
		t.Errorf("engine was called before the profile check: %v", c)
	}
}

func TestInvalidBootConfigIsRejected(t *testing.T) {
	e := &fakeEngine{}
	if err := Run(context.Background(), e, boot.Config{Persona: "beos"}, lookupLab, fast, nopLog{}, nil); err == nil {
		t.Error("invalid persona accepted")
	}
}

func TestIdentityOnlyRestoresOnStop(t *testing.T) {
	e := &fakeEngine{}
	stop, done := run(t, e, boot.Config{MAC: true})
	waitFor(t, "identity applied", func() bool { return len(e.log()) >= 1 })
	stop()
	<-done
	got := e.log()
	if len(got) != 2 || got[0] != "apply-identity" || got[1] != "restore" {
		t.Errorf("calls = %v", got)
	}
}

func TestDisabledByCmdline(t *testing.T) {
	yes := []string{"quiet idspoof.disable=1", "idspoof.disable ro", "a b idspoof.disable=1 c"}
	no := []string{"", "quiet splash", "idspoof.disable=0", "notidspoof.disable=1", "idspoof.disabled=1"}
	for _, c := range yes {
		if !DisabledByCmdline(c) {
			t.Errorf("%q should disable", c)
		}
	}
	for _, c := range no {
		if DisabledByCmdline(c) {
			t.Errorf("%q should not disable", c)
		}
	}
}

func TestReadyIsCalledAfterIdentityBeforeTunnel(t *testing.T) {
	e := &fakeEngine{}
	var atReady []string
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- Run(ctx, e, boot.Config{MAC: true, Tunnel: "tun2socks", Profile: "lab"}, lookupLab, fast, nopLog{},
			func() { atReady = e.log() })
	}()
	waitFor(t, "tunnel up", func() bool { return e.TunnelStatus().Running })
	cancel()
	<-done
	if len(atReady) != 1 || atReady[0] != "apply-identity" {
		t.Errorf("ready fired with calls %v; want exactly [apply-identity]", atReady)
	}
}

func TestReadyIsCalledWhenIdle(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	called := make(chan struct{}, 1)
	done := make(chan error, 1)
	go func() {
		done <- Run(ctx, &fakeEngine{}, boot.Config{}, lookupLab, fast, nopLog{}, func() { called <- struct{}{} })
	}()
	select {
	case <-called:
	case <-time.After(time.Second):
		t.Error("an idle daemon must still report ready, or the service never finishes starting")
	}
	cancel()
	<-done
}

func TestNotifyWritesToSocket(t *testing.T) {
	sock := filepath.Join(t.TempDir(), "notify")
	ln, err := net.ListenPacket("unixgram", sock)
	if err != nil {
		t.Skipf("unixgram unavailable: %v", err)
	}
	defer ln.Close()
	t.Setenv("NOTIFY_SOCKET", sock)
	Notify("READY=1")
	buf := make([]byte, 64)
	ln.SetReadDeadline(time.Now().Add(time.Second))
	n, _, err := ln.ReadFrom(buf)
	if err != nil || string(buf[:n]) != "READY=1" {
		t.Errorf("got %q, %v", buf[:n], err)
	}
	// Without the variable it must be a silent no-op.
	os.Unsetenv("NOTIFY_SOCKET")
	Notify("READY=1")
}
