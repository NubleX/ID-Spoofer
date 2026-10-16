//go:build linux

// rewriter_daemon_linux.go — The NFQUEUE rewriter must outlive the CLI
// process: the kernel keeps diverting SYN packets to queue 42 as long as
// the iptables rule exists, and with no userland dequeuer the kernel's
// queue-lifetime timer drops them, killing every new TCP connection.
//
// apply therefore spawns a detached helper process — the same binary
// re-exec'd as the hidden `idspoof __rewriter` subcommand — which binds
// the queue and rewrites packets until signalled. restore terminates it.
// Liveness is tracked via a pid file in the state directory.

package netident

import (
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
)

const (
	// rewriterPidFileName is the pid file written by the helper process.
	// Format: "<pid>\t<persona>\t<cmd>\n"
	rewriterPidFileName = "rewriter.pid"

	// rewriterLogFileName captures the helper's stdout/stderr for debugging.
	rewriterLogFileName = "rewriter.log"

	// rewriterReadyTimeout bounds how long apply waits for the helper to
	// bind the queue and advertise itself.
	rewriterReadyTimeout = 5 * time.Second

	// rewriterStopTimeout bounds how long we wait for SIGTERM to land.
	rewriterStopTimeout = 3 * time.Second
)

// rewriterInfo is the parsed pid file.
type rewriterInfo struct {
	PID     int
	Persona PersonaType
	// Cmd records which subcommand owns the pid file ("__rewriter":
	// the detached helper, "serve": foreground managed mode). Legacy
	// two-field pid files default to the helper.
	Cmd string
}

// readRewriterInfo parses the pid file. Returns (_, false) when the file is
// missing or malformed.
func readRewriterInfo(pidFile string) (rewriterInfo, bool) {
	data, err := os.ReadFile(pidFile)
	if err != nil {
		return rewriterInfo{}, false
	}
	fields := strings.Fields(string(data))
	if len(fields) < 1 {
		return rewriterInfo{}, false
	}
	pid, err := strconv.Atoi(fields[0])
	if err != nil || pid <= 0 {
		return rewriterInfo{}, false
	}
	info := rewriterInfo{PID: pid, Persona: PersonaWindows}
	if len(fields) > 1 {
		info.Persona = PersonaType(fields[1])
	}
	if len(fields) > 2 {
		info.Cmd = fields[2]
	}
	if info.Cmd == "" {
		info.Cmd = "__rewriter"
	}
	return info, true
}

// rewriterProcAlive reports whether pid points at a live rewriter
// process owned by the subcommand named by cmd ("__rewriter" or
// "serve"). The /proc/<pid>/cmdline check guards against PID reuse: a
// stale pid file pointing at an unrelated process that recycled the
// PID must not be treated (or signalled) as ours. Both NUL boundaries
// matter: the appended NUL makes a marker that is the final argv entry
// match too, and the trailing one stops a marker-prefixed element (a
// recycled PID running, say, "serve-proxy") from matching; a recycled
// process would have to carry cmd as an exact argv element.
func rewriterProcAlive(pid int, cmd string) bool {
	if pid <= 1 {
		return false
	}
	if err := syscall.Kill(pid, 0); err != nil {
		return false
	}
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/cmdline", pid))
	if err != nil {
		return false
	}
	cmdline := string(append(data, 0)) // NUL-terminated argv
	return strings.Contains(cmdline, "\x00"+cmd+"\x00")
}

// RewriterStatus reports the rewriter daemon's state for status displays.
func RewriterStatus(stateDir string) (pid int, persona string, alive bool) {
	if stateDir == "" {
		return 0, "", false
	}
	info, ok := readRewriterInfo(filepath.Join(stateDir, rewriterPidFileName))
	if !ok {
		return 0, "", false
	}
	alive = rewriterProcAlive(info.PID, info.Cmd)
	return info.PID, string(info.Persona), alive
}

// SpawnRewriterDaemon ensures a live rewriter daemon for the given persona.
//
//   - A live daemon for the same persona is reused (idempotent re-apply).
//   - A live daemon for a different persona is stopped and replaced.
//   - A stale pid file is cleaned up.
//
// The helper is spawned in its own session (Setsid) so it survives the CLI
// exiting and terminal hangups. Returns the live daemon's PID.
func SpawnRewriterDaemon(stateDir string, persona PersonaType) (int, error) {
	if stateDir == "" {
		return 0, fmt.Errorf("state directory not configured; cannot spawn rewriter daemon")
	}
	pidFile := filepath.Join(stateDir, rewriterPidFileName)

	// Handle any existing daemon first.
	if info, ok := readRewriterInfo(pidFile); ok {
		switch {
		case rewriterProcAlive(info.PID, info.Cmd) && info.Persona == persona:
			return info.PID, nil // already running for this persona.
		case rewriterProcAlive(info.PID, info.Cmd):
			if err := killRewriterProcess(info.PID, info.Cmd); err != nil {
				return 0, fmt.Errorf("stopping previous rewriter (PID %d): %w", info.PID, err)
			}
			os.Remove(pidFile)
		default:
			os.Remove(pidFile) // stale pid file.
		}
	}

	self, err := os.Executable()
	if err != nil {
		return 0, fmt.Errorf("resolving self path: %w", err)
	}

	cmd := exec.Command(self, "__rewriter", "--persona", string(persona), "--state-dir", stateDir)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	// Truncate: each daemon generation gets a fresh log. Appending left
	// stale errors from earlier runs in the tail and could surface an
	// old last line in the spawn-failure diagnostic below.
	logFile, err := os.OpenFile(filepath.Join(stateDir, rewriterLogFileName),
		os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
	if err != nil {
		return 0, fmt.Errorf("opening rewriter log: %w", err)
	}
	devNull, nerr := os.OpenFile(os.DevNull, os.O_RDONLY, 0)
	if nerr == nil {
		cmd.Stdin = devNull
	}
	cmd.Stdout = logFile
	cmd.Stderr = logFile
	if err := cmd.Start(); err != nil {
		logFile.Close()
		return 0, fmt.Errorf("starting rewriter process: %w", err)
	}
	if devNull != nil {
		devNull.Close()
	}

	// Wait for the helper to bind the queue and advertise itself.
	startWait := time.Now()
	for {
		if info, ok := readRewriterInfo(pidFile); ok &&
			info.PID == cmd.Process.Pid && rewriterProcAlive(info.PID, info.Cmd) {
			logFile.Close()
			return info.PID, nil
		}
		if time.Since(startWait) >= rewriterReadyTimeout {
			break
		}
		time.Sleep(25 * time.Millisecond)
	}

	// Failure path: capture diagnostics, tear down, remove the queue rule.
	var lastLog string
	if cmd.Process != nil {
		cmd.Process.Kill()
		_ = cmd.Wait()
	}
	logFile.Close()
	if data, err := os.ReadFile(filepath.Join(stateDir, rewriterLogFileName)); err == nil {
		if lines := strings.Split(strings.TrimSpace(string(data)), "\n"); len(lines) > 0 {
			lastLog = lines[len(lines)-1]
		}
	}
	os.Remove(pidFile)
	return 0, fmt.Errorf("rewriter did not bind NFQUEUE within %s (last log: %q)",
		rewriterReadyTimeout, lastLog)
}

// StopRewriterDaemon terminates the rewriter daemon, if one is running.
// Returns the PID of the stopped daemon, or 0 if none was running.
func StopRewriterDaemon(stateDir string) (int, error) {
	if stateDir == "" {
		return 0, nil
	}
	pidFile := filepath.Join(stateDir, rewriterPidFileName)
	info, ok := readRewriterInfo(pidFile)
	if !ok || !rewriterProcAlive(info.PID, info.Cmd) {
		os.Remove(pidFile) // stale file, if any.
		return 0, nil
	}
	if err := killRewriterProcess(info.PID, info.Cmd); err != nil {
		return info.PID, fmt.Errorf("stopping rewriter (PID %d): %w", info.PID, err)
	}
	os.Remove(pidFile)
	return info.PID, nil
}

// killRewriterProcess sends SIGTERM and escalates to SIGKILL after a
// grace period. cmd is the owning subcommand marker, re-verified at
// every poll so a recycled PID is never signalled as ours.
func killRewriterProcess(pid int, cmd string) error {
	if err := syscall.Kill(pid, syscall.SIGTERM); err != nil {
		return err
	}
	deadline := time.Now().Add(rewriterStopTimeout)
	for rewriterProcAlive(pid, cmd) && time.Now().Before(deadline) {
		time.Sleep(50 * time.Millisecond)
	}
	if rewriterProcAlive(pid, cmd) {
		return syscall.Kill(pid, syscall.SIGKILL)
	}
	return nil
}

// PrepareRewriterDaemon binds the NFQUEUE, seeds the persona, and
// advertises liveness (pid file) so status/apply/restore can find the
// engine. It does NOT block on signals, so a caller that must do other
// work between starting and stopping the engine (e.g. `idspoof serve`
// applying the stack first) can.
func PrepareRewriterDaemon(persona PersonaType, stateDir string, marker string) (*NFQueueRewriter, error) {
	if stateDir == "" {
		return nil, fmt.Errorf("state directory not configured")
	}
	pidFile := filepath.Join(stateDir, rewriterPidFileName)

	// Refuse to double-bind the queue if another live daemon owns it.
	if info, ok := readRewriterInfo(pidFile); ok && rewriterProcAlive(info.PID, info.Cmd) {
		return nil, fmt.Errorf("rewriter already running (PID %d, persona %s)", info.PID, info.Persona)
	}

	if err := os.MkdirAll(stateDir, 0o755); err != nil {
		return nil, fmt.Errorf("creating state dir: %w", err)
	}

	// The owning process has no knowledge of the CLI's in-memory state
	// — seed the persona before the rewriter goroutine reads it.
	activePersona.Store(persona)

	r := NewNFQueueRewriter(nfqueueNum)
	if err := r.Start(); err != nil {
		return nil, fmt.Errorf("binding NFQUEUE %d: %w", nfqueueNum, err)
	}

	// Advertise liveness so apply/restore/status can find us. Atomic
	// publish (temp file + rename): readers only ever see a complete
	// file, so a crash mid-write cannot leave a torn pid file that
	// parses back as a legacy two-field entry and mislabels this
	// daemon.
	tmp := fmt.Sprintf("%s.%d", pidFile, os.Getpid())
	if err := os.WriteFile(tmp, []byte(fmt.Sprintf("%d\t%s\t%s\n", os.Getpid(), persona, marker)), 0o644); err != nil {
		r.Stop()
		return nil, fmt.Errorf("writing pid file: %w", err)
	}
	if err := os.Rename(tmp, pidFile); err != nil {
		os.Remove(tmp)
		r.Stop()
		return nil, fmt.Errorf("publishing pid file: %w", err)
	}
	return r, nil
}

// FinishRewriterDaemon stops the engine and removes the pid file. The
// caller owns the blocking step (a signal wait or the process's own
// lifetime). A nil engine is a true no-op — it means this process does
// not own the queue, so a live pid file from someone else (say, the
// detached helper spawned by an earlier apply) must be left intact.
func FinishRewriterDaemon(r *NFQueueRewriter, stateDir string) {
	if r == nil {
		return
	}
	r.Stop()
	os.Remove(filepath.Join(stateDir, rewriterPidFileName))
}

// RunRewriterDaemon runs the NFQUEUE rewriter in the foreground until
// SIGTERM/SIGINT. Entry point of the hidden `idspoof __rewriter`
// subcommand (spawned detached by apply, outlives the CLI): it prepares
// the engine, blocks on a stop signal, then finishes. marker records
// which owning subcommand wrote the pid file, so liveness checks match
// the right argv entry.
func RunRewriterDaemon(persona PersonaType, stateDir string, marker string) error {
	r, err := PrepareRewriterDaemon(persona, stateDir, marker)
	if err != nil {
		return err
	}

	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGTERM, syscall.SIGINT)
	<-sigs

	FinishRewriterDaemon(r, stateDir)
	return nil
}
