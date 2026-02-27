// Package state provides an atomic key=value state file compatible with the
// bash v1 state.env format used by the legacy ID-Spoofer scripts.
package state

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

// FileState implements Manager using an atomic key=value text file.
// The file format is intentionally identical to the bash state.env so that
// users upgrading from the bash version keep their rollback state.
type FileState struct {
	mu      sync.RWMutex
	stateDir string
	path    string
}

// NewFileState creates a FileState rooted at stateDir.
// The state file is named "state.env" inside stateDir.
func NewFileState(stateDir string) (*FileState, error) {
	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		return nil, fmt.Errorf("creating state dir %s: %w", stateDir, err)
	}
	return &FileState{
		stateDir: stateDir,
		path:     filepath.Join(stateDir, "state.env"),
	}, nil
}

// Get retrieves the value for key. Returns ("", false) if not found.
func (f *FileState) Get(key string) (string, bool) {
	f.mu.RLock()
	defer f.mu.RUnlock()
	m, err := f.readAll()
	if err != nil {
		return "", false
	}
	v, ok := m[key]
	return v, ok
}

// Set persists key=value, creating or updating the file atomically.
func (f *FileState) Set(key, value string) error {
	f.mu.Lock()
	defer f.mu.Unlock()

	m, _ := f.readAll()
	if m == nil {
		m = make(map[string]string)
	}
	m[key] = value
	return f.writeAll(m)
}

// Delete removes a key from the state file.
func (f *FileState) Delete(key string) error {
	f.mu.Lock()
	defer f.mu.Unlock()

	m, _ := f.readAll()
	if m == nil {
		return nil
	}
	delete(m, key)
	return f.writeAll(m)
}

// All returns a copy of all key/value pairs.
func (f *FileState) All() (map[string]string, error) {
	f.mu.RLock()
	defer f.mu.RUnlock()
	return f.readAll()
}

// StateDir returns the directory where state files are stored.
func (f *FileState) StateDir() string { return f.stateDir }

// readAll parses the state file. Returns empty map if file does not exist.
func (f *FileState) readAll() (map[string]string, error) {
	file, err := os.Open(f.path)
	if os.IsNotExist(err) {
		return make(map[string]string), nil
	}
	if err != nil {
		return nil, err
	}
	defer file.Close()

	m := make(map[string]string)
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		idx := strings.IndexByte(line, '=')
		if idx < 0 {
			continue
		}
		m[line[:idx]] = line[idx+1:]
	}
	return m, scanner.Err()
}

// writeAll atomically writes the map to the state file.
func (f *FileState) writeAll(m map[string]string) error {
	tmp := f.path + ".tmp"
	file, err := os.OpenFile(tmp, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return fmt.Errorf("opening temp state file: %w", err)
	}

	w := bufio.NewWriter(file)
	for k, v := range m {
		fmt.Fprintf(w, "%s=%s\n", k, v)
	}
	if err := w.Flush(); err != nil {
		file.Close()
		os.Remove(tmp)
		return err
	}
	if err := file.Sync(); err != nil {
		file.Close()
		os.Remove(tmp)
		return err
	}
	file.Close()

	return os.Rename(tmp, f.path)
}
