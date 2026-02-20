# Code Review: ID-Spoofer Issues

## Critical Issues Identified

### 1. Hostname Management Problems

**Location**: `src/bin/hardware-spoof.sh` lines 289-318

**Issues**:
- ❌ **Not using `hostnamectl`**: The script uses the legacy `hostname` command instead of `hostnamectl`, which doesn't properly integrate with systemd
- ❌ **Direct `/etc/hostname` write**: Line 304 writes directly to `/etc/hostname` without:
  - Checking if file exists
  - Validating hostname format (RFC 1123 compliance)
  - Backing up original file
  - Coordinating with systemd
- ❌ **Fragile `/etc/hosts` modification**: Line 308 uses a regex that:
  - Only matches `127.0.1.1` entries (misses `127.0.0.1` entries)
  - Doesn't handle multiple hostname entries
  - Doesn't preserve comments or other entries
  - Creates `.bak` files that accumulate
- ❌ **No NetworkManager coordination**: NetworkManager caches hostname and may overwrite changes
- ❌ **No systemd service notification**: Services using hostname won't be notified of changes

**Impact**: Hostname changes may not persist, systemd services may use stale hostname, NetworkManager may revert changes, filesystem may have inconsistent state.

### 2. MAC Address Management Problems

**Location**: `src/bin/hardware-spoof.sh` lines 216-287

**Issues**:
- ❌ **No NetworkManager coordination**: Lines 240-243 bring interfaces down without:
  - Stopping NetworkManager service or disabling it for specific interfaces
  - Notifying NetworkManager of MAC changes
  - NetworkManager may immediately revert MAC addresses or conflict
- ❌ **No systemd-networkd handling**: If systemd-networkd is managing interfaces, changes will be overwritten
- ❌ **No interface state restoration**: If script fails mid-operation, interfaces may remain down
- ❌ **Race conditions**: Multiple network managers may conflict during MAC changes
- ❌ **No persistent MAC configuration**: Changes are temporary and lost on reboot

**Impact**: NetworkManager may revert MAC addresses, interfaces may stay down after failures, network connectivity lost, system confusion about interface identities.

### 3. Filesystem Consistency Issues

**Issues**:
- ❌ **Non-atomic file operations**: Direct writes to `/etc/hostname` and `/etc/hosts` without:
  - Atomic writes (write to temp file, then rename)
  - File locking
  - Transaction rollback on failure
- ❌ **Backup file accumulation**: `sed -i.bak` creates `.bak` files that accumulate
- ❌ **No validation**: Hostname format not validated before writing (can contain invalid characters)
- ❌ **`set -e` danger**: Script exits immediately on any error, leaving system in inconsistent state

**Impact**: Corrupted system files, invalid hostnames breaking system services, backup file clutter, inconsistent system state on errors.

### 4. Missing Service Coordination

**Issues**:
- ❌ **No NetworkManager integration**: Should use `nmcli` to properly manage MAC addresses
- ❌ **No systemd-networkd support**: Should check and handle systemd-networkd configuration
- ❌ **No udev rule handling**: MAC addresses may be managed by udev rules
- ❌ **No service restart**: Services using hostname/MAC may need restart

**Impact**: Changes get overwritten by network managers, system services use stale information, conflicts between different management systems.

### 5. Error Handling and Rollback

**Issues**:
- ❌ **No rollback mechanism**: If operations fail partway, no way to restore original state
- ❌ **`set -e` too aggressive**: Exits immediately, doesn't allow cleanup
- ❌ **No transaction support**: Operations aren't atomic - partial failures leave inconsistent state
- ❌ **Temporary files not cleaned on error**: Cleanup only happens on EXIT, but errors may prevent cleanup

**Impact**: System left in broken state after failures, no recovery mechanism, manual intervention required.

## Recommended Fixes

### Priority 1: Critical Fixes

1. **Use `hostnamectl` instead of `hostname` command**
   - Properly integrates with systemd
   - Validates hostname format
   - Notifies all services

2. **Coordinate with NetworkManager**
   - Use `nmcli` to manage MAC addresses
   - Disable NetworkManager for interfaces during changes
   - Re-enable after changes complete

3. **Add proper error handling**
   - Remove or modify `set -e` to allow cleanup
   - Add rollback mechanism
   - Use atomic file operations

4. **Validate hostname format**
   - Check RFC 1123 compliance
   - Reject invalid characters
   - Ensure length limits

### Priority 2: Important Improvements

1. **Atomic file operations**
   - Write to temp files first
   - Use `mv` to atomically replace files
   - Proper backup mechanism

2. **Service coordination**
   - Detect active network manager
   - Handle systemd-networkd
   - Check for udev rules

3. **Better `/etc/hosts` handling**
   - Preserve all entries
   - Handle multiple hostname entries
   - Don't create backup files (use version control)

4. **Transaction support**
   - Track all changes
   - Rollback on failure
   - Verify changes succeeded

### Priority 3: Nice to Have

1. **Persistent MAC configuration**
   - Create NetworkManager connection profiles
   - Support systemd-networkd configs
   - Handle udev rules

2. **Better logging**
   - Log all changes before applying
   - Log rollback operations
   - More detailed error messages

3. **Dry-run mode**
   - Show what would change
   - Validate without applying
   - Test mode

## Specific Code Locations Needing Changes

1. **`spoof_hostname()` function** (lines 289-318)
   - Replace `hostname` with `hostnamectl`
   - Add hostname validation
   - Improve `/etc/hosts` handling
   - Add atomic file operations

2. **`spoof_mac_addresses()` function** (lines 216-287)
   - Add NetworkManager coordination
   - Add systemd-networkd detection
   - Improve error handling
   - Add rollback mechanism

3. **Error handling** (throughout)
   - Modify `set -e` behavior
   - Add rollback functions
   - Improve cleanup on errors

4. **File operations** (multiple locations)
   - Use atomic writes
   - Add proper backups
   - Remove `.bak` file creation
