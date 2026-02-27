package platform

import "errors"

// ErrNotPrivileged is returned when the process lacks required privileges.
var ErrNotPrivileged = errors.New("this command must be run as root (sudo idspoof ...)")
