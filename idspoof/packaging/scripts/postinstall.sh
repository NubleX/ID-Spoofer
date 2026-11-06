#!/bin/sh
# Package post-install (deb/rpm): enable the daemon and refresh desktop caches.
set -e
if [ -d /run/systemd/system ]; then
    systemctl daemon-reload || true
    systemctl enable idspoof.service || true
    # restart so an upgrade runs the new binary; the daemon idles with no boot profile
    systemctl restart idspoof.service || true
fi
command -v gtk-update-icon-cache >/dev/null 2>&1 && gtk-update-icon-cache -q -t -f /usr/share/icons/hicolor || true
command -v update-desktop-database >/dev/null 2>&1 && update-desktop-database -q /usr/share/applications || true
exit 0
