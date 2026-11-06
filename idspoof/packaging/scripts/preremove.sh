#!/bin/sh
# Package pre-remove: stop and disable on real removal, not on upgrade.
# deb passes "remove"/"upgrade"; rpm passes the number of remaining installs.
set -e
case "$1" in
    remove|0)
        if [ -d /run/systemd/system ]; then
            # stopping the daemon restores the original identity
            systemctl disable --now idspoof.service || true
            systemctl daemon-reload || true
        fi
        ;;
esac
exit 0
