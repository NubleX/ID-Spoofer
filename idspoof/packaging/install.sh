#!/bin/sh
# ID-Spoofer installer: binary, boot daemon (systemd), menu entry and icon.
#
#   sudo ./install.sh              install and start the daemon
#   sudo ./install.sh uninstall    stop the daemon and remove everything
#
# Environment:
#   PREFIX=/usr/local   install prefix
#   DESTDIR=            stage into this root instead (no systemctl, no root needed)
#   BIN=                path to the idspoof binary (default: next to this script)
#   NO_START=1          install and enable the unit but do not start it now
set -eu

PREFIX=${PREFIX:-/usr/local}
DESTDIR=${DESTDIR:-}
here=$(cd "$(dirname "$0")" && pwd)

# Works from the release tarball (files under ./packaging) and from the
# source tree (this script sits inside packaging/).
src="$here/packaging"
[ -d "$src" ] || src="$here"
bin=${BIN:-}
if [ -z "$bin" ]; then
    for c in "$here/idspoof" "$here/../bin/idspoof"; do
        [ -x "$c" ] && bin=$c && break
    done
fi

action=${1:-install}
unit_dir="$DESTDIR/etc/systemd/system"
app_dir="$DESTDIR$PREFIX/share/applications"
icon_dir="$DESTDIR$PREFIX/share/icons/hicolor"
doc_dir="$DESTDIR$PREFIX/share/doc/idspoof"

die() { echo "install.sh: $*" >&2; exit 1; }
live() { [ -z "$DESTDIR" ]; }
has_systemd() { live && [ -d /run/systemd/system ] && command -v systemctl >/dev/null 2>&1; }

if live && [ "$(id -u)" -ne 0 ]; then
    die "run as root:  sudo $0 $action"
fi

case "$action" in
install)
    [ -n "$bin" ] && [ -f "$bin" ] || die "idspoof binary not found; set BIN=/path/to/idspoof"
    for f in systemd/idspoof.service idspoof.desktop icons/idspoof-256.png icons/idspoof-48.png; do
        [ -f "$src/$f" ] || die "missing $src/$f"
    done

    # Stop a running daemon first so the binary can be replaced.
    if has_systemd && systemctl is-active --quiet idspoof.service 2>/dev/null; then
        systemctl stop idspoof.service || true
    fi

    install -D -m 755 "$bin" "$DESTDIR$PREFIX/bin/idspoof"
    install -d -m 755 "$DESTDIR/etc/idspoof"

    # The packaged files reference /usr/bin/idspoof; point them at PREFIX.
    install -d -m 755 "$unit_dir" "$app_dir"
    sed "s#/usr/bin/idspoof#$PREFIX/bin/idspoof#g" "$src/systemd/idspoof.service" > "$unit_dir/idspoof.service"
    sed "s#/usr/bin/idspoof#$PREFIX/bin/idspoof#g" "$src/idspoof.desktop" > "$app_dir/idspoof.desktop"
    chmod 644 "$unit_dir/idspoof.service" "$app_dir/idspoof.desktop"

    install -D -m 644 "$src/icons/idspoof-256.png" "$icon_dir/256x256/apps/idspoof.png"
    install -D -m 644 "$src/icons/idspoof-48.png"  "$icon_dir/48x48/apps/idspoof.png"

    install -d -m 755 "$doc_dir/examples"
    [ -f "$src/tun2socks.example.yaml" ] && install -m 644 "$src/tun2socks.example.yaml" "$doc_dir/examples/"
    [ -f "$src/networkmanager/99-mullvad-ufw" ] && install -m 644 "$src/networkmanager/99-mullvad-ufw" "$doc_dir/examples/"

    if live; then
        command -v gtk-update-icon-cache >/dev/null 2>&1 && gtk-update-icon-cache -q -t -f "$PREFIX/share/icons/hicolor" || true
        command -v update-desktop-database >/dev/null 2>&1 && update-desktop-database -q "$PREFIX/share/applications" || true
    fi
    if has_systemd; then
        systemctl daemon-reload
        systemctl enable idspoof.service
        [ "${NO_START:-}" = "1" ] || systemctl start idspoof.service
        echo "daemon: $(systemctl is-enabled idspoof.service), $(systemctl is-active idspoof.service)"
    elif live; then
        echo "systemd not detected: start the daemon yourself with '$PREFIX/bin/idspoof daemon'"
    fi
    echo "installed: $PREFIX/bin/idspoof, ID-Spoofer in the application menu."
    echo "open the TUI with 'sudo $PREFIX/bin/idspoof menu'; press B there to set what starts at boot."
    ;;
uninstall)
    if has_systemd; then
        # stopping the daemon restores the original identity
        systemctl disable --now idspoof.service 2>/dev/null || true
    fi
    rm -f "$DESTDIR$PREFIX/bin/idspoof" "$unit_dir/idspoof.service" "$app_dir/idspoof.desktop" \
          "$icon_dir/256x256/apps/idspoof.png" "$icon_dir/48x48/apps/idspoof.png"
    rm -rf "$doc_dir"
    has_systemd && systemctl daemon-reload || true
    echo "removed. Kept /etc/idspoof (boot profile) and /var/log/idspoof (profiles, state); delete them by hand if unwanted."
    ;;
*)
    die "usage: $0 [install|uninstall]"
    ;;
esac
