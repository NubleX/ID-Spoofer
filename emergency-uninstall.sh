#!/bin/bash

# ID-Spoofer Emergency Uninstaller
# Standalone script to remove existing installations
# Run this to clean up your current installation before updating
# Author: Igor Dunaev / NubleX

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    echo "Error: This script must be run as root"
    echo "Usage: sudo $0"
    exit 1
fi

echo "ID-Spoofer Emergency Uninstaller"
echo "================================="
echo "This will remove the current ID-Spoofer installation."
echo

# Confirm removal
read -p "Continue with removal? (y/n): " -r confirm
if [[ ! $confirm =~ ^[Yy]$ ]]; then
    echo "Removal cancelled."
    exit 0
fi

echo "Removing ID-Spoofer installation..."

# Stop any running processes
pkill -f "hardware-spoof" 2>/dev/null || true
pkill -f "idspoof" 2>/dev/null || true

# Remove executable files
echo "Removing executable files..."
rm -f /usr/local/bin/hardware-spoof.sh
rm -f /usr/local/bin/idspoof-menu.sh
rm -f /usr/local/bin/idspoof
rm -f /usr/local/bin/idspoof-menu
rm -f /usr/local/bin/idspoof-uninstall
rm -f /usr/bin/hardware-spoof.sh
rm -f /usr/bin/idspoof*

# Remove desktop integration (this fixes your dropdown menu issue)
echo "Removing desktop integration..."
rm -f /usr/share/applications/hardware-spoofer.desktop
rm -f /usr/share/applications/idspoof.desktop
rm -f /usr/share/applications/id-spoofer.desktop
rm -f /usr/local/share/applications/hardware-spoofer.desktop

# Update desktop database to refresh the application menu
if command -v update-desktop-database >/dev/null 2>&1; then
    update-desktop-database /usr/share/applications/ 2>/dev/null || true
    echo "Updated application menu."
fi

# Remove any systemd services
if [ -f /etc/systemd/system/idspoof-restore.service ]; then
    systemctl stop idspoof-restore.service 2>/dev/null || true
    systemctl disable idspoof-restore.service 2>/dev/null || true
    rm -f /etc/systemd/system/idspoof-restore.service
    systemctl daemon-reload 2>/dev/null || true
    echo "Removed systemd service."
fi

# Remove log directories
rm -rf /var/log/idspoof 2>/dev/null || true
rm -rf /var/log/hardware-spoof 2>/dev/null || true

# Clean temporary files
rm -rf /tmp/idspoofer-* 2>/dev/null || true

# Optional: Restore MAC addresses
read -p "Do you want to restore original MAC addresses? (y/n): " -r restore_mac
if [[ $restore_mac =~ ^[Yy]$ ]]; then
    echo "Restoring MAC addresses..."
    if command -v macchanger >/dev/null 2>&1; then
        for interface in $(ip -o link show | awk -F': ' '{print $2}' | grep -v "lo"); do
            echo "Restoring $interface..."
            ip link set "$interface" down 2>/dev/null || true
            macchanger -p "$interface" 2>/dev/null || true
            ip link set "$interface" up 2>/dev/null || true
        done
        echo "MAC addresses restored."
    else
        echo "macchanger not found - cannot restore MAC addresses."
    fi
fi

echo
echo "Removal completed successfully!"
echo "The application should no longer appear in your dropdown menu."
echo "You may need to restart your desktop session or reboot for complete cleanup."
echo
echo "You can now safely install the updated version."