#!/bin/bash

# ID-Spoofer Comprehensive Uninstaller
# Version 1.0.0
# Author: Igor Dunaev / NubleX
# Removes all traces of ID-Spoofer from the system

set -e

# Script metadata
VERSION="1.0.0"
SCRIPT_NAME="ID-Spoofer Uninstaller"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Print colored output
print_status() {
    local status="$1"
    local message="$2"
    case "$status" in
        "INFO")  echo -e "${BLUE}[INFO]${NC} $message" ;;
        "OK")    echo -e "${GREEN}[OK]${NC} $message" ;;
        "WARN")  echo -e "${YELLOW}[WARN]${NC} $message" ;;
        "ERROR") echo -e "${RED}[ERROR]${NC} $message" >&2 ;;
    esac
}

# Print banner
print_banner() {
    echo -e "${RED}"
    echo "╔════════════════════════════════════════════════╗"
    echo "║       ID-SPOOFER UNINSTALLER v$VERSION          ║"
    echo "║       Complete System Cleanup                  ║"
    echo "╚════════════════════════════════════════════════╝"
    echo -e "${NC}"
}

# Check if running as root
check_root() {
    if [ "$EUID" -ne 0 ]; then
        print_status "ERROR" "This uninstaller must be run as root"
        echo "Usage: sudo $0"
        exit 1
    fi
}

# Confirm uninstallation
confirm_uninstall() {
    echo -e "${YELLOW}This will completely remove ID-Spoofer from your system.${NC}"
    echo "The following items will be removed:"
    echo "  - All executable scripts and symbolic links"
    echo "  - Desktop integration files"
    echo "  - Log directories and files"
    echo "  - Systemd services (if present)"
    echo "  - Configuration files"
    echo
    read -p "Are you sure you want to proceed? (yes/no): " -r confirm
    
    if [[ ! $confirm =~ ^[Yy][Ee][Ss]$ ]]; then
        print_status "INFO" "Uninstallation cancelled by user"
        exit 0
    fi
}

# Remove executable files
remove_executables() {
    print_status "INFO" "Removing executable files..."
    
    local executables=(
        "/usr/local/bin/hardware-spoof.sh"
        "/usr/local/bin/idspoof-menu.sh"
        "/usr/local/bin/idspoof"
        "/usr/local/bin/idspoof-menu"
        "/usr/local/bin/idspoof-uninstall"
        "/usr/bin/hardware-spoof.sh"
        "/usr/bin/idspoof-menu.sh"
        "/usr/bin/idspoof"
        "/usr/bin/idspoof-menu"
        "/usr/bin/idspoof-uninstall"
    )
    
    local removed_count=0
    for executable in "${executables[@]}"; do
        if [ -f "$executable" ]; then
            rm -f "$executable"
            print_status "OK" "Removed: $executable"
            ((removed_count++))
        fi
    done
    
    if [ $removed_count -eq 0 ]; then
        print_status "WARN" "No executable files found to remove"
    else
        print_status "OK" "Removed $removed_count executable files"
    fi
}

# Remove desktop integration
remove_desktop_integration() {
    print_status "INFO" "Removing desktop integration..."
    
    local desktop_files=(
        "/usr/share/applications/hardware-spoofer.desktop"
        "/usr/share/applications/idspoof.desktop"
        "/usr/share/applications/id-spoofer.desktop"
        "/usr/local/share/applications/hardware-spoofer.desktop"
        "/usr/local/share/applications/idspoof.desktop"
        "/usr/local/share/applications/id-spoofer.desktop"
    )
    
    local removed_count=0
    for desktop_file in "${desktop_files[@]}"; do
        if [ -f "$desktop_file" ]; then
            rm -f "$desktop_file"
            print_status "OK" "Removed: $desktop_file"
            ((removed_count++))
        fi
    done
    
    # Update desktop database
    if command -v update-desktop-database >/dev/null 2>&1; then
        update-desktop-database /usr/share/applications/ 2>/dev/null || true
        update-desktop-database /usr/local/share/applications/ 2>/dev/null || true
        print_status "OK" "Updated desktop database"
    fi
    
    if [ $removed_count -eq 0 ]; then
        print_status "WARN" "No desktop files found to remove"
    else
        print_status "OK" "Removed $removed_count desktop integration files"
    fi
}

# Remove systemd services
remove_systemd_services() {
    print_status "INFO" "Removing systemd services..."
    
    local services=(
        "idspoof-restore.service"
        "hardware-spoof.service"
        "id-spoofer.service"
    )
    
    local removed_count=0
    for service in "${services[@]}"; do
        local service_path="/etc/systemd/system/$service"
        if [ -f "$service_path" ]; then
            # Stop and disable service if it's running
            if systemctl is-active --quiet "$service" 2>/dev/null; then
                systemctl stop "$service" 2>/dev/null || true
                print_status "OK" "Stopped service: $service"
            fi
            
            if systemctl is-enabled --quiet "$service" 2>/dev/null; then
                systemctl disable "$service" 2>/dev/null || true
                print_status "OK" "Disabled service: $service"
            fi
            
            rm -f "$service_path"
            print_status "OK" "Removed: $service_path"
            ((removed_count++))
        fi
    done
    
    # Reload systemd daemon if any services were removed
    if [ $removed_count -gt 0 ] && command -v systemctl >/dev/null 2>&1; then
        systemctl daemon-reload 2>/dev/null || true
        print_status "OK" "Reloaded systemd daemon"
    fi
    
    if [ $removed_count -eq 0 ]; then
        print_status "WARN" "No systemd services found to remove"
    else
        print_status "OK" "Removed $removed_count systemd services"
    fi
}

# Remove log directories and files
remove_logs() {
    print_status "INFO" "Removing log directories and files..."
    
    local log_locations=(
        "/var/log/idspoof"
        "/var/log/hardware-spoof"
        "/var/log/id-spoofer"
        "/tmp/idspoofer-*"
    )
    
    local removed_count=0
    for location in "${log_locations[@]}"; do
        if [[ "$location" == *"*"* ]]; then
            # Handle wildcard patterns
            for match in $location; do
                if [ -e "$match" ]; then
                    rm -rf "$match"
                    print_status "OK" "Removed: $match"
                    ((removed_count++))
                fi
            done
        else
            if [ -e "$location" ]; then
                rm -rf "$location"
                print_status "OK" "Removed: $location"
                ((removed_count++))
            fi
        fi
    done
    
    if [ $removed_count -eq 0 ]; then
        print_status "WARN" "No log files found to remove"
    else
        print_status "OK" "Removed $removed_count log locations"
    fi
}

# Remove configuration files
remove_configuration() {
    print_status "INFO" "Removing configuration files..."
    
    local config_locations=(
        "/etc/idspoof"
        "/etc/hardware-spoof"
        "/etc/id-spoofer"
        "/usr/local/etc/idspoof"
        "/usr/local/etc/hardware-spoof"
        "/usr/local/etc/id-spoofer"
    )
    
    local removed_count=0
    for location in "${config_locations[@]}"; do
        if [ -e "$location" ]; then
            rm -rf "$location"
            print_status "OK" "Removed: $location"
            ((removed_count++))
        fi
    done
    
    if [ $removed_count -eq 0 ]; then
        print_status "WARN" "No configuration files found to remove"
    else
        print_status "OK" "Removed $removed_count configuration locations"
    fi
}

# Clean user-specific files (optional)
clean_user_files() {
    print_status "INFO" "Checking for user-specific files..."
    
    # Check common user directories for any leftover files
    local user_dirs=()
    while IFS= read -r -d '' user_home; do
        user_dirs+=("$user_home")
    done < <(find /home -maxdepth 1 -type d -print0 2>/dev/null)
    
    local cleaned_count=0
    for user_dir in "${user_dirs[@]}"; do
        local user_config="$user_dir/.config/idspoof"
        local user_cache="$user_dir/.cache/idspoof"
        local user_local="$user_dir/.local/share/idspoof"
        
        for location in "$user_config" "$user_cache" "$user_local"; do
            if [ -e "$location" ]; then
                rm -rf "$location"
                print_status "OK" "Removed user file: $location"
                ((cleaned_count++))
            fi
        done
    done
    
    if [ $cleaned_count -eq 0 ]; then
        print_status "INFO" "No user-specific files found"
    else
        print_status "OK" "Cleaned $cleaned_count user-specific locations"
    fi
}

# Restore network settings (optional)
restore_network_settings() {
    local restore_network="no"
    read -p "Do you want to restore original MAC addresses? (y/n): " -r restore_confirm
    
    if [[ $restore_confirm =~ ^[Yy]$ ]]; then
        restore_network="yes"
    fi
    
    if [ "$restore_network" = "yes" ]; then
        print_status "INFO" "Restoring original MAC addresses..."
        
        # Get all network interfaces except loopback
        local interfaces
        interfaces=$(ip -o link show | awk -F': ' '{print $2}' | grep -v "lo" | sort)
        
        local restored_count=0
        while IFS= read -r interface; do
            if [ -n "$interface" ]; then
                if command -v macchanger >/dev/null 2>&1; then
                    if ip link set "$interface" down 2>/dev/null; then
                        if macchanger -p "$interface" >/dev/null 2>&1; then
                            ip link set "$interface" up 2>/dev/null || true
                            print_status "OK" "Restored MAC for: $interface"
                            ((restored_count++))
                        else
                            print_status "WARN" "Failed to restore MAC for: $interface"
                            ip link set "$interface" up 2>/dev/null || true
                        fi
                    else
                        print_status "WARN" "Failed to bring down interface: $interface"
                    fi
                else
                    print_status "WARN" "macchanger not available for MAC restoration"
                    break
                fi
            fi
        done <<< "$interfaces"
        
        if [ $restored_count -gt 0 ]; then
            print_status "OK" "Restored MAC addresses for $restored_count interfaces"
        else
            print_status "WARN" "No MAC addresses were restored"
        fi
    fi
}

# Verify complete removal
verify_removal() {
    print_status "INFO" "Verifying complete removal..."
    
    local remaining_files=()
    
    # Check for any remaining files
    local search_patterns=(
        "/usr/local/bin/*spoof*"
        "/usr/bin/*spoof*"
        "/usr/share/applications/*spoof*"
        "/usr/local/share/applications/*spoof*"
        "/etc/systemd/system/*spoof*"
        "/var/log/*spoof*"
        "/etc/*spoof*"
    )
    
    for pattern in "${search_patterns[@]}"; do
        for file in $pattern; do
            if [ -e "$file" ]; then
                remaining_files+=("$file")
            fi
        done
    done
    
    if [ ${#remaining_files[@]} -eq 0 ]; then
        print_status "OK" "Verification complete - all files removed successfully"
    else
        print_status "WARN" "Some files may still remain:"
        printf '  - %s\n' "${remaining_files[@]}"
        echo
        read -p "Do you want to remove these remaining files? (y/n): " -r remove_remaining
        if [[ $remove_remaining =~ ^[Yy]$ ]]; then
            for file in "${remaining_files[@]}"; do
                rm -rf "$file" 2>/dev/null || true
                print_status "OK" "Removed: $file"
            done
        fi
    fi
}

# Main uninstallation function
main() {
    print_banner
    
    check_root
    confirm_uninstall
    
    print_status "INFO" "Starting complete removal of ID-Spoofer..."
    echo
    
    remove_executables
    remove_desktop_integration
    remove_systemd_services
    remove_logs
    remove_configuration
    clean_user_files
    restore_network_settings
    verify_removal
    
    echo
    print_status "OK" "ID-Spoofer has been completely removed from your system"
    echo
    echo -e "${GREEN}Uninstallation Summary:${NC}"
    echo "  ✓ All executable files removed"
    echo "  ✓ Desktop integration cleaned"
    echo "  ✓ System services removed"
    echo "  ✓ Log files cleaned"
    echo "  ✓ Configuration files removed"
    echo "  ✓ User-specific files cleaned"
    echo
    echo -e "${YELLOW}Post-uninstallation notes:${NC}"
    echo "  • You may need to restart your desktop session to clear menu entries"
    echo "  • Network connectivity should be automatically restored"
    echo "  • System reboot is recommended if you experience any issues"
    echo "  • Dependencies (macchanger, zenity, etc.) were not removed"
    echo
    print_status "INFO" "Uninstallation completed successfully"
}

# Run main function
main "$@"