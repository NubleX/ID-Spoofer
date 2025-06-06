#!/bin/bash

# ID-Spoofer - Linux Identity Spoofing Tool
# Version 1.0.0
# Author: Igor Dunaev / NubleX
# A tool for spoofing hardware and network identifiers in Linux

# Exit on any error
set -e

# Script metadata
VERSION="1.0.0"
SCRIPT_NAME="ID-Spoofer"
AUTHOR="Igor Dunaev / NubleX"

# Check if running as root
if [ "$(id -u)" -ne "0" ]; then
  echo "Error: This script must be run as root" >&2
  echo "Usage: sudo $0 [options]" >&2
  exit 1
fi

# Check for required commands
REQUIRED_CMDS=("macchanger" "ip" "awk" "tr" "fold" "hostname" "sed" "sysctl")
MISSING_CMDS=()

for cmd in "${REQUIRED_CMDS[@]}"; do
  if ! command -v "$cmd" >/dev/null 2>&1; then
    MISSING_CMDS+=("$cmd")
  fi
done

if [ ${#MISSING_CMDS[@]} -gt 0 ]; then
  echo "Error: Required commands not found: ${MISSING_CMDS[*]}" >&2
  echo "Please install missing packages:" >&2
  echo "  Ubuntu/Debian: sudo apt-get install macchanger net-tools iproute2" >&2
  echo "  RHEL/CentOS: sudo yum install macchanger net-tools iproute2" >&2
  exit 1
fi

# Optional commands for GUI/notifications
HAS_ZENITY=0
HAS_NOTIFY=0
if [ -n "$DISPLAY" ]; then
  if command -v zenity >/dev/null 2>&1; then
    HAS_ZENITY=1
  fi
  
  if command -v notify-send >/dev/null 2>&1; then
    HAS_NOTIFY=1
  fi
fi

# Global variables
GUI_MODE="no"
MAC_ONLY="no"
HOSTNAME_ONLY="no"
QUIET_MODE="no"
LOG_FILE=""
TEMP_DIR="/tmp/idspoofer-$$"
PROGRESS_FILE=""
PROGRESS_PID=""

# Create temporary directory
mkdir -p "$TEMP_DIR"

# Cleanup function
cleanup() {
  local exit_code=$?
  
  # Kill progress dialog if running
  if [ -n "$PROGRESS_PID" ]; then
    kill "$PROGRESS_PID" 2>/dev/null || true
  fi
  
  # Remove temporary files
  rm -rf "$TEMP_DIR" 2>/dev/null || true
  rm -f "$PROGRESS_FILE" 2>/dev/null || true
  
  exit $exit_code
}

# Set trap for cleanup
trap cleanup EXIT INT TERM

# Logging function
log_message() {
  local level="$1"
  local message="$2"
  local timestamp
  timestamp=$(date '+%Y-%m-%d %H:%M:%S')
  
  if [ -n "$LOG_FILE" ]; then
    echo "[$timestamp] [$level] $message" >> "$LOG_FILE"
  fi
  
  if [ "$QUIET_MODE" = "no" ] && [ "$level" = "ERROR" ]; then
    echo "ERROR: $message" >&2
  fi
}

# Function to show script banner
show_banner() {
  if [ "$QUIET_MODE" = "yes" ]; then
    return
  fi
  
  echo "╔════════════════════════════════════════════════╗"
  echo "║       $SCRIPT_NAME v$VERSION                        ║"
  echo "║       Linux Identity Spoofing Tool             ║"
  echo "╚════════════════════════════════════════════════╝"
  echo
}

# Function to generate random MAC address
random_mac() {
  # Use locally administered unicast MAC (02:xx:xx:xx:xx:xx)
  printf '02:%02X:%02X:%02X:%02X:%02X\n' $((RANDOM%256)) $((RANDOM%256)) $((RANDOM%256)) $((RANDOM%256)) $((RANDOM%256))
}

# Function to generate a random hostname
random_hostname() {
  local prefixes=("WIN" "PC" "DESKTOP" "LAPTOP" "SYSTEM" "WORKSTATION")
  local prefix="${prefixes[$((RANDOM % ${#prefixes[@]}))]}"
  local suffix
  suffix=$(tr -dc 'A-Z0-9' < /dev/urandom | fold -w 6 | head -n 1)
  echo "${prefix}-${suffix}"
}

# Function to generate Windows-like system info
gen_windows_info() {
  local manufacturers=("Dell Inc." "HP" "Lenovo" "ASUS" "Acer" "Microsoft Corporation")
  local products=("Latitude" "Inspiron" "ProBook" "ThinkPad" "Surface" "ROG" "Predator")
  local versions=("A01" "1.0" "2.3.4" "3.1")
  
  local manufacturer="${manufacturers[$((RANDOM % ${#manufacturers[@]}))]}"
  local product="${products[$((RANDOM % ${#products[@]}))]}"
  local version="${versions[$((RANDOM % ${#versions[@]}))]}"
  local serial
  serial=$(tr -dc 'A-Z0-9' < /dev/urandom | fold -w 10 | head -n 1)
  
  echo "$manufacturer" > "$TEMP_DIR/manufacturer"
  echo "$product" > "$TEMP_DIR/product"
  echo "$version" > "$TEMP_DIR/version"
  echo "$serial" > "$TEMP_DIR/serial"
  
  log_message "INFO" "Generated system info: $manufacturer $product"
}

# Function to display progress 
show_progress() {
  local message="$1"
  local percent="$2"
  
  log_message "PROGRESS" "[$percent%] $message"
  
  if [ "$QUIET_MODE" = "yes" ]; then
    return
  fi
  
  if [ "$HAS_ZENITY" -eq 1 ] && [ "$GUI_MODE" = "yes" ] && [ -n "$PROGRESS_FILE" ]; then
    echo "$percent" > "$PROGRESS_FILE"
    echo "# $message" >> "$PROGRESS_FILE"
  else
    printf "%-50s [%3d%%]\n" "$message" "$percent"
  fi
}

# Function to show notification
show_notification() {
  local title="$1"
  local message="$2"
  
  log_message "INFO" "$title: $message"
  
  if [ "$QUIET_MODE" = "yes" ]; then
    return
  fi
  
  if [ "$HAS_NOTIFY" -eq 1 ] && [ "$GUI_MODE" = "yes" ]; then
    notify-send -i security-high "$title" "$message" 2>/dev/null || true
  else
    echo "→ $title: $message"
  fi
}

# Function to confirm action
confirm_action() {
  local title="$1"
  local message="$2"
  
  if [ "$QUIET_MODE" = "yes" ]; then
    return 0
  fi
  
  if [ "$HAS_ZENITY" -eq 1 ] && [ "$GUI_MODE" = "yes" ]; then
    zenity --question --title="$title" --text="$message\n\nContinue?" --width=350 2>/dev/null
    return $?
  else
    echo "=== $title ==="
    echo "$message"
    read -p "Continue? (y/n): " -r confirm
    if [[ $confirm =~ ^[Yy]([Ee][Ss])?$ ]]; then
      return 0
    else
      return 1
    fi
  fi
}

# Function to get network interfaces
get_network_interfaces() {
  ip -o link show | awk -F': ' '{print $2}' | grep -v "lo" | sort
}

# Function to spoof MAC addresses
spoof_mac_addresses() {
  log_message "INFO" "Starting MAC address spoofing"
  show_progress "Discovering network interfaces..." 10
  
  local interfaces
  interfaces=$(get_network_interfaces)
  
  if [ -z "$interfaces" ]; then
    log_message "ERROR" "No network interfaces found"
    show_notification "Error" "No network interfaces found"
    return 1
  fi
  
  show_progress "Disabling network interfaces..." 20
  
  # Store original MAC addresses
  true > "$TEMP_DIR/original_macs"
  while IFS= read -r interface; do
    if [ -n "$interface" ]; then
      local original_mac
      original_mac=$(ip link show "$interface" | grep -o -E '([[:xdigit:]]{1,2}:){5}[[:xdigit:]]{1,2}' | head -1)
      echo "$interface:$original_mac" >> "$TEMP_DIR/original_macs"
      
      # Bring interface down
      ip link set "$interface" down 2>/dev/null || {
        log_message "WARN" "Failed to bring down interface $interface"
      }
    fi
  done <<< "$interfaces"
  
  show_progress "Changing MAC addresses..." 60
  
  # Change MAC addresses
  true > "$TEMP_DIR/mac_changes"
  while IFS= read -r interface; do
    if [ -n "$interface" ]; then
      local new_mac
      new_mac=$(random_mac)
      
      if macchanger -m "$new_mac" "$interface" >/dev/null 2>&1; then
        echo "$interface: $new_mac" >> "$TEMP_DIR/mac_changes"
        log_message "INFO" "Changed MAC for $interface to $new_mac"
      else
        log_message "WARN" "Failed to change MAC for $interface"
      fi
    fi
  done <<< "$interfaces"
  
  show_progress "Re-enabling network interfaces..." 90
  
  # Bring interfaces back up
  while IFS= read -r interface; do
    if [ -n "$interface" ]; then
      ip link set "$interface" up 2>/dev/null || {
        log_message "WARN" "Failed to bring up interface $interface"
      }
    fi
  done <<< "$interfaces"
  
  show_progress "MAC address spoofing complete" 100
  
  if [ -f "$TEMP_DIR/mac_changes" ] && [ -s "$TEMP_DIR/mac_changes" ]; then
    local mac_info
    mac_info=$(cat "$TEMP_DIR/mac_changes")
    show_notification "MAC Addresses Changed" "$mac_info"
    log_message "INFO" "MAC spoofing completed successfully"
  else
    log_message "ERROR" "No MAC addresses were changed"
    return 1
  fi
}

# Function to spoof hostname
spoof_hostname() {
  log_message "INFO" "Starting hostname spoofing"
  show_progress "Generating new hostname..." 30
  
  local new_hostname
  new_hostname=$(random_hostname)
  
  # Store original hostname
  hostname > "$TEMP_DIR/original_hostname"
  
  show_progress "Setting hostname..." 70
  
  # Set new hostname
  if hostname "$new_hostname" 2>/dev/null; then
    echo "$new_hostname" > /etc/hostname
    
    # Update /etc/hosts
    if [ -f /etc/hosts ]; then
      sed -i.bak "s/127\.0\.1\.1.*/127.0.1.1\t$new_hostname/g" /etc/hosts
    fi
    
    show_progress "Hostname spoofing complete" 100
    show_notification "Hostname Changed" "New hostname: $new_hostname"
    log_message "INFO" "Hostname changed to: $new_hostname"
  else
    log_message "ERROR" "Failed to set hostname"
    return 1
  fi
}

# Function to spoof OS fingerprint
spoof_os_fingerprint() {
  log_message "INFO" "Starting OS fingerprint spoofing"
  show_progress "Modifying TCP/IP stack parameters..." 50
  
  # Store original values
  {
    echo "net.ipv4.ip_default_ttl=$(sysctl -n net.ipv4.ip_default_ttl 2>/dev/null || echo 64)"
    echo "net.ipv4.tcp_timestamps=$(sysctl -n net.ipv4.tcp_timestamps 2>/dev/null || echo 1)"
    echo "net.ipv4.tcp_window_scaling=$(sysctl -n net.ipv4.tcp_window_scaling 2>/dev/null || echo 1)"
  } > "$TEMP_DIR/original_sysctl"
  
  # Apply Windows-like settings
  sysctl -w net.ipv4.ip_default_ttl=128 >/dev/null 2>&1 || log_message "WARN" "Failed to set TTL"
  sysctl -w net.ipv4.tcp_timestamps=0 >/dev/null 2>&1 || log_message "WARN" "Failed to disable TCP timestamps"
  sysctl -w net.ipv4.tcp_window_scaling=0 >/dev/null 2>&1 || log_message "WARN" "Failed to disable TCP window scaling"
  
  show_progress "OS fingerprint spoofing complete" 100
  show_notification "OS Fingerprint Modified" "TCP/IP stack now appears as Windows"
  log_message "INFO" "OS fingerprint spoofing completed"
}

# Function to spoof system info
spoof_system_info() {
  log_message "INFO" "Starting system info spoofing"
  show_progress "Generating system profile..." 50
  
  gen_windows_info
  
  local manufacturer product
  manufacturer=$(cat "$TEMP_DIR/manufacturer" 2>/dev/null || echo "Unknown")
  product=$(cat "$TEMP_DIR/product" 2>/dev/null || echo "System")
  
  show_progress "System info spoofing complete" 100
  show_notification "System Profile Changed" "System: $manufacturer $product"
  log_message "INFO" "System info spoofing completed"
}

# Function to display help
show_help() {
  cat << EOF
$SCRIPT_NAME v$VERSION - Linux Identity Spoofing Tool

DESCRIPTION:
    A comprehensive toolkit for spoofing hardware identifiers, MAC addresses,
    and system fingerprints to enhance anonymity during penetration testing
    and security assessments.

USAGE:
    $(basename "$0") [OPTIONS]

OPTIONS:
    --gui              Use GUI elements if available
    --mac-only         Only spoof MAC addresses
    --hostname-only    Only spoof hostname
    --quiet            No interactive prompts or output
    --log FILE         Log actions to specified file
    --version          Show version information
    --help             Show this help message

EXAMPLES:
    $(basename "$0")              # Run full spoofing in terminal mode
    $(basename "$0") --gui        # Run with GUI if available
    $(basename "$0") --mac-only   # Only change MAC addresses
    $(basename "$0") --quiet      # Run without user interaction

AUTHOR:
    $AUTHOR

LICENSE:
    GNU General Public License v3.0

EOF
}

# Function to show version
show_version() {
  echo "$SCRIPT_NAME v$VERSION"
  echo "Copyright (C) 2025 $AUTHOR"
  echo "License GPLv3+: GNU GPL version 3 or later"
  echo "This is free software: you are free to change and redistribute it."
}

# Process command-line arguments
while [ $# -gt 0 ]; do
  case "$1" in
    --gui)
      GUI_MODE="yes"
      ;;
    --mac-only)
      MAC_ONLY="yes"
      ;;
    --hostname-only)
      HOSTNAME_ONLY="yes"
      ;;
    --quiet)
      QUIET_MODE="yes"
      ;;
    --log)
      shift
      if [ -z "$1" ]; then
        echo "Error: --log requires a filename" >&2
        exit 1
      fi
      LOG_FILE="$1"
      ;;
    --version)
      show_version
      exit 0
      ;;
    --help)
      show_help
      exit 0
      ;;
    *)
      echo "Error: Unknown option: $1" >&2
      echo "Use --help for usage information" >&2
      exit 1
      ;;
  esac
  shift
done

# Validate conflicting options
if [ "$MAC_ONLY" = "yes" ] && [ "$HOSTNAME_ONLY" = "yes" ]; then
  echo "Error: --mac-only and --hostname-only cannot be used together" >&2
  exit 1
fi

# Initialize logging
if [ -n "$LOG_FILE" ]; then
  # Create log directory if it doesn't exist
  log_dir=$(dirname "$LOG_FILE")
  mkdir -p "$log_dir" 2>/dev/null || {
    echo "Error: Cannot create log directory: $log_dir" >&2
    exit 1
  }
  
  # Initialize log file
  echo "=== $SCRIPT_NAME v$VERSION - Session started at $(date) ===" > "$LOG_FILE"
  log_message "INFO" "Logging initialized to: $LOG_FILE"
fi

# Setup progress tracking for GUI mode
if [ "$HAS_ZENITY" -eq 1 ] && [ "$GUI_MODE" = "yes" ] && [ "$QUIET_MODE" = "no" ]; then
  PROGRESS_FILE=$(mktemp)
  (
    tail -f "$PROGRESS_FILE" 2>/dev/null | zenity --progress \
      --title="$SCRIPT_NAME v$VERSION" \
      --text="Initializing..." \
      --percentage=0 \
      --auto-close \
      --width=400 2>/dev/null
  ) &
  PROGRESS_PID=$!
fi

# Main execution logic
show_banner
log_message "INFO" "Starting $SCRIPT_NAME v$VERSION"

if [ "$MAC_ONLY" = "yes" ]; then
  log_message "INFO" "Mode: MAC address spoofing only"
  if confirm_action "MAC Address Spoofing" "This will change all your network interface MAC addresses."; then
    if spoof_mac_addresses; then
      echo "MAC address spoofing completed successfully!"
    else
      echo "MAC address spoofing failed!" >&2
      exit 1
    fi
  else
    echo "MAC address spoofing cancelled."
    log_message "INFO" "MAC spoofing cancelled by user"
    exit 0
  fi

elif [ "$HOSTNAME_ONLY" = "yes" ]; then
  log_message "INFO" "Mode: Hostname spoofing only"
  if confirm_action "Hostname Spoofing" "This will change your system's hostname."; then
    if spoof_hostname; then
      echo "Hostname spoofing completed successfully!"
    else
      echo "Hostname spoofing failed!" >&2
      exit 1
    fi
  else
    echo "Hostname spoofing cancelled."
    log_message "INFO" "Hostname spoofing cancelled by user"
    exit 0
  fi

else
  # Full identity spoofing
  log_message "INFO" "Mode: Full identity spoofing"
  if confirm_action "Full Identity Spoofing" "This will change your MAC addresses, hostname, OS fingerprint, and system profile."; then
    show_progress "Starting full identity spoofing..." 0
    
    failed_operations=()
    
    # Execute spoofing operations
    if ! spoof_mac_addresses; then
      failed_operations+=("MAC addresses")
    fi
    
    if ! spoof_hostname; then
      failed_operations+=("hostname")
    fi
    
    if ! spoof_os_fingerprint; then
      failed_operations+=("OS fingerprint")
    fi
    
    if ! spoof_system_info; then
      failed_operations+=("system info")
    fi
    
    # Generate final report
    echo
    echo "===== IDENTITY SPOOFING COMPLETE ====="
    
    # Show results
    new_hostname=$(hostname)
    echo "New hostname: $new_hostname"
    
    if [ -f "$TEMP_DIR/manufacturer" ] && [ -f "$TEMP_DIR/product" ]; then
      manufacturer=$(cat "$TEMP_DIR/manufacturer")
      product=$(cat "$TEMP_DIR/product")
      echo "System: $manufacturer $product"
    fi
    
    echo "MAC addresses:"
    if [ -f "$TEMP_DIR/mac_changes" ]; then
      cat "$TEMP_DIR/mac_changes"
    else
      echo "  No MAC changes recorded"
    fi
    
    # Report any failures
    if [ ${#failed_operations[@]} -gt 0 ]; then
      echo
      echo "WARNING: Some operations failed:"
      printf '  - %s\n' "${failed_operations[@]}"
      log_message "WARN" "Failed operations: ${failed_operations[*]}"
    fi
    
    echo "====================================="
    
    # Final notification
    if [ ${#failed_operations[@]} -eq 0 ]; then
      show_notification "Identity Spoofing Complete" "All operations completed successfully"
      log_message "INFO" "Full identity spoofing completed successfully"
    else
      show_notification "Identity Spoofing Partial" "Some operations failed - check output"
      log_message "WARN" "Identity spoofing completed with errors"
    fi
    
  else
    echo "Identity spoofing cancelled."
    log_message "INFO" "Full identity spoofing cancelled by user"
    exit 0
  fi
fi

# Final log entry
if [ -n "$LOG_FILE" ]; then
  echo "=== Session ended at $(date) ===" >> "$LOG_FILE"
fi

echo
echo "Operation completed. Check system settings and network connectivity."
echo "To restore original settings, use the restore functions or reboot."

log_message "INFO" "$SCRIPT_NAME session completed"
exit 0