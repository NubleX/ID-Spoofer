#!/bin/bash

# ID-Spoofer Installer v1.0.0
# Author: Igor Dunaev / NubleX
# This script installs all components of the ID-Spoofer toolkit

set -e  # Exit on any error

# Script metadata
VERSION="1.0.0"
SCRIPT_NAME="ID-Spoofer Installer"
INSTALL_PREFIX="/usr/local"
DESKTOP_PREFIX="/usr/share"

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
    echo -e "${BLUE}"
    echo "╔════════════════════════════════════════════════╗"
    echo "║       ID-SPOOFER INSTALLER v$VERSION            ║"
    echo "║       Linux Identity Spoofing Tool             ║"
    echo "╚════════════════════════════════════════════════╝"
    echo -e "${NC}"
}

# Check if running as root
check_root() {
    if [ "$EUID" -ne 0 ]; then
        print_status "ERROR" "This installer must be run as root"
        echo "Usage: sudo $0"
        exit 1
    fi
}

# Detect distribution
detect_distro() {
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        DISTRO="$ID"
        VERSION_ID="$VERSION_ID"
    elif [ -f /etc/debian_version ]; then
        DISTRO="debian"
    elif [ -f /etc/redhat-release ]; then
        DISTRO="rhel"
    else
        DISTRO="unknown"
    fi
    
    print_status "INFO" "Detected distribution: $DISTRO"
}

# Install dependencies based on distribution
install_dependencies() {
    print_status "INFO" "Installing dependencies for $DISTRO..."
    
    case "$DISTRO" in
        "ubuntu"|"debian"|"kali")
            apt-get update -qq
            apt-get install -y macchanger net-tools iproute2 zenity libnotify-bin
            ;;
        "fedora")
            dnf install -y macchanger net-tools iproute zenity libnotify
            ;;
        "rhel"|"centos"|"rocky"|"almalinux")
            if command -v dnf >/dev/null 2>&1; then
                dnf install -y epel-release
                dnf install -y macchanger net-tools iproute zenity libnotify
            else
                yum install -y epel-release
                yum install -y macchanger net-tools iproute zenity libnotify
            fi
            ;;
        "arch"|"manjaro")
            pacman -Sy --noconfirm macchanger net-tools iproute2 zenity libnotify
            ;;
        "opensuse"|"sles")
            zypper install -y macchanger net-tools iproute2 zenity libnotify-tools
            ;;
        *)
            print_status "WARN" "Unknown distribution. Please install dependencies manually:"
            echo "  Required: macchanger, net-tools, iproute2"
            echo "  Optional: zenity, libnotify-bin (for GUI support)"
            read -p "Continue anyway? (y/N): " -r
            if [[ ! $REPLY =~ ^[Yy]$ ]]; then
                exit 1
            fi
            ;;
    esac
    
    print_status "OK" "Dependencies installed successfully"
}

# Verify required tools are available
verify_tools() {
    print_status "INFO" "Verifying required tools..."
    
    local required_tools=("macchanger" "ip" "hostname" "sysctl")
    local missing_tools=()
    
    for tool in "${required_tools[@]}"; do
        if ! command -v "$tool" >/dev/null 2>&1; then
            missing_tools+=("$tool")
        fi
    done
    
    if [ ${#missing_tools[@]} -gt 0 ]; then
        print_status "ERROR" "Missing required tools: ${missing_tools[*]}"
        print_status "ERROR" "Please install missing dependencies and try again"
        exit 1
    fi
    
    print_status "OK" "All required tools are available"
}

# Install main scripts
install_scripts() {
    print_status "INFO" "Installing spoofer scripts..."
    
    # Check if source files exist
    if [ ! -f "src/bin/hardware-spoof.sh" ]; then
        print_status "ERROR" "Source file not found: src/bin/hardware-spoof.sh"
        print_status "ERROR" "Please run this installer from the project root directory"
        exit 1
    fi
    
    # Install main script
    cp "src/bin/hardware-spoof.sh" "$INSTALL_PREFIX/bin/"
    chmod +x "$INSTALL_PREFIX/bin/hardware-spoof.sh"
    
    # Install menu script if it exists
    if [ -f "src/bin/idspoof-menu.sh" ]; then
        cp "src/bin/idspoof-menu.sh" "$INSTALL_PREFIX/bin/"
        chmod +x "$INSTALL_PREFIX/bin/idspoof-menu.sh"
    fi
    
    # Create symbolic links
    ln -sf "$INSTALL_PREFIX/bin/hardware-spoof.sh" "$INSTALL_PREFIX/bin/idspoof"
    
    if [ -f "$INSTALL_PREFIX/bin/idspoof-menu.sh" ]; then
        ln -sf "$INSTALL_PREFIX/bin/idspoof-menu.sh" "$INSTALL_PREFIX/bin/idspoof-menu"
    fi
    
    print_status "OK" "Scripts installed successfully"
}

# Install desktop integration
install_desktop_integration() {
    print_status "INFO" "Installing desktop integration..."
    
    if [ -f "src/share/applications/hardware-spoofer.desktop" ]; then
        # Install desktop file
        cp "src/share/applications/hardware-spoofer.desktop" "$DESKTOP_PREFIX/applications/"
        
        # Update desktop database if available
        if command -v update-desktop-database >/dev/null 2>&1; then
            update-desktop-database "$DESKTOP_PREFIX/applications/" 2>/dev/null || true
        fi
        
        print_status "OK" "Desktop integration installed"
    else
        print_status "WARN" "Desktop file not found, skipping desktop integration"
    fi
}

# Create uninstaller
create_uninstaller() {
    print_status "INFO" "Creating uninstaller..."
    
    cat > "$INSTALL_PREFIX/bin/idspoof-uninstall" << 'EOF'
#!/bin/bash

# ID-Spoofer Uninstaller

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    echo "Error: Uninstaller must be run as root"
    exit 1
fi

echo "Uninstalling ID-Spoofer..."

# Remove scripts
rm -f /usr/local/bin/hardware-spoof.sh
rm -f /usr/local/bin/idspoof-menu.sh
rm -f /usr/local/bin/idspoof
rm -f /usr/local/bin/idspoof-menu
rm -f /usr/local/bin/idspoof-uninstall

# Remove desktop integration
rm -f /usr/share/applications/hardware-spoofer.desktop

# Update desktop database
if command -v update-desktop-database >/dev/null 2>&1; then
    update-desktop-database /usr/share/applications/ 2>/dev/null || true
fi

echo "ID-Spoofer has been uninstalled."
echo "Note: Dependencies were not removed. Uninstall manually if needed."
EOF

    chmod +x "$INSTALL_PREFIX/bin/idspoof-uninstall"
    print_status "OK" "Uninstaller created at $INSTALL_PREFIX/bin/idspoof-uninstall"
}

# Setup systemd service (optional)
setup_systemd_service() {
    if [ -d "/etc/systemd/system" ] && command -v systemctl >/dev/null 2>&1; then
        print_status "INFO" "Setting up systemd service (optional)..."
        
        cat > "/etc/systemd/system/idspoof-restore.service" << EOF
[Unit]
Description=ID-Spoofer MAC Address Restore Service
DefaultDependencies=false
Before=network-pre.target
Wants=network-pre.target

[Service]
Type=oneshot
ExecStart=/bin/bash -c 'for iface in \$(ip -o link show | awk -F": " "{print \$2}" | grep -v lo); do macchanger -p \$iface 2>/dev/null || true; done'
RemainAfterExit=true

[Install]
WantedBy=multi-user.target
EOF
        
        systemctl daemon-reload
        print_status "OK" "Systemd service created (disabled by default)"
        print_status "INFO" "To enable MAC restore on boot: systemctl enable idspoof-restore"
    fi
}

# Post-installation setup
post_install_setup() {
    print_status "INFO" "Performing post-installation setup..."
    
    # Create log directory
    mkdir -p /var/log/idspoof
    chmod 755 /var/log/idspoof
    
    # Set appropriate permissions
    chmod 755 "$INSTALL_PREFIX/bin/hardware-spoof.sh"
    if [ -f "$INSTALL_PREFIX/bin/idspoof-menu.sh" ]; then
        chmod 755 "$INSTALL_PREFIX/bin/idspoof-menu.sh"
    fi
    
    print_status "OK" "Post-installation setup completed"
}

# Main installation function
main() {
    print_banner
    
    print_status "INFO" "Starting installation..."
    
    check_root
    detect_distro
    install_dependencies
    verify_tools
    install_scripts
    install_desktop_integration
    create_uninstaller
    setup_systemd_service
    post_install_setup
    
    echo
    print_status "OK" "Installation completed successfully!"
    echo
    echo -e "${GREEN}You can now use ID-Spoofer with the following commands:${NC}"
    echo "  sudo idspoof                    # Full identity spoofing"
    echo "  sudo idspoof --gui              # GUI mode (if available)"
    echo "  sudo idspoof --mac-only         # MAC addresses only"
    echo "  sudo idspoof --hostname-only    # Hostname only"
    echo "  sudo idspoof --help             # Show help"
    echo
    if [ -f "$INSTALL_PREFIX/bin/idspoof-menu.sh" ]; then
        echo "  sudo idspoof-menu               # Interactive menu"
        echo
    fi
    echo -e "${BLUE}Desktop integration:${NC}"
    echo "  Look for 'ID-Spoofer' in your application menu"
    echo
    echo -e "${YELLOW}Important notes:${NC}"
    echo "  - Always run with sudo/root privileges"
    echo "  - Use responsibly and only on systems you own or have permission to test"
    echo "  - MAC address changes may temporarily disrupt network connectivity"
    echo "  - To uninstall: sudo idspoof-uninstall"
    echo
}

# Run main function
main "$@"