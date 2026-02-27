#!/bin/bash

# Menu-based Hardware Spoofing Tool for Linux
# Author: Igor Dunaev / NubleX

# Check if running as root
if [ "$EUID" -ne 0 ]; then
  echo "Please run as root"
  exit 1
fi

# ANSI color codes
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Clear the terminal
clear

echo -e "${BLUE}██╗██████╗     ███████╗██████╗  ██████╗  ██████╗ ███████╗███████╗██████╗ ${NC}"
echo -e "${BLUE}██║██╔══██╗    ███╔═══╝██╔══██╗██╔═══██╗██╔═══██╗██╔════╝██╔════╝██╔══██╗${NC}"
echo -e "${BLUE}██║██║  ██║    ███████╗██████╔╝██║   ██║██║   ██║█████╗  █████╗  ██████╔╝${NC}"
echo -e "${BLUE}██║██║  ██║    ╚════██║██╔═══╝ ██║   ██║██║   ██║██╔══╝  ██╔══╝  ██╔══██╗${NC}"
echo -e "${BLUE}██║██████╔╝    ███████║██║     ╚██████╔╝╚██████╔╝██║     ███████╗██║  ██║${NC}"
echo -e "${BLUE}╚═╝╚═════╝     ╚══════╝╚═╝      ╚═════╝  ╚═════╝ ╚═╝     ╚══════╝╚═╝  ╚═╝${NC}"
echo
echo -e "${GREEN}Identity and Network Fingerprint Spoofing Tool${NC}"
echo -e "${YELLOW}----------------------------------------------${NC}"
echo

# Function to check current system information
show_current_info() {
  echo -e "${YELLOW}Current System Information:${NC}"
  echo -e "${BLUE}Hostname:${NC} $(hostname)"
  echo -e "${BLUE}MAC Addresses:${NC}"
  ip link | grep -A 1 "^[0-9]" | grep -v "lo" | grep "link" | awk '{print "  " $2}'
  echo -e "${BLUE}IP Addresses:${NC}"
  ip addr | grep "inet " | grep -v "127.0.0.1" | awk '{print "  " $2}'
  echo -e "${BLUE}System:${NC} $(grep -m 1 "system" /etc/os-release | cut -d'"' -f 2)"
  echo
}

# Main menu
show_menu() {
  echo -e "${GREEN}Available Options:${NC}"
  echo -e "  ${BLUE}1)${NC} Spoof MAC Addresses Only"
  echo -e "  ${BLUE}2)${NC} Spoof Hostname Only"
  echo -e "  ${BLUE}3)${NC} Spoof Full System (MAC, Hostname, TCP/IP Stack)"
  echo -e "  ${BLUE}4)${NC} Show Current System Information"
  echo -e "  ${BLUE}5)${NC} Restore Original MAC Addresses"
  echo -e "  ${BLUE}0)${NC} Exit"
  echo
  echo -ne "${YELLOW}Enter your choice [0-5]:${NC} "
  read choice
  echo
}

# Function to spoof MAC addresses only
spoof_mac_only() {
  echo -e "${YELLOW}Spoofing MAC Addresses...${NC}"
  sudo /usr/local/bin/hardware-spoof.sh --mac-only
  echo
  echo -e "${GREEN}Press Enter to continue...${NC}"
  read
}

# Function to spoof hostname only
spoof_hostname_only() {
  echo -e "${YELLOW}Spoofing Hostname...${NC}"
  sudo /usr/local/bin/hardware-spoof.sh --hostname-only
  echo
  echo -e "${GREEN}Press Enter to continue...${NC}"
  read
}

# Function to perform full system spoofing
spoof_full_system() {
  echo -e "${YELLOW}Performing Full System Spoofing...${NC}"
  sudo /usr/local/bin/hardware-spoof.sh
  echo
  echo -e "${GREEN}Press Enter to continue...${NC}"
  read
}

# Function to restore original MAC addresses
restore_mac() {
  echo -e "${YELLOW}Restoring Original MAC Addresses...${NC}"
  
  for interface in $(ip -o link show | awk -F': ' '{print $2}' | grep -v "lo"); do
    echo "Resetting $interface to permanent MAC"
    ip link set $interface down
    macchanger -p $interface
    ip link set $interface up
  done
  
  echo -e "${GREEN}Done!${NC}"
  echo
  echo -e "${GREEN}Press Enter to continue...${NC}"
  read
}

# Main loop
while true; do
  clear
  show_current_info
  show_menu
  
  case $choice in
    1) spoof_mac_only ;;
    2) spoof_hostname_only ;;
    3) spoof_full_system ;;
    4) 
      echo -e "${GREEN}Press Enter to continue...${NC}"
      read
      ;;
    5) restore_mac ;;
    0) 
      echo -e "${GREEN}Exiting...${NC}"
      exit 0
      ;;
    *)
      echo -e "${RED}Invalid option. Press Enter to continue...${NC}"
      read
      ;;
  esac
done
