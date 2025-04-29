#!/bin/bash

# Starting ARP Detection
LEGIT_MAC_TABLE='/tmp/legit_mac_table.txt'
TEMP_ARP_TABLE='/tmp/temp_arp_table.txt'

# Function to check if ARP spoofing is happening
block_arp_spoofing() {
    local attacker_ip=$1
    local target_ip=$2
    if grep -q "$attacker_ip" "$LEGIT_MAC_TABLE" && grep -q "$target_ip" "$LEGIT_MAC_TABLE"; then
        echo "Rule already exists for Attacker IP: $attacker_ip and Target IP: $target_ip"
    else
        echo "Blocking ARP spoofing: Attacker IP $attacker_ip spoofing Target IP $target_ip"
        sudo iptables -A INPUT -d "$target_ip" -s "$attacker_ip" -j DROP
    fi
}

# Function to detect ARP spoofing
detect_arp_spoofing() {
    arp -n | awk '/^[0-9.]+/ {print $1,$3}' > "$TEMP_ARP_TABLE"
    while read -r ip mac; do
        if grep -q "$ip" "$LEGIT_MAC_TABLE"; then
            legit_mac=$(grep "$ip" "$LEGIT_MAC_TABLE" | awk '{print $2}')
            if [[ "$legit_mac" != "$mac" ]]; then
                echo "ARP spoof detected! IP: $ip is spoofed by MAC: $mac"
                block_arp_spoofing "$ip" "$mac"
            fi
        else
            echo "$ip $mac" >> "$LEGIT_MAC_TABLE"
            echo "Added Legitimate IP-MAC pair: $ip -> $mac"
        fi
    done < "$TEMP_ARP_TABLE"
}

# Main script to start ARP spoofing detection
echo "Starting ARP spoof detection..."
while true; do
    detect_arp_spoofing
    sleep 5
done

