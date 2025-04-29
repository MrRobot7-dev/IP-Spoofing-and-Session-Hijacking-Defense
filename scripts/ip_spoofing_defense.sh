#!/bin/bash

# ---------------------------
# 1. INSTALL DEPENDENCIES
# ---------------------------
echo "[*] Installing required packages..."
sudo apt update
sudo apt install -y snort tcpdump iptables

# ---------------------------
# 2. CONFIGURE SNORT RULES
# ---------------------------
echo "[*] Setting up Snort custom rules for IP spoofing and SYN flood detection..."

RULES_FILE="/etc/snort/rules/local.rules"

read -r -d '' CUSTOM_RULES << EORULES
# Detect SYN Flood Attack
alert tcp any any -> any 80 (msg:"Potential SYN Flood Attack"; flags:S; detection_filter:track by_src, count 20, seconds 1; sid:1000001; rev:1;)

# Detect IP Spoofing
alert ip any any -> any any (msg:"IP Spoofing Detected"; ipopts:rr; sid:1000002; rev:1;)

# Detect SYN Flood with Spoofed IPs
alert tcp any any -> any 80 (msg:"Possible SYN Flood with Spoofed IPs"; flags:S; detection_filter:track by_dst, count 50, seconds 1; sid:1000003; rev:1;)
EORULES

for SID in 1000001 1000002 1000003; do
  if grep -q "sid:$SID" "$RULES_FILE"; then
    echo "[*] Rule with sid:$SID already exists in local.rules"
  else
    echo "[+] Adding rule with sid:$SID..."
    echo "$CUSTOM_RULES" | sudo tee -a "$RULES_FILE" > /dev/null
    break
  fi
done

# ---------------------------
# 3. RUN SNORT TO MONITOR
# ---------------------------
echo "[*] Running Snort in IDS mode to detect spoofing and SYN floods..."
sudo snort -A console -q -u snort -g snort -c /etc/snort/snort.conf -i enp0s3 &

# ---------------------------
# 4. AUTOMATED BLOCKING SCRIPT
# ---------------------------
echo "[*] Launching automated spoofed IP blocking system..."

CAPTURED_FILE="captured_ips.txt"
BLOCK_DURATION=300

> "$CAPTURED_FILE"

run_tcpdump() {
  sudo tcpdump -i enp0s3 -nn -tttt -U | \
  awk '/seq/ {print $0}' | \
  awk '{split($0, a, "seq "); if (a[2] > 1324580000) print $4}' | \
  cut -d'.' -f1-4 | \
  while read ip; do
    if ! grep -qx "$ip" "$CAPTURED_FILE"; then
      echo "$ip" >> "$CAPTURED_FILE"
    fi
  done &
  TCPDUMP_PID=$!
}

block_ip_for_duration() {
  local ip=$1
  if ! sudo iptables -C INPUT -s "$ip" -j DROP 2>/dev/null; then
    sudo iptables -A INPUT -s "$ip" -j DROP
    sudo iptables -A INPUT -s "$ip" -j LOG --log-prefix "Dropped spoofed traffic: "
  fi
  sleep $BLOCK_DURATION
  sudo iptables -D INPUT -s "$ip" -j DROP
}

run_tcpdump

while true; do
  if [[ -s "$CAPTURED_FILE" ]]; then
    break
  fi
  sleep 2
done

cat "$CAPTURED_FILE" | sort | uniq | while read -r ip; do
  block_ip_for_duration "$ip" &
done

wait

