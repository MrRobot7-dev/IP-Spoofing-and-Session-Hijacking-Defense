# IP Spoofing and Session Hijacking Defense System

This project demonstrates the practical detection and mitigation of **IP Spoofing** and **Session Hijacking** attacks using open-source tools in a virtual lab environment.

## 🧪 Project Objective

To simulate and mitigate common network attacks using tools like **Wireshark**, **Snort**, **iptables**, **hping3**, and **Ettercap** in a controlled VM setup.

## 🖥️ Test Environment

- Virtualization: **VMware Workstation**
- OS: Ubuntu 22.04 (Attacker, Victim, and REMnux VM as Server)
- Tools Used: `Wireshark`, `Snort`, `iptables`, `hping3`, `arpspoof`, `Ettercap`, `net-tools`

## ⚔️ Attacks Simulated

### 1. IP Spoofing
- Simulated using `hping3` to forge packets with spoofed IP addresses.
- Detection with **Snort** and **Wireshark**.
- Mitigation using `iptables` rules.

### 2. Session Hijacking
- Conducted using `Ettercap` to intercept and manipulate sessions.
- Detection of cleartext credentials via **Wireshark**.
- Defense by enabling **HTTPS** and blocking spoofed ARP packets.

## 🧰 Tools and Commands

All simulation and defense scripts are stored in the [`/scripts`](./scripts) directory:
- `ip_spoofing_attack.sh`
- `ip_spoofing_defense.sh`
- `session_hijacking_attack.sh`
- `session_hijacking_defense.sh`

Each script contains step-by-step commands to run attacks and mitigations.

## 🔒 Key Defenses Implemented

- IDS-based alerting using **Snort** rules.
- Manual and automated blocking via **iptables**.
- ARP spoofing detection using `arpspoof` and network behavior.
- Hardening communication with **SSL (HTTPS)** to prevent credential theft.

## 🧠 Learning Outcome

- Deepened understanding of network protocol abuse.
- Practical skills in detection, analysis, and mitigation of network threats.

## ⚙️ Requirements

```bash
sudo apt update
sudo apt install snort wireshark iptables hping3 ettercap-graphical net-tools apache2
```

Or use the requirements.txt provided.
