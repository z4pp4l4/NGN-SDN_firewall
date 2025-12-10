#!/bin/bash

echo "[INFO] WARMING UP ARP CACHES..."
echo "-------------------------------------"
echo

# INTERNAL HOSTS
INT_HOSTS=("h1" "h2" "h3")

# EXTERNAL ATTACKERS
ATTACKERS=("ext1" "ext2" "ext3" "ext4" "ext5" "ext6" "ext7")
TARGET_IP="192.168.10.1"         # target inside internal subnet
TARGET_PORT="2020"               # monitored port in firewall

# Pre-populate ARP tables
echo "[INFO] Warming up ARP caches..."
for i in 1 2 3; do
  for j in 1 2 3 4 5 6 7; do
      kathara exec h$i -- ping -c1 -W1 192.168.20.$((j+1)) >/dev/null 2>&1
  done
  echo "h$i completed..."
done
echo "[INFO] ARP warm-up completed."
echo
