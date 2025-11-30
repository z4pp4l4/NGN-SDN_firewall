#!/bin/bash
kathara lstart

sleep 1
kathara lconfig -n wireshark --add A

# Pre-populate ARP tables
echo "[INFO] Warming up ARP caches..."

# Internal hosts to external attackers
for i in 1 2 3; do
  for j in 1 2 3 4 5 6 7; do
    kathara exec h$i -- ping -c1 -W1 192.168.20.$((j+1)) >/dev/null 2>&1
  done
  echo "h$i completed..."
done

echo "[INFO] ARP warm-up completed."



