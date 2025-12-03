#!/bin/bash

echo "[INFO] Starting DoS scenario test..."
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

# 1. NORMAL BASELINE TRAFFIC
echo "[STEP 1] Sending normal traffic..."
kathara exec h1 -- nc -zvw1 $TARGET_IP $TARGET_PORT 
echo "[OK] Baseline traffic sent."
echo

# 2. SMALL ATTACK TEST (should NOT trigger firewall)
echo "[STEP 2] Small burst test (should not be detected)..."
for i in {1..5}; do
  kathara exec ext1 -- hping3 -S -p $TARGET_PORT --count 1 $TARGET_IP 
done
echo "[OK] Small test completed (5 packets sent)."
echo

# 3. REAL DoS ATTACK (this SHOULD trigger firewall)
echo "[STEP 3] Launching DoS attack (should trigger firewall)..."
echo "Sending 20 rapid SYN packets to exceed threshold..."

# Send 20 packets rapidly in parallel (threshold is 10 packets in 3 seconds)
for i in {1..20}; do
  kathara exec ext1 -- hping3 -S -p $TARGET_PORT --count 1 $TARGET_IP >/dev/null 2>&1 &
done

# Wait for all background processes to complete
wait

echo "[OK] Attack completed (20 packets sent)."
echo

# Give firewall time to process and install block rule
sleep 2

# 4. CHECK THAT FIREWALL BLOCKED ext1
echo "[STEP 4] Testing if attacker is blocked..."
kathara exec ext1 -- nc -zvw1 $TARGET_IP $TARGET_PORT
if [ $? -ne 0 ]; then
    echo "[SUCCESS] Attacker ext1 is BLOCKED by the firewall."
else
    echo "[FAIL] Attacker ext1 is NOT blocked!"
fi
echo

# 5. WAIT FOR RULE TIMEOUT
echo "[STEP 5] Waiting for firewall timeout (20 seconds)..."
sleep 20

# 6. TEST THAT BLOCK IS REMOVED AFTER TIMEOUT
echo "[STEP 6] Checking if attacker is unblocked after rule expiration..."
kathara exec ext1 -- nc -zvw1 $TARGET_IP $TARGET_PORT
if [ $? -eq 0 ]; then
    echo "[SUCCESS] Attacker ext1 is UNBLOCKED (timeout works)."
else
    echo "[FAIL] Attacker still blocked after timeout!"
fi

echo
echo "-------------------------------------"
echo "[INFO] DoS scenario test completed."
