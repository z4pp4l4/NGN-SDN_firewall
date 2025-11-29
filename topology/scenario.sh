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

# 1. NORMAL BASELINE TRAFFIC
echo "[STEP 1] Sending normal traffic..."
kathara exec h1 -- nc -l -p 2020 -k &
kathara exec h2 -- nc -l -p 2020 -k &
sleep 2
kathara exec h1 -- nc -zvw1 $TARGET_IP 2020 
kathara exec h2 -- nc -zvw1 $TARGET_IP 2020 
echo "[OK] Baseline traffic sent."
echo

#to hide the stderr / stdout => >/dev/null 2>&1
# 2. SMALL ATTACK TEST (should NOT trigger firewall)
echo "[STEP 2] Small burst test (should not be detected)..."
for i in {1..10}; do
  kathara exec ext1 -- hping3 -S -p $TARGET_PORT --count 1 $TARGET_IP  
done
echo "[OK] Small test completed."
echo

# 3. REAL DoS ATTACK (this SHOULD trigger firewall)
echo "[STEP 3] Launching DoS attack (should trigger firewall)..."
kathara exec ext1 -- hping3 -S -p $TARGET_PORT -i u1000 --flood $TARGET_IP &
HPING_PID=$!
sleep 3
kill $HPING_PID 
echo "[OK] Flood completed."
echo

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
echo "[STEP 5] Waiting for firewall timeout (10 seconds)..."
sleep 10

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


