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
kathara exec h1 -- nc -zvw1 192.168.10.1 2020 
echo "[OK] Baseline traffic sent."
echo

#to hide the stderr / stdout => >/dev/null 2>&1
# 2. SMALL ATTACK TEST (should NOT trigger firewall)
echo "[STEP 2] Small burst test (should not be detected)..."
for i in {1..10}; do
  kathara exec ext1 -- hping3 -S -p $TARGET_PORT --count 1 $TARGET_IP # 
done
echo "[OK] Small test completed."
echo

# 3. REAL DoS ATTACK (this SHOULD trigger firewall)
# Sending 150+ packets in 10 seconds to exceed threshold of 100
echo "[STEP 3] Launching DoS attack (should trigger firewall)..."
echo "Running hping3 flood for 12 seconds to ensure detection..."
#kathara exec ext1 -- hping3 -S -p $TARGET_PORT --flood $TARGET_IP > /dev/null 2>&1 &
#is executed 10 times, generating 10 rapid SYN packets.

kathara exec ext1 -- hping3 -S -p $TARGET_PORT --rand-source --count 1 $TARGET_IP > /dev/null 2>&1 &

#--rand-source removes all SYN collisions.


HPING_PID=$!

# Let it run for 12 seconds to ensure we exceed 100 packets in the 10-second window
sleep 12
kathara exec ext1 -- pkill -9 hpin
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
sleep 15

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


