#!/bin/bash
echo "[start-ovs] Starting user-space OVS..."

# Start ovsdb-server
ovsdb-server \
  --remote=punix:/var/run/openvswitch/db.sock \
  --remote=ptcp:6640:127.0.0.1 \
  --pidfile --detach

# Initialize DB if needed
ovs-vsctl --db=unix:/var/run/openvswitch/db.sock --no-wait init

# Start ovs-vswitchd
ovs-vswitchd unix:/var/run/openvswitch/db.sock \
  --pidfile --detach

echo "[start-ovs] OVS is running. Handing over to Kathara startup..."

exec /bin/bash

