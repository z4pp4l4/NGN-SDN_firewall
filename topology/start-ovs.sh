#!/bin/bash
set -e

echo "[s1] Initializing Open vSwitch..."

# Create DB if missing
if [ ! -f /etc/openvswitch/conf.db ]; then
  ovsdb-tool create /etc/openvswitch/conf.db /usr/share/openvswitch/vswitch.ovsschema
fi

# Start ovsdb-server + ovs-vswitchd
/usr/share/openvswitch/scripts/ovs-ctl start --system-id=random

# Give it a moment
sleep 1

echo "[s1] OVS started. Handing control to shell."
exec bash

