The network config:


### Controller
subnet: 192.168.100.0/30
controller side= 192.168.100.1/30
switcher side= 192.168.100.2/30 (eth0 / A)

### Internal network
subnet: 192.168.10.0/29
3 hosts : 192.168.10.1/29 - 192.168.10.2/29 - 192.168.10.3/29
attached to s1[1]=B
connected to eth1 port of s1

### Internal network
subnet: 192.168.10.0/29
3 hosts : 192.168.10.1/29 - 192.168.10.2/29 - 192.168.10.3/29
attached to s1[1]=B
connected to eth1 port of s1

### External network
subnet: 192.168.20.0/28
7 hosts : 192.168.20.1/28 - ... - 192.168.20.7/28
attached to s1[2]=C
connected to eth2 port of s1

### switcher
s1[0]=A ==> controller
S1[1]=B ==> internal
s1[2]=C ==> external
(for MAC addresses)

gateway:
internal side: 192.168.10.4/29
external side: 192.168.20.8/28

######## 24/11 update
* the SDN topology works 
* addresses and gateways are configured
* hosts within the same subnet can connect but the inter-subnet connectivity is not yet implemented, it's gonna be handled by the firewall/ L3 ryu app. I will collaborate with leo about this last part (i can do the basic firewall which doesn't block anything)

######## 25/11 update
i've done the L3switch.py file that enables inter-subnet communication (without any rule)

usage to start lab :
cd topology
./start-lab.sh

to stop lab: 
./stop-lab.sh

usage of the gui:
cd GUI/
source venv/bin/activate
python3 gui.py
