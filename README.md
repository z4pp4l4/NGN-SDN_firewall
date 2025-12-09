# NGN-SDN_firewall
Project for the "Next generation networks" course

**Overview**

The aim of this project is to create a SDN with three main features:
- a simulated network with two main LANs, one that should mimic a small company and the other a larger network
- have a switch that should control the traffic between the company and the emulated Internet, acting therefore as a firewall
- have a simple GUI that displays the network topology and shows packets flowing in the network

**Design and Methodologies**

The network was simulated using [kathara](https://www.kathara.org/). When the lab starts, the [OVS](https://www.openvswitch.org/) switch is configured to connect to the [Ryu](https://ryu.readthedocs.io/en/latest/parameters.html) controller which sends FlowMod instructions to the switch that can later apply them to handle the traffic between the networks.
For what concerns the GUI, we used [customtkinter](https://customtkinter.tomschimansky.com/) to show a simple display of the topology. What is most interesting about the frontend part of our project is how we show packets that are flowing in the network. To do this part we found of particular use the python library [Scapy](https://scapy.readthedocs.io/en/latest/) that sniffed packets flowing in the katharà simulated network. We now needed a way to communicate these packets to the host OS, for this we used an hostpipe that was configured (inside lab.conf) as: 
```bash
hostpipe[bridged]=true
```
this gave us a way to communicate with the host through the hostpipe interface, we then needed to setup another network alongside a route for the switch so that it could know a way to reach "172.17.0.1" (which is the ip address of the host according to the Docker configuration).
At this point we simply had a script that sniffed packets flowing in the network and opened a TCP connection on port 5000 to connect the isolated network with the GUI which used a thread to listen for the connection and check for incoming packets.
The same method was also applied to the controller that had the job of blocking IP addresses and notify the GUI of the black list.

**Documentation**

To run this project one should carefully check the requirements:
- have a running VM that supports Ubuntu (this was tested with Ubuntu 24.10, later or earlier versions may or may not work, other Linux distributions were not tested)
- have python 3.10 installed (this is an important requirement since newer versions of python did NOT work, older versions may or may not work)
- have katharà installed

To run the project from the GUI one should be careful enough and create a python virtual environment to run the project. This can be done by:
```bash
cd GUI/
python3.10 -m venv venv
source venv/bin/activate
```
Then you can install the libraries neccessary to run the project by
```bash
pip install -r requirements.txt
```
After a successfull installation you're ready to run the project by:
```bash
cd GUI/
python3.10 gui.py
```
If after clicking on 'start simulation' it asks the permission to create the route for the host you should grant it and check that the output says 'Sniffer is connected' and 'Firewall is connected'.
You can run our test by
```bash
cd ../topology
./scenario.sh
```
or make a custom one and run it in a similar manner.

-----------------------------------------------------------------------------------------------------------------------------------------------------------------
