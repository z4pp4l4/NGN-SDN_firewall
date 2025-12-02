import customtkinter
from overview import MyOverview
from topology import MyTopologyFrame
from radiobuttons import MyRadioButtonFrame
import subprocess
import socket
import threading
import queue
import scapy.all as scapy
import json

class App(customtkinter.CTk):
    def __init__(self):
        super().__init__()
        ##########################################
        self.listener_started = False
        self.listener_started_firewall = False
        ######### ouss added###########

        self.open_popups = {}

        self.packet_queue = queue.Queue()
        self.check_packet_queue()

        self.firewall_event_queue = queue.Queue()
        self.check_firewall_queue()

        self.title("NGN GUI")
        self.geometry("800x800")
        self.grid_columnconfigure((0, 1), weight=1)
        self.grid_rowconfigure((0,1,2,3), weight=1)

        values = ["firewall 1", "firewall 2", "firewall 3"]
        int_hosts = ["host  1", "host 2", "host 3"]
        ext_hosts = ["hack 1", "hack 2", "hack 3", "hack 4", "hack 5", "hack 6", "hack 7"]
        self.topology_frame = MyTopologyFrame(self, app_ref=self, title="Topology", int_hosts=int_hosts, ext_hosts=ext_hosts)
        self.topology_frame.grid(row=0, column=0, padx=10, pady=(10,0), sticky="nsew")
        self.radiobutton_frame = MyRadioButtonFrame(self, values=values)
        self.radiobutton_frame.grid(row=1, column=0, padx=10, pady=(10,0), sticky="nsew")
        self.scrollable_checkbox_frame = MyOverview(self, title="Overview")
        self.scrollable_checkbox_frame.grid(row=0, column=1, padx=10, pady=(10,0), sticky="nsew")

        self.button = customtkinter.CTkButton(self, text="start simulation", command=self.button_callback)
        self.button.grid(row=2, column=0, padx=10, pady=10, sticky="ew")

        self.log_frame = customtkinter.CTkTextbox(self, height=200)
        self.log_frame.grid(row=3, column=0, columnspan=2, padx=10, pady=(10,10), sticky="nsew")

        self.protocol("WM_DELETE_WINDOW", self.on_close)

    def on_close(self):
        subprocess.run(["bash", "./stop-lab.sh"], cwd="../topology/")
        self.destroy()
    def button_callback(self):
        # 1. Start the lab
        subprocess.run(["bash", "./start-lab.sh"], cwd="../topology/")

        # 2. Ensure the host route exists (idempotent)
        route_sniffer = "192.168.70.0/29"
        route_firewall = "192.168.100.0/30"
        via = "172.17.0.3"

        print("INFO: Checking if host route_sniffer exists...")

        # CHECK if the route_sniffer is already present
        existing = subprocess.run(
            ["ip", "route", "show", route_sniffer],
            capture_output=True,
            text=True
        ).stdout

        if via in existing:
            print("INFO: route_sniffer already exists. Skipping 'ip route_sniffer add'.")
        else:
            print("INFO: route_sniffer does not exist. Attempting to add it...")
            try:
                subprocess.run(
                    ["sudo", "ip", "route", "add", route_sniffer, "via", via],
                    check=True,
                    stderr=subprocess.PIPE,
                    text=True
                )
                print("INFO: Host route_sniffer added successfully.")
            except subprocess.CalledProcessError as e:
                print("ERROR: Failed to add host route_sniffer.")
                print("stderr:", e.stderr)
                print(f"Please run manually: sudo ip route add {route_sniffer} via {via}")

        # CHECK if route_firewall is already present
        print("INFO: Checking if host route_firewall exists...")

        existing_firewall = subprocess.run(
            ["ip", "route", "show", route_firewall],
            capture_output=True,
            text=True
        ).stdout

        if via in existing_firewall:
            print("INFO: route_firewall already exists. Skipping 'ip route_firewall add'.")
        else:
            print("INFO: route_firewall does not exist. Attempting to add it...")
            try:
                subprocess.run(
                    ["sudo", "ip", "route", "add", route_firewall, "via", via],
                    check=True,
                    stderr=subprocess.PIPE,
                    text=True
                )
                print("INFO: Host route_firewall added successfully.")
            except subprocess.CalledProcessError as e:
                print("ERROR: Failed to add host route_firewall.")
                print("stderr:", e.stderr)
                print(f"Please run manually: sudo ip route add {route_firewall} via {via}")

        # 3. Start the listener thread for the switch
        if not self.listener_started:
            threading.Thread(target=self.packet_listener_thread, daemon=True).start()
        
        # Start the listener thread for the firewall
        if not self.listener_started_firewall:
            threading.Thread(target=self.blocked_ips_listener_thread, daemon=True).start()

        # 4. Start the sniffer container client
        self.sniffer = subprocess.Popen(
            ["kathara", "exec", "s1", "--", "python3", "/shared/sniffer_switch.py"],
            cwd="../topology/",
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )



    def packet_listener_thread(self):

        self.listener_started = True

        server = socket.socket()
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind(("0.0.0.0", 5000))
        server.listen(1)

        print("Waiting for connection from switch sniffer...")
        conn, _ = server.accept()
        print("Sniffer is connected")

        while True:
            data = conn.recv(4096)
            if not data:
                break
            pkt=scapy.Ether(data)
            self.packet_queue.put(pkt.summary())
    
    def blocked_ips_listener_thread(self):

        self.listener_started_firewall = True

        server = socket.socket()
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind(("0.0.0.0", 5001))
        server.listen(1)

        print("Waiting for firewall connection...")
        conn, _ = server.accept()
        print("Firewall connected.")

        buffer = ""
        while True:
            data = conn.recv(4096)
            if not data:
                break

            buffer += data.decode()
            while "\n" in buffer:
                line, buffer = buffer.split("\n", 1)
                if line.strip():
                    self.firewall_event_queue.put(line.strip())

    
    def check_packet_queue(self):
        while not self.packet_queue.empty():
            pkt = self.packet_queue.get()

            # ---------------------------------------------
            # 1. Append packet to the main global log
            # ---------------------------------------------
            self.log_frame.insert("end", pkt + "\n")
            self.log_frame.see("end")

            # ---------------------------------------------
            # 2. Extract source IP from packet summary
            #    Scapy summary looks like:
            #    "Ether / IP 192.168.10.3 > 192.168.20.4 ..."
            # ---------------------------------------------
            src_ip = None
            parts = pkt.split()

            # Find the first IPv4-looking token
            for token in parts:
                if token.count(".") == 3:  # simple IPv4 detection
                    src_ip = token
                    break

            # ---------------------------------------------
            # 3. Deliver packet message to the popup of that IP
            # ---------------------------------------------
            if src_ip in self.open_popups:
                popup = self.open_popups[src_ip]
                popup.append_message(pkt)

        # Keep checking every 50ms
        self.after(50, self.check_packet_queue)
    def check_firewall_queue(self):
        while not self.firewall_event_queue.empty():
            raw = self.firewall_event_queue.get()
            event = json.loads(raw)

            if event["type"] == "block":
                ip = event["ip"]
                duration = event["duration"]
                reason = event["reason"]

                self.scrollable_checkbox_frame.add_blocked_ip(ip, duration, reason)

                if ip in self.open_popups:
                    self.open_popups[ip].set_block_info(duration, reason)

        self.after(50, self.check_firewall_queue)



app = App()

app.mainloop()
