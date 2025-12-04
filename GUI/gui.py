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

        self.packet_history = {}
        self.block_history = {}

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
        route = "192.168.70.0/29"
        via = "172.17.0.3"

        print("INFO: Checking if host route exists...")

        # CHECK if the route_sniffer is already present
        existing = subprocess.run(
            ["ip", "route", "show", route],
            capture_output=True,
            text=True
        ).stdout

        if via in existing:
            print("INFO: host route already exists. Skipping 'ip route_sniffer add'.")
        else:
            print("INFO: route does not exist. Attempting to add it...")
            try:
                subprocess.run(
                    ["sudo", "ip", "route", "add", route, "via", via],
                    check=True,
                    stderr=subprocess.PIPE,
                    text=True
                )
                print("INFO: Host route added successfully.")
            except subprocess.CalledProcessError as e:
                print("ERROR: Failed to add host route.")
                print("stderr:", e.stderr)
                print(f"Please run manually: sudo ip route add {route} via {via}")


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
    def register_popup(self, ip, popup_window):
        """Call this when creating/opening a popup for a given IP."""
        self.open_popups[ip] = popup_window

        # Replay stored packet history into the newly opened popup
        for msg in self.packet_history.get(ip, []):
            popup_window.append_message(msg)

        # Replay stored firewall blocks
        for duration, reason in self.block_history.get(ip, []):
            popup_window.set_block_info(duration, reason)

    def unregister_popup(self, ip):
        """Call this when closing a popup for a given IP."""
        if ip in self.open_popups:
            del self.open_popups[ip]
    
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
            pkt = scapy.Ether(data)

            # Extract IPs safely using Scapy
            ip_layer = pkt.getlayer(scapy.IP)
            if ip_layer:
                src_ip = ip_layer.src
                dst_ip = ip_layer.dst
            else:
                src_ip = None
                dst_ip = None

            self.packet_queue.put((pkt.summary(), src_ip, dst_ip))
    
    def blocked_ips_listener_thread(self):

        self.listener_started_firewall = True

        server = socket.socket()
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind(("0.0.0.0", 5001))
        server.listen(1)

        print("Waiting for firewall connection...")
        conn, _ = server.accept()
        print("Firewall connected.")

        while True:
            data = conn.recv(4096)
            if not data:
                break

            while "\n" in buffer:
                line, buffer = buffer.split("\n", 1)
                line = line.strip()
                if line:
                    # Push raw JSON string to firewall queue
                    self.firewall_event_queue.put(line)

    def check_packet_queue(self):
        while not self.packet_queue.empty():
                summary, src_ip, _ = self.packet_queue.get()

                self.log_frame.insert("end", summary + "\n")
                self.log_frame.see("end")

                if src_ip:
                    # Always store in history, regardless of popup being open
                    if src_ip not in self.packet_history:
                        self.packet_history[src_ip] = []
                    self.packet_history[src_ip].append(summary)

                    # Cap history length to avoid unlimited growth
                    if len(self.packet_history[src_ip]) > 500:
                        self.packet_history[src_ip] = self.packet_history[src_ip][-500:]

                    # If popup is open, update it live (maybe redundant)
                    if src_ip in self.open_popups:
                        popup = self.open_popups[src_ip]
                        popup.append_message(summary)

        self.after(50, self.check_packet_queue)
    def check_firewall_queue(self):
        while not self.firewall_event_queue.empty():
            raw = self.firewall_event_queue.get()
            event = json.loads(raw)
            print("Received firewall event:", event)

            if event["type"] == "block":
                ip = event["ip"]
                duration = event["duration"]
                reason = event["reason"]

                self.scrollable_checkbox_frame.add_blocked_ip(ip, duration, reason)
                # Always store in history
                if ip not in self.block_history:
                    self.block_history[ip] = []
                self.block_history[ip].append((duration, reason))

                # Keep history bounded to last 100 entries
                if len(self.block_history[ip]) > 100:
                    self.block_history[ip] = self.block_history[ip][-100:]

                # If popup is open, update it (maybe redundant)
                if ip in self.open_popups:
                    self.open_popups[ip].set_block_info(duration, reason)

                if ip in self.open_popups:
                    self.open_popups[ip].set_block_info(duration, reason)

        self.after(50, self.check_firewall_queue)



app = App()

app.mainloop()
