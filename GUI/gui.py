import customtkinter
import time
from overview import MyOverview
from topology import MyTopologyFrame
import subprocess
import socket
import threading
import queue
import scapy.all as scapy
import json
import base64


class App(customtkinter.CTk):
    def __init__(self):
        super().__init__()

        self.listener_started = False
        self.listener_started_firewall = False
        self.firewall_cmd_socket = None   # NEW: command channel GUI → Firewall
        self.firewall_event_socket = None # existing event channel Firewall → GUI


        self.open_popups = {}

        self.packet_stats = {}      # { "ARP": {count:int, ts:str}, ... }
        self.packet_cards = {}      # card widgets per protocol

        self.ip_packet_stats = {}


        self.packet_history = {}
        self.block_history = {}


        self.packet_queue = queue.Queue()
        self.check_packet_queue()

        self.firewall_event_queue = queue.Queue()
        self.check_firewall_queue()

        self.title("NGN GUI")
        self.geometry("800x800")
        self.grid_columnconfigure((0, 1), weight=1)
        self.grid_rowconfigure((0, 1, 2, 3), weight=1)

        values = ["firewall 1", "firewall 2", "firewall 3"]
        int_hosts = ["host  1", "host 2", "host 3"]
        ext_hosts = ["hack 1", "hack 2", "hack 3", "hack 4", "hack 5", "hack 6", "hack 7"]

        self.topology_frame = MyTopologyFrame(
            self, app_ref=self, title="Topology",
            int_hosts=int_hosts, ext_hosts=ext_hosts
        )
        self.topology_frame.grid(row=0, column=0, padx=10, pady=(10, 0), sticky="nsew")

        self.scrollable_checkbox_frame = MyOverview(self, title="Overview", app_ref=self)
        self.scrollable_checkbox_frame.grid(row=0, column=1, padx=10, pady=(10, 0), sticky="nsew")

        self.button = customtkinter.CTkButton(self, text="start simulation", command=self.button_callback)
        self.button.grid(row=2, column=0, padx=10, pady=10, sticky="ew", columnspan=2)

        self.packet_view = customtkinter.CTkScrollableFrame(self, label_text="Packets")
        self.packet_view.grid(row=4, column=0, columnspan=2, padx=10, pady=10, sticky="nsew")

        self.protocol("WM_DELETE_WINDOW", self.on_close)

    def connect_firewall_command_channel(self):
        """GUI listens for firewall COMMAND channel on port 6001."""
        server = socket.socket()
        #server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind(("0.0.0.0", 6001))
        server.listen(1)

        print("[GUI] Waiting for firewall COMMAND channel on 6001...")
        conn, _ = server.accept()
        print("[GUI] Firewall COMMAND channel connected.")
        self.firewall_cmd_socket = conn


    def add_packet_card(self, pkt):
        ts = time.strftime("%H:%M:%S", time.localtime(pkt.time))

        if pkt.haslayer(scapy.ARP):
            proto = "ARP"
            color = "#FFA500"   # Orange
        elif pkt.haslayer(scapy.ICMP):
            proto = "ICMP"
            color = "#0000FF"   # Blue
        elif pkt.haslayer(scapy.TCP):
            proto = "TCP"
            color = "#FF0000"   # Red
        elif pkt.haslayer(scapy.UDP):
            proto = "UDP"
            color = "#008000"   # Green
        else:
            proto = "OTHER"
            color = "#000000"

        if proto not in self.packet_stats:
            self.packet_stats[proto] = {"count": 0, "ts": ts}
        self.packet_stats[proto]["count"] += 1
        self.packet_stats[proto]["ts"] = ts

        # if no card exists → create one
        if proto not in self.packet_cards:
            card = customtkinter.CTkFrame(self.packet_view, corner_radius=10)
            card.pack(fill="x", padx=5, pady=5)

            top = customtkinter.CTkFrame(card, fg_color="transparent")
            top.pack(fill="x")

            proto_label = customtkinter.CTkLabel(
                top, text=f"[{proto}]", font=("Arial", 14), text_color=color
            )
            proto_label.pack(side="left", padx=10)

            info_label = customtkinter.CTkLabel(card, font=("Arial", 13))
            info_label.pack(anchor="w", padx=10)

            self.packet_cards[proto] = info_label

        # update the displayed text (super fast)
        info = self.packet_stats[proto]
        self.packet_cards[proto].configure(
            text=f"Count: {info['count']}   Last packet: {info['ts']}"
        )

    def on_close(self):
        subprocess.run(["bash", "./stop-lab.sh"], cwd="../topology/")
        self.destroy()

    def button_callback(self):
        subprocess.run(["bash", "./start-lab.sh"], cwd="../topology/")

        route_sniffer = "192.168.70.0/29"
        via = "172.17.0.3"

        print("INFO: Checking if host route_sniffer exists...")

        existing = subprocess.run(
            ["ip", "route", "show", route_sniffer],
            capture_output=True,
            text=True
        ).stdout

        if via in existing:
            print("INFO: host route already exists. Skipping 'ip route add'.")
        else:
            print("INFO: route does not exist. Attempting to add it...")
            print("INFO: route does not exist. Attempting to add it...")
            try:
                subprocess.run(
                    ["sudo", "ip", "route", "add", route_sniffer, "via", via],
                    check=True,
                    stderr=subprocess.PIPE,
                    text=True
                )
                print("INFO: Host route added successfully.")
            except subprocess.CalledProcessError as e:
                print("ERROR: Failed to add host route.")
                print("stderr:", e.stderr)
                print(f"Please run manually: sudo ip route add {route_sniffer} via {via}")

        if not self.listener_started:
            threading.Thread(target=self.packet_listener_thread, daemon=True).start()
        
        if not self.listener_started_firewall:
            threading.Thread(target=self.blocked_ips_listener_thread, daemon=True).start()

        ###maybe here add another commuication thread to send commands to firewall
        # NEW: Start GUI → Firewall command channel    
        threading.Thread(target=self.connect_firewall_command_channel, daemon=True).start()

        self.sniffer = subprocess.Popen(
            ["kathara", "exec", "s1", "--", "python3", "/shared/sniffer_switch.py"],
            cwd="../topology/",
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        print("waiting 15 seconds for the whole environment to boot up...")
        time.sleep(15)
        print("Starting ARP warm-up...")
        subprocess.run(["bash", "./ARP_warmup.sh"], cwd="../topology/")

    def register_popup(self, ip, popup_window):
        self.open_popups[ip] = popup_window

        if ip in self.ip_packet_stats:
            popup_window.load_packet_stats(self.ip_packet_stats[ip])

        if ip not in self.block_history or not self.block_history[ip]:
            return  # No history → nothing to restore

        last_event = self.block_history[ip][-1]
        event_type = last_event["type"]
        duration = last_event.get("duration", 0)
        reason = last_event.get("reason", "")
        timestamp = last_event.get("timestamp", time.time())
        now = time.time()

        # Handle static block
        if event_type == "block" and duration < 0:
            popup_window.set_block_info(duration, reason)
            return

        # Handle timed block
        if event_type == "block" and duration > 0:
            elapsed = now - timestamp
            remaining = duration - elapsed

            if remaining <= 0:
                # Block already expired
                popup_window.show_unblocked_label("timeout")
            else:
                # Block still active → restore countdown & label
                popup_window.block_start_time = timestamp
                popup_window.block_end_time = timestamp + duration
                popup_window.set_block_info(remaining, reason)
                popup_window.after(int(remaining * 1000),
                    lambda: popup_window.show_unblocked_label("timeout"))
            return

        # Handle unblock event
        if event_type == "unblock":
            popup_window.show_unblocked_label(reason)
            if ip in self.block_history:
                self.block_history[ip] = []
                self.block_history[ip].append(last_event)

            return



    def unregister_popup(self, ip):
        if ip in self.open_popups:
            del self.open_popups[ip]

    def send_firewall_command(self, event: dict):
        if not self.firewall_cmd_socket:
            print("Firewall COMMAND CHANNEL NOT CONNECTED!")
            return

        try:
            msg = json.dumps(event) + "\n"
            self.firewall_cmd_socket.sendall(msg.encode())
            print("[GUI → Firewall] Sent:", msg.strip())
        except Exception as e:
            print(" Error sending command to firewall:", e)

    
    def packet_listener_thread(self):

        self.listener_started = True

        server = socket.socket()
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind(("0.0.0.0", 5000))
        server.listen(1)

        print("Waiting for connection from switch sniffer...")
        conn, _ = server.accept()
        print("Sniffer is connected")

        buffer = ""

        while True:
            data = conn.recv(4096).decode()
            if not data:
                break

            buffer += data

            while "\n" in buffer:
                line, buffer = buffer.split("\n", 1)
                if not line.strip():
                    continue

                try:
                    raw = base64.b64decode(line)
                    pkt = scapy.Ether(raw)
                except Exception as e:
                    print("Decode error:", e)
                    continue

                self.packet_queue.put(pkt)

    def blocked_ips_listener_thread(self):
        """GUI listens for BLOCK events on port 5001."""
        self.listener_started_firewall = True

        server = socket.socket()
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind(("0.0.0.0", 5001))
        server.listen(1)

        print("[GUI] Waiting for firewall EVENT channel on 5001...")
        conn, _ = server.accept()
        print("[GUI] Firewall EVENT channel connected.")
        self.firewall_event_socket = conn

        buffer = ""

        while True:
            data = conn.recv(4096).decode()
            if not data:
                break

            buffer += data

            while "\n" in buffer:
                line, buffer = buffer.split("\n", 1)
                if line.strip():
                    print("[FIREWALL → GUI EVENT] Received:", line.strip())
                    self.firewall_event_queue.put(line.strip())


    def check_packet_queue(self):
        while not self.packet_queue.empty():
            pkt = self.packet_queue.get()
            ip_layer = pkt.getlayer(scapy.IP)
            src_ip = ip_layer.src if ip_layer else None

            self.add_packet_card(pkt)

            if src_ip:
                ts = time.strftime("%H:%M:%S", time.localtime(pkt.time))

                if src_ip not in self.ip_packet_stats:
                    self.ip_packet_stats[src_ip] = {}

                # Determine protocol
                if pkt.haslayer(scapy.ARP):
                    proto = "ARP"
                elif pkt.haslayer(scapy.ICMP):
                    proto = "ICMP"
                elif pkt.haslayer(scapy.TCP):
                    proto = "TCP"
                elif pkt.haslayer(scapy.UDP):
                    proto = "UDP"
                else:
                    proto = "OTHER"

                # Update per-protocol stats
                if proto not in self.ip_packet_stats[src_ip]:
                    self.ip_packet_stats[src_ip][proto] = {"count": 0, "ts": ts}

                self.ip_packet_stats[src_ip][proto]["count"] += 1
                self.ip_packet_stats[src_ip][proto]["ts"] = ts

                if src_ip not in self.packet_history:
                    self.packet_history[src_ip] = []
                self.packet_history[src_ip].append(pkt)

                if len(self.packet_history[src_ip]) > 500:
                    self.packet_history[src_ip] = self.packet_history[src_ip][-500:]

                for popup_ip, popup in self.open_popups.items():
                    if popup_ip == src_ip:
                        popup.load_packet_stats(self.ip_packet_stats[src_ip])


        self.after(50, self.check_packet_queue)

    def check_firewall_queue(self):
        while not self.firewall_event_queue.empty():
            raw = self.firewall_event_queue.get()
            event = json.loads(raw)
            print("[GUI] Processing firewall event:", event)
            if event.get("type") == "block":
                ip = event["ip"]
                duration = event["duration"]
                reason = event["reason"]
                event["timestamp"] = time.time()

                print(f"[GUI] IP {ip} BLOCKED for {duration}s due to {reason}")
                self.scrollable_checkbox_frame.add_blocked_ip(ip, duration, reason)

                if ip not in self.block_history:
                    self.block_history[ip] = []
                self.block_history[ip].append(event)

                if len(self.block_history[ip]) > 100:
                    self.block_history[ip] = self.block_history[ip][-100:]

                for popup in self.open_popups.values():
                    popup.apply_firewall_event(event)
            elif event.get("type") == "unblock":
                ip = event["ip"]
                duration = 0
                if "duration" in event:
                    duration = event["duration"]
                reason = event["reason"]

                print(f"[GUI] IP {ip} UNBLOCKED due to {reason}")
                self.scrollable_checkbox_frame.remove_blocked_ip(ip, reason)
                if ip in self.block_history:
                    self.block_history[ip].append(event)


                for popup in self.open_popups.values():
                    popup.apply_firewall_event(event)


        self.after(1000, self.check_firewall_queue)



app = App()
app.mainloop()
