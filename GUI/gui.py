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

        self.open_popups = {}

        self.packet_history = {}
        self.block_history = {}

        self.packet_history = {}
        self.block_history = {}

        self.packet_queue = queue.Queue()
        self.check_packet_queue()

        self.firewall_event_queue = queue.Queue()
        self.check_firewall_queue()

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

        self.scrollable_checkbox_frame = MyOverview(self, title="Overview")
        self.scrollable_checkbox_frame.grid(row=0, column=1, padx=10, pady=(10, 0), sticky="nsew")

        self.button = customtkinter.CTkButton(self, text="start simulation", command=self.button_callback)
        self.button.grid(row=2, column=0, padx=10, pady=10, sticky="ew", columnspan=2)

        self.packet_view = customtkinter.CTkScrollableFrame(self, label_text="Packets")
        self.packet_view.grid(row=4, column=0, columnspan=2, padx=10, pady=10, sticky="nsew")

        self.protocol("WM_DELETE_WINDOW", self.on_close)

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

        src = pkt[scapy.IP].src if pkt.haslayer(scapy.IP) else ""
        dst = pkt[scapy.IP].dst if pkt.haslayer(scapy.IP) else ""
        summary = pkt.summary()

        card = customtkinter.CTkFrame(self.packet_view, corner_radius=10)
        card.pack(fill="x", padx=5, pady=5)

        top_row = customtkinter.CTkFrame(card, fg_color="transparent")
        top_row.pack(fill="x")

        customtkinter.CTkLabel(top_row, text=ts, font=("Arial", 14, "bold")).pack(side="left", padx=5)

        customtkinter.CTkLabel(
            top_row, text=f"[{proto}]", font=("Arial", 14), text_color=color
        ).pack(side="left", padx=10)

        flow_text = f"{src}  →  {dst}"
        customtkinter.CTkLabel(card, text=flow_text, font=("Arial", 13)).pack(anchor="w", padx=10)

        customtkinter.CTkLabel(
            card, text=summary, font=("Arial", 12), text_color="#666666"
        ).pack(anchor="w", padx=10, pady=(0, 5))

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

        self.sniffer = subprocess.Popen(
            ["kathara", "exec", "s1", "--", "python3", "/shared/sniffer_switch.py"],
            cwd="../topology/",
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )

    def register_popup(self, ip, popup_window):
        self.open_popups[ip] = popup_window

        for pkt in self.packet_history.get(ip, []):
            popup_window.add_packet_card(pkt)

        for duration, reason in self.block_history.get(ip, []):
            popup_window.set_block_info(duration, reason)

    def unregister_popup(self, ip):
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
            data = conn.recv(4096).decode()
            if not data:
                break

            buffer += data

            while "\n" in buffer:
                line, buffer = buffer.split("\n", 1)
                if line.strip():
                    self.firewall_event_queue.put(line.strip())

    def check_packet_queue(self):
        while not self.packet_queue.empty():
            pkt = self.packet_queue.get()
            ip_layer = pkt.getlayer(scapy.IP)
            src_ip = ip_layer.src if ip_layer else None

            self.add_packet_card(pkt)

            if src_ip:
                if src_ip not in self.packet_history:
                    self.packet_history[src_ip] = []
                self.packet_history[src_ip].append(pkt)

                if len(self.packet_history[src_ip]) > 500:
                    self.packet_history[src_ip] = self.packet_history[src_ip][-500:]

                if src_ip in self.open_popups:
                    popup = self.open_popups[src_ip]
                    popup.add_packet_card(pkt)

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

                if ip not in self.block_history:
                    self.block_history[ip] = []
                self.block_history[ip].append((duration, reason))

                if len(self.block_history[ip]) > 100:
                    self.block_history[ip] = self.block_history[ip][-100:]

                if ip in self.open_popups:
                    self.open_popups[ip].set_block_info(duration, reason)

        self.after(50, self.check_firewall_queue)


app = App()
app.mainloop()
