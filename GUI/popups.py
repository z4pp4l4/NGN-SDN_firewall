import customtkinter
import time
import scapy.all as scapy

class ToplevelWindow(customtkinter.CTkToplevel):
    def __init__(self, master, value, app_ref):
        super().__init__(master)

        self.app_ref = app_ref
        self.value = value
        self.geometry("420x480")
        self.title(value)
        self.resizable(False, False)
        self.packet_stats = {}      # { "ARP": {count:int, ts:str}, ... }
        self.packet_cards = {}      # card widgets per protocol


        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(3, weight=1)

  
        info_frame = customtkinter.CTkFrame(self)
        info_frame.grid(row=0, column=0, padx=10, pady=10, sticky="ew")

        self.block_label = customtkinter.CTkLabel(self, text="", text_color="red")
        self.block_label.grid(row=1, column=0, padx=10, pady=5, sticky="ew")
        self.block_label.grid_remove()

        # NEW — label for static/port rules
        self.extra_label = customtkinter.CTkLabel(self, text="", text_color="orange")
        self.extra_label.grid(row=2, column=0, padx=10, pady=5, sticky="ew")
        self.extra_label.grid_remove()

        self.packet_view = customtkinter.CTkScrollableFrame(self, label_text="Packets")
        self.packet_view.grid(row=3, column=0, padx=10, pady=10, sticky="nsew")

        value_cat = value.split()[0]

        if value_cat == "host":
            host_num = int(value.split()[1])
            self.ip = f"192.168.10.{host_num}"
            self.mac = f"00:00:00:00:00:{host_num:02X}"

            customtkinter.CTkLabel(info_frame, text="IP:").grid(row=0, column=0, sticky="w")
            customtkinter.CTkLabel(info_frame, text=self.ip).grid(row=0, column=1, sticky="w")

            customtkinter.CTkLabel(info_frame, text="MAC:").grid(row=1, column=0, sticky="w")
            customtkinter.CTkLabel(info_frame, text=self.mac).grid(row=1, column=1, sticky="w")

        elif value_cat == "controller":
            self.ip = "192.168.100.1"
            customtkinter.CTkLabel(info_frame, text="IP:").grid(row=0, column=0, sticky="w")
            customtkinter.CTkLabel(info_frame, text=self.ip).grid(row=0, column=1, sticky="w")

        elif value_cat == "switch":
            self.ip = None
            customtkinter.CTkLabel(info_frame, text="Switch").grid(row=0, column=0, sticky="w")

        else:  # external attackers
            host_num = int(value.split()[1])
            self.ip = f"192.168.20.{host_num}"
            self.mac = f"00:00:00:00:00:{host_num:02X}"

            customtkinter.CTkLabel(info_frame, text="IP:").grid(row=0, column=0, sticky="w")
            customtkinter.CTkLabel(info_frame, text=self.ip).grid(row=0, column=1, sticky="w")

            customtkinter.CTkLabel(info_frame, text="MAC:").grid(row=1, column=0, sticky="w")
            customtkinter.CTkLabel(info_frame, text=self.mac).grid(row=1, column=1, sticky="w")

        # Register popup with GUI for updates
        if self.ip:
            self.app_ref.register_popup(self.ip, self)

        self.protocol("WM_DELETE_WINDOW", self.on_close)

    def add_packet_card(self, pkt):
        ts = time.strftime("%H:%M:%S", time.localtime(pkt.time))

        if pkt.haslayer(scapy.ARP):
            proto, color = "ARP", "#FFA500"
        elif pkt.haslayer(scapy.ICMP):
            proto, color = "ICMP", "#0000FF"
        elif pkt.haslayer(scapy.TCP):
            proto, color = "TCP", "#FF0000"
        elif pkt.haslayer(scapy.UDP):
            proto, color = "UDP", "#008000"
        else:
            proto, color = "OTHER", "#000000"

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

    def apply_firewall_event(self, event):
        t = event.get("type")
        ip = event.get("ip")
        reason = event.get("reason", "").upper()
        duration = event.get("duration", 0)

        if ip != self.ip:
            return

        # Proper block event handling
        if t == "block" and duration > 0:
            self.block_start_time = time.time()
            self.block_end_time = self.block_start_time + duration
            self.set_block_info(duration, reason)
            self.after(int(duration * 1000), lambda: self.show_unblocked_label(reason="timeout"))
            if ip in self.app_ref.block_history:
                del self.app_ref.block_history[ip]
            return

        # Unblock event from firewall
        if t == "unblock":
            self.show_unblocked_label(reason)
            if ip in self.app_ref.block_history:
                self.app_ref.block_history[ip] = []
                self.app_ref.block_history[ip].append(event)
            
            return

        # Static rules
        if t == "block" and duration < 0:
            self.set_block_info(duration, reason)
            return


    def show_unblocked_label(self, reason="manual"):
        ts = time.strftime("%H:%M:%S")
        self.block_label.configure(
            text=f" UNBLOCKED ({reason.upper()}) at {ts}",
            text_color="green"
        )
        self.block_label.grid()
    def set_block_info(self, duration, reason):
        if duration <= 0:
            msg = f"STATIC BLOCK RULE due to {reason.upper()}"
            self.block_label.configure(text=msg, text_color="red")
            self.block_label.grid()
            return

        reason = reason.upper()
        # Show block label immediately
        msg = f"BLOCKED: {reason} for {int(duration)}s"
        self.block_label.configure(text=msg, text_color="red")
        self.block_label.grid()



    def on_close(self):
        if self.ip:
            self.app_ref.unregister_popup(self.ip)
        self.destroy()
    def load_packet_stats(self, stats):
        # Initialize storage if needed
        if not hasattr(self, "packet_cards"):
            self.packet_cards = {}

        for proto, data in stats.items():
            count = data["count"]
            ts = data["ts"]

            # Set default colors for protocols
            colors = {
                "ARP": "#FFA500",
                "ICMP": "#0000FF",
                "TCP": "#FF0000",
                "UDP": "#008000",
                "OTHER": "#000000"
            }
            color = colors.get(proto, "#000000")

            # Create card if missing
            if proto not in self.packet_cards:
                card = customtkinter.CTkFrame(self.packet_view, corner_radius=10)
                card.pack(fill="x", padx=5, pady=5)

                top = customtkinter.CTkFrame(card, fg_color="transparent")
                top.pack(fill="x")

                proto_label = customtkinter.CTkLabel(
                    top, text=f"[{proto}]", font=("Arial",14), text_color=color
                )
                proto_label.pack(side="left", padx=10)

                info_label = customtkinter.CTkLabel(card, font=("Arial", 13))
                info_label.pack(anchor="w", padx=10)

                self.packet_cards[proto] = info_label

            # Update card text
            self.packet_cards[proto].configure(
                text=f"Count: {count}   Last packet: {ts}"
            )

