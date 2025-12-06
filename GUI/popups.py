import customtkinter
import time
import scapy.all as scapy

class ToplevelWindow(customtkinter.CTkToplevel):
    def __init__(self, master, value, app_ref):
        super().__init__(master)

        self.app_ref = app_ref
        self.app_ref = app_ref
        self.value = value
        self.geometry("400x400")
        self.title(value)
        self.resizable(False, False)

        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(3, weight=1)

        info_frame = customtkinter.CTkFrame(self)
        info_frame.grid(row=0, column=0, padx=10, pady=10, sticky="ew")

        self.block_label = customtkinter.CTkLabel(self, text="", text_color="red")
        self.block_label.grid(row=1, column=0, padx=10, pady=(0, 5), sticky="ew")
        self.block_label.grid_remove()

        self.packet_view = customtkinter.CTkScrollableFrame(self, label_text="Packets")
        self.packet_view.grid(row=3, column=0, padx=10, pady=10, sticky="nsew")

        # ---- Determine host IP/MAC ----
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
            self.ip = None
            customtkinter.CTkLabel(info_frame, text="Switch").grid(row=0, column=0, sticky="w")

        else:  
            host_num = int(value.split()[1])
            self.ip = f"192.168.20.{host_num}"
            self.mac = f"00:00:00:00:00:{host_num:02X}"

            customtkinter.CTkLabel(info_frame, text="IP:").grid(row=0, column=0, sticky="w")
            customtkinter.CTkLabel(info_frame, text=self.ip).grid(row=0, column=1, sticky="w")

            customtkinter.CTkLabel(info_frame, text="MAC:").grid(row=1, column=0, sticky="w")
            customtkinter.CTkLabel(info_frame, text=self.mac).grid(row=1, column=1, sticky="w")

        if self.ip:
            self.app_ref.register_popup(self.ip, self)
            self.app_ref.register_popup(self.ip, self)

        self.protocol("WM_DELETE_WINDOW", self.on_close)

    def add_packet_card(self, pkt):

        ts = time.strftime("%H:%M:%S", time.localtime(pkt.time))

        if pkt.haslayer(scapy.ARP):
            proto = "ARP"
            color = "#FFA500"
        elif pkt.haslayer(scapy.ICMP):
            proto = "ICMP"
            color = "#0000FF"
        elif pkt.haslayer(scapy.TCP):
            proto = "TCP"
            color = "#FF0000"
        elif pkt.haslayer(scapy.UDP):
            proto = "UDP"
            color = "#008000"
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

    def set_block_info(self, duration, reason):
        msg = f"⚠ BLOCKED: {reason.upper()} for {duration}s"
        self.block_label.configure(text=msg)
        self.block_label.grid()

    def clear_block_info(self):
        self.block_label.grid_remove()

    def on_close(self):
        if self.ip:
            self.app_ref.unregister_popup(self.ip)
        self.destroy()
