import customtkinter
class ToplevelWindow(customtkinter.CTkToplevel):
    def __init__(self, master, value, app_ref):
        super().__init__(master)

        self.app_ref = app_ref     # reference back to App
        self.value = value
        self.geometry("400x300")
        self.title(value)
        self.resizable(False, False)

        # ---- Outer Layout ----
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(1, weight=1)

        # ---- Info frame ----
        info_frame = customtkinter.CTkFrame(self)
        info_frame.grid(row=0, column=0, padx=10, pady=10, sticky="ew")

        # ---- Log frame for this host ----
        self.host_log = customtkinter.CTkTextbox(self, height=120)
        self.host_log.grid(row=1, column=0, padx=10, pady=10, sticky="nsew")

        value_cat = value.split()[0]

        if value_cat == "host":
            host_num = int(value.split()[1])
            base_ip = "192.168.10."
            mac_prefix = "00:00:00:00:00:"

            self.ip = f"{base_ip}{host_num}"
            self.mac = f"{mac_prefix}{host_num:02X}"

            customtkinter.CTkLabel(info_frame, text="IP:").grid(row=0, column=0, sticky="w")
            customtkinter.CTkLabel(info_frame, text=self.ip).grid(row=0, column=1, sticky="w")

            customtkinter.CTkLabel(info_frame, text="MAC:").grid(row=1, column=0, sticky="w")
            customtkinter.CTkLabel(info_frame, text=self.mac).grid(row=1, column=1, sticky="w")

        elif value_cat == "controller":
            self.ip = "192.168.100.1"
            customtkinter.CTkLabel(info_frame, text="IP:").grid(row=0, column=0, sticky="w")
            customtkinter.CTkLabel(info_frame, text=self.ip).grid(row=0, column=1, sticky="w")

        elif value_cat == "switch":
            self.ip = None   # switch has multiple IPs — skip filtering
            customtkinter.CTkLabel(info_frame, text="Switch").grid(row=0, column=0, sticky="w")

        else:   # external host
            host_num = int(value.split()[1])
            base_ip = "192.168.20."
            mac_prefix = "00:00:00:00:00:"

            self.ip = f"{base_ip}{host_num}"
            self.mac = f"{mac_prefix}{host_num:02X}"

            customtkinter.CTkLabel(info_frame, text="IP:").grid(row=0, column=0, sticky="w")
            customtkinter.CTkLabel(info_frame, text=self.ip).grid(row=0, column=1, sticky="w")

            customtkinter.CTkLabel(info_frame, text="MAC:").grid(row=1, column=0, sticky="w")
            customtkinter.CTkLabel(info_frame, text=self.mac).grid(row=1, column=1, sticky="w")

        # register this popup
        if self.ip:
            self.app_ref.open_popups[self.ip] = self
            print(f"self.open_popups: {self.app_ref.open_popups}")

        # deregister on close
        self.protocol("WM_DELETE_WINDOW", self.on_close)

    def on_close(self):
        if self.ip and self.ip in self.app_ref.open_popups:
            del self.app_ref.open_popups[self.ip]
        self.destroy()

    def append_message(self, msg):
        """Append host-specific messages."""
        self.host_log.insert("end", msg + "\n")
        self.host_log.see("end")
    def set_block_info(self, duration, reason):
        """Show a warning label that this IP is blocked."""
        msg = f"⚠ BLOCKED ({reason.upper()}) - {duration}s"
        self.block_label.configure(text=msg)
        self.block_label.grid()  # make it visible

    def clear_block_info(self):
        """Hide the warning label."""
        self.block_label.grid_remove()