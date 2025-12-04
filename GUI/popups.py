import customtkinter
import customtkinter

class ToplevelWindow(customtkinter.CTkToplevel):
    def __init__(self, master, value, app_ref):
        super().__init__(master)

        self.app_ref = app_ref
        self.value = value
        self.geometry("400x300")
        self.title(value)
        self.resizable(False, False)

        # ---- Layout ----
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(2, weight=1)

        # ---- Info frame ----
        info_frame = customtkinter.CTkFrame(self)
        info_frame.grid(row=0, column=0, padx=10, pady=10, sticky="ew")

        # ---- Block label (hidden by default) ----
        self.block_label = customtkinter.CTkLabel(self, text="", text_color="red")
        self.block_label.grid(row=1, column=0, padx=10, pady=(0,5), sticky="ew")
        self.block_label.grid_remove()

        # ---- Log box ----
        self.host_log = customtkinter.CTkTextbox(self, height=120)
        self.host_log.grid(row=2, column=0, padx=10, pady=10, sticky="nsew")

        # ---- Determine host IP/MAC ----
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
            self.ip = None
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

        # ---- Register popup with the main App ----
        if self.ip:
            self.app_ref.register_popup(self.ip, self)

        # ---- Close handler ----
        self.protocol("WM_DELETE_WINDOW", self.on_close)

    def on_close(self):
        if self.ip:
            self.app_ref.unregister_popup(self.ip)
        self.destroy()

    def append_message(self, msg):
        self.host_log.insert("end", msg + "\n")
        self.host_log.see("end")

    def set_block_info(self, duration, reason):
        msg = f"⚠ BLOCKED ({reason.upper()}) - {duration}s"
        self.block_label.configure(text=msg)
        self.block_label.grid()  # show label

    def clear_block_info(self):
        self.block_label.grid_remove()