import customtkinter

class ToplevelWindow(customtkinter.CTkToplevel):
    def __init__(self, master, value):
        super().__init__(master)
        self.geometry("400x300")
        self.columnconfigure((0, 1), weight=1)

        value_cat=value.split()[0]
        if value_cat=="host":
            int_ip_addr="192.168.10.0"
            mac_addr="0B:00:00:00:00:"
            host_num=int(value.split()[1])
            self.ip_address= f"{int_ip_addr}{host_num}"
            self.mac_address = f"{mac_addr}{host_num:02X}"
            self.label_ip = customtkinter.CTkLabel(self, text=f"ip address: {self.ip_address}")
            self.label_mac = customtkinter.CTkLabel(self, text=f"mac address: {self.mac_address}")
            self.label_ip.grid(row=0, column = 1, padx= 10, pady=10)
            self.label_mac.grid(row=1, column = 1, padx=10, pady=10)
        elif value_cat=="switch":
            self.label_internal_ip = customtkinter.CTkLabel(self, text="ip address for internal network: 192.168.10.04")
            self.label_internal_ip.grid(row=0, column=1, padx=10, pady=10)
            self.label_external_ip = customtkinter.CTkLabel(self, text="ip address for external network: 192.168.20.04")
            self.label_external_ip.grid(row=1, column=1, padx=10, pady=10)
            self.label_controller_ip = customtkinter.CTkLabel(self, text="ip address for controller network: 192.168.100.2")
            self.label_controller_ip.grid(row=2, column=1, padx=10, pady=10)
            self.label_mac_internal=customtkinter.CTkLabel(self, text="mac address for internal network: 0B:00:00:00:00:1B")
            self.label_mac_internal.grid(row=0, column=0, padx=10, pady=10)
            self.label_mac_external=customtkinter.CTkLabel(self, text= "mac address for external network: 0C:00:00:00:00:1C")
            self.label_mac_external.grid(row=1, column=0, padx=10, pady=10)
        elif value_cat=="controller":
            self.label_ip=customtkinter.CTkLabel(self, text="ip address: 192.168.100.1")
            self.label_ip.grid(row=0, column = 1, padx=10, pady=10)
        else :
            int_ip_addr="192.168.20.0"
            mac_addr="0C:00:00:00:00:"
            host_num=int(value.split()[1])
            self.ip_address= f"{int_ip_addr}{host_num}"
            self.mac_address = f"{mac_addr}{host_num:02X}"
            self.label_ip = customtkinter.CTkLabel(self, text=f"ip address: {self.ip_address}")
            self.label_mac = customtkinter.CTkLabel(self, text=f"mac address: {self.mac_address}")
            self.label_ip.grid(row=0, column = 1, padx= 10, pady=10)
            self.label_mac.grid(row=1, column = 1, padx=10, pady=10)
        self.lift()
        self.focus_force()
        self.attributes("-topmost", True)
        self.after(100, lambda: self.attributes("-topmost", False))