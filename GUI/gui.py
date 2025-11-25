import customtkinter
from overview import MyOverview
from topology import MyTopologyFrame
from wireshark import PacketSnifferFrame
import subprocess
class App(customtkinter.CTk):
    def __init__(self):
        super().__init__()

        self.title("NGN GUI")
        self.geometry("800x800")
        self.grid_columnconfigure((0, 1), weight=1)
        self.grid_rowconfigure((0,1), weight=1)

        values = ["firewall 1", "firewall 2", "firewall 3"]
        int_hosts = ["host  1", "host 2", "host 3"]
        ext_hosts = ["hack 1", "hack 2", "hack 3", "hack 4", "hack 5", "hack 6", "hack 7"]
        self.radiobutton_frame = MyTopologyFrame(self, title="Topology", values=values, int_hosts=int_hosts, ext_hosts=ext_hosts)
        self.radiobutton_frame.grid(row=0, column=0, padx=10, pady=(10,0), sticky="nsew")
        self.scrollable_checkbox_frame = MyOverview(self, title="Overview", values=values)
        self.scrollable_checkbox_frame.grid(row=0, column=1, padx=10, pady=(10,0), sticky="nsew")

        self.button = customtkinter.CTkButton(self, text="start simulation", command=self.button_callback)
        self.button.grid(row=3, column=0, padx=10, pady=10, sticky="ew")

        self.sniffer_frame=PacketSnifferFrame(self, subnet="192.168.10.0/29")
        self.sniffer_frame.grid(row=4, column = 0, padx=10, pady=10, sticky = "nsew")

    def button_callback(self):
        subprocess.run(["./start_lab"], cwd="../topology/")

app = App()

app.mainloop()
