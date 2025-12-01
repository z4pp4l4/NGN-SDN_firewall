import customtkinter
from overview import MyOverview
from topology import MyTopologyFrame
from radiobuttons import MyRadioButtonFrame
import subprocess
import socket
import threading
import queue
class App(customtkinter.CTk):
    def __init__(self):
        super().__init__()
        ##########################################
        self.listener_started = False
        ######### ouss added###########

        self.packet_queue = queue.Queue()
        self.check_packet_queue()

        self.title("NGN GUI")
        self.geometry("800x800")
        self.grid_columnconfigure((0, 1), weight=1)
        self.grid_rowconfigure((0,1,2,3), weight=1)

        values = ["firewall 1", "firewall 2", "firewall 3"]
        int_hosts = ["host  1", "host 2", "host 3"]
        ext_hosts = ["hack 1", "hack 2", "hack 3", "hack 4", "hack 5", "hack 6", "hack 7"]
        self.topology_frame = MyTopologyFrame(self, title="Topology", values=values, int_hosts=int_hosts, ext_hosts=ext_hosts)
        self.topology_frame.grid(row=0, column=0, padx=10, pady=(10,0), sticky="nsew")
        self.radiobutton_frame = MyRadioButtonFrame(self, values=values)
        self.radiobutton_frame.grid(row=1, column=0, padx=10, pady=(10,0), sticky="nsew")
        self.scrollable_checkbox_frame = MyOverview(self, title="Overview", values=values)
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
        subprocess.run(["bash","./start-lab.sh"], cwd="../topology/")
        
        # 2. Add the route to the HOST OS to allow return traffic 
        #    NOTE: This command will likely require a password prompt from 'sudo' 
        #    and will block the GUI until entered, or you must run it manually.
        try:
            print("INFO: Attempting to add Host route for return traffic...")
            # Use the verified IP 172.17.0.3
            subprocess.run(["sudo", "ip", "route", "add", "192.168.70.0/29", "via", "172.17.0.3"], check=True)
            print("INFO: Host route added successfully.")
        except subprocess.CalledProcessError as e:
            # Route already exists is a common error if the button is clicked twice
            if "File exists" in e.output: 
                print("INFO: Host route already exists.")
            else:
                print(f"ERROR: Failed to add host route. Please run the following command manually: sudo ip route add 192.168.70.0/29 via 172.17.0.3")

        # 3. Start the listener thread 
        if not self.listener_started:
             threading.Thread(target=self.packet_listener_thread, daemon=True).start()

        # 4. Start the sniffer client
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
            self.packet_queue.put(data.decode(errors="ignore"))

    def check_packet_queue(self):
        while not self.packet_queue.empty():
            pkt = self.packet_queue.get()
            self.log_frame.insert("end", pkt + "\n")
            self.log_frame.see("end") 
        self.after(50, self.check_packet_queue)


app = App()

app.mainloop()
