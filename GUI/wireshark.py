import threading
import queue
import time
import customtkinter as ctk

from pylibpcap.pcap import sniff


class PacketSnifferFrame(ctk.CTkFrame):
    def __init__(self, master, interface=None, subnet="192.168.10.0/29", **kwargs):
        super().__init__(master, **kwargs)

        self.interface = interface
        self.subnet = subnet
        self.packet_queue = queue.Queue()
        self.running = False

        # Title
        self.label = ctk.CTkLabel(self, text=f"Sniffing: {subnet}", font=("Arial", 16))
        self.label.pack(pady=10)

        # Output box
        self.output_box = ctk.CTkTextbox(self, width=700, height=400)
        self.output_box.pack(padx=10, pady=10)

        # Start button
        self.start_button = ctk.CTkButton(self, text="Start Sniffing", command=self.start_sniffing)
        self.start_button.pack(pady=5)

        # Stop button
        self.stop_button = ctk.CTkButton(self, text="Stop", command=self.stop_sniffing)
        self.stop_button.pack(pady=5)

        # GUI update loop
        self.after(100, self.update_output_box)

    # -------------------------------------------------------

    def start_sniffing(self):
        if self.running:
            return

        self.running = True
        self.output_box.insert("end", "Starting capture...\n")

        sniff_thread = threading.Thread(target=self.capture_loop, daemon=True)
        sniff_thread.start()

    # -------------------------------------------------------

    def stop_sniffing(self):
        self.running = False
        self.output_box.insert("end", "Stopping capture...\n")

    # -------------------------------------------------------

    def capture_loop(self):
        """
        Uses pylibpcap.sniff() which works in WSL, Linux, Mac, and Windows
        without needing to compile native extensions.
        """

        # BPF filter
        bpf = f"net {self.subnet}"

        try:
            for ts, pkt, *_ in sniff(
                iface=self.interface,
                filters=bpf,
                promisc=True,
                immediate=True
            ):
                if not self.running:
                    break

                timestamp = time.strftime("%H:%M:%S", time.localtime(ts))
                msg = f"[{timestamp}] {len(pkt)} bytes\n"
                self.packet_queue.put(msg)

        except Exception as e:
            self.packet_queue.put(f"ERROR: {e}\n")

    # -------------------------------------------------------

    def update_output_box(self):
        """Transfers queued output into the GUI textbox."""
        try:
            while True:
                line = self.packet_queue.get_nowait()
                self.output_box.insert("end", line)
                self.output_box.see("end")
        except queue.Empty:
            pass

        self.after(100, self.update_output_box)
