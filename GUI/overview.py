
import customtkinter
import time

class MyOverview(customtkinter.CTkFrame):
    def __init__(self, master, title, app_ref):
        super().__init__(master)
        self.grid_columnconfigure((0,1,2,3), weight=1)
        self.title_label = customtkinter.CTkLabel(
            self,
            text=title,
            font=customtkinter.CTkFont(size=20, weight="bold"),
            text_color=("gray10", "gray90")
        )
        self.title_label.grid(row=0, column=0, columnspan=4, pady=(10, 5))

        self.app_ref = app_ref
        self.blocked = {}

        self.command_var = customtkinter.StringVar(value="block_ip")

        self.command_dropdown = customtkinter.CTkOptionMenu(
            self,
            values=[
                "block_ip",
                "unblock_ip",
                "static_block_ip",
                "static_unblock_ip",
                "block_port",
                "unblock_port",
            ],
            variable=self.command_var,
            command=self.update_fields_for_command
        )
        self.command_dropdown.grid(row=1, column=0, padx=10, pady=(10,5), sticky="ew",columnspan=2)

        # Frame that will contain dynamic input fields:
        self.fields_frame = customtkinter.CTkFrame(self)
        self.fields_frame.grid(row=2, column=0, sticky="ew", padx=10, pady=5)
        self.fields_frame.grid_columnconfigure(2, weight=1)

        # Create all possible input widgets:
        self.ip_entry = customtkinter.CTkEntry(self.fields_frame, placeholder_text="IP address")
        self.duration_entry = customtkinter.CTkEntry(self.fields_frame, placeholder_text="Duration (seconds)")
        self.port_entry = customtkinter.CTkEntry(self.fields_frame, placeholder_text="Port number")

        self.protocol_var = customtkinter.StringVar(value="TCP")
        self.protocol_menu = customtkinter.CTkOptionMenu(
            self.fields_frame, values=["TCP","UDP"], variable=self.protocol_var
        )

        self.direction_var = customtkinter.StringVar(value="any")
        self.direction_menu = customtkinter.CTkOptionMenu(
            self.fields_frame, values=["any","inbound","outbound"], variable=self.direction_var
        )

        # Action button
        self.send_btn = customtkinter.CTkButton(
            self,
            text="Send Command",
            command=self.send_selected_command
        )
        self.send_btn.grid(row=3, column=0, padx=10, pady=(5,10), sticky="ew", columnspan=2)

        # Blocked IP display starts at this row
        self.base_row = 3

        # Show initial field layout
        self.update_fields_for_command("block_ip")
        self.blocked_frame = customtkinter.CTkScrollableFrame(
            self,
            label_text="Blocked IP Addresses"
        )
        self.blocked_frame.bind("<Configure>", self._update_blocked_label_wrap)
        self.blocked_frame.grid(
            row=4, column=0,
            sticky="nsew",
            padx=10, pady=10,
            columnspan=4
        )

        self.blocked_frame.grid_columnconfigure((0,1,2,3), weight=1)

        self.update_blocked_list()

    def _update_blocked_label_wrap(self, event=None):
        # How wide the scrollable frame is
        width = self.blocked_frame.winfo_width()

        # Give labels some padding margin so they don't touch the sides
        wrap = max(width - 40, 50)  # 50px minimum wraplength

        # Update wrap for all blocked-IP labels
        for ip, data in self.blocked.items():
            data["label"].configure(wraplength=wrap)

    #  DYNAMIC FIELD HANDLING
    def clear_fields(self):
        for widget in self.fields_frame.winfo_children():
            widget.grid_forget()


    def update_fields_for_command(self, cmd):
        """Show only the relevant fields for the selected command."""
        self.clear_fields()

        # Commands requiring only IP
        if cmd in ("block_ip","unblock_ip","static_block_ip","static_unblock_ip"):
            self.ip_entry.grid(row=0, column=0, sticky="ew", pady=5,columnspan=2)

            if cmd == "block_ip":  # dynamic timed block
                self.duration_entry.grid(row=1, column=0, sticky="ew", pady=5,columnspan=2)

        # Commands requiring PORT + PROTOCOL (+ optional direction)
        elif cmd in ("block_port","unblock_port"):
            self.protocol_menu.grid(row=0, column=0, sticky="ew", pady=5, columnspan=2)
            self.port_entry.grid(row=1, column=0, sticky="ew", pady=5, columnspan=2)
            self.direction_menu.grid(row=2, column=0, sticky="ew", pady=5, columnspan=2)

    #  SEND COMMAND BUTTON
    def send_selected_command(self):
        cmd = self.command_var.get()

        # Build correct JSON object based on command
        event = {"type": cmd}

        if cmd in ("block_ip","unblock_ip","static_block_ip","static_unblock_ip"):
            ip = self.ip_entry.get().strip()
            if not ip:
                print("❌ Missing IP")
                return
            event["ip"] = ip

            if cmd == "block_ip":
                dur = self.duration_entry.get().strip()
                if dur.isdigit():
                    event["duration"] = int(dur)
                else:
                    print("⚠ No duration provided, defaulting to 10s")
                    event["duration"] = 10

        elif cmd in ("block_port","unblock_port"):
            proto = self.protocol_var.get()
            direction = self.direction_var.get()
            port_text = self.port_entry.get().strip()

            if not port_text.isdigit():
                print("❌ Invalid port")
                return

            event["protocol"] = proto
            event["port"] = int(port_text)
            event["direction"] = direction

        print("[GUI → Firewall] Sending:", event)
        self.app_ref.send_firewall_command(event)




    def add_blocked_ip(self, ip, duration, reason):

        if ip in self.blocked:
            self.update_blocked_ip(ip, duration, reason)
            return

        if duration < 0:
            text = f"{ip} — BLOCKED (STATIC RULE) due to {reason.upper()}"
        elif duration == 0:
            text = f"{ip} was UNBLOCKED due to {reason.upper()}" 
        else:
            text = f"{ip} — BLOCKED for {duration}s due to {reason.upper()}"

        label = customtkinter.CTkLabel(
            self.blocked_frame,
            text=text,
            text_color="red",
            wraplength=1
        )
        row = len(self.blocked)
        label.grid(row=row, column=0, sticky="ew", padx=10, pady=5, columnspan=4)

        self.blocked[ip] = {
            "reason": reason,
            "duration": duration,
            "timestamp": time.time(),
            "label": label,
            "expired": False
        }
    def remove_blocked_ip(self, ip, reason="manual"):
        if ip not in self.blocked:
            return  # Nothing to remove

        data = self.blocked[ip]
        old_label = data["label"]

        # Remove or hide the old blocked label
        old_label.grid_forget()

        # Create new green 'unblocked' label
        ts = time.strftime("%H:%M:%S")
        text = f"{ip} was UNBLOCKED at {ts} due to {reason.upper()}"

        new_label = customtkinter.CTkLabel(
            self.blocked_frame,
            text=text,
            text_color="green",
            wraplength=1
        )

        # Place it in the same position (replace old label)
        row = list(self.blocked.keys()).index(ip)
        new_label.grid(row=row, column=0, sticky="ew", padx=10, pady=5, columnspan=4)

        # Save updated entry
        self.blocked[ip] = {
            "reason": reason,
            "duration": 0,
            "timestamp": time.time(),
            "label": new_label,
            "expired": True
        }


    def update_blocked_ip(self, ip, duration, reason):
        self.blocked[ip]["reason"] = reason
        self.blocked[ip]["duration"] = duration
        self.blocked[ip]["timestamp"] = time.time()
        self.blocked[ip]["expired"] = False




    def update_blocked_list(self):
        now = time.time()

        for ip, data in list(self.blocked.items()):
            duration = data["duration"]
            reason = data["reason"].upper()

            if duration < 0:
                data["label"].configure(
                    text=f"{ip} — BLOCKED (STATIC RULE) due to {reason}", text_color="red"
                )
                continue
            elif duration == 0:
                data["label"].configure(
                    text=f"{ip} was UNBLOCKED due to {reason}", text_color="green"
                )
                # Optionally, remove from list after some time
                continue

            elapsed = now - data["timestamp"]
            remaining = int(duration - elapsed)

            if remaining > 0:
                data["label"].configure(
                    text=f"{ip} — BLOCKED for {duration}s ({remaining}s left) due to {reason}",
                    text_color="red"
                )
            else:
                if not data["expired"]:
                    data["label"].configure(
                        text=f"{ip} was blocked for {duration}s due to {reason}",
                        text_color="red"
                    )
                    data["expired"] = True

        self.after(500, self.update_blocked_list)
