import customtkinter
import time

class MyOverview(customtkinter.CTkScrollableFrame):
    def __init__(self, master, title):
        super().__init__(master, label_text=title)
        self.grid_columnconfigure(0, weight=1)

        self.blocked = {}
        self.bind("<Configure>", self._update_wrap_lengths)

        self.update_blocked_list()
    def _update_wrap_lengths(self, event):
        for ip, data in self.blocked.items():
            label = data["label"]
            label.configure(wraplength=self.winfo_width() - 40)
    def add_blocked_ip(self, ip, duration, reason):
        """Add an IP to the list with visible label."""
        if ip in self.blocked:
            self.update_blocked_ip(ip, duration, reason)
            return

        text = f"{ip} — BLOCKED for {duration}s due to {reason.upper()}"
        label = customtkinter.CTkLabel(self, text=text, text_color="red", wraplength=1)
        row = len(self.blocked)

        label.grid(row=row, column=0, sticky="ew", padx=10, pady=5)

        self.blocked[ip] = {
            "reason": reason,
            "duration": duration,
            "timestamp": time.time(),
            "label": label,
            "expired": False
        }

    def update_blocked_ip(self, ip, duration, reason):
        """Update an existing block entry."""
        self.blocked[ip]["reason"] = reason
        self.blocked[ip]["duration"] = duration
        self.blocked[ip]["timestamp"] = time.time()
        self.blocked[ip]["expired"] = False 

    def update_blocked_list(self):
        """Update countdown, and leave text after expiration."""
        now = time.time()

        for ip, data in list(self.blocked.items()):
            elapsed = now - data["timestamp"]
            remaining = int(data["duration"] - elapsed)

            reason = data["reason"].upper()

            if remaining > 0:
                data["label"].configure(
                    text=f"⚠ {ip} — BLOCKED for {data['duration']}s due to {reason} ({remaining}s left)",
                    text_color="red"
                )
            else:
                if not data["expired"]:
                    data["label"].configure(
                        text=f"{ip} was blocked for {data['duration']} seconds due to {reason}",
                        text_color="red"
                    )
                    data["expired"] = True

        self.after(1000, self.update_blocked_list)
