import customtkinter
import time

class MyOverview(customtkinter.CTkScrollableFrame):
    def __init__(self, master, title):
        super().__init__(master, label_text=title)
        self.grid_columnconfigure(0, weight=1)

        # Store blocked IPs here:
        #   ip -> {"reason": str, "duration": int, "timestamp": float, "label": widget}
        self.blocked = {}

        # Update every second to refresh countdowns
        self.update_blocked_list()

    def add_blocked_ip(self, ip, duration, reason):
        """Add an IP to the list with a visible label."""
        # If already listed, update it instead
        if ip in self.blocked:
            self.update_blocked_ip(ip, duration, reason)
            return

        # Create label text
        text = f"⚠ {ip} — {reason.upper()} ({duration}s)"
        label = customtkinter.CTkLabel(self, text=text, text_color="red")
        row = len(self.blocked)

        label.grid(row=row, column=0, sticky="w", padx=10, pady=5)

        # Store
        self.blocked[ip] = {
            "reason": reason,
            "duration": duration,
            "timestamp": time.time(),
            "label": label
        }

    def update_blocked_ip(self, ip, duration, reason):
        """Update an existing blocked IP."""
        self.blocked[ip]["reason"] = reason
        self.blocked[ip]["duration"] = duration
        self.blocked[ip]["timestamp"] = time.time()

    def update_blocked_list(self):
        """Runs every second to update countdown timers."""
        now = time.time()
        remove_list = []

        for ip, data in self.blocked.items():
            elapsed = now - data["timestamp"]
            remaining = int(data["duration"] - elapsed)

            if remaining <= 0:
                # Time expired — remove label
                data["label"].destroy()
                remove_list.append(ip)
            else:
                # Update label text
                reason = data["reason"].upper()
                data["label"].configure(
                    text=f"⚠ {ip} — {reason} ({remaining}s)"
                )

        # Remove expired IPs
        for ip in remove_list:
            del self.blocked[ip]

        # Schedule next update
        self.after(1000, self.update_blocked_list)
