import customtkinter
import tkinter as tk
from PIL import Image
from popups import ToplevelWindow


class MyTopologyFrame(customtkinter.CTkFrame):
    def __init__(self, master, app_ref, title, int_hosts, ext_hosts):
        super().__init__(master)
        self.app_ref = app_ref
        self.title_label_text = title

        self.toplevel_window = None
        self.grid_columnconfigure((0,1,2), weight=1)
        self.grid_rowconfigure((0,1), weight=1)

        # Title
        title_label = customtkinter.CTkLabel(
            self, text=self.title_label_text,
            fg_color="gray30", corner_radius=6,
            padx=10, pady=6
        )
        title_label.grid(row=0, column=0, columnspan=3, pady=10, sticky="ew")

        
        self.internal_frame = DashedBubble(self, width=200, height=300, label="192.168.10.0/29")
        self.internal_frame.grid(row=1, column=0, padx=20, pady=10)

        self.populate_hosts(self.internal_frame.inner, int_hosts, "images/circle.png", size=(35, 35))

        self.external_frame = DashedBubble(self, width=200, height=350, label="192.168.20.0/28")
        self.external_frame.grid(row=1, column=1, padx=20, pady=10)

        self.populate_hosts(self.external_frame.inner, ext_hosts, "images/hacker.png", size=(28, 28))

        self.controller_frame = DashedBubble(self, width=150, height=250, label="192.168.100.0/30")
        self.controller_frame.grid(row=1, column=2, padx=20, pady=10)

        self.populate_hosts(self.controller_frame.inner, ["controller"], "images/controller.png", size=(40, 40))

    # -------------------------------------------------
    #  Populate a bubble with image-buttons
    # -------------------------------------------------
    def populate_hosts(self, frame, host_list, icon_path, size):
        for host in host_list:
            img = customtkinter.CTkImage(
                light_image=Image.open(icon_path),
                size=size
            )

            btn = customtkinter.CTkButton(
                frame,
                image=img,
                text="",
                width=size[0] + 10,
                height=size[1] + 10,
                fg_color="transparent",
                hover_color="gray30",
                command=lambda h=host: self.on_click(h)
            )
            btn.pack(pady=6)


    def on_click(self, value):
        ip = None
    
        # compute IP the same way the popup class does
        parts = value.split()
        cat = parts[0]
    
        if cat == "host":
            ip = f"192.168.10.{int(parts[1])}"
        elif cat == "controller":
            ip = "192.168.100.1"
        elif cat != "switch":  # external host
            ip = f"192.168.20.{int(parts[1])}"
    
        # if popup exists already → focus it
        if ip and ip in self.app_ref.open_popups:
            popup = self.app_ref.open_popups[ip]
            popup.lift()
            popup.focus_force()
            return
    
        # otherwise create a new popup
        ToplevelWindow(self, value, self.app_ref)


class DashedBubble(customtkinter.CTkFrame):
    def __init__(self, master, label="Network", width=180, height=260):
        super().__init__(master, fg_color="transparent")

        self.label = customtkinter.CTkLabel(
            self,
            text=label,
            font=("Arial", 16, "bold"),
            text_color="#444"
        )
        self.label.pack(pady=(0, 5))

        # ✔ FIX: use a single safe color for Canvas
        bg_color = self._apply_appearance_mode("#e5e5e5")

        self.canvas = tk.Canvas(
            self,
            width=width,
            height=height,
            bg=bg_color,
            highlightthickness=0
        )
        self.canvas.pack()

        self._draw_dashed_bubble(width, height)

        self.inner = customtkinter.CTkFrame(self.canvas, fg_color="transparent")
        self.canvas.create_window(width//2, height//2, window=self.inner)
    def _draw_dashed_bubble(self, w, h):
        r = 40          # rounded corner radius
        dash = (4, 4)   # dashed pattern
        color = "#bbbbbb"
        # Corners
        self.canvas.create_arc(0, 0, r*2, r*2,
            start=90, extent=90, style="arc",
            outline=color, width=2, dash=dash)
        self.canvas.create_arc(w-r*2, 0, w, r*2,
            start=0, extent=90, style="arc",
            outline=color, width=2, dash=dash)
        self.canvas.create_arc(w-r*2, h-r*2, w, h,
            start=270, extent=90, style="arc",
            outline=color, width=2, dash=dash)
        self.canvas.create_arc(0, h-r*2, r*2, h,
            start=180, extent=90, style="arc",
            outline=color, width=2, dash=dash)
        # Lines between corners
        self.canvas.create_line(r, 0, w-r, 0,
            fill=color, width=2, dash=dash)
        self.canvas.create_line(r, h, w-r, h,
            fill=color, width=2, dash=dash)
        self.canvas.create_line(0, r, 0, h-r,
            fill=color, width=2, dash=dash)
        self.canvas.create_line(w, r, w, h-r,
            fill=color, width=2, dash=dash)
