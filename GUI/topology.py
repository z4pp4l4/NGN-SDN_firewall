import customtkinter
from PIL import Image
from popups import ToplevelWindow

class MyTopologyFrame(customtkinter.CTkFrame):
    def __init__(self, master, title, values, int_hosts, ext_hosts):
        super().__init__(master)
        self.entities = []
        self.values = values
        self.title_label = title
        self.radiobuttons = []
        self.toplevel_window = None
        self.variable = customtkinter.StringVar(value="")

        max_cols = max(len(int_hosts), len(ext_hosts), len(values))
        for c in range(max_cols + 2):
            self.grid_columnconfigure(c, weight=1)
        for r in range(5):
            self.grid_rowconfigure(r, weight=1)

        self.title_label = customtkinter.CTkLabel(self, text=self.title_label, fg_color="gray30", corner_radius=6)
        self.title_label.grid(row=0, column=0, padx=5, pady=(5, 0), sticky="ew", columnspan=max_cols + 2)

        for i, value in enumerate(self.values):
            radiobutton = customtkinter.CTkRadioButton(self, text=value, value=value, variable=self.variable)
            radiobutton.grid(row=1, column=i+1, padx=5, pady=2)
            self.radiobuttons.append(radiobutton)

        # Internal hosts
        for i, int_host in enumerate(int_hosts):
            circle_img = customtkinter.CTkImage(light_image=Image.open("images/circle.png"), size=(30, 30))
            btn = customtkinter.CTkButton(
                self, image=circle_img, text=int_host, width=40, height=40, corner_radius=8,
                command=lambda i_h=int_host: self.on_click(i_h)
            )
            btn.grid(row=2, column=i+1, padx=5, pady=5)
            self.entities.append(btn)

        # Switch
        switch_image = customtkinter.CTkImage(light_image=Image.open("images/switch.png"), size=(30, 30))
        switch_col = len(int_hosts)//2 + 1
        btn = customtkinter.CTkButton(
            self, image=switch_image, text="switch", width=40, height=40, corner_radius=8,
            command=lambda: self.on_click("switch")
        )
        btn.grid(row=3, column=switch_col, padx=5, pady=3)
        self.entities.append(btn)

        # Controller
        controller_image = customtkinter.CTkImage(light_image=Image.open("images/controller.png"), size=(30, 30))
        btn = customtkinter.CTkButton(
            self, image=controller_image, text="controller", width=40, height=40, corner_radius=8,
            command=lambda: self.on_click("controller")
        )
        btn.grid(row=3, column=max(1, switch_col - 2), padx=5, pady=3)
        self.entities.append(btn)

        # External hosts
        for i, ext_host in enumerate(ext_hosts):
            hacker_image = customtkinter.CTkImage(light_image=Image.open("images/hacker.png"), size=(15, 15))
            btn = customtkinter.CTkButton(
                self, image=hacker_image, text=ext_host, width=30, height=30, corner_radius=8,
                command=lambda e_h=ext_host: self.on_click(e_h)
            )
            btn.grid(row=4, column=i+1, padx=5, pady=3)
            self.entities.append(btn)

    def on_click(self, value):
        self.selected = value
        ToplevelWindow(self, value)

    def get(self):
        return self.variable.get()

    def set(self, value):
        self.variable.set(value)
