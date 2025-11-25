import customtkinter
from PIL import Image
from popups import ToplevelWindow
class MyTopologyFrame(customtkinter.CTkFrame):
    def __init__(self, master, title, values, int_hosts, ext_hosts):
        super().__init__(master)
        self.grid_columnconfigure((0,1,2,3,4,5,6), weight=1)
        self.grid_rowconfigure((0,1,2,3,4), weight=1)
        self.entities = []
        self.values = values
        self.title_label = title
        self.radiobuttons = []
        self.toplevel_window = None
        self.variable = customtkinter.StringVar(value="")

        self.title_label = customtkinter.CTkLabel(self, text=self.title_label, fg_color="gray30", corner_radius=6)
        self.title_label.grid(row=0, column=0, padx=10, pady=(10, 0), sticky="ew", columnspan=(len(self.values)+len(ext_hosts)))

        for i, value in enumerate(self.values):
            radiobutton = customtkinter.CTkRadioButton(self, text=value, value=value, variable=self.variable)
            radiobutton.grid(row=1, column=i+2, padx=10, pady=(10, 0), sticky="w")
            self.radiobuttons.append(radiobutton)
        #internal host topology
        for i,int_host in enumerate(int_hosts):
            circle_img = customtkinter.CTkImage(light_image=Image.open("images/circle.png"), size=(40, 40))
            btn = customtkinter.CTkButton(self, image=circle_img, text=int_host, width=50, height=50, corner_radius=10, command=lambda i_h=int_host: self.on_click(i_h))
            btn.grid(row = 2, column = i+2, padx=10, pady=10)
            self.entities.append(btn)
        #switch
        switch_image=customtkinter.CTkImage(light_image=Image.open("images/switch.png"), size=(40, 40))
        btn=customtkinter.CTkButton(self, image=switch_image, text="switch", width=50, height=50, corner_radius=10, command = lambda: self.on_click("switch"))
        btn.grid(row=3, column = 3, padx=10, pady=10)
        self.entities.append(btn)
        #controller
        controller_image=customtkinter.CTkImage(light_image=Image.open("images/controller.png"), size=(40,40))
        btn=customtkinter.CTkButton(self, image=controller_image, text="controller", width=50, height=50, corner_radius=10, command= lambda: self.on_click("controller"))
        btn.grid(row=3, column = 1, padx=10, pady=10)
        self.entities.append(btn)
        #external hosts
        for i, ext_host in enumerate(ext_hosts):
            hacker_image = customtkinter.CTkImage(light_image=Image.open("images/hacker.png"), size=(15, 15))
            btn = customtkinter.CTkButton(self, image=hacker_image, text=ext_host, width=20, height=20, corner_radius=10, command=lambda e_h=ext_host: self.on_click(e_h))
            btn.grid(row=4, column=i, padx=10, pady=10)
            self.entities.append(btn)

    def on_click(self, value):
        self.selected=value
        ToplevelWindow(self, value)

    def get(self):
        return self.variable.get()

    def set(self, value):
        self.variable.set(value) 