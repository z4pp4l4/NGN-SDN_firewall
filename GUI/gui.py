import customtkinter
from PIL import Image

class MyRadiobuttonFrame(customtkinter.CTkFrame):
    def __init__(self, master, title, values, int_hosts, ext_hosts):
        super().__init__(master)
        self.grid_columnconfigure((0,1,2,3,4,5,6), weight=1)
        self.grid_rowconfigure((0,1,2,3,4), weight=1)
        self.entities = []
        self.values = values
        self.title = title
        self.radiobuttons = []
        self.variable = customtkinter.StringVar(value="")

        self.title = customtkinter.CTkLabel(self, text=self.title, fg_color="gray30", corner_radius=6)
        self.title.grid(row=0, column=0, padx=10, pady=(10, 0), sticky="ew", columnspan=(len(self.values)+len(ext_hosts)))

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
        #external hosts
        for i, ext_host in enumerate(ext_hosts):
            hacker_image = customtkinter.CTkImage(light_image=Image.open("images/hacker.png"), size=(15, 15))
            btn = customtkinter.CTkButton(self, image=hacker_image, text=ext_host, width=20, height=20, corner_radius=10, command=lambda e_h=ext_host: self.on_click(e_h))
            btn.grid(row=4, column=i, padx=10, pady=10)
            self.entities.append(btn)

    def on_click(self, value):
        self.selected=value
        return self.selected

    def get(self):
        return self.variable.get()

    def set(self, value):
        self.variable.set(value) 


class MyScrollableCheckboxFrame(customtkinter.CTkScrollableFrame):
    def __init__(self, master, title, values):
        super().__init__(master, label_text=title)
        self.grid_columnconfigure(0, weight=1)
        self.values = values
        self.checkboxes = []

        for i, value in enumerate(self.values):
            checkbox = customtkinter.CTkCheckBox(self, text=value)
            checkbox.grid(row=i, column=0, padx=10, pady=(10, 0), sticky="w")
            self.checkboxes.append(checkbox)

    def get(self):
        checked_checkboxes = []
        for checkbox in self.checkboxes:
            if checkbox.get() == 1:
                checked_checkboxes.append(checkbox.cget("text"))
        return checked_checkboxes
class App(customtkinter.CTk):
    def __init__(self):
        super().__init__()

        self.title("NGN GUI")
        self.geometry("800x800")
        self.grid_columnconfigure((0, 1), weight=1)
        self.grid_rowconfigure((0,1), weight=1)

        values = ["firewall 1", "firewall 2", "firewall 3"]
        int_hosts = ["pc hr", "pc ceo", "pc coo"]
        ext_hosts = ["hack 1", "hack 2", "hack 3", "hack 4", "hack 5", "hack 6", "hack 7"]
        self.radiobutton_frame = MyRadiobuttonFrame(self, title="Topology", values=values, int_hosts=int_hosts, ext_hosts=ext_hosts)
        self.radiobutton_frame.grid(row=0, column=0, padx=10, pady=(10,0), sticky="nsew")
        self.scrollable_checkbox_frame = MyScrollableCheckboxFrame(self, title="Overview", values=values)
        self.scrollable_checkbox_frame.grid(row=0, column=1, padx=10, pady=(10,0), sticky="nsew")

        self.button = customtkinter.CTkButton(self, text="start simulation", command=self.button_callback)
        self.button.grid(row=3, column=0, padx=10, pady=10, sticky="ew")

    def button_callback(self):
        print("overview checkbox:", self.scrollable_checkbox_frame.get())
        print("simulation checkbox:", self.radiobutton_frame.get())

app = App()
app.mainloop()