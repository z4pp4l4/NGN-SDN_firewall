import customtkinter

class MyRadioButtonFrame(customtkinter.CTkFrame):
    def __init__(self, master, values):
        super().__init__(master)
        self.values = values
        self.radiobuttons = []
        self.variable = customtkinter.StringVar(value="")
        self.grid_columnconfigure((0,1,2), weight=1)
        self.grid_rowconfigure((0,1), weight=1)

        self.radiobutton_title=customtkinter.CTkLabel(self, text="Configurations", fg_color="gray30", corner_radius=6)
        self.radiobutton_title.grid(row=0, column=0, padx=5, pady=5, sticky="ew", columnspan=3)

        for i, value in enumerate(self.values):
            radiobutton = customtkinter.CTkRadioButton(self, text=value, value=value, variable=self.variable)
            radiobutton.grid(row=1, column=i, padx=5, pady=2)
            self.radiobuttons.append(radiobutton)
    def get(self):
        return self.variable.get()

    def set(self, value):
        self.variable.set(value)
