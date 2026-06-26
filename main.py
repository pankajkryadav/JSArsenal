# main.py
import customtkinter
from ui import MainFrame
import multiprocessing

class App(customtkinter.CTk):
    def __init__(self):
        super().__init__()
        # NEW: Branded title with logo
        self.title("⚙️ JS Arsenal by pankajkryadav")
        self.geometry("850x750") # Slightly taller for new fields

        self.main_frame = MainFrame(master=self)
        self.main_frame.pack(padx=10, pady=10, fill="both", expand=True)
        self.protocol("WM_DELETE_WINDOW", self.on_closing)

    def on_closing(self):
        # Gracefully stop the backend process if it's running
        self.main_frame.engine.stop_analysis()
        self.destroy()

if __name__ == "__main__":
    multiprocessing.freeze_support()
    app = App()
    app.mainloop()