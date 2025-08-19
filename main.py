import tkinter as tk
from tkinter import ttk, filedialog

class DupeSweep:
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("DupliClean")
        self.root.geometry("800x600")
        
        main_frame = ttk.Frame(self.root)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        scan_frame = ttk.Frame(main_frame)
        scan_frame.pack(fill=tk.X, pady=5)
        
        scan_btn = ttk.Button(scan_frame, text="Scan Folder", command=self.scan)
        scan_btn.pack(side=tk.LEFT, padx=5)
        
        progress_frame = ttk.Frame(main_frame)
        progress_frame.pack(fill=tk.X, pady=5)
        
        self.progress_var = tk.DoubleVar()
        self.progress = ttk.Progressbar(progress_frame, length=750, variable=self.progress_var)
        self.progress.pack(fill=tk.X)
        
        self.status = tk.StringVar()
        self.status.set("Ready to scan")
        status_lbl = ttk.Label(progress_frame, textvariable=self.status)
        status_lbl.pack(pady=5)
        
        results_frame = ttk.Frame(main_frame)
        results_frame.pack(fill=tk.BOTH, expand=True, pady=10)
        
    def scan(self):
        folder = filedialog.askdirectory()
        if not folder:
            return
        self.status.set("Scanning...")
        self.progress_var.set(30)
        
    def run(self):
        self.root.mainloop()

if __name__ == "__main__":
    app = DupeSweep()
    app.run()