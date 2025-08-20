import os
import hashlib
import tkinter as tk
from tkinter import filedialog, ttk
from collections import defaultdict

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
        
        tree_frame = ttk.Frame(main_frame)
        tree_frame.pack(fill=tk.BOTH, expand=True, pady=10)
        
        self.tree = ttk.Treeview(tree_frame, columns=("Size", "Count"), show="headings")
        self.tree.heading("Size", text="Size (bytes)")
        self.tree.column("Size", width=120, anchor=tk.E)
        self.tree.heading("Count", text="Duplicates")
        self.tree.column("Count", width=80, anchor=tk.CENTER)
        
        vsb = ttk.Scrollbar(tree_frame, orient="vertical", command=self.tree.yview)
        hsb = ttk.Scrollbar(tree_frame, orient="horizontal", command=self.tree.xview)
        self.tree.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)
        
        self.tree.grid(row=0, column=0, sticky="nsew")
        vsb.grid(row=0, column=1, sticky="ns")
        hsb.grid(row=1, column=0, sticky="ew")
        
        tree_frame.grid_rowconfigure(0, weight=1)
        tree_frame.grid_columnconfigure(0, weight=1)
        
        self.duplicates = defaultdict(list)
        self.hash_groups = defaultdict(list)
        self.file_map = {}
    
    def get_hash(self, filepath):
        hasher = hashlib.sha256()
        try:
            with open(filepath, "rb") as f:
                while chunk := f.read(8192):
                    hasher.update(chunk)
            return hasher.hexdigest()
        except Exception:
            return None
    
    def scan(self):
        folder = filedialog.askdirectory()
        if not folder:
            return
            
        self.status.set("Counting files...")
        self.progress_var.set(0)
        self.root.update()
        
        total_files = 0
        for root, _, files in os.walk(folder):
            total_files += len(files)
        
        size_map = defaultdict(list)
        processed_files = 0
        for root, _, files in os.walk(folder):
            for f in files:
                path = os.path.join(root, f)
                try:
                    size = os.path.getsize(path)
                    size_map[size].append(path)
                    processed_files += 1
                    if processed_files % 100 == 0:
                        self.progress_var.set(processed_files * 50 / total_files)
                        self.status.set(f"Files scanned: {processed_files}/{total_files}")
                        self.root.update()
                except OSError:
                    pass
        
        self.duplicates = {size: paths for size, paths in size_map.items() if len(paths) > 1}
        total_to_hash = sum(len(paths) for paths in self.duplicates.values())
        hash_files_processed = 0
        
        for size, paths in self.duplicates.items():
            hash_map = defaultdict(list)
            for path in paths:
                file_hash = self.get_hash(path)
                if file_hash:
                    hash_map[file_hash].append(path)
                
                hash_files_processed += 1
                if hash_files_processed % 5 == 0:
                    progress = 50 + (hash_files_processed * 50 / total_to_hash)
                    self.progress_var.set(progress)
                    self.status.set(f"Hashing: {hash_files_processed}/{total_to_hash}")
                    self.root.update()
            
            for h, dupes in hash_map.items():
                if len(dupes) > 1:
                    self.hash_groups[(size, h)] = dupes
        
        for (size, h), paths in self.hash_groups.items():
            item_id = self.tree.insert("", tk.END, values=(f"{size:,}", len(paths)))
            self.file_map[item_id] = (size, h, paths)
        
        self.progress_var.set(100)
        self.status.set(f"Scan complete! Found {len(self.hash_groups)} duplicate groups")

    def run(self):
        self.root.mainloop()

if __name__ == "__main__":
    app = DupeSweep()
    app.run()