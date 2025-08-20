import os
import hashlib
import gc
import tkinter as tk
from tkinter import filedialog, ttk, messagebox
from collections import defaultdict

class DupeSweep:
    BATCH_SIZE = 500
    
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("DupliClean")
        self.root.geometry("900x700")
        
        main_frame = ttk.Frame(self.root)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        scan_frame = ttk.Frame(main_frame)
        scan_frame.pack(fill=tk.X, pady=5)
        scan_btn = ttk.Button(scan_frame, text="Scan Folder", command=self.scan)
        scan_btn.pack(side=tk.LEFT, padx=5)
        
        self.cancel_btn = ttk.Button(scan_frame, text="Cancel Scan", command=self.cancel_scan, state=tk.DISABLED)
        self.cancel_btn.pack(side=tk.LEFT, padx=5)
        
        progress_frame = ttk.Frame(main_frame)
        progress_frame.pack(fill=tk.X, pady=5)
        
        self.progress_var = tk.DoubleVar()
        self.progress = ttk.Progressbar(progress_frame, length=800, variable=self.progress_var)
        self.progress.pack(fill=tk.X)
        
        self.status = tk.StringVar()
        self.status.set("Ready to scan")
        status_lbl = ttk.Label(progress_frame, textvariable=self.status)
        status_lbl.pack(pady=5)
        
        tree_frame = ttk.Frame(main_frame)
        tree_frame.pack(fill=tk.BOTH, expand=True, pady=10)
        
        self.tree = ttk.Treeview(tree_frame, columns=("Size", "Count", "Hash"), show="headings", selectmode="browse")
        self.tree.heading("Size", text="Size (bytes)")
        self.tree.column("Size", width=120, anchor=tk.E)
        self.tree.heading("Count", text="Duplicates")
        self.tree.column("Count", width=80, anchor=tk.CENTER)
        self.tree.heading("Hash", text="Content Hash")
        self.tree.column("Hash", width=200)
        
        vsb = ttk.Scrollbar(tree_frame, orient="vertical", command=self.tree.yview)
        hsb = ttk.Scrollbar(tree_frame, orient="horizontal", command=self.tree.xview)
        self.tree.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)
        
        self.tree.grid(row=0, column=0, sticky="nsew")
        vsb.grid(row=0, column=1, sticky="ns")
        hsb.grid(row=1, column=0, sticky="ew")
        
        tree_frame.grid_rowconfigure(0, weight=1)
        tree_frame.grid_columnconfigure(0, weight=1)
        
        details_frame = ttk.LabelFrame(main_frame, text="Selected Duplicate Group")
        details_frame.pack(fill=tk.X, pady=5)
        
        self.details_var = tk.StringVar()
        details_label = ttk.Label(details_frame, textvariable=self.details_var, wraplength=850)
        details_label.pack(fill=tk.X, padx=5, pady=2)
        
        list_frame = ttk.Frame(details_frame)
        list_frame.pack(fill=tk.X, padx=5, pady=5)
        
        ttk.Label(list_frame, text="Files in this group:").pack(anchor=tk.W)
        
        self.file_listbox = tk.Listbox(list_frame, height=6, selectmode=tk.EXTENDED)
        self.file_listbox.pack(fill=tk.X, pady=5)
        
        selection_frame = ttk.Frame(details_frame)
        selection_frame.pack(fill=tk.X, pady=5)
                
        action_frame = ttk.Frame(main_frame)
        action_frame.pack(fill=tk.X, pady=5)
        
        self.delete_btn = ttk.Button(action_frame, text="Delete Selected Files", command=self.delete_selected, state=tk.DISABLED)
        self.delete_btn.pack(side=tk.LEFT, padx=5)
        
        self.duplicates = defaultdict(list)
        self.hash_groups = defaultdict(list)
        self.file_map = {}
        self.current_group = None
        self.scan_canceled = False
        
        self.tree.bind("<<TreeviewSelect>>", self.on_tree_select)
    
    def get_hash(self, filepath):
        hasher = hashlib.sha256()
        try:
            with open(filepath, "rb") as f:
                while chunk := f.read(8192):
                    hasher.update(chunk)
            return hasher.hexdigest()
        except Exception:
            return None
            
    def cancel_scan(self):
        self.scan_canceled = True
        self.cancel_btn.config(state=tk.DISABLED)
    
    def scan(self):
        folder = filedialog.askdirectory()
        if not folder:
            return
            
        self.scan_canceled = False
        self.cancel_btn.config(state=tk.NORMAL)
        
        for item in self.tree.get_children():
            self.tree.delete(item)
        self.duplicates.clear()
        self.hash_groups.clear()
        self.file_map.clear()
        self.file_listbox.delete(0, tk.END)
        self.details_var.set("")
        self.delete_btn.config(state=tk.DISABLED)
        
        self.status.set("Counting files...")
        self.progress_var.set(0)
        self.root.update()
        
        total_files = 0
        for root, _, files in os.walk(folder):
            total_files += len(files)
        
        size_map = defaultdict(list)
        processed_files = 0
        batch_count = 0
        
        for root, _, files in os.walk(folder):
            if self.scan_canceled:
                self.status.set("Scan canceled")
                self.cancel_btn.config(state=tk.DISABLED)
                return
                
            for f in files:
                path = os.path.join(root, f)
                try:
                    if not os.path.isfile(path):
                        continue
                    size = os.path.getsize(path)
                    size_map[size].append(path)
                    processed_files += 1
                    
                    if processed_files % 100 == 0:
                        self.progress_var.set(processed_files * 50 / total_files)
                        self.status.set(f"Files scanned: {processed_files}/{total_files}")
                        self.root.update()
                except OSError:
                    pass
                
                batch_count += 1
                if batch_count >= self.BATCH_SIZE:
                    gc.collect()
                    batch_count = 0
            
            gc.collect()
        
        self.duplicates = {size: paths for size, paths in size_map.items() if len(paths) > 1}
        self.status.set(f"Found {len(self.duplicates)} potential duplicate groups")
        self.root.update()
        
        total_to_hash = sum(len(paths) for paths in self.duplicates.values())
        hash_files_processed = 0
        batch_count = 0
        
        for size, paths in self.duplicates.items():
            if self.scan_canceled:
                self.status.set("Scan canceled")
                self.cancel_btn.config(state=tk.DISABLED)
                return
                
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
                
                batch_count += 1
                if batch_count >= self.BATCH_SIZE:
                    gc.collect()
                    batch_count = 0
            
            for h, dupes in hash_map.items():
                if len(dupes) > 1:
                    self.hash_groups[(size, h)] = dupes
        
        for (size, h), paths in self.hash_groups.items():
            item_id = self.tree.insert("", tk.END, values=(f"{size:,}", len(paths), h[:16] + "..."))
            self.file_map[item_id] = (size, h, paths)
        
        self.progress_var.set(100)
        self.status.set(f"Scan complete! Found {len(self.hash_groups)} duplicate groups")
        self.cancel_btn.config(state=tk.DISABLED)
    
    def on_tree_select(self, event):
        self.file_listbox.delete(0, tk.END)
        self.details_var.set("")
        self.current_group = None
        self.delete_btn.config(state=tk.DISABLED)
        
        selected_items = self.tree.selection()
        if not selected_items:
            return
        
        item_id = selected_items[0]
        group_data = self.file_map.get(item_id)
        if not group_data:
            return
            
        size, h, paths = group_data
        self.current_group = group_data
        self.details_var.set(f"Duplicate Group: {len(paths)} files, Size: {size:,} bytes, Hash: {h[:16]}...")
        
        for path in paths:
            self.file_listbox.insert(tk.END, path)
        
        self.delete_btn.config(state=tk.NORMAL)
    
    def delete_selected(self):
        if not self.current_group:
            return
            
        selected = self.file_listbox.curselection()
        if not selected:
            messagebox.showinfo("No Selection", "Please select files to delete first.")
            return
            
        if not messagebox.askyesno("Confirm Deletion", "Permanently delete selected files?"):
            return
            
        deleted_count = 0
        for idx in selected:
            path = self.file_listbox.get(idx)
            try:
                os.remove(path)
                deleted_count += 1
            except Exception as e:
                print(f"Error deleting {path}: {e}")
        
        messagebox.showinfo("Deletion Complete", f"Deleted {deleted_count} files")
        self.scan()
    
    def run(self):
        self.root.mainloop()

if __name__ == "__main__":
    app = DupeSweep()
    app.run()
