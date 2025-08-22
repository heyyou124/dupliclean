import os
import hashlib
import gc
import tkinter as tk
from tkinter import filedialog, ttk, messagebox
from collections import defaultdict
from PIL import Image, ImageTk

class DupeSweep:
    BATCH_SIZE = 500
    
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("DupliClean")
        self.root.geometry("1000x800")
        self.root.minsize(900, 700)
        
        self.style = ttk.Style()
        self.style.configure("TButton", padding=6)
        self.style.configure("Title.TLabel", font=('Helvetica', 10, 'bold'))
        
        main_frame = ttk.Frame(self.root)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        header_frame = ttk.Frame(main_frame)
        header_frame.pack(fill=tk.X, pady=(0, 10))
        
        title_label = ttk.Label(header_frame, text="DupliClean - Duplicate File Finder", 
                               style="Title.TLabel")
        title_label.pack(side=tk.LEFT)
        
        scan_frame = ttk.Frame(header_frame)
        scan_frame.pack(side=tk.RIGHT)
        
        scan_btn = ttk.Button(scan_frame, text="Scan Folder", command=self.scan)
        scan_btn.pack(side=tk.LEFT, padx=5)
        
        self.cancel_btn = ttk.Button(scan_frame, text="Cancel Scan", command=self.cancel_scan, state=tk.DISABLED)
        self.cancel_btn.pack(side=tk.LEFT, padx=5)
        
        progress_frame = ttk.LabelFrame(main_frame, text="Progress")
        progress_frame.pack(fill=tk.X, pady=5)
        
        self.progress_var = tk.DoubleVar()
        self.progress = ttk.Progressbar(progress_frame, length=850, variable=self.progress_var, mode='determinate')
        self.progress.pack(fill=tk.X, padx=5, pady=5)
        
        self.status = tk.StringVar()
        self.status.set("Ready to scan")
        status_lbl = ttk.Label(progress_frame, textvariable=self.status)
        status_lbl.pack(pady=(0, 5))
        
        stats_frame = ttk.Frame(progress_frame)
        stats_frame.pack(fill=tk.X, padx=5, pady=(0, 5))
        
        self.stats_var = tk.StringVar()
        self.stats_var.set("Total duplicates: 0 | Space wasted: 0 bytes")
        stats_label = ttk.Label(stats_frame, textvariable=self.stats_var)
        stats_label.pack(side=tk.LEFT)
        
        results_frame = ttk.LabelFrame(main_frame, text="Duplicate Groups")
        results_frame.pack(fill=tk.BOTH, expand=True, pady=5)
        
        tree_frame = ttk.Frame(results_frame)
        tree_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
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
        details_label = ttk.Label(details_frame, textvariable=self.details_var, wraplength=950)
        details_label.pack(fill=tk.X, padx=5, pady=2)
        
        preview_frame = ttk.Frame(details_frame)
        preview_frame.pack(fill=tk.X, padx=5, pady=5)
        
        preview_container = ttk.Frame(preview_frame)
        preview_container.pack(fill=tk.X)
        
        self.preview_canvas = tk.Canvas(preview_container, height=90, bg='#f0f0f0')
        self.preview_canvas.pack(side=tk.LEFT, fill=tk.X, expand=True)
        
        preview_scroll = ttk.Scrollbar(preview_container, orient=tk.HORIZONTAL, command=self.preview_canvas.xview)
        preview_scroll.pack(side=tk.RIGHT, fill=tk.Y)
        self.preview_canvas.configure(xscrollcommand=preview_scroll.set)
        
        list_frame = ttk.Frame(details_frame)
        list_frame.pack(fill=tk.X, padx=5, pady=5)
        
        ttk.Label(list_frame, text="Files in this group:").pack(anchor=tk.W)
        
        self.file_listbox = tk.Listbox(list_frame, height=6, selectmode=tk.EXTENDED)
        self.file_listbox.pack(fill=tk.X, pady=5)
        
        selection_frame = ttk.Frame(details_frame)
        selection_frame.pack(fill=tk.X, pady=5)
        
        ttk.Button(selection_frame, text="Select All", command=self.select_all).pack(side=tk.LEFT, padx=5)
        ttk.Button(selection_frame, text="Clear Selection", command=self.clear_selection).pack(side=tk.LEFT, padx=5)
        ttk.Button(selection_frame, text="Invert Selection", command=self.invert_selection).pack(side=tk.LEFT, padx=5)
        
        action_frame = ttk.Frame(main_frame)
        action_frame.pack(fill=tk.X, pady=5)
        
        self.delete_btn = ttk.Button(action_frame, text="Delete Selected Files", command=self.delete_selected, state=tk.DISABLED)
        self.delete_btn.pack(side=tk.LEFT, padx=5)
        
        self.delete_all_btn = ttk.Button(action_frame, text="Delete All Duplicates (Keep One)", 
                                       command=self.delete_all_duplicates, state=tk.DISABLED)
        self.delete_all_btn.pack(side=tk.LEFT, padx=5)
        
        self.export_btn = ttk.Button(action_frame, text="Export File List", command=self.export_file_list, state=tk.DISABLED)
        self.export_btn.pack(side=tk.LEFT, padx=5)
        
        self.duplicates = defaultdict(list)
        self.hash_groups = defaultdict(list)
        self.file_map = {}
        self.current_group = None
        self.scan_canceled = False
        self.preview_labels = []
        self.previews = []
        self.total_duplicate_files = 0
        self.total_wasted_space = 0
        
        self.tree.bind("<<TreeviewSelect>>", self.on_tree_select)
        self.file_listbox.bind("<<ListboxSelect>>", self.on_file_select)
        
        self.setup_context_menu()
    
    def setup_context_menu(self):
        self.context_menu = tk.Menu(self.root, tearoff=0)
        self.context_menu.add_command(label="Open File Location", command=self.open_file_location)
        self.context_menu.add_command(label="Copy File Path", command=self.copy_file_path)
        
        self.file_listbox.bind("<Button-3>", self.show_context_menu)
    
    def show_context_menu(self, event):
        try:
            self.context_menu.tk_popup(event.x_root, event.y_root)
        finally:
            self.context_menu.grab_release()
    
    def open_file_location(self):
        selected = self.file_listbox.curselection()
        if selected:
            path = self.file_listbox.get(selected[0])
            folder = os.path.dirname(path)
            if os.name == 'nt':
                os.startfile(folder)
            elif os.name == 'posix':
                os.system(f'open "{folder}"' if sys.platform == 'darwin' else f'xdg-open "{folder}"')
    
    def copy_file_path(self):
        selected = self.file_listbox.curselection()
        if selected:
            path = self.file_listbox.get(selected[0])
            self.root.clipboard_clear()
            self.root.clipboard_append(path)
    
    def export_file_list(self):
        if not self.hash_groups:
            messagebox.showinfo("No Data", "No duplicate files to export.")
            return
            
        filename = filedialog.asksaveasfilename(
            defaultextension=".txt",
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")]
        )
        
        if not filename:
            return
            
        try:
            with open(filename, 'w') as f:
                f.write("DupliClean - Duplicate File Report\n")
                f.write("=" * 50 + "\n\n")
                
                for (size, h), paths in self.hash_groups.items():
                    f.write(f"Group: {size} bytes, {len(paths)} duplicates\n")
                    f.write(f"Hash: {h}\n")
                    f.write("Files:\n")
                    
                    for path in paths:
                        f.write(f"  {path}\n")
                    
                    f.write("\n")
                
                f.write(f"Total duplicate groups: {len(self.hash_groups)}\n")
                f.write(f"Total duplicate files: {self.total_duplicate_files}\n")
                f.write(f"Total wasted space: {self.format_file_size(self.total_wasted_space)}\n")
            
            messagebox.showinfo("Export Complete", f"File list exported to {filename}")
        except Exception as e:
            messagebox.showerror("Export Error", f"Failed to export file list: {str(e)}")
    
    def format_file_size(self, size_bytes):
        for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
            if size_bytes < 1024.0:
                return f"{size_bytes:.2f} {unit}"
            size_bytes /= 1024.0
        return f"{size_bytes:.2f} PB"
    
    def get_hash(self, filepath):
        hasher = hashlib.sha256()
        try:
            with open(filepath, "rb") as f:
                while chunk := f.read(8192):
                    if self.scan_canceled:
                        return None
                    hasher.update(chunk)
            return hasher.hexdigest()
        except Exception:
            return None
            
    def cancel_scan(self):
        self.scan_canceled = True
        self.cancel_btn.config(state=tk.DISABLED)
        self.status.set("Canceling scan...")
    
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
        self.delete_all_btn.config(state=tk.DISABLED)
        self.export_btn.config(state=tk.DISABLED)
        self.preview_canvas.delete("all")
        
        for label in self.preview_labels:
            label.destroy()
        self.preview_labels = []
        self.previews = []
        
        self.status.set("Counting files...")
        self.progress_var.set(0)
        self.stats_var.set("Total duplicates: 0 | Space wasted: 0 bytes")
        self.root.update()
        
        total_files = 0
        for root, _, files in os.walk(folder):
            if self.scan_canceled:
                self.status.set("Scan canceled")
                self.cancel_btn.config(state=tk.DISABLED)
                return
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
        hash_group_count = 0
        
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
                    hash_group_count += 1
        
        self.total_duplicate_files = sum(len(paths) - 1 for paths in self.hash_groups.values())
        self.total_wasted_space = sum(size * (len(paths) - 1) for (size, h), paths in self.hash_groups.items())
        
        for (size, h), paths in self.hash_groups.items():
            item_id = self.tree.insert("", tk.END, text="", values=(f"{size:,}", len(paths), h[:16] + "..."))
            self.file_map[item_id] = (size, h, paths)
            
            if paths[0].lower().endswith(('.png', '.jpg', '.jpeg', '.bmp', '.gif', '.webp')):
                try:
                    img = Image.open(paths[0])
                    img.thumbnail((32, 32), Image.LANCZOS)
                    photo = ImageTk.PhotoImage(img)
                    self.previews.append(photo)
                    self.tree.item(item_id, image=photo)
                except Exception:
                    pass
        
        self.progress_var.set(100)
        self.status.set(f"Scan complete! Found {hash_group_count} duplicate groups")
        self.stats_var.set(f"Total duplicates: {self.total_duplicate_files} | Space wasted: {self.format_file_size(self.total_wasted_space)}")
        self.cancel_btn.config(state=tk.DISABLED)
        self.export_btn.config(state=tk.NORMAL)
    
    def on_tree_select(self, event):
        self.file_listbox.delete(0, tk.END)
        self.details_var.set("")
        self.current_group = None
        self.delete_btn.config(state=tk.DISABLED)
        self.delete_all_btn.config(state=tk.DISABLED)
        self.preview_canvas.delete("all")
        
        for label in self.preview_labels:
            label.destroy()
        self.preview_labels = []
        self.previews = []
        
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
        
        preview_frame = ttk.Frame(self.preview_canvas)
        self.preview_canvas.create_window((0, 0), window=preview_frame, anchor=tk.NW)
        
        for idx, path in enumerate(paths[:15]):
            try:
                frame = ttk.Frame(preview_frame)
                frame.grid(row=0, column=idx, padx=5, pady=5)
                
                filename = os.path.basename(path)
                if len(filename) > 15:
                    filename = filename[:12] + "..."
                
                if path.lower().endswith(('.png', '.jpg', '.jpeg', '.bmp', '.gif', '.webp')):
                    img = Image.open(path)
                    img.thumbnail((64, 64), Image.LANCZOS)
                    photo = ImageTk.PhotoImage(img)
                    self.previews.append(photo)
                    label = ttk.Label(frame, image=photo, compound=tk.TOP, text=filename)
                    label.image = photo
                else:
                    label = ttk.Label(frame, text=filename, compound=tk.TOP)
                
                label.pack()
                self.preview_labels.append(label)
            except Exception:
                try:
                    frame = ttk.Frame(preview_frame)
                    frame.grid(row=0, column=idx, padx=5, pady=5)
                    filename = os.path.basename(path)
                    if len(filename) > 15:
                        filename = filename[:12] + "..."
                    label = ttk.Label(frame, text=filename)
                    label.pack()
                    self.preview_labels.append(label)
                except Exception:
                    pass
        
        preview_frame.update_idletasks()
        self.preview_canvas.config(scrollregion=self.preview_canvas.bbox("all"))
        
        for path in paths:
            self.file_listbox.insert(tk.END, path)
        
        self.delete_btn.config(state=tk.NORMAL)
        self.delete_all_btn.config(state=tk.NORMAL)
    
    def on_file_select(self, event):
        selected = self.file_listbox.curselection()
        if selected:
            path = self.file_listbox.get(selected[0])
            self.details_var.set(f"Selected: {path}")
    
    def select_all(self):
        self.file_listbox.select_set(0, tk.END)
    
    def clear_selection(self):
        self.file_listbox.select_clear(0, tk.END)
    
    def invert_selection(self):
        all_indices = set(range(self.file_listbox.size()))
        selected_indices = set(self.file_listbox.curselection())
        new_selection = all_indices - selected_indices
        
        self.file_listbox.select_clear(0, tk.END)
        for index in new_selection:
            self.file_listbox.select_set(index)
    
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
    
    def delete_all_duplicates(self):
        if not self.current_group:
            return
            
        size, h, paths = self.current_group
        if len(paths) < 2:
            return
            
        if not messagebox.askyesno("Confirm Deletion", 
                                  f"Delete all duplicates in this group?\n\n"
                                  f"This will delete {len(paths)-1} files, keeping the first one."):
            return
            
        deleted_count = 0
        for path in paths[1:]:
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