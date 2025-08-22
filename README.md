# DupliClean - Duplicate File Finder and Cleaner


## Features

- **Smart Scanning**: Finds duplicates by content using SHA-256 hashing
- **Visual Previews**: Thumbnail previews for image files (JPEG, PNG, BMP, GIF, WebP)
- **Batch Processing**: Efficiently handles large numbers of files with memory optimization
- **Flexible Selection**: Multiple selection options (select all, clear, invert)
- **Safe Deletion**: Confirmation dialogs and option to keep original files
- **Export Functionality**: Save duplicate file lists for later reference
- **Context Menu**: Right-click options to open file location or copy file path
- **Progress Tracking**: Real-time progress updates during scanning

## Installation
1. clone repo  
    ```git clone https://github.com/heyyou124/dupliclean```
2. open project  
    ```cd dupliclean```
3. install requirements  
    ```pip install -r requirements.txt```
4. run program  
    ```python main.py```

## Usage

1. Click "Scan Folder" to select a directory to scan for duplicates
2. Wait for the scan to complete (progress is shown in the status bar)
3. Select a duplicate group from the results list to view details
4. Use the selection tools to choose which files to delete
5. Click "Delete Selected Files" or "Delete All Duplicates" to remove duplicates
6. Use the "Export File List" button to save a report of all duplicates

## RAM Optimization Techniques

### 1. Batched Processing
```python
BATCH_SIZE = 500
```
- Prevents memory spikes during large scanning operations

### 2. Incremental Garbage Collection
```python
batch_count += 1
if batch_count >= self.BATCH_SIZE:
    gc.collect()
    batch_count = 0
```
- Prevents memory fragmentation during long-running operations

### 3. Efficient Data Structures
```python
from collections import defaultdict
self.hash_groups = defaultdict(list)
```
- Minimizes memory overhead for storing file metadata

### 4. Stream-Based File Hashing
```python
def get_hash(self, filepath):
    hasher = hashlib.sha256()
    with open(filepath, "rb") as f:
        while chunk := f.read(8192):
            hasher.update(chunk)
    return hasher.hexdigest()
```
- Enables hashing of very large files without high memory usage

### 5. Selective UI Updates
- UI elements aren't updated all at once

### 6. Memory Cleanup Between Operations
```python
def scan(self):
    for item in self.tree.get_children():
        self.tree.delete(item)
    self.duplicates.clear()
    self.hash_groups.clear()
```

### 7. Optimized Image Handling
```python
img.thumbnail((64, 64), Image.LANCZOS)
```
- Images are resized to thumbnails immediately after loading
