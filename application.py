import os
import tkinter as tk
from tkinter import messagebox, scrolledtext
import threading
from ransomware_monitor import start_scan, start_monitoring, LOG_FILE, block_ransomware


def start_gui():
    root = tk.Tk()
    root.title("Ransomware Detection System")
    root.geometry("800x600")
    root.configure(bg="#1e1e1e")

    label = tk.Label(root, text="\u2692 Ransomware Monitor", font=(
        "Arial", 18, "bold"), fg="white", bg="#1e1e1e")
    label.pack(pady=10)

    log_widget = scrolledtext.ScrolledText(
        root, height=20, width=100, bg="#121212", fg="white", font=("Consolas", 10))
    log_widget.pack(pady=10)

    # Tag configurations for the different log levels
    log_widget.tag_config("high", foreground="red")
    log_widget.tag_config("low", foreground="green")
    log_widget.tag_config("info", foreground="white")

    button_frame = tk.Frame(root, bg="#1e1e1e")
    button_frame.pack(pady=10)

    tk.Button(button_frame, text="Start System Scan", command=lambda: start_scan(log_widget), bg="#4dff4d", fg="black", font=("Arial", 10, "bold"), width=15).grid(row=0, column=0, padx=5, pady=5)

    # Now calling block_ransomware correctly
    tk.Button(button_frame, text="Force Kill Malware", command=block_ransomware, bg="#ff4d4d", fg="white", font=("Arial", 10, "bold"), width=15).grid(row=0, column=1, padx=5, pady=5)

    # View Log Button
    tk.Button(button_frame, text="View Log", command=lambda: os.system(f'notepad.exe {LOG_FILE}'), bg="#ffcc00", fg="black", font=("Arial", 10, "bold"), width=15).grid(row=0, column=2, padx=5, pady=5)

    # Start monitoring
    threading.Thread(target=start_monitoring, args=(log_widget,), daemon=True).start()

    root.mainloop()

if __name__ == "__main__":
    start_gui()
