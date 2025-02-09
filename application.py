import os
import tkinter as tk
import threading
from tkinter import scrolledtext
# Removed LOG_FILE import
from ransomware_monitor import start_scan, start_monitoring, block_ransomware


def start_gui():
    root = tk.Tk()
    root.title("Ransomware Detection System")
    root.geometry("800x600")
    root.configure(bg="#1e1e1e")

    label = tk.Label(root, text="\u2692 Ransomware Monitor", font=("Arial", 18, "bold"), fg="white", bg="#1e1e1e")
    label.pack(pady=10)

    log_widget = scrolledtext.ScrolledText(root, height=20, width=100, bg="#121212", fg="white", font=("Consolas", 10))
    log_widget.pack(pady=10)
    log_widget.tag_config("high", foreground="red")
    log_widget.tag_config("low", foreground="green")

    button_frame = tk.Frame(root, bg="#1e1e1e")
    button_frame.pack(pady=10)

    tk.Button(button_frame, text="Start System Scan", command=lambda: start_scan(log_widget), bg="#4dff4d", fg="black", font=("Arial", 10, "bold"), width=15).grid(row=0, column=0, padx=5, pady=5)
    tk.Button(button_frame, text="Force Kill Malware", command=block_ransomware, bg="#ff4d4d", fg="white", font=("Arial", 10, "bold"), width=15).grid(row=0, column=1, padx=5, pady=5)
    tk.Button(button_frame, text="View Log", command=lambda: os.system(f'notepad.exe logs/ransomware_scan_log.csv'), bg="#ffcc00", fg="black", font=("Arial", 10, "bold"), width=15).grid(row=0, column=2, padx=5, pady=5)

    threading.Thread(target=start_monitoring, args=(log_widget,), daemon=True).start()
    root.mainloop()


if __name__ == "__main__":
    start_gui()
