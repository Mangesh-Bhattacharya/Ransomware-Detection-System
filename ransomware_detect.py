import os
import psutil
import time
import tkinter as tk
import threading
from datetime import datetime
from tkinter import messagebox
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

# Suspicious file extensions often used by ransomware
SUSPICIOUS_EXTENSIONS = {'.locked', '.enc', '.crypt', '.crypto', '.ransom'}
MALICIOUS_KEYWORDS = ["ransom", "encrypt", "locker", "virus", "trojan", "malware"]

class RansomwareMonitor(FileSystemEventHandler):
    def __init__(self, alert_function, log_widget, log_file_path):
        self.alert_function = alert_function
        self.log_widget = log_widget
        self.log_file_path = log_file_path

    def on_created(self, event):
        if not event.is_directory:
            self.handle_event(event)

    def on_modified(self, event):
        if not event.is_directory:
            self.handle_event(event)

    def on_moved(self, event):
        if not event.is_directory:
            self.handle_event(event)

    def handle_event(self, event):
        """ Check file for suspicious activity """
        _, ext = os.path.splitext(event.src_path)
        if ext in SUSPICIOUS_EXTENSIONS or self.detect_malicious_behavior(event.src_path):
            alert_message = f"Suspicious file detected: {event.src_path}"
            self.alert_function(alert_message)
            self.log_event(alert_message)
            self.block_ransomware()

    def detect_malicious_behavior(self, file_path):
        """ Check for patterns of malicious behavior, such as file activity """
        for word in MALICIOUS_KEYWORDS:
            if word in file_path.lower():
                return True
        return False

    def block_ransomware(self):
        """ Kill suspicious processes """
        for proc in psutil.process_iter(['pid', 'name']):
            try:
                if any(word in proc.info['name'].lower() for word in ["ransom", "encrypt", "locker", "virus", "trojan"]):
                    psutil.Process(proc.info['pid']).terminate()
                    print(f"Blocked process: {proc.info['name']}")
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                pass

    def log_event(self, message):
        """ Write log to the file and the GUI widget """
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        log_message = f"{timestamp} - {message}\n"
        with open(self.log_file_path, "a") as log_file:
            log_file.write(log_message)  # Append to log file
        self.log_widget.insert(tk.END, log_message, "high")


def block_ransomware():
    """ Kill suspicious processes (standalone function for the button) """
    for proc in psutil.process_iter(['pid', 'name']):
        try:
            if any(word in proc.info['name'].lower() for word in ["ransom", "encrypt", "locker", "virus", "trojan"]):
                psutil.Process(proc.info['pid']).terminate()
                print(f"Blocked process: {proc.info['name']}")
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            pass


def start_monitoring(alert_function, log_widget, log_file_path):
    """ Start monitoring file system changes """
    observer = Observer()
    event_handler = RansomwareMonitor(
        alert_function, log_widget, log_file_path)

    # Specify directories to monitor; you can adjust this to monitor more directories
    directories_to_monitor = [os.path.expanduser(
        "~"), "/path/to/important/folder"]

    for directory in directories_to_monitor:
        observer.schedule(event_handler, path=directory, recursive=True)

    observer.start()
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
    observer.join()


def start_gui():
    """ Start GUI application """
    def alert_user(message):
        messagebox.showwarning("Ransomware Alert!", message)

    def view_log():
        """ Start system scan when the "View Logs" button is clicked and display logs """
        if not os.path.exists(log_dir):
            os.makedirs(log_dir)

        log_file_path = os.path.join(log_dir, "ransomware_log.log")

        # Start monitoring in a separate thread
        threading.Thread(target=start_monitoring, args=(
            alert_user, log_widget, log_file_path), daemon=True).start()

        # Wait for logs to be created, then open them
        time.sleep(2)  # Give it a moment to start scanning
        with open(log_file_path, "r") as log_file:
            log_data = log_file.read()
        messagebox.showinfo("Log", log_data)

    # Create log directory if it doesn't exist
    log_dir = os.path.join(os.getcwd(), "logs")

    # Start GUI
    root = tk.Tk()
    root.title("Ransomware Detection System")
    root.geometry("700x500")
    root.configure(bg="#121212")

    label = tk.Label(root, text="Ransomware Monitor", font=(
        "Arial", 16, "bold"), fg="white", bg="#121212")
    label.pack(pady=10)

    log_widget = tk.Text(root, height=15, width=80,
                         bg="#1e1e1e", fg="white", font=("Consolas", 10))
    log_widget.pack(pady=10)
    log_widget.tag_config("high", foreground="red")
    log_widget.tag_config("medium", foreground="orange")
    log_widget.tag_config("low", foreground="green")

    button_frame = tk.Frame(root, bg="#121212")
    button_frame.pack(pady=10)

    tk.Button(button_frame, text="Kill Processes", command=block_ransomware, bg="#ff4d4d",
              fg="white", font=("Arial", 10, "bold"), width=15).grid(row=0, column=0, padx=5, pady=5)
    tk.Button(button_frame, text="Disable Monitor", command=root.quit, bg="#ffcc00",
              fg="black", font=("Arial", 10, "bold"), width=15).grid(row=0, column=1, padx=5, pady=5)
    tk.Button(button_frame, text="View Log", command=view_log, bg="#4da6ff", fg="white", font=(
        "Arial", 10, "bold"), width=15).grid(row=0, column=2, padx=5, pady=5)
    tk.Button(button_frame, text="Add Directory", command=lambda: messagebox.showinfo("Feature", "Add Directory feature coming soon!"),
              bg="#66ff66", fg="black", font=("Arial", 10, "bold"), width=15).grid(row=0, column=3, padx=5, pady=5)
    tk.Button(button_frame, text="Remove Directory", command=lambda: messagebox.showinfo("Feature", "Remove Directory feature coming soon!"),
              bg="#ff9966", fg="black", font=("Arial", 10, "bold"), width=15).grid(row=1, column=1, padx=5, pady=5)

    root.mainloop()


if __name__ == "__main__":
    start_gui()
