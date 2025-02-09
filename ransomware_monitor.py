import os
import psutil
import time
import threading
import tkinter as tk
from datetime import datetime
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
import csv

SUSPICIOUS_EXTENSIONS = {'.locked', '.enc', '.crypt', '.crypto', '.ransom'}
LOG_FILE = "ransomware_scan_log.csv"  # Change to CSV file


class RansomwareMonitor(FileSystemEventHandler):
    def __init__(self, log_widget):
        self.log_widget = log_widget

    def on_modified(self, event):
        if not event.is_directory:
            _, ext = os.path.splitext(event.src_path)
            if ext in SUSPICIOUS_EXTENSIONS:
                log_message = f"\u26A0 Suspicious File Detected: {event.src_path}"
                self.log_event(log_message, "high")
                block_ransomware()
            else:
                log_message = f"\u2705 Non-Suspicious File Detected: {event.src_path}"
                self.log_event(log_message, "low")

    def log_event(self, message, tag):
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        full_message = f"{timestamp} - {message}"

        # Write log to CSV
        with open(LOG_FILE, mode='a', newline='', encoding='utf-8') as log_file:
            writer = csv.writer(log_file)
            # Write timestamp, message, and tag
            writer.writerow([timestamp, message, tag])

        # Insert log message into the widget with the appropriate color
        self.log_widget.insert(tk.END, full_message + "\n", tag)
        self.log_widget.yview(tk.END)

    def scan_system(self):
        """Scan system directories for suspicious files and log them."""
        # You can define your directories to scan here
        directories_to_scan = [os.path.expanduser("~"), "C:/", "/home/"]

        for directory in directories_to_scan:
            self.log_event(f"Scanning directory: {directory}", "info")
            for root, dirs, files in os.walk(directory):
                for file in files:
                    _, ext = os.path.splitext(file)
                    if ext in SUSPICIOUS_EXTENSIONS:
                        file_path = os.path.join(root, file)
                        self.log_event(
                            f"Suspicious file found: {file_path}", "high")
                        block_ransomware()
                    else:
                        file_path = os.path.join(root, file)
                        self.log_event(
                            f"Non-suspicious file: {file_path}", "low")

            # After scanning a directory, show progress in the GUI
            self.log_event(f"Finished scanning {directory}\n", "info")


def block_ransomware():
    for proc in psutil.process_iter(['pid', 'name']):
        try:
            if any(word in proc.info['name'].lower() for word in ["ransom", "encrypt", "locker"]):
                psutil.Process(proc.info['pid']).terminate()
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            pass


def start_monitoring(log_widget):
    observer = Observer()
    event_handler = RansomwareMonitor(log_widget)
    observer.schedule(
        event_handler, path=os.path.expanduser("~"), recursive=True)
    observer.start()
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
    observer.join()


def start_scan(log_widget):
    # Start system scan in a separate thread so the GUI remains responsive
    monitor = RansomwareMonitor(log_widget)
    threading.Thread(target=monitor.scan_system, daemon=True).start()
