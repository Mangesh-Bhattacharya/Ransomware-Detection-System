import os
import psutil
import time
import threading
import tkinter as tk
from datetime import datetime
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
import csv
from openpyxl import Workbook

# Define the path for the logs directory
# 'logs' directory in the project folder
LOGS_DIR = os.path.join(os.path.dirname(__file__), 'logs')
# Create the directory if it doesn't exist
os.makedirs(LOGS_DIR, exist_ok=True)

# Define the log file path in the 'logs' directory
SUSPICIOUS_EXTENSIONS = {'.locked', '.enc', '.crypt', '.crypto', '.ransom'}
LOG_FILE_CSV = os.path.join(
    LOGS_DIR, "ransomware_scan_log.csv")  # CSV log file
# Excel log file (if using Excel)
LOG_FILE_XLSX = os.path.join(LOGS_DIR, "ransomware_scan_log.xlsx")


class RansomwareMonitor(FileSystemEventHandler):
    def __init__(self, log_widget):
        self.log_widget = log_widget
        self.create_log()  # Create the log file (CSV or Excel)

    def create_log(self):
        """Create the log file (CSV or Excel) if it doesn't exist."""
        if not os.path.exists(LOG_FILE_CSV):
            with open(LOG_FILE_CSV, mode='w', newline='', encoding='utf-8') as log_file:
                writer = csv.writer(log_file)
                # Write headers for CSV
                writer.writerow(["Timestamp", "Message", "Tag"])

        # Create Excel file if needed (uncomment if using Excel)
        # if not os.path.exists(LOG_FILE_XLSX):
        #     wb = Workbook()
        #     ws = wb.active
        #     ws.append(["Timestamp", "Message", "Tag"])  # Headers for Excel
        #     wb.save(LOG_FILE_XLSX)

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
        with open(LOG_FILE_CSV, mode='a', newline='', encoding='utf-8') as log_file:
            writer = csv.writer(log_file)
            # Write timestamp, message, and tag
            writer.writerow([timestamp, message, tag])

        # Write to Excel (if using Excel logging, uncomment the relevant section)
        # wb = openpyxl.load_workbook(LOG_FILE_XLSX)
        # ws = wb.active
        # ws.append([timestamp, message, tag])
        # wb.save(LOG_FILE_XLSX)

        # Insert log message into the widget with the appropriate color
        self.log_widget.insert(tk.END, full_message + "\n", tag)
        self.log_widget.yview(tk.END)

    def scan_system(self):
        """Scan system directories for suspicious files and log them."""
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
    monitor = RansomwareMonitor(log_widget)
    threading.Thread(target=monitor.scan_system, daemon=True).start()
