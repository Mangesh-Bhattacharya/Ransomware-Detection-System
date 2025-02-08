import os
import psutil
import time
import tkinter as tk
from tkinter import messagebox
from watchdog import Obeserver
from watchdog.events import FileSystemEventHandler

# Suspicious file extensions often used by ransomware
suspicious_ext = {'.locked', '.enc', '.crypt', '.crypto', '.ransom'}

class RansomwareMonitor(FileSystemEventHandler):
    def __init__(self, alert_function):
        self.aler_fuction = alert_function
        
    def on_modified(self, event):
        if not event.is_directory:
            _, ext = os.path.splitext(event.src_path)
            if ext in suspicious_ext:
                self.alert_function(f" Suspicious file detceted: {event.src_path}")
                block_ransomware()
    
    def block_ransomware():
        """ Kill suspicious processes """
        for proc in psutil.process_iter(['pid', 'name']):
            try:
                if any(word in proc.info['name'].lower() for word in ["ransom", "encrypt", "locker"]):
                    psutil.Process(proc.info['pid']).terminate()
                    print(f"Blocked process: {proc.info['name']}")
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                pass
            
    def start_monitoring(alert_function):
        """ Start monitoring for suspicious files """
        Obeserver = Obeserver()
        event_handler = RansomwareMonitor(alert_function)
        Obeserver.schedule(event_handler, path=os.path.expanduser("~"), recursive=True)
        Obeserver.start()
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            Obeserver.stop()
        Obeserver.join()
        
    def start_gui():
        """ Ransomware Detector Application """
        root = tk.Tk()
        root.title("Ransomware Detector System")
        root.geometry("400x300")
        label.pack(pady=20)
        start.monitoring(alert_user)
        root.mainloop
        
    if __name__ == "__main__":
        start_gui()
