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
