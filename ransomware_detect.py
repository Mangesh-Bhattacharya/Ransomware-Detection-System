import os
import psutil
import time
import tkinter as tk
from tkinter import messagebox
from watchdog import Obeserver
from watchdog.events import FileSystemEventHandler

# Suspicious file extensions often used by ransomware
