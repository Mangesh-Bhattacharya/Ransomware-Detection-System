🛡️ Ransomware Detection System
A real-time ransomware detection system built in Python with an interactive GUI to monitor and prevent ransomware attacks. The system detects suspicious file modifications, identifies potential threats, and alerts users to take action.

🚀 Features
✅ Real-time File Monitoring – Uses watchdog to track file changes
✅ Suspicious Extension Detection – Identifies ransomware-like file extensions
✅ Process Monitoring & Blocking – Detects and stops suspicious ransomware processes
✅ Interactive GUI – Alerts users through a graphical interface (Tkinter)
✅ Lightweight & Efficient – Runs in the background without consuming excessive resources

🏗️ How It Works
1. **Monitors File System Activity:** Detects files with ransomware-related extensions (`.locked`, `.enc`, `.crypt`, etc.).
2. **Identifies Suspicious Processes:** Checks running processes for ransomware-like behavior.
3. **Alerts & Blocks Threats:** Notifies users and attempts to terminate malicious processes.
4. **Provides a GUI Interface:** Displays real-time alerts and system status.

📦 Installation
