# 🛡️ Ransomware Detection System

## 📌 Overview
The **Ransomware Detection System** is a Python-based tool designed to monitor file system activities and detect potential ransomware threats in real-time. It leverages heuristic-based detection to identify suspicious file modifications and process activities. Additionally, it features an interactive **GUI** that alerts users and provides a protective mechanism against ransomware attacks.

## 🚀 Features
✅ **Real-Time File System Monitoring** – Detects unusual file modifications  
✅ **Suspicious File Extension Detection** – Identifies encrypted or renamed files  
✅ **Process Monitoring** – Scans running processes for ransomware-like behavior  
✅ **Automated Threat Prevention** – Terminates suspicious processes on detection  
✅ **GUI Alert System** – Warns users when threats are detected  

## 🛠️ Technologies Used  
- **Python** 🐍  
- `watchdog` – For real-time file system monitoring  
- `psutil` – To analyze running processes  
- `tkinter` – For GUI alerts and notifications  

## 📂 How It Works  
1. The script **monitors directories** for suspicious file modifications.  
2. It checks for **suspicious extensions** commonly used by ransomware.  
3. If detected, the system **alerts the user via a GUI popup**.  
4. The script also **scans processes** and automatically **terminates potential ransomware** threats.  

## 🖥️ Installation & Usage  
```bash
# Clone the repository
git clone https://github.com/Mangesh-Bhattacharya/Ransomware-Detection-System.git
cd Ransomware-Detection-System

### 2. Install dependencies:
There are two ways to install the necessary dependencies: using **`pip`** or by using a **requirements.txt** file.

#### Option 1: Using `pip` (Direct Installation):
```bash
pip install watchdog psutil tkinter openpyxl
```

#### Option 2: Using `requirements.txt` (Preferred Method):
1. Make sure you have the `requirements.txt` file in the project directory (it should already be created in the repository).
2. Install all dependencies by running:
```bash
pip install -r requirements.txt
```

# Run the script
python main.py
```

## ⚠️ Disclaimer  
This tool is **for educational purposes only**. It is not a substitute for professional antivirus solutions. Always use additional cybersecurity measures to protect your data.
