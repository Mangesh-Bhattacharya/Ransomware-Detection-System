# ransomware_monitor.py
# Core file system monitoring and process enforcement engine.
# Integrates with ThreatIntelligenceEngine and BehavioralAnalyzer
# for multi-layer detection across all regulated industries.
#
# Detection layers:
#   1. Extension-based detection  (signature IOC from threat_intelligence.py)
#   2. Behavioral rate analysis   (behavioral_analyzer.py sliding-window counters)
#   3. Shannon entropy screening  (encrypted-file detection)
#   4. Known-hash matching        (SHA-256 against ransomware hash database)
#   5. Process name heuristics    (kill ransomware-like process names)
#   6. Critical-path awareness    (industry-specific directory protection)

import os
import psutil
import time
import threading
import logging
from datetime import datetime
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
import csv
from openpyxl import Workbook

from threat_intelligence import get_engine
from behavioral_analyzer import (
    get_analyzer, reset_analyzer,
    EVT_MODIFY, EVT_RENAME, EVT_DELETE, EVT_CREATE,
)

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# LOG FILE PATHS
# ---------------------------------------------------------------------------
LOGS_DIR = os.path.join(os.path.dirname(__file__), "logs")
os.makedirs(LOGS_DIR, exist_ok=True)
LOG_FILE_CSV = os.path.join(LOGS_DIR, "ransomware_scan_log.csv")
LOG_FILE_XLSX = os.path.join(LOGS_DIR, "ransomware_scan_log.xlsx")


class RansomwareMonitor(FileSystemEventHandler):
    """
    Watchdog event handler that feeds all file system events to the
    BehavioralAnalyzer and logs results to the GUI and to disk.
    """

    def __init__(self, log_widget, incident_reporter=None):
        """
        :param log_widget: tkinter ScrolledText widget for real-time log display.
        :param incident_reporter: Optional IncidentReporter instance. When provided,
                                  full incident reports are generated for high/critical alerts.
        """
        super().__init__()
        self.log_widget = log_widget
        self.incident_reporter = incident_reporter
        self._engine = get_engine()
        self._analyzer = get_analyzer(alert_callback=self._on_behavioral_alert)
        self._create_log_files()
        logger.info("[RansomwareMonitor] Started. Industry='%s'", self._engine.industry)

    def _create_log_files(self):
        """Create CSV log file with headers if it does not exist."""
        if not os.path.exists(LOG_FILE_CSV):
            with open(LOG_FILE_CSV, mode="w", newline="", encoding="utf-8") as f:
                writer = csv.writer(f)
                writer.writerow([
                    "Timestamp", "EventType", "FilePath", "Extension",
                    "Entropy", "SHA256", "Severity", "Industry", "Reasons"
                ])

    # -----------------------------------------------------------------------
    # WATCHDOG EVENT HANDLERS
    # -----------------------------------------------------------------------

    def on_modified(self, event):
        if not event.is_directory:
            self._process_event(EVT_MODIFY, event.src_path)

    def on_created(self, event):
        if not event.is_directory:
            self._process_event(EVT_CREATE, event.src_path)

    def on_deleted(self, event):
        if not event.is_directory:
            self._process_event(EVT_DELETE, event.src_path)

    def on_moved(self, event):
        if not event.is_directory:
            self._process_event(EVT_RENAME, event.dest_path, old_filepath=event.src_path)

    # -----------------------------------------------------------------------
    # CORE PROCESSING
    # -----------------------------------------------------------------------

    def _process_event(self, event_type: str, filepath: str, old_filepath: str = None):
        """Route an event through the multi-layer detection pipeline."""
        alert = self._analyzer.record_event(event_type, filepath, old_filepath)
        _, ext = os.path.splitext(filepath)

        if alert:
            severity = alert.get("severity", "MEDIUM")
            reasons_text = "; ".join(alert.get("reasons", []))
            entropy = alert.get("entropy", 0.0)
            sha256 = alert.get("sha256") or "N/A"

            message = (
                f"\u26A0 [{severity}] {event_type.upper()} | {filepath} "
                f"| entropy={entropy:.2f} | {reasons_text[:120]}"
            )
            self._log_event(message, "high" if severity in ("HIGH", "CRITICAL") else "medium")
            self._write_csv_log(event_type, filepath, ext, entropy, sha256, severity,
                                reasons_text)

            # Trigger process blocking for high/critical events
            if severity in ("HIGH", "CRITICAL"):
                block_ransomware(self._engine.ransomware_process_patterns)

            # Generate full incident report if reporter is available
            if self.incident_reporter and severity in ("HIGH", "CRITICAL"):
                try:
                    self.incident_reporter.handle_alert(alert)
                except Exception as e:
                    logger.error("[RansomwareMonitor] Incident reporter error: %s", e)
        else:
            message = f"\u2705 [{event_type.upper()}] {filepath}"
            self._log_event(message, "low")

    def _on_behavioral_alert(self, alert: dict):
        """Callback from BehavioralAnalyzer when a threshold is breached."""
        # Already handled in _process_event; this hook is available for
        # additional downstream integrations (SIEM, SOAR, webhook, etc.)
        pass

    # -----------------------------------------------------------------------
    # LOGGING HELPERS
    # -----------------------------------------------------------------------

    def _log_event(self, message: str, tag: str):
        """Write a timestamped message to the GUI log widget."""
        import tkinter as tk
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        full_message = f"{timestamp} - {message}"
        try:
            self.log_widget.insert(tk.END, full_message + "\n", tag)
            self.log_widget.yview(tk.END)
        except Exception:
            pass  # Widget may be destroyed during shutdown

    def _write_csv_log(self, event_type, filepath, ext, entropy, sha256,
                       severity, reasons_text):
        """Append a row to the CSV audit log."""
        try:
            with open(LOG_FILE_CSV, mode="a", newline="", encoding="utf-8") as f:
                writer = csv.writer(f)
                writer.writerow([
                    datetime.now().isoformat(), event_type, filepath, ext,
                    f"{entropy:.4f}", sha256, severity,
                    self._engine.industry, reasons_text
                ])
        except OSError as e:
            logger.error("[RansomwareMonitor] CSV log write error: %s", e)

    # -----------------------------------------------------------------------
    # FULL-SYSTEM SCAN
    # -----------------------------------------------------------------------

    def scan_system(self):
        """
        Walk configured directories and apply all detection layers to
        each file found.  Designed to run in a background thread.
        """
        directories_to_scan = [os.path.expanduser("~"), "C:/", "/home/"]
        self._log_event("Starting full-system scan...", "info")

        for directory in directories_to_scan:
            if not os.path.exists(directory):
                continue
            self._log_event(f"Scanning: {directory}", "info")
            for root, _, files in os.walk(directory):
                for filename in files:
                    filepath = os.path.join(root, filename)
                    self._process_event(EVT_CREATE, filepath)

            self._log_event(f"Finished scanning {directory}", "info")

        self._log_event("Full-system scan complete.", "info")


# ---------------------------------------------------------------------------
# PROCESS BLOCKING
# ---------------------------------------------------------------------------

def block_ransomware(process_patterns=None):
    """
    Terminate processes whose names match known ransomware patterns.

    :param process_patterns: List of lowercase pattern strings to match against
                             process names.  Defaults to built-in patterns from
                             ThreatIntelligenceEngine.
    """
    if process_patterns is None:
        process_patterns = get_engine().ransomware_process_patterns

    killed = []
    for proc in psutil.process_iter(["pid", "name"]):
        try:
            name = proc.info["name"].lower()
            if any(pattern in name for pattern in process_patterns):
                psutil.Process(proc.info["pid"]).terminate()
                killed.append(f"[pid={proc.info['pid']}] {proc.info['name']}")
                logger.warning("[ProcessBlock] Terminated suspicious process: %s (pid=%d)",
                               proc.info["name"], proc.info["pid"])
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            pass
    return killed


# ---------------------------------------------------------------------------
# START FUNCTIONS  (called from application.py / main.py)
# ---------------------------------------------------------------------------

def start_monitoring(log_widget, industry: str = "general",
                     custom_ioc_file: str = None,
                     watch_path: str = None,
                     incident_reporter=None):
    """
    Start real-time file system monitoring in a background thread.

    :param log_widget:        tkinter ScrolledText widget.
    :param industry:          Industry profile key (healthcare, banking, nuclear, …).
    :param custom_ioc_file:   Path to a JSON IOC feed file (optional).
    :param watch_path:        Directory to monitor (defaults to user home directory).
    :param incident_reporter: IncidentReporter instance (optional).
    """
    from threat_intelligence import reset_engine
    reset_engine(industry=industry, custom_ioc_file=custom_ioc_file)
    reset_analyzer()

    monitor = RansomwareMonitor(log_widget, incident_reporter=incident_reporter)
    path = watch_path or os.path.expanduser("~")

    observer = Observer()
    observer.schedule(monitor, path=path, recursive=True)

    def _run():
        observer.start()
        logger.info("[Monitor] Watching '%s' for industry='%s'", path, industry)
        try:
            while True:
                time.sleep(1)
        except (KeyboardInterrupt, SystemExit):
            pass
        finally:
            observer.stop()
        observer.join()

    thread = threading.Thread(target=_run, daemon=True)
    thread.start()
    return observer, thread


def start_scan(log_widget, industry: str = "general",
               custom_ioc_file: str = None,
               incident_reporter=None):
    """
    Start a full-system scan in a background thread.

    :param log_widget:        tkinter ScrolledText widget.
    :param industry:          Industry profile key.
    :param custom_ioc_file:   Path to a JSON IOC feed file (optional).
    :param incident_reporter: IncidentReporter instance (optional).
    """
    from threat_intelligence import reset_engine
    reset_engine(industry=industry, custom_ioc_file=custom_ioc_file)
    reset_analyzer()

    monitor = RansomwareMonitor(log_widget, incident_reporter=incident_reporter)
    thread = threading.Thread(target=monitor.scan_system, daemon=True)
    thread.start()
    return thread
