# application.py
# GUI application for the Ransomware Detection System.
# Enhanced with:
#   - Industry / sector profile selector (healthcare, banking, nuclear, energy, government)
#   - Real-time behavioral dashboard (rate counters + alert count)
#   - Incident report viewer
#   - Status bar showing active profile and compliance frameworks
#   - Color-coded severity tags (critical, high, medium, low, info)

import os
import threading
import tkinter as tk
from tkinter import scrolledtext, ttk, filedialog, messagebox
from datetime import datetime

from threat_intelligence import INDUSTRY_PROFILES, reset_engine, get_engine
from ransomware_monitor import start_scan, start_monitoring, block_ransomware
from behavioral_analyzer import reset_analyzer, get_analyzer
from incident_reporter import IncidentReporter, REPORTS_DIR


# ---------------------------------------------------------------------------
# COLOR SCHEME
# ---------------------------------------------------------------------------
BG_DARK       = "#0d1117"
BG_PANEL      = "#161b22"
BG_WIDGET     = "#1c2128"
FG_WHITE      = "#e6edf3"
FG_MUTED      = "#8b949e"
ACCENT_GREEN  = "#3fb950"
ACCENT_YELLOW = "#d29922"
ACCENT_ORANGE = "#f0883e"
ACCENT_RED    = "#f85149"
ACCENT_PURPLE = "#a371f7"
ACCENT_BLUE   = "#58a6ff"

SEVERITY_COLORS = {
    "critical": ACCENT_RED,
    "high":     ACCENT_ORANGE,
    "medium":   ACCENT_YELLOW,
    "low":      ACCENT_GREEN,
    "info":     ACCENT_BLUE,
}


def start_gui():
    root = tk.Tk()
    root.title("Ransomware Detection System — Cybersecurity Platform")
    root.geometry("1100x780")
    root.configure(bg=BG_DARK)
    root.minsize(900, 650)

    # -----------------------------------------------------------------------
    # STATE
    # -----------------------------------------------------------------------
    selected_industry = tk.StringVar(value="general")
    monitor_active = tk.BooleanVar(value=False)
    watch_path_var = tk.StringVar(value=os.path.expanduser("~"))
    status_text = tk.StringVar(value="Status: Idle")

    # -----------------------------------------------------------------------
    # TITLE BAR
    # -----------------------------------------------------------------------
    title_frame = tk.Frame(root, bg=BG_PANEL, pady=8)
    title_frame.pack(fill=tk.X)

    tk.Label(
        title_frame,
        text="\u26E8  Ransomware Detection System",
        font=("Arial", 16, "bold"),
        fg=ACCENT_BLUE, bg=BG_PANEL
    ).pack(side=tk.LEFT, padx=15)

    tk.Label(
        title_frame,
        textvariable=status_text,
        font=("Consolas", 10),
        fg=FG_MUTED, bg=BG_PANEL
    ).pack(side=tk.RIGHT, padx=15)

    # -----------------------------------------------------------------------
    # TOP CONFIG ROW
    # -----------------------------------------------------------------------
    config_frame = tk.Frame(root, bg=BG_DARK, pady=6)
    config_frame.pack(fill=tk.X, padx=10)

    # Industry selector
    tk.Label(config_frame, text="Industry Profile:",
             font=("Arial", 10, "bold"), fg=FG_WHITE, bg=BG_DARK).pack(side=tk.LEFT, padx=(0, 4))

    industry_keys = list(INDUSTRY_PROFILES.keys())
    industry_labels = [INDUSTRY_PROFILES[k]["label"] for k in industry_keys]
    industry_map = dict(zip(industry_labels, industry_keys))

    industry_combo = ttk.Combobox(
        config_frame,
        values=industry_labels,
        state="readonly",
        width=38,
        font=("Arial", 9)
    )
    industry_combo.set(INDUSTRY_PROFILES["general"]["label"])
    industry_combo.pack(side=tk.LEFT, padx=(0, 12))

    # Watch path selector
    tk.Label(config_frame, text="Watch Path:",
             font=("Arial", 10), fg=FG_WHITE, bg=BG_DARK).pack(side=tk.LEFT, padx=(0, 4))

    path_entry = tk.Entry(config_frame, textvariable=watch_path_var,
                          width=30, bg=BG_WIDGET, fg=FG_WHITE,
                          insertbackground=FG_WHITE, font=("Consolas", 9))
    path_entry.pack(side=tk.LEFT, padx=(0, 4))

    def browse_path():
        chosen = filedialog.askdirectory(initialdir=watch_path_var.get())
        if chosen:
            watch_path_var.set(chosen)

    tk.Button(config_frame, text="Browse", command=browse_path,
              bg=BG_WIDGET, fg=FG_WHITE, font=("Arial", 8),
              relief=tk.FLAT, padx=6).pack(side=tk.LEFT)

    # -----------------------------------------------------------------------
    # MAIN SPLIT — left: log, right: dashboard
    # -----------------------------------------------------------------------
    main_frame = tk.Frame(root, bg=BG_DARK)
    main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=6)

    # --- Log panel (left) ---
    log_frame = tk.LabelFrame(main_frame, text=" Event Log ",
                               fg=FG_MUTED, bg=BG_DARK,
                               font=("Arial", 9), bd=1)
    log_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

    log_widget = scrolledtext.ScrolledText(
        log_frame, height=28, bg=BG_WIDGET, fg=FG_WHITE,
        font=("Consolas", 9), insertbackground=FG_WHITE, wrap=tk.WORD
    )
    log_widget.pack(fill=tk.BOTH, expand=True, padx=4, pady=4)

    # Color tags
    for tag, color in SEVERITY_COLORS.items():
        log_widget.tag_config(tag, foreground=color)
    log_widget.tag_config("high",   foreground=ACCENT_ORANGE)
    log_widget.tag_config("medium", foreground=ACCENT_YELLOW)
    log_widget.tag_config("low",    foreground=ACCENT_GREEN)
    log_widget.tag_config("info",   foreground=ACCENT_BLUE)

    # --- Dashboard panel (right) ---
    dash_frame = tk.LabelFrame(main_frame, text=" Live Dashboard ",
                                fg=FG_MUTED, bg=BG_DARK,
                                font=("Arial", 9), bd=1, width=260)
    dash_frame.pack(side=tk.RIGHT, fill=tk.Y, padx=(8, 0))
    dash_frame.pack_propagate(False)

    # Metric labels
    dash_metrics = {}
    metric_defs = [
        ("industry",       "Industry",           FG_WHITE),
        ("frameworks",     "Frameworks",          FG_MUTED),
        ("modify_rate",    "Modify rate / min",   FG_WHITE),
        ("rename_rate",    "Rename rate / min",   FG_WHITE),
        ("delete_rate",    "Delete rate / min",   FG_WHITE),
        ("new_exts",       "New exts / min",      FG_WHITE),
        ("alerts",         "Alerts this session", ACCENT_RED),
        ("last_severity",  "Last severity",       ACCENT_ORANGE),
    ]

    for key, label, fg in metric_defs:
        row = tk.Frame(dash_frame, bg=BG_DARK)
        row.pack(fill=tk.X, padx=6, pady=2)
        tk.Label(row, text=label + ":", width=20, anchor="w",
                 font=("Arial", 8), fg=FG_MUTED, bg=BG_DARK).pack(side=tk.LEFT)
        var = tk.StringVar(value="—")
        lbl = tk.Label(row, textvariable=var, anchor="w",
                       font=("Consolas", 8, "bold"), fg=fg, bg=BG_DARK)
        lbl.pack(side=tk.LEFT)
        dash_metrics[key] = var

    # Compliance info text
    tk.Label(dash_frame, text="Active Compliance Controls:",
             font=("Arial", 8, "bold"), fg=FG_MUTED, bg=BG_DARK).pack(anchor="w", padx=6, pady=(8, 0))
    compliance_text = tk.Text(dash_frame, height=8, bg=BG_WIDGET, fg=ACCENT_BLUE,
                               font=("Consolas", 7), bd=0, wrap=tk.WORD)
    compliance_text.pack(fill=tk.X, padx=6, pady=2)

    # -----------------------------------------------------------------------
    # INCIDENT REPORTER with GUI callback
    # -----------------------------------------------------------------------
    incident_log: list = []

    def gui_incident_callback(summary: str, severity: str):
        tag = severity.lower() if severity.lower() in SEVERITY_COLORS else "medium"
        log_widget.insert(tk.END, summary + "\n", tag)
        log_widget.yview(tk.END)
        incident_log.append(summary)
        dash_metrics["alerts"].set(str(reporter.get_report_count()))
        dash_metrics["last_severity"].set(severity)

    reporter = IncidentReporter(gui_callback=gui_incident_callback)

    # -----------------------------------------------------------------------
    # DASHBOARD REFRESH
    # -----------------------------------------------------------------------
    def _refresh_dashboard():
        try:
            engine = get_engine()
            analyzer = get_analyzer()
            snapshot = analyzer.get_status_snapshot()

            dash_metrics["industry"].set(engine.profile["label"][:28])
            dash_metrics["frameworks"].set(", ".join(engine.profile["compliance_frameworks"])[:30])
            dash_metrics["modify_rate"].set(str(snapshot["modify_rate_1min"]))
            dash_metrics["rename_rate"].set(str(snapshot["rename_rate_1min"]))
            dash_metrics["delete_rate"].set(str(snapshot["delete_rate_1min"]))
            dash_metrics["new_exts"].set(str(snapshot["new_extension_diversity"]))

            # Update compliance control text
            compliance_text.config(state=tk.NORMAL)
            compliance_text.delete("1.0", tk.END)
            controls = engine.get_compliance_controls()
            for fw, ctrl_list in controls.items():
                compliance_text.insert(tk.END, f"{fw}: {', '.join(ctrl_list)}\n")
            compliance_text.config(state=tk.DISABLED)
        except Exception:
            pass
        root.after(2000, _refresh_dashboard)

    root.after(2000, _refresh_dashboard)

    # -----------------------------------------------------------------------
    # CONTROL BUTTONS
    # -----------------------------------------------------------------------
    btn_frame = tk.Frame(root, bg=BG_DARK, pady=6)
    btn_frame.pack(fill=tk.X, padx=10)

    def _apply_industry():
        label = industry_combo.get()
        key = industry_map.get(label, "general")
        selected_industry.set(key)
        reset_engine(industry=key)
        reset_analyzer()
        status_text.set(f"Status: Industry set to '{INDUSTRY_PROFILES[key]['label']}'")
        log_widget.insert(tk.END,
            f"\u2139 Industry profile set to: {INDUSTRY_PROFILES[key]['label']}\n", "info")
        log_widget.yview(tk.END)

    def _start_scan():
        _apply_industry()
        status_text.set("Status: Full-system scan running...")
        start_scan(log_widget, industry=selected_industry.get(),
                   incident_reporter=reporter)

    def _start_monitor():
        _apply_industry()
        if monitor_active.get():
            messagebox.showinfo("Monitor", "Real-time monitoring is already active.")
            return
        monitor_active.set(True)
        path = watch_path_var.get()
        status_text.set(f"Status: Monitoring '{path}'")
        start_monitoring(log_widget, industry=selected_industry.get(),
                         watch_path=path, incident_reporter=reporter)

    def _block_now():
        killed = block_ransomware()
        if killed:
            for p in killed:
                log_widget.insert(tk.END, f"\u2620 KILLED: {p}\n", "critical")
        else:
            log_widget.insert(tk.END, "\u2714 No ransomware-like processes found.\n", "low")
        log_widget.yview(tk.END)

    def _view_reports():
        if not os.path.exists(REPORTS_DIR) or not os.listdir(REPORTS_DIR):
            messagebox.showinfo("Reports", "No incident reports found.")
            return
        win = tk.Toplevel(root)
        win.title("Incident Reports")
        win.geometry("900x600")
        win.configure(bg=BG_DARK)
        txt = scrolledtext.ScrolledText(win, bg=BG_WIDGET, fg=FG_WHITE,
                                        font=("Consolas", 8))
        txt.pack(fill=tk.BOTH, expand=True, padx=8, pady=8)
        for fname in sorted(os.listdir(REPORTS_DIR)):
            if fname.endswith(".json"):
                fpath = os.path.join(REPORTS_DIR, fname)
                with open(fpath, "r", encoding="utf-8") as f:
                    txt.insert(tk.END, f"{'='*60}\n{fname}\n{'='*60}\n")
                    txt.insert(tk.END, f.read() + "\n\n")

    def _clear_log():
        log_widget.delete("1.0", tk.END)

    btn_cfg = [
        ("Apply Profile",        _apply_industry,  ACCENT_BLUE),
        ("Start System Scan",    _start_scan,       ACCENT_GREEN),
        ("Start Live Monitor",   _start_monitor,    "#1f8b4c"),
        ("Block Ransomware Now", _block_now,        ACCENT_RED),
        ("View Incident Reports",_view_reports,     ACCENT_PURPLE),
        ("Clear Log",            _clear_log,        FG_MUTED),
    ]

    for text, cmd, color in btn_cfg:
        tk.Button(
            btn_frame, text=text, command=cmd,
            bg=color, fg="white" if color != FG_MUTED else BG_DARK,
            font=("Arial", 9, "bold"), relief=tk.FLAT,
            padx=10, pady=5, cursor="hand2"
        ).pack(side=tk.LEFT, padx=4)

    # -----------------------------------------------------------------------
    # STATUS BAR
    # -----------------------------------------------------------------------
    status_bar = tk.Frame(root, bg=BG_PANEL, pady=3)
    status_bar.pack(fill=tk.X, side=tk.BOTTOM)
    tk.Label(
        status_bar,
        text="Ransomware Detection System | Multi-Industry Cybersecurity Platform",
        font=("Arial", 8), fg=FG_MUTED, bg=BG_PANEL
    ).pack(side=tk.LEFT, padx=10)
    tk.Label(
        status_bar,
        text=f"Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        font=("Consolas", 8), fg=FG_MUTED, bg=BG_PANEL
    ).pack(side=tk.RIGHT, padx=10)

    # -----------------------------------------------------------------------
    # INITIAL LOG MESSAGE
    # -----------------------------------------------------------------------
    log_widget.insert(tk.END,
        "\u2692 Ransomware Detection System Ready\n"
        "Select an industry profile, configure the watch path, then start monitoring.\n"
        "Supported sectors: Healthcare (HIPAA), Banking (PCI-DSS), Nuclear (NRC/NERC CIP),\n"
        "                   Energy (IEC-62443), Government (FISMA/CMMC), General.\n"
        "\n", "info"
    )

    root.mainloop()
