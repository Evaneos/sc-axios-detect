#!/usr/bin/env python3
"""GUI scanner for the axios supply chain compromise.

Wraps the detection logic from detect-axios.py in a tkinter interface.
Zero external dependencies — stdlib only.

Usage: python3 detect-axios-gui.py
"""

import json
import os
import platform
import re
import shutil
import socket
import subprocess
import sys
import threading
import time
import tkinter as tk
from tkinter import filedialog, scrolledtext
from pathlib import Path

# ---------------------------------------------------------------------------
# Import the Scanner class from detect-axios.py (same directory)
# If bundled by PyInstaller, the scanner module is included via --hidden-import
# ---------------------------------------------------------------------------

# Rather than importing (which complicates PyInstaller), we inline the IOC
# constants and reuse the Scanner class by importing the module directly.
_script_dir = os.path.dirname(os.path.abspath(__file__))
if _script_dir not in sys.path:
    sys.path.insert(0, _script_dir)

# Rename to avoid clash with potential "detect-axios" module naming issues
# We'll import the module by manipulating the path
import importlib.util

_scanner_path = os.path.join(_script_dir, "detect-axios.py")
if not os.path.isfile(_scanner_path):
    # PyInstaller bundle: try the expected location
    _scanner_path = os.path.join(sys._MEIPASS, "detect-axios.py") if hasattr(sys, "_MEIPASS") else _scanner_path

_spec = importlib.util.spec_from_file_location("detect_axios", _scanner_path)
_mod = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_mod)

Scanner = _mod.Scanner
SEVERITY_ORDER = _mod.SEVERITY_ORDER

# ---------------------------------------------------------------------------
# Color palette
# ---------------------------------------------------------------------------

BG = "#1e1e2e"
BG_LIGHT = "#2a2a3e"
FG = "#cdd6f4"
FG_DIM = "#6c7086"
GREEN = "#a6e3a1"
YELLOW = "#f9e2af"
RED = "#f38ba8"
BLUE = "#89b4fa"
ACCENT = "#cba6f7"

SEVERITY_COLORS = {
    "CLEAN": GREEN,
    "LATENT": YELLOW,
    "INSTALLED": RED,
    "CONFIRMED": RED,
}

SEVERITY_LABELS = {
    "CLEAN": "All clear -- no compromise detected",
    "LATENT": "LATENT -- Compromised version in lockfile, not yet installed",
    "INSTALLED": "INSTALLED -- Malicious package was installed (infection probable)",
    "CONFIRMED": "CONFIRMED -- Malware execution artifacts detected",
}


class ScannerGUI:
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("Axios Supply Chain Scanner")
        self.root.configure(bg=BG)
        self.root.minsize(700, 520)

        # Try to set a reasonable starting size
        self.root.geometry("750x580")

        self.scan_thread = None
        self.scanner = None
        self.json_path = None

        self._build_ui()

    def _build_ui(self):
        # --- Header ---
        header_frame = tk.Frame(self.root, bg=BG, pady=12)
        header_frame.pack(fill=tk.X, padx=20)

        tk.Label(
            header_frame, text="Axios Supply Chain Scanner",
            font=("Helvetica", 18, "bold"), fg=FG, bg=BG
        ).pack(anchor=tk.W)

        tk.Label(
            header_frame,
            text="Detects compromised axios@1.14.1 / axios@0.30.4 and related IOCs",
            font=("Helvetica", 10), fg=FG_DIM, bg=BG
        ).pack(anchor=tk.W, pady=(2, 0))

        # --- Path selector ---
        path_frame = tk.Frame(self.root, bg=BG, pady=4)
        path_frame.pack(fill=tk.X, padx=20)

        tk.Label(
            path_frame, text="Scan path:", font=("Helvetica", 10),
            fg=FG_DIM, bg=BG
        ).pack(side=tk.LEFT)

        self.path_var = tk.StringVar(value=self._default_root())
        self.path_entry = tk.Entry(
            path_frame, textvariable=self.path_var,
            font=("Courier", 11), bg=BG_LIGHT, fg=FG,
            insertbackground=FG, relief=tk.FLAT, highlightthickness=1,
            highlightcolor=ACCENT, highlightbackground=BG_LIGHT
        )
        self.path_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(8, 4))

        self.browse_btn = tk.Button(
            path_frame, text="Browse", command=self._browse,
            font=("Helvetica", 9), bg=BG_LIGHT, fg=FG,
            activebackground=ACCENT, activeforeground=BG,
            relief=tk.FLAT, padx=10, cursor="hand2"
        )
        self.browse_btn.pack(side=tk.LEFT, padx=(0, 4))

        self.scan_btn = tk.Button(
            path_frame, text="Scan", command=self._start_scan,
            font=("Helvetica", 10, "bold"), bg=ACCENT, fg=BG,
            activebackground=BLUE, activeforeground=BG,
            relief=tk.FLAT, padx=16, cursor="hand2"
        )
        self.scan_btn.pack(side=tk.LEFT)

        # --- Progress ---
        progress_frame = tk.Frame(self.root, bg=BG, pady=8)
        progress_frame.pack(fill=tk.X, padx=20)

        self.step_var = tk.StringVar(value="Ready")
        tk.Label(
            progress_frame, textvariable=self.step_var,
            font=("Helvetica", 10), fg=FG_DIM, bg=BG, anchor=tk.W
        ).pack(fill=tk.X)

        # Simple progress bar using a canvas
        self.progress_canvas = tk.Canvas(
            progress_frame, height=6, bg=BG_LIGHT,
            highlightthickness=0, bd=0
        )
        self.progress_canvas.pack(fill=tk.X, pady=(6, 0))
        self.progress_bar = self.progress_canvas.create_rectangle(
            0, 0, 0, 6, fill=ACCENT, outline=""
        )

        # --- Result banner (hidden until scan completes) ---
        self.result_frame = tk.Frame(self.root, bg=BG, pady=4)
        self.result_frame.pack(fill=tk.X, padx=20)

        self.result_label = tk.Label(
            self.result_frame, text="", font=("Helvetica", 12, "bold"),
            bg=BG, fg=GREEN, anchor=tk.W, wraplength=680
        )
        self.result_label.pack(fill=tk.X)

        self.json_label = tk.Label(
            self.result_frame, text="", font=("Courier", 9),
            bg=BG, fg=BLUE, anchor=tk.W, cursor="hand2", wraplength=680
        )
        self.json_label.pack(fill=tk.X, pady=(2, 0))
        self.json_label.bind("<Button-1>", self._copy_json_path)

        # --- Log output ---
        log_frame = tk.Frame(self.root, bg=BG, pady=4)
        log_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=(0, 12))

        self.log = scrolledtext.ScrolledText(
            log_frame, font=("Courier", 10), bg=BG_LIGHT, fg=FG,
            relief=tk.FLAT, highlightthickness=1,
            highlightcolor=BG_LIGHT, highlightbackground=BG_LIGHT,
            insertbackground=FG, wrap=tk.WORD, state=tk.DISABLED
        )
        self.log.pack(fill=tk.BOTH, expand=True)

        # Configure log colors
        self.log.tag_config("alert", foreground=RED)
        self.log.tag_config("warn", foreground=YELLOW)
        self.log.tag_config("ok", foreground=GREEN)
        self.log.tag_config("header", foreground=ACCENT, font=("Courier", 10, "bold"))

    def _default_root(self) -> str:
        if platform.system() == "Windows":
            return os.environ.get("SYSTEMDRIVE", "C:") + "\\"
        return "/"

    def _browse(self):
        path = filedialog.askdirectory(initialdir=self.path_var.get())
        if path:
            self.path_var.set(path)

    def _log(self, text: str, tag: str = ""):
        self.log.config(state=tk.NORMAL)
        if tag:
            self.log.insert(tk.END, text + "\n", tag)
        else:
            self.log.insert(tk.END, text + "\n")
        self.log.see(tk.END)
        self.log.config(state=tk.DISABLED)

    def _set_progress(self, step: int, total: int, label: str):
        self.step_var.set(f"[{step}/{total}] {label}")
        self.progress_canvas.update_idletasks()
        width = self.progress_canvas.winfo_width()
        fill_width = int(width * step / total)
        self.progress_canvas.coords(self.progress_bar, 0, 0, fill_width, 6)

    def _start_scan(self):
        scan_path = self.path_var.get().strip()
        if not os.path.isdir(scan_path):
            self.result_label.config(text=f"Invalid path: {scan_path}", fg=RED)
            return

        # Reset UI
        self.scan_btn.config(state=tk.DISABLED, text="Scanning...")
        self.browse_btn.config(state=tk.DISABLED)
        self.path_entry.config(state=tk.DISABLED)
        self.result_label.config(text="")
        self.json_label.config(text="")
        self.json_path = None
        self.log.config(state=tk.NORMAL)
        self.log.delete("1.0", tk.END)
        self.log.config(state=tk.DISABLED)
        self._set_progress(0, 6, "Starting scan...")

        self.scan_thread = threading.Thread(target=self._run_scan, args=(scan_path,), daemon=True)
        self.scan_thread.start()

    def _run_scan(self, scan_path: str):
        """Run the scan in a background thread, posting updates to the GUI."""
        scanner = Scanner(scan_path)

        # Override the scanner's output methods to route to our GUI
        original_alert = scanner.alert
        original_warn = scanner.warn
        original_ok = scanner.ok
        original_header = scanner.header

        def gui_alert(msg):
            self.root.after(0, lambda: self._log(f"[ALERT] {msg}", "alert"))

        def gui_warn(msg):
            self.root.after(0, lambda: self._log(f"[WARN] {msg}", "warn"))

        def gui_ok(msg):
            self.root.after(0, lambda: self._log(f"[OK] {msg}", "ok"))

        def gui_header(msg):
            self.root.after(0, lambda: self._log(msg, "header"))

        scanner.alert = gui_alert
        scanner.warn = gui_warn
        scanner.ok = gui_ok
        scanner.header = gui_header

        # Run each step with progress updates
        scanner.artifact_found = False

        steps = [
            ("Scanning installed axios packages...", scanner.scan_axios_packages),
            ("Scanning lockfiles...", scanner.scan_lockfiles),
            ("Scanning for malicious packages...", scanner.scan_malicious_packages),
            ("Scanning for RAT payload files...", scanner.scan_rat_payloads),
            ("Scanning for C2 traces and processes...", scanner.scan_network_and_processes),
            ("Scanning npm cache...", scanner.scan_npm_cache),
        ]

        for i, (label, step_fn) in enumerate(steps):
            self.root.after(0, lambda s=i+1, l=label: self._set_progress(s, 6, l))
            try:
                step_fn()
            except Exception as e:
                self.root.after(0, lambda err=e: self._log(f"Error: {err}", "warn"))

        if scanner.artifact_found:
            scanner.escalate("CONFIRMED")

        # Write JSON if needed
        json_file = None
        if scanner.severity != "CLEAN":
            hostname = socket.gethostname().split(".")[0]
            timestamp = time.strftime("%Y%m%d-%H%M%S")
            json_file = f"axios-scan-{hostname}-{timestamp}.json"

            report = {
                "scan_date": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                "hostname": hostname,
                "os": scanner.os_type,
                "scan_root": scan_path,
                "severity": scanner.severity,
                "finding_count": len(scanner.findings),
                "findings": scanner.findings,
            }

            with open(json_file, "w", encoding="utf-8") as f:
                json.dump(report, f, indent=2)

            json_file = os.path.abspath(json_file)

        # Post results to GUI
        self.root.after(0, lambda: self._show_results(scanner.severity, len(scanner.findings), json_file))

    def _show_results(self, severity: str, count: int, json_file: str | None):
        color = SEVERITY_COLORS.get(severity, FG)
        label = SEVERITY_LABELS.get(severity, severity)

        self.result_label.config(text=label, fg=color)

        if json_file:
            self.json_path = json_file
            self.json_label.config(
                text=f"Report saved: {json_file}  (click to copy path)"
            )
        else:
            self.json_label.config(text="")

        self._set_progress(6, 6, f"Done -- {count} finding(s), severity: {severity}")
        self.scan_btn.config(state=tk.NORMAL, text="Scan")
        self.browse_btn.config(state=tk.NORMAL)
        self.path_entry.config(state=tk.NORMAL)

    def _copy_json_path(self, _event=None):
        if self.json_path:
            self.root.clipboard_clear()
            self.root.clipboard_append(self.json_path)
            self.json_label.config(text=f"Copied: {self.json_path}")

    def run(self):
        self.root.mainloop()


def main():
    app = ScannerGUI()
    app.run()


if __name__ == "__main__":
    main()
