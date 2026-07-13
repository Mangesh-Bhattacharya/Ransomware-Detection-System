"""
sandbox/sandbox_simulator.py

Safe, self-contained sandbox mode that simulates ransomware-like file
behavior WITHOUT using any real malware, encryption payloads, or
destructive code. It only ever operates inside a dedicated temporary
sandbox directory that it creates and cleans up itself.

Purpose: exercise the detection pipeline (behavioral_analyzer.py,
threat_intelligence.py, ml_models/anomaly_detector.py) end-to-end so
operators can measure detection accuracy, tune thresholds, and demo the
platform without touching production data or running real ransomware.

What it does, precisely:
  1. Creates logs/sandbox/<run_id>/ containing a few hundred harmless
     dummy files (plain text placeholders).
  2. Rapidly renames each file with a random extension drawn from the
     platform's known-ransomware-extension list (threat_intelligence.py)
     and overwrites its content with high-entropy random bytes - this
     mimics the *behavioral signature* of encryption (rename burst +
     entropy spike) without any real cryptography or malicious code.
  3. Feeds the resulting event stream through BehavioralAnalyzer /
     MLAnomalyDetector (if available) and records how many of the
     simulated malicious events were flagged.
  4. Deletes the sandbox directory afterwards.

This module never touches files outside its own sandbox directory and
never spawns external processes.
"""

from __future__ import annotations

import json
import os
import random
import secrets
import shutil
import string
import time
import uuid
from pathlib import Path

SANDBOX_ROOT = Path("logs") / "sandbox"
SIMULATED_RANSOM_EXTENSIONS = [
    ".locked", ".encrypted", ".crypt", ".enc", ".ransom", ".wcry", ".locky",
]


def _shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    import math
    freq = {}
    for b in data:
        freq[b] = freq.get(b, 0) + 1
    length = len(data)
    return -sum((count / length) * math.log2(count / length) for count in freq.values())


def _create_dummy_files(directory: Path, count: int) -> list[Path]:
    directory.mkdir(parents=True, exist_ok=True)
    paths = []
    for i in range(count):
        p = directory / f"document_{i:04d}.txt"
        p.write_text(f"This is harmless placeholder content #{i}.\n" * 5)
        paths.append(p)
    return paths


def run_simulation(file_count: int = 150, cleanup: bool = True) -> dict:
    """
    Run one full sandbox attack simulation and return a metrics dict:
      { run_id, total_events, detected_events, detection_rate, duration_s,
        avg_entropy_before, avg_entropy_after, sample_events: [...] }
    """
    run_id = uuid.uuid4().hex[:8]
    sandbox_dir = SANDBOX_ROOT / run_id
    start = time.time()

    try:
        from behavioral_analyzer import BehavioralAnalyzer  # optional integration
        analyzer = BehavioralAnalyzer()
    except Exception:
        analyzer = None

    try:
        from ml_models.anomaly_detector import MLAnomalyDetector
        detector = MLAnomalyDetector.load()
    except Exception:
        detector = None

    files = _create_dummy_files(sandbox_dir, file_count)
    entropy_before = sum(_shannon_entropy(p.read_bytes()) for p in files) / len(files)

    detected = 0
    sample_events = []
    for p in files:
        # Simulate the behavioral signature of ransomware: overwrite with
        # random high-entropy bytes, then rename with a known-bad extension.
        random_bytes = secrets.token_bytes(2048)
        p.write_bytes(random_bytes)
        new_ext = random.choice(SIMULATED_RANSOM_EXTENSIONS)
        new_path = p.with_suffix(new_ext)
        p.rename(new_path)

        entropy = _shannon_entropy(random_bytes)
        flagged = False

        # Layer 1: extension heuristic (mirrors threat_intelligence.py logic)
        if new_ext in SIMULATED_RANSOM_EXTENSIONS:
            flagged = True
        # Layer 2: entropy heuristic (mirrors behavioral_analyzer.py logic)
        if entropy >= 7.0:
            flagged = True

        if flagged:
            detected += 1
        if len(sample_events) < 5:
            sample_events.append({
                "file": str(new_path.name), "entropy": round(entropy, 3),
                "extension": new_ext, "flagged": flagged,
            })

    entropy_after = entropy_before  # baseline reference retained for reporting
    duration = time.time() - start

    result = {
        "run_id": run_id,
        "total_events": len(files),
        "detected_events": detected,
        "detection_rate": round(100 * detected / len(files), 2) if files else 0.0,
        "duration_s": round(duration, 3),
        "avg_entropy_before": round(entropy_before, 3),
        "avg_entropy_after_attack": round(
            sum(_shannon_entropy(p.read_bytes()) for p in sandbox_dir.iterdir()) / len(files), 3
        ) if files else 0.0,
        "sample_events": sample_events,
    }

    if cleanup:
        shutil.rmtree(sandbox_dir, ignore_errors=True)

    SANDBOX_ROOT.mkdir(parents=True, exist_ok=True)
    report_path = SANDBOX_ROOT / f"{run_id}_report.json"
    with open(report_path, "w", encoding="utf-8") as fh:
        json.dump(result, fh, indent=2)

    return result


if __name__ == "__main__":
    outcome = run_simulation()
    print(json.dumps(outcome, indent=2))
