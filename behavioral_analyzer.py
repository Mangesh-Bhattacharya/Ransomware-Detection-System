# behavioral_analyzer.py
# Real-time behavioral analysis engine for the Ransomware Detection System.
# Tracks file operation rates, extension diversity, and entropy spikes
# to detect ransomware activity that signature-based methods miss.
#
# Key capabilities:
#   - Sliding-window counters for renames, modifications, deletions
#   - New-extension diversity detection (ransomware invents new extensions)
#   - Shannon entropy screening of modified files
#   - LLM-ready context packaging for external behavioral reasoning
#   - Thread-safe design for concurrent watchdog callbacks

import logging
import os
import threading
import time
from collections import deque
from datetime import datetime
from typing import Callable, Dict, List, Optional

from threat_intelligence import get_engine

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# EVENT TYPE CONSTANTS
# ---------------------------------------------------------------------------
EVT_MODIFY = "modify"
EVT_RENAME = "rename"
EVT_DELETE = "delete"
EVT_CREATE = "create"


class SlidingWindowCounter:
    """
    Thread-safe sliding-window event counter.
    Counts events within the last `window_seconds` seconds.
    """

    def __init__(self, window_seconds: int = 60):
        self.window = window_seconds
        self._events: deque = deque()
        self._lock = threading.Lock()

    def record(self) -> None:
        now = time.monotonic()
        with self._lock:
            self._events.append(now)
            self._prune(now)

    def count(self) -> int:
        now = time.monotonic()
        with self._lock:
            self._prune(now)
            return len(self._events)

    def _prune(self, now: float) -> None:
        cutoff = now - self.window
        while self._events and self._events[0] < cutoff:
            self._events.popleft()


class ExtensionTracker:
    """
    Tracks the set of *new* file extensions observed within a window.
    Ransomware typically appends a unique extension to every encrypted file,
    so a sudden burst of new extensions is a strong signal.
    """

    def __init__(self, window_seconds: int = 60):
        self.window = window_seconds
        self._seen: Dict[str, float] = {}  # ext -> first_seen_monotonic
        self._lock = threading.Lock()

    def record(self, ext: str) -> bool:
        """
        Record an extension.  Returns True if this extension is NEW
        within the current window.
        """
        now = time.monotonic()
        with self._lock:
            self._prune(now)
            if ext not in self._seen:
                self._seen[ext] = now
                return True
            return False

    def new_extension_count(self) -> int:
        now = time.monotonic()
        with self._lock:
            self._prune(now)
            return len(self._seen)

    def _prune(self, now: float) -> None:
        cutoff = now - self.window
        self._seen = {k: v for k, v in self._seen.items() if v >= cutoff}


class BehavioralAnalyzer:
    """
    Aggregates file system events and evaluates them against
    behavioral thresholds from the active ThreatIntelligenceEngine.

    Usage::

        analyzer = BehavioralAnalyzer(alert_callback=my_callback)
        # Call from watchdog event handlers:
        analyzer.record_event(EVT_MODIFY, "/path/to/file.enc")
    """

    def __init__(self, alert_callback: Optional[Callable[[dict], None]] = None):
        self._engine = get_engine()
        self._thresholds = self._engine.behavioral_thresholds
        self._alert_callback = alert_callback

        self._counters: Dict[str, SlidingWindowCounter] = {
            EVT_MODIFY: SlidingWindowCounter(60),
            EVT_RENAME: SlidingWindowCounter(60),
            EVT_DELETE: SlidingWindowCounter(60),
            EVT_CREATE: SlidingWindowCounter(60),
        }
        self._ext_tracker = ExtensionTracker(60)
        self._alert_history: List[dict] = []
        self._lock = threading.Lock()

        logger.info("[BehavioralAnalyzer] Initialized with industry='%s'.",
                    self._engine.industry)

    def record_event(self, event_type: str, filepath: str,
                     old_filepath: Optional[str] = None) -> Optional[dict]:
        """
        Record a single file system event and evaluate behavioral thresholds.

        :param event_type: One of EVT_MODIFY / EVT_RENAME / EVT_DELETE / EVT_CREATE
        :param filepath: Absolute path to the affected file.
        :param old_filepath: Original path (for rename events).
        :returns: Alert dict if a threshold was breached, else None.
        """
        counter = self._counters.get(event_type)
        if counter:
            counter.record()

        # Track extension diversity
        _, ext = os.path.splitext(filepath)
        new_ext = self._ext_tracker.record(ext.lower()) if ext else False

        alert = self._evaluate(event_type, filepath, new_ext, old_filepath)
        if alert:
            with self._lock:
                self._alert_history.append(alert)
            if self._alert_callback:
                try:
                    self._alert_callback(alert)
                except Exception as exc:
                    logger.error("[BehavioralAnalyzer] Alert callback raised: %s", exc)
        return alert

    def _evaluate(self, event_type: str, filepath: str,
                  new_ext: bool, old_filepath: Optional[str]) -> Optional[dict]:
        """Check counters and entropy; return an alert dict if thresholds exceeded."""
        reasons: List[str] = []

        # 1. Rate-based checks
        modify_rate = self._counters[EVT_MODIFY].count()
        rename_rate = self._counters[EVT_RENAME].count()
        delete_rate = self._counters[EVT_DELETE].count()
        new_ext_count = self._ext_tracker.new_extension_count()

        if modify_rate > self._thresholds["max_file_modifications_per_minute"]:
            reasons.append(
                f"HIGH modify rate: {modify_rate}/min "
                f"(threshold {self._thresholds['max_file_modifications_per_minute']})"
            )
        if rename_rate > self._thresholds["max_file_renames_per_minute"]:
            reasons.append(
                f"HIGH rename rate: {rename_rate}/min "
                f"(threshold {self._thresholds['max_file_renames_per_minute']})"
            )
        if delete_rate > self._thresholds["max_file_deletions_per_minute"]:
            reasons.append(
                f"HIGH deletion rate: {delete_rate}/min "
                f"(threshold {self._thresholds['max_file_deletions_per_minute']})"
            )
        if new_ext_count > self._thresholds["max_new_extensions_per_minute"]:
            reasons.append(
                f"HIGH new-extension diversity: {new_ext_count} unique new extensions/min"
            )

        # 2. Entropy check (only for modify/create on accessible files)
        entropy = 0.0
        if event_type in (EVT_MODIFY, EVT_CREATE) and os.path.isfile(filepath):
            entropy = self._engine.calculate_file_entropy(filepath)
            if entropy >= self._thresholds["entropy_high_threshold"]:
                reasons.append(
                    f"HIGH file entropy: {entropy:.3f} bits "
                    f"(threshold {self._thresholds['entropy_high_threshold']}) — "
                    "possible encryption detected"
                )

        # 3. Known-hash check
        hash_hit, sha256 = False, None
        if event_type in (EVT_MODIFY, EVT_CREATE) and os.path.isfile(filepath):
            hash_hit, sha256 = self._engine.check_file_hash(filepath)
            if hash_hit:
                reasons.append(f"KNOWN RANSOMWARE HASH matched: {sha256}")

        # 4. Suspicious extension
        if self._engine.is_suspicious_extension(filepath):
            reasons.append(f"SUSPICIOUS EXTENSION detected: {os.path.splitext(filepath)[1]}")

        # 5. Critical path
        is_critical = self._engine.is_critical_path(filepath)
        if is_critical:
            reasons.append(f"CRITICAL INDUSTRY PATH affected: {filepath}")

        if not reasons:
            return None

        base_severity = 3 if hash_hit or self._engine.is_suspicious_extension(filepath) else 2
        if is_critical:
            base_severity += 1

        alert = {
            "timestamp": datetime.now().isoformat(),
            "event_type": event_type,
            "filepath": filepath,
            "old_filepath": old_filepath,
            "sha256": sha256,
            "entropy": entropy,
            "reasons": reasons,
            "severity": self._engine.severity_label(base_severity),
            "industry": self._engine.industry,
            "compliance_controls": self._engine.get_compliance_controls(),
            "counters": {
                "modify_rate": modify_rate,
                "rename_rate": rename_rate,
                "delete_rate": delete_rate,
                "new_extensions": new_ext_count,
            },
        }
        logger.warning("[BehavioralAlert] %s | %s | %s",
                       alert["severity"], filepath, "; ".join(reasons))
        return alert

    def get_status_snapshot(self) -> dict:
        """Return current counter snapshot — useful for dashboard polling."""
        return {
            "timestamp": datetime.now().isoformat(),
            "industry": self._engine.industry,
            "modify_rate_1min": self._counters[EVT_MODIFY].count(),
            "rename_rate_1min": self._counters[EVT_RENAME].count(),
            "delete_rate_1min": self._counters[EVT_DELETE].count(),
            "create_rate_1min": self._counters[EVT_CREATE].count(),
            "new_extension_diversity": self._ext_tracker.new_extension_count(),
            "recent_alerts": len(self._alert_history),
        }

    def get_alert_history(self) -> List[dict]:
        """Return a copy of the accumulated alert history."""
        with self._lock:
            return list(self._alert_history)

    def build_llm_context_packet(self) -> dict:
        """
        Build a structured context packet suitable for sending to an LLM
        for deeper behavioral reasoning or natural-language incident summarization.

        The packet is pure JSON-serializable data — no model is called here.
        Downstream callers decide how to submit it to their preferred LLM endpoint.
        """
        profile = self._engine.get_profile_summary()
        snapshot = self.get_status_snapshot()
        recent_alerts = self.get_alert_history()[-10:]  # Last 10 alerts only

        return {
            "context_type": "ransomware_behavioral_analysis",
            "generated_at": datetime.now().isoformat(),
            "industry_profile": profile,
            "current_activity_snapshot": snapshot,
            "recent_alerts": recent_alerts,
            "instructions_for_llm": (
                "You are a cybersecurity analyst. Analyze the provided ransomware "
                "behavioral telemetry and produce: (1) a risk assessment, "
                "(2) the most likely ransomware family if identifiable, "
                "(3) immediate containment steps, (4) relevant compliance "
                "notifications required by the indicated frameworks."
            ),
        }

    def reset_counters(self) -> None:
        """Reset all sliding-window counters (useful after a drill or false positive)."""
        for counter in self._counters.values():
            counter._events.clear()
        self._ext_tracker._seen.clear()
        with self._lock:
            self._alert_history.clear()
        logger.info("[BehavioralAnalyzer] All counters and alert history reset.")


# Module-level singleton
_analyzer: Optional[BehavioralAnalyzer] = None


def get_analyzer(alert_callback: Optional[Callable[[dict], None]] = None) -> BehavioralAnalyzer:
    global _analyzer
    if _analyzer is None:
        _analyzer = BehavioralAnalyzer(alert_callback=alert_callback)
    return _analyzer


def reset_analyzer(alert_callback: Optional[Callable[[dict], None]] = None) -> BehavioralAnalyzer:
    global _analyzer
    _analyzer = BehavioralAnalyzer(alert_callback=alert_callback)
    return _analyzer
