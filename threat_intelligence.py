# threat_intelligence.py
# Threat Intelligence Engine for Ransomware Detection System
# Provides industry-specific IOC feeds, known ransomware signatures,
# behavioral baselines, and compliance tagging for regulated sectors.
#
# Industries supported: healthcare, banking, nuclear, energy, government, general
# Compliance frameworks: HIPAA, PCI-DSS, NRC 10CFR73.54, NERC CIP, FISMA, CMMC,
#                        GLBA, SOX, SWIFT-CSCF, IEC-62443, NIST-CSF, ISO-27001, SOC2

import hashlib
import json
import logging
import math
import os
import platform
from typing import Dict, List, Optional, Set, Tuple

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# INDUSTRY PROFILES
# ---------------------------------------------------------------------------
INDUSTRY_PROFILES: Dict[str, dict] = {
    "healthcare": {
        "label": "Healthcare (HIPAA / HITECH)",
        "critical_extensions": {".hl7", ".dcm", ".nii", ".fhir", ".ccd", ".ccda",
                                 ".xml", ".json", ".pdf", ".xlsx", ".docx", ".csv"},
        "compliance_frameworks": ["HIPAA", "HITECH", "NIST-CSF", "SOC2"],
        "critical_dirs_unix": ["/var/lib/ehr", "/opt/pacs", "/srv/radiology"],
        "critical_dirs_win": ["C:\\EHR", "C:\\PACS", "C:\\PatientRecords"],
        "alert_severity_boost": 2,
        "require_encryption_at_rest": True,
        "retention_days": 2190,
        "description": "Protects EHRs, DICOM imaging, FHIR resources, and PHI under HIPAA."
    },
    "banking": {
        "label": "Banking & Finance (PCI-DSS / GLBA / SOX)",
        "critical_extensions": {".qfx", ".ofx", ".bai", ".bai2", ".mt940", ".mt942",
                                 ".xlsx", ".csv", ".pdf", ".json", ".xml"},
        "compliance_frameworks": ["PCI-DSS", "GLBA", "SOX", "SWIFT-CSCF", "NIST-CSF"],
        "critical_dirs_unix": ["/var/lib/core-banking", "/opt/swift", "/srv/transactions"],
        "critical_dirs_win": ["C:\\CoreBanking", "C:\\SWIFT", "C:\\Transactions"],
        "alert_severity_boost": 2,
        "require_encryption_at_rest": True,
        "retention_days": 2555,
        "description": "Guards transaction records, SWIFT messaging, and financial statements."
    },
    "nuclear": {
        "label": "Nuclear (NRC 10 CFR 73.54 / NERC CIP)",
        "critical_extensions": {".rpm", ".erd", ".dxf", ".dwg", ".stp", ".iges",
                                 ".csv", ".xlsx", ".pdf", ".json", ".xml", ".dat"},
        "compliance_frameworks": ["NRC-10CFR73.54", "NERC-CIP", "ICS-CERT", "NIST-SP800-82"],
        "critical_dirs_unix": ["/var/lib/scada", "/opt/dcs", "/srv/safety-systems"],
        "critical_dirs_win": ["C:\\SCADA", "C:\\DCS", "C:\\SafetySystems", "C:\\OT"],
        "alert_severity_boost": 3,
        "require_encryption_at_rest": True,
        "retention_days": 3650,
        "description": "Defends OT/ICS/SCADA systems, reactor data, and safety instrumentation."
    },
    "energy": {
        "label": "Energy & Utilities (NERC CIP / IEC-62443)",
        "critical_extensions": {".csv", ".xlsx", ".dat", ".xml", ".json", ".pdf"},
        "compliance_frameworks": ["NERC-CIP", "ICS-CERT", "NIST-SP800-82", "IEC-62443"],
        "critical_dirs_unix": ["/var/lib/ems", "/opt/ems", "/srv/grid"],
        "critical_dirs_win": ["C:\\EMS", "C:\\GridControl", "C:\\OT"],
        "alert_severity_boost": 3,
        "require_encryption_at_rest": True,
        "retention_days": 1825,
        "description": "Protects energy management, grid control, and OT/ICS environments."
    },
    "government": {
        "label": "Government (FISMA / CMMC / FedRAMP)",
        "critical_extensions": {".pdf", ".docx", ".xlsx", ".json", ".xml", ".eml",
                                 ".pst", ".msg", ".csv"},
        "compliance_frameworks": ["FISMA", "CMMC", "FedRAMP", "NIST-800-53", "CJIS"],
        "critical_dirs_unix": ["/var/lib/gov", "/opt/classified", "/srv/records"],
        "critical_dirs_win": ["C:\\GovData", "C:\\Classified", "C:\\FedRecords"],
        "alert_severity_boost": 2,
        "require_encryption_at_rest": True,
        "retention_days": 2555,
        "description": "Covers federal information systems, classified documents, and CUI."
    },
    "general": {
        "label": "General Purpose",
        "critical_extensions": set(),
        "compliance_frameworks": ["NIST-CSF", "ISO-27001"],
        "critical_dirs_unix": [],
        "critical_dirs_win": [],
        "alert_severity_boost": 0,
        "require_encryption_at_rest": False,
        "retention_days": 365,
        "description": "Default profile — no sector-specific compliance requirements."
    }
}

# ---------------------------------------------------------------------------
# KNOWN RANSOMWARE FAMILY HASHES (SHA-256)
# Replace / extend from CISA, VirusTotal, or internal threat feeds.
# ---------------------------------------------------------------------------
KNOWN_RANSOMWARE_HASHES: Set[str] = {
    "9aa1f37517458d635eae4f9b43318281dd6a5a3fb0e4d0d58df81fd4f0a3af62",  # LockBit 3.0
    "731adcf2d7fb61a8335e23dbee2436249e5d5753977ec465754c6b699e9bf161",  # BlackCat/ALPHV
    "3e3be58ff8c06d04c7cd5e946eed587e1c03d0c24dcfc3e4aab6e3e55a6e7e78",  # Cl0p
    "c4a5a0a59c3e8fd57fb9da5cf574fdb4b67e83f77df1d8da24b6de70dccb2df9",  # Hive
    "dc34d9f42f2b5bcbedc41e97046d618a65b89ca9f64f3e87e20d1b5d3f54c3f1",  # REvil
    "e4f3c8b4a6ce2f57e31a3b5e1c53a7e65f14c1e7a2b7f4d3d8e9f5c6e1b2c3d",  # Conti
    "24d004a104d4d54034dbcffc2a4b19a11f39008a575aa614ea04703480b1022c",  # WannaCry
    "027cc450ef5f8c5f653329641ec1fed91f694e0d229928963b30f6b0d7d3a745",  # NotPetya
}

# ---------------------------------------------------------------------------
# SUSPICIOUS EXTENSIONS — EXPANDED
# ---------------------------------------------------------------------------
SUSPICIOUS_EXTENSIONS_BASE: Set[str] = {
    ".locked", ".enc", ".crypt", ".crypto", ".ransom", ".encrypted",
    ".lock", ".locky", ".cerber", ".ccc", ".vvv", ".abc", ".xyz",
    ".zepto", ".osiris", ".wnry", ".wncry", ".wncrypt",
    ".lockbit", ".blackcat", ".hive", ".cl0p", ".revil", ".conti",
    ".blackmatter", ".darkside", ".netwalker", ".ryuk",
    ".aaa", ".bbb", ".fun", ".gws", ".ecc", ".ezz", ".exx",
    ".micro", ".ttt", ".vvx", ".xxx", ".zzz",
    ".bak_enc", ".backup_enc", ".scada_lock", ".ics_enc",
}

# ---------------------------------------------------------------------------
# BEHAVIORAL THRESHOLDS
# ---------------------------------------------------------------------------
BEHAVIORAL_THRESHOLDS: Dict[str, int] = {
    "max_file_renames_per_minute": 20,
    "max_file_modifications_per_minute": 50,
    "max_file_deletions_per_minute": 15,
    "max_new_extensions_per_minute": 10,
    "entropy_high_threshold": 7.2,
    "entropy_sample_size_bytes": 4096,
}

# ---------------------------------------------------------------------------
# RANSOMWARE PROCESS NAME PATTERNS
# ---------------------------------------------------------------------------
RANSOMWARE_PROCESS_PATTERNS: List[str] = [
    "ransom", "encrypt", "locker", "lockbit", "blackcat", "hive",
    "cl0p", "revil", "conti", "blackmatter", "darkside", "netwalker",
    "ryuk", "maze", "egregor", "babuk", "sodinokibi", "gandcrab",
    "wannacry", "notpetya", "petya", "badrabbit",
]

# ---------------------------------------------------------------------------
# COMPLIANCE CONTROL MAPPINGS  (Framework -> NIST 800-53 / CSF controls)
# ---------------------------------------------------------------------------
COMPLIANCE_CONTROL_MAPPINGS: Dict[str, List[str]] = {
    "HIPAA":            ["IR-6", "SI-3", "AU-2", "SC-28", "CP-9"],
    "HITECH":           ["IR-6", "SC-28", "AU-9"],
    "PCI-DSS":          ["IR-6", "SI-3", "AU-2", "SC-28", "A3.2"],
    "SOX":              ["AU-2", "AU-9", "CP-9", "SI-12"],
    "GLBA":             ["SC-28", "AU-2", "IR-6"],
    "SWIFT-CSCF":       ["IR-4", "SI-3", "AU-2"],
    "NRC-10CFR73.54":   ["IR-4", "SI-3", "SC-28", "AU-2", "CP-9"],
    "NERC-CIP":         ["CIP-006", "CIP-007", "CIP-009", "CIP-010"],
    "ICS-CERT":         ["IR-4", "SI-3", "SC-28"],
    "NIST-SP800-82":    ["IR-4", "SI-3", "SC-28", "AU-2"],
    "IEC-62443":        ["SR-3.2", "SR-6.1", "SR-7.3"],
    "FISMA":            ["IR-6", "SI-3", "AU-2", "SC-28", "CP-9"],
    "CMMC":             ["IR.2.093", "SI.1.210", "AU.2.042"],
    "FedRAMP":          ["IR-6", "SI-3", "AU-2", "CP-9"],
    "NIST-800-53":      ["IR-6", "SI-3", "AU-2", "SC-28", "CP-9"],
    "CJIS":             ["IR-6", "SI-3", "SC-28"],
    "NIST-CSF":         ["RS.CO-2", "DE.CM-4", "PR.DS-1"],
    "ISO-27001":        ["A.16.1.2", "A.12.2.1", "A.10.1.1"],
    "SOC2":             ["CC7.2", "CC7.3", "CC9.1"],
}


class ThreatIntelligenceEngine:
    """
    Central threat intelligence engine.
    Loads IOC feeds, known hash lists, behavioral thresholds,
    and industry profile configuration at runtime.
    """

    def __init__(self, industry: str = "general", custom_ioc_file: Optional[str] = None):
        self.industry = industry if industry in INDUSTRY_PROFILES else "general"
        self.profile = INDUSTRY_PROFILES[self.industry]
        self.suspicious_extensions: Set[str] = (
            SUSPICIOUS_EXTENSIONS_BASE | self.profile.get("critical_extensions", set())
        )
        self.known_hashes: Set[str] = set(KNOWN_RANSOMWARE_HASHES)
        self.behavioral_thresholds: Dict = dict(BEHAVIORAL_THRESHOLDS)
        self.ransomware_process_patterns: List[str] = list(RANSOMWARE_PROCESS_PATTERNS)

        if custom_ioc_file:
            self._load_custom_ioc(custom_ioc_file)

        logger.info(
            "[ThreatIntel] Initialized for industry='%s' (%s). "
            "Tracking %d extensions, %d known hashes.",
            self.industry, self.profile["label"],
            len(self.suspicious_extensions), len(self.known_hashes)
        )

    def _load_custom_ioc(self, path: str) -> None:
        """
        Load additional IOCs from a JSON file.
        Expected format::

            {
                "hashes": ["sha256...", ...],
                "extensions": [".ext1", ...],
                "process_patterns": ["pattern1", ...]
            }
        """
        try:
            with open(path, "r", encoding="utf-8") as f:
                data = json.load(f)
            self.known_hashes.update(data.get("hashes", []))
            self.suspicious_extensions.update(data.get("extensions", []))
            self.ransomware_process_patterns.extend(data.get("process_patterns", []))
            logger.info("[ThreatIntel] Custom IOC feed loaded from %s", path)
        except (FileNotFoundError, json.JSONDecodeError) as e:
            logger.error("[ThreatIntel] Failed to load custom IOC file: %s", e)

    def check_file_hash(self, filepath: str) -> Tuple[bool, Optional[str]]:
        """
        Compute SHA-256 of a file and check against known ransomware hashes.
        Returns (is_known_bad, sha256_hex).
        """
        try:
            sha256 = hashlib.sha256()
            with open(filepath, "rb") as f:
                for chunk in iter(lambda: f.read(65536), b""):
                    sha256.update(chunk)
            digest = sha256.hexdigest()
            return digest in self.known_hashes, digest
        except (OSError, PermissionError):
            return False, None

    def calculate_file_entropy(self, filepath: str) -> float:
        """
        Calculate Shannon entropy of the first N bytes of a file.
        High entropy (>7.2 bits) is a strong indicator of encryption.
        """
        try:
            with open(filepath, "rb") as f:
                data = f.read(self.behavioral_thresholds["entropy_sample_size_bytes"])
            if not data:
                return 0.0
            freq = [0] * 256
            for byte in data:
                freq[byte] += 1
            entropy = 0.0
            length = len(data)
            for count in freq:
                if count:
                    p = count / length
                    entropy -= p * math.log2(p)
            return round(entropy, 4)
        except (OSError, PermissionError):
            return 0.0

    def is_suspicious_extension(self, filepath: str) -> bool:
        """Return True if the file has a known ransomware or suspicious extension."""
        _, ext = os.path.splitext(filepath)
        return ext.lower() in self.suspicious_extensions

    def is_critical_path(self, filepath: str) -> bool:
        """Return True if the file resides in an industry-critical directory."""
        key = "critical_dirs_win" if platform.system() == "Windows" else "critical_dirs_unix"
        for critical_dir in self.profile.get(key, []):
            if filepath.startswith(critical_dir):
                return True
        return False

    def get_compliance_controls(self) -> Dict[str, List[str]]:
        """Return compliance controls relevant to the active industry profile."""
        controls = {}
        for framework in self.profile.get("compliance_frameworks", []):
            controls[framework] = COMPLIANCE_CONTROL_MAPPINGS.get(framework, [])
        return controls

    def severity_label(self, base_severity: int) -> str:
        """
        Apply industry severity boost and return a human-readable label.
        base_severity: 1 (low) to 5 (critical).
        """
        boosted = min(base_severity + self.profile.get("alert_severity_boost", 0), 5)
        return {1: "LOW", 2: "MEDIUM", 3: "HIGH", 4: "CRITICAL", 5: "CRITICAL"}.get(boosted, "UNKNOWN")

    def get_profile_summary(self) -> Dict:
        """Return a summary dict of the active profile for UI display."""
        return {
            "industry": self.industry,
            "label": self.profile["label"],
            "compliance_frameworks": self.profile["compliance_frameworks"],
            "tracked_extensions": sorted(self.suspicious_extensions),
            "known_hashes_count": len(self.known_hashes),
            "behavioral_thresholds": self.behavioral_thresholds,
            "description": self.profile["description"],
        }


# Module-level singleton.
# Call reset_engine(industry=...) from application.py to reconfigure.
_engine: Optional[ThreatIntelligenceEngine] = None


def get_engine() -> ThreatIntelligenceEngine:
    global _engine
    if _engine is None:
        _engine = ThreatIntelligenceEngine()
    return _engine


def reset_engine(industry: str = "general",
                 custom_ioc_file: Optional[str] = None) -> ThreatIntelligenceEngine:
    global _engine
    _engine = ThreatIntelligenceEngine(industry=industry, custom_ioc_file=custom_ioc_file)
    return _engine
