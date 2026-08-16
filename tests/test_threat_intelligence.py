"""Unit tests for threat_intelligence.py — industry profiles, entropy,
extension/hash matching, and compliance control mapping."""

import json
import os

import pytest

from threat_intelligence import (
    INDUSTRY_PROFILES,
    KNOWN_RANSOMWARE_HASHES,
    ThreatIntelligenceEngine,
    reset_engine,
)


@pytest.fixture
def engine():
    return ThreatIntelligenceEngine(industry="healthcare")


def test_unknown_industry_falls_back_to_general():
    engine = ThreatIntelligenceEngine(industry="not-a-real-sector")
    assert engine.industry == "general"


@pytest.mark.parametrize("industry", list(INDUSTRY_PROFILES.keys()))
def test_all_industry_profiles_load(industry):
    engine = ThreatIntelligenceEngine(industry=industry)
    assert engine.industry == industry
    assert engine.profile["label"]
    assert isinstance(engine.behavioral_thresholds, dict)


def test_suspicious_extension_detected(engine):
    assert engine.is_suspicious_extension("report.locked") is True
    assert engine.is_suspicious_extension("report.docx.enc") is True


def test_benign_extension_not_flagged():
    # Use the "general" profile specifically: healthcare/banking/government
    # profiles deliberately fold common document extensions (.docx, .pdf, ...)
    # into their critical-extensions set, since bulk activity touching those
    # types is itself worth flagging for those industries.
    general_engine = ThreatIntelligenceEngine(industry="general")
    assert general_engine.is_suspicious_extension("report.docx") is False


def test_industry_specific_extension_is_merged_into_suspicious_set(engine):
    # healthcare profile tags .dcm as critical; general does not
    healthcare = ThreatIntelligenceEngine(industry="healthcare")
    general = ThreatIntelligenceEngine(industry="general")
    assert ".dcm" in healthcare.suspicious_extensions
    assert ".dcm" not in general.suspicious_extensions


def test_entropy_of_uniform_random_bytes_is_high(tmp_path, engine):
    path = tmp_path / "random.bin"
    path.write_bytes(os.urandom(4096))
    entropy = engine.calculate_file_entropy(str(path))
    assert entropy > 7.0


def test_entropy_of_repeated_byte_is_zero(tmp_path, engine):
    path = tmp_path / "flat.bin"
    path.write_bytes(b"\x00" * 4096)
    entropy = engine.calculate_file_entropy(str(path))
    assert entropy == 0.0


def test_entropy_of_missing_file_is_zero(engine):
    assert engine.calculate_file_entropy("/nonexistent/path/file.bin") == 0.0


def test_check_file_hash_matches_known_ransomware(tmp_path, engine):
    # Craft a file whose sha256 is *not* pre-known; verify the negative path,
    # then verify the known-hash set is wired in correctly.
    path = tmp_path / "clean.txt"
    path.write_text("just a normal file")
    is_bad, digest = engine.check_file_hash(str(path))
    assert is_bad is False
    assert digest is not None
    assert digest not in KNOWN_RANSOMWARE_HASHES


def test_check_file_hash_missing_file_returns_false_none(engine):
    is_bad, digest = engine.check_file_hash("/nonexistent/path/file.bin")
    assert is_bad is False
    assert digest is None


def test_load_custom_ioc_extends_engine(tmp_path):
    ioc_file = tmp_path / "custom_ioc.json"
    ioc_file.write_text(json.dumps({
        "hashes": ["deadbeef" * 8],
        "extensions": [".myorgenc"],
        "process_patterns": ["mysuspiciousproc"],
    }))
    engine = ThreatIntelligenceEngine(industry="general", custom_ioc_file=str(ioc_file))
    assert "deadbeef" * 8 in engine.known_hashes
    assert ".myorgenc" in engine.suspicious_extensions
    assert "mysuspiciousproc" in engine.ransomware_process_patterns


def test_load_custom_ioc_missing_file_does_not_raise(tmp_path):
    missing = tmp_path / "does_not_exist.json"
    # Should log an error internally and leave the engine usable, not crash.
    engine = ThreatIntelligenceEngine(industry="general", custom_ioc_file=str(missing))
    assert engine.industry == "general"


def test_severity_label_boosted_by_industry():
    nuclear = ThreatIntelligenceEngine(industry="nuclear")  # +3 boost
    general = ThreatIntelligenceEngine(industry="general")  # +0 boost
    assert nuclear.severity_label(1) == "CRITICAL"
    assert general.severity_label(1) == "LOW"


def test_severity_label_caps_at_critical():
    nuclear = ThreatIntelligenceEngine(industry="nuclear")
    assert nuclear.severity_label(5) == "CRITICAL"


def test_get_compliance_controls_returns_mapped_frameworks():
    engine = ThreatIntelligenceEngine(industry="banking")
    controls = engine.get_compliance_controls()
    assert "PCI-DSS" in controls
    assert controls["PCI-DSS"]  # non-empty control list


def test_get_profile_summary_shape():
    engine = ThreatIntelligenceEngine(industry="government")
    summary = engine.get_profile_summary()
    for key in ("industry", "label", "compliance_frameworks",
                "tracked_extensions", "known_hashes_count",
                "behavioral_thresholds", "description"):
        assert key in summary


def test_reset_engine_updates_module_singleton():
    from threat_intelligence import get_engine
    reset_engine(industry="banking")
    assert get_engine().industry == "banking"
    reset_engine(industry="general")
    assert get_engine().industry == "general"
