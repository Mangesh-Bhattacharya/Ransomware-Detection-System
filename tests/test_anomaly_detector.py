"""Unit tests for ml_models/anomaly_detector.py.

Uses a small synthetic dataset (not the full 4400-row default) so the suite
stays fast in CI while still exercising real model training and inference.
"""

import pytest

import ml_models.anomaly_detector as ad_module
from ml_models.anomaly_detector import (
    FEATURE_COLUMNS,
    MLAnomalyDetector,
    synthesize_training_data,
)

BENIGN_SAMPLE = {
    "file_modify_rate": 3, "file_rename_rate": 1, "file_delete_rate": 0,
    "file_create_rate": 2, "unique_extension_count": 2, "avg_entropy": 3.4,
    "max_entropy": 4.2, "proc_cpu_percent": 8, "proc_child_count": 0,
    "proc_handle_count": 12, "network_conn_count": 1,
}

MALICIOUS_SAMPLE = {
    "file_modify_rate": 95, "file_rename_rate": 70, "file_delete_rate": 25,
    "file_create_rate": 50, "unique_extension_count": 15, "avg_entropy": 7.8,
    "max_entropy": 7.95, "proc_cpu_percent": 75, "proc_child_count": 5,
    "proc_handle_count": 140, "network_conn_count": 8,
}


@pytest.fixture(scope="module")
def fitted_detector():
    data = synthesize_training_data(n_benign=200, n_malicious=40, random_state=1)
    detector = MLAnomalyDetector(random_state=1)
    detector.fit(data)
    return detector


def test_synthesize_training_data_shape_and_labels():
    df = synthesize_training_data(n_benign=50, n_malicious=10, random_state=1)
    assert len(df) == 60
    assert set(FEATURE_COLUMNS).issubset(df.columns)
    assert df["is_ransomware"].sum() == 10


def test_fit_raises_on_missing_columns():
    import pandas as pd
    detector = MLAnomalyDetector()
    with pytest.raises(ValueError):
        detector.fit(pd.DataFrame({"file_modify_rate": [1, 2, 3]}))


def test_fit_returns_classification_metrics(fitted_detector):
    data = synthesize_training_data(n_benign=200, n_malicious=40, random_state=1)
    detector = MLAnomalyDetector(random_state=1)
    metrics = detector.fit(data)
    assert "classification_report" in metrics
    assert metrics["roc_auc"] is not None
    assert 0.0 <= metrics["roc_auc"] <= 1.0


def test_assess_before_fit_raises():
    detector = MLAnomalyDetector()
    with pytest.raises(RuntimeError):
        detector.assess(BENIGN_SAMPLE)


def test_malicious_sample_scores_higher_than_benign(fitted_detector):
    benign_result = fitted_detector.assess(BENIGN_SAMPLE)
    malicious_result = fitted_detector.assess(MALICIOUS_SAMPLE)
    assert malicious_result.risk_score > benign_result.risk_score
    assert malicious_result.is_classified_malicious is True
    assert benign_result.is_classified_malicious is False


def test_assess_returns_top_contributing_features(fitted_detector):
    result = fitted_detector.assess(MALICIOUS_SAMPLE)
    assert len(result.contributing_features) == 3
    assert set(result.contributing_features).issubset(FEATURE_COLUMNS)


def test_save_and_load_round_trip_preserves_predictions(tmp_path, monkeypatch, fitted_detector):
    monkeypatch.setattr(ad_module, "MODEL_DIR", tmp_path)
    saved_path = fitted_detector.save(name="test_model")
    assert saved_path.exists()

    reloaded = MLAnomalyDetector.load(name="test_model")
    original = fitted_detector.assess(MALICIOUS_SAMPLE)
    restored = reloaded.assess(MALICIOUS_SAMPLE)
    assert restored.risk_score == pytest.approx(original.risk_score)


def test_load_missing_model_raises(tmp_path, monkeypatch):
    monkeypatch.setattr(ad_module, "MODEL_DIR", tmp_path)
    with pytest.raises(FileNotFoundError):
        MLAnomalyDetector.load(name="does_not_exist")
