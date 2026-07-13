"""
ml_models/anomaly_detector.py

Machine-learning based anomaly detection for the Ransomware Detection System.

Combines two complementary models:
  * IsolationForest        - unsupervised outlier detection over live
                              behavioral telemetry (file event rates,
                              entropy, process stats).
  * RandomForestClassifier - supervised classifier trained on labeled
                              file-activity / process-behavior feature
                              vectors to distinguish "benign" vs
                              "ransomware-like" behavior.

Both models share the same feature schema so they can be blended into a
single risk score (0-100) consumed by the dashboard, the LLM assistant, and
the auto-response engine. All training/inference is local - no telemetry
ever leaves the host.
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, asdict
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, roc_auc_score
from sklearn.preprocessing import StandardScaler

logger = logging.getLogger("ransomware_detector.ml")

MODEL_DIR = Path(__file__).resolve().parent / "saved_models"
MODEL_DIR.mkdir(exist_ok=True)

FEATURE_COLUMNS = [
    "file_modify_rate",       # files modified per minute
    "file_rename_rate",       # files renamed per minute
    "file_delete_rate",       # files deleted per minute
    "file_create_rate",       # files created per minute
    "unique_extension_count", # distinct extensions touched in window
    "avg_entropy",            # mean Shannon entropy of touched files
    "max_entropy",            # max Shannon entropy observed
    "proc_cpu_percent",       # CPU usage of the most active related process
    "proc_child_count",       # number of spawned child processes
    "proc_handle_count",      # open file handles held by the process
    "network_conn_count",     # active outbound connections opened
]


@dataclass
class RiskAssessment:
    """Structured result returned by MLAnomalyDetector.assess()."""

    risk_score: float
    isolation_forest_score: float
    random_forest_probability: float
    is_anomalous: bool
    is_classified_malicious: bool
    contributing_features: dict

    def to_dict(self) -> dict:
        return asdict(self)


class MLAnomalyDetector:
    """Wraps an IsolationForest (unsupervised) and a RandomForestClassifier
    (supervised) trained on the same behavioral feature schema."""

    def __init__(self, contamination: float = 0.05, random_state: int = 42):
        self.scaler = StandardScaler()
        self.isolation_forest = IsolationForest(
            n_estimators=200,
            contamination=contamination,
            random_state=random_state,
            n_jobs=-1,
        )
        self.random_forest = RandomForestClassifier(
            n_estimators=300,
            max_depth=12,
            class_weight="balanced",
            random_state=random_state,
            n_jobs=-1,
        )
        self._is_fitted = False

    # ------------------------------------------------------------------ #
    # Training
    # ------------------------------------------------------------------ #
    def fit(self, df: pd.DataFrame, label_col: str = "is_ransomware") -> dict:
        """Train both models on a DataFrame containing FEATURE_COLUMNS plus
        an optional binary label column for supervised training. Returns
        evaluation metrics for the held-out test split."""
        missing = set(FEATURE_COLUMNS) - set(df.columns)
        if missing:
            raise ValueError(f"Training data missing columns: {missing}")

        X = df[FEATURE_COLUMNS].fillna(0.0).values
        X_scaled = self.scaler.fit_transform(X)

        self.isolation_forest.fit(X_scaled)

        metrics = {}
        if label_col in df.columns:
            y = df[label_col].astype(int).values
            X_train, X_test, y_train, y_test = train_test_split(
                X_scaled, y, test_size=0.25, random_state=42, stratify=y
            )
            self.random_forest.fit(X_train, y_train)
            y_pred = self.random_forest.predict(X_test)
            y_proba = self.random_forest.predict_proba(X_test)[:, 1]
            metrics = {
                "classification_report": classification_report(
                    y_test, y_pred, output_dict=True, zero_division=0
                ),
                "roc_auc": float(roc_auc_score(y_test, y_proba))
                if len(set(y_test)) > 1 else None,
            }
            logger.info("RandomForest trained. ROC-AUC=%s", metrics.get("roc_auc"))
        else:
            logger.warning(
                "No label column '%s' found - RandomForest left untrained. "
                "IsolationForest-only mode active.", label_col,
            )

        self._is_fitted = True
        return metrics

    # ------------------------------------------------------------------ #
    # Inference
    # ------------------------------------------------------------------ #
    def assess(self, features: dict) -> RiskAssessment:
        """Score a single behavioral snapshot (dict keyed by
        FEATURE_COLUMNS) and return a blended RiskAssessment."""
        if not self._is_fitted:
            raise RuntimeError("Model not fitted or loaded. Call fit() or load().")

        vector = np.array([[features.get(c, 0.0) for c in FEATURE_COLUMNS]])
        vector_scaled = self.scaler.transform(vector)

        raw_if_score = self.isolation_forest.decision_function(vector_scaled)[0]
        is_outlier = self.isolation_forest.predict(vector_scaled)[0] == -1
        if_norm = float(np.clip((0.5 - raw_if_score) * 100, 0, 100))

        rf_proba = 0.0
        is_malicious = False
        try:
            rf_proba = float(self.random_forest.predict_proba(vector_scaled)[0][1])
            is_malicious = rf_proba >= 0.5
        except Exception:
            pass  # RandomForest untrained - IsolationForest-only mode

        blended = 0.5 * if_norm + 0.5 * (rf_proba * 100)
        top_features = self._top_contributing_features(features)

        return RiskAssessment(
            risk_score=round(blended, 2),
            isolation_forest_score=round(if_norm, 2),
            random_forest_probability=round(rf_proba, 4),
            is_anomalous=bool(is_outlier),
            is_classified_malicious=is_malicious,
            contributing_features=top_features,
        )

    def _top_contributing_features(self, features: dict, top_n: int = 3) -> dict:
        """Naive contribution ranking - highlights the most extreme feature
        values relative to typical benign baselines. Used for LLM
        explanations, not as a rigorous SHAP-style attribution."""
        baselines = {
            "file_modify_rate": 5, "file_rename_rate": 2, "file_delete_rate": 1,
            "file_create_rate": 3, "unique_extension_count": 3, "avg_entropy": 4.0,
            "max_entropy": 5.0, "proc_cpu_percent": 15, "proc_child_count": 1,
            "proc_handle_count": 20, "network_conn_count": 2,
        }
        deviations = {
            k: abs(features.get(k, 0) - baselines.get(k, 0)) for k in FEATURE_COLUMNS
        }
        ranked = sorted(deviations.items(), key=lambda kv: kv[1], reverse=True)
        return {k: features.get(k, 0) for k, _ in ranked[:top_n]}

    # ------------------------------------------------------------------ #
    # Persistence
    # ------------------------------------------------------------------ #
    def save(self, name: str = "ransomware_ml_model") -> Path:
        path = MODEL_DIR / f"{name}.joblib"
        joblib.dump(
            {
                "scaler": self.scaler,
                "isolation_forest": self.isolation_forest,
                "random_forest": self.random_forest,
                "is_fitted": self._is_fitted,
            },
            path,
        )
        logger.info("Model saved to %s", path)
        return path

    @classmethod
    def load(cls, name: str = "ransomware_ml_model") -> "MLAnomalyDetector":
        path = MODEL_DIR / f"{name}.joblib"
        if not path.exists():
            raise FileNotFoundError(f"No saved model at {path}")
        payload = joblib.load(path)
        detector = cls()
        detector.scaler = payload["scaler"]
        detector.isolation_forest = payload["isolation_forest"]
        detector.random_forest = payload["random_forest"]
        detector._is_fitted = payload["is_fitted"]
        return detector


def synthesize_training_data(n_benign: int = 4000, n_malicious: int = 400,
                              random_state: int = 42) -> pd.DataFrame:
    """Generates a synthetic labeled dataset for bootstrapping the models
    when no historical incident data is available yet. Benign samples model
    typical office/dev workstation activity; malicious samples model
    high-velocity encryption/rename bursts consistent with observed
    ransomware families. Replace with real telemetry captured from
    behavioral_analyzer.py as it accumulates in production."""
    rng = np.random.default_rng(random_state)

    benign = pd.DataFrame({
        "file_modify_rate": rng.poisson(4, n_benign),
        "file_rename_rate": rng.poisson(1, n_benign),
        "file_delete_rate": rng.poisson(0.5, n_benign),
        "file_create_rate": rng.poisson(2, n_benign),
        "unique_extension_count": rng.integers(1, 5, n_benign),
        "avg_entropy": rng.normal(3.5, 0.8, n_benign).clip(0, 8),
        "max_entropy": rng.normal(4.5, 1.0, n_benign).clip(0, 8),
        "proc_cpu_percent": rng.normal(10, 6, n_benign).clip(0, 100),
        "proc_child_count": rng.poisson(1, n_benign),
        "proc_handle_count": rng.poisson(15, n_benign),
        "network_conn_count": rng.poisson(2, n_benign),
    })
    benign["is_ransomware"] = 0

    malicious = pd.DataFrame({
        "file_modify_rate": rng.poisson(80, n_malicious),
        "file_rename_rate": rng.poisson(60, n_malicious),
        "file_delete_rate": rng.poisson(20, n_malicious),
        "file_create_rate": rng.poisson(40, n_malicious),
        "unique_extension_count": rng.integers(6, 20, n_malicious),
        "avg_entropy": rng.normal(7.6, 0.3, n_malicious).clip(0, 8),
        "max_entropy": rng.normal(7.9, 0.15, n_malicious).clip(0, 8),
        "proc_cpu_percent": rng.normal(65, 15, n_malicious).clip(0, 100),
        "proc_child_count": rng.poisson(4, n_malicious),
        "proc_handle_count": rng.poisson(120, n_malicious),
        "network_conn_count": rng.poisson(6, n_malicious),
    })
    malicious["is_ransomware"] = 1

    return pd.concat([benign, malicious], ignore_index=True).sample(
        frac=1, random_state=random_state
    ).reset_index(drop=True)


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    data = synthesize_training_data()
    detector = MLAnomalyDetector()
    metrics = detector.fit(data)
    print(json.dumps(metrics, indent=2, default=str))
    detector.save()

    sample_attack = {
        "file_modify_rate": 95, "file_rename_rate": 70, "file_delete_rate": 25,
        "file_create_rate": 50, "unique_extension_count": 12, "avg_entropy": 7.7,
        "max_entropy": 7.95, "proc_cpu_percent": 72, "proc_child_count": 5,
        "proc_handle_count": 140, "network_conn_count": 7,
    }
    result = detector.assess(sample_attack)
    print(json.dumps(result.to_dict(), indent=2))
