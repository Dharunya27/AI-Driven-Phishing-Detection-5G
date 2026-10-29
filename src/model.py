"""
Model Training and Serialization for Phishing URL Detection
Architecture: Random Forest Classifier
Configured according to the Diskominfo Kota Prabumulih research parameters.
"""

import os
import joblib
import numpy as np
from pathlib import Path
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score
from typing import Dict, Any, Tuple

from src.features import FEATURE_COLUMNS, extract_features, to_feature_vector

DEFAULT_CHECKPOINT_DIR = Path(__file__).resolve().parent.parent / "checkpoints"
DEFAULT_MODEL_PATH = DEFAULT_CHECKPOINT_DIR / "model_demo.joblib"


def get_default_model(n_estimators: int = 10, max_depth: int = 15, random_state: int = 42) -> RandomForestClassifier:
    """
    Initializes Random Forest Classifier matching research parameters:
    n_estimators = 10, max_depth in range [1, 20].
    """
    return RandomForestClassifier(
        n_estimators=n_estimators,
        max_depth=max_depth,
        random_state=random_state,
        n_jobs=-1
    )


def create_representative_seed_dataset() -> Tuple[np.ndarray, np.ndarray]:
    """
    Constructs a calibrated seed dataset of legitimate and phishing URLs
    for instant out-of-the-box operation and automated test environments.
    """
    urls_legit = [
        "https://www.google.com",
        "https://github.com/aral3000",
        "https://unsri.ac.id",
        "https://prabumulihkota.go.id",
        "https://kominfo.go.id",
        "https://en.wikipedia.org/wiki/Machine_learning",
        "https://www.kaggle.com/datasets",
        "https://pypi.org/project/scikit-learn",
        "https://docs.python.org/3/library/urllib.parse.html",
        "https://stackoverflow.com/questions",
        "https://news.ycombinator.com",
        "https://medium.com",
        "https://scikit-learn.org/stable/modules/ensemble.html",
        "https://cloud.google.com",
        "https://aws.amazon.com"
    ]

    urls_phish = [
        "http://192.168.1.105/secure-login-account-update/verify.php?token=9283749",
        "http://paypal.com.account-verification-system.update-alert.xyz/signin",
        "http://bca-klik-secure-banking.online-confirm-id.net/login.html?id=8392",
        "http://login-appleid-verify.security-check-account-apple.info/auth/login",
        "http://www-facebook-com.account-checkpoint-verify-auth.co/login.php",
        "http://10.0.0.1/auth/google/signin/oauth2?state=392817364",
        "http://bri-internet-banking-pembaruan-sistem.top/verification/step1",
        "http://microsoft-365-password-reset.secure-login-portal-office.live/update",
        "http://netflix-billing-update-subscription.support-center-pay.site/billing",
        "http://mandiri-online-validasi-rekening.id-update.vip/portal/auth",
        "http://instagram-help-copyright-infringement.appeal-form.biz/confirm",
        "http://dinas-kominfo.verifikasi-pegawai-update.pw/login.php?user=admin",
        "http://172.16.254.1/phishing-test/form.php",
        "http://google-drive-shared-document-view.file-download-safe.top/view",
        "http://secure-whatsapp-web-qr-login-connect.my.id/auth/scan"
    ]

    X = []
    y = []

    for u in urls_legit:
        feat = extract_features(u)
        X.append(to_feature_vector(feat))
        y.append(0)

    for u in urls_phish:
        feat = extract_features(u)
        X.append(to_feature_vector(feat))
        y.append(1)

    return np.array(X, dtype=np.float32), np.array(y, dtype=np.int32)


def train_and_save_model(model_path: Path = DEFAULT_MODEL_PATH) -> RandomForestClassifier:
    """Trains Random Forest model on seed data and serializes to disk."""
    X, y = create_representative_seed_dataset()
    model = get_default_model(n_estimators=10, max_depth=10, random_state=42)
    model.fit(X, y)

    model_path.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "model": model,
        "feature_columns": FEATURE_COLUMNS,
        "author": "M. Athallah Rafif Aldera",
        "algorithm": "RandomForestClassifier",
        "parameters": {"n_estimators": 10, "max_depth": 10}
    }
    joblib.dump(payload, model_path)
    return model


def load_trained_model(model_path: Path = DEFAULT_MODEL_PATH) -> Tuple[Any, Dict[str, Any]]:
    """Loads serialised model payload from disk, initializing if missing."""
    if not model_path.exists():
        train_and_save_model(model_path)

    payload = joblib.load(model_path)
    if isinstance(payload, dict):
        return payload["model"], payload
    return payload, {}
