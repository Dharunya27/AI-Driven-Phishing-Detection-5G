#!/usr/bin/env python3
"""
Self-Contained Verification Suite for Phishing Detection System
Runs without external test frameworks via: python test_phishing.py
"""

import sys
from pathlib import Path

# Add project root to sys.path
PROJECT_ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(PROJECT_ROOT))

from src.features import extract_features, to_feature_vector, FEATURE_COLUMNS
from src.predictor import PhishingPredictor


def test_feature_extraction():
    """Verify 9-feature lexical extractor behavior on diverse URL variants."""
    print("[RUNNING] test_feature_extraction...")
    
    # 1. Normal domain
    f1 = extract_features("https://unsri.ac.id/portal/index.html")
    assert len(f1) == 9
    assert all(k in f1 for k in FEATURE_COLUMNS)
    assert f1["IpAddress"] == 0
    assert f1["HttpsInHostname"] == 0
    assert f1["NumDots"] >= 2
    assert f1["PathLevel"] == 2

    # 2. IP address URL
    f2 = extract_features("http://192.168.1.50:8080/secure/login")
    assert f2["IpAddress"] == 1
    assert f2["AtSymbol"] == 0

    # 3. Deceptive https in hostname
    f3 = extract_features("http://https-secure-paypal-update.com/login")
    assert f3["HttpsInHostname"] == 1

    # 4. At-symbol obfuscation
    f4 = extract_features("http://legitimate-site.com@phishing-target.net/verify")
    assert f4["AtSymbol"] == 1

    vec = to_feature_vector(f1)
    assert len(vec) == 9
    assert all(isinstance(v, float) for v in vec)
    print("  [PASS] Feature extraction matches specification.")


def test_predictor_inference():
    """Verify model initialization, probability calibration, and risk factors."""
    print("[RUNNING] test_predictor_inference...")
    predictor = PhishingPredictor()

    # Legitimate URL test
    res_legit = predictor.predict("https://www.google.com")
    assert "prediction" in res_legit
    assert "phishing_probability" in res_legit
    assert 0.0 <= res_legit["phishing_probability"] <= 1.0
    assert res_legit["is_phishing"] is False
    assert res_legit["prediction"] == "Legitimate"

    # Malicious IP URL test
    res_phish = predictor.predict("http://192.168.1.1/secure-update-login-account/verify.php?token=9283749")
    assert res_phish["is_phishing"] is True
    assert res_phish["prediction"] == "Phishing"
    assert len(res_phish["risk_factors"]) > 0
    assert any("IP address" in factor for factor in res_phish["risk_factors"])

    # Batch test
    batch_res = predictor.predict_batch([
        "https://unsri.ac.id",
        "http://paypal.com.account-update.xyz/login"
    ])
    assert len(batch_res) == 2
    assert batch_res[0]["url"] == "https://unsri.ac.id"
    print("  [PASS] Predictor inference and risk heuristics verified.")


def test_api_endpoints():
    """Verify FastAPI route contracts via FastAPI TestClient."""
    print("[RUNNING] test_api_endpoints...")
    from fastapi.testclient import TestClient
    from api import app

    client = TestClient(app)

    # Health check
    resp_health = client.get("/health")
    assert resp_health.status_code == 200
    assert resp_health.json()["status"] == "healthy"

    # Single URL predict
    resp_pred = client.post("/predict", json={"url": "https://prabumulihkota.go.id"})
    assert resp_pred.status_code == 200
    data = resp_pred.json()
    assert data["prediction"] in ["Legitimate", "Phishing"]
    assert "latency_ms" in data

    # Empty URL validation
    resp_bad = client.post("/predict", json={"url": ""})
    assert resp_bad.status_code == 400

    print("  [PASS] FastAPI REST endpoints passed contract tests.")


if __name__ == "__main__":
    print("\n" + "=" * 50)
    print("PHISHING DETECTION SYSTEM VERIFICATION SUITE")
    print("=" * 50)
    test_feature_extraction()
    test_predictor_inference()
    test_api_endpoints()
    print("=" * 50)
    print("ALL TESTS PASSED SUCCESSFULLY (100%)\n")
