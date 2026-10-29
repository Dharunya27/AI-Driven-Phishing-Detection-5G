"""
Inference & Risk Assessment Engine for Phishing URL Detection
Provides unified probability scoring, feature breakdown, and risk diagnostics.
"""

import time
from typing import Dict, Any, List, Optional
from pathlib import Path

from src.features import extract_features, to_feature_vector
from src.model import load_trained_model, DEFAULT_MODEL_PATH


class PhishingPredictor:
    def __init__(self, model_path: Optional[Path] = None):
        path = model_path or DEFAULT_MODEL_PATH
        self.model, self.metadata = load_trained_model(path)

    def analyze_risk_factors(self, features: Dict[str, Any]) -> List[str]:
        """Identifies suspicious heuristics to provide explainable risk indicators."""
        factors = []
        if features["IpAddress"] == 1:
            factors.append("IP address used directly as host instead of domain name")
        if features["HttpsInHostname"] == 1:
            factors.append("Deceptive 'https' token embedded within hostname")
        if features["NumDots"] >= 4:
            factors.append(f"Excessive dot count ({features['NumDots']}) indicating subdomain spoofing")
        if features["AtSymbol"] == 1:
            factors.append("'@' symbol detected in URL (user-info obfuscation technique)")
        if features["UrlLength"] > 80:
            factors.append(f"Abnormally long URL string ({features['UrlLength']} characters)")
        if features["NumDash"] >= 3:
            factors.append(f"Multiple hyphens ({features['NumDash']}) frequently used in lookalike domains")
        if features["NumNumericChars"] >= 10:
            factors.append(f"High concentration of numeric characters ({features['NumNumericChars']} digits)")
        if features["PathLevel"] >= 4:
            factors.append(f"Deep directory tree nesting (level {features['PathLevel']})")
        return factors

    def predict(self, url: str, threshold: float = 0.5) -> Dict[str, Any]:
        """
        Evaluates a single URL and returns detailed classification results.
        """
        t0 = time.perf_counter()
        features = extract_features(url)
        vector = [to_feature_vector(features)]

        # Predict probability
        probs = self.model.predict_proba(vector)[0]
        # index 1 represents phishing probability
        phish_prob = float(probs[1]) if len(probs) > 1 else float(probs[0])
        phish_prob = round(phish_prob, 4)

        is_phishing = phish_prob >= threshold
        confidence = phish_prob if is_phishing else round(1.0 - phish_prob, 4)

        if phish_prob < 0.35:
            risk_level = "Low Risk (Safe)"
        elif phish_prob < 0.65:
            risk_level = "Moderate Suspicion"
        else:
            risk_level = "High Risk (Phishing Threat)"

        factors = self.analyze_risk_factors(features)
        latency = (time.perf_counter() - t0) * 1000.0

        return {
            "url": url,
            "prediction": "Phishing" if is_phishing else "Legitimate",
            "is_phishing": bool(is_phishing),
            "phishing_probability": phish_prob,
            "legitimate_probability": round(1.0 - phish_prob, 4),
            "confidence": confidence,
            "risk_level": risk_level,
            "decision_threshold": float(threshold),
            "risk_factors": factors,
            "features": features,
            "latency_ms": round(latency, 2)
        }

    def predict_batch(self, urls: List[str], threshold: float = 0.5) -> List[Dict[str, Any]]:
        """Processes multiple URLs sequentially."""
        return [self.predict(u, threshold=threshold) for u in urls]
