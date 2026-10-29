# Phishing URL Detection System

[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![Scikit-Learn](https://img.shields.io/badge/scikit--learn-1.3+-f89939.svg)](https://scikit-learn.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.100+-009688.svg)](https://fastapi.tiangolo.com/)
[![Streamlit](https://img.shields.io/badge/Streamlit-1.28+-ff4b4b.svg)](https://streamlit.io/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Bahasa Indonesia](https://img.shields.io/badge/Language-Bahasa%20Indonesia-green.svg)](README_ID.md)

> 📖 **Language**: **English** | [Versi Bahasa Indonesia](README_ID.md)

An end-to-end Machine Learning security system designed to detect and classify phishing URLs in real time using **lexical feature extraction** and **Random Forest ensemble learning**.

Developed based on field research and operational deployment during an engineering internship at **Dinas Komunikasi dan Informatika (KOMINFO) Kota Prabumulih** in collaboration with **Sriwijaya University**.

---

## 📌 Project Metadata

- **Author**: **M. Athallah Rafif Aldera, S.Kom.**
- **Institution**: Department of Computer Systems, Faculty of Computer Science, **Sriwijaya University**
- **Public Sector Partner**: **Dinas Komunikasi dan Informatika (KOMINFO) Kota Prabumulih**
- **Domain**: Applied Machine Learning, Cybersecurity, Threat Intelligence, Web Security
- **Core Technology**: Python, Scikit-Learn, Random Forest, FastAPI, Streamlit, Joblib

---

## 📄 Operational Background & Problem Statement

Phishing attacks remain one of the primary threat vectors targeting government agency portals and civic digital infrastructure. Traditional defense mechanisms rely heavily on static blacklists, which fail to intercept zero-day phishing domains and generate high maintenance overhead.

This project delivers a **network-independent, real-time URL risk assessment engine**. By analyzing 9 structural and lexical patterns embedded directly in the URL string, the system determines threat probability in less than 5 milliseconds without querying external DNS servers or exposing user browsing traffic to third parties.

---

## 📊 Empirical Benchmarks & Dataset Profile

The model was trained and evaluated on an extensive benchmark dataset comprising **662,591 raw records**. Following listwise deletion of 32,520 records (<5%) with missing labels, the final dataset contained **630,071 validated URLs**.

### Class Distribution (Imbalanced Real-World Regime)
- **Legitimate URLs**: 84.13%
- **Phishing URLs**: 15.87%

### Evaluation Metrics (80:20 Train:Test Split)

| Metric | Training Set | Testing Set (Unseen) | Research Insight |
| :--- | :---: | :---: | :--- |
| **Accuracy** | **91.0%** | **89.0%** | Consistent global discernment across benign and malicious domains |
| **Precision** | **81.2%** | **73.2%** | High true-positive fidelity; minimizing false alarms for public service users |
| **Recall** | 56.0% | 49.0% | Trade-off observed in highly imbalanced classes without artificial oversampling |
| **F1-Score** | 94.0% | 59.0% | Documented metric delta characteristic of real-world imbalanced cybersecurity datasets |

---

## 🔍 Lexical Feature Taxonomy

The system computes 9 lexical features directly from the raw URL string:

| # | Feature Name | Data Type | Description & Threat Heuristic |
| :-: | :--- | :---: | :--- |
| 1 | `NumDots` | Integer | Frequency of '.' characters. Heavy subdomain nesting often mimics official structures. |
| 2 | `UrlLength` | Integer | Total character count. Long strings frequently conceal encoded session identifiers. |
| 3 | `NumDash` | Integer | Frequency of '-' characters commonly used in brand spoofing (e.g. `bank-secure-login.com`). |
| 4 | `AtSymbol` | Binary | Presence of '@'. In standard URL syntax, everything preceding '@' is treated as user info. |
| 5 | `IpAddress` | Binary | Direct IPv4/IPv6 hostname usage, bypassing DNS domain registration. |
| 6 | `HttpsInHostname` | Binary | Deceptive insertion of the string 'https' inside domain/subdomain names. |
| 7 | `PathLevel` | Integer | Directory hierarchy depth (slash count in path). |
| 8 | `PathLength` | Integer | Character length of the URL path component. |
| 9 | `NumNumericChars` | Integer | Total digit count across the URL. |

---

## 🏗️ Architecture & Component Layout

```text
phishing-detection-system/
├── .gitignore                          # Excludes heavy CSV datasets and temporary caches
├── requirements.txt                    # Project dependency specification
├── README.md                           # Main English documentation
├── README_ID.md                        # Indonesian documentation
├── test_phishing.py                    # Assert-based verification suite
├── app.py                              # Interactive Streamlit Web UI
├── api.py                              # Production FastAPI REST service
└── src/
    ├── __init__.py
    ├── features.py                     # URL normalization and 9-feature lexical extractor
    ├── model.py                        # Random Forest training, evaluation, and joblib persistence
    └── predictor.py                    # Unified scoring engine with heuristic risk diagnostics
```

---

## 🚀 Quick Start Guide

### 1. Installation
```bash
git clone https://github.com/aral3000/phishing-detection-system.git
cd phishing-detection-system

# Create virtual environment
python -m venv venv
venv\Scripts\activate   # Windows
# source venv/bin/activate  # Linux/macOS

pip install -r requirements.txt
```

### 2. Run Verification Test Suite
```bash
python test_phishing.py
```

### 3. Launch Interactive Streamlit Web UI
```bash
streamlit run app.py
```
Open `http://localhost:8501` to test single URLs or batch link files with visual risk gauges.

### 4. Start FastAPI REST Service
```bash
uvicorn api:app --host 0.0.0.0 --port 8000 --reload
```
Interactive Swagger documentation is available at `http://localhost:8000/docs`.

#### Sample REST API Call
```bash
curl -X POST "http://localhost:8000/predict" \
     -H "Content-Type: application/json" \
     -d '{"url": "http://192.168.1.1/secure-update-login/verify.php", "threshold": 0.5}'
```

#### Sample Response
```json
{
  "url": "http://192.168.1.1/secure-update-login/verify.php",
  "prediction": "Phishing",
  "is_phishing": true,
  "phishing_probability": 0.9015,
  "legitimate_probability": 0.0985,
  "confidence": 0.9015,
  "risk_level": "High Risk (Phishing Threat)",
  "decision_threshold": 0.5,
  "risk_factors": [
    "IP address used directly as host instead of domain name"
  ],
  "latency_ms": 1.45
}
```

---

## 🔒 Security & Safe Execution Design

- **Zero Outbound HTTP Requests during Scan**: Analysis is performed strictly via string and URL path parsing. Scanning a malicious link cannot trigger drive-by downloads or inform the attacker.
- **Microsecond Latency**: Optimized string operations allow high-throughput screening in edge gateways and reverse proxies.

---

## 📜 Citation & Credits

- Author: **M. Athallah Rafif Aldera, S.Kom.**
- Academic Institution: **Universitas Sriwijaya**
- Field Agency: **Dinas KOMINFO Kota Prabumulih**
- License: Released under the [MIT License](LICENSE).
