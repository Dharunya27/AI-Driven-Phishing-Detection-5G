"""
Streamlit Web Interface for Phishing URL Detection
Developed by M. Athallah Rafif Aldera
Sriwijaya University / Dinas KOMINFO Kota Prabumulih
"""

import streamlit as st
import pandas as pd
import json

from src.predictor import PhishingPredictor
from src.features import FEATURE_COLUMNS

# Page configuration
st.set_page_config(
    page_title="Phishing URL Guard | AI Detection System",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom CSS for polished aesthetic
st.markdown("""
<style>
    .metric-card-phish {
        background-color: #fee2e2;
        border-left: 6px solid #ef4444;
        padding: 16px;
        border-radius: 8px;
        margin-bottom: 15px;
    }
    .metric-card-safe {
        background-color: #dcfce7;
        border-left: 6px solid #22c55e;
        padding: 16px;
        border-radius: 8px;
        margin-bottom: 15px;
    }
    .metric-card-warn {
        background-color: #fef9c3;
        border-left: 6px solid #eab308;
        padding: 16px;
        border-radius: 8px;
        margin-bottom: 15px;
    }
</style>
""", unsafe_allow_html=True)


@st.cache_resource
def get_predictor():
    return PhishingPredictor()


predictor = get_predictor()

# Sidebar: System Metadata & Controls
with st.sidebar:
    st.image("https://img.icons8.com/fluency/96/shield.png", width=64)
    st.title("Phishing URL Guard")
    st.markdown("**Version 1.0.0** | Production Ready")
    st.markdown("---")
    
    st.markdown("### 📊 Research Benchmark")
    st.markdown("""
    - **Dataset**: 630,071 URLs (Filtered)
    - **Classifier**: Random Forest (`n_est=10`)
    - **Test Accuracy**: **89.0%**
    - **Training Accuracy**: 91.0%
    - **Test Precision**: 73.2%
    - **Org**: Dinas KOMINFO Kota Prabumulih
    """)
    st.markdown("---")
    
    st.markdown("### ⚙️ Inference Settings")
    threshold = st.slider(
        "Decision Threshold",
        min_value=0.1,
        max_value=0.9,
        value=0.5,
        step=0.05,
        help="Adjust cutoff probability for classifying a URL as Phishing."
    )
    
    st.markdown("---")
    st.markdown("Designed by **M. Athallah Rafif Aldera, S.Kom.**")
    st.markdown("[GitHub](https://github.com/aral3000) • [Thesis Repo](https://github.com/aral3000/cervical-cancer-stylegan2-densenet121)")

# Main Interface
st.title("🛡️ AI-Powered Phishing URL Detection System")
st.markdown("""
Real-time cybersecurity scanner identifying malicious links via **lexical feature extraction** 
and **Random Forest ensemble learning**. Built for public agency infrastructure and enterprise screening.
""")

tab1, tab2, tab3 = st.tabs(["Single URL Inspection", "Batch URL Processing", "Architecture & Features"])

with tab1:
    col1, col2 = st.columns([3, 1])
    with col1:
        sample_url_choice = st.selectbox(
            "Quick Demo Examples:",
            [
                "Custom URL (Enter below)",
                "https://prabumulihkota.go.id (Legitimate Government Portal)",
                "https://github.com/aral3000 (Legitimate GitHub Profile)",
                "http://192.168.1.105/secure-login-account-update/verify.php?token=9283749 (Malicious IP Phishing)",
                "http://paypal.com.account-verification-system.update-alert.xyz/signin (Deceptive Brand Spoofing)",
                "http://bca-klik-secure-banking.online-confirm-id.net/login.html?id=8392 (Banking Impersonation)"
            ]
        )

        default_val = ""
        if sample_url_choice != "Custom URL (Enter below)":
            default_val = sample_url_choice.split(" ")[0]

        target_url = st.text_input(
            "Enter Target URL for Analysis:",
            value=default_val,
            placeholder="e.g. http://secure-banking-portal-update.com/login"
        )
    
    with col2:
        st.write("")
        st.write("")
        analyze_btn = st.button("🚀 Analyze URL", type="primary", use_container_width=True)

    if analyze_btn and target_url.strip():
        with st.spinner("Extracting lexical features & running Random Forest inference..."):
            try:
                res = predictor.predict(target_url, threshold=threshold)
                
                # Top Result Banner
                if res["is_phishing"]:
                    st.markdown(f"""
                    <div class="metric-card-phish">
                        <h2 style="color: #b91c1c; margin: 0;">⚠️ THREAT DETECTED: PHISHING URL</h2>
                        <p style="font-size: 1.1em; color: #7f1d1d; margin: 5px 0 0 0;">
                            Phishing Probability: <strong>{res['phishing_probability'] * 100:.2f}%</strong> | 
                            Confidence: <strong>{res['confidence'] * 100:.2f}%</strong> | 
                            Latency: <strong>{res['latency_ms']} ms</strong>
                        </p>
                    </div>
                    """, unsafe_allow_html=True)
                else:
                    st.markdown(f"""
                    <div class="metric-card-safe">
                        <h2 style="color: #15803d; margin: 0;">✅ SAFE: LEGITIMATE URL</h2>
                        <p style="font-size: 1.1em; color: #14532d; margin: 5px 0 0 0;">
                            Legitimate Probability: <strong>{res['legitimate_probability'] * 100:.2f}%</strong> | 
                            Confidence: <strong>{res['confidence'] * 100:.2f}%</strong> | 
                            Latency: <strong>{res['latency_ms']} ms</strong>
                        </p>
                    </div>
                    """, unsafe_allow_html=True)

                col_res1, col_res2, col_res3 = st.columns(3)
                col_res1.metric("Prediction Verdict", res["prediction"])
                col_res2.metric("Phishing Probability", f"{res['phishing_probability'] * 100:.1f}%")
                col_res3.metric("Inference Latency", f"{res['latency_ms']} ms")

                st.progress(res["phishing_probability"])

                # Risk Factors
                if res["risk_factors"]:
                    st.warning("⚠️ **Suspicious Indicators Detected:**")
                    for factor in res["risk_factors"]:
                        st.write(f"- {factor}")
                else:
                    st.info("ℹ️ No suspicious heuristic anomalies triggered in lexical structure.")

                # Feature Breakdown
                st.markdown("### 🔍 Lexical Feature Inspection")
                feat_df = pd.DataFrame([res["features"]]).T
                feat_df.columns = ["Observed Value"]
                st.dataframe(feat_df, use_container_width=True)

                with st.expander("📦 Raw JSON Payload (API Equivalent)"):
                    st.code(json.dumps(res, indent=2), language="json")

            except Exception as e:
                st.error(f"Analysis error: {e}")

with tab2:
    st.subheader("Batch URL Inspection")
    batch_input = st.text_area(
        "Enter URLs to evaluate (one per line):",
        value="https://google.com\nhttp://192.168.1.1/login\nhttps://unsri.ac.id\nhttp://paypal-security-alert.update-center.xyz",
        height=150
    )
    if st.button("Evaluate Batch URLs", type="primary"):
        urls = [line.strip() for line in batch_input.split("\n") if line.strip()]
        if urls:
            with st.spinner(f"Evaluating {len(urls)} URLs..."):
                results = predictor.predict_batch(urls, threshold=threshold)
                summary_data = []
                for r in results:
                    summary_data.append({
                        "URL": r["url"],
                        "Verdict": r["prediction"],
                        "Phishing Probability": f"{r['phishing_probability'] * 100:.1f}%",
                        "Risk Level": r["risk_level"],
                        "Latency (ms)": r["latency_ms"]
                    })
                st.dataframe(pd.DataFrame(summary_data), use_container_width=True)

with tab3:
    st.subheader("System Architecture & Feature Taxonomy")
    st.markdown("""
    The detection system leverages 9 distinct lexical features extracted directly from raw URL strings without requiring live network requests or external web scrapers, ensuring ultra-low latency (<5ms) and safe operation:
    
    1. **NumDots**: Counts the frequency of dots. Subdomain nesting is heavily abused by phishing actors to mimic authentic domain structures.
    2. **UrlLength**: Total string length. Phishing URLs frequently contain long session identifiers and obfuscated redirection parameters.
    3. **NumDash**: Counts hyphens, common in lookalike spoofing (e.g. `paypal-secure-update.com`).
    4. **AtSymbol**: Detects user-info obfuscation (the `@` symbol discards preceding authority segments).
    5. **IpAddress**: Identifies raw IPv4 or IPv6 host designations, bypassing standard DNS domain registration.
    6. **HttpsInHostname**: Flags the string `https` embedded into the hostname or subdomains to mislead non-technical users.
    7. **PathLevel**: Measures directory hierarchy depth.
    8. **PathLength**: Character length of the resource path.
    9. **NumNumericChars**: Counts digit frequency in the URL.
    """)
