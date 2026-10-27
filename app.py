import ipaddress
from urllib.parse import urlsplit, unquote

import joblib
import pandas as pd
import streamlit as st
import tldextract

st.set_page_config(page_title="PhishGuard | URL Scanner", page_icon="🛡️", layout="centered")

FEATURES = [
    "URLLength", "DomainLength", "IsDomainIP", "TLDLength", "NoOfSubDomain",
    "HasObfuscation", "NoOfObfuscatedChar", "ObfuscationRatio",
    "NoOfLettersInURL", "LetterRatioInURL", "NoOfDegitsInURL",
    "DegitRatioInURL", "NoOfEqualsInURL", "NoOfQMarkInURL",
    "NoOfAmpersandInURL", "NoOfOtherSpecialCharsInURL",
    "SpacialCharRatioInURL", "IsHTTPS",
]
MODEL_PATH = "phishguard_model.joblib"


def normalize_url(raw_url: str) -> str:
    value = raw_url.strip()
    if not value:
        raise ValueError("Enter a URL first.")
    if not urlsplit(value).scheme:
        value = "https://" + value
    parts = urlsplit(value)
    if parts.scheme.lower() not in {"http", "https"}:
        raise ValueError("Only HTTP and HTTPS URLs are supported.")
    if not parts.hostname:
        raise ValueError("That doesn't look like a valid URL. Include a domain name.")
    if any(ch.isspace() for ch in parts.hostname):
        raise ValueError("The domain name contains whitespace.")
    return value


def extract_url_features(raw_url: str) -> dict:
    """
    Initial URL feature extractor for the 18 model inputs.

    IMPORTANT: Verify these calculations against the exact PhiUSIIL feature
    definitions before treating predictions as reliable. In particular,
    obfuscation and special-character formulas may differ from the dataset's
    original feature-generation code.
    """
    url = normalize_url(raw_url)
    parts = urlsplit(url)
    host = (parts.hostname or "").lower().rstrip(".")
    decoded_url = unquote(url)

    try:
        ipaddress.ip_address(host.strip("[]"))
        is_ip = 1
    except ValueError:
        is_ip = 0

    # Uses the packaged suffix snapshot; disables network updates.
    extractor = tldextract.TLDExtract(suffix_list_urls=())
    ext = extractor(host)
    tld = ext.suffix or (host.rsplit(".", 1)[-1] if "." in host else "")
    subdomain_count = len([p for p in ext.subdomain.split(".") if p])

    # Initial heuristic: percent-encoding as an obfuscation signal.
    no_obfuscated_chars = url.count("%")
    has_obfuscation = int(no_obfuscated_chars > 0)
    obfuscation_ratio = no_obfuscated_chars / max(len(url), 1)

    letters = sum(ch.isalpha() for ch in url)
    digits = sum(ch.isdigit() for ch in url)
    equals_count = url.count("=")
    qmark_count = url.count("?")
    ampersand_count = url.count("&")

    # Initial character set; confirm it matches the dataset definition.
    other_special_chars = set("!#$%()*+,-./:;@[]_~'\\")
    other_special_count = sum(ch in other_special_chars for ch in url)
    length = len(url)

    return {
        "URLLength": length,
        "DomainLength": len(host),
        "IsDomainIP": is_ip,
        "TLDLength": len(tld),
        "NoOfSubDomain": subdomain_count,
        "HasObfuscation": has_obfuscation,
        "NoOfObfuscatedChar": no_obfuscated_chars,
        "ObfuscationRatio": obfuscation_ratio,
        "NoOfLettersInURL": letters,
        "LetterRatioInURL": letters / max(length, 1),
        "NoOfDegitsInURL": digits,
        "DegitRatioInURL": digits / max(length, 1),
        "NoOfEqualsInURL": equals_count,
        "NoOfQMarkInURL": qmark_count,
        "NoOfAmpersandInURL": ampersand_count,
        "NoOfOtherSpecialCharsInURL": other_special_count,
        "SpacialCharRatioInURL": other_special_count / max(length, 1),
        "IsHTTPS": int(parts.scheme.lower() == "https"),
    }


@st.cache_resource
def load_model_artifact():
    artifact = joblib.load(MODEL_PATH)
    if not isinstance(artifact, dict) or "model" not in artifact:
        raise ValueError("Model file must be a dictionary containing a 'model' key.")
    if list(artifact.get("features", FEATURES)) != FEATURES:
        raise ValueError("Saved model feature names/order do not match this app.")
    return artifact


st.title("🛡️ PhishGuard")
st.subheader("Machine-learning phishing URL detector")
st.write("Enter a website URL to estimate whether its URL structure resembles phishing or legitimate examples from the training dataset.")
st.info("Prototype warning: this is not a live reputation or malware scanner. A prediction cannot guarantee a website is safe. Do not enter passwords or sensitive information based only on this result.")

try:
    artifact = load_model_artifact()
except FileNotFoundError:
    st.error(f"Model file not found: `{MODEL_PATH}`. Place the downloaded model file next to `app.py`.")
    st.stop()
except Exception as exc:
    st.error(f"Could not load the model: {exc}")
    st.stop()

user_url = st.text_input("Website URL", placeholder="https://example.com/login")
scan_clicked = st.button("Scan URL", type="primary", use_container_width=True)

if scan_clicked:
    try:
        normalized = normalize_url(user_url)
        feature_dict = extract_url_features(normalized)
        input_df = pd.DataFrame([feature_dict], columns=FEATURES)
        model = artifact["model"]
        prediction = int(model.predict(input_df)[0])

        st.divider()
        st.subheader("Scan result")
        st.caption(f"Scanned URL: {normalized}")
        if prediction == 0:
            st.error("⚠️ Potential phishing URL")
            st.write("The model classified this URL as phishing-like. Avoid entering credentials or payment information unless you independently verify it.")
        else:
            st.success("✅ Likely legitimate URL")
            st.write("The model classified this URL as legitimate-like. This is not a guarantee of safety; phishing websites can use HTTPS.")

        if hasattr(model, "predict_proba"):
            probabilities = model.predict_proba(input_df)[0]
            class_probabilities = dict(zip(model.classes_, probabilities))
            c1, c2 = st.columns(2)
            c1.metric("Phishing-like", f"{float(class_probabilities.get(0, 0.0)):.1%}")
            c2.metric("Legitimate-like", f"{float(class_probabilities.get(1, 0.0)):.1%}")
            st.caption("These are model scores, not calibrated real-world probabilities.")

        with st.expander("View extracted features"):
            st.dataframe(pd.DataFrame({"Feature": list(feature_dict.keys()), "Value": list(feature_dict.values())}), use_container_width=True, hide_index=True)

    except ValueError as exc:
        st.warning(str(exc))
    except Exception as exc:
        st.error(f"Prediction failed: {exc}")

with st.expander("About this project"):
    st.markdown("""
    **Model:** Random Forest trained on selected URL-derived features from the PhiUSIIL Phishing URL Dataset.

    **Label mapping:** `0 = Phishing`, `1 = Legitimate`.

    **Evaluation note:** The reported score came from a domain-grouped split. It is not a guarantee of real-world performance.

    **Feature definitions:** The app's initial calculations—especially subdomains, obfuscation, and special-character counts—must be validated against the dataset's original feature-generation logic before presenting the detector as reliable.
    """)
