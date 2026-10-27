# PhishGuard — Streamlit starter

A small Streamlit interface for your Random Forest model trained on 18 URL-derived
features from the PhiUSIIL Phishing URL Dataset.

## Files
- `app.py` — Streamlit UI and initial URL feature extractor.
- `requirements.txt` — dependencies.
- `phishguard_model.joblib` — download this from your Kaggle notebook; it is not included.

## Export the trained model from Kaggle

Run this in the notebook where `rf_domain` was trained:

```python
import joblib

model_artifact = {
    "model": rf_domain,
    "features": list(X_train_domain.columns),
    "label_mapping": {0: "Phishing", 1: "Legitimate"},
}
joblib.dump(model_artifact, "phishguard_model.joblib")
```

Download `phishguard_model.joblib` from the Kaggle output/files panel and place it
in the same directory as `app.py`.

## Run locally

```bash
python -m pip install -r requirements.txt
streamlit run app.py
```

## Critical limitation: validate feature definitions

The model expects these features, in this order:

1. URLLength
2. DomainLength
3. IsDomainIP
4. TLDLength
5. NoOfSubDomain
6. HasObfuscation
7. NoOfObfuscatedChar
8. ObfuscationRatio
9. NoOfLettersInURL
10. LetterRatioInURL
11. NoOfDegitsInURL
12. DegitRatioInURL
13. NoOfEqualsInURL
14. NoOfQMarkInURL
15. NoOfAmpersandInURL
16. NoOfOtherSpecialCharsInURL
17. SpacialCharRatioInURL
18. IsHTTPS

The dataset's exact feature-generation definitions were not included in the model
artifact. The app has transparent initial formulas, but some formulas—especially
obfuscation and special-character features—may not match the original dataset
implementation. Validate feature values against the original feature-generation
code or known dataset rows before treating predictions as reliable.

The model is an educational prototype, not a browser security tool. A URL can be
phishing even if it uses HTTPS. Never describe any prediction as a guarantee of
safety. Only load trusted joblib files.
