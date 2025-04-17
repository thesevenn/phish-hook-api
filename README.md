# PHISH HOOK
___
Layered sequential approach to detecting phishing emails.
Rule-based filters and Machine Learning techniques applied in hybrid manner to utilize their strengths in better predicting phishing attempts.

---

## Features

- Parses `.eml` files and raw email text
- Rule-based detection (sender checks, URLs, language patterns)
- Lightweight ML models for content classification
- Returns a numeric threat score and categorized risk level (`Safe`, `Caution`, `Suspicious`, `Critical`)
- Confidence score provided alongside detection result
- Frontend interface: Clean UI for manual use — mobile-first, responsive, and requires no sign-up.
- Secure by design: Emails are processed locally or via internal endpoints; no data is shared externally.
- Fast response time: Optimized for near-instantaneous analysis — typically under a 100ms per detection.

---

### Usage

The API is not publicly available without request. You can use the detection system on Phish Hook's internet facing interface at [PhishHook web app](https://placholder.interface.test).

---

## Disclaimer
Phish Hook was developed as an academic project. It is not intended for enterprise use. Emails submitted are used only for analysis and temporary evaluation to improve detection logic.