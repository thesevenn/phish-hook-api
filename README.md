<p align="center"><img src="./docs/icon.svg" width="120" /></p>

<div align="center"><h1>Phishook - Phishing Email Detection</h1></div>

___
A Lightweight **Layered Sequential Approach** to phishing email detection.
Rule-based filters and Machine Learning techniques applied in hybrid manner to utilize their strengths in better predicting phishing attempts. The Detection system is a Proof of Concept based on my Research during Capstone Project Work on **Phishing Email Detection using Rule-based and ML Techniques**.

### Phishook Web - A User-Friendly Interface for Email Analysis

---

Built with React and TailwindCSS, the Phishook web client offers a streamlined UI for interacting with the detection API — no setup needed. Just upload an email file and get instant analysis with visual verdicts.

👉 Try it yourself at - 🔗 [**Phishook Web**](https://phishook.netlify.app/)

## 🚀 Features

- Parses `.eml` files and raw email text
- Rule-based detection (sender checks, URLs, language patterns)
- Lightweight ML models for content classification
- Returns a numeric threat score and categorized risk level (`Safe`, `Caution`, `Suspicious`, `Critical`)
- Confidence score provided alongside detection result
- Frontend interface: Clean UI for manual use — mobile-first, responsive, and requires no sign-up.
- Secure by design: Emails are processed locally or via internal endpoints; no data is shared externally.
- Quick analysis: Optimized for near-instantaneous analysis — typically under 80ms per detection.

## 📊 Metrics

### 🎯 Accuracy

- Overall system accuracy: 93.6% (_combined Rule Filters + ML inference_)
- Rule-based filter accuracy: 91.7% (_Assuming uncertain cases are treated as incorrect_)
- ML model accuracy:
  - Email classifier: 99.9% (_trained and tested on a dataset of 40,000 emails_)
  - URL classifier: 91.3% (_trained and tested on 11,000+ URLs_)

### ✅ Performance Metrics

- Average response time: ~600ms (_on 0.1 CPU Render free tier_)
- Worst-case response time: ~1 minute (_due to cold server starts_)
- Average analysis time (Rule + ML): 30ms
- Average ML inference time: 15ms (_Email + URL classifiers combined_)

> [!Note]
> Response time can vary depending on server cold starts and Render webservices tier limitations.

## 🪫 Limitations

- Web service is running on minimal resources limiting performance
- No WHOIS lookup is currently made to reduce response time
- Email attachments are not analyzed in current setting
- No Feedback loop to improve classification models
- No Database is used to create and store caches

## 🔭 Future Scope and Features

- Adding feedback loop to utilize uploaded emails into improving classification models
- Handling and analyzing attachments
- More robust and verbose Filters result
- Cached WHOIS lookup to add URL check but keep response time under limit.
- Adding endpoints for only Rule or ML based analysis

## Dependencies
- Top 5000 Domains parsed as brand name is used from [Majestic million dataset](https://majesticmillion.com)
- A snapshot of phishing URLs from [PhishTank](https://phishtank.com/phishing_urls.csv) containing 60,000+ URLs is used

## Screenshots

## System Architecture

## Installation and Setup

```bash
    git clone repo
    cd ./repo
    pip install -r requirements.txt
    uvicorn main:app
```
```python
import requests
rq = requests.Request('POST',"https://phishook.app.render.com")
response = rq.json()
```
> [!Note]
> If you are using PyCharm IDE for this project, avoid using `--reload` option instead choose a different port or simply use `uvicorn main:app` or use your own terminal

## Usage
You have two options to use the Detection system and try it out.
1. Clone the Repo and run locally
2. Use the official Phishook interface at [Phishook Web App](https://phishook.netlify.app/)

> [!Note]
> The API is not publicly available at this moment as it is just a Proof of Concept being supported by free Tier on Render.


## 📢 Disclaimer

This tool provides automated analysis based on known phishing patterns and lightweight models. It is a proof of concept developed for academic purposes and is not intended as a full-fledged or enterprise-grade security solution. While it can help flag suspicious emails, no detection system is perfect. Mistakes can occur. Always use your judgment and verify critical communications independently before engaging with any email content.

## 📝 License

This project is licensed under the **Creative Commons Attribution-NonCommercial 4.0 International (CC BY-NC 4.0)** license.

You're free to:

- Share — copy and redistribute the material in any medium or format
- Adapt — improve, transform, and build upon the material

**Under the following terms**:

- **Attribution** — You must give appropriate credit.
- **NonCommercial** — You may not use the material for commercial purposes.
- **No Brand Misuse** — The name “Phishook” may not be used to endorse or promote derived works.

📄 [Read full license here](https://creativecommons.org/licenses/by-nc/4.0/)