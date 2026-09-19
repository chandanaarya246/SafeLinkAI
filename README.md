# 🔐 SafeLink AI

### Rule-Based URL Security Analyzer

SafeLink AI is a beginner-friendly cybersecurity project that analyzes website URLs and identifies potentially suspicious characteristics using rule-based security checks.

The project generates a risk score from **0 to 100** and provides explanations for the indicators detected in the URL.

> **Note:** The current version uses rule-based analysis. Machine Learning/AI features are planned for a future version.

---

## 🚀 Features

- 🔎 URL security analysis
- 📊 Risk score from 0–100
- 🟢 Low Risk detection
- 🟠 Medium Risk detection
- 🔴 High Risk detection
- 🔐 HTTPS detection
- 🌐 IP address detection
- 🔗 URL shortener detection
- ⚠️ Suspicious keyword detection
- 🧩 Subdomain analysis
- 🔢 Non-standard port detection
- 📝 Suspicious query parameter detection
- 📏 URL length analysis
- ❌ Invalid URL validation
- 📈 Visual risk meter
- 💻 Responsive cybersecurity dashboard

---

## 🛠️ Technologies Used

- Python
- Flask
- HTML
- CSS
- Regular Expressions
- URL Parsing

---

## 📊 Risk Analysis

SafeLink AI checks several characteristics of a URL.

Examples include:

| Security Indicator | Description |
|---|---|
| HTTPS | Checks whether the website uses HTTPS |
| IP Address | Detects URLs using an IP address instead of a domain |
| URL Length | Identifies unusually long URLs |
| Suspicious Keywords | Checks for words such as login or verify |
| Subdomains | Checks for unusually large numbers of subdomains |
| URL Shorteners | Detects common URL shortening services |
| Special Characters | Checks for unusual URL patterns |
| Ports | Detects non-standard ports |
| Query Parameters | Checks for suspicious parameter names |

The final score is calculated using the current rule-based scoring system.

---

## 💻 How to Run

### 1. Clone the repository

```bash
git clone https://github.com/chandanaarya246/SafeLinkAI.git