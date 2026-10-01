# 🛡️ Real-Time AI/ML-Based Phishing Detection and Prevention System (PDPS)

> A hybrid cybersecurity web application leveraging Natural Language Processing (NLP), Machine Learning, heuristic threat intelligence, and zero-day attack vectors analysis to identify and prevent phishing attacks in real time.

---

## 📌 Project Overview

The **Real-Time AI/ML-Based Phishing Detection and Prevention System (PDPS)** is an end-to-end web security solution built with **Flask**, **Scikit-Learn**, **NLTK**, and **SQLite**. The system inspects incoming Web URLs, analyzes structural features, applies heuristic rule sets, matches against verified ground-truth datasets, and passes features into an NLP-trained machine learning model (`model1.pkl`) to evaluate the threat level of any given URL.

Users can create accounts, securely log in, scan URLs for potential phishing threats, view interactive visual analytics, and review complete historical audit logs of previous scans.

---

## ✨ Key Features

- **🧠 Multi-Layered Threat Detection Engine**:
  1. **Dataset Ground-Truth Matching**: Instant lookup against verified phishing and safe site records (`url_data.xlsx`).
  2. **Trusted Domain Whitelisting**: Automated verification for global authority domains (e.g., Google, Microsoft, Apple, Amazon, PayPal, major financial institutions).
  3. **Zero-Day & Heuristic Vector Extraction**:
     - **Brand Spoofing & Impersonation**: Detects fake domain names attempting to impersonate popular target brands.
     - **Typosquatting Detection**: Uses pattern matching to catch visual domain tricks (`g00gle`, `rnicrosof7`, `paypa1`).
     - **High-Risk TLD Filtering**: Identifies suspicious top-level domains frequently abused by attackers (`.xyz`, `.top`, `.zip`, `.online`, `.click`, `.host`).
     - **IP Host & Symbol Obfuscation**: Catches raw IP hosts, `@` symbol redirections, port anomalies, excessive hyphens, and excessive subdomains.
     - **Suspicious Keyword Identification**: Scans for high-risk authentication keywords (`login`, `bank`, `webscr`, `update`, `credential`).
  4. **NLP & Scikit-Learn ML Classifier**: Tokenizes and stems URL paths with `NLTK` (`RegexpTokenizer`, `SnowballStemmer`) and converts text to vectors via `CountVectorizer` for classification using pre-trained ML models (`model1.pkl`).
  5. **Composite Risk Scoring**: Calculates a dynamic risk percentage (0–100%) and categorizes links into **Safe**, **Medium**, or **High** risk levels with custom security advice.

- **🔒 Secure Authentication & User Management**:
  - User registration and login using strong password hashing (`Werkzeug`).
  - Session-based route protection for detector, charts, and history views.

- **📊 Dashboard & Visualization**:
  - Live interactive scanning web portal (`/detect`).
  - Interactive risk metric charts (`/visualization`) displaying scan risk levels and risk percentage trends.
  - Comprehensive historical scan records database (`/previous-results`).

---

## 🏗️ Project Architecture & Directory Structure

```
Real-Time AIML-Based Phishing Detection and Prevention System/
├── app.py                      # Core Flask application, ML pipeline & database routes
├── model1.pkl                  # Serialized Scikit-Learn ML model
├── url_data.xlsx               # Reference URL dataset for NLP training & verification
├── url_Train.ipynb             # Jupyter Notebook for ML model training & evaluation
├── results.db                  # SQLite database (Users & Scan Audit History)
├── app.log                     # Runtime application log output
├── templates/                  # HTML Templates (Jinja2)
│   ├── index.html              # Home page dashboard
│   ├── detect.html             # URL input scanner page
│   ├── result.html             # Scan result & threat breakdown page
│   ├── visualization.html      # Risk level analytics & charts page
│   ├── view_previous_result.html# Historical scan log table page
│   ├── login.html              # User login page
│   ├── register.html           # User registration page
│   ├── about.html              # System architecture & about page
│   └── contact.html            # Support & contact page
└── static/                     # CSS, JS, and image assets
```

---

## 🗄️ Database Schema (`results.db`)

### 1. `users` Table
| Column Name | Type | Description |
| :--- | :--- | :--- |
| `id` | INTEGER | Primary Key (Auto Increment) |
| `username` | TEXT | Unique username |
| `email` | TEXT | Unique email address |
| `password` | TEXT | Hashed password string |

### 2. `results` Table
| Column Name | Type | Description |
| :--- | :--- | :--- |
| `id` | INTEGER | Primary Key (Auto Increment) |
| `url` | TEXT | Target URL analyzed |
| `protocol` | TEXT | URL protocol (`http` / `https` / `ftp`) |
| `prediction` | TEXT | Result status (`"Good link"` or `"Harmful link"`) |
| `risk_level` | TEXT | Threat classification (`"Safe"`, `"Medium"`, `"High"`) |
| `risk_percentage`| INTEGER | Calculated composite risk score (0 to 100%) |
| `suggestion1` | TEXT | Specific threat detection reasoning |
| `suggestion2` | TEXT | Security mitigation recommendation |
| `timestamp` | TEXT | Execution timestamp (`DD-MM-YYYY HH:MM:SS AM/PM`) |

---

## 🚀 Getting Started & Installation

### Prerequisites
- **Python 3.8+**
- **pip** package installer

### Setup Steps

1. **Navigate to the Project Directory**:
   ```bash
   cd "PDPS/Batch-B6/Real-Time AIML-Based Phishing Detection and Prevention System"
   ```

2. **Create & Activate Virtual Environment**:
   ```bash
   # Windows (PowerShell)
   python -m venv .venv
   .\.venv\Scripts\Activate.ps1

   # Linux / macOS
   python3 -m venv .venv
   source .venv/bin/activate
   ```

3. **Install Dependencies**:
   ```bash
   pip install flask pandas scikit-learn nltk openpyxl werkzeug
   ```

4. **Run the Application**:
   ```bash
   python app.py
   ```

5. **Access the Web Portal**:
   Open your web browser and navigate to:
   ```
   http://127.0.0.1:5000
   ```

---

## 💻 Usage Guide

1. **Register / Sign In**: Register a new account or log in with your credentials.
2. **Scan URL**: Go to **Detect URL**, enter any web address (e.g., `http://login-paypal-security-update.xyz`), and select the protocol.
3. **Review Threat Analysis**: View the risk status, calculated risk percentage, threat breakdown, and security recommendations.
4. **Visual Analytics**: Navigate to **Visualization** to analyze recent scan metrics and threat distribution.
5. **Scan History**: View past analysis history on **Previous Results**.

---

## 🔬 Model Training & Customization

To retrain the machine learning model or update the reference dataset:
1. Open `url_Train.ipynb` in Jupyter Notebook or VS Code.
2. Update or append new URL records to `url_data.xlsx`.
3. Execute the notebook cells to rebuild the NLP feature extraction pipeline (`RegexpTokenizer`, `SnowballStemmer`, `CountVectorizer`).
4. Re-export the trained model to `model1.pkl`.

---

## 🛡️ Security & Mitigation Best Practices

- **Zero Trust**: Always verify website URLs before submitting credentials.
- **Protocol Inspection**: Beware of unencrypted (`http://`) links requesting authentication.
- **Domain Verification**: Ensure the host domain matches official corporate domain names rather than look-alike subdomains or hyphenated variations.

---

## 📄 License & Contact

This project is developed for cybersecurity research and phishing threat mitigation. For support or queries, reach out through the in-app Contact portal.
