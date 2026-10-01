import warnings
warnings.filterwarnings("ignore")
import re
import sqlite3
import pickle
import pandas as pd
from datetime import datetime
from urllib.parse import urlparse
from flask import Flask, request, jsonify, render_template, session, redirect, url_for
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
from nltk.tokenize import RegexpTokenizer
from nltk.stem.snowball import SnowballStemmer
from sklearn.feature_extraction.text import CountVectorizer

app = Flask(__name__)
app.secret_key = "secret_key_phishing_shield_2026"

safe_protocols = ["http", "https", "ftp", "sftp"]

suspicious_keywords = {
    "login", "secure", "account", "update", "verify", "signin",
    "bank", "confirm", "webscr", "confirm", "security", "auth",
    "signin", "payment", "credentials", "credential", "verify",
    "paypal", "ebay", "apple", "microsoft", "amazon"
}

DB_NAME = "results.db"


def init_db():
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS results (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            url TEXT,
            protocol TEXT,
            prediction TEXT,
            risk_level TEXT,
            risk_percentage INTEGER,
            suggestion1 TEXT,
            suggestion2 TEXT,
            timestamp TEXT
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE,
            email TEXT UNIQUE,
            password TEXT
        )
    """)

    conn.commit()
    conn.close()


init_db()

ml_model = None
vectorizer = None
url_lookup = {}


def normalize_url(url):
    if not url:
        return ""
    cleaned = str(url).strip().strip("'").strip('"').lower()
    cleaned = re.sub(r'^https?://', '', cleaned)
    cleaned = re.sub(r'^ftp://', '', cleaned)
    cleaned = cleaned.rstrip('/')
    return cleaned


trusted_domains = {
    "google.com", "youtube.com", "facebook.com", "instagram.com", "twitter.com", "x.com",
    "wikipedia.org", "apple.com", "amazon.com", "microsoft.com", "linkedin.com", "github.com",
    "reddit.com", "netflix.com", "openai.com", "stackoverflow.com", "paypal.com", "zoom.us",
    "medium.com", "gitlab.com", "cloudflare.com", "dropbox.com", "spotify.com", "twitch.tv",
    "microsoftonline.com", "office.com", "live.com", "yahoo.com", "bing.com", "whatsapp.com",
    "telegram.org", "quora.com", "adobe.com", "chase.com", "bankofamerica.com", "wellsfargo.com",
    "steampowered.com", "citi.com", "binance.com", "coinbase.com", "ebay.com", "walmart.com",
    "usps.com", "fedex.com", "dhl.com", "target.com", "nytimes.com", "cnn.com", "bbc.com"
}

target_brands = [
    "paypal", "google", "apple", "microsoft", "amazon", "netflix", "facebook", "bankofamerica",
    "chase", "wellsfargo", "binance", "coinbase", "meta", "instagram", "outlook", "office365",
    "linkedin", "twitter", "steam", "ebay", "walmart", "usps", "fedex", "dhl", "citi", "appleid"
]

high_risk_tlds = {
    "xyz", "top", "tk", "ml", "ga", "cf", "gq", "site", "online", "club", "work", "click",
    "monster", "zip", "mov", "fit", "rest", "cam", "icu", "buzz", "space", "tech", "live",
    "info", "best", "host", "pw", "website", "fun", "casa", "link", "skin", "download",
    "racing", "stream", "bid", "loan", "support", "help", "security", "center"
}

shortener_domains = {
    "bit.ly", "tinyurl.com", "t.co", "is.gd", "ow.ly", "buff.ly", "cutt.ly", "goo.gl",
    "rebrand.ly", "shorturl.at"
}


def get_hostname(url):
    if not url:
        return ""
    try:
        candidate = url if "://" in url else f"http://{url}"
        parsed = urlparse(candidate)
        hostname = (parsed.hostname or "").lower()
        return hostname.removeprefix("www.") if hasattr(hostname, "removeprefix") else (hostname[4:] if hostname.startswith("www.") else hostname)
    except Exception:
        return ""


def is_trusted_domain(hostname):
    if not hostname:
        return False
    for trusted in trusted_domains:
        if hostname == trusted or hostname.endswith("." + trusted):
            return True
    return False


def detect_brand_spoofing(hostname, url):
    if not hostname:
        return False, ""
    url_lower = url.lower()
    for brand in target_brands:
        if brand in hostname or brand in url_lower:
            if not is_trusted_domain(hostname):
                return True, brand
    return False, ""


def detect_typosquatting(hostname):
    if not hostname:
        return False
    typo_patterns = [
        r'g[0o]{2}gl[e3]', r'paypa[l11]', r'rnicrosof[t7]', r'am[a4]z[o0]n',
        r'netfl[i1]x', r'f[a4]ceb[o0]{2}k', r'b[a4]nk', r'appl[e3]id', r'g00gle'
    ]
    for pattern in typo_patterns:
        if re.search(pattern, hostname):
            if not is_trusted_domain(hostname):
                return True
    return False


def has_suspicious_keywords(url):
    if not url:
        return False
    url_lower = url.lower()
    return any(keyword in url_lower for keyword in suspicious_keywords)


def looks_like_obvious_phish(url):
    if not url:
        return False
    if "@" in url:
        return True
    lower_url = url.lower()
    if lower_url.startswith("hxxp://") or lower_url.startswith("hxxps://"):
        return True
    if url.count("//") > 1:
        return True
    parsed = urlparse(url if "://" in url else f"http://{url}")
    if parsed.hostname and re.fullmatch(r"\d+\.\d+\.\d+\.\d+", parsed.hostname):
        return True
    if "@@" in url:
        return True
    return False


def analyze_url(url, protocol="https"):
    clean_u = normalize_url(url)
    if clean_u.startswith("http://"):
        clean_u_np = clean_u[7:]
    elif clean_u.startswith("https://"):
        clean_u_np = clean_u[8:]
    else:
        clean_u_np = clean_u

    # 1. Dataset Ground-Truth Lookup
    matched_label = url_lookup.get(clean_u) or url_lookup.get(clean_u_np)
    if matched_label == 'bad':
        return "Harmful link", "High", 95, "Known phishing URL verified against reference dataset.", "Do not visit or enter credentials on this website."
    if matched_label == 'good':
        return "Good link", "Safe", 5, "Verified legitimate website in cybersecurity database.", "Safe to browse securely."

    hostname = get_hostname(url)
    candidate = url if "://" in url else f"http://{url}"
    parsed = urlparse(candidate)
    tld = hostname.split('.')[-1] if '.' in hostname else ""

    # 2. Known Trusted Real-World Domain Whitelist Check
    if is_trusted_domain(hostname) and not looks_like_obvious_phish(url):
        return "Good link", "Safe", 5, "Verified legitimate domain in trusted global cybersecurity whitelist.", "Safe to browse securely."

    # 3. Real-World Zero-Day Phishing Feature Extraction
    is_spoofed, brand_name = detect_brand_spoofing(hostname, url)
    is_typo = detect_typosquatting(hostname)
    is_high_risk_tld = tld in high_risk_tlds
    is_ip_host = bool(re.fullmatch(r"\d+\.\d+\.\d+\.\d+", hostname)) if hostname else False
    is_shortener = hostname in shortener_domains
    has_excessive_subdomains = hostname.count('.') >= 3
    has_excessive_hyphens = hostname.count('-') >= 2
    has_suspicious_symbol = "@" in url or url.count("//") > 1 or (parsed.port and parsed.port not in [80, 443])
    has_auth = has_suspicious_keywords(url)

    # 4. Scikit-Learn NLP Machine Learning Classifier Prediction
    bad_prob = 0.0
    pred = 0
    if ml_model and vectorizer:
        try:
            tokenizer = RegexpTokenizer(r'[A-Za-z]+')
            stemmer = SnowballStemmer("english")
            tokens = [stemmer.stem(w) for w in tokenizer.tokenize(url)]
            feat = vectorizer.transform([' '.join(tokens)])
            pred = ml_model.predict(feat)[0]
            probs = ml_model.predict_proba(feat)[0]
            bad_prob = probs[1] if len(probs) > 1 else (1.0 if pred == 1 else 0.0)
        except Exception:
            bad_prob = 0.5 if pred == 1 else 0.0

    # 5. Composite Real-World Risk Score Calculation (0 - 100)
    risk_score = int(bad_prob * 100)

    if is_spoofed or is_typo:
        risk_score += 45
    if is_ip_host:
        risk_score += 40
    if is_high_risk_tld:
        risk_score += 30
    if has_suspicious_symbol:
        risk_score += 25
    if has_excessive_hyphens and has_auth:
        risk_score += 20
    if has_auth and is_high_risk_tld:
        risk_score += 25
    if is_shortener:
        risk_score += 15

    # Clamp risk score
    risk_score = min(98, max(5, risk_score))

    # 6. Final Decision & Recommendation Generation
    if risk_score >= 45 or pred == 1 or is_spoofed or is_ip_host or is_typo or (is_high_risk_tld and has_auth):
        risk_level = "High" if risk_score >= 70 else "Medium"
        
        reasons = []
        if is_spoofed or is_typo:
            reasons.append(f"Impersonates official brand '{brand_name.capitalize() if brand_name else 'trusted domain'}' via spoofed domain name")
        if is_ip_host:
            reasons.append("Uses raw IP address host instead of domain name")
        if is_high_risk_tld:
            reasons.append(f"Uses high-risk TLD (.{tld}) commonly exploited for phishing")
        if has_excessive_hyphens:
            reasons.append("Contains suspicious hyphenated subdomain structure")
        if has_suspicious_symbol:
            reasons.append("Contains deceptive symbols or obfuscated path formatting")
        if not reasons:
            reasons.append("AI/ML model identified zero-day phishing patterns in URL structure")

        suggestion1 = f"Real-World Threat Engine Alert: {'; '.join(reasons)}."
        suggestion2 = "Avoid submitting credentials, passwords, or financial information on this website."
        
        return "Harmful link", risk_level, risk_score, suggestion1, suggestion2

    safe_score = max(5, 100 - risk_score)
    return "Good link", "Safe", safe_score, "AI/ML Real-World Engine indicates low risk and normal domain structure.", "Proceed with standard caution and verify the website address before entering sensitive data."


def load_ml_model_and_data():
    global ml_model, vectorizer, url_lookup
    try:
        df = pd.read_excel("url_data.xlsx")
        df.dropna(inplace=True)

        for _, row in df.iterrows():
            clean_u = str(row['URL']).strip().strip("'").strip('"').lower()
            if clean_u.startswith("http://"):
                clean_u_np = clean_u[7:]
            elif clean_u.startswith("https://"):
                clean_u_np = clean_u[8:]
            else:
                clean_u_np = clean_u
            label_val = str(row['Label']).strip().lower()
            url_lookup[clean_u] = label_val
            url_lookup[clean_u_np] = label_val

        tokenizer = RegexpTokenizer(r'[A-Za-z]+')
        stemmer = SnowballStemmer("english")
        vectorizer = CountVectorizer()

        text_tokenized = df.URL.map(lambda t: tokenizer.tokenize(str(t)))
        text_stemmed = text_tokenized.map(lambda t: [stemmer.stem(word) for word in t])
        text_sent = text_stemmed.map(lambda t: ' '.join(t))
        vectorizer.fit(text_sent)

        with open("model1.pkl", "rb") as f:
            ml_model = pickle.load(f)
        print("ML Model and url_data loaded successfully!")
    except Exception as e:
        print(f"Error loading ML model/data: {e}")


load_ml_model_and_data()


def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            if request.is_json:
                return jsonify({"error": "Authentication required."}), 401
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function


@app.route('/')
@login_required
def index():
    return render_template("index.html")


@app.route('/login', methods=['GET', 'POST'])
def login():
    if 'user_id' in session:
        return redirect(url_for('index'))

    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')

        conn = sqlite3.connect(DB_NAME)
        cursor = conn.cursor()
        cursor.execute("SELECT id, username, password FROM users WHERE LOWER(username) = LOWER(?) OR LOWER(email) = LOWER(?)", (username, username))
        user = cursor.fetchone()
        conn.close()

        if user and check_password_hash(user[2], password):
            session['user_id'] = user[0]
            session['username'] = user[1]
            return redirect(url_for('index'))
        else:
            return render_template("login.html", error="Invalid username or password.")

    return render_template("login.html")


@app.route('/register', methods=['GET', 'POST'])
def register():
    if 'user_id' in session:
        return redirect(url_for('index'))

    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        email = request.form.get('email', '').strip()
        password = request.form.get('password', '')

        if not username or not email or not password:
            return render_template("register.html", error="All fields are required.")

        conn = sqlite3.connect(DB_NAME)
        cursor = conn.cursor()
        cursor.execute("SELECT id FROM users WHERE LOWER(username) = LOWER(?) OR LOWER(email) = LOWER(?)", (username, email))
        existing_user = cursor.fetchone()

        if existing_user:
            conn.close()
            return render_template("register.html", error="Username or email already exists.")

        hashed_password = generate_password_hash(password)
        cursor.execute("INSERT INTO users (username, email, password) VALUES (?, ?, ?)", (username, email, hashed_password))
        user_id = cursor.lastrowid
        conn.commit()
        conn.close()

        session['user_id'] = user_id
        session['username'] = username
        return redirect(url_for('index'))

    return render_template("register.html")


@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))


@app.route('/about')
def about():
    return render_template("about.html")


@app.route('/contact')
def contact():
    return render_template("contact.html")


@app.route('/detect')
@login_required
def detect():
    return render_template("detect.html")


@app.route('/predict', methods=['POST'])
@login_required
def predict():
    try:
        url = request.form.get('url') or (request.json.get('url') if request.is_json else '')
        protocol = request.form.get('protocol') or (request.json.get('protocol') if request.is_json else 'https')

        if not url:
            if request.is_json:
                return jsonify({"error": "Website URL is required."}), 400
            return render_template("detect.html", error="Please enter a Website URL to analyze.")

        protocol = protocol.lower()

        risk_level = "None"
        risk_percentage = 0
        suggestion1 = ""
        suggestion2 = ""

        prediction, risk_level, risk_percentage, suggestion1, suggestion2 = analyze_url(url, protocol)

        # Proper formatted timestamp
        current_time = datetime.now().strftime("%d-%m-%Y %I:%M:%S %p")

        conn = sqlite3.connect(DB_NAME)
        cursor = conn.cursor()

        cursor.execute("""
            INSERT INTO results
            (url, protocol, prediction, risk_level,
             risk_percentage, suggestion1, suggestion2, timestamp)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            url,
            protocol,
            prediction,
            risk_level,
            risk_percentage,
            suggestion1,
            suggestion2,
            current_time
        ))

        conn.commit()
        conn.close()

        return render_template(
            "result.html",
            url=url,
            protocol=protocol,
            prediction=prediction,
            risk_level=risk_level,
            risk_percentage=risk_percentage,
            suggestion1=suggestion1,
            suggestion2=suggestion2
        )

    except Exception as e:
        if request.is_json:
            return jsonify({"error": str(e)}), 400
        return render_template("detect.html", error=f"Error analyzing URL: {str(e)}")


@app.route('/visualization')
@login_required
def visualization():
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()

    cursor.execute("""
        SELECT risk_level, risk_percentage
        FROM results
        ORDER BY id DESC
        LIMIT 10
    """)

    rows = cursor.fetchall()
    conn.close()

    levels = [r[0] for r in rows]
    percentages = [r[1] for r in rows]

    return render_template(
        "visualization.html",
        levels=levels,
        percentages=percentages
    )


@app.route('/previous-results')
@login_required
def previous_results():
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()

    cursor.execute("""
        SELECT id, url, protocol, prediction,
               risk_level, risk_percentage,
               suggestion1, suggestion2, timestamp
        FROM results
        ORDER BY id DESC
    """)

    rows = cursor.fetchall()
    conn.close()

    return render_template(
        "view_previous_result.html",
        results=rows
    )


if __name__ == "__main__":
    app.run(debug=True)
