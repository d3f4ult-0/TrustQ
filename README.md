# 🛡️ TrustQ

### **Because "it has HTTPS" is not a cybersecurity strategy.**

**TrustQ** is an explainable digital trust analysis system that evaluates websites and produces a **Trust Quotient from 0–100**, along with the reasons behind that score.

Instead of simply screaming **"PHISHING!!!"** at the user and running away, TrustQ asks a more useful question:

> **"How trustworthy does this website actually appear, and why?"**

## 🚨 The Problem

The internet has approximately **seven billion ways to make a user regret clicking a link.**

A URL can be:

* Legitimate but poorly configured
* Secure but newly registered
* Old but missing important security headers
* Completely harmless but using questionable infrastructure
* Or, you know, an actual phishing site

Existing security tools often focus on detecting known threats.

TrustQ tries to provide something more understandable:

> **A score + evidence + context.**

Because apparently humans like knowing *why* something is suspicious.

# 🧠 How TrustQ Works

TrustQ analyzes a website using several independent categories rather than throwing random points into one enormous mathematical soup.

### Current scoring architecture

| Category                |  Weight |
| ----------------------- | ------: |
| 🛡️ Threat Intelligence | **35%** |
| 🌐 Domain Reputation    | **25%** |
| 🔐 Security Posture     | **25%** |
| 📡 Network Signals      | **15%** |

The final Trust Quotient is produced from these weighted category scores.

**The current scoring rules and point allocation are manually designed and calibrated.** TrustQ does **not currently use AI or machine learning to determine the score.**

This architecture keeps the scoring system transparent and makes it possible to refine the rules as more evidence and testing become available.

## 🔎 What TrustQ Checks

### 🛡️ Threat Intelligence

TrustQ checks external threat-intelligence sources such as:

* **Google Safe Browsing**
* **OpenPhish**

The goal is to distinguish between:

> **"No known threat detected"**

and

> **"We couldn't actually check."**

Because those are, surprisingly, not the same thing.

### 🌐 Domain Reputation

TrustQ examines domain-related signals including:

* RDAP registration information
* Domain age
* Registration availability
* Domain-related reputation signals

A very recently registered domain doesn't automatically mean **EVIL™**.

It simply means:

> *"Hmm. Interesting. Let's look at the other evidence."*

### 🔐 Security Posture

TrustQ checks security-related properties including:

* HTTPS accessibility
* SSL certificate validity
* SSL certificate expiry
* HSTS
* Content Security Policy
* CSP Report-Only
* X-Content-Type-Options
* X-Frame-Options

Security headers aren't magical trust certificates, but they provide useful information about how a website is configured.

### 📡 Network Signals

TrustQ also considers network-level observations such as:

* DNS resolution
* HTTPS accessibility
* HTTP fallback
* Protocol actually used
* Redirect behaviour
* Network accessibility

Because sometimes the website doesn't even bother to explain what it is doing.

TrustQ has to investigate.

# 🔗 URL Intelligence

TrustQ isn't limited to boring little:

```text
example.com
```

It can handle:

```text
https://example.com
```

and deeper URLs such as:

```text
https://youtube.com/BeastBoyShub/members
```

The system parses the URL, extracts the hostname, validates it, and analyzes the relevant domain/network signals.

Because apparently URLs evolved from:

```text
website.com
```

into:

```text
https://website.com/some/very/specific/thing?id=938472&source=why
```

# 🧮 Trust Quotient

The result is a score between:

```text
0 ─────────────────────────────── 100
```

The important part is that **TrustQ doesn't just give the number.**
It also exposes the underlying category scores and signals so the user can understand *why* the website received its rating.

### Example

```text
Trust Quotient
       92 / 100

Threat Intelligence     100
Domain Reputation        94
Security Posture         86
Network Signals          88
```

The goal is **explainability**, not just:

> "A mysterious algorithm says 92. Trust me bro."

# 🏗️ Architecture

```text
                 ┌─────────────────┐
                 │      User       │
                 └────────┬────────┘
                          │
                          ▼
                 ┌─────────────────┐
                 │ React Frontend  │
                 └────────┬────────┘
                          │
                     HTTP / JSON
                          │
                          ▼
                 ┌─────────────────┐
                 │ FastAPI Backend │
                 └────────┬────────┘
                          │
              ┌───────────┼───────────┐
              ▼           ▼           ▼
         URL Parsing   Analysis    Scoring
              │           │           │
              └───────────┼───────────┘
                          │
              ┌───────────┼───────────┐
              ▼           ▼           ▼
            RDAP     Threat Intel    DNS/SSL
              │           │           │
              └───────────┼───────────┘
                          ▼
                    Trust Quotient
                          │
                          ▼
                   JSON Response
                          │
                          ▼
                 Beautiful Frontend
```

The architecture is designed so the frontend doesn't need to understand the entire analysis engine.

It just receives the results and makes them look considerably less terrifying.

---

# 🛠️ Tech Stack

### Backend

* 🐍 Python
* ⚡ FastAPI
* `requests`
* RDAP
* DNS / SSL analysis
* Threat-intelligence APIs

### Frontend

* ⚛️ React / JavaScript
* HTML
* CSS
* Responsive UI
* Dark / Light mode

### Development

* Git
* GitHub
* Cloud deployment architecture

# 📂 Project Structure

The project is broadly organized around separate analysis responsibilities:

```text
TrustQ/
│
├── backend/
│   ├── main.py
│   ├── url_handler.py
│   ├── scoring.py
│   ├── rdap.py
│   └── ...
│
├── frontend/
│   ├── index.html
│   ├── script.js
│   ├── style.css
│   └── ...
│
└── README.md
```

The exact structure may evolve because software projects apparently enjoy moving furniture around while you're trying to debug them.

# 🚀 Running TrustQ

## 1. Clone the repository

```bash
git clone https://github.com/d3f4ult-0/TrustQ.git
cd TrustQ
```

## 2. Set up the backend

Create a virtual environment:

```bash
python -m venv .venv
```

Activate it:

### Linux/macOS

```bash
source .venv/bin/activate
```

### Windows

```powershell
.venv\Scripts\activate
```

Install dependencies:

```bash
pip install -r requirements.txt
```

## 3. Configure environment variables

API keys should **never** be hard-coded into the source code.

Use environment variables for services such as:

```text
GOOGLE_SAFE_BROWSING_API_KEY=(YOUR_KEY) [Create a separate .env file in your work folder.]
api_key = os.getenv("GOOGLE_SAFE_BROWSING_KEY") [Add this in your code]
```

and any other required credentials.

### Please don't commit `.env` files.

GitHub does not need your API keys.

Future-you especially does not need the email from Google saying:

> **"Your API key has been exposed."**

## 4. Start the FastAPI server

For example:

```bash
uvicorn main:app --reload
```

The API should then be available locally.

# 🌐 API Concept

TrustQ accepts a URL and sends it through the analysis pipeline.

Conceptually:

```http
POST /analyze
```

with something like:

```json
{
  "url": "https://example.com"
}
```

The backend performs the analysis and returns structured information containing the Trust Quotient, category scores, and supporting signals.

The frontend then transforms that JSON into something humans can actually read.

Because JSON is technically beautiful, but displaying raw JSON to a normal person is a cry for help.

# 🧪 Example Analysis

A successful analysis might conceptually look like:

```json
{
  "trust_quotient": 92,
  "threat_intelligence": 100,
  "domain_reputation": 94,
  "security_posture": 86,
  "network_signals": 88
}
```

The frontend can then turn that into:

```text
╭──────────────────────────────╮
│        TRUST QUOTIENT        │
│                              │
│          92 / 100            │
│                              │
│  🛡️ Threat Intel       100   │
│  🌐 Domain Reputation   94   │
│  🔐 Security Posture    86   │
│  📡 Network Signals     88   │
╰──────────────────────────────╯
```

# ⚠️ Important Limitations

TrustQ is **not a universal truth machine**.

A high score does not guarantee that a website is safe.
A low score does not necessarily mean that a website is malicious.

For example:

```text
Bad security configuration
        ≠
Malicious website
```

and:

```text
HTTPS
        ≠
Automatically trustworthy
```

TrustQ is an **evidence-based trust estimation system**, not a magical crystal ball with a REST API.

# 🧠 Why Explainability Matters

A security system saying:

> ❌ **DO NOT TRUST**

isn't particularly useful if the user has no idea why.

TrustQ aims to provide the reasoning behind its assessment.

For example:

```text
Trust Quotient: 41/100

Reasons:
⚠️ Domain registered very recently
⚠️ Threat intelligence source returned a warning
⚠️ Missing HSTS
⚠️ Weak security posture
✅ HTTPS certificate is valid
```

The user gets **context**, not merely a red button.

# 🤖 Future Plans

Potential future improvements include:

* [ ] Better URL/path intelligence
* [ ] Better redirect-chain analysis
* [ ] More network signals
* [ ] Improved threat-intelligence error handling
* [ ] Distinguish "not detected" from "couldn't check"
* [ ] Confidence scoring
* [ ] Further score calibration
* [ ] More threat-intelligence sources
* [ ] More polished responsive frontend
* [ ] Cloud backend deployment
* [ ] Browser extension
* [ ] Automated analysis improvements
* [ ] Machine-learning-assisted scoring

### 🤖 Possible future AI-assisted scoring

The **current TrustQ scoring system is manually designed**. A future version could potentially use machine learning to learn relationships between signals from a properly constructed and labelled dataset.

That would require substantial work, including:

* Collecting representative legitimate and malicious-domain data
* Defining reliable labels
* Engineering useful features
* Training and validating models
* Measuring false positives and false negatives
* Comparing model performance against the current rule-based system
* Maintaining explainability

The goal would not simply be to replace the current scoring system with a black box, but to determine whether a trained model can produce **more accurate and defensible trust estimates** while retaining meaningful explanations.

# 🔒 Security Philosophy

TrustQ follows a simple principle:

> **Don't ask users to blindly trust the security tool. Show them the evidence.**

The goal is not to replace existing security infrastructure.
It's to make its signals more understandable and actionable.

# 📜 Disclaimer

TrustQ is an experimental cybersecurity project.

It should **not** be treated as a definitive security verdict or as a replacement for professional security analysis.

Trust scores are estimates generated from available signals and may be affected by:

* Missing information
* API failures
* Incorrect or incomplete external data
* Temporary network conditions
* Website configuration changes
* False positives
* False negatives

In other words:

**The internet is complicated and TrustQ is not omniscient.**

Neither are humans.

The humans are arguably worse.

# 👨‍💻 Development Status

**Status: 🟢 Actively developed**

TrustQ started as an idea about making digital trust easier to understand and gradually evolved into an actual working analysis pipeline.

The project is still being refined, calibrated, debugged, redesigned, and occasionally held together with Python and questionable optimism.

But it works.

And that's a pretty good place to start.

## ⭐ If You Found This Interesting

Give the project a star.

It provides approximately **zero additional security**, but it makes the developer emotionally stronger.

```text
$ git add .
$ git commit -m "made website less suspicious"
$ git push
```

**TrustQ**

> *Because clicking "Continue Anyway" shouldn't be your entire cybersecurity strategy.* 🛡️

**AND FOR FUCK'S SAKE, DON'T USE THIS TO UNDERSTAND HUMANS. THEY HAVE MORE BUGS THAN FC25.**
