# 🔍 WebScoreKit

**Automated Web Security Scoring Engine**  
Scan any domain and get a **0–100 security score** across 6 categories — SSL, Headers, DNS, Ports, Leaks, and Reputation.

> ⚠️ For authorized systems and educational use only.

---

## 🎯 What It Does

Point WebScoreKit at any domain. It runs 6 parallel security checks and produces a weighted security score with a letter grade (A+ to F), detailed findings, and an optional JSON report.

```
══════════════════════════════════════════════════════
  TARGET : example.com
  SCORE  : 74/100  [██████████████░░░░░░]
  GRADE  : B
══════════════════════════════════════════════════════

  MODULE         SCORE      BAR
  ──────────────────────────────────────────────────
  SSL            23/25      [██████████]
  HEADERS        18/25      [███████░░░]
  DNS            14/20      [███████░░░]
  PORTS          13/15      [████████░░]
  LEAKS           4/10      [████░░░░░░]
  REPUTATION      2/5       [████░░░░░░]
```

---

## 🗂️ Modules

| Module | Weight | Checks |
|--------|--------|--------|
| **SSL/TLS** | 25% | Protocol version, cipher suite, cert expiry, SAN match, self-signed detection |
| **HTTP Headers** | 25% | CSP, HSTS, X-Frame-Options, X-Content-Type, Referrer-Policy, Permissions-Policy, CORS, info leakage |
| **DNS Security** | 20% | SPF, DMARC, DNSSEC, CAA, zone transfer test |
| **Port Scan** | 15% | 30+ ports, banner grabbing, risk classification (RDP, Redis, MongoDB, etc.) |
| **Info Leaks** | 10% | `.git`, `.env`, backup files, admin panels, Swagger, GraphQL endpoints |
| **Reputation** | 5% | 6 DNSBL blacklist checks + VirusTotal (optional) |

---

## 🚀 Installation

```bash
git clone https://github.com/ozancolhak/WebScoreKit
cd WebScoreKit
pip install -r requirements.txt
```

---

## 📖 Usage

```bash
# Basic scan
python3 webscorekit.py example.com

# Full scan with JSON report
python3 webscorekit.py example.com -o report.json

# Skip slow modules
python3 webscorekit.py example.com --skip ports reputation

# Run specific modules only
python3 webscorekit.py example.com --only ssl headers dns

# With VirusTotal API key
python3 webscorekit.py example.com --vt-key YOUR_API_KEY

# Scan from URL directly
python3 webscorekit.py https://example.com/some/path
```

---

## 📊 Score Breakdown

| Grade | Score | Meaning |
|-------|-------|---------|
| A+ | 90–100 | Excellent security posture |
| A  | 80–89  | Strong — minor improvements possible |
| B  | 70–79  | Good — some findings to address |
| C  | 60–69  | Moderate — several issues present |
| D  | 50–59  | Poor — significant vulnerabilities |
| F  | 0–49   | Critical — immediate action required |

---

## 📄 JSON Report

```json
{
  "domain": "example.com",
  "total": 74,
  "grade": "B",
  "modules": {
    "ssl":     { "score": 90, "max": 100 },
    "headers": { "score": 72, "max": 100 },
    "dns":     { "score": 70, "max": 100 }
  },
  "findings": [
    {
      "module":   "Headers",
      "severity": "HIGH",
      "title":    "Missing Header: Content-Security-Policy",
      "detail":   "Add a Content-Security-Policy header to prevent XSS."
    }
  ]
}
```

---

## 🏗️ Project Structure

```
WebScoreKit/
├── webscorekit.py              # Main CLI
├── requirements.txt
├── modules/
│   ├── ssl_check.py            # SSL/TLS analysis
│   ├── headers_check.py        # HTTP security headers
│   ├── dns_check.py            # DNS (SPF, DMARC, DNSSEC)
│   ├── ports_check.py          # Port scanner + banner grabbing
│   ├── leaks_check.py          # Information disclosure
│   └── reputation_check.py    # DNSBL + VirusTotal
└── utils/
    ├── score_engine.py         # Weighted scoring + report
    └── banner.py               # Terminal output helpers
```

---

## ⚙️ Requirements

- Python 3.8+
- `requests` library
- VirusTotal API key (free tier, optional)

---

## 📜 License

MIT License — Educational and authorized security assessment use only.
