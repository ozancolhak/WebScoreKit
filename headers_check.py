"""
WebScoreKit - HTTP Güvenlik Header Analiz Modülü
Kontroller: CSP, HSTS, X-Frame-Options, X-Content-Type, Referrer-Policy,
            Permissions-Policy, CORS, Server bilgi sızıntısı
"""

import requests
from utils.banner import ok, fail, info, warn, good, bad, section
from utils.score_engine import ScoreEngine

requests.packages.urllib3.disable_warnings()

HEADERS_CONFIG = {
    "Strict-Transport-Security": {
        "points":   15,
        "severity": "HIGH",
        "detail":   "Add: Strict-Transport-Security: max-age=31536000; includeSubDomains",
        "validate": lambda v: "max-age" in v and int(''.join(filter(str.isdigit, v.split("max-age=")[1].split(";")[0])) or 0) >= 31536000,
    },
    "Content-Security-Policy": {
        "points":   20,
        "severity": "HIGH",
        "detail":   "Add a Content-Security-Policy header to prevent XSS.",
        "validate": lambda v: len(v) > 10 and "unsafe-inline" not in v,
    },
    "X-Frame-Options": {
        "points":   10,
        "severity": "MEDIUM",
        "detail":   "Add: X-Frame-Options: DENY or SAMEORIGIN",
        "validate": lambda v: v.upper() in ("DENY", "SAMEORIGIN"),
    },
    "X-Content-Type-Options": {
        "points":   10,
        "severity": "MEDIUM",
        "detail":   "Add: X-Content-Type-Options: nosniff",
        "validate": lambda v: v.lower() == "nosniff",
    },
    "Referrer-Policy": {
        "points":   10,
        "severity": "LOW",
        "detail":   "Add: Referrer-Policy: strict-origin-when-cross-origin",
        "validate": lambda v: v in ("no-referrer", "strict-origin", "strict-origin-when-cross-origin"),
    },
    "Permissions-Policy": {
        "points":   10,
        "severity": "LOW",
        "detail":   "Add Permissions-Policy to restrict browser features.",
        "validate": lambda v: len(v) > 5,
    },
    "X-XSS-Protection": {
        "points":   5,
        "severity": "LOW",
        "detail":   "Add: X-XSS-Protection: 1; mode=block (legacy browsers)",
        "validate": lambda v: "1" in v,
    },
    "Cross-Origin-Opener-Policy": {
        "points":   10,
        "severity": "MEDIUM",
        "detail":   "Add: Cross-Origin-Opener-Policy: same-origin",
        "validate": lambda v: "same-origin" in v,
    },
    "Cross-Origin-Resource-Policy": {
        "points":   10,
        "severity": "MEDIUM",
        "detail":   "Add: Cross-Origin-Resource-Policy: same-origin",
        "validate": lambda v: "same-origin" in v or "same-site" in v,
    },
}

LEAK_HEADERS = ["Server", "X-Powered-By", "X-AspNet-Version", "X-Generator", "X-Drupal-Cache"]

def check_headers(domain: str, engine: ScoreEngine):
    section(f"HTTP Security Headers — {domain}")
    score    = 0
    findings = []
    max_pts  = sum(h["points"] for h in HEADERS_CONFIG.values())

    try:
        url = f"https://{domain}"
        r   = requests.get(url, timeout=10, verify=False, allow_redirects=True,
                           headers={"User-Agent": "Mozilla/5.0 (WebScoreKit)"})
        hdrs = {k.lower(): v for k, v in r.headers.items()}

        # ── Güvenlik header'ları ─────────────────────────────────────────
        for header, cfg in HEADERS_CONFIG.items():
            val = hdrs.get(header.lower())
            if val:
                try:
                    valid = cfg["validate"](val)
                except:
                    valid = True
                if valid:
                    good(f"{header}: {val[:70]}")
                    score += cfg["points"]
                else:
                    warn(f"{header}: Present but misconfigured → {val[:60]}")
                    score += cfg["points"] // 2
                    findings.append({"module": "Headers", "severity": cfg["severity"],
                                     "title": f"Misconfigured: {header}",
                                     "detail": cfg["detail"]})
            else:
                bad(f"{header}: MISSING")
                findings.append({"module": "Headers", "severity": cfg["severity"],
                                 "title": f"Missing Header: {header}",
                                 "detail": cfg["detail"]})

        # ── Bilgi sızıntısı header'ları ──────────────────────────────────
        print()
        info("Checking for information disclosure headers...")
        for leak in LEAK_HEADERS:
            val = hdrs.get(leak.lower())
            if val:
                bad(f"{leak}: {val} — technology disclosed!")
                findings.append({"module": "Headers", "severity": "MEDIUM",
                                 "title": f"Information Disclosure: {leak}",
                                 "detail": f"Remove or obfuscate the {leak} header."})
            else:
                good(f"{leak}: Not exposed")

        # ── CORS kontrol ────────────────────────────────────────────────
        acao = hdrs.get("access-control-allow-origin")
        if acao == "*":
            bad("CORS: Access-Control-Allow-Origin: * (wildcard!)")
            findings.append({"module": "Headers", "severity": "HIGH",
                             "title": "Wildcard CORS Policy",
                             "detail": "Restrict CORS to trusted origins only."})
        elif acao:
            warn(f"CORS: {acao}")
        else:
            good("CORS: Not exposed publicly")

        score = min(score, max_pts)

    except Exception as e:
        warn(f"Header check error: {e}")

    engine.add("headers", score, max_pts, findings)
    info(f"Headers Score: {score}/{max_pts}")
    return score
