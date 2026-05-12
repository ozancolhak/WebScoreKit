"""
WebScoreKit - Bilgi Sızıntısı Modülü
Kontroller: robots.txt, sitemap, .git, .env, backup files, admin panels
"""

import requests
from utils.banner import ok, fail, info, warn, good, bad, section
from utils.score_engine import ScoreEngine

requests.packages.urllib3.disable_warnings()
MAX_SCORE = 100

SENSITIVE_PATHS = {
    # Git / Source
    "/.git/HEAD":           ("HIGH",   "Git repository exposed — source code leak risk"),
    "/.git/config":         ("HIGH",   "Git config exposed"),
    "/.env":                ("HIGH",   ".env file exposed — credentials/API keys leak"),
    "/.env.backup":         ("HIGH",   ".env backup exposed"),
    "/.env.local":          ("HIGH",   ".env.local exposed"),

    # Backup / Config
    "/backup.zip":          ("HIGH",   "Backup archive publicly accessible"),
    "/backup.sql":          ("HIGH",   "Database backup exposed"),
    "/db.sql":              ("HIGH",   "Database dump exposed"),
    "/config.php":          ("HIGH",   "PHP config file exposed"),
    "/config.yml":          ("MEDIUM", "YAML config exposed"),
    "/config.json":         ("MEDIUM", "JSON config exposed"),
    "/wp-config.php":       ("HIGH",   "WordPress config exposed"),
    "/settings.py":         ("HIGH",   "Django settings exposed"),

    # Admin panels
    "/admin":               ("MEDIUM", "Admin panel accessible"),
    "/admin/login":         ("MEDIUM", "Admin login page exposed"),
    "/administrator":       ("MEDIUM", "Joomla admin panel"),
    "/wp-admin":            ("MEDIUM", "WordPress admin panel"),
    "/phpmyadmin":          ("HIGH",   "phpMyAdmin exposed publicly"),
    "/adminer.php":         ("HIGH",   "Adminer DB manager exposed"),

    # Logs / Debug
    "/debug":               ("HIGH",   "Debug endpoint exposed"),
    "/server-status":       ("MEDIUM", "Apache server-status exposed"),
    "/server-info":         ("MEDIUM", "Apache server-info exposed"),
    "/.well-known/security.txt": ("INFO", "security.txt present (good practice)"),

    # API docs
    "/swagger":             ("LOW",    "Swagger UI exposed"),
    "/swagger-ui.html":     ("LOW",    "Swagger UI exposed"),
    "/api/docs":            ("LOW",    "API docs exposed"),
    "/graphql":             ("MEDIUM", "GraphQL endpoint exposed — check introspection"),
    "/v1":                  ("LOW",    "API v1 endpoint exposed"),
    "/api":                 ("LOW",    "API endpoint exposed"),
}

ROBOTS_SENSITIVE = ["admin", "login", "backup", "config", "private", "secret", "internal", "staging"]
INTERESTING_STATUS = [200, 301, 302, 403]

def check_leaks(domain: str, engine: ScoreEngine):
    section(f"Information Leak Check — {domain}")
    score    = MAX_SCORE
    findings = []
    base_url = f"https://{domain}"
    headers  = {"User-Agent": "Mozilla/5.0 (WebScoreKit)"}

    # ── robots.txt analizi ──────────────────────────────────────────────
    info("Analyzing robots.txt...")
    try:
        r = requests.get(f"{base_url}/robots.txt", timeout=8, verify=False, headers=headers)
        if r.status_code == 200:
            good("robots.txt found")
            for line in r.text.lower().splitlines():
                if line.startswith("disallow:"):
                    path = line.replace("disallow:", "").strip()
                    for kw in ROBOTS_SENSITIVE:
                        if kw in path:
                            warn(f"Sensitive path in robots.txt: {path}")
                            findings.append({"module": "Leaks", "severity": "LOW",
                                             "title": f"Sensitive Path in robots.txt: {path}",
                                             "detail": "Attackers can use robots.txt to discover hidden paths."})
        else:
            info("robots.txt not found (optional)")
    except Exception as e:
        warn(f"robots.txt error: {e}")

    # ── Hassas dosya taraması ───────────────────────────────────────────
    info(f"Scanning {len(SENSITIVE_PATHS)} sensitive paths...")
    for path, (severity, detail) in SENSITIVE_PATHS.items():
        try:
            r = requests.get(f"{base_url}{path}", timeout=6, verify=False,
                             headers=headers, allow_redirects=False)

            if r.status_code == 200:
                if severity == "INFO":
                    good(f"{path} [{r.status_code}] — {detail}")
                    score += 2  # security.txt için bonus
                else:
                    bad(f"{path} [{r.status_code}] — {severity}")
                    findings.append({"module": "Leaks", "severity": severity,
                                     "title": f"Exposed: {path}",
                                     "detail": detail})
                    score -= 15 if severity == "HIGH" else 7 if severity == "MEDIUM" else 3

            elif r.status_code == 403:
                warn(f"{path} [403] — Forbidden (exists but protected)")
                findings.append({"module": "Leaks", "severity": "LOW",
                                 "title": f"Path Exists (403): {path}",
                                 "detail": "Path exists but access is restricted. Verify protection."})
                score -= 2
            else:
                pass  # 404 = clean

        except requests.exceptions.Timeout:
            pass
        except Exception:
            pass

    # ── .git dizin indeksi ──────────────────────────────────────────────
    try:
        r = requests.get(f"{base_url}/.git/", timeout=6, verify=False, headers=headers)
        if r.status_code == 200 and "HEAD" in r.text:
            bad("Git directory listing OPEN — full source code exposed!")
            findings.append({"module": "Leaks", "severity": "HIGH",
                             "title": "Open Git Directory (/.git/)",
                             "detail": "Entire source code may be downloadable. Restrict access immediately."})
            score -= 25
    except:
        pass

    score = max(min(score, MAX_SCORE), 0)
    engine.add("leaks", score, MAX_SCORE, findings)
    info(f"Leaks Score: {score}/{MAX_SCORE}")
    return score
