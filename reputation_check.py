"""
WebScoreKit - Reputation Kontrol Modülü
Kontroller: VirusTotal (API key opsiyonel), DNS blacklist (DNSBL) sorguları
"""

import requests
import socket
from utils.banner import ok, fail, info, warn, good, bad, section
from utils.score_engine import ScoreEngine

requests.packages.urllib3.disable_warnings()
MAX_SCORE = 100

DNSBL_SERVERS = [
    "zen.spamhaus.org",
    "bl.spamcop.net",
    "dnsbl.sorbs.net",
    "b.barracudacentral.org",
    "dnsbl-1.uceprotect.net",
    "ix.dnsbl.manitu.net",
]

def reverse_ip(ip: str) -> str:
    return ".".join(reversed(ip.split(".")))

def check_dnsbl(ip: str, dnsbl: str) -> bool:
    query = f"{reverse_ip(ip)}.{dnsbl}"
    try:
        socket.gethostbyname(query)
        return True  # Listed
    except socket.gaierror:
        return False  # Not listed

def check_virustotal(domain: str, api_key: str) -> dict:
    url = f"https://www.virustotal.com/api/v3/domains/{domain}"
    headers = {"x-apikey": api_key}
    try:
        r = requests.get(url, headers=headers, timeout=10)
        if r.status_code == 200:
            data = r.json()
            stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
            return stats
    except:
        pass
    return {}

def check_reputation(domain: str, engine: ScoreEngine, vt_api_key: str = None):
    section(f"Reputation Check — {domain}")
    score    = MAX_SCORE
    findings = []

    try:
        ip = socket.gethostbyname(domain)
        info(f"Checking reputation for IP: {ip}")
    except:
        warn("Could not resolve IP for reputation check.")
        engine.add("reputation", 50, MAX_SCORE, findings)
        return 50

    # ── DNSBL Sorguları ──────────────────────────────────────────────────
    info(f"Querying {len(DNSBL_SERVERS)} DNSBL servers...")
    blacklisted = []
    for dnsbl in DNSBL_SERVERS:
        listed = check_dnsbl(ip, dnsbl)
        if listed:
            bad(f"BLACKLISTED on {dnsbl}")
            blacklisted.append(dnsbl)
        else:
            good(f"Clean on {dnsbl}")

    if blacklisted:
        score -= 30 * len(blacklisted) // len(DNSBL_SERVERS)
        findings.append({"module": "Reputation", "severity": "HIGH",
                         "title": f"IP Blacklisted on {len(blacklisted)} DNSBL(s)",
                         "detail": f"Listed on: {', '.join(blacklisted)}"})
    else:
        good("Not listed on any DNSBL — clean reputation")

    # ── VirusTotal (API key varsa) ───────────────────────────────────────
    if vt_api_key:
        info("Querying VirusTotal...")
        stats = check_virustotal(domain, vt_api_key)
        if stats:
            malicious   = stats.get("malicious", 0)
            suspicious  = stats.get("suspicious", 0)
            harmless    = stats.get("harmless", 0)
            total       = sum(stats.values())
            info(f"VT Results — Malicious: {malicious} | Suspicious: {suspicious} | Harmless: {harmless} / {total}")
            if malicious > 0:
                bad(f"VirusTotal: {malicious} engines flagged as MALICIOUS!")
                score -= 40
                findings.append({"module": "Reputation", "severity": "HIGH",
                                 "title": f"VirusTotal: {malicious} Malicious Detections",
                                 "detail": f"Domain flagged by {malicious}/{total} AV engines."})
            elif suspicious > 0:
                warn(f"VirusTotal: {suspicious} engines flagged as suspicious")
                score -= 15
                findings.append({"module": "Reputation", "severity": "MEDIUM",
                                 "title": f"VirusTotal: {suspicious} Suspicious Detections",
                                 "detail": f"Domain flagged suspicious by {suspicious}/{total} engines."})
            else:
                good("VirusTotal: Clean — no detections")
        else:
            warn("VirusTotal query failed or no data.")
    else:
        info("VirusTotal skipped — use --vt-key <API_KEY> to enable")

    score = max(min(score, MAX_SCORE), 0)
    engine.add("reputation", score, MAX_SCORE, findings)
    info(f"Reputation Score: {score}/{MAX_SCORE}")
    return score
