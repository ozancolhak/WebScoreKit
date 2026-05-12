"""
WebScoreKit - DNS Güvenlik Analiz Modülü
Kontroller: SPF, DMARC, DNSSEC, MX, CAA, Zone Transfer
"""

import socket
import subprocess
import re
from utils.banner import ok, fail, info, warn, good, bad, section
from utils.score_engine import ScoreEngine

MAX_SCORE = 100

def dns_query(domain: str, record_type: str) -> list:
    """Basit DNS sorgusu — dig veya nslookup olmadan socket ile."""
    try:
        import dns.resolver
        answers = dns.resolver.resolve(domain, record_type)
        return [str(r) for r in answers]
    except ImportError:
        # dnspython yoksa subprocess ile
        try:
            result = subprocess.run(
                ["nslookup", f"-type={record_type}", domain],
                capture_output=True, text=True, timeout=10
            )
            return [result.stdout]
        except:
            return []
    except Exception:
        return []

def check_dns(domain: str, engine: ScoreEngine):
    section(f"DNS Security — {domain}")
    score    = 0
    findings = []

    # ── A / AAAA kaydı ────────────────────────────────────────────────
    try:
        ipv4 = socket.gethostbyname(domain)
        good(f"A Record: {ipv4}")
        score += 5
    except:
        bad("A Record: Not resolved!")
        findings.append({"module": "DNS", "severity": "HIGH",
                         "title": "Domain Not Resolvable",
                         "detail": "Domain has no A record."})

    # ── SPF ────────────────────────────────────────────────────────────
    info("Checking SPF record...")
    txt_records = dns_query(domain, "TXT")
    spf_found   = False
    for r in txt_records:
        if "v=spf1" in r.lower():
            spf_found = True
            if "~all" in r:
                warn(f"SPF: {r[:80]} — softfail (~all), consider -all")
                score += 15
            elif "-all" in r:
                good(f"SPF: {r[:80]} — strict (-all)")
                score += 20
            else:
                warn(f"SPF: {r[:80]} — no explicit 'all' policy")
                score += 10
                findings.append({"module": "DNS", "severity": "MEDIUM",
                                 "title": "SPF Policy Too Permissive",
                                 "detail": "Add -all to enforce strict SPF policy."})
    if not spf_found:
        bad("SPF: No SPF record found!")
        findings.append({"module": "DNS", "severity": "HIGH",
                         "title": "Missing SPF Record",
                         "detail": "Add a TXT record: v=spf1 include:... -all"})

    # ── DMARC ──────────────────────────────────────────────────────────
    info("Checking DMARC record...")
    dmarc_records = dns_query(f"_dmarc.{domain}", "TXT")
    dmarc_found   = False
    for r in dmarc_records:
        if "v=dmarc1" in r.lower():
            dmarc_found = True
            if "p=reject" in r.lower():
                good(f"DMARC: p=reject — strong policy")
                score += 25
            elif "p=quarantine" in r.lower():
                warn(f"DMARC: p=quarantine — consider p=reject")
                score += 15
                findings.append({"module": "DNS", "severity": "LOW",
                                 "title": "DMARC Policy: quarantine (not reject)",
                                 "detail": "Upgrade DMARC policy to p=reject."})
            else:
                bad(f"DMARC: p=none — monitoring only, no protection!")
                score += 5
                findings.append({"module": "DNS", "severity": "MEDIUM",
                                 "title": "DMARC Policy Too Weak (p=none)",
                                 "detail": "Change DMARC policy to p=quarantine or p=reject."})
    if not dmarc_found:
        bad("DMARC: No DMARC record found!")
        findings.append({"module": "DNS", "severity": "HIGH",
                         "title": "Missing DMARC Record",
                         "detail": "Add TXT record at _dmarc.<domain>: v=DMARC1; p=reject; ..."})

    # ── CAA ────────────────────────────────────────────────────────────
    info("Checking CAA record...")
    caa_records = dns_query(domain, "CAA")
    if caa_records and any(r.strip() for r in caa_records):
        good(f"CAA: {caa_records[0][:60]}")
        score += 15
    else:
        warn("CAA: No CAA record — any CA can issue certificates!")
        findings.append({"module": "DNS", "severity": "MEDIUM",
                         "title": "Missing CAA Record",
                         "detail": "Add CAA record to restrict certificate issuance."})

    # ── Zone Transfer ────────────────────────────────────────────────────
    info("Checking zone transfer (AXFR)...")
    ns_records = dns_query(domain, "NS")
    for ns in ns_records[:2]:
        ns = ns.strip().rstrip(".")
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            sock.connect((ns, 53))
            sock.close()
            # Basit AXFR testi — gerçek AXFR DNS kütüphanesi gerektirir
            # Burada sadece port 53 TCP açıklığını raporlarız
            warn(f"NS {ns}: TCP port 53 open — AXFR may be possible, verify manually")
            score += 0
        except:
            good(f"NS {ns}: Zone transfer port not accessible")
            score += 10
            break

    # ── DNSSEC ─────────────────────────────────────────────────────────
    info("Checking DNSSEC...")
    ds_records = dns_query(domain, "DS")
    if ds_records and any(r.strip() for r in ds_records):
        good(f"DNSSEC: DS record found — enabled")
        score += 15
    else:
        warn("DNSSEC: No DS record found — DNSSEC not enabled")
        findings.append({"module": "DNS", "severity": "LOW",
                         "title": "DNSSEC Not Enabled",
                         "detail": "Enable DNSSEC to protect against DNS spoofing."})

    score = min(score, MAX_SCORE)
    engine.add("dns", score, MAX_SCORE, findings)
    info(f"DNS Score: {score}/{MAX_SCORE}")
    return score
