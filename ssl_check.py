"""
WebScoreKit - SSL/TLS Analiz Modülü
Kontroller: Sertifika geçerliliği, süre, zayıf cipher, protokol versiyonu, HSTS
"""

import ssl
import socket
import datetime
from utils.banner import ok, fail, info, warn, good, bad, section
from utils.score_engine import ScoreEngine

MAX_SCORE = 100

def check_ssl(domain: str, engine: ScoreEngine):
    section(f"SSL/TLS Analysis — {domain}")
    score    = 0
    findings = []
    port     = 443

    context = ssl.create_default_context()
    try:
        with socket.create_connection((domain, port), timeout=10) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert    = ssock.getpeercert()
                cipher  = ssock.cipher()
                version = ssock.version()

        # ── Protokol versiyonu ───────────────────────────────────────────
        proto_scores = {"TLSv1.3": 30, "TLSv1.2": 25, "TLSv1.1": 5, "TLSv1": 0, "SSLv3": 0}
        proto_score  = proto_scores.get(version, 0)
        score += proto_score
        if proto_score >= 25:
            good(f"Protocol: {version} ({proto_score}/30)")
        else:
            bad(f"Protocol: {version} — outdated! ({proto_score}/30)")
            findings.append({"module": "SSL", "severity": "HIGH",
                             "title": f"Weak TLS Protocol: {version}",
                             "detail": "Upgrade to TLS 1.2 or 1.3."})

        # ── Cipher suite ────────────────────────────────────────────────
        cipher_name = cipher[0] if cipher else "UNKNOWN"
        weak_ciphers = ["RC4", "DES", "3DES", "MD5", "NULL", "EXPORT", "anon"]
        if any(w in cipher_name for w in weak_ciphers):
            bad(f"Cipher: {cipher_name} — WEAK!")
            findings.append({"module": "SSL", "severity": "HIGH",
                             "title": f"Weak Cipher Suite: {cipher_name}",
                             "detail": "Disable weak ciphers in server config."})
        else:
            good(f"Cipher: {cipher_name}")
            score += 20

        # ── Sertifika geçerlilik süresi ──────────────────────────────────
        not_after_str = cert.get("notAfter", "")
        if not_after_str:
            not_after = datetime.datetime.strptime(not_after_str, "%b %d %H:%M:%S %Y %Z")
            days_left  = (not_after - datetime.datetime.utcnow()).days
            if days_left > 30:
                good(f"Certificate valid: {days_left} days remaining")
                score += 20
            elif days_left > 0:
                warn(f"Certificate expiring soon: {days_left} days!")
                score += 10
                findings.append({"module": "SSL", "severity": "MEDIUM",
                                 "title": f"Certificate Expiring in {days_left} Days",
                                 "detail": "Renew the SSL certificate before expiry."})
            else:
                bad("Certificate EXPIRED!")
                findings.append({"module": "SSL", "severity": "HIGH",
                                 "title": "SSL Certificate Expired",
                                 "detail": "Immediately renew the SSL certificate."})

        # ── CN / SAN kontrolü ────────────────────────────────────────────
        san = [v for t, v in cert.get("subjectAltName", []) if t == "DNS"]
        if domain in san or f"*.{'.'.join(domain.split('.')[1:])}" in san:
            good(f"SAN match confirmed: {domain}")
            score += 15
        else:
            bad(f"Domain not in SAN: {san}")
            findings.append({"module": "SSL", "severity": "HIGH",
                             "title": "Certificate Domain Mismatch",
                             "detail": f"Certificate SANs: {san}"})

        # ── Self-signed kontrol ──────────────────────────────────────────
        issuer  = dict(x[0] for x in cert.get("issuer", []))
        subject = dict(x[0] for x in cert.get("subject", []))
        if issuer.get("organizationName") == subject.get("organizationName"):
            bad("Self-signed certificate detected!")
            findings.append({"module": "SSL", "severity": "HIGH",
                             "title": "Self-Signed Certificate",
                             "detail": "Use a certificate from a trusted CA."})
        else:
            good(f"Issued by: {issuer.get('organizationName', 'Unknown CA')}")
            score += 15

    except ssl.SSLCertVerificationError as e:
        bad(f"SSL verification failed: {e}")
        findings.append({"module": "SSL", "severity": "HIGH",
                         "title": "SSL Certificate Verification Failed",
                         "detail": str(e)})
    except ConnectionRefusedError:
        bad("Port 443 closed — HTTPS not available!")
        findings.append({"module": "SSL", "severity": "HIGH",
                         "title": "HTTPS Not Available",
                         "detail": "Server does not accept connections on port 443."})
    except Exception as e:
        warn(f"SSL check error: {e}")

    score = min(score, MAX_SCORE)
    engine.add("ssl", score, MAX_SCORE, findings)
    info(f"SSL Score: {score}/{MAX_SCORE}")
    return score
