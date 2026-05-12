"""
WebScoreKit - Port Tarama Modülü
Kontroller: Gereksiz açık portlar, tehlikeli servisler, banner grabbing
"""

import socket
import concurrent.futures
from utils.banner import ok, fail, info, warn, good, bad, section
from utils.score_engine import ScoreEngine

MAX_SCORE = 100

# Risk seviyeleri
RISKY_PORTS = {
    21:   ("FTP",         "HIGH",   "Unencrypted file transfer — use SFTP/FTPS"),
    23:   ("Telnet",      "HIGH",   "Unencrypted remote access — use SSH"),
    25:   ("SMTP",        "MEDIUM", "Open SMTP may allow spam relay"),
    53:   ("DNS TCP",     "LOW",    "DNS TCP open — check zone transfer"),
    80:   ("HTTP",        "LOW",    "HTTP open — ensure redirect to HTTPS"),
    110:  ("POP3",        "MEDIUM", "Unencrypted mail retrieval"),
    111:  ("RPC",         "HIGH",   "RPC portmapper exposed — potential RCE vector"),
    135:  ("MSRPC",       "HIGH",   "Windows RPC exposed publicly"),
    139:  ("NetBIOS",     "HIGH",   "NetBIOS exposed — Windows file sharing"),
    143:  ("IMAP",        "MEDIUM", "Unencrypted IMAP — use IMAPS"),
    389:  ("LDAP",        "HIGH",   "LDAP exposed — potential credential exposure"),
    443:  ("HTTPS",       "INFO",   "Expected — HTTPS running"),
    445:  ("SMB",         "HIGH",   "SMB exposed publicly — EternalBlue risk"),
    1433: ("MSSQL",       "HIGH",   "Database port exposed to internet"),
    1521: ("Oracle DB",   "HIGH",   "Database port exposed to internet"),
    2375: ("Docker",      "HIGH",   "Docker API exposed — full container takeover"),
    2376: ("Docker TLS",  "MEDIUM", "Docker TLS API exposed"),
    3306: ("MySQL",       "HIGH",   "Database port exposed to internet"),
    3389: ("RDP",         "HIGH",   "RDP exposed — brute-force / BlueKeep risk"),
    4369: ("RabbitMQ",    "MEDIUM", "Message broker exposed"),
    5432: ("PostgreSQL",  "HIGH",   "Database port exposed to internet"),
    5900: ("VNC",         "HIGH",   "VNC exposed — unencrypted remote desktop"),
    6379: ("Redis",       "HIGH",   "Redis exposed — unauthenticated access risk"),
    7001: ("WebLogic",    "HIGH",   "WebLogic exposed — multiple critical CVEs"),
    8080: ("HTTP-Alt",    "MEDIUM", "Alternate HTTP port — check for admin panels"),
    8443: ("HTTPS-Alt",   "LOW",    "Alternate HTTPS port open"),
    8888: ("Jupyter",     "HIGH",   "Jupyter Notebook exposed — RCE risk"),
    9200: ("Elasticsearch","HIGH",  "Elasticsearch exposed — unauthenticated access"),
    9300: ("ES Cluster",  "HIGH",   "Elasticsearch cluster port exposed"),
    27017:("MongoDB",     "HIGH",   "MongoDB exposed — unauthenticated access risk"),
    50000:("SAP",         "HIGH",   "SAP exposed — multiple critical vulnerabilities"),
}

EXPECTED_OPEN = {80, 443}

def grab_banner(ip: str, port: int, timeout: float = 2.0) -> str:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((ip, port))
        s.send(b"HEAD / HTTP/1.0\r\n\r\n")
        banner = s.recv(256).decode(errors="replace").strip()
        s.close()
        return banner[:100]
    except:
        return ""

def scan_port(ip: str, port: int, timeout: float = 1.5) -> bool:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        result = s.connect_ex((ip, port))
        s.close()
        return result == 0
    except:
        return False

def check_ports(domain: str, engine: ScoreEngine):
    section(f"Port Scan — {domain}")
    score    = MAX_SCORE
    findings = []

    try:
        ip = socket.gethostbyname(domain)
        info(f"Resolved: {domain} → {ip}")
    except:
        warn("Could not resolve domain for port scan.")
        engine.add("ports", 50, MAX_SCORE, findings)
        return 50

    ports_to_scan = list(RISKY_PORTS.keys())
    open_ports    = []

    info(f"Scanning {len(ports_to_scan)} ports with 50 threads...")
    with concurrent.futures.ThreadPoolExecutor(max_workers=50) as ex:
        future_map = {ex.submit(scan_port, ip, p): p for p in ports_to_scan}
        for future in concurrent.futures.as_completed(future_map):
            port = future_map[future]
            if future.result():
                open_ports.append(port)

    open_ports.sort()
    info(f"Open ports found: {len(open_ports)}")

    for port in open_ports:
        meta = RISKY_PORTS.get(port, (f"Port {port}", "LOW", "Unknown service"))
        svc, sev, detail = meta

        banner = grab_banner(ip, port)
        banner_str = f" | Banner: {banner[:60]}" if banner else ""

        if port in EXPECTED_OPEN:
            good(f"Port {port:<6} {svc:<15} [expected]{banner_str}")
        elif sev == "HIGH":
            bad(f"Port {port:<6} {svc:<15} [HIGH RISK]{banner_str}")
            score -= 15
            findings.append({"module": "Ports", "severity": "HIGH",
                             "title": f"High-Risk Port Open: {port} ({svc})",
                             "detail": detail})
        elif sev == "MEDIUM":
            warn(f"Port {port:<6} {svc:<15} [MEDIUM]{banner_str}")
            score -= 7
            findings.append({"module": "Ports", "severity": "MEDIUM",
                             "title": f"Risky Port Open: {port} ({svc})",
                             "detail": detail})
        else:
            info(f"Port {port:<6} {svc:<15} [LOW]{banner_str}")
            score -= 2
            findings.append({"module": "Ports", "severity": "LOW",
                             "title": f"Port Open: {port} ({svc})",
                             "detail": detail})

    if not open_ports:
        good("No risky ports found in scan range.")

    score = max(score, 0)
    engine.add("ports", score, MAX_SCORE, findings)
    info(f"Ports Score: {score}/{MAX_SCORE}")
    return score
