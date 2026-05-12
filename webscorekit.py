#!/usr/bin/env python3
"""
WebScoreKit - Automated Web Security Scoring Engine
Author: Ozan İsmail Çolhak
"""

import argparse
import json
import sys
from utils.banner import print_banner
from utils.score_engine import ScoreEngine
from modules.ssl_check        import check_ssl
from modules.headers_check    import check_headers
from modules.dns_check        import check_dns
from modules.ports_check      import check_ports
from modules.leaks_check      import check_leaks
from modules.reputation_check import check_reputation

def parse_domain(target: str) -> str:
    target = target.strip()
    for prefix in ("https://", "http://"):
        if target.startswith(prefix):
            target = target[len(prefix):]
    return target.split("/")[0]

def main():
    print_banner()

    parser = argparse.ArgumentParser(
        description="WebScoreKit — Automated Web Security Scoring Engine",
        formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument("target",
        help="Domain or URL to scan (e.g. example.com or https://example.com)")
    parser.add_argument("--skip", nargs="+",
        choices=["ssl", "headers", "dns", "ports", "leaks", "reputation"],
        default=[],
        help="Skip specific modules")
    parser.add_argument("--only", nargs="+",
        choices=["ssl", "headers", "dns", "ports", "leaks", "reputation"],
        help="Run only specified modules")
    parser.add_argument("--vt-key",
        help="VirusTotal API key for reputation check")
    parser.add_argument("-o", "--output",
        help="Save full report as JSON (e.g. report.json)")
    parser.add_argument("--threads", type=int, default=50,
        help="Port scan threads (default: 50)")

    args   = parser.parse_args()
    domain = parse_domain(args.target)

    print(f"  Target  : \033[1m{domain}\033[0m")
    print(f"  Modules : ssl · headers · dns · ports · leaks · reputation\n")

    engine  = ScoreEngine(domain)
    modules = {
        "ssl":        lambda: check_ssl(domain, engine),
        "headers":    lambda: check_headers(domain, engine),
        "dns":        lambda: check_dns(domain, engine),
        "ports":      lambda: check_ports(domain, engine),
        "leaks":      lambda: check_leaks(domain, engine),
        "reputation": lambda: check_reputation(domain, engine, args.vt_key),
    }

    run_modules = args.only if args.only else list(modules.keys())
    run_modules = [m for m in run_modules if m not in args.skip]

    for mod in run_modules:
        try:
            modules[mod]()
        except KeyboardInterrupt:
            print("\n  Interrupted.")
            break
        except Exception as e:
            print(f"  [!] Module {mod} error: {e}")

    engine.print_report()

    if args.output:
        with open(args.output, "w") as f:
            json.dump(engine.to_dict(), f, indent=2, ensure_ascii=False)
        print(f"  Report saved → {args.output}\n")

if __name__ == "__main__":
    main()
