"""
WebScoreKit - Merkezi Skorlama Motoru
Her modülden puan toplar, ağırlıklı ortalama hesaplar, rapor üretir.
"""

from utils.banner import BOLD, RESET, GREEN, YELLOW, RED, CYAN, WHITE, GRAY

WEIGHTS = {
    "ssl":        25,   # SSL/TLS
    "headers":    25,   # HTTP Security Headers
    "dns":        20,   # DNS (SPF, DMARC, DNSSEC)
    "ports":      15,   # Açık portlar
    "leaks":      10,   # Bilgi sızıntısı
    "reputation":  5,   # Dış kaynak reputation
}

class ScoreEngine:
    def __init__(self, domain: str):
        self.domain   = domain
        self.scores   = {}   # module -> (score, max, findings)
        self.findings = []

    def add(self, module: str, score: int, max_score: int, findings: list):
        self.scores[module] = {"score": score, "max": max_score, "findings": findings}
        self.findings.extend(findings)

    def total(self) -> int:
        total_weighted = 0
        for module, weight in WEIGHTS.items():
            if module in self.scores:
                s = self.scores[module]
                pct = s["score"] / s["max"] if s["max"] > 0 else 0
                total_weighted += pct * weight
        return int(total_weighted)

    def grade(self, score: int) -> tuple:
        if score >= 90: return "A+", GREEN
        if score >= 80: return "A",  GREEN
        if score >= 70: return "B",  CYAN
        if score >= 60: return "C",  YELLOW
        if score >= 50: return "D",  YELLOW
        return "F", RED

    def print_report(self):
        total = self.total()
        grade, color = self.grade(total)
        bar_filled = int(total / 5)
        bar = "█" * bar_filled + "░" * (20 - bar_filled)

        print(f"\n{'═'*58}")
        print(f"  TARGET : {WHITE}{BOLD}{self.domain}{RESET}")
        print(f"  SCORE  : {color}{BOLD}{total}/100{RESET}  [{bar}]")
        print(f"  GRADE  : {color}{BOLD}{grade}{RESET}")
        print(f"{'═'*58}")

        print(f"\n  {'MODULE':<14} {'SCORE':<10} {'BAR'}")
        print(f"  {'─'*50}")
        for module, weight in WEIGHTS.items():
            if module not in self.scores:
                continue
            s     = self.scores[module]
            pct   = s["score"] / s["max"] if s["max"] > 0 else 0
            pts   = int(pct * weight)
            mini  = "█" * int(pct * 10) + "░" * (10 - int(pct * 10))
            c     = GREEN if pct >= 0.8 else YELLOW if pct >= 0.5 else RED
            print(f"  {module.upper():<14} {c}{pts}/{weight}{RESET}      [{mini}]")

        print(f"\n  {'─'*50}")
        if self.findings:
            print(f"  {BOLD}FINDINGS ({len(self.findings)}){RESET}")
            for f in self.findings:
                icon = "✗" if f["severity"] == "HIGH" else "!" if f["severity"] == "MEDIUM" else "·"
                c    = RED if f["severity"] == "HIGH" else YELLOW if f["severity"] == "MEDIUM" else GRAY
                print(f"  {c}{icon}{RESET} [{f['module']}] {f['title']}")
                if f.get("detail"):
                    print(f"    {GRAY}{f['detail']}{RESET}")
        else:
            print(f"  {GREEN}No significant findings.{RESET}")
        print()

    def to_dict(self) -> dict:
        return {
            "domain":   self.domain,
            "total":    self.total(),
            "grade":    self.grade(self.total())[0],
            "modules":  self.scores,
            "findings": self.findings,
        }
