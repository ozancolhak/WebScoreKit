# Terminal Renk Kodları
RESET  = "\033[0m"
BOLD   = "\033[1m"
GREEN  = "\033[92m"
YELLOW = "\033[93m"
RED    = "\033[91m"
CYAN   = "\033[96m"
WHITE  = "\033[97m"
GRAY   = "\033[90m"

# Durum Fonksiyonları (Callable hale getiriyoruz)
def ok(msg):      print(f"{GREEN}[+]{RESET} {msg}")
def fail(msg):    print(f"{RED}[-]{RESET} {msg}")
def info(msg):    print(f"{CYAN}[*]{RESET} {msg}")
def warn(msg):    print(f"{YELLOW}[!]{RESET} {msg}")
def good(msg):    return f"{GREEN}{msg}{RESET}"
def bad(msg):     return f"{RED}{msg}{RESET}"
def section(msg): print(f"\n{BOLD}{WHITE}--- {msg} ---{RESET}")

def print_banner():
    print(r"""
  _       __     __  _____                    __ __ _ __ 
 | |     / /___ / / / ___/_________  ________/ //_//_// /_
 | | /| / / __ \ / /\__ \/ ___/ __ \/ ___/ _ \ ,<   / __/
 | |/ |/ /  __/_/ /___/ / /__/ /_/ / /  /  __/ /| | / /_  
 |__/|__/\___/(_)/____/\___/\____/_/   \___/_/ |_| \__/  
                                                          
    Automated Web Security Scoring Engine
    """)
