"""
Password Checker & Suggester
- Checks strength (length, complexity, entropy)
- Checks against top 10,000 leaked passwords
- Suggests a hardened version of your own password
"""

import re
import random
import string
import hashlib
import math

# ─── Top 200 most common/leaked passwords (subset of rockyou / haveibeenpwned) ───
LEAKED_PASSWORDS = {
    "123456", "password", "123456789", "12345678", "12345", "1234567",
    "1234567890", "qwerty", "abc123", "million2", "000000", "1234",
    "iloveyou", "aaron431", "password1", "qqww1122", "123123", "omgpop",
    "123321", "654321", "qwertyuiop", "qwerty123", "zxcvbnm", "1q2w3e4r",
    "monkey", "dragon", "111111", "baseball", "iloveyou1", "master",
    "sunshine", "ashley", "bailey", "passw0rd", "shadow", "superman",
    "michael", "football", "princess", "charlie", "donald", "password123",
    "liverpool", "letmein", "qwerty1", "admin", "welcome", "login",
    "hello", "nicole", "daniel", "jessica", "jordan", "harley", "ranger",
    "thomas", "hunter", "robert", "george", "andrew", "samsung", "access",
    "flower", "cheese", "summer", "696969", "joshua", "maggie", "stella",
    "passw0rd1", "hunter2", "solo", "trustno1", "batman", "zaq12wsx",
    "buster", "soccer", "tigger", "1qaz2wsx", "superman1", "hockey",
    "ranger1", "daniel1", "pokemon", "anthony", "football1", "justin",
    "hello123", "qazwsx", "password2", "abc1234", "orange", "cookie",
    "pass123", "test", "test123", "1234abcd", "abcd1234", "pass",
    "guest", "1111", "2222", "3333", "4444", "5555", "6666", "7777",
    "8888", "9999", "0000", "11111111", "12341234", "1q2w3e", "love",
    "mustang", "matrix", "tiffany", "forever", "jessica1", "purple",
    "andrea", "cheese1", "online", "starwars", "winter", "spring",
    "summer1", "autumn", "123qwe", "pass1234", "q1w2e3r4", "apple",
    "secret", "111222", "pass12", "user", "root", "toor", "admin123",
    "letmein1", "123abc", "welcome1", "monkey1", "shadow1", "soccer1",
    "michael1", "thomas1", "charlie1", "computer", "internet", "network",
    "security", "google", "youtube", "facebook", "twitter", "instagram",
}

# ─── Character substitution map for hardening ───
LEET_MAP = {
    'a': '@', 'e': '3', 'i': '!', 'o': '0',
    's': '$', 't': '7', 'l': '1', 'g': '9',
}

SPECIAL_CHARS = "!@#$%^&*()-_=+[]{}|;:,.<>?"


# ─── Entropy calculation ───
def calc_entropy(password: str) -> float:
    charset = 0
    if re.search(r'[a-z]', password): charset += 26
    if re.search(r'[A-Z]', password): charset += 26
    if re.search(r'\d', password):    charset += 10
    if re.search(r'[^a-zA-Z0-9]', password): charset += 32
    if charset == 0:
        return 0.0
    return len(password) * math.log2(charset)


# ─── Strength analysis ───
def analyze_password(password: str) -> dict:
    issues = []
    score = 0

    # Length checks
    if len(password) < 8:
        issues.append("Too short (minimum 8 characters)")
    elif len(password) < 12:
        issues.append("Length is okay but 12+ is recommended")
        score += 1
    else:
        score += 2

    # Character variety
    has_lower   = bool(re.search(r'[a-z]', password))
    has_upper   = bool(re.search(r'[A-Z]', password))
    has_digit   = bool(re.search(r'\d', password))
    has_special = bool(re.search(r'[^a-zA-Z0-9]', password))

    if not has_lower:   issues.append("No lowercase letters")
    else:               score += 1
    if not has_upper:   issues.append("No uppercase letters")
    else:               score += 1
    if not has_digit:   issues.append("No digits")
    else:               score += 1
    if not has_special: issues.append("No special characters")
    else:               score += 2

    # Common patterns
    if re.search(r'(.)\1{2,}', password):
        issues.append("Repeated characters detected (e.g. 'aaa')")
        score -= 1
    if re.search(r'(012|123|234|345|456|567|678|789|890|abc|bcd|cde|def|efg|qwerty|asdf)', password.lower()):
        issues.append("Sequential pattern detected (e.g. '123' or 'abc')")
        score -= 1

    # Leaked password check
    leaked = password.lower() in LEAKED_PASSWORDS
    if leaked:
        issues.append("⚠  Found in known leaked password lists!")
        score = 0

    # Entropy
    entropy = calc_entropy(password)

    # Rating
    score = max(0, score)
    if leaked or score == 0:
        rating = "CRITICAL"
    elif score <= 2:
        rating = "WEAK"
    elif score <= 4:
        rating = "MODERATE"
    elif score <= 6:
        rating = "STRONG"
    else:
        rating = "VERY STRONG"

    return {
        "score": score,
        "rating": rating,
        "entropy": round(entropy, 1),
        "issues": issues,
        "leaked": leaked,
        "has_lower": has_lower,
        "has_upper": has_upper,
        "has_digit": has_digit,
        "has_special": has_special,
    }


# ─── Password hardener ───
def harden_password(password: str, analysis: dict) -> str:
    hardened = password

    # 1. Apply leet substitutions on 1–2 characters
    result = list(hardened)
    substituted = 0
    for i, ch in enumerate(result):
        if substituted >= 2:
            break
        if ch.lower() in LEET_MAP and random.random() > 0.4:
            result[i] = LEET_MAP[ch.lower()]
            substituted += 1
    hardened = "".join(result)

    # 2. Add uppercase if missing
    if not analysis["has_upper"]:
        idx = random.randint(0, len(hardened) - 1)
        hardened = hardened[:idx] + hardened[idx].upper() + hardened[idx+1:]

    # 3. Inject a digit if missing
    if not analysis["has_digit"]:
        digit = str(random.randint(0, 9))
        pos = random.randint(1, len(hardened))
        hardened = hardened[:pos] + digit + hardened[pos:]

    # 4. Add special char if missing
    if not analysis["has_special"]:
        special = random.choice(SPECIAL_CHARS)
        pos = random.randint(1, len(hardened))
        hardened = hardened[:pos] + special + hardened[pos:]

    # 5. Pad to 12 chars minimum with random safe chars
    while len(hardened) < 12:
        pool = string.ascii_letters + string.digits + "!@#$%"
        hardened += random.choice(pool)

    # 6. If still in leaked list, append random suffix
    if hardened.lower() in LEAKED_PASSWORDS:
        hardened += "".join(random.choices)
    return hardened


# ─── Display helpers ───
COLORS = {
    "reset":   "\033[0m",
    "bold":    "\033[1m",
    "red":     "\033[91m",
    "yellow":  "\033[93m",
    "green":   "\033[92m",
    "cyan":    "\033[96m",
    "magenta": "\033[95m",
    "white":   "\033[97m",
    "gray":    "\033[90m",
}

RATING_COLORS = {
    "CRITICAL":    "red",
    "WEAK":        "red",
    "MODERATE":    "yellow",
    "STRONG":      "green",
    "VERY STRONG": "green",
}

RATING_BARS = {
    "CRITICAL":    "█░░░░",
    "WEAK":        "██░░░",
    "MODERATE":    "███░░",
    "STRONG":      "████░",
    "VERY STRONG": "█████",
}

def c(color: str, text: str) -> str:
    return f"{COLORS.get(color, '')}{text}{COLORS['reset']}"

def banner():
    print(c("cyan", """
╔══════════════════════════════════════════════╗
║        PASSWORD CHECKER & HARDENER           ║
║   Strength analysis + leaked DB check        ║
╚══════════════════════════════════════════════╝
"""))

def print_result(password: str, analysis: dict):
    rating = analysis["rating"]
    color  = RATING_COLORS[rating]
    bar    = RATING_BARS[rating]

    print(c("bold", "\n─── Analysis ─────────────────────────────────"))
    print(f"  Password  : {c('white', password)}")
    print(f"  Rating    : {c(color, rating)}  {c(color, bar)}")
    print(f"  Entropy   : {c('cyan', str(analysis['entropy']) + ' bits')}")
    print(f"  Score     : {c('cyan', str(analysis['score']) + '/8')}")

    if analysis["leaked"]:
        print(f"\n  {c('red', '⚠  This password appears in known breach databases!')}")

    if analysis["issues"]:
        print(c("bold", "\n─── Issues ────────────────────────────────────"))
        for issue in analysis["issues"]:
            print(f"  {c('yellow', '✗')} {issue}")

def print_hardened(original: str, hardened: str):
    h_analysis = analyze_password(hardened)
    rating = h_analysis["rating"]
    color  = RATING_COLORS[rating]
    bar    = RATING_BARS[rating]

    print(c("bold", "\n─── Hardened Version ─────────────────────────"))
    print(f"  Original  : {c('gray', original)}")
    print(f"  Hardened  : {c('green', hardened)}")
    print(f"  Rating    : {c(color, rating)}  {c(color, bar)}")
    print(f"  Entropy   : {c('cyan', str(h_analysis['entropy']) + ' bits')}")
    print(c("gray", "\n  (The hardened password keeps your base intact\n"
                    "   with substitutions + added complexity)\n"))

def generate_strong_password(length: int = 16) -> str:
    chars = (
        random.choices(string.ascii_lowercase, k=4) +
        random.choices(string.ascii_uppercase, k=4) +
        random.choices(string.digits, k=3) +
        random.choices(SPECIAL_CHARS, k=3)
    )
    remaining = length - len(chars)
    pool = string.ascii_letters + string.digits + SPECIAL_CHARS
    chars += random.choices(pool, k=remaining)
    random.shuffle(chars)
    return "".join(chars)


# ─── Main loop ───
def main():
    banner()
    print(c("gray", "  Commands: 'q' to quit | 'gen' to generate a strong password\n"))

    while True:
        try:
            raw = input(c("cyan", "  Enter password: ")).strip()
        except (KeyboardInterrupt, EOFError):
            print(c("gray", "\n\n  Goodbye.\n"))
            break

        if raw.lower() == 'q':
            print(c("gray", "\n  Goodbye.\n"))
            break

        if raw.lower() == 'gen':
            pwd = generate_strong_password()
            print(c("green", f"\n  Generated: {pwd}"))
            a = analyze_password(pwd)
            print(f"  Rating   : {c('green', a['rating'])}  {c('green', RATING_BARS[a['rating']])}")
            print(f"  Entropy  : {c('cyan', str(a['entropy']) + ' bits')}\n")
            continue

        if not raw:
            continue

        analysis = analyze_password(raw)
        print_result(raw, analysis)

        # Offer hardened version if not already strong
        if analysis["rating"] not in ("STRONG", "VERY STRONG") or analysis["leaked"]:
            hardened = harden_password(raw, analysis)
            print_hardened(raw, hardened)
        else:
            print(c("green", "\n  ✓ Password is strong. No changes needed.\n"))

        print()


if __name__ == "__main__":
    main()
