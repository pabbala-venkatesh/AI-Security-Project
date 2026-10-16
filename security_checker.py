
import re

SUSPICIOUS_PHRASES = [
    "verify your account",
    "account suspended",
    "urgent action required",
    "click here",
    "confirm your password",
    "share your otp",
    "claim your prize",
]


def analyze_message(message):
    """Identify common phishing warning signs."""
    findings = []
    text = message.lower()

    for phrase in SUSPICIOUS_PHRASES:
        if phrase in text:
            findings.append(f"Suspicious phrase: '{phrase}'")

    urls = re.findall(
        r"https?://\S+|www\.\S+",
        message,
        re.IGNORECASE,
    )

    if urls:
        findings.append(
            f"Contains {len(urls)} link(s). Check them carefully."
        )

    return findings


def assess_risk(message):
    """Calculate a simple, rule-based risk estimate."""
    findings = analyze_message(message)
    text = message.lower()

    phrase_count = sum(
        1 for phrase in SUSPICIOUS_PHRASES
        if phrase in text
    )

    urls = re.findall(
        r"https?://\S+|www\.\S+",
        message,
        re.IGNORECASE,
    )

    score = min(100, phrase_count * 25 + len(urls) * 20)

    if score >= 50:
        level = "High"
    elif score >= 25:
        level = "Medium"
    else:
        level = "Low"

    return {
        "score": score,
        "level": level,
        "findings": findings,
    }
