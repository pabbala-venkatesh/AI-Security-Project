
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

SHORTENED_DOMAINS = [
    "bit.ly",
    "tinyurl.com",
    "t.co",
    "ow.ly",
    "is.gd",
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

    for url in urls:
        cleaned_url = url.lower().rstrip(".,!?;:")

        if cleaned_url.startswith("www."):
            domain = cleaned_url[4:].split("/")[0]
        else:
            domain = cleaned_url.split("://")[-1].split("/")[0]

        if domain in SHORTENED_DOMAINS:
            findings.append(
                f"Shortened URL detected: '{domain}'. "
                "Check the final destination carefully."
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

    shortened_count = sum(
        1
        for url in urls
        if (
            url.lower().rstrip(".,!?;:").startswith("https://")
            or url.lower().rstrip(".,!?;:").startswith("http://")
            or url.lower().rstrip(".,!?;:").startswith("www.")
        )
        and (
            url.lower().rstrip(".,!?;:").split("://")[-1].split("/")[0]
            in SHORTENED_DOMAINS
            or (
                url.lower().rstrip(".,!?;:").startswith("www.")
                and url.lower().rstrip(".,!?;:")[4:].split("/")[0]
                in SHORTENED_DOMAINS
            )
        )
    )

    score = min(
        100,
        phrase_count * 25 + len(urls) * 20 + shortened_count * 10,
    )

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
