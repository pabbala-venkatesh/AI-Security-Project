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
    """Check a message for common phishing warning signs."""
    findings = []
    text = message.lower()

    for phrase in SUSPICIOUS_PHRASES:
        if phrase in text:
            findings.append(f"Suspicious phrase: '{phrase}'")

    # Detect links in the message.
    urls = re.findall(r"https?://\S+|www\.\S+", message, re.IGNORECASE)

    if urls:
        findings.append(f"Contains {len(urls)} link(s). Check them carefully.")

    return findings


def main():
    print("=" * 45)
    print("       AI SECURITY - MESSAGE CHECKER")
    print("=" * 45)

    message = input("\nEnter a test message: ")
    findings = analyze_message(message)

    if findings:
        print("\nWarning: Possible phishing indicators found!")
        for finding in findings:
            print("-", finding)
    else:
        print("\nNo listed warning signs detected.")

    print("\nNote: This tool cannot guarantee that a message is safe.")


if __name__ == "__main__":
    main()