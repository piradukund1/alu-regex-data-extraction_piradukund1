#!/usr/bin/env python3

import json
import re
from pathlib import Path


INPUT_FILE = Path(__file__).parent.parent / "input" / "raw-text.txt"
OUTPUT_FILE = Path(__file__).parent.parent / "output" / "sample-output.json"


# this is Email pattern part, it requires a valid local part, @ symbol, domain and top-level domain.
EMAIL_PATTERN = re.compile(
    r"\b[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@"
    r"[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+\b"
)


# this is credit-card pattern session it Supports common  13-19 digit card numbers separated by spaces or hyphens.
CARD_PATTERN = re.compile(
    r"\b(?:\d[ -]?){13,18}\d\b"
)


# this is URL pattern part this Matches HTTP and HTTPS URLs.
URL_PATTERN = re.compile(
    r"https?://[A-Za-z0-9.-]+"
    r"(?:/[A-Za-z0-9._~:/?#\[\]@!$&'()*+,;=%-]*)?"
)


# this is Phone pattern which Supports common Rwandan phone formats.
PHONE_PATTERN = re.compile(
    r"(?<!\d)(?:\+250[\s-]?\d{3}[\s-]?\d{3}[\s-]?\d{3}"
    r"|0\d{9})(?!\d)"
)

# this is ALU-specific email domains provided here
ALU_DOMAINS = (
    "@alueducation.com",
    "@alumni.alueducation.com",
    "@si.alueducation.com",
)

# this is Suspicious content indicators these are treated as unsafe input and are not executed or interpreted.
SUSPICIOUS_PATTERNS = [
    re.compile(r"<\s*script\b", re.IGNORECASE),
    re.compile(r"\bDROP\s+TABLE\b", re.IGNORECASE),
    re.compile(r"\bUNION\s+SELECT\b", re.IGNORECASE),
    re.compile(r"\b(?:OR|AND)\s+['\"]?\d+['\"]?\s*=\s*['\"]?\d+",
               re.IGNORECASE),
]

#these are functions for implementing the above variables

def is_safe_input(text):
    """ this Return False when obvious malicious payloads are detected."""
    return not any(pattern.search(text) for pattern in SUSPICIOUS_PATTERNS)

def normalize_card(card):
    """  this Remove spaces and hyphens from a card number."""
    return re.sub(r"[ -]", "", card)

def is_valid_card(card):
    """
      this Validate a card using basic length and Luhn checksum rules.
    """
    digits = normalize_card(card)

    if not digits.isdigit() or not 13 <= len(digits) <= 19:
        return False

    total = 0
    reverse_digits = digits[::-1]

    for index, digit in enumerate(reverse_digits):
        number = int(digit)

        if index % 2 == 1:
            number *= 2
            if number > 9:
                number -= 9

        total += number

    return total % 10 == 0


def mask_email(email):
    """  this Mask an email to avoid unnecessary exposure."""
    username, domain = email.split("@", 1)

    if len(username) <= 2:
        masked_username = "*" * len(username)
    else:
        masked_username = username[0] + "***" + username[-1]

    return f"{masked_username}@{domain}"


def mask_card(card):
    """ this Return only the last four digits of a card number."""
    digits = normalize_card(card)
    return f"**** **** **** {digits[-4:]}"


def extract_emails(text):
    """ this Extract valid email addresses."""
    return sorted(set(EMAIL_PATTERN.findall(text)))


def extract_cards(text):
    """ this Extract and validate credit card numbers."""
    matches = CARD_PATTERN.findall(text)

    valid_cards = []

    for card in matches:
        if is_valid_card(card):
            valid_cards.append(mask_card(card))

    return sorted(set(valid_cards))


def extract_urls(text):
    """ this Extract HTTP and HTTPS URLs."""
    return sorted(set(URL_PATTERN.findall(text)))


def extract_phones(text):
    """ this Extract valid-looking Rwandan phone numbers."""
    return sorted(set(PHONE_PATTERN.findall(text)))


def classify_alu_emails(emails):
    """ this Classify emails according to ALU's official domains."""
    official = []
    alumni = []
    si = []

    for email in emails:
        lower_email = email.lower()

        if lower_email.endswith("@alueducation.com"):
            official.append(mask_email(email))

        elif lower_email.endswith("@alumni.alueducation.com"):
            alumni.append(mask_email(email))

        elif lower_email.endswith("@si.alueducation.com"):
            si.append(mask_email(email))

    return {
        "official": sorted(set(official)),
        "alumni": sorted(set(alumni)),
        "si": sorted(set(si)),
    }


def main():
    """ this Read input, extract data and save structured results."""

    text = INPUT_FILE.read_text(encoding="utf-8")

    safe = is_safe_input(text)

    if not safe:
        print("Warning: suspicious content detected in input.")
        print("The suspicious content will not be executed or trusted.")

    emails = extract_emails(text)
    cards = extract_cards(text)
    urls = extract_urls(text)
    phones = extract_phones(text)

    alu_emails = classify_alu_emails(emails)

    results = {
        "security": {
            "input_trusted": False,
            "suspicious_content_detected": not safe,
            "sensitive_data_masked": True,
        },
        "summary": {
            "emails_found": len(emails),
            "credit_cards_found": len(cards),
            "urls_found": len(urls),
            "phones_found": len(phones),
        },
        "data": {
            "emails": [mask_email(email) for email in emails],
            "credit_cards": cards,
            "urls": urls,
            "phone_numbers": phones,
        },
        "alu_email_validation": alu_emails,
    }

    OUTPUT_FILE.parent.mkdir(parents=True, exist_ok=True)

    OUTPUT_FILE.write_text(
        json.dumps(results, indent=4),
        encoding="utf-8"
    )

    print(json.dumps(results, indent=4))


if __name__ == "__main__":
    main()