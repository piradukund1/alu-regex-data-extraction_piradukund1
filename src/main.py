#!/usr/bin/env python3

import json
import re
from pathlib import Path

INPUT_FILE = Path(__file__).parent.parent / "input" / "raw-text.txt"
OUTPUT_FILE = Path(__file__).parent.parent / "output" / "sample-output.json" 

# regex pattern for the each of the datatypes the user will be extracting from the rawtext file
EMAIL_RE = re.compile(r"\b[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+\b")
CARD_RE = re.compile(r"\b(?:\d[ -]?){13,18}\d\b")  # for checking if is 13-19 digit sequences,space/hyphen separated
URL_RE = re.compile(r"https?://[A-Za-z0-9.-]+(?:/[A-Za-z0-9._~:/?#\[\]@!$&'()*+,;=%-]*)?")
PHONE_RE = re.compile(r"(?<!\d)(?:\+250[\s-]?\d{3}[\s-]?\d{3}[\s-]?\d{3}|0\d{9})(?!\d)")  # this is for checking if it the rwandan formats

ALU_DOMAIN = ("alueducation.com", "alumi.alueducation.com", "alueducation.org", "alueducation.com" , "si.alueducation.com")

# this the part that indicates a malicious or untrusted payload and dectects but it never executed

SUSPICIOUS_RE = [
    re.compile(r"<\s*script\b", re.I),
    re.compile(r"\bDROP\s+TABLE\b", re.I),
    re.compile(r"\bUNION\s+SELECT\b", re.I),
    re.compile(r"\b(?:OR|AND)\s+['\"]?\d+['\"]?\s*=\s*['\"]?\d+", re.I),
]

#  this turns true when the suspicious regex patterns are found in the input broo
is_safe_input = lambda text: not any(p.search(text) for p in SUSPICIOUS_RE)

# for the string space, hyphens and the card number be plain digit string
normalize_card = lambda card: re.sub(r"[ -]", "", card)

def is_valid_card(card):
    """ checking the lenght and then run the luhn checksum to filter ouot non real card numbers"""
    digits = normalize_card(card)
    if not digits.isdigit() or not 13 <= len(digits) <= 19:
        return False

    total = 0
    for i, d in enumerate(digits[::-1]): # processing the right to left
        n = int(d) * 2 if i % 2 else int(d) # double every second digit from the right
        total += n - 9 if n > 9 else n #substract 9 if doubling pushed it past 9
    return total % 10 == 0

def mask_email(email):
    """keep first and last char of the local part, hide the rest with asterisks, and keep the domain intact"""
    user, domain = email.split("@", 1)
    masked = "*" * len(user) if len(user) <= 2 else f"{user[0]}***{user[-1]}"
    return f"{masked}@{domain}"

def mask_card(card):
    """reduce the card number to just its last 4 digits only"""
    return f"**** **** **** {normalize_card(card)[-4:]}"

# simple regex extraction and dedupe helpers
extract_emails = lambda text: sorted(set(EMAIL_RE.findall(text)))
extract_urls = lambda text: sorted(set(URL_RE.findall(text)))
extract_phones = lambda text: sorted(set(PHONE_RE.findall(text)))

def extract_cards(text):
    """find card like number sequences and keep only the luhn valid ones and then mask them"""
    return sorted({mask_card(c) for c in CARD_RE.findall(text) if is_valid_card(c)})

def classify_alu_emails(emails):
    """sorting the ALU emails into the official , alumni ,si buckets based on their domain suffix."""
    buckets = {"official": [], "alumni": [], "si": []}
    for email in emails:
        lower = email.lower()
        # this part for for hecking alumni/si before official since their domains also end in "alueducation.com"
        for key, domain in zip(("alumni", "si", "official"),
                                ("alumni.alueducation.com", "si.alueducation.com", "alueducation.com")):
            if lower.endswith("@" + domain):
                buckets[key].append(mask_email(email))
                break
    return {k: sorted(set(v)) for k, v in buckets.items()}

def main():
    """part of read input extract/mask sensitive data and write the JSON report."""
    text = INPUT_FILE.read_text(encoding="utf-8")

    safe = is_safe_input(text)
    if not safe:
        print("Warning: suspicious content detected in input. Not executed or trusted.")

    emails = extract_emails(text)
    cards = extract_cards(text)
    urls = extract_urls(text)
    phones = extract_phones(text)

    results = {
        # flags describing how the input was handled
        "security": {
            "input_trusted": False, # raw input is never trusted, even if it looks safe
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
            "emails": [mask_email(e) for e in emails],
            "credit_cards": cards,
            "urls": urls,
            "phone_numbers": phones,
        }, 
        "alu_email_validation": classify_alu_emails(emails),
    }

    # ensure the output directory exists and write the results to the disk
    OUTPUT_FILE.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT_FILE.write_text(json.dumps(results, indent=4), encoding="utf-8")
    print(json.dumps(results, indent=4))

# only run the main() when this file is executed directly(not on import)
if __name__ == "__main__":
    main()


