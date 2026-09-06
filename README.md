# Regex Onboarding Hackathon

## Data Extraction & Secure Validation

This project shows how regular expressions can be used to extract structured information from messy, production-style text while applying basic security and validation checks

The program processes a raw API-style text file and extracts:

* Email addresses
* Credit card numbers
* URLs
* Rwandan phone numbers

It also performs ALU-specific email validation for:

* `@alueducation.com`
* `@alumni.alueducation.com`
* `@si.alueducation.com`

## Project Structure

```text
alu-regex-data-extraction_piradukund1/
├── input/
│   └── raw-text.txt
├── src/
│   └── main.py
├── output/
│   └── sample-output.json
└── README.md
```

## How It Works

The program reads the raw text from `input/raw-text.txt` and applies regular expression patterns to identify supported data types.

### Email Extraction

The email regex checks for a valid username, `@` symbol, domain and top-level domain.

### Credit Card Extraction

The program identifies possible card numbers containing between 13 and 19 digits. A Luhn checksum is then used to reject numbers that do not pass basic card validation.

Credit card numbers are never written to the output in full. Only the last four digits are displayed.

### URL Extraction

The URL pattern identifies HTTP and HTTPS addresses, including URLs containing paths and query-style characters.

### Phone Extraction

The phone pattern supports common Rwandan phone formats, including:

```text
+250 788 123 456
0788123456
```

## ALU Email Validation

The program separates valid ALU email addresses into three categories:

### Official ALU

```text
@alueducation.com
```

### ALU Alumni

```text
@alumni.alueducation.com
```

### ALU SI

```text
@si.alueducation.com
```

The program first identifies properly structured email addresses before checking their domains.

## Security Considerations

Input received from an external API should never automatically be trusted.

The sample input contains suspicious examples such as:

```text
<script>alert("ignore validation")</script>
DROP TABLE customers;
" OR "1"="1
```

The program detects several common suspicious patterns and reports that the input contains potentially unsafe content.

The program does not execute, evaluate or interpret extracted text as code.

Sensitive information is also protected:

* Email usernames are partially masked.
* Credit card numbers are never exposed in full.
* Only the last four card digits are included in the output.

## Running the Program

Make sure Python 3 is installed.

From the project root, run:

```bash
python3 src/main.py
```

The program will:

1. Read `input/raw-text.txt`.
2. Check for suspicious content.
3. Extract emails.
4. Validate credit card numbers.
5. Extract URLs.
6. Extract phone numbers.
7. Validate ALU email domains.
8. Mask sensitive information.
9. Save the results to `output/sample-output.json`.

## Example

Run:

```bash
python3 src/main.py
```

The program prints the extracted results to the terminal and saves the same structured information as JSON in the file of sample-output.json

## Security Principle

The main security principle used in this project is:

> External input is untrusted until it has been validated.

Regex is used for pattern recognition, while additional validation is used where regex alone is not sufficient, such as credit card checksum validation.

## Technologies

* Python 3
* Regular Expressions
* JSON
* File handling
* Luhn checksum validation
