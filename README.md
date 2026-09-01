# PII Scanner



A command-line tool that detects Personally Identifiable Information (PII) across multiple file formats, built for data privacy audits and accidental data exposure checks.



**Status: Work in progress.** The CLI is functional; a GUI is planned.



## Why This Exists



People accumulate files they forget about — old resumes, spreadsheets, exported emails, backup codes — that contain sensitive personal data. This tool scans a directory and tells you exactly which files hold what, so you can clean up before someone else finds it.



## Features



- **Multi-format scanning** — plain text, `.pdf`, `.docx`, `.xlsx`, and `.eml` files

- **Confidence tiering** — results split into DEFINITE (validated) and POSSIBLE (needs review)

- **Digit-normalized filtering** — search `8605197419` and find `(860) 519-7419`, `860.519.7419`, and every other formatting variant

- **Interactive prompts** — no CLI flags required; the tool guides you through configuration

- **Layered validation** — regex pattern matching, Luhn checksum, issuer prefix, and length validation for credit cards

- **Masked card detection** — finds redacted numbers like `****1234`, which can still leak PII

- **Exclusion lists** — skip known non-personal directories (emulator configs, system files) to cut false positives



## Detected PII Types



| Type | Validation |
|------|-----------|
| Email addresses | Format matching |
| Phone numbers | NANP rules (area codes can't start with 0/1), strict + loose patterns |
| SSNs | Dash-delimited format with word boundaries |
| Credit cards | Issuer prefix + Luhn algorithm + length validation |
| Masked cards (`****1234`) | Reported as POSSIBLE — partial numbers can't be verified |



Card patterns cover Visa, Mastercard, Discover (4-4-4-4 grouping) and American Express (4-6-5 grouping), with or without separators.



## Supported File Types



`.txt` `.py` `.json` `.csv` `.log` `.xml` `.html` `.md` `.ini` `.cfg` `.pdf` `.docx` `.xlsx` `.eml`



PDFs, Word documents, and spreadsheets are parsed with PyMuPDF, python-docx, and openpyxl respectively — the binary formats aren't readable as plain text.



## Usage

### Option 1: Download the Exe (No Python Required)
  1. Go to the [Releases page](https://github.com/cyber-quack/pii-scanner/releases)
  2. Download `CyberQuack PII Scanner.exe`
  3. Double-click to run
  4. If Windows SmartScreen appears, click **More info** → **Run anyway** (the exe is unsigned)

Follow the on-screen prompts to select PII types, enter filters, and choose a directory or file to scan.

### Option 2: Run From Source
  Requires Python 3.6+ and three dependencies:
    pip install PyMuPDF python-docx openpyxl

  Then run:
    python "CyberQuack PII Scanner.py"

### What the Prompts Look Like
<img width="1705" height="1492" alt="image" src="https://github.com/user-attachments/assets/ef2c8a72-7c0e-4f47-83b9-b9aae8510ce6" />


## Example Output

<img width="1420" height="1697" alt="image" src="https://github.com/user-attachments/assets/8f3748f1-55df-4a6e-9382-ec02a2ee14ff" />


## Design Notes


- **False positive reduction:** Strict regex requires consistent separator formatting; a looser pattern feeds results into a POSSIBLE tier instead of discarding them, so coverage isn't lost.

- **Credit card validation is layered:** structural regex → issuer prefix → length check → Luhn checksum. Random 16-digit sequences are much less likely to survive all four.

- **Format-specific parsing:** PDF/DOCX/XLSX/EML files are parsed into text first, then fed through the same regex pipeline — one scanning engine, many input formats.


## Ethical Notice


For authorized security testing and educational purposes only. Never scan files or systems you don't have permission to audit. Findings may include real PII — handle results responsibly.


## Roadmap

- [x] Multi-format file support (PDF, DOCX, XLSX, EML)
- [x] Confidence-tiered reporting (DEFINITE / POSSIBLE)
- [x] Digit-normalized filtering
- [x] Damaged PDF handling with user consent
- [x] Mid-scan cancellation (press Q)
- [x] Input validation for all prompts
- [ ] Export findings to TXT/CSV
- [ ] Pagination for large result sets
- [ ] OCR for scanned documents (Full version)
- [ ] Additional PII types (passport numbers, international phones, API keys)
- [ ] GUI (tkinter)


## Changelog

- v1.1.0 — Scan cancellation, damaged PDF consent flow, input validation, exit pause
- v1.0.0 — Initial release

**Windows SmartScreen notice:** This executable is not code-signed.
On first launch, Windows may show a "Windows protected your PC" message.
Click **More info** → **Run anyway** to proceed.

**Why it's unsigned:** Code signing certificates are expensive for individual
developers. Since the source code is fully open, you can verify everything
this program does by reading it — or run it from source with Python instead
of using the executable.
