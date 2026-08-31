\# PII Scanner



A command-line tool that detects Personally Identifiable Information (PII) across multiple file formats, built for data privacy audits and accidental data exposure checks.



\*\*Status: Work in progress.\*\* The CLI is functional; a GUI is planned.



\## Why This Exists



People accumulate files they forget about — old resumes, spreadsheets, exported emails, backup codes — that contain sensitive personal data. This tool scans a directory and tells you exactly which files hold what, so you can clean up before someone else finds it.



\## Features



\- \*\*Multi-format scanning\*\* — plain text, `.pdf`, `.docx`, `.xlsx`, and `.eml` files

\- \*\*Confidence tiering\*\* — results split into DEFINITE (validated) and POSSIBLE (needs review)

\- \*\*Digit-normalized filtering\*\* — search `8605197419` and find `(860) 519-7419`, `860.519.7419`, and every other formatting variant

\- \*\*Interactive prompts\*\* — no CLI flags required; the tool guides you through configuration

\- \*\*Layered validation\*\* — regex pattern matching, Luhn checksum, issuer prefix, and length validation for credit cards

\- \*\*Masked card detection\*\* — finds redacted numbers like `\*\*\*\*1234`, which can still leak PII

\- \*\*Exclusion lists\*\* — skip known non-personal directories (emulator configs, system files) to cut false positives



\## Detected PII Types



| Type | Validation |

|------|-----------|

| Email addresses | Format matching |

| Phone numbers | NANP rules (area codes can't start with 0/1), strict + loose patterns |

| SSNs | Dash-delimited format with word boundaries |

| Credit cards | Issuer prefix + Luhn algorithm + length validation |

| Masked cards (`\*\*\*\*1234`) | Reported as POSSIBLE — partial numbers can't be verified |



Card patterns cover Visa, Mastercard, Discover (4-4-4-4 grouping) and American Express (4-6-5 grouping), with or without separators.



\## Supported File Types



`.txt` `.py` `.json` `.csv` `.log` `.xml` `.html` `.md` `.ini` `.cfg` `.pdf` `.docx` `.xlsx` `.eml`



PDFs, Word documents, and spreadsheets are parsed with PyMuPDF, python-docx, and openpyxl respectively — the binary formats aren't readable as plain text.



\## Usage



Run interactively — no command-line flags required:



python scanner.py





You'll be prompted to:



1\. Choose PII types to search (`email,phone,ssn,credit_card`, or blank for all)

2\. Optionally enter specific values to filter for (partial values OK — e.g., `@outlook.com` or an area code)

3\. Enter a directory or single file to scan



Results print as a report grouped by file, with DEFINITE findings shown first and POSSIBLE findings available on request.



\## Requirements



\- Python 3.6+

\- Dependencies:



pip install PyMuPDF python-docx openpyxl



\## Example Output



============================================================ DEFINITE PII FINDINGS



FILE: contacts.xlsx ──────────────────────────────────────────────────────────── \[PHONE] 3 unique value(s) → (860) 519-7419 \[DEFINITE] → 860.519.7419 \[DEFINITE] \[CREDIT CARD] 1 unique value(s) → 4111 1111 1111 1111 \[DEFINITE]





\## Design Notes



\- \*\*False positive reduction:\*\* Strict regex requires consistent separator formatting; a looser pattern feeds results into a POSSIBLE tier instead of discarding them, so coverage isn't lost.

\- \*\*Credit card validation is layered:\*\* structural regex → issuer prefix → length check → Luhn checksum. Random 16-digit sequences almost never survive all four.

\- \*\*Format-specific parsing:\*\* PDF/DOCX/XLSX/EML files are parsed into text first, then fed through the same regex pipeline — one scanning engine, many input formats.



\## Ethical Notice



For authorized security testing and educational purposes only. Never scan files or systems you don't have permission to audit. Findings may include real PII — handle results responsibly.



\## Roadmap



\- \[ ] GUI (tkinter)

\- \[ ] Export findings to CSV/HTML

\- \[ ] Additional PII types (API keys, AWS credentials)

\- \[ ] SQLite database scanning



