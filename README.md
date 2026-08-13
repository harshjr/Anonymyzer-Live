# PII Anonymizer v2

Production-oriented baseline for TXT, DOCX and selectable-text PDF files.

## Key v2 improvement

DOCX processing now works at the OOXML (`word/*.xml`) level instead of assuming
all visible text is represented by `python-docx` paragraph runs.

This means it can detect text split across Word runs and text inside hyperlinks,
tables, headers and footers much more reliably.

## Install

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python -m spacy download en_core_web_sm
```

## Run

```bash
python pii_anonymizer.py input.docx
python pii_anonymizer.py input.txt
python pii_anonymizer.py input.pdf
```

Custom output:

```bash
python pii_anonymizer.py input.docx -o output_redacted.docx
```

Optional count-only report:

```bash
python pii_anonymizer.py input.docx --report report.json
```

The report never stores original PII.

## Test with the supplied document

```bash
python pii_anonymizer.py "Red Herring Prospectus.docx"   -o "Red Herring Prospectus_redacted.docx"   --report report.json
```

## Important limitations

- Scanned/image-only PDFs require OCR before reliable text PII detection.
- DOCX content in unusual embedded objects, charts, drawings or custom XML may
  require additional handlers.
- A PII detector can miss entities or produce false positives. Validation is a
  safety check, not a guarantee.
- Do not persist the original-to-fake mapping unless it is protected by an
  appropriate security/key-management design.
