# PII Document Anonymizer

A lightweight, robust Python tool that detects personally identifiable information (PII), replaces it with consistent synthetic fake data, and outputs sanitized documents while preserving document structures and formatting.

Supports **Plain Text (`.txt`)**, **Microsoft Word (`.docx`)**, and **Text-based PDF (`.pdf`)** documents.

---

## 🎯 Architecture & Design Rationale

Rather than relying purely on regex or purely on heavy transformer models, the system uses a **Hybrid Detection Strategy**:
- **Deterministic Rules & Algorithmic Validators**: Used for structured, high-precision entities (e.g. Luhn algorithm for Credit Cards, `phonenumbers` for phone formats, `ipaddress` validation for IPv4).
- **Statistical Named Entity Recognition (NER)**: spaCy (`en_core_web_sm`) and Microsoft Presidio for contextual entities (Person, Organization/Company, Physical Address).
- **Generic Edge-Case Normalization**: Case normalization for ALL-CAPS text blocks commonly found in legal documents (e.g. prospectus promoter lists) and delimiter boundary splitting.
- **Consistent Synthetic Replacement**: A 1-to-1 mapping via `Faker` ensuring the same entity always receives the exact same synthetic replacement throughout the document.

```
                  +-----------------------------------+
                  |          Input Document           |
                  |        (.txt / .docx / .pdf)      |
                  +-----------------+-----------------+
                                    |
                                    v
                  +-----------------+-----------------+
                  |      Text & Structure Parsing     |
                  | (XML nodes, tables, instrText)    |
                  +-----------------+-----------------+
                                    |
                                    v
+-----------------------------------+-----------------------------------+
|                     Hybrid Detection Pipeline                        |
|  - Email (Regex)                 - SSN (Contextual Regex)             |
|  - Phone (Phonenumbers library)  - Date of Birth (Pattern + Keywords) |
|  - Credit Card (Luhn validator)  - Person / Org / Address (spaCy NER) |
|  - IPv4 (ipaddress validator)    - Case normalization for ALL-CAPS    |
+-----------------------------------+-----------------------------------+
                                    |
                                    v
                  +-----------------+-----------------+
                  |  Consistent Synthetic Replacement |
                  |   (1-to-1 Faker-backed dictionary)|
                  +-----------------+-----------------+
                                    |
                                    v
                  +-----------------+-----------------+
                  |      Document Reconstruction      |
                  |  - DOCX: XML runs & w:instrText   |
                  |  - PDF: PyMuPDF true redaction    |
                  +-----------------+-----------------+
                                    |
                                    v
                  +-----------------+-----------------+
                  |   Post-Redaction Validation Pass  |
                  |      (PASS / WARNING reporting)   |
                  +-----------------------------------+
```

---

## 📋 Supported PII Types

| PII Type | Primary Detection Mechanism | Synthetic Generator |
| :--- | :--- | :--- |
| **Full Names** | spaCy NER (`PERSON`) + ALL-CAPS case normalization | Realistic fake name (`Faker.name()`) |
| **Email Addresses** | Deterministic Email Regex | Fake email (`Faker.email()`) |
| **Phone Numbers** | Regex + Google `phonenumbers` validation | Fake phone preserving country prefix (+91 / +1) |
| **Company / Organization** | spaCy NER (`ORG`) | Fake company name (`Faker.company()`) |
| **Physical Addresses** | spaCy NER (`GPE`/`LOC`/`FAC`) + Presidio (protected geographic entities) | Fake street address (`Faker.address()`) |
| **Social Security Numbers** | Format-validated SSN Regex | Fake SSN (`Faker.ssn()`) |
| **Credit Card Numbers** | Regex + Luhn Algorithm checksum | Fake Luhn-valid credit card (`Faker.credit_card_number()`) |
| **Date of Birth** | Date regex patterns with contextual triggers (`DOB`, `born`, `birth date`) | Fake birth date (`Faker.date_of_birth()`) |
| **IP Addresses** | Regex + `ipaddress.IPv4Address` validation | Fake public IPv4 (`Faker.ipv4_public()`) |

---

## 📑 Document Structure Handling

### Microsoft Word (`.docx`)
Business and legal documents rarely store text in simple paragraph sequences. The DOCX engine operates at the XML level:
- **Tables & Nested Tables**: Traverses all rows (`w:tr`) and cells (`w:tc`) recursively.
- **Run Splitting**: When an entity is split across multiple Word runs (e.g. `<w:t>Rashi </w:t><w:t>Patil</w:t>`), offsets are mapped across text nodes and formatted run boundaries are preserved.
- **Hyperlinks & Field Codes**: Sanitizes `<w:instrText>` nodes containing `HYPERLINK "mailto:..."` and `.rels` targets so original email addresses and URLs do not linger inside document metadata.
- **Headers, Footers & Text Boxes**: Traverses `word/header*.xml`, `word/footer*.xml`, and shape text boxes (`<w:txbxContent>`, `<v:textbox>`, `<a:t>`).

### Portable Document Format (`.pdf`)
- Applies true PDF redaction via PyMuPDF (`add_redact_annot` + `apply_redactions()`), physically erasing the underlying text rather than drawing visual overlay boxes.
- Scans for selectable text. If an image-only / scanned PDF is provided, emits a clear warning:
  `"This appears to be an image/scanned PDF. OCR is not currently supported."`

---

## 🚀 Installation & Usage

### 1. Installation
```bash
python -m venv myenv
source myenv/bin/activate
pip install -r requirements.txt
python -m spacy download en_core_web_sm
```

### 2. CLI Usage
```bash
# Basic redaction (generates input_redacted.ext)
python pii_anonymizer.py document.docx

# Custom output file and random seed for repeatable fake data
python pii_anonymizer.py input.docx -o output_redacted.docx --seed 42

# Generate JSON audit report
python pii_anonymizer.py document.pdf --report audit_report.json

# Enable privacy-safe debug mode
python pii_anonymizer.py document.txt --debug
```

### 3. Run Test Suite
```bash
python test_pii.py
```

---

## 🔍 Validation & Privacy-Safe Debugging

- **Post-Redaction Scanner**: After saving the document, the tool re-opens the file, traverses all structures, and runs a secondary PII detection scan to ensure de-identification quality.
- **Privacy-Safe Logs**: Debug mode outputs detector names (`Detected EMAIL using regex`, `Detected PERSON using spaCy`) and never prints sensitive original PII into logs or reports.

---

## ⚠️ Limitations & Future Improvements

### Current Limitations
1. **Scanned / Image-Only PDFs**: Text within bitmap scans requires OCR, which is outside the scope of this lightweight 24-hour project.
2. **Complex Embedded Objects**: SmartArt or OLE embedded binary packages are not modified.

### Future Improvements
1. **OCR Pipeline**: Integrate Tesseract / EasyOCR for scanned PDF and image support.
2. **Country-Specific Identifiers**: Add dedicated recognizers for Indian Aadhaar and PAN numbers.
3. **Fine-Tuned Domain NER**: Fine-tune transformer models on financial and legal prospectus datasets for even higher entity precision.
4. **Enhanced PDF Layout Retention**: Re-render replacement text matching original font metrics and styles.












# PII Document Anonymizer

A Python tool that detects and anonymizes personally identifiable
information from TXT, DOCX and text-based PDF documents.

## Why I built this

PII is often present in support tickets, customer documents and
business reports. Manually removing this information is time-consuming
and error-prone.

This project explores a lightweight NLP-based approach for automatically
detecting and replacing PII while preserving document usability.

## Approach

The project uses a hybrid detection strategy:

- Regex for structured entities
- Presidio/spaCy for contextual entities
- phonenumbers for phone validation
- Faker for synthetic replacements

## Supported PII

- Person names
- Email addresses
- Phone numbers
- Company names
- Addresses
- SSNs
- Credit cards
- Dates of birth
- IP addresses

## Supported files

- TXT
- DOCX
- Text-based PDF

## Limitations

The current version does not process image-only/scanned PDFs.
OCR would be a natural future extension.

Complex Word objects such as SmartArt and some embedded objects
may not be processed.

NER-based detection can also produce false positives or miss
ambiguous entities, so the generated document is run through
a second validation pass.

## Future improvements

- OCR support
- Better address recognition
- Additional country-specific PII
- Improved DOCX shape/text-box handling
- Evaluation using a manually labelled dataset