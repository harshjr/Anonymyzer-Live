#!/usr/bin/env python3
"""
PII Document Anonymizer

A clean, hybrid PII detection and synthetic redaction tool supporting
.txt, .docx, and text-based .pdf documents.

Key Capabilities:
- Hybrid detection: Regex & validation (Email, Phone, CC, IP, SSN, DOB) + spaCy & Presidio (Person, Org, Address)
- Consistent synthetic replacement: same entity receives same fake value throughout the document
- Deep DOCX processing: paragraphs, tables, nested tables, cells, headers, footers, textboxes,
  run-split text, and field codes / hyperlinks (w:instrText and .rels)
- Text-based PDF redaction with PyMuPDF annotations and clear warning for scanned/image PDFs
- Post-redaction validation scan to ensure high sanitization quality without leaking sensitive data
- Privacy-safe debug mode
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import logging
import re
import sys
import zipfile
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable
from xml.etree import ElementTree as ET

try:
    import pymupdf as fitz
except ImportError:
    import fitz

import phonenumbers
import spacy
from faker import Faker
from presidio_analyzer import AnalyzerEngine

SUPPORTED_EXTENSIONS = {".txt", ".docx", ".pdf"}

# XML Namespaces for DOCX
NS = {
    "w": "http://schemas.openxmlformats.org/wordprocessingml/2006/main",
    "r": "http://schemas.openxmlformats.org/officeDocument/2006/relationships",
    "v": "urn:schemas-microsoft-com:vml",
    "wp": "http://schemas.openxmlformats.org/drawingml/2006/wordprocessingDrawing",
    "a": "http://schemas.openxmlformats.org/drawingml/2006/main",
}

# Common document field labels that should never be classified as personal names
LABEL_WORDS = {
    "email", "e-mail", "telephone", "tel", "phone", "fax", "website", "web",
    "url", "name", "contact", "contact person", "promoter", "promoters", "director",
    "directors", "company", "address", "registered office", "corporate office",
    "table", "section", "annexure", "page", "date", "status", "auditor",
    "auditors", "officer", "compliance officer", "shareholder", "shareholders",
    "description", "particulars", "term", "definitions", "abbreviations"
}

# Standalone country/state names that should not be replaced with a full multi-line street address
GENERIC_GEOGRAPHIC_NAMES = {
    "india", "united states", "usa", "uk", "united kingdom", "canada",
    "australia", "germany", "france", "japan", "singapore", "maharashtra",
    "delhi", "karnataka", "tamil nadu", "gujarat", "california", "new york", "texas"
}

# Regex patterns for deterministic PII types
EMAIL_REGEX = re.compile(
    r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"
)

# International and domestic phone formats (+91 ..., 022-..., (020)..., 10-12 digits)
PHONE_REGEX = re.compile(
    r"(?:\+?\d{1,3}[-.\s]?)?\(?\d{2,5}\)?[-.\s]?\d{3,4}[-.\s]?\d{3,5}\b"
)

# Credit card regex (13-19 digits with optional hyphens/spaces)
CREDIT_CARD_REGEX = re.compile(
    r"\b(?:\d{4}[-\s]?){3}\d{1,4}\b|\b\d{13,19}\b"
)

# IPv4 regex
IPV4_REGEX = re.compile(
    r"\b(?:\d{1,3}\.){3}\d{1,3}\b"
)

# US SSN regex
SSN_REGEX = re.compile(
    r"\b(?!000|666|9\d{2})\d{3}-(?!00)\d{2}-(?!0000)\d{4}\b"
)

# Date of birth trigger keywords and date formats
DOB_KEYWORDS = re.compile(
    r"\b(?:dob|date\s+of\s+birth|birth\s+date|born|d\.o\.b)\b", re.IGNORECASE
)
DATE_REGEX = re.compile(
    r"\b(?:\d{1,2}[-/.]\d{1,2}[-/.]\d{2,4}|\d{4}[-/.]\d{1,2}[-/.]\d{1,2}|"
    r"(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)[a-z]*\s+\d{1,2},?\s+\d{4}|"
    r"\d{1,2}\s+(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)[a-z]*\s+\d{4})\b",
    re.IGNORECASE
)


@dataclass(frozen=True)
class Entity:
    start: int
    end: int
    text: str
    kind: str
    score: float
    detector: str = "rule"


def is_luhn_valid(number_str: str) -> bool:
    """Validate credit card number using the Luhn checksum algorithm."""
    digits = [int(c) for c in number_str if c.isdigit()]
    if not (13 <= len(digits) <= 19):
        return False
    checksum = 0
    reverse_digits = digits[::-1]
    for i, d in enumerate(reverse_digits):
        if i % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        checksum += d
    return checksum % 10 == 0


def is_valid_ipv4(ip_str: str) -> bool:
    """Validate IPv4 address string."""
    try:
        ip = ipaddress.ip_address(ip_str)
        return isinstance(ip, ipaddress.IPv4Address)
    except ValueError:
        return False


def is_valid_phone(phone_str: str) -> bool:
    """Validate phone number string using Google phonenumbers library."""
    digits = re.sub(r"\D", "", phone_str)
    if not (7 <= len(digits) <= 15):
        return False
    
    for region in ("IN", "US", None):
        try:
            parsed = phonenumbers.parse(phone_str, region)
            if phonenumbers.is_possible_number(parsed) and phonenumbers.is_valid_number(parsed):
                return True
        except Exception:
            pass
    return False


class SyntheticMapper:
    """
    Maintains a consistent 1-to-1 mapping of original PII entities
    to synthetic fake values throughout a document.
    """
    def __init__(self, seed: int | None = None):
        self.fake = Faker("en_US")
        if seed is not None:
            Faker.seed(seed)
        self.mapping: dict[tuple[str, str], str] = {}

    def _normalize_key(self, kind: str, value: str) -> tuple[str, str]:
        cleaned = re.sub(r"\s+", " ", value.strip().lower())
        return kind, cleaned

    def get(self, kind: str, original: str) -> str:
        key = self._normalize_key(kind, original)
        if key not in self.mapping:
            self.mapping[key] = self.generate(kind, original)
        return self.mapping[key]

    def generate(self, kind: str, original: str) -> str:
        if kind == "PERSON":
            return self.fake.name()
        if kind == "EMAIL":
            return self.fake.email()
        if kind == "PHONE":
            cleaned = original.strip()
            if "+91" in cleaned or cleaned.startswith("91 "):
                return "+91 " + self.fake.numerify("9#########")
            return "+1 " + self.fake.numerify("###-###-####")
        if kind == "COMPANY":
            return self.fake.company()
        if kind == "ADDRESS":
            return self.fake.address().replace("\n", ", ")
        if kind == "SSN":
            return self.fake.ssn()
        if kind == "CREDIT_CARD":
            return self.fake.credit_card_number()
        if kind == "DATE_OF_BIRTH":
            return self.fake.date_of_birth().strftime("%Y-%m-%d")
        if kind == "IP_ADDRESS":
            return self.fake.ipv4_public()
        return "[REDACTED]"


class PIIEngine:
    """
    Hybrid PII Detection Engine combining deterministic rules/regexes
    with spaCy NER and Presidio Analyzer.
    """
    def __init__(self, min_score: float = 0.55, debug: bool = False):
        try:
            self.nlp = spacy.load("en_core_web_sm")
        except OSError:
            from spacy.cli import download
            download("en_core_web_sm")
            self.nlp = spacy.load("en_core_web_sm")

        self.analyzer = AnalyzerEngine()
        self.min_score = min_score
        self.debug = debug

    def _log_debug(self, msg: str):
        if self.debug:
            print(f"[DEBUG] {msg}")

    def detect_deterministic(self, text: str) -> list[Entity]:
        """Detect entities using deterministic regexes and algorithmic validators."""
        entities: list[Entity] = []

        # 1. Emails
        for match in EMAIL_REGEX.finditer(text):
            entities.append(Entity(
                start=match.start(),
                end=match.end(),
                text=match.group(0),
                kind="EMAIL",
                score=1.0,
                detector="regex"
            ))
            self._log_debug("Detected EMAIL using regex")

        # 2. Phone Numbers
        for match in PHONE_REGEX.finditer(text):
            val = match.group(0).strip()
            if is_valid_phone(val):
                entities.append(Entity(
                    start=match.start(),
                    end=match.end(),
                    text=match.group(0),
                    kind="PHONE",
                    score=0.90,
                    detector="phonenumbers"
                ))
                self._log_debug("Detected PHONE using phonenumbers")

        # 3. Credit Cards (with Luhn check)
        for match in CREDIT_CARD_REGEX.finditer(text):
            val = match.group(0).strip()
            if is_luhn_valid(val):
                entities.append(Entity(
                    start=match.start(),
                    end=match.end(),
                    text=match.group(0),
                    kind="CREDIT_CARD",
                    score=1.0,
                    detector="luhn_regex"
                ))
                self._log_debug("Detected CREDIT_CARD using Luhn validation")

        # 4. IP Addresses
        for match in IPV4_REGEX.finditer(text):
            val = match.group(0).strip()
            if is_valid_ipv4(val):
                entities.append(Entity(
                    start=match.start(),
                    end=match.end(),
                    text=match.group(0),
                    kind="IP_ADDRESS",
                    score=1.0,
                    detector="ipaddress"
                ))
                self._log_debug("Detected IP_ADDRESS using ipaddress validation")

        # 5. SSNs
        for match in SSN_REGEX.finditer(text):
            entities.append(Entity(
                start=match.start(),
                end=match.end(),
                text=match.group(0),
                kind="SSN",
                score=0.95,
                detector="ssn_regex"
            ))
            self._log_debug("Detected SSN using regex")

        # 6. Dates of Birth (Contextual)
        for match in DATE_REGEX.finditer(text):
            start = max(0, match.start() - 60)
            end = min(len(text), match.end() + 40)
            context = text[start:end]
            if DOB_KEYWORDS.search(context):
                entities.append(Entity(
                    start=match.start(),
                    end=match.end(),
                    text=match.group(0),
                    kind="DATE_OF_BIRTH",
                    score=0.90,
                    detector="dob_context_regex"
                ))
                self._log_debug("Detected DATE_OF_BIRTH using date pattern + context")

        return entities

    def detect_nlp(self, text: str) -> list[Entity]:
        """Detect entities using spaCy NER and Presidio Analyzer with casing normalization."""
        nlp_entities: list[Entity] = []

        # Pass 1: Direct spaCy NER
        doc = self.nlp(text)
        for ent in doc.ents:
            val = ent.text.strip()
            val_clean = val.lower().rstrip(":")

            if not val_clean or val_clean in LABEL_WORDS:
                continue

            kind = None
            if ent.label_ == "PERSON":
                kind = "PERSON"
            elif ent.label_ == "ORG":
                kind = "COMPANY"
            elif ent.label_ in ("GPE", "LOC", "FAC"):
                if val_clean not in GENERIC_GEOGRAPHIC_NAMES:
                    kind = "ADDRESS"

            if not kind:
                continue

            # Handle slash-separated composite names (e.g. "Person 1 / Person 2")
            if "/" in val and kind == "PERSON":
                offset = ent.start_char
                for part in val.split("/"):
                    part_stripped = part.strip()
                    if len(part_stripped) > 2 and part_stripped.lower() not in LABEL_WORDS:
                        p_start = text.find(part_stripped, offset)
                        p_end = p_start + len(part_stripped)
                        nlp_entities.append(Entity(
                            start=p_start,
                            end=p_end,
                            text=part_stripped,
                            kind="PERSON",
                            score=0.85,
                            detector="spacy_split"
                        ))
                    offset += len(part) + 1
                self._log_debug("Detected PERSON using spaCy (split across delimiter)")
                continue

            nlp_entities.append(Entity(
                start=ent.start_char,
                end=ent.end_char,
                text=val,
                kind=kind,
                score=0.85,
                detector="spacy"
            ))
            self._log_debug(f"Detected {kind} using spaCy")

        # Pass 2: Case normalization for uppercase text blocks
        if text.isupper() or any(w.isupper() and len(w) > 3 for w in text.split()):
            title_text = text.title()
            doc_title = self.nlp(title_text)
            for ent in doc_title.ents:
                val = text[ent.start_char:ent.end_char].strip()
                val_clean = val.lower().rstrip(":")

                if not val_clean or val_clean in LABEL_WORDS:
                    continue

                kind = None
                if ent.label_ == "PERSON":
                    kind = "PERSON"
                elif ent.label_ == "ORG":
                    kind = "COMPANY"
                elif ent.label_ in ("GPE", "LOC", "FAC"):
                    if val_clean not in GENERIC_GEOGRAPHIC_NAMES:
                        kind = "ADDRESS"

                if not kind:
                    continue

                nlp_entities.append(Entity(
                    start=ent.start_char,
                    end=ent.end_char,
                    text=val,
                    kind=kind,
                    score=0.80,
                    detector="spacy_titlecase"
                ))
                self._log_debug(f"Detected {kind} using spaCy (titlecase pass)")

        # Pass 3: Presidio Analyzer for additional contextual recognizers
        presidio_results = self.analyzer.analyze(
            text=text,
            language="en",
            score_threshold=self.min_score,
            entities=["LOCATION", "PERSON"]
        )
        for r in presidio_results:
            val = text[r.start:r.end].strip()
            val_clean = val.lower().rstrip(":")
            if not val_clean or val_clean in LABEL_WORDS:
                continue

            kind = "ADDRESS" if r.entity_type == "LOCATION" else "PERSON"
            if kind == "ADDRESS" and val_clean in GENERIC_GEOGRAPHIC_NAMES:
                continue

            nlp_entities.append(Entity(
                start=r.start,
                end=r.end,
                text=val,
                kind=kind,
                score=r.score,
                detector="presidio"
            ))
            self._log_debug(f"Detected {kind} using Presidio")

        return nlp_entities

    def detect(self, text: str) -> list[Entity]:
        """Combine deterministic and NLP detections with non-overlapping prioritization."""
        if not text or not text.strip():
            return []

        deterministic = self.detect_deterministic(text)
        nlp = self.detect_nlp(text)

        all_candidates = deterministic + nlp

        # Sort by: higher score first, longer span first, earlier start index
        all_candidates.sort(key=lambda e: (-e.score, -(e.end - e.start), e.start))

        # Discard overlapping spans, keeping the highest priority entity
        selected: list[Entity] = []
        for cand in all_candidates:
            if not any(cand.start < s.end and cand.end > s.start for s in selected):
                selected.append(cand)

        return sorted(selected, key=lambda e: e.start)

    def redact_text(self, text: str, mapper: SyntheticMapper) -> tuple[str, list[dict]]:
        """Redact a plain text string from right to left using synthetic replacements."""
        entities = self.detect(text)
        output = text
        audit = []
        for e in reversed(entities):
            replacement = mapper.get(e.kind, e.text)
            output = output[:e.start] + replacement + output[e.end:]
            audit.append({
                "type": e.kind,
                "replacement": replacement,
                "detector": e.detector
            })
        return output, list(reversed(audit))


# ---------------- Plain Text (.txt) ----------------

def process_txt(src: Path, dst: Path, engine: PIIEngine, mapper: SyntheticMapper) -> list[dict]:
    """Process and redact a plain text file."""
    text = src.read_text(encoding="utf-8", errors="replace")
    output, audit = engine.redact_text(text, mapper)
    dst.write_text(output, encoding="utf-8")
    return audit


# ---------------- Word Document (.docx) ----------------

def replace_text_in_nodes(nodes: list[ET.Element], engine: PIIEngine, mapper: SyntheticMapper) -> list[dict]:
    """
    Replace detected PII entities across a sequence of XML text nodes (<w:t> or <a:t>).
    Preserves XML formatting and handles entities split across multiple run elements.
    """
    if not nodes:
        return []

    pieces = [n.text or "" for n in nodes]
    full = "".join(pieces)
    if not full.strip():
        return []

    entities = engine.detect(full)
    if not entities:
        return []

    replacements = [(e, mapper.get(e.kind, e.text)) for e in entities]

    # Process entities from right to left to keep character offsets stable
    for e, replacement in reversed(replacements):
        node_spans = []
        pos = 0
        for node, piece in zip(nodes, pieces):
            node_spans.append((pos, pos + len(piece), node))
            pos += len(piece)

        affected = [
            (a, b, node)
            for a, b, node in node_spans
            if a < e.end and b > e.start
        ]

        if not affected:
            continue

        first_a, first_b, first_node = affected[0]
        last_a, last_b, last_node = affected[-1]

        local_start = e.start - first_a

        if first_node is last_node:
            old_text = first_node.text or ""
            local_end = e.end - first_a
            first_node.text = old_text[:local_start] + replacement + old_text[local_end:]
        else:
            first_text = first_node.text or ""
            last_text = last_node.text or ""

            prefix = first_text[:local_start]
            suffix_index = e.end - last_a
            suffix = last_text[suffix_index:]

            first_node.text = prefix + replacement
            last_node.text = suffix

            # Clear intermediate nodes
            for _, _, node in affected[1:-1]:
                node.text = ""

        # Update pieces array for next entity replacement
        pieces = [n.text or "" for n in nodes]

    return [{"type": e.kind, "replacement": repl, "detector": e.detector} for e, repl in replacements]


def replace_instr_text_nodes(nodes: list[ET.Element], engine: PIIEngine, mapper: SyntheticMapper) -> list[dict]:
    """
    Process Word field codes (w:instrText) such as HYPERLINK mailto: / http: targets.
    """
    audit = []
    for node in nodes:
        text = node.text or ""
        if not text.strip():
            continue
        
        for match in EMAIL_REGEX.finditer(text):
            email = match.group(0)
            fake_email = mapper.get("EMAIL", email)
            text = text.replace(email, fake_email)
            audit.append({"type": "EMAIL", "replacement": fake_email, "detector": "instrText_regex"})
        
        node.text = text
    return audit


def process_docx(src: Path, dst: Path, engine: PIIEngine, mapper: SyntheticMapper) -> list[dict]:
    """
    Deep DOCX processing:
    - Traverses all XML parts (document.xml, header*.xml, footer*.xml, footnotes, endnotes)
    - Processes paragraphs across normal text, tables, nested tables, cells, text boxes (<w:txbxContent>, <v:textbox>)
    - Anonymizes field code hyperlinks (<w:instrText>) and .rels targets
    """
    audit = []

    with zipfile.ZipFile(src, "r") as zin, zipfile.ZipFile(dst, "w", zipfile.ZIP_DEFLATED) as zout:
        for item in zin.infolist():
            data = zin.read(item.filename)

            is_word_xml = (
                item.filename.startswith("word/")
                and item.filename.endswith(".xml")
                and not item.filename.endswith(".rels")
            )
            is_rels = item.filename.endswith(".rels")

            if is_word_xml:
                try:
                    root = ET.fromstring(data)

                    # 1. Process all paragraphs across document, tables, headers, footers, textboxes
                    all_paragraphs = root.findall(".//w:p", NS)
                    for p in all_paragraphs:
                        t_nodes = p.findall(".//w:t", NS)
                        audit.extend(replace_text_in_nodes(t_nodes, engine, mapper))

                    # 2. Process DrawingML text nodes (<a:t>)
                    a_text_nodes = root.findall(".//a:t", NS)
                    if a_text_nodes:
                        audit.extend(replace_text_in_nodes(a_text_nodes, engine, mapper))

                    # 3. Process field code instructions (<w:instrText>) for mailto/hyperlinks
                    instr_nodes = root.findall(".//w:instrText", NS)
                    if instr_nodes:
                        audit.extend(replace_instr_text_nodes(instr_nodes, engine, mapper))

                    data = ET.tostring(root, encoding="utf-8", xml_declaration=True)
                except ET.ParseError:
                    pass

            elif is_rels:
                try:
                    root = ET.fromstring(data)
                    changed = False
                    for elem in root.iter():
                        target = elem.attrib.get("Target", "")
                        if "mailto:" in target or "@" in target:
                            for match in EMAIL_REGEX.finditer(target):
                                email = match.group(0)
                                fake_email = mapper.get("EMAIL", email)
                                target = target.replace(email, fake_email)
                                elem.attrib["Target"] = target
                                changed = True
                                audit.append({"type": "EMAIL", "replacement": fake_email, "detector": "rels_target"})
                    if changed:
                        data = ET.tostring(root, encoding="utf-8", xml_declaration=True)
                except ET.ParseError:
                    pass

            zout.writestr(item, data)

    return audit


# ---------------- PDF Document (.pdf) ----------------

def process_pdf(src: Path, dst: Path, engine: PIIEngine, mapper: SyntheticMapper) -> list[dict]:
    """
    Process text-based PDF using PyMuPDF:
    - Emits clear warning if PDF is scanned (no extractable text)
    - Applies actual PDF redactions removing underlying text
    - Inserts synthetic replacement text
    """
    doc = fitz.open(src)
    audit = []

    try:
        total_text_chars = sum(len(page.get_text("text").strip()) for page in doc)
        if total_text_chars == 0:
            print("\nWARNING: This appears to be an image/scanned PDF. OCR is not currently supported.", file=sys.stderr)
            doc.save(dst, garbage=4, deflate=True)
            return audit

        for page in doc:
            page_text = page.get_text("text")
            if not page_text.strip():
                continue

            entities = engine.detect(page_text)

            for e in entities:
                replacement = mapper.get(e.kind, e.text)
                rects = page.search_for(e.text)

                for rect in rects:
                    page.add_redact_annot(
                        rect,
                        text=replacement,
                        fontname="helv",
                        fontsize=max(6, min(12, rect.height * 0.75)),
                    )

                audit.append({
                    "type": e.kind,
                    "replacement": replacement,
                    "detector": e.detector
                })

            page.apply_redactions()

        doc.save(dst, garbage=4, deflate=True)
    finally:
        doc.close()

    return audit


# ---------------- Document Text Extraction & Validation ----------------

def extract_all_text(path: Path) -> str:
    """Extract all visible and structural text from .txt, .docx, or .pdf for validation."""
    suffix = path.suffix.lower()

    if suffix == ".txt":
        return path.read_text(encoding="utf-8", errors="replace")

    if suffix == ".docx":
        chunks = []
        with zipfile.ZipFile(path, "r") as z:
            for name in z.namelist():
                if name.startswith("word/") and name.endswith(".xml") and not name.endswith(".rels"):
                    try:
                        root = ET.fromstring(z.read(name))
                        for n in root.findall(".//w:t", NS):
                            if n.text:
                                chunks.append(n.text)
                        for n in root.findall(".//w:instrText", NS):
                            if n.text:
                                chunks.append(n.text)
                    except ET.ParseError:
                        pass
        return " ".join(chunks)

    if suffix == ".pdf":
        doc = fitz.open(path)
        try:
            return " ".join(page.get_text("text") for page in doc)
        finally:
            doc.close()

    return ""


def validate(path: Path, engine: PIIEngine) -> list[Entity]:
    """Run post-redaction validation scan on the sanitized output document."""
    extracted = extract_all_text(path)
    if not extracted.strip():
        return []
    return engine.detect(extracted)


# ---------------- Command Line Interface ----------------

def parse_args():
    parser = argparse.ArgumentParser(
        description="PII Document Anonymizer - Detect and replace PII with synthetic data."
    )
    parser.add_argument("input", type=Path, help="Input document path (.txt, .docx, .pdf)")
    parser.add_argument("-o", "--output", type=Path, help="Output redacted document path")
    parser.add_argument("--seed", type=int, help="Random seed for repeatable synthetic data")
    parser.add_argument("--min-score", type=float, default=0.55, help="Confidence threshold for Presidio (default: 0.55)")
    parser.add_argument("--report", type=Path, help="Optional JSON audit report output path")
    parser.add_argument("--no-validate", action="store_true", help="Skip post-redaction validation")
    parser.add_argument("--debug", action="store_true", help="Enable privacy-preserving debug logging")
    return parser.parse_args()


def main():
    args = parse_args()

    if not args.input.exists():
        print(f"ERROR: Input file '{args.input}' does not exist.", file=sys.stderr)
        return 2

    suffix = args.input.suffix.lower()
    if suffix not in SUPPORTED_EXTENSIONS:
        print(f"ERROR: Unsupported file type '{suffix}'. Supported types: {', '.join(sorted(SUPPORTED_EXTENSIONS))}", file=sys.stderr)
        return 2

    output = args.output or args.input.with_name(
        args.input.stem + "_redacted" + args.input.suffix
    )

    if output.resolve() == args.input.resolve():
        print("ERROR: Output path cannot overwrite the input path.", file=sys.stderr)
        return 2

    engine = PIIEngine(min_score=args.min_score, debug=args.debug)
    mapper = SyntheticMapper(seed=args.seed)

    print(f"\nProcessing: {args.input}")

    if suffix == ".txt":
        audit = process_txt(args.input, output, engine, mapper)
    elif suffix == ".docx":
        audit = process_docx(args.input, output, engine, mapper)
    else:
        audit = process_pdf(args.input, output, engine, mapper)

    counts = Counter(item["type"] for item in audit)

    print(f"Sanitized : {output}")
    print("\nSummary of detected & replaced PII entities:")
    if counts:
        for kind, count in sorted(counts.items()):
            print(f"  {kind:18} {count}")
    else:
        print("  No PII detected.")

    if args.report:
        report_data = {
            "input": str(args.input),
            "output": str(output),
            "total_entities_replaced": len(audit),
            "entity_counts": dict(counts),
        }
        args.report.write_text(json.dumps(report_data, indent=2), encoding="utf-8")
        print(f"\nAudit report saved to: {args.report}")

    if not args.no_validate:
        remaining = validate(output, engine)
        if remaining:
            print(f"\nVALIDATION: WARNING - {len(remaining)} potential remaining entity patterns detected.")
            print("(Note: Secondary scans may detect synthetic replacement names/companies as entity patterns)")
        else:
            print("\nVALIDATION: PASS - No remaining un-redacted PII detected.")

    print("\nProcessing complete.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
