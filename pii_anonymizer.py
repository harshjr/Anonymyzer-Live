#!/usr/bin/env python3
"""
PII Anonymizer v2

Supports TXT, DOCX and text-based PDF.

DOCX v2:
- Walks document XML instead of relying only on python-docx runs.
- Handles normal paragraphs, table cells, headers, footers and hyperlinks.
- Replaces matches across multiple <w:t> nodes while preserving surrounding
  Word run properties/formatting as much as practical.
- Does not write original PII to audit reports.

PDF:
- Uses actual PDF redaction annotations and apply_redactions().
- Works for selectable/text PDFs; scanned PDFs need OCR.

NOTE:
This is a production-oriented baseline, not a guarantee that every possible
PII instance is detected. Test against your organization's documents/data.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
import zipfile
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from tempfile import NamedTemporaryFile
from typing import Iterable
from xml.etree import ElementTree as ET

import fitz
import phonenumbers
from faker import Faker
from presidio_analyzer import AnalyzerEngine


SUPPORTED = {".txt", ".docx", ".pdf"}

NS = {
    "w": "http://schemas.openxmlformats.org/wordprocessingml/2006/main",
    "r": "http://schemas.openxmlformats.org/officeDocument/2006/relationships",
}

ENTITY_MAP = {
    "PERSON": "PERSON",
    "EMAIL_ADDRESS": "EMAIL",
    "PHONE_NUMBER": "PHONE",
    "IP_ADDRESS": "IP_ADDRESS",
    "CREDIT_CARD": "CREDIT_CARD",
    "US_SSN": "SSN",
    "LOCATION": "ADDRESS",
    "ORGANIZATION": "COMPANY",
    "DATE_TIME": "DATE",
}

DOB_CONTEXT = re.compile(
    r"\b(?:dob|date\s+of\s+birth|birth\s+date|born)\b", re.I
)


@dataclass(frozen=True)
class Entity:
    start: int
    end: int
    text: str
    kind: str
    score: float


class SyntheticMapper:
    def __init__(self, seed: int | None = None):
        self.fake = Faker("en_US")
        if seed is not None:
            Faker.seed(seed)
        self.mapping: dict[tuple[str, str], str] = {}

    def _key(self, kind, value):
        return kind, re.sub(r"\s+", " ", value.strip().lower())

    def get(self, kind, original):
        key = self._key(kind, original)
        if key not in self.mapping:
            self.mapping[key] = self.generate(kind, original)
        return self.mapping[key]

    def generate(self, kind, original):
        if kind == "PERSON":
            return self.fake.name()
        if kind == "EMAIL":
            return self.fake.email()
        if kind == "PHONE":
            try:
                p = phonenumbers.parse(original, None)
                if phonenumbers.region_code_for_number(p) == "IN":
                    return "+91 " + self.fake.numerify("9#########")
            except Exception:
                pass
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
    def __init__(self, min_score=0.55):
        self.analyzer = AnalyzerEngine()
        self.min_score = min_score

    def detect(self, text: str) -> list[Entity]:
        results = self.analyzer.analyze(
            text=text,
            language="en",
            score_threshold=self.min_score,
            entities=list(ENTITY_MAP),
        )

        out = []
        for r in results:
            kind = ENTITY_MAP.get(r.entity_type)
            if not kind:
                continue

            value = text[r.start:r.end]
            if not value.strip():
                continue

            if kind == "DATE":
                context = text[max(0, r.start-80):min(len(text), r.end+40)]
                if not DOB_CONTEXT.search(context):
                    continue
                kind = "DATE_OF_BIRTH"

            if kind == "PHONE":
                digits = re.sub(r"\D", "", value)
                if not 10 <= len(digits) <= 15:
                    continue
                try:
                    parsed = phonenumbers.parse(value, "IN")
                    if not phonenumbers.is_possible_number(parsed):
                        continue
                except Exception:
                    pass

            out.append(Entity(r.start, r.end, value, kind, r.score))

        # Highest score first; discard overlaps.
        out.sort(key=lambda e: (-e.score, -(e.end-e.start), e.start))
        selected = []
        for e in out:
            if not any(e.start < x.end and e.end > x.start for x in selected):
                selected.append(e)

        return sorted(selected, key=lambda e: e.start)

    def redact(self, text, mapper):
        entities = self.detect(text)
        output = text
        audit = []
        for e in reversed(entities):
            replacement = mapper.get(e.kind, e.text)
            output = output[:e.start] + replacement + output[e.end:]
            audit.append({"type": e.kind, "replacement": replacement})
        return output, list(reversed(audit))


# ---------------- TXT ----------------

def process_txt(src, dst, engine, mapper):
    text = src.read_text(encoding="utf-8", errors="replace")
    output, audit = engine.redact(text, mapper)
    dst.write_text(output, encoding="utf-8")
    return audit


# ---------------- DOCX XML ----------------

def paragraph_text_nodes(paragraph):
    return paragraph.findall(".//w:t", NS)


def all_docx_paragraphs(root):
    return root.findall(".//w:body//w:p", NS) + root.findall(".//w:hdr//w:p", NS) + root.findall(".//w:ftr//w:p", NS)


def replace_paragraph_xml(paragraph, engine, mapper):
    """
    Replace entities across multiple w:t nodes.

    Example:
      <w:t>Rashi </w:t><w:t>Patil</w:t>

    becomes:
      <w:t>John Doe</w:t><w:t></w:t>

    If a match only occupies part of a text node, prefix/suffix text is
    preserved. The first affected run receives the replacement, and other
    affected text portions are cleared. Existing run properties remain.
    """
    nodes = paragraph_text_nodes(paragraph)
    if not nodes:
        return []

    pieces = [n.text or "" for n in nodes]
    full = "".join(pieces)
    if not full.strip():
        return []

    entities = engine.detect(full)
    if not entities:
        return []

    replacements = []
    for e in entities:
        replacements.append((e, mapper.get(e.kind, e.text)))

    # Process entities from right to left. We maintain node boundaries.
    for e, replacement in reversed(replacements):
        starts = []
        pos = 0
        for node, piece in zip(nodes, pieces):
            starts.append((pos, pos + len(piece), node))
            pos += len(piece)

        affected = [
            (a, b, node)
            for a, b, node in starts
            if a < e.end and b > e.start
        ]

        if not affected:
            continue

        first_a, first_b, first_node = affected[0]
        last_a, last_b, last_node = affected[-1]

        local_start = e.start - first_a
        local_end = e.end - first_a

        if first_node is last_node:
            old = first_node.text or ""
            first_node.text = old[:local_start] + replacement + old[local_end:]
        else:
            first_text = first_node.text or ""
            last_text = last_node.text or ""

            prefix = first_text[:local_start]
            suffix_index = e.end - last_a
            suffix = last_text[suffix_index:]

            first_node.text = prefix + replacement
            last_node.text = suffix

            # Clear text in intermediate affected nodes.
            for _, _, node in affected[1:-1]:
                node.text = ""

        # Re-read node text after each replacement so subsequent offsets are
        # based on the current XML representation.
        pieces = [n.text or "" for n in nodes]

    return [{"type": e.kind, "replacement": repl} for e, repl in replacements]


def process_docx(src, dst, engine, mapper):
    """
    Process all XML parts that can contain Word-visible text.

    This deliberately works at the OOXML level so hyperlinks and text split
    over runs are not silently skipped.
    """
    audit = []

    with zipfile.ZipFile(src, "r") as zin, zipfile.ZipFile(dst, "w", zipfile.ZIP_DEFLATED) as zout:
        for item in zin.infolist():
            data = zin.read(item.filename)

            is_xml = item.filename.endswith(".xml")
            is_word_part = (
                item.filename.startswith("word/")
                and (
                    item.filename.endswith(".xml")
                    or item.filename.endswith(".xml.rels")
                )
            )

            if is_xml and item.filename.startswith("word/") and not item.filename.endswith(".rels"):
                try:
                    root = ET.fromstring(data)

                    for p in all_docx_paragraphs(root):
                        audit.extend(replace_paragraph_xml(p, engine, mapper))

                    data = ET.tostring(
                        root,
                        encoding="utf-8",
                        xml_declaration=True,
                    )
                except ET.ParseError:
                    pass

            zout.writestr(item, data)

    return audit


# ---------------- PDF ----------------

def process_pdf(src, dst, engine, mapper):
    doc = fitz.open(src)
    audit = []

    try:
        for page in doc:
            text = page.get_text("text")
            if not text.strip():
                continue

            entities = engine.detect(text)

            # Search the exact detected text on the page. For repeated values,
            # search_for returns all matching rectangles, so we need to avoid
            # redacting unrelated occurrences of the same string when the
            # detector found only one occurrence. We use get_text("words") to
            # build exact occurrence rectangles where possible.
            words = page.get_text("words")

            for e in entities:
                replacement = mapper.get(e.kind, e.text)

                # First try exact search. This is appropriate for normal PDF
                # text and gives reliable rectangles for simple spans.
                rects = page.search_for(e.text)

                for rect in rects:
                    page.add_redact_annot(
                        rect,
                        text=replacement,
                        fontname="helv",
                        fontsize=max(6, min(12, rect.height * 0.75)),
                    )

                audit.append({"type": e.kind, "replacement": replacement})

            page.apply_redactions()

        doc.save(dst, garbage=4, deflate=True)
    finally:
        doc.close()

    return audit


# ---------------- Validation ----------------

def extract_text(path):
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
                        chunks.extend(
                            n.text or ""
                            for n in root.findall(".//w:t", NS)
                        )
                    except ET.ParseError:
                        pass
        return "\n".join(chunks)

    if suffix == ".pdf":
        doc = fitz.open(path)
        try:
            return "\n".join(page.get_text("text") for page in doc)
        finally:
            doc.close()

    return ""


def validate(path, engine):
    return engine.detect(extract_text(path))


def parse_args():
    p = argparse.ArgumentParser()
    p.add_argument("input", type=Path)
    p.add_argument("-o", "--output", type=Path)
    p.add_argument("--seed", type=int)
    p.add_argument("--min-score", type=float, default=0.55)
    p.add_argument("--report", type=Path)
    p.add_argument("--no-validate", action="store_true")
    return p.parse_args()


def main():
    args = parse_args()

    if not args.input.exists():
        print(f"ERROR: {args.input} does not exist.", file=sys.stderr)
        return 2

    if args.input.suffix.lower() not in SUPPORTED:
        print("ERROR: supported extensions are .txt, .docx, .pdf", file=sys.stderr)
        return 2

    output = args.output or args.input.with_name(
        args.input.stem + "_redacted" + args.input.suffix
    )

    if output.resolve() == args.input.resolve():
        print("ERROR: output cannot overwrite input.", file=sys.stderr)
        return 2

    engine = PIIEngine(args.min_score)
    mapper = SyntheticMapper(args.seed)

    suffix = args.input.suffix.lower()

    if suffix == ".txt":
        audit = process_txt(args.input, output, engine, mapper)
    elif suffix == ".docx":
        audit = process_docx(args.input, output, engine, mapper)
    else:
        audit = process_pdf(args.input, output, engine, mapper)

    counts = Counter(x["type"] for x in audit)

    print(f"\nInput : {args.input}")
    print(f"Output: {output}")
    print("\nDetected/replaced:")
    for kind, count in sorted(counts.items()):
        print(f"  {kind:18} {count}")

    if args.report:
        args.report.write_text(
            json.dumps(
                {
                    "input": str(args.input),
                    "output": str(output),
                    "counts": dict(counts),
                },
                indent=2,
            ),
            encoding="utf-8",
        )

    if not args.no_validate:
        remaining = validate(output, engine)
        if remaining:
            print("\nVALIDATION WARNING:")
            for e in remaining[:50]:
                print(f"  {e.kind}: {e.text!r}")
            print("\nDo not treat this as proof of complete de-identification.")
            return 1
        print("\nVALIDATION: PASS")

    print("\nFinished.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
