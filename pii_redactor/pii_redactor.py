import re
import ipaddress
import hashlib
from dataclasses import dataclass
from typing import List, Dict

import spacy
import phonenumbers
from faker import Faker


# ============================================================
# CONFIGURATION
# ============================================================

INPUT_FILE = "ticket_log.txt"
OUTPUT_FILE = "redacted_ticket.txt"

# Set to True if you want the same original value to always
# produce the same fake value across multiple executions.
DETERMINISTIC = False

# Seed Faker when deterministic behavior is wanted.
SEED = 12345


# ============================================================
# INITIALIZATION
# ============================================================

fake = Faker()

if DETERMINISTIC:
    Faker.seed(SEED)

try:
    nlp = spacy.load("en_core_web_sm")
except OSError:
    print(
        "\nspaCy model not found.\n"
        "Install it using:\n"
        "python -m spacy download en_core_web_sm\n"
    )
    raise


# ============================================================
# ENTITY DATA STRUCTURE
# ============================================================

@dataclass
class Entity:
    start: int
    end: int
    text: str
    entity_type: str
    priority: int


# ============================================================
# PII REGEX PATTERNS
# ============================================================

EMAIL_PATTERN = re.compile(
    r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"
)


# Supports common international phone formats.
PHONE_PATTERN = re.compile(
    r"""
    (?<!\w)
    (?:
        \+\d{1,3}[\s.-]?
    )?
    (?:
        \(\d{2,4}\)[\s.-]?
    )?
    \d{3,4}[\s.-]?\d{3,4}[\s.-]?\d{3,4}
    (?!\w)
    """,
    re.VERBOSE,
)


# US SSN
SSN_PATTERN = re.compile(
    r"(?<!\d)\d{3}[- ]\d{2}[- ]\d{4}(?!\d)"
)


# Credit cards:
# 13-19 digits, optionally separated by spaces or hyphens.
CREDIT_CARD_PATTERN = re.compile(
    r"(?<!\d)(?:\d[ -]?){13,19}(?!\d)"
)


# IPv4
IPV4_PATTERN = re.compile(
    r"\b(?:\d{1,3}\.){3}\d{1,3}\b"
)


# IPv6 - simplified pattern
IPV6_PATTERN = re.compile(
    r"(?<![\w:])"
    r"(?:[0-9A-Fa-f]{1,4}:){2,7}"
    r"[0-9A-Fa-f]{1,4}"
    r"(?![\w:])"
)


# Dates that are explicitly connected to DOB.
DOB_PATTERN = re.compile(
    r"""
    (?:
        date\s+of\s+birth |
        dob |
        born\s+(?:on)?
    )
    \s*[:\-]?\s*
    (
        \d{1,4}[/-]\d{1,2}[/-]\d{1,4}
        |
        \d{1,2}\s+[A-Za-z]+\s+\d{2,4}
        |
        [A-Za-z]+\s+\d{1,2},?\s+\d{2,4}
    )
    """,
    re.IGNORECASE | re.VERBOSE,
)


# Address-like text following common address labels.
ADDRESS_PATTERN = re.compile(
    r"""
    (?:
        address |
        mailing\s+address |
        home\s+address |
        residential\s+address |
        street\s+address
    )
    \s*[:\-]\s*
    (
        [^\n]{5,150}
    )
    """,
    re.IGNORECASE | re.VERBOSE,
)


# ============================================================
# VALIDATION FUNCTIONS
# ============================================================

def is_valid_ipv4(value: str) -> bool:
    """Check whether a value is actually a valid IPv4 address."""

    try:
        ipaddress.IPv4Address(value)
        return True
    except ValueError:
        return False


def is_valid_ipv6(value: str) -> bool:
    """Check whether a value is actually a valid IPv6 address."""

    try:
        ipaddress.IPv6Address(value)
        return True
    except ValueError:
        return False


def luhn_check(number: str) -> bool:
    """
    Validate credit card numbers using the Luhn algorithm.
    """

    digits = re.sub(r"\D", "", number)

    if not 13 <= len(digits) <= 19:
        return False

    total = 0
    reverse_digits = digits[::-1]

    for index, digit in enumerate(reverse_digits):
        value = int(digit)

        if index % 2 == 1:
            value *= 2

            if value > 9:
                value -= 9

        total += value

    return total % 10 == 0


def normalize(value: str) -> str:
    """
    Normalize an entity before using it as a dictionary key.
    """

    return re.sub(r"\s+", " ", value.strip().lower())


# ============================================================
# ENTITY DETECTION
# ============================================================

class PIIDetector:

    def __init__(self):
        self.entities: List[Entity] = []

    def add_entity(
        self,
        start: int,
        end: int,
        text: str,
        entity_type: str,
        priority: int
    ):
        if start >= end:
            return

        self.entities.append(
            Entity(
                start=start,
                end=end,
                text=text,
                entity_type=entity_type,
                priority=priority
            )
        )

    # --------------------------------------------------------
    # EMAIL
    # --------------------------------------------------------

    def detect_emails(self, text: str):

        for match in EMAIL_PATTERN.finditer(text):

            self.add_entity(
                match.start(),
                match.end(),
                match.group(),
                "EMAIL",
                100
            )

    # --------------------------------------------------------
    # PHONE
    # --------------------------------------------------------

    def detect_phones(self, text: str):

        for match in PHONE_PATTERN.finditer(text):

            value = match.group().strip()

            # Avoid interpreting very short numbers as phones.
            digits = re.sub(r"\D", "", value)

            if len(digits) < 10:
                continue

            self.add_entity(
                match.start(),
                match.end(),
                value,
                "PHONE",
                90
            )

    # --------------------------------------------------------
    # SSN
    # --------------------------------------------------------

    def detect_ssn(self, text: str):

        for match in SSN_PATTERN.finditer(text):

            self.add_entity(
                match.start(),
                match.end(),
                match.group(),
                "SSN",
                100
            )

    # --------------------------------------------------------
    # CREDIT CARD
    # --------------------------------------------------------

    def detect_credit_cards(self, text: str):

        for match in CREDIT_CARD_PATTERN.finditer(text):

            value = match.group()

            if luhn_check(value):

                self.add_entity(
                    match.start(),
                    match.end(),
                    value,
                    "CREDIT_CARD",
                    100
                )

    # --------------------------------------------------------
    # IP ADDRESS
    # --------------------------------------------------------

    def detect_ips(self, text: str):

        for match in IPV4_PATTERN.finditer(text):

            value = match.group()

            if is_valid_ipv4(value):

                self.add_entity(
                    match.start(),
                    match.end(),
                    value,
                    "IP_ADDRESS",
                    100
                )

        for match in IPV6_PATTERN.finditer(text):

            value = match.group()

            if is_valid_ipv6(value):

                self.add_entity(
                    match.start(),
                    match.end(),
                    value,
                    "IP_ADDRESS",
                    100
                )

    # --------------------------------------------------------
    # DATE OF BIRTH
    # --------------------------------------------------------

    def detect_dob(self, text: str):

        for match in DOB_PATTERN.finditer(text):

            # The actual date is capture group 1.
            date_text = match.group(1)

            start = match.start(1)
            end = match.end(1)

            self.add_entity(
                start,
                end,
                date_text,
                "DATE_OF_BIRTH",
                95
            )

    # --------------------------------------------------------
    # ADDRESS
    # --------------------------------------------------------

    def detect_addresses(self, text: str):

        for match in ADDRESS_PATTERN.finditer(text):

            address = match.group(1).strip()

            start = match.start(1)
            end = match.end(1)

            self.add_entity(
                start,
                end,
                address,
                "ADDRESS",
                85
            )

    # --------------------------------------------------------
    # NER
    # --------------------------------------------------------

    def detect_ner(self, text: str):

        doc = nlp(text)

        for ent in doc.ents:

            # PERSON = person's name
            if ent.label_ == "PERSON":

                self.add_entity(
                    ent.start_char,
                    ent.end_char,
                    ent.text,
                    "PERSON",
                    80
                )

            # ORG = company/organization
            elif ent.label_ == "ORG":

                self.add_entity(
                    ent.start_char,
                    ent.end_char,
                    ent.text,
                    "COMPANY",
                    70
                )

            # GPE/LOC can sometimes represent locations.
            # We don't automatically redact every location because
            # cities/countries are not necessarily PII.
            #
            # Instead, addresses are handled separately.
            elif ent.label_ in {"FAC"}:

                self.add_entity(
                    ent.start_char,
                    ent.end_char,
                    ent.text,
                    "ADDRESS",
                    60
                )

    # --------------------------------------------------------
    # RUN ALL DETECTORS
    # --------------------------------------------------------

    def detect(self, text: str) -> List[Entity]:

        self.entities = []

        self.detect_emails(text)
        self.detect_phones(text)
        self.detect_ssn(text)
        self.detect_credit_cards(text)
        self.detect_ips(text)
        self.detect_dob(text)
        self.detect_addresses(text)
        self.detect_ner(text)

        return self.resolve_overlaps(self.entities)

    # --------------------------------------------------------
    # OVERLAPPING ENTITY RESOLUTION
    # --------------------------------------------------------

    @staticmethod
    def resolve_overlaps(entities: List[Entity]) -> List[Entity]:

        # Highest priority first.
        entities = sorted(
            entities,
            key=lambda e: (
                -e.priority,
                -(e.end - e.start)
            )
        )

        selected = []

        for entity in entities:

            overlaps = False

            for existing in selected:

                if (
                    entity.start < existing.end
                    and entity.end > existing.start
                ):
                    overlaps = True
                    break

            if not overlaps:
                selected.append(entity)

        return sorted(
            selected,
            key=lambda e: e.start
        )


# ============================================================
# SYNTHETIC DATA GENERATOR
# ============================================================

class SyntheticDataGenerator:

    def __init__(self):

        self.fake = fake

        self.mappings: Dict[str, str] = {}

        self.person_counter = 0
        self.email_counter = 0
        self.phone_counter = 0
        self.company_counter = 0

    # --------------------------------------------------------
    # MAPPING KEY
    # --------------------------------------------------------

    def make_key(self, entity_type: str, value: str) -> str:

        return f"{entity_type}:{normalize(value)}"

    # --------------------------------------------------------
    # GET EXISTING OR CREATE NEW
    # --------------------------------------------------------

    def get_or_create(self, entity_type: str, value: str) -> str:

        key = self.make_key(entity_type, value)

        if key in self.mappings:
            return self.mappings[key]

        replacement = self.generate(entity_type)

        self.mappings[key] = replacement

        return replacement

    # --------------------------------------------------------
    # GENERATE SYNTHETIC DATA
    # --------------------------------------------------------

    def generate(self, entity_type: str) -> str:

        if entity_type == "PERSON":

            return self.fake.name()

        if entity_type == "EMAIL":

            return self.fake.email()

        if entity_type == "PHONE":

            return "+1 " + self.fake.numerify("###-###-####")

        if entity_type == "COMPANY":

            return self.fake.company()

        if entity_type == "ADDRESS":

            return self.fake.address().replace("\n", ", ")

        if entity_type == "SSN":

            return self.fake.ssn()

        if entity_type == "CREDIT_CARD":

            return self.fake.credit_card_number()

        if entity_type == "DATE_OF_BIRTH":

            return self.fake.date_of_birth().strftime("%Y-%m-%d")

        if entity_type == "IP_ADDRESS":

            return self.fake.ipv4()

        return "[REDACTED]"


# ============================================================
# REDACTOR
# ============================================================

class PIIRedactor:

    def __init__(self):

        self.detector = PIIDetector()
        self.generator = SyntheticDataGenerator()

    def redact(self, text: str):

        entities = self.detector.detect(text)

        # Process from right to left.
        #
        # This is extremely important because replacing text from
        # left to right would change the character positions of
        # entities that appear later in the document.
        entities = sorted(
            entities,
            key=lambda e: e.start,
            reverse=True
        )

        redacted_text = text

        replacement_log = []

        for entity in entities:

            replacement = self.generator.get_or_create(
                entity.entity_type,
                entity.text
            )

            redacted_text = (
                redacted_text[:entity.start]
                + replacement
                + redacted_text[entity.end:]
            )

            replacement_log.append({
                "type": entity.entity_type,
                "original": entity.text,
                "replacement": replacement
            })

        return redacted_text, replacement_log


# ============================================================
# VALIDATION
# ============================================================

def validate_redacted_text(text: str):

    detector = PIIDetector()

    remaining = detector.detect(text)

    return remaining


# ============================================================
# PRINT REPORT
# ============================================================

def print_report(replacement_log):

    print("\n" + "=" * 70)
    print("PII REPLACEMENT REPORT")
    print("=" * 70)

    if not replacement_log:

        print("No PII detected.")

        return

    # Remove duplicate mappings for display.
    seen = set()

    for item in reversed(replacement_log):

        key = (
            item["type"],
            normalize(item["original"])
        )

        if key in seen:
            continue

        seen.add(key)

        print(
            f'{item["type"]:15} '
            f'{item["original"]}  ->  {item["replacement"]}'
        )

    print("=" * 70)
    print(f"Unique PII values replaced: {len(seen)}")


# ============================================================
# MAIN
# ============================================================

def main():

    print("=" * 70)
    print("PII TICKET LOG ANONYMIZER")
    print("=" * 70)

    # --------------------------------------------------------
    # READ INPUT
    # --------------------------------------------------------

    try:

        with open(
            INPUT_FILE,
            "r",
            encoding="utf-8"
        ) as file:

            text = file.read()

    except FileNotFoundError:

        print(f"\nInput file not found: {INPUT_FILE}")
        return

    print(f"\nInput file : {INPUT_FILE}")
    print(f"Characters : {len(text):,}")

    # --------------------------------------------------------
    # REDACT
    # --------------------------------------------------------

    redactor = PIIRedactor()

    redacted_text, replacement_log = redactor.redact(text)

    # --------------------------------------------------------
    # WRITE OUTPUT
    # --------------------------------------------------------

    with open(
        OUTPUT_FILE,
        "w",
        encoding="utf-8"
    ) as file:

        file.write(redacted_text)

    # --------------------------------------------------------
    # REPORT
    # --------------------------------------------------------

    print_report(replacement_log)

    print(f"\nOutput file: {OUTPUT_FILE}")

    # --------------------------------------------------------
    # VALIDATION
    # --------------------------------------------------------

    print("\nRunning validation...")

    remaining = validate_redacted_text(redacted_text)

    if remaining:

        print("\nWARNING: Possible PII still remains!")

        for entity in remaining:

            print(
                f"  {entity.entity_type}: "
                f"{entity.text}"
            )

    else:

        print("Validation PASSED.")
        print("No detected PII remains.")

    print("\nDone.")


if __name__ == "__main__":
    main()
