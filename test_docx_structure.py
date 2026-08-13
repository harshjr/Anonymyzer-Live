# test_docx_structure.py
# Run:
#   python test_docx_structure.py "Red Herring Prospectus.docx"
#
# This only reports where visible text is stored. It does not modify the file.

import sys
import zipfile
import xml.etree.ElementTree as ET

W = "http://schemas.openxmlformats.org/wordprocessingml/2006/main"
NS = {"w": W}

path = sys.argv[1]

parts = 0
text_nodes = 0
chars = 0

with zipfile.ZipFile(path) as z:
    for name in z.namelist():
        if not name.startswith("word/") or not name.endswith(".xml"):
            continue
        if name.endswith(".rels"):
            continue
        try:
            root = ET.fromstring(z.read(name))
        except ET.ParseError:
            continue

        nodes = root.findall(".//w:t", NS)
        if nodes:
            parts += 1
            text_nodes += len(nodes)
            chars += sum(len(n.text or "") for n in nodes)

print("Word XML parts containing text:", parts)
print("w:t text nodes:", text_nodes)
print("characters:", chars)
