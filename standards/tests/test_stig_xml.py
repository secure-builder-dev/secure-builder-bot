"""standards/scripts/build-stig-index.py:safe_root — a downloaded STIG is untrusted XML.

Both STIG readers parse through safe_root, which refuses a document that declares a DTD, so no
entity is ever expanded (semgrep use-defused-xml-parse, found once check-full's semgrep ran).
"""

import importlib.util
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location("bsi", ROOT / "standards" / "scripts" / "build-stig-index.py")
bsi = importlib.util.module_from_spec(spec)
spec.loader.exec_module(bsi)

XCCDF = ('<?xml version="1.0"?><Benchmark xmlns="http://checklists.nist.gov/xccdf/1.1">'
         '<Rule id="r1"><version>APSC-DV-000010</version><title>Limit sessions</title></Rule></Benchmark>')


def write(tmp_path: Path, data: bytes) -> Path:
    p = tmp_path / "stig.xml"
    p.write_bytes(data)
    return p


def test_a_plain_xccdf_document_parses(tmp_path):
    root = bsi.safe_root(write(tmp_path, XCCDF.encode()))
    assert root is not None and root.tag.endswith("Benchmark")
    assert list(bsi.rules(write(tmp_path, XCCDF.encode()))) == [("APSC-DV-000010", "Limit sessions")]


def test_an_external_entity_is_refused_before_anything_resolves_it(tmp_path):
    xxe = b'<?xml version="1.0"?><!DOCTYPE b [<!ENTITY x SYSTEM "file:///etc/passwd">]><b>&x;</b>'
    assert bsi.safe_root(write(tmp_path, xxe)) is None


def test_an_entity_bomb_is_refused(tmp_path):
    bomb = (b'<?xml version="1.0"?><!DOCTYPE b [<!ENTITY a "aaaaaaaaaa">'
            + b"".join(f'<!ENTITY {chr(98 + i)} "{("&" + chr(97 + i) + ";") * 10}">'.encode() for i in range(8))
            + b"]><b>&i;</b>")
    assert bsi.safe_root(write(tmp_path, bomb)) is None


def test_a_dtd_in_utf16_is_refused_too(tmp_path):
    doc = '<?xml version="1.0" encoding="UTF-16"?><!DOCTYPE b [<!ENTITY x "y">]><b>&x;</b>'
    assert bsi.safe_root(write(tmp_path, doc.encode("utf-16"))) is None


def test_a_document_that_is_not_xml_is_none_not_a_crash(tmp_path):
    assert bsi.safe_root(write(tmp_path, b"<b><unclosed></b>")) is None
    assert list(bsi.rules(write(tmp_path, b"not xml"))) == []
