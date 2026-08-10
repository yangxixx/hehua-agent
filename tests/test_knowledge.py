"""Tests for the cross-challenge knowledge base."""
from hehua.core.knowledge import Knowledge, family_of


def test_family_of():
    assert family_of("c-04") == "c"
    assert family_of("e3-01") == "e3"
    assert family_of("f2-05") == "f2"
    assert family_of("a-16") == "a"
    assert family_of("xben-017") == "x"  # XBOW siblings grouped (mirrors scheduler)


def test_add_and_siblings(tmp_path):
    kb = Knowledge(tmp_path / "k.jsonl")
    kb.add("c-02", {"product": "GeoServer", "cve": "CVE-2024-36401",
                    "facts": ["unauth RCE via OGC filter"]})
    kb.add("a-01", {"product": "CMS", "facts": ["sqli in /api"]})
    kb.add("c-05", {"product": "Langflow", "cve": "CVE-2025-3248"})
    sib = kb.siblings("c")
    assert [e["code"] for e in sib] == ["c-02", "c-05"]
    assert kb.siblings("a")[0]["code"] == "a-01"


def test_intel_block_only_same_family(tmp_path):
    kb = Knowledge(tmp_path / "k.jsonl")
    kb.add("a-01", {"product": "CMS", "facts": ["x"]})
    kb.add("c-02", {"product": "GeoServer", "cve": "CVE-2024-36401"})
    block = kb.intel_block("c")
    assert block is not None and "GeoServer" in block and "c-02" in block
    assert "a-01" not in block  # different family must not leak
    assert kb.intel_block("d") is None  # no knowledge yet


def test_persists_across_instances(tmp_path):
    p = tmp_path / "k.jsonl"
    Knowledge(p).add("c-02", {"product": "GeoServer"})
    kb2 = Knowledge(p)  # reload from disk
    assert kb2.siblings("c")[0]["product"] == "GeoServer"


def test_empty_knowledge_safe(tmp_path):
    kb = Knowledge(tmp_path / "nope.jsonl")
    assert kb.intel_block("c") is None
    assert kb.siblings("c") == []
