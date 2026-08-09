"""paramgen: compound API param names must cover the a-14 lesson."""
import importlib.util
from pathlib import Path

_SPEC = importlib.util.spec_from_file_location(
    "paramgen", Path(__file__).resolve().parents[1] / "scripts" / "paramgen.py")
_pg = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(_pg)


def test_covers_a14_compound():
    names = _pg.generate()
    # the exact param that cost a-14 in run-6661, plus common variants
    for probe in ("target_endpoint", "targetEndpoint", "target_url",
                  "remote_endpoint", "source_url", "import_endpoint",
                  "fetch_endpoint", "callback_url", "dest_endpoint"):
        assert probe in names, probe


def test_seeds_ranked_first():
    names = _pg.generate()
    # cheap one-word names come before the compound long tail
    for seed in ("url", "uri", "target", "endpoint"):
        assert names.index(seed) < len(_pg.SEEDS)


def test_unique_and_truncatable():
    names = _pg.generate()
    assert len(names) == len(set(names))
    assert len(_pg.generate()) >= 200  # enough long tail to brute-force
    assert len(names[:120]) == 120     # --n truncation is safe
