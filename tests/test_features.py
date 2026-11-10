import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from main import FEATURES, parse_features


def test_parse_features_keeps_all_valid():
    assert parse_features("secretscanning,codescanning,dependabot") == [
        "secretscanning",
        "codescanning",
        "dependabot",
    ]


def test_parse_features_drops_every_invalid(capsys):
    # Regression test: the old implementation removed entries from the list
    # while iterating over it, so consecutive invalid names were skipped and
    # kept (e.g. "nope1,nope2,secretscanning" kept "nope2").
    assert parse_features("nope1,nope2,secretscanning") == ["secretscanning"]
    out = capsys.readouterr().out
    assert "Invalid feature: nope1" in out
    assert "Invalid feature: nope2" in out


def test_parse_features_all_invalid():
    assert parse_features("nope1,nope2") == []


def test_features_constant_unchanged():
    assert FEATURES == ["secretscanning", "codescanning", "dependabot"]
