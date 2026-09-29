"""The published index must only carry orderable versions (termograph spec D3/D4)."""

import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PATTERN = r"^[0-9]+\.[0-9]+(\.[0-9]+)?$"


def test_schema_constrains_version_to_the_orderable_pattern():
    schema = json.loads((ROOT / "index.schema.json").read_text(encoding="utf-8"))
    version = schema["properties"]["bundles"]["items"]["properties"]["version"]
    assert version.get("pattern") == PATTERN


def test_every_published_entry_satisfies_it():
    index = json.loads((ROOT / "index.json").read_text(encoding="utf-8"))
    bad = [e["id"] for e in index["bundles"] if not re.match(PATTERN, e["version"])]
    assert bad == [], f"entries with an unorderable version: {bad}"
