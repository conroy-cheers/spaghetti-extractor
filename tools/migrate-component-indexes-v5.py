#!/usr/bin/env python3
"""Rewrite target component input indexes into canonical content-bound V5 form."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from spaghetti_extractor.components.indexes_v5 import ComponentIntentIndexV5
from spaghetti_extractor.util import write_json


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("roots", nargs="+", type=Path)
    arguments = parser.parse_args()
    for target_root in arguments.roots:
        for relative, kind in (
            (Path("interfaces-v5/index.json"), "interface"),
            (Path("bindings-v5/index.json"), "machine_binding"),
        ):
            path = target_root / relative
            payload = json.loads(path.read_text(encoding="utf-8"))
            index = ComponentIntentIndexV5.create(
                kind=kind,
                components=payload.get("components", []),
                blockers=payload.get("blockers", []),
            )
            write_json(path, index.to_payload())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
