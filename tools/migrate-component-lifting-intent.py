#!/usr/bin/env python3
"""Clean-cut a component catalog into canonical V5 lifting intent."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from spaghetti_extractor.components.lifting_intent import ComponentLiftingIntentV1
from spaghetti_extractor.util import write_json


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("paths", nargs="+", type=Path)
    arguments = parser.parse_args()
    for path in arguments.paths:
        payload = json.loads(path.read_text(encoding="utf-8"))
        if payload.get("format") == "spaghetti-extractor-component-lifting-intent-v1":
            ComponentLiftingIntentV1.parse(payload)
            continue
        components = []
        for row in payload["components"]:
            component = {"id": row["id"], "label": row["label"]}
            source = row.get("source")
            if source is not None:
                component["source"] = {
                    "files": [
                        value.removeprefix("source/") for value in source["files"]
                    ],
                    "shared_inputs": [
                        value.removeprefix("source/")
                        for value in source.get("shared_inputs", [])
                    ],
                    "operation_symbols": source["operations"],
                }
            if row.get("relation") is not None:
                component["relation_intent"] = row["relation"]
            if row.get("induction") is not None:
                component["induction_intent"] = row["induction"]
            components.append(component)
        groups = [
            {"id": row["id"], "label": row["label"], "members": row["members"]}
            for row in payload.get("groups", [])
        ]
        intent = ComponentLiftingIntentV1.create(
            program_id=payload["program_id"],
            components=components,
            groups=groups,
            configurations=payload["configurations"],
        )
        write_json(path, intent.to_payload())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
