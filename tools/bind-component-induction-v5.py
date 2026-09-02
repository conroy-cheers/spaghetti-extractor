#!/usr/bin/env python3
"""Content-bind V5 machine intents to combined induction declarations."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from spaghetti_extractor.artifacts.artifact_set import canonical_sha256_v3
from spaghetti_extractor.components.binding_intent import (
    ComponentMachineBindingIntentV1,
)
from spaghetti_extractor.components.lifting_intent import ComponentLiftingIntentV1
from spaghetti_extractor.util import write_json


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--intent-root", type=Path, required=True)
    args = parser.parse_args()
    root = args.intent_root
    lifting = ComponentLiftingIntentV1.parse(json.loads(
        (root / "components.json").read_text(encoding="utf-8")
    ))
    declarations = {
        str(row["id"]): root / str(row["induction_intent"])
        for row in lifting.components
        if "induction_intent" in row
    }
    index_path = root / "bindings-v5/index.json"
    index = json.loads(index_path.read_text(encoding="utf-8"))
    for row in index.get("components", []):
        component_id = str(row["component_id"])
        declaration_path = declarations.get(component_id)
        if declaration_path is None:
            continue
        declaration = json.loads(declaration_path.read_text(encoding="utf-8"))
        declaration_sha256 = canonical_sha256_v3(declaration)
        binding_path = root / "bindings-v5" / str(row["binding_intent"])
        payload = json.loads(binding_path.read_text(encoding="utf-8"))
        operations = []
        for operation in payload["operations"]:
            operations.append({
                **operation,
                "induction_evidence_sha256": declaration_sha256,
            })
        binding = ComponentMachineBindingIntentV1.create(
            component_id=component_id,
            operations=operations,
            blockers=payload["blockers"],
        )
        write_json(binding_path, binding.to_payload())
        row["intent_sha256"] = binding.intent_sha256
    write_json(index_path, index)


if __name__ == "__main__":
    main()
