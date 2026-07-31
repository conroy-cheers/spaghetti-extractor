#!/usr/bin/env python3
"""Bind generated Lean terms to exact source and compiled `.olean` hashes."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any, Mapping


REQUEST_FORMAT = "stage-a-lean-kernel-check-requests-v1"
RECEIPT_FORMAT = "stage-a-lean-kernel-check-receipts-v1"


def _load_object(path: Path, description: str) -> Mapping[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, Mapping):
        raise ValueError(f"{description} is not an object")
    return value


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _term(value: object, index: int) -> dict[str, str]:
    if not isinstance(value, Mapping):
        raise ValueError(f"kernel-check request {index} term is not an object")
    result: dict[str, str] = {}
    for field in ("module", "namespace", "symbol"):
        item = value.get(field)
        if not isinstance(item, str) or not item:
            raise ValueError(
                f"kernel-check request {index} term has no {field}"
            )
        result[field] = item
    if not result["module"].startswith("StageA."):
        raise ValueError(
            f"kernel-check request {index} module is outside StageA"
        )
    if set(value) != set(result):
        raise ValueError(
            f"kernel-check request {index} term has unknown fields"
        )
    return result


def create_receipts(
    *,
    bundle_path: Path,
    source_root: Path,
    requests_path: Path,
) -> dict[str, Any]:
    bundle = _load_object(bundle_path, "Lean target bundle")
    if bundle.get("format") != "stage-a-lean-target-bundle-v2":
        raise ValueError("Lean target bundle has the wrong format")
    requests = _load_object(requests_path, "kernel-check request inventory")
    if requests.get("format") != REQUEST_FORMAT:
        raise ValueError("kernel-check request inventory has the wrong format")
    rows = requests.get("requests")
    if not isinstance(rows, list):
        raise ValueError("kernel-check request inventory has no request list")

    outputs: dict[str, list[Mapping[str, Any]]] = {}
    node_rows = bundle.get("nodes")
    if not isinstance(node_rows, list):
        raise ValueError("Lean target bundle has no node inventory")
    for node_index, node in enumerate(node_rows):
        if not isinstance(node, Mapping):
            raise ValueError(f"Lean target bundle node {node_index} is invalid")
        output_rows = node.get("outputs")
        if not isinstance(output_rows, list):
            raise ValueError(
                f"Lean target bundle node {node_index} has no outputs"
            )
        for output_index, output in enumerate(output_rows):
            if not isinstance(output, Mapping):
                raise ValueError(
                    f"Lean target bundle node {node_index} output "
                    f"{output_index} is invalid"
                )
            module = output.get("module")
            if not isinstance(module, str) or not module:
                raise ValueError("Lean target bundle output has no module")
            outputs.setdefault(module, []).append(output)

    receipts: dict[str, Any] = {}
    terms_seen: set[tuple[str, str, str]] = set()
    for index, row in enumerate(rows):
        if not isinstance(row, Mapping) or set(row) != {"term"}:
            raise ValueError(
                f"kernel-check request {index} must contain exactly one term"
            )
        term = _term(row["term"], index)
        term_key = (term["module"], term["namespace"], term["symbol"])
        if term_key in terms_seen:
            raise ValueError("kernel-check request inventory duplicates a term")
        terms_seen.add(term_key)

        short_module = term["module"].removeprefix("StageA.")
        source = source_root / "StageA" / f"{short_module}.lean"
        if not source.is_file():
            raise ValueError(
                f"kernel-check source is missing for {term['module']}"
            )
        matching = outputs.get(short_module, [])
        if len(matching) != 1:
            raise ValueError(
                f"compiled output for {term['module']} is absent or ambiguous"
            )
        output = matching[0]
        olean_sha256 = output.get("olean_sha256")
        if (
            not isinstance(olean_sha256, str)
            or len(olean_sha256) != 64
            or any(
                character not in "0123456789abcdef"
                for character in olean_sha256
            )
        ):
            raise ValueError(
                f"compiled output for {term['module']} has no valid hash"
            )
        audit = output.get("axiom_audit")
        inventories = (
            audit.get("inventories")
            if isinstance(audit, Mapping)
            else None
        )
        if not isinstance(inventories, Mapping):
            raise ValueError(
                f"compiled output for {term['module']} has no term audit"
            )
        qualified = f"{term['namespace']}.{term['symbol']}"
        audited = [
            value
            for declaration, value in inventories.items()
            if (
                declaration == term["symbol"]
                or declaration == qualified
                or qualified.endswith(f".{declaration}")
            )
        ]
        if len(audited) != 1 or audited[0] is None:
            raise ValueError(
                f"compiled output did not audit {qualified}"
            )
        prior = receipts.get(term["module"])
        if prior is None:
            receipts[term["module"]] = {
                "module": term["module"],
                "olean_sha256": olean_sha256,
                "source_sha256": _sha256(source),
                "status": "checked",
                "terms": [term],
            }
        else:
            if (
                prior["olean_sha256"] != olean_sha256
                or prior["source_sha256"] != _sha256(source)
            ):
                raise ValueError(
                    "one generated module has inconsistent compiled evidence"
                )
            prior["terms"].append(term)

    for receipt in receipts.values():
        receipt["terms"] = sorted(
            receipt["terms"],
            key=lambda term: (
                term["namespace"],
                term["symbol"],
            ),
        )
        if len(receipt["terms"]) == 1:
            receipt["term"] = receipt["terms"][0]

    return {
        "format": RECEIPT_FORMAT,
        "bundle_sha256": _sha256(bundle_path),
        "requests_sha256": _sha256(requests_path),
        "receipts": receipts,
        "status": "checked",
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--bundle", required=True)
    parser.add_argument("--source-root", required=True)
    parser.add_argument("--requests", required=True)
    parser.add_argument("--out", required=True)
    arguments = parser.parse_args()
    result = create_receipts(
        bundle_path=Path(arguments.bundle),
        source_root=Path(arguments.source_root),
        requests_path=Path(arguments.requests),
    )
    output = Path(arguments.out)
    output.mkdir(parents=True, exist_ok=True)
    (output / "kernel-check-receipts.json").write_text(
        json.dumps(result, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    (output / "kernel-checks.json").write_text(
        json.dumps(result["receipts"], indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


if __name__ == "__main__":
    main()
