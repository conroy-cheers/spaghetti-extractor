#!/usr/bin/env python3
"""Classify exact side ISA inventories against reviewed semantic evidence."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from spaghetti_extractor.relational.semantic_coverage import (
    build_semantic_coverage,
    validate_semantic_coverage,
)
from spaghetti_extractor.util import write_json


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--original-isa", required=True)
    parser.add_argument("--candidate-isa", required=True)
    parser.add_argument("--access-domain-receipts")
    parser.add_argument("--access-domain-receipt-proposals")
    parser.add_argument("--out", required=True)
    arguments = parser.parse_args()
    original_path = Path(arguments.original_isa)
    candidate_path = Path(arguments.candidate_isa)
    original = json.loads(original_path.read_text(encoding="utf-8"))
    candidate = json.loads(candidate_path.read_text(encoding="utf-8"))
    receipts = (
        json.loads(
            Path(arguments.access_domain_receipts).read_text(encoding="utf-8")
        )
        if arguments.access_domain_receipts
        else None
    )
    artifact = build_semantic_coverage(
        original,
        candidate,
        access_domain_receipts=receipts,
    )
    validate_semantic_coverage(
        artifact,
        original_side_isa=original,
        candidate_side_isa=candidate,
        access_domain_receipts=receipts,
    )
    output = Path(arguments.out)
    output.mkdir(parents=True, exist_ok=True)
    write_json(output / "semantic-coverage.json", artifact)
    if arguments.access_domain_receipt_proposals:
        from spaghetti_extractor.relational.access_domain_receipts import (
            build_access_domain_kernel_check_requests,
        )

        proposals = json.loads(
            Path(arguments.access_domain_receipt_proposals).read_text(
                encoding="utf-8"
            )
        )
        write_json(
            output / "access-domain-kernel-check-requests.json",
            build_access_domain_kernel_check_requests(proposals),
        )
    binaries = {
        descriptor["side"]: descriptor["binary_sha256"]
        for descriptor in artifact["inputs"]
    }
    receipt_diagnostics = artifact["access_domain_receipts"]["diagnostics"]
    exact_diagnostics: dict[
        tuple[str, str, int, int, str, str], list[str]
    ] = {}
    loose_diagnostics: dict[
        tuple[str, int, int, str, str], list[str]
    ] = {}
    location_diagnostics: dict[tuple[str, int], list[str]] = {}
    global_diagnostics: list[str] = []
    for diagnostic in receipt_diagnostics:
        if (
            diagnostic["side"] is not None
            and diagnostic["binary_sha256"] is not None
            and diagnostic["rva"] is not None
            and diagnostic["size"] is not None
            and diagnostic["bytes"] is not None
            and diagnostic["semantic_form"] is not None
        ):
            key = (
                diagnostic["side"],
                diagnostic["binary_sha256"],
                diagnostic["rva"],
                diagnostic["size"],
                diagnostic["bytes"],
                diagnostic["semantic_form"],
            )
            exact_diagnostics.setdefault(key, []).append(diagnostic["code"])
            loose_key = (
                diagnostic["side"],
                diagnostic["rva"],
                diagnostic["size"],
                diagnostic["bytes"],
                diagnostic["semantic_form"],
            )
            loose_diagnostics.setdefault(loose_key, []).append(
                diagnostic["code"]
            )
            location_diagnostics.setdefault(
                (diagnostic["side"], diagnostic["rva"]), []
            ).append(diagnostic["code"])
        else:
            global_diagnostics.append(diagnostic["code"])
    access_domain_blockers = []
    for occurrence in artifact["occurrences"]:
        if occurrence["access_fault_domain"] != "requires-proof":
            continue
        key = (
            occurrence["side"],
            binaries[occurrence["side"]],
            occurrence["rva"],
            occurrence["size"],
            occurrence["bytes"],
            occurrence["form"],
        )
        reason_codes = exact_diagnostics.get(key)
        if reason_codes is None:
            reason_codes = loose_diagnostics.get(
                (key[0], key[2], key[3], key[4], key[5])
            )
        if reason_codes is None:
            reason_codes = location_diagnostics.get((key[0], key[2]))
        if reason_codes is None:
            reason_codes = (
                global_diagnostics
                if global_diagnostics
                else ["access-domain-receipt-missing"]
            )
        access_domain_blockers.append(
            {
                "side": key[0],
                "binary_sha256": key[1],
                "rva": key[2],
                "size": key[3],
                "bytes": key[4],
                "semantic_form": key[5],
                "reason_codes": sorted(set(reason_codes)),
            }
        )
    write_json(
        output / "semantic-blockers.json",
        {
            "format": "stage-a-relational-semantic-coverage-blockers-v1",
            "coverage_sha256": artifact["coverage_sha256"],
            "status": artifact["status"],
            "counts": artifact["counts"]["by_qualification"],
            "access_domain_receipts": artifact["access_domain_receipts"],
            "access_domain_blockers": access_domain_blockers,
            "occurrences": [
                occurrence
                for occurrence in artifact["occurrences"]
                if occurrence["qualification"] != "qualified"
            ],
        },
    )


if __name__ == "__main__":
    main()
