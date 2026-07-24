#!/usr/bin/env python3

from __future__ import annotations

import argparse
import json
from pathlib import Path

from spaghetti_extractor.relational.lean.pe_byte_packs import (
    generate_pe_byte_pack_bundle,
)
from spaghetti_extractor.relational.lean.universal_paired_external_environment import (
    UniversalPairedExternalEnvironmentBindings,
    write_universal_paired_external_environment_source,
)
from spaghetti_extractor.util import sha256_file, write_json


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--original", required=True)
    parser.add_argument("--candidate", required=True)
    parser.add_argument("--machine-import-report", required=True)
    parser.add_argument("--out", required=True)
    args = parser.parse_args()

    original = Path(args.original)
    candidate = Path(args.candidate)
    machine_import_report = Path(args.machine_import_report)
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)

    candidate_inventory = generate_pe_byte_pack_bundle(
        pe_path=candidate,
        out_dir=out,
        module_prefix="GeneratedGnuHelloExternalCandidate",
        namespace="StageA.GeneratedRelational",
        pack_size=256 * 1024,
        chunk_size=1024,
        standalone=False,
        authoritative_module="GeneratedGnuHelloExternalCandidatePE",
        authoritative_bytes_name="externalCandidateBytes",
        authoritative_pe_name="externalCandidatePe",
        runtime_binding_prefix="externalCandidate",
    )
    lean_path, report_path = write_universal_paired_external_environment_source(
        original_pe=original,
        candidate_pe=candidate,
        machine_import_report=machine_import_report,
        out_dir=out,
        bindings=UniversalPairedExternalEnvironmentBindings(
            original_module="StageA.GeneratedGnuHelloOriginalPE",
            candidate_module="StageA.GeneratedGnuHelloExternalCandidatePE",
            static_import_module="StageA.GeneratedStaticMachineImportContracts",
            original_namespace="StageA.GeneratedRelational",
            candidate_namespace="StageA.GeneratedRelational",
            static_import_namespace=(
                "StageA.GeneratedRelational.StaticMachineImports"
            ),
            original_bytes="originalBytes",
            candidate_bytes="externalCandidateBytes",
            original_pe="originalPe",
            candidate_pe="externalCandidatePe",
            original_imports="originalImports",
            candidate_imports="externalCandidateImports",
            original_pe_parsed="originalPeParsed",
            candidate_pe_parsed="externalCandidatePeParsed",
        ),
        module="GeneratedGnuHelloUniversalPairedExternalEnvironment",
    )
    report = json.loads(report_path.read_text(encoding="utf-8"))
    modules = [row["name"] for row in candidate_inventory.modules]
    modules.append(lean_path.stem)
    write_json(
        out / "phase-manifest.json",
        {
            "format": "stage-a-gnu-hello-roundtrip-phase-v1",
            "phase": "universal-paired-external-environment",
            "status": "source-ready",
            "proof_authority": False,
            "executes_original_binary": False,
            "executes_candidate_binary": False,
            "inputs": {
                "original_sha256": sha256_file(original),
                "candidate_sha256": sha256_file(candidate),
                "machine_import_report_sha256": sha256_file(
                    machine_import_report
                ),
            },
            "modules": modules,
            "targets": [lean_path.stem],
            "authorizing_term": report["authorizing_term"],
            "proved_by_generated_terms": report["proved_by_generated_terms"],
            "remaining_premises": report["remaining_premises"],
            "counts": {
                **report["counts"],
                "candidate_pe_byte_packs": len(candidate_inventory.packs),
            },
            "public_outputs": {
                "report": report_path.name,
                "candidate_pe_inventory": "pe-byte-pack-inventory.json",
                "lean_module": f"StageA/{lean_path.name}",
            },
        },
    )


if __name__ == "__main__":
    main()
