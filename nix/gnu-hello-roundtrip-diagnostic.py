#!/usr/bin/env python3
"""Persist non-authoritative GNU round-trip proof diagnostics.

This entry point is intentionally separate from the phase driver: changing
diagnostic presentation must not invalidate static extraction or candidate
generation.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import runpy
from typing import Any


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _write_json(path: Path, value: Any) -> None:
    path.write_text(
        json.dumps(value, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--driver", required=True)
    parser.add_argument("--original", required=True)
    parser.add_argument("--reference-contract", required=True)
    parser.add_argument("--state-machine", required=True)
    parser.add_argument("--load-image-contract", required=True)
    parser.add_argument("--machine-import-report", required=True)
    parser.add_argument("--callable-resolver-profile")
    parser.add_argument("--shard-size", type=int, default=128)
    parser.add_argument("--out", required=True)
    args = parser.parse_args()

    driver = runpy.run_path(args.driver)
    original = Path(args.original)
    reference_contract = Path(args.reference_contract)
    state_machine = Path(args.state_machine)
    load_image_contract = Path(args.load_image_contract)
    machine_import_report = Path(args.machine_import_report)
    sha256_file = driver["sha256_file"]

    terminal_proposals = driver[
        "load_interpreter_mixed_terminal_proposals"
    ](
        machine_import_report,
        original_sha256=sha256_file(original),
        reference_contract_sha256=sha256_file(reference_contract),
        state_machine_sha256=sha256_file(state_machine),
    )
    register_contracts = driver[
        "load_original_register_control_call_contract_proposals"
    ](
        machine_import_report,
        original_sha256=sha256_file(original),
        state_machine_sha256=sha256_file(state_machine),
    )
    boundary_sites = driver["_machine_import_boundary_site_proposals"](
        machine_import_report
    )
    callable_proposal = (
        None
        if args.callable_resolver_profile is None
        else driver["discover_callable_external_proposal"](
            original_pe=original,
            state_machine=state_machine,
            machine_import_report=machine_import_report,
            profile=Path(args.callable_resolver_profile),
        )
    )
    if callable_proposal is not None and not callable_proposal.complete:
        raise ValueError("callable resolver proposal is incomplete")
    spec = driver["_mixed_original_spec"](
        original=original,
        reference_contract=reference_contract,
        load_image_contract=load_image_contract,
        with_boundary_bindings=True,
        shard_size=args.shard_size,
        terminal_boundary_proposals=terminal_proposals,
        machine_import_boundary_sites=boundary_sites,
        register_control_call_contracts=register_contracts,
        static_data_bindings=(
            ()
            if callable_proposal is None
            else callable_proposal.static_data_bindings
        ),
    )
    plan = driver["plan_interpreter_mixed_original"](state_machine, spec)

    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    report = out / "interpreter-mixed-original-plan.json"
    _write_json(report, plan.to_json())
    inputs = {
        "original_pe": original,
        "reference_contract": reference_contract,
        "state_machine": state_machine,
        "load_image_contract": load_image_contract,
        "machine_import_report": machine_import_report,
        **(
            {}
            if args.callable_resolver_profile is None
            else {
                "callable_resolver_profile": Path(
                    args.callable_resolver_profile
                )
            }
        ),
    }
    _write_json(out / "phase-manifest.json", {
        "format": "stage-a-gnu-hello-roundtrip-phase-v1",
        "phase": "mixed-original-diagnostic",
        "status": "ready" if plan.complete else "incomplete",
        "proof_authority": False,
        "authorizing_term": None,
        "executes_original_binary": False,
        "executes_candidate_binary": False,
        "inputs": {
            role: {"path": path.name, "sha256": _sha256(path)}
            for role, path in sorted(inputs.items())
        },
        "public_outputs": {"report": report.name},
        "counts": {
            "regions": len(plan.regions),
            "reachable_targets": len(plan.reachable_target_ids),
            "blockers": len(plan.blockers),
            "diagnostics": len(plan.diagnostics),
        },
    })


if __name__ == "__main__":
    main()
