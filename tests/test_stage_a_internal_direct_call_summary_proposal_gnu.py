from __future__ import annotations

import json
import os
import unittest
from pathlib import Path

from spaghetti_extractor.relational.lean.internal_direct_call_summary_proposal import (
    DirectCallSummaryRequest,
    construct_internal_direct_call_summary_proposals,
    discover_internal_direct_call_sites,
)


class StageAGnuInternalDirectCallSummaryProposalTests(unittest.TestCase):
    def test_discovers_a_generic_ebx_crossing_summary_proposal(self) -> None:
        artifacts = _gnu_artifacts()
        if artifacts is None:
            self.skipTest("hash-matched GNU hello proposal artifacts are unavailable")
        pe, state_machine, machine_import_report = artifacts
        sites = discover_internal_direct_call_sites(
            pe, state_machine, machine_import_report
        )
        self.assertGreater(len(sites), 0)

        plan = construct_internal_direct_call_summary_proposals(
            pe,
            state_machine,
            machine_import_report,
            [DirectCallSummaryRequest(site, ("ebx",)) for site in sites[:64]],
        )

        self.assertGreater(
            len(plan.proposals),
            0,
            [
                (hex(item.request.callsite_rva), item.category, item.detail)
                for item in plan.blockers
            ],
        )
        proposal = plan.proposals[0]
        self.assertEqual(proposal.request.registers, ("ebx",))
        self.assertGreater(len(proposal.region_rvas), 0)
        self.assertFalse(plan.to_json()["authority"]["python_proof_status_emitted"])
        serialized = json.dumps(plan.to_json()).lower()
        for product_name in ("gnu", "hello"):
            self.assertNotIn(product_name, serialized)


def _gnu_artifacts() -> tuple[Path, Path, Path] | None:
    explicit = tuple(
        os.environ.get(name)
        for name in (
            "SPAGHETTI_TEST_GNU_HELLO_PE",
            "SPAGHETTI_TEST_GNU_HELLO_STATE_MACHINE",
            "SPAGHETTI_TEST_GNU_HELLO_MACHINE_IMPORT_REPORT",
        )
    )
    if all(explicit):
        paths = tuple(Path(value) for value in explicit if value is not None)
        if len(paths) == 3 and all(path.is_file() for path in paths):
            return paths[0], paths[1], paths[2]

    root = Path(__file__).parents[1]
    report = (
        root
        / "build/stage-b-gnu-hello-roundtrip/static-machine-import-contracts-v1"
        / "machine-import-contract-report.json"
    )
    if not report.is_file():
        return None
    payload = json.loads(report.read_text(encoding="utf-8"))
    inputs = payload.get("inputs", {})
    pe_value = inputs.get("original_pe")
    state_hash = inputs.get("state_machine_sha256")
    if not isinstance(pe_value, str) or not isinstance(state_hash, str):
        return None
    pe = Path(pe_value)
    if not pe.is_file():
        return None
    candidates = sorted((
        root / "build/stage-b-gnu-hello-roundtrip"
    ).glob("stage-a-static-export*/state-machine.jsonl"))
    for state in candidates:
        import hashlib

        if hashlib.sha256(state.read_bytes()).hexdigest() == state_hash:
            return pe, state, report
    return None


if __name__ == "__main__":
    unittest.main()
