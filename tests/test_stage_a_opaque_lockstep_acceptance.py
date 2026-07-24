from __future__ import annotations

import unittest
from copy import deepcopy
from types import SimpleNamespace
from typing import Any

from spaghetti_extractor.relational.lean.acceptance import (
    _opaque_lockstep_inventory_plan,
)
from spaghetti_extractor.stage_binary import StageAImport


def _semantic_import(symbol: str = "GetTickCount") -> dict[str, Any]:
    return {
        "dll": "kernel32.dll",
        "name": {"op": "symbol", "bytes": list(symbol.encode("utf-8"))},
    }


def _fixture(
    *, kind: str = "external_call", disposition: str = "returns",
) -> tuple[object, object, dict[str, Any], list[dict[str, Any]], dict[str, Any], dict[str, Any]]:
    imported = _semantic_import()
    operation = "external_call" if kind == "external_call" else "external_jump"
    site = {
        "id": 7,
        "edge_index": 41,
        "site_kind": (
            "decoded_external_call"
            if kind == "external_call"
            else "direct_import_thunk"
        ),
        "dispatch_profile": (
            "decoded_external_call"
            if kind == "external_call"
            else "checked_direct_import_thunk"
        ),
        "source_region_index": 0,
        "target_region_index": 1,
        "source_target_id": 11,
        "continuation_target_id": 12,
        "machine_contract_id": 3,
        "argument_relation_claims": [],
        "argument_expressions": [],
        "boundary_invariant": {},
    }
    step = {
        "kind": kind,
        "node_id": 5,
        "external_site": site,
        "decoded_import": imported,
    }
    if kind == "external_call":
        step["edges"] = [{"edge_id": 41}]
    binary = SimpleNamespace(
        imports=(StageAImport("kernel32.dll", "GetTickCount", None, 0x2040),)
    )
    candidate_binary = SimpleNamespace(
        imports=(StageAImport("kernel32.dll", "GetTickCount", None, 0x3040),)
    )
    contract = {
        "regions": [{}, {}],
        "machine_import_call_contracts": [{
            "id": 3,
            "import": {"dll": "kernel32.dll", "symbol": "GetTickCount"},
            "disposition": disposition,
            "memory_effect": "none",
            "memory_footprints": [],
        }],
    }
    behavior = {"outcome": {"op": operation, "import": imported, "arguments": []}}
    behaviors = [
        {"original_ir": behavior, "candidate_ir": deepcopy(behavior)},
        {"original_ir": {}, "candidate_ir": {}},
    ]
    plan = {"node_steps": [step], "protocol_callback_states": [], "launch": {}}
    return binary, candidate_binary, contract, behaviors, plan, site


def _inventory(
    fixture: tuple[object, object, dict[str, Any], list[dict[str, Any]], dict[str, Any], dict[str, Any]],
    *, candidates: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    original, candidate, contract, behaviors, plan, site = fixture
    return _opaque_lockstep_inventory_plan(
        original,
        candidate,
        contract,
        behaviors,
        plan,
        [site] if candidates is None else candidates,
    )


class StageAOpaqueLockstepAcceptanceTests(unittest.TestCase):
    def test_builds_complete_returning_tail_and_terminal_inventories(self) -> None:
        cases = (
            ("external_call", "returns", "returns"),
            ("external_jump", "returns", "returns"),
            ("external_terminate", "terminates", "terminates"),
        )
        for kind, disposition, expected in cases:
            with self.subTest(kind=kind):
                result = _inventory(_fixture(kind=kind, disposition=disposition))
                self.assertEqual(result["status"], "ready", result)
                self.assertEqual(result["required_site_ids"], [7])
                self.assertEqual(
                    result["artifact"]["call_sites"][0]["disposition"], expected
                )
                self.assertEqual(result["counts"]["covered"], 1)

    def test_missing_or_ambiguous_site_evidence_is_incomplete(self) -> None:
        fixture = _fixture()
        site = fixture[-1]
        for name, candidates in (
            ("missing", []),
            ("ambiguous", [site, deepcopy(site)]),
        ):
            with self.subTest(name=name):
                result = _inventory(fixture, candidates=candidates)
                self.assertEqual(result["status"], "incomplete")
                self.assertIn(
                    "opaque_lockstep_site_evidence_ambiguous",
                    {gap["code"] for gap in result["gaps"]},
                )

    def test_unresolved_indirect_identity_is_a_precise_frontier(self) -> None:
        fixture = _fixture()
        fixture[-1]["dispatch_profile"] = "dynamic_indirect"
        result = _inventory(fixture)

        self.assertEqual(result["status"], "incomplete")
        self.assertIn(
            "opaque_lockstep_indirect_identity_unsupported",
            {gap["code"] for gap in result["gaps"]},
        )

    def test_mixed_protocol_callback_and_tls_frames_fail_closed(self) -> None:
        fixture = _fixture()
        fixture[-2]["node_steps"].append({"kind": "external_protocol", "node_id": 8})
        fixture[-2]["protocol_callback_states"] = [{"node_id": 9}]
        fixture[-2]["launch"] = {"tls_callback_node_ids": [10, 11]}
        result = _inventory(fixture)

        self.assertEqual(result["status"], "incomplete")
        self.assertEqual(result["counts"]["tls_roots"], 2)
        self.assertTrue({
            "opaque_lockstep_protocol_callback_frame_unsupported",
            "opaque_lockstep_callback_entry_frame_unsupported",
            "opaque_lockstep_tls_entry_frame_unsupported",
        }.issubset({gap["code"] for gap in result["gaps"]}))

    def test_protocol_only_graph_retains_existing_exact_profile(self) -> None:
        fixture = _fixture()
        fixture[-2]["node_steps"] = [{"kind": "external_protocol", "node_id": 8}]
        result = _inventory(fixture, candidates=[])

        self.assertEqual(result["status"], "not_applicable")
        self.assertEqual(result["counts"]["protocol"], 1)


if __name__ == "__main__":
    unittest.main()
