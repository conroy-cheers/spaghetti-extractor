from __future__ import annotations

import json
import tempfile
import unittest
from hashlib import sha256
from pathlib import Path

from spaghetti_extractor.artifact_formats import (
    COMPONENT_PROPOSAL_SET_FORMAT,
    COMPONENT_SELECTION_FORMAT,
    SEMANTIC_COMPONENT_DECLARATIONS_FORMAT,
)
from spaghetti_extractor.component_selection import (
    ComponentSelectionError,
    bind_component_selection,
    materialize_component_declarations,
)
from spaghetti_extractor.util import write_json


def _digest(value: object) -> str:
    return sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()


def _proposal_set() -> dict[str, object]:
    core = {
        "format": COMPONENT_PROPOSAL_SET_FORMAT,
        "status": "ready",
        "executes_original_binary": False,
        "proof_authority": "none",
        "bindings": {
            "machine_ir_sha256": "a" * 64,
            "machine_ir_manifest_sha256": "b" * 64,
            "reconstruction_plan_sha256": "c" * 64,
            "original_binary_sha256": "d" * 64,
        },
        "proposals": [
            {
                "id": "proposal:compare",
                "status": "proposed",
                "blockers": [],
                "proposal_sha256": "e" * 64,
                "kind": "inline",
                "membership": {"unit_ids": ["unit:b", "unit:a"]},
                "reachability": {"classification": "exact"},
                "interface_hint": {
                    "status": "proposed",
                    "parameters": [],
                    "results": [],
                    "objects": [],
                    "persistent_state": [],
                    "services": [],
                    "preconditions": [],
                    "postconditions": [],
                    "observations": [],
                },
            }
        ],
        "coverage": {"machine_unit_ids": ["unit:a", "unit:b"]},
    }
    return {**core, "proposal_set_sha256": _digest(core)}


def _call_proposal(
    *,
    proposal_id: str,
    unit_id: str,
    rva: int,
    target_unit_id: str,
    target_rva: int,
    interface: object,
) -> dict[str, object]:
    return {
        "id": proposal_id,
        "status": "blocked",
        "blockers": [
            {
                "id": "gap:" + unit_id,
                "category": "unclosed_internal_call_dependency",
                "observed": {
                    "target_rva": target_rva,
                    "target_unit_id": target_unit_id,
                },
                "source_location": {"unit_id": unit_id},
            }
        ],
        "membership": {"rva_start": rva, "unit_ids": [unit_id]},
        "reachability": {"classification": "exact"},
        "interface_hint": interface,
    }


class ComponentSelectionTests(unittest.TestCase):
    def test_materialization_preserves_exact_membership_and_resets_authority(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            proposals = root / "proposals.json"
            write_json(proposals, _proposal_set())
            selection = bind_component_selection(
                {
                    "format": COMPONENT_SELECTION_FORMAT,
                    "proposal_set_sha256": _proposal_set()["proposal_set_sha256"],
                    "program_id": "fixture",
                    "components": [
                        {
                            "proposal_id": "proposal:compare",
                            "id": "compare-route",
                            "label": "Compare route",
                            "purpose": "Hide machine flags",
                            "kind": "inline",
                            "membership": {"unit_ids": ["unit:forged"]},
                            "emission": {"policy": "inline"},
                        }
                    ],
                }
            )
            output = root / "declarations.json"
            payload = materialize_component_declarations(
                proposals=proposals,
                selection=selection,
                out=output,
            )

            self.assertEqual(payload["format"], SEMANTIC_COMPONENT_DECLARATIONS_FORMAT)
            component = payload["components"][0]
            self.assertEqual(component["membership"]["unit_ids"], ["unit:a", "unit:b"])
            self.assertEqual(component["refinement"]["status"], "not_started")
            self.assertEqual(component["logical_interface"]["status"], "proposed")
            self.assertEqual(component["logical_interface"]["persistent_state"], [])
            self.assertEqual(
                component["refinement"]["stages"][0]["proposal_id"],
                "proposal:compare",
            )
            self.assertEqual(
                component["refinement"]["stages"][0]["membership_sha256"],
                _digest({"unit_ids": ["unit:a", "unit:b"]}),
            )
            self.assertNotIn(
                "proposal_sha256", component["refinement"]["stages"][0]
            )

    def test_stale_selection_binding_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            proposals = root / "proposals.json"
            write_json(proposals, _proposal_set())
            selection = bind_component_selection(
                {
                    "format": COMPONENT_SELECTION_FORMAT,
                    "proposal_set_sha256": "0" * 64,
                    "program_id": "fixture",
                    "components": [
                        {
                            "proposal_id": "proposal:compare",
                            "id": "compare-route",
                        }
                    ],
                }
            )
            with self.assertRaisesRegex(ComponentSelectionError, "binding is stale"):
                materialize_component_declarations(
                    proposals=proposals,
                    selection=selection,
                    out=root / "declarations.json",
                )

    def test_stable_membership_binding_survives_unrelated_proposal_set_change(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            proposals_payload = _proposal_set()
            selected = proposals_payload["proposals"][0]
            selected["bindings"] = {"membership_bindings_sha256": "f" * 64}
            proposals_payload["diagnostic_revision"] = 2
            proposals_payload.pop("proposal_set_sha256")
            proposals_payload["proposal_set_sha256"] = _digest(proposals_payload)
            proposals = root / "proposals.json"
            write_json(proposals, proposals_payload)
            selection = bind_component_selection(
                {
                    "format": COMPONENT_SELECTION_FORMAT,
                    "proposal_set_sha256": "0" * 64,
                    "program_id": "fixture",
                    "components": [
                        {
                            "proposal_id": "proposal:compare",
                            "proposal_binding_sha256": "f" * 64,
                            "id": "compare-route",
                        }
                    ],
                }
            )

            payload = materialize_component_declarations(
                proposals=proposals,
                selection=selection,
                out=root / "declarations.json",
            )

            self.assertEqual(
                payload["selection"]["binding_mode"], "stable_membership_v1"
            )
            self.assertEqual(
                payload["selection"]["selected_proposal_set_sha256"], "0" * 64
            )
            self.assertEqual(
                payload["components"][0]["refinement"]["stages"][0][
                    "proposal_binding_sha256"
                ],
                "f" * 64,
            )

    def test_stable_membership_binding_rejects_changed_selected_units(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            proposals_payload = _proposal_set()
            proposals_payload["proposals"][0]["bindings"] = {
                "membership_bindings_sha256": "f" * 64
            }
            proposals_payload.pop("proposal_set_sha256")
            proposals_payload["proposal_set_sha256"] = _digest(proposals_payload)
            proposals = root / "proposals.json"
            write_json(proposals, proposals_payload)
            selection = bind_component_selection(
                {
                    "format": COMPONENT_SELECTION_FORMAT,
                    "proposal_set_sha256": proposals_payload[
                        "proposal_set_sha256"
                    ],
                    "program_id": "fixture",
                    "components": [
                        {
                            "proposal_id": "proposal:compare",
                            "proposal_binding_sha256": "e" * 64,
                            "id": "compare-route",
                        }
                    ],
                }
            )

            with self.assertRaisesRegex(
                ComponentSelectionError, "membership binding is stale"
            ):
                materialize_component_declarations(
                    proposals=proposals,
                    selection=selection,
                    out=root / "declarations.json",
                )

    def test_blocked_proposal_cannot_be_selected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            proposals_payload = _proposal_set()
            proposals_payload["proposals"][0]["status"] = "blocked"
            proposals_payload["proposals"][0]["blockers"] = [
                {"category": "unclosed_internal_call_dependency"}
            ]
            proposals_payload.pop("proposal_set_sha256")
            proposals_payload["proposal_set_sha256"] = _digest(proposals_payload)
            proposals = root / "proposals.json"
            write_json(proposals, proposals_payload)
            selection = bind_component_selection(
                {
                    "format": COMPONENT_SELECTION_FORMAT,
                    "proposal_set_sha256": proposals_payload["proposal_set_sha256"],
                    "program_id": "fixture",
                    "components": [
                        {
                            "proposal_id": "proposal:compare",
                            "id": "compare-route",
                        }
                    ],
                }
            )
            with self.assertRaisesRegex(ComponentSelectionError, "is blocked"):
                materialize_component_declarations(
                    proposals=proposals,
                    selection=selection,
                    out=root / "declarations.json",
                )

    def test_exact_selected_component_call_discharges_only_call_blockers(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            proposals_payload = _proposal_set()
            caller = proposals_payload["proposals"][0]
            caller.update(
                {
                    "status": "blocked",
                    "membership": {
                        "rva_start": 0x1000,
                        "unit_ids": ["unit:caller"],
                    },
                    "blockers": [
                        {
                            "id": "gap:call",
                            "category": "unclosed_internal_call_dependency",
                            "observed": {
                                "target_rva": 0x2000,
                                "target_unit_id": "unit:callee",
                            },
                            "source_location": {"unit_id": "unit:caller"},
                        }
                    ],
                }
            )
            proposals_payload["proposals"].append(
                {
                    "id": "proposal:callee",
                    "status": "proposed",
                    "blockers": [],
                    "membership": {
                        "rva_start": 0x2000,
                        "unit_ids": ["unit:callee", "unit:return"],
                    },
                    "reachability": {"classification": "exact"},
                    "interface_hint": caller["interface_hint"],
                }
            )
            proposals_payload.pop("proposal_set_sha256")
            proposals_payload["proposal_set_sha256"] = _digest(proposals_payload)
            proposals = root / "proposals.json"
            write_json(proposals, proposals_payload)
            selection = bind_component_selection(
                {
                    "format": COMPONENT_SELECTION_FORMAT,
                    "proposal_set_sha256": proposals_payload[
                        "proposal_set_sha256"
                    ],
                    "program_id": "fixture",
                    "components": [
                        {
                            "proposal_id": "proposal:compare",
                            "id": "caller",
                            "component_calls": [
                                {
                                    "target_component_id": "callee",
                                    "target_rva": 0x2000,
                                }
                            ],
                        },
                        {
                            "proposal_id": "proposal:callee",
                            "id": "callee",
                        },
                    ],
                }
            )
            payload = materialize_component_declarations(
                proposals=proposals,
                selection=selection,
                out=root / "declarations.json",
            )
            dependency = next(
                item for item in payload["components"] if item["id"] == "caller"
            )["component_calls"][0]
            self.assertEqual(dependency["target_component_id"], "callee")
            self.assertEqual(dependency["target_unit_id"], "unit:callee")
            self.assertEqual(
                dependency["callsites"],
                [{"gap_id": "gap:call", "source_unit_id": "unit:caller"}],
            )

    def test_nested_selected_component_call_graph_is_materialized(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            proposals_payload = _proposal_set()
            interface = proposals_payload["proposals"][0]["interface_hint"]
            proposals_payload["proposals"] = [
                _call_proposal(
                    proposal_id="proposal:caller",
                    unit_id="unit:caller",
                    rva=0x1000,
                    target_unit_id="unit:middle",
                    target_rva=0x2000,
                    interface=interface,
                ),
                _call_proposal(
                    proposal_id="proposal:middle",
                    unit_id="unit:middle",
                    rva=0x2000,
                    target_unit_id="unit:leaf",
                    target_rva=0x3000,
                    interface=interface,
                ),
                {
                    "id": "proposal:leaf",
                    "status": "proposed",
                    "blockers": [],
                    "membership": {
                        "rva_start": 0x3000,
                        "unit_ids": ["unit:leaf"],
                    },
                    "reachability": {"classification": "exact"},
                    "interface_hint": interface,
                },
            ]
            proposals_payload.pop("proposal_set_sha256")
            proposals_payload["proposal_set_sha256"] = _digest(proposals_payload)
            proposals = root / "proposals.json"
            write_json(proposals, proposals_payload)
            selection = bind_component_selection(
                {
                    "format": COMPONENT_SELECTION_FORMAT,
                    "proposal_set_sha256": proposals_payload[
                        "proposal_set_sha256"
                    ],
                    "program_id": "fixture",
                    "components": [
                        {
                            "proposal_id": "proposal:caller",
                            "id": "caller",
                            "component_calls": [
                                {
                                    "target_component_id": "middle",
                                    "target_rva": 0x2000,
                                }
                            ],
                        },
                        {
                            "proposal_id": "proposal:middle",
                            "id": "middle",
                            "component_calls": [
                                {
                                    "target_component_id": "leaf",
                                    "target_rva": 0x3000,
                                }
                            ],
                        },
                        {"proposal_id": "proposal:leaf", "id": "leaf"},
                    ],
                }
            )

            payload = materialize_component_declarations(
                proposals=proposals,
                selection=selection,
                out=root / "declarations.json",
            )

            by_id = {item["id"]: item for item in payload["components"]}
            self.assertEqual(
                by_id["caller"]["component_calls"][0]["target_component_id"],
                "middle",
            )
            self.assertEqual(
                by_id["middle"]["component_calls"][0]["target_component_id"],
                "leaf",
            )

    def test_recursive_selected_component_call_graph_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            proposals_payload = _proposal_set()
            interface = proposals_payload["proposals"][0]["interface_hint"]
            proposals_payload["proposals"] = [
                _call_proposal(
                    proposal_id="proposal:first",
                    unit_id="unit:first",
                    rva=0x1000,
                    target_unit_id="unit:second",
                    target_rva=0x2000,
                    interface=interface,
                ),
                _call_proposal(
                    proposal_id="proposal:second",
                    unit_id="unit:second",
                    rva=0x2000,
                    target_unit_id="unit:first",
                    target_rva=0x1000,
                    interface=interface,
                ),
            ]
            proposals_payload.pop("proposal_set_sha256")
            proposals_payload["proposal_set_sha256"] = _digest(proposals_payload)
            proposals = root / "proposals.json"
            write_json(proposals, proposals_payload)
            selection = bind_component_selection(
                {
                    "format": COMPONENT_SELECTION_FORMAT,
                    "proposal_set_sha256": proposals_payload[
                        "proposal_set_sha256"
                    ],
                    "program_id": "fixture",
                    "components": [
                        {
                            "proposal_id": "proposal:first",
                            "id": "first",
                            "component_calls": [
                                {
                                    "target_component_id": "second",
                                    "target_rva": 0x2000,
                                }
                            ],
                        },
                        {
                            "proposal_id": "proposal:second",
                            "id": "second",
                            "component_calls": [
                                {
                                    "target_component_id": "first",
                                    "target_rva": 0x1000,
                                }
                            ],
                        },
                    ],
                }
            )

            with self.assertRaisesRegex(
                ComponentSelectionError, "recursive component-call graph"
            ):
                materialize_component_declarations(
                    proposals=proposals,
                    selection=selection,
                    out=root / "declarations.json",
                )


if __name__ == "__main__":
    unittest.main()
