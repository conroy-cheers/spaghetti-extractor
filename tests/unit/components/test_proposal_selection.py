from __future__ import annotations

import copy
import hashlib
import json
import tempfile
import unittest
from pathlib import Path

from spaghetti_extractor.components.formats import (
    COMPONENT_DISCOVERY_RESULT_V2_FORMAT,
)
from spaghetti_extractor.components.intent import ComponentIntentError
from spaghetti_extractor.components.proposal_package import (
    write_component_proposal_package_v2,
)
from spaghetti_extractor.components.proposal_selection import (
    load_component_proposal_selection_v1,
    write_component_proposal_selection_v1,
)
from spaghetti_extractor.components.resolution import (
    resolve_component_catalog,
    resolve_component_catalog_from_selection,
)
from spaghetti_extractor.util import json_dumps


class ProposalSelectionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.intent = self.root / "components.json"
        self.package = self.root / "proposals"
        self.selection = self.root / "selected-proposals.json"
        self.intent.write_text(
            json.dumps(
                {
                    "format": "spaghetti-extractor-component-catalog-intent-v2",
                    "program_id": "fixture-pe32-v1",
                    "permitted_activation_profiles": ["bounded-equivalence-v1"],
                    "components": [
                        {
                            "id": "selected",
                            "label": "Selected unit",
                            "selector": {
                                "entry_rva": 0x1000,
                                "end_rva": 0x1001,
                                "proposal_kind": "singleton",
                            },
                            "evidence_profile": "structural-draft-v1",
                        }
                    ],
                    "groups": [],
                    "configurations": [],
                },
                indent=2,
                sort_keys=True,
            )
            + "\n",
            encoding="ascii",
        )
        self.payload = _payload()
        write_component_proposal_package_v2(
            payload=self.payload, out=self.package
        )

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def test_selected_input_drives_same_resolution_as_full_package(self) -> None:
        write_component_proposal_selection_v1(
            proposals=self.package, intent=self.intent, out=self.selection
        )
        selected = load_component_proposal_selection_v1(self.selection)
        self.assertEqual(set(selected.proposals), {"selected"})

        full = resolve_component_catalog(
            proposals=self.package,
            intent=self.intent,
            out=self.root / "full-resolution.json",
        )
        narrow = resolve_component_catalog_from_selection(
            selection=self.selection,
            intent=self.intent,
            out=self.root / "narrow-resolution.json",
        )
        self.assertEqual(full, narrow)

    def test_unselected_diagnostic_change_keeps_selected_input_identical(self) -> None:
        first = write_component_proposal_selection_v1(
            proposals=self.package, intent=self.intent, out=self.selection
        )
        changed_payload = copy.deepcopy(self.payload)
        changed_payload["proposals"][1]["diagnostic_note"] = "changed"
        _rehash_proposal(changed_payload["proposals"][1])
        _rehash_discovery(changed_payload)
        changed_package = self.root / "changed-proposals"
        changed_selection = self.root / "changed-selection.json"
        write_component_proposal_package_v2(
            payload=changed_payload, out=changed_package
        )
        second = write_component_proposal_selection_v1(
            proposals=changed_package,
            intent=self.intent,
            out=changed_selection,
        )

        self.assertEqual(first, second)
        self.assertEqual(self.selection.read_bytes(), changed_selection.read_bytes())

    def test_selected_diagnostic_change_keeps_selected_input_identical(self) -> None:
        first = write_component_proposal_selection_v1(
            proposals=self.package, intent=self.intent, out=self.selection
        )
        changed_payload = copy.deepcopy(self.payload)
        changed_payload["proposals"][0]["diagnostic_note"] = "changed"
        _rehash_proposal(changed_payload["proposals"][0])
        _rehash_discovery(changed_payload)
        changed_package = self.root / "changed-proposals"
        changed_selection = self.root / "changed-selection.json"
        write_component_proposal_package_v2(
            payload=changed_payload, out=changed_package
        )
        second = write_component_proposal_selection_v1(
            proposals=changed_package,
            intent=self.intent,
            out=changed_selection,
        )

        self.assertEqual(first, second)

    def test_selected_resolution_field_change_changes_selected_input(self) -> None:
        first = write_component_proposal_selection_v1(
            proposals=self.package, intent=self.intent, out=self.selection
        )
        changed_payload = copy.deepcopy(self.payload)
        changed_payload["proposals"][0]["id"] = "component-proposal:renamed"
        _rehash_proposal(changed_payload["proposals"][0])
        _rehash_discovery(changed_payload)
        changed_package = self.root / "changed-proposals"
        changed_selection = self.root / "changed-selection.json"
        write_component_proposal_package_v2(
            payload=changed_payload, out=changed_package
        )
        second = write_component_proposal_selection_v1(
            proposals=changed_package,
            intent=self.intent,
            out=changed_selection,
        )

        self.assertNotEqual(first["selection_sha256"], second["selection_sha256"])

    def test_selection_tampering_fails_closed(self) -> None:
        write_component_proposal_selection_v1(
            proposals=self.package, intent=self.intent, out=self.selection
        )
        payload = json.loads(self.selection.read_text(encoding="ascii"))
        payload["selections"][0]["selector"]["entry_rva"] = 0x2000
        payload.pop("selection_sha256")
        payload["selection_sha256"] = _sha256(payload)
        self.selection.write_text(json_dumps(payload) + "\n", encoding="ascii")

        with self.assertRaisesRegex(ComponentIntentError, "stale or contradictory"):
            load_component_proposal_selection_v1(self.selection)

    def test_malformed_resolution_projection_fails_closed(self) -> None:
        write_component_proposal_selection_v1(
            proposals=self.package, intent=self.intent, out=self.selection
        )
        payload = json.loads(self.selection.read_text(encoding="ascii"))
        payload["selections"][0]["proposal"]["bindings"][
            "membership_bindings_sha256"
        ] = "bad"
        payload.pop("selection_sha256")
        payload["selection_sha256"] = _sha256(payload)
        self.selection.write_text(json_dumps(payload) + "\n", encoding="ascii")

        with self.assertRaisesRegex(ComponentIntentError, "invalid membership binding"):
            load_component_proposal_selection_v1(self.selection)


def _payload() -> dict[str, object]:
    unit_bindings = [
        {
            "unit_id": f"unit:{index}",
            "contract_sha256": hashlib.sha256(
                f"contract:{index}".encode("ascii")
            ).hexdigest(),
            "instruction_bytes_sha256": hashlib.sha256(
                f"instructions:{index}".encode("ascii")
            ).hexdigest(),
        }
        for index in range(2)
    ]
    proposals: list[dict[str, object]] = []
    for index, binding in enumerate(unit_bindings):
        proposal = {
            "id": f"component-proposal:fixture-{index}",
            "status": "proposed",
            "proposal_kinds": ["singleton"],
            "membership": {
                "unit_ids": [binding["unit_id"]],
                "unit_count": 1,
                "rva_start": 0x1000 + index * 0x10,
                "rva_end": 0x1001 + index * 0x10,
                "noncontiguous": False,
            },
            "reachability": {"classification": "exact"},
            "score": {"front": 0, "rank": index},
            "bindings": {"membership_bindings_sha256": _sha256([binding])},
            "blockers": [],
        }
        _rehash_proposal(proposal)
        proposals.append(proposal)
    payload = {
        "format": COMPONENT_DISCOVERY_RESULT_V2_FORMAT,
        "status": "proposed",
        "authority": {
            "class": "untrusted_component_discovery_proposals",
            "can_authorize_replacement": False,
            "requires_operator_selection": True,
            "requires_interface_refinement": True,
        },
        "executes_original_binary": False,
        "bindings": {
            "machine_ir_sha256": "a" * 64,
            "machine_ir_manifest_sha256": "b" * 64,
            "reconstruction_plan_sha256": "c" * 64,
            "original_binary_sha256": "d" * 64,
        },
        "limits": {
            "max_units_per_candidate": 512,
            "max_candidates_per_seed": 12,
            "path_search_depth": 64,
        },
        "graph_facts": {"nodes": unit_bindings},
        "seed_index": [],
        "proposals": proposals,
        "coverage": {"exact": {"complete": True}},
        "issues": [],
    }
    _rehash_discovery(payload)
    return payload


def _rehash_proposal(proposal: dict[str, object]) -> None:
    proposal.pop("proposal_sha256", None)
    proposal["proposal_sha256"] = _sha256(proposal)


def _rehash_discovery(payload: dict[str, object]) -> None:
    payload.pop("discovery_result_sha256", None)
    payload["discovery_result_sha256"] = _sha256(payload)


def _sha256(value: object) -> str:
    return hashlib.sha256(json_dumps(value).encode("ascii")).hexdigest()


if __name__ == "__main__":
    unittest.main()
