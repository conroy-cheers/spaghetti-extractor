from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

from spaghetti_extractor.relational.original_cutpoint_graph_ir import (
    OriginalCutpointGraphIRError,
    load_original_cutpoint_graph_ir,
    original_cutpoint_graph_ir_from_plan,
)
from spaghetti_extractor.util import sha256_file, write_json


class StageAOriginalCutpointGraphIRTests(unittest.TestCase):
    def _fixture(
        self, root: Path
    ) -> tuple[Path, Path, SimpleNamespace]:
        original = root / "original.exe"
        original.write_bytes(b"MZ-cutpoint-fixture")
        state_machine = root / "state-machine.jsonl"
        transitions = (
            {
                "edge_conditions": [{"target_rva": 0x1010}],
                "external_events": [],
                "outcome": {"kind": "jump", "target_rva": 0x1010},
            },
            {
                "edge_conditions": [{"target_rva": 0x1020}],
                "external_events": [{
                    "kind": "internal_call",
                    "return_rva": 0x1020,
                    "target_rva": 0x1000,
                }],
                "outcome": {"kind": "fallthrough", "target_rva": 0x1020},
            },
            {
                "edge_conditions": [],
                "external_events": [],
                "outcome": {"kind": "return"},
            },
        )
        state_machine.write_text(
            "\n".join(
                json.dumps({
                    "contract_sha256": f"{index + 1:064x}",
                    "instruction_bytes_sha256": f"{index + 17:064x}",
                    "original": {
                        "rva_start": rva,
                        "rva_end": rva + 16,
                    },
                    **transitions[index],
                }, sort_keys=True)
                for index, rva in enumerate((0x1000, 0x1010, 0x1020))
            )
            + "\n",
            encoding="ascii",
        )
        regions = (
            SimpleNamespace(
                target_id=0,
                rva=0x1000,
                size=16,
                alias_rvas=(),
                successor_ids=(1,),
                root=True,
                synthetic_terminal_padding=False,
            ),
            SimpleNamespace(
                target_id=1,
                rva=0x1010,
                size=16,
                alias_rvas=(),
                successor_ids=(0, 2),
                root=False,
                synthetic_terminal_padding=False,
            ),
            SimpleNamespace(
                target_id=2,
                rva=0x1020,
                size=16,
                alias_rvas=(),
                successor_ids=(),
                root=False,
                synthetic_terminal_padding=False,
            ),
        )
        plan = SimpleNamespace(
            state_machine_sha256=sha256_file(state_machine),
            regions=regions,
            reachable_target_ids=(0, 1, 2),
            register_control_provenance={
                "exact_graph": {
                    "edges": [
                        {
                            "edge_index": 7,
                            "kind": "direct",
                            "machine_contract_id": None,
                            "source_target_id": 0,
                            "target_target_id": 1,
                        },
                        {
                            "edge_index": 11,
                            "kind": "call_return",
                            "machine_contract_id": 3,
                            "source_target_id": 1,
                            "target_target_id": 2,
                        },
                    ]
                }
            },
        )
        return original, state_machine, plan

    def test_round_trip_binds_semantics_edges_roots_and_inputs(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            original, state_machine, plan = self._fixture(root)
            graph = original_cutpoint_graph_ir_from_plan(
                plan,
                original_pe=original,
                state_machine=state_machine,
            )
            path = root / "graph.json"
            write_json(path, graph.to_json())
            loaded = load_original_cutpoint_graph_ir(
                path,
                original_pe=original,
                state_machine=state_machine,
            )

        self.assertEqual(loaded, graph)
        self.assertEqual(loaded.root_target_ids, (0,))
        self.assertEqual(loaded.edge_index(1, 2, kind="call_return"), 11)
        self.assertIsInstance(
            loaded.edge_index(1, 0, kind="call_entry"),
            int,
        )
        self.assertEqual(
            {
                (edge.kind, edge.transition_role, edge.execution_successor)
                for edge in loaded.edges
            },
            {
                ("direct", "immediate", True),
                ("call_entry", "immediate", True),
                ("call_return", "continuation", False),
            },
        )
        self.assertEqual(
            loaded.regions[1].semantic_contract_sha256,
            f"{2:064x}",
        )

    def test_rejects_semantic_hash_tampering(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            original, state_machine, plan = self._fixture(root)
            payload = original_cutpoint_graph_ir_from_plan(
                plan,
                original_pe=original,
                state_machine=state_machine,
            ).to_json()
            payload["regions"][1]["semantic_contract_sha256"] = "0" * 64
            path = root / "graph.json"
            write_json(path, payload)
            with self.assertRaisesRegex(
                OriginalCutpointGraphIRError,
                "semantic binding",
            ):
                load_original_cutpoint_graph_ir(
                    path,
                    original_pe=original,
                    state_machine=state_machine,
                )

    def test_rejects_wrong_execution_successor_classification(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            original, state_machine, plan = self._fixture(root)
            payload = original_cutpoint_graph_ir_from_plan(
                plan,
                original_pe=original,
                state_machine=state_machine,
            ).to_json()
            call_return = next(
                edge for edge in payload["edges"]
                if edge["kind"] == "call_return"
            )
            call_return["execution_successor"] = True
            path = root / "graph.json"
            write_json(path, payload)
            with self.assertRaisesRegex(
                OriginalCutpointGraphIRError,
                "execution-successor classification",
            ):
                load_original_cutpoint_graph_ir(
                    path,
                    original_pe=original,
                    state_machine=state_machine,
                )

    def test_rejects_missing_call_entry_transition(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            original, state_machine, plan = self._fixture(root)
            payload = original_cutpoint_graph_ir_from_plan(
                plan,
                original_pe=original,
                state_machine=state_machine,
            ).to_json()
            payload["edges"] = [
                edge for edge in payload["edges"]
                if edge["kind"] != "call_entry"
            ]
            path = root / "graph.json"
            write_json(path, payload)
            with self.assertRaisesRegex(
                OriginalCutpointGraphIRError,
                "transition inventory is incomplete",
            ):
                load_original_cutpoint_graph_ir(
                    path,
                    original_pe=original,
                    state_machine=state_machine,
                )

    def test_rejects_changed_state_machine(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            original, state_machine, plan = self._fixture(root)
            graph = original_cutpoint_graph_ir_from_plan(
                plan,
                original_pe=original,
                state_machine=state_machine,
            )
            path = root / "graph.json"
            write_json(path, graph.to_json())
            state_machine.write_text(
                state_machine.read_text(encoding="ascii") + "\n",
                encoding="ascii",
            )
            with self.assertRaisesRegex(
                OriginalCutpointGraphIRError,
                "state machine",
            ):
                load_original_cutpoint_graph_ir(
                    path,
                    original_pe=original,
                    state_machine=state_machine,
                )


if __name__ == "__main__":
    unittest.main()
