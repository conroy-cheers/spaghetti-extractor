from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from spaghetti_extractor.stage_b_reachable_slice import (
    write_stage_b_reachable_slice,
)
from spaghetti_extractor.stage_binary import StageAInputError
from spaghetti_extractor.util import sha256_file


_THEOREM = "StageA.GeneratedRelational.candidatePE32ProgramsEquivalent"


def _write_json(path: Path, value: object) -> None:
    path.write_text(json.dumps(value, sort_keys=True) + "\n", encoding="utf-8")


def _fixture(root: Path) -> tuple[Path, Path, Path, Path]:
    graph_path = root / "relational-product-graph.json"
    acceptance_path = root / "whole-program-acceptance.json"
    state_machine_path = root / "state-machine.jsonl"
    prepared_path = root / "prepared-proof.json"
    graph = {
        "format": "stage-a-relational-product-graph-v1",
        "counts": {
            "declared_reachability_control_closed": True,
            "reachable_product_local_complete": True,
            "reachable_decoded_control_frontier_nodes": 0,
            "reachable_local_refinement_frontier_edges": 0,
            "declared_reachable_nodes": 2,
        },
        "evidence": {
            "declared_reachable_node_ids": [0, 2],
            "canonical_node_inventory": [
                {"node_id": 0, "original_rva_start": 0x1008},
                {"node_id": 1, "original_rva_start": 0x1010},
                {"node_id": 2, "original_rva_start": 0x1020},
            ],
        },
    }
    acceptance = {
        "format": "stage-a-whole-program-acceptance-v1",
        "status": "ready",
        "required_theorem": _THEOREM,
        "theorem": _THEOREM,
    }
    rows = [
        {
            "id": f"transfer-{index}",
            "original": {"rva_start": rva, "rva_end": rva + 0x10},
        }
        for index, rva in enumerate((0x1000, 0x1010, 0x1020))
    ]
    _write_json(graph_path, graph)
    _write_json(acceptance_path, acceptance)
    state_machine_path.write_text(
        "".join(json.dumps(row, sort_keys=True) + "\n" for row in rows),
        encoding="utf-8",
    )
    prepared = {
        "format": "stage-a-prepared-relational-v1",
        "status": "prepared",
        "acceptance": acceptance,
        "expected_final_theorem": _THEOREM,
        "product_graph_sha256": sha256_file(graph_path),
        "whole_program_acceptance_sha256": sha256_file(acceptance_path),
    }
    _write_json(prepared_path, prepared)
    return prepared_path, graph_path, acceptance_path, state_machine_path


class StageBReachableSliceTests(unittest.TestCase):
    def test_selects_only_final_theorem_closed_reachable_transfers(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            prepared, graph, acceptance, state_machine = _fixture(root)
            report = write_stage_b_reachable_slice(
                prepared_proof=prepared,
                product_graph=graph,
                whole_program_acceptance=acceptance,
                state_machine=state_machine,
                out_dir=root / "out",
            )
            self.assertEqual(report["status"], "ready")
            self.assertEqual(report["counts"]["selected_transfers"], 2)
            rows = [
                json.loads(line)
                for line in (root / "out/state-machine-reachable.jsonl")
                .read_text(encoding="utf-8")
                .splitlines()
            ]
            self.assertEqual([row["id"] for row in rows], ["transfer-0", "transfer-2"])
            self.assertIn("no proof authority", report["authority"])

    def test_rejects_incomplete_acceptance(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            prepared, graph, acceptance, state_machine = _fixture(root)
            acceptance_payload = json.loads(acceptance.read_text(encoding="utf-8"))
            acceptance_payload.update(status="incomplete", theorem=None, blockers=[])
            _write_json(acceptance, acceptance_payload)
            prepared_payload = json.loads(prepared.read_text(encoding="utf-8"))
            prepared_payload["acceptance"] = acceptance_payload
            prepared_payload["whole_program_acceptance_sha256"] = sha256_file(acceptance)
            prepared_payload["expected_final_theorem"] = None
            _write_json(prepared, prepared_payload)
            with self.assertRaisesRegex(StageAInputError, "final-theorem-ready"):
                write_stage_b_reachable_slice(
                    prepared_proof=prepared,
                    product_graph=graph,
                    whole_program_acceptance=acceptance,
                    state_machine=state_machine,
                    out_dir=root / "out",
                )

    def test_rejects_unclosed_control_or_refinement_frontier(self) -> None:
        for field in (
            "declared_reachability_control_closed",
            "reachable_product_local_complete",
        ):
            with self.subTest(field=field), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                prepared, graph, acceptance, state_machine = _fixture(root)
                payload = json.loads(graph.read_text(encoding="utf-8"))
                payload["counts"][field] = False
                _write_json(graph, payload)
                prepared_payload = json.loads(prepared.read_text(encoding="utf-8"))
                prepared_payload["product_graph_sha256"] = sha256_file(graph)
                _write_json(prepared, prepared_payload)
                with self.assertRaisesRegex(StageAInputError, "requires"):
                    write_stage_b_reachable_slice(
                        prepared_proof=prepared,
                        product_graph=graph,
                        whole_program_acceptance=acceptance,
                        state_machine=state_machine,
                        out_dir=root / "out",
                    )

    def test_rejects_reachable_node_without_semantic_transfer(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            prepared, graph, acceptance, state_machine = _fixture(root)
            state_machine.write_text(
                json.dumps({
                    "id": "transfer-0",
                    "original": {"rva_start": 0x1000, "rva_end": 0x1010},
                })
                + "\n",
                encoding="utf-8",
            )
            with self.assertRaisesRegex(StageAInputError, "has no semantic transfer"):
                write_stage_b_reachable_slice(
                    prepared_proof=prepared,
                    product_graph=graph,
                    whole_program_acceptance=acceptance,
                    state_machine=state_machine,
                    out_dir=root / "out",
                )


if __name__ == "__main__":
    unittest.main()
