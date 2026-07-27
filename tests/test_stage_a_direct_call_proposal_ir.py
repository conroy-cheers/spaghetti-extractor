from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

from spaghetti_extractor.relational.direct_call_proposal_ir import (
    DirectCallProposalIRError,
    DirectCallSummaryRequest,
    direct_call_proposal_ir_from_plans,
    load_direct_call_proposal_ir,
)
from spaghetti_extractor.util import sha256_file, write_json


class StageADirectCallProposalIRTests(unittest.TestCase):
    def test_summary_request_accepts_frame_only_values_and_rejects_bad_offsets(
        self,
    ) -> None:
        request = DirectCallSummaryRequest(
            0x1018,
            (),
            caller_rva=0x1010,
            caller_frame_word_offsets=(0, 32),
        )

        self.assertIs(request.checked(), request)
        with self.assertRaisesRegex(
            DirectCallProposalIRError,
            "at least one register or caller-frame word",
        ):
            DirectCallSummaryRequest(0x1018, ()).checked()
        with self.assertRaisesRegex(
            DirectCallProposalIRError,
            "contains duplicates",
        ):
            DirectCallSummaryRequest(
                0x1018,
                (),
                caller_frame_word_offsets=(32, 32),
            ).checked()
        with self.assertRaisesRegex(
            DirectCallProposalIRError,
            "callee-frame offset bound",
        ):
            DirectCallSummaryRequest(
                0x1018,
                (),
                caller_frame_word_offsets=(65532,),
            ).checked()

    def _inputs(self, root: Path) -> dict[str, Path]:
        paths = {
            "base_plan": root / "base-plan.json",
            "load_image_contract": root / "load-image-contract.json",
            "machine_import_report": root / "machine-import-report.json",
            "original_pe": root / "original.exe",
            "reference_contract": root / "reference-contract.json",
            "state_machine": root / "state-machine.jsonl",
            "writable_slot_authority_report": root / "writable-report.json",
        }
        for index, path in enumerate(paths.values()):
            path.write_bytes(f"input-{index}\n".encode("ascii"))
        transitions = (
            {
                "edge_conditions": [{"target_rva": 0x1010}],
                "external_events": [{
                    "kind": "internal_call",
                    "return_rva": 0x1010,
                    "target_rva": 0x1020,
                }],
                "outcome": {"kind": "fallthrough", "target_rva": 0x1010},
            },
            {
                "edge_conditions": [{"target_rva": 0x1020}],
                "external_events": [],
                "outcome": {"kind": "jump", "target_rva": 0x1020},
            },
            {
                "edge_conditions": [],
                "external_events": [],
                "outcome": {"kind": "return"},
            },
        )
        paths["state_machine"].write_text(
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
        return paths

    def _plans(
        self, inputs: dict[str, Path]
    ) -> tuple[SimpleNamespace, SimpleNamespace]:
        stack_expression = {
            "op": "load",
            "width": 4,
            "address": {
                "op": "add32",
                "args": [
                    {"op": "reg", "name": "esp"},
                    {"op": "const", "value": 16},
                ],
            },
        }
        stack_site = SimpleNamespace(
            source_rva=0x1010,
            instruction_rva=0x1018,
            category="stack_or_dynamic_pointer",
            is_call=True,
            continuation_rva=0x1020,
            target_expression=stack_expression,
        )
        regions = (
            SimpleNamespace(
                target_id=0,
                rva=0x1000,
                size=16,
                successor_ids=(1, 2),
                root=True,
                alias_rvas=(),
                synthetic_terminal_padding=False,
                indirect_sites=(),
            ),
            SimpleNamespace(
                target_id=1,
                rva=0x1010,
                size=16,
                successor_ids=(2,),
                root=False,
                alias_rvas=(),
                synthetic_terminal_padding=False,
                indirect_sites=(),
            ),
            SimpleNamespace(
                target_id=2,
                rva=0x1020,
                size=16,
                successor_ids=(),
                root=False,
                alias_rvas=(),
                synthetic_terminal_padding=False,
                indirect_sites=(),
            ),
        )
        register_control = {
            "internal_direct_call_sites": [
                {
                    "callsite_rva": 0x1008,
                    "continuation_rva": 0x1010,
                    "continuation_target_id": 1,
                    "edge_index": 99,
                    "source_rva": 0x1000,
                    "source_target_id": 0,
                }
            ],
            "exact_graph": {
                "edges": [
                    {
                        "edge_index": 99,
                        "kind": "call_return",
                        "machine_contract_id": None,
                        "source_target_id": 0,
                        "target_target_id": 1,
                    },
                    {
                        "edge_index": 100,
                        "kind": "direct",
                        "machine_contract_id": None,
                        "source_target_id": 1,
                        "target_target_id": 2,
                    },
                ]
            },
        }
        plan_json = {
            "format": "stage-a-interpreter-mixed-original-v1",
            "state_machine_sha256": sha256_file(inputs["state_machine"]),
            "status": "incomplete",
        }
        common = {
            "state_machine_sha256": sha256_file(inputs["state_machine"]),
            "regions": regions,
            "reachable_target_ids": (0, 1, 2),
            "register_control_provenance": register_control,
            "blockers": (
                SimpleNamespace(
                    reason_code="unresolved_indirect_control",
                    rva=0x1010,
                    detail=(
                        "stack_or_dynamic_pointer requires a runtime proof"
                    ),
                ),
            ),
            "indirect_sites": (stack_site,),
            "to_json": lambda: plan_json,
        }
        authority_base = SimpleNamespace(**common)
        consumed = SimpleNamespace(**common)
        write_json(inputs["base_plan"], plan_json)
        return authority_base, consumed

    def test_round_trip_preserves_hash_bound_phase_projection(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            inputs = self._inputs(root)
            authority_base, consumed = self._plans(inputs)
            projected = direct_call_proposal_ir_from_plans(
                authority_base_plan=authority_base,
                consumed_plan=consumed,
                input_paths=inputs,
            )
            path = root / "direct-call-proposal-ir.json"
            write_json(path, projected.to_json())
            loaded = load_direct_call_proposal_ir(
                path, expected_input_paths=inputs
            )

        self.assertEqual(loaded, projected)
        self.assertEqual(loaded.target_rvas, {
            0: 0x1000,
            1: 0x1010,
            2: 0x1020,
        })
        self.assertEqual(loaded.call_return_edge_index(0, 1), 99)
        self.assertEqual(
            loaded.original_cutpoint_graph.edge_index(
                1, 2, kind="direct"
            ),
            100,
        )
        self.assertEqual(
            loaded.stack_dynamic_control.remaining_source_rvas,
            (0x1010,),
        )

    def test_loader_rejects_changed_input(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            inputs = self._inputs(root)
            authority_base, consumed = self._plans(inputs)
            path = root / "direct-call-proposal-ir.json"
            write_json(
                path,
                direct_call_proposal_ir_from_plans(
                    authority_base_plan=authority_base,
                    consumed_plan=consumed,
                    input_paths=inputs,
                ).to_json(),
            )
            inputs["machine_import_report"].write_text(
                "changed\n", encoding="ascii"
            )
            with self.assertRaisesRegex(
                DirectCallProposalIRError,
                "machine_import_report",
            ):
                load_direct_call_proposal_ir(
                    path, expected_input_paths=inputs
                )

    def test_loader_rejects_duplicate_region_identity(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            inputs = self._inputs(root)
            authority_base, consumed = self._plans(inputs)
            payload = direct_call_proposal_ir_from_plans(
                authority_base_plan=authority_base,
                consumed_plan=consumed,
                input_paths=inputs,
            ).to_json()
            payload["regions"][1]["target_id"] = 0
            path = root / "direct-call-proposal-ir.json"
            write_json(path, payload)
            with self.assertRaisesRegex(
                DirectCallProposalIRError,
                "dense canonical index",
            ):
                load_direct_call_proposal_ir(
                    path, expected_input_paths=inputs
                )

    def test_loader_rejects_plan_payload_drift(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            inputs = self._inputs(root)
            authority_base, consumed = self._plans(inputs)
            path = root / "direct-call-proposal-ir.json"
            write_json(
                path,
                direct_call_proposal_ir_from_plans(
                    authority_base_plan=authority_base,
                    consumed_plan=consumed,
                    input_paths=inputs,
                ).to_json(),
            )
            base = json.loads(inputs["base_plan"].read_text(encoding="utf-8"))
            base["status"] = "ready"
            write_json(inputs["base_plan"], base)
            # Restore the recorded file hash to isolate the canonical-plan
            # check from ordinary input hash validation.
            payload = json.loads(path.read_text(encoding="utf-8"))
            payload["inputs"]["base_plan"] = sha256_file(inputs["base_plan"])
            write_json(path, payload)
            with self.assertRaisesRegex(
                DirectCallProposalIRError,
                "canonical base plan",
            ):
                load_direct_call_proposal_ir(
                    path, expected_input_paths=inputs
                )


if __name__ == "__main__":
    unittest.main()
