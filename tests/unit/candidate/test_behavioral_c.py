from __future__ import annotations

import json
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

from spaghetti_extractor.artifacts.formats import (
    BEHAVIORAL_C_LAYOUT_INTENT_FORMAT,
    BEHAVIORAL_C_PACKAGE_FORMAT,
)
from spaghetti_extractor.candidate.behavioral_c import (
    BehavioralCLayoutIntent,
    build_behavioral_c_plan,
    write_spx_behavioral_c_package,
)
from spaghetti_extractor.candidate.behavioral_c_render import behavioral_c_source
from spaghetti_extractor.candidate.behavioral_c_package import (
    _runtime_qualification_payload,
)
from spaghetti_extractor.candidate.interpreter_model import (
    CandidateInterpreterError,
    _Action,
    _Node,
    _Transfer,
)
from tests.unit.candidate.interpreter._support import _row, _test_machine_ir_unit


def _transfer(rva: int, *, nodes=(), actions=()) -> _Transfer:
    return _Transfer(
        identity=f"semantic-transfer:{rva:x}",
        contract_sha256="a" * 64,
        instruction_bytes_sha256="b" * 64,
        rva_start=rva,
        nodes=tuple(nodes),
        x87_nodes=(),
        actions=tuple(actions),
        calls=(),
        x87_operations=(),
    )


class BehavioralCBackendTests(unittest.TestCase):
    def test_runtime_qualification_preserves_native_ingress_authority(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            qualification = Path(tmp) / "qualification.json"
            qualification.write_text(json.dumps({
                "format": (
                    "spaghetti-extractor-behavioral-c-runtime-qualification-v1"
                ),
                "status": "complete",
                "machine_ir_sha256": "a" * 64,
                "qualified_providers": ["memory.read"],
                "native_ingress_plan_sha256": "b" * 64,
                "qualified_native_ingress_features": [
                    "same_thread_reentrancy_v1",
                    "host_thread_concurrency_v1",
                ],
                "qualified_private_stack_bytes": 131072,
                "proof_authority": False,
            }), encoding="utf-8")

            payload = _runtime_qualification_payload(
                path=qualification,
                machine_ir_sha256="a" * 64,
                required_providers=["memory.read"],
            )

            self.assertEqual(payload["status"], "complete")
            self.assertEqual(payload["native_ingress_plan_sha256"], "b" * 64)
            self.assertEqual(payload["qualified_private_stack_bytes"], 131072)
            self.assertEqual(payload["qualified_native_ingress_features"], [
                "host_thread_concurrency_v1",
                "same_thread_reentrancy_v1",
            ])

    def test_renders_direct_control_without_semantic_program_tables(self) -> None:
        rows = (
            _transfer(
                0x1000,
                nodes=(_Node("reg", aux=0), _Node("const", immediate=0), _Node("eq", (0, 1))),
                actions=(
                    _Action("eval_word", (2,)),
                    _Action("outcome_branch", (2, 0x1010, 0x1020)),
                ),
            ),
            _transfer(
                0x1010,
                nodes=(_Node("const", immediate=7),),
                actions=(
                    _Action("eval_word", (0,)),
                    _Action("outcome_return", (0,)),
                ),
            ),
            _transfer(
                0x1020,
                nodes=(_Node("const", immediate=9),),
                actions=(
                    _Action("eval_word", (0,)),
                    _Action("outcome_return", (0,)),
                ),
            ),
        )
        plan = build_behavioral_c_plan(rows, entry_rvas=(0x1000,))

        source, spans = behavioral_c_source(rows, plan)

        self.assertEqual(len(plan.functions), 1)
        self.assertEqual(set(spans), {0x1000, 0x1010, 0x1020})
        self.assertIn("if (w_00001000_2) goto spx_unit_00001010", source)
        self.assertEqual(source.count("input = *state;"), 3)
        self.assertNotIn("spx_word_node", source)
        self.assertNotIn("spx_program_transfer", source)
        self.assertNotIn("word_valid", source)

    def test_atomic_observation_is_materialized_only_by_one_rmw(self) -> None:
        row = _transfer(
            0x2000,
            nodes=(
                _Node("const", immediate=0x430320),
                _Node("reg", aux=3),
                _Node("load", (0,), aux=4),
            ),
            actions=(
                _Action("eval_word", (0,)),
                _Action("eval_word", (1,)),
                _Action("atomic_exchange", (0, 1, 2), aux=4),
                _Action("set_reg", (2,), aux=3),
                _Action("sync_eflags"),
                _Action("outcome_return", (2,)),
            ),
        )
        plan = build_behavioral_c_plan((row,), entry_rvas=(0x2000,))

        source, _spans = behavioral_c_source((row,), plan)

        self.assertEqual(source.count("spx_runtime_atomic_exchange("), 1)
        self.assertNotIn("spx_read(rt", source)
        self.assertIn("state->edx = w_00002000_2;", source)

    def test_package_emits_exact_coverage_and_compiler_consumable_c(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            machine_ir = root / "machine-ir.jsonl"
            machine_ir.write_text(
                json.dumps(_test_machine_ir_unit(_row()), sort_keys=True) + "\n",
                encoding="utf-8",
            )

            package = write_spx_behavioral_c_package(
                machine_ir=machine_ir,
                out=root / "out",
                entry_rvas=(0x1000,),
            )

            self.assertEqual(package["format"], BEHAVIORAL_C_PACKAGE_FORMAT)
            self.assertEqual(package["status"], "ready")
            self.assertEqual(package["completion_status"], "complete")
            self.assertEqual(package["counts"]["required_units"], 1)
            self.assertFalse(package["constraints"]["runtime_instruction_decoder"])
            completion = json.loads(
                (root / "out" / "behavioral-c-completion.json").read_text()
            )
            self.assertEqual(len(completion["owned_units"]), 1)
            self.assertEqual(completion["owned_units"][0]["rva_start"], 0x1000)
            compiler = shutil.which("cc")
            if compiler is not None:
                subprocess.run(
                    [
                        compiler,
                        "-std=c11",
                        "-Wall",
                        "-Wextra",
                        "-Werror",
                        "-I",
                        str(root / "out"),
                        "-c",
                        str(root / "out" / "behavioral-c.c"),
                        "-o",
                        str(root / "behavioral-c.o"),
                    ],
                    check=True,
                    capture_output=True,
                    text=True,
                )

    def test_layout_intent_cannot_invent_machine_units(self) -> None:
        row = _transfer(
            0x1000,
            nodes=(_Node("const", immediate=0),),
            actions=(_Action("outcome_return", (0,)),),
        )
        intent = BehavioralCLayoutIntent.from_payload(
            {
                "format": BEHAVIORAL_C_LAYOUT_INTENT_FORMAT,
                "roots": [0xDEAD],
                "names": {},
                "forced_labels": [],
            }
        )

        with self.assertRaises(CandidateInterpreterError) as caught:
            build_behavioral_c_plan((row,), intent=intent)

        self.assertEqual(caught.exception.code, "behavioral_c_layout_unknown_rva")


if __name__ == "__main__":
    unittest.main()
