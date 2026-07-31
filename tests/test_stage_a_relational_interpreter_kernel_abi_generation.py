from __future__ import annotations

import json
import struct
import tempfile
import unittest
from pathlib import Path

from spaghetti_extractor.relational.lean.interpreter_kernel import (
    INTERPRETER_KERNEL_PLAN_FORMAT,
)
from spaghetti_extractor.relational.lean.interpreter_kernel_abi import (
    INTERPRETER_KERNEL_ABI_FORMAT,
    RelationalInterpreterKernelABIGenerationError,
    abi_plan_payload_sha256,
    build_relational_interpreter_kernel_abi_plan,
    relational_interpreter_kernel_abi_parameters_source,
    relational_interpreter_kernel_abi_source,
)
from spaghetti_extractor.relational.lean.interpreter_kernel_data import (
    INTERPRETER_KERNEL_DATA_FORMAT,
)
from spaghetti_extractor.stage_b_engine_layout import (
    EngineField,
    EngineFieldKind,
    EngineFlag,
    EngineLayoutFeature,
    EngineRegister,
    STAGE_B_ENGINE_LAYOUT_HEADER_WORDS,
    STAGE_B_ENGINE_LAYOUT_MAGIC,
    STAGE_B_ENGINE_LAYOUT_RECORD_WORDS,
    STAGE_B_ENGINE_LAYOUT_VERSION,
)
from spaghetti_extractor.util import sha256_bytes


_FIELD_ORDER = {
    EngineFieldKind.REGISTER: 0,
    EngineFieldKind.EFLAGS: 1,
    EngineFieldKind.FLAG: 2,
    EngineFieldKind.X87_STACK: 3,
    EngineFieldKind.X87_EMPTY: 4,
    EngineFieldKind.X87_TAG: 5,
    EngineFieldKind.X87_CONTROL: 6,
    EngineFieldKind.X87_STATUS: 7,
    EngineFieldKind.X87_PENDING_EXCEPTION: 8,
    EngineFieldKind.X87_LAST_OPCODE: 9,
    EngineFieldKind.X87_INSTRUCTION_POINTER: 10,
    EngineFieldKind.X87_CODE_SELECTOR: 11,
    EngineFieldKind.X87_DATA_POINTER: 12,
    EngineFieldKind.X87_DATA_SELECTOR: 13,
    EngineFieldKind.FS_BASE: 14,
    EngineFieldKind.ORIGINAL_RVA: 15,
}


def _field_width(field: EngineField) -> int:
    if field.kind == EngineFieldKind.X87_STACK:
        return 10
    if field.kind in {
        EngineFieldKind.X87_TAG,
        EngineFieldKind.X87_PENDING_EXCEPTION,
    }:
        return 1
    if field.kind in {
        EngineFieldKind.X87_CONTROL,
        EngineFieldKind.X87_STATUS,
        EngineFieldKind.X87_LAST_OPCODE,
        EngineFieldKind.X87_CODE_SELECTOR,
        EngineFieldKind.X87_DATA_SELECTOR,
    }:
        return 2
    return 4


def _layout_bytes(*, omit: EngineField | None = None) -> bytes:
    fields = {EngineField.register(register) for register in EngineRegister}
    fields.update(EngineField.flag(flag) for flag in EngineFlag)
    fields.add(EngineField(EngineFieldKind.EFLAGS))
    fields.update(EngineField.x87_stack(index) for index in range(8))
    fields.update(EngineField.x87_empty(index) for index in range(8))
    fields.update(EngineField.x87_tag(index) for index in range(8))
    fields.update(
        EngineField(kind)
        for kind in (
            EngineFieldKind.X87_CONTROL,
            EngineFieldKind.X87_STATUS,
            EngineFieldKind.X87_PENDING_EXCEPTION,
            EngineFieldKind.X87_LAST_OPCODE,
            EngineFieldKind.X87_INSTRUCTION_POINTER,
            EngineFieldKind.X87_CODE_SELECTOR,
            EngineFieldKind.X87_DATA_POINTER,
            EngineFieldKind.X87_DATA_SELECTOR,
            EngineFieldKind.FS_BASE,
            EngineFieldKind.ORIGINAL_RVA,
        )
    )
    if omit is not None:
        fields.remove(omit)
    ordered = sorted(fields, key=lambda field: (_FIELD_ORDER[field.kind], field.index))
    records: list[int] = []
    cursor = 0
    for field in ordered:
        width = _field_width(field)
        records.extend((int(field.kind), field.index, cursor, width))
        cursor += width
    total_words = STAGE_B_ENGINE_LAYOUT_HEADER_WORDS + len(ordered) * 4
    words = [
        STAGE_B_ENGINE_LAYOUT_MAGIC,
        STAGE_B_ENGINE_LAYOUT_VERSION,
        total_words,
        STAGE_B_ENGINE_LAYOUT_HEADER_WORDS,
        STAGE_B_ENGINE_LAYOUT_RECORD_WORDS,
        len(ordered),
        cursor,
        8,
        int(
            EngineLayoutFeature.SPLIT_FLAGS
            | EngineLayoutFeature.PACKED_EFLAGS
            | EngineLayoutFeature.FS_BASE
            | EngineLayoutFeature.ORIGINAL_RVA
        ),
        0,
        *records,
    ]
    return struct.pack(f"<{len(words)}I", *words)


def _function(role: str, start: int) -> dict[str, object]:
    return {
        "role": role,
        "rva_start": start,
        "rva_end": start + 4,
        "size": 4,
        "sha256": "1" * 64,
        "blocks": [
            {
                "entry_rva": start,
                "instructions": [
                    {"rva": start, "bytes": "55", "mnemonic": "push"},
                    {"rva": start + 1, "bytes": "89e5", "mnemonic": "mov"},
                    {"rva": start + 3, "bytes": "c3", "mnemonic": "ret"},
                ],
                "successors": [],
            }
        ],
        "x87_frames": [],
        "padding": [],
        "loops": [],
        "frame": {
            "required": True,
            "push_rva": start,
            "setup_rva": start + 1,
            "teardown_rvas": [start + 2],
            "return_rvas": [start + 3],
        },
    }


class StageARelationalInterpreterKernelABIGenerationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.layout = _layout_bytes()
        self.layout_path = self.root / "engine-layout.bin"
        self.layout_path.write_bytes(self.layout)
        candidate_digest = "a" * 64
        self.kernel = {
            "format": INTERPRETER_KERNEL_PLAN_FORMAT,
            "candidate": {"pe_sha256": candidate_digest, "size": 4096},
            "program": {"transfer_count": 2},
            "engine_layout": {
                "artifact_sha256": sha256_bytes(self.layout),
                "compiled_range": {
                    "rva_start": 0x1800,
                    "rva_end": 0x1800 + len(self.layout),
                    "size": len(self.layout),
                    "sha256": sha256_bytes(self.layout),
                },
            },
            "kernel_functions": [
                _function(role, 0x1000 + index * 0x100)
                for index, role in enumerate(
                    ("programLookup", "interpreterStep", "runFunction", "invokeCall")
                )
            ],
            "issues": [],
        }
        self.data = {
            "format": INTERPRETER_KERNEL_DATA_FORMAT,
            "candidate_sha256": candidate_digest,
            "table_rva": 0x2000,
            "count_rva": 0x2100,
            "counts": {"transfers": 2},
        }
        self.kernel_path = self.root / "kernel.json"
        self.data_path = self.root / "data.json"
        self._write_inputs()

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def _write_inputs(self) -> None:
        self.kernel_path.write_text(json.dumps(self.kernel), encoding="utf-8")
        self.data_path.write_text(json.dumps(self.data), encoding="utf-8")

    def _build(self):
        return build_relational_interpreter_kernel_abi_plan(
            kernel_plan=self.kernel_path,
            data_inventory=self.data_path,
            engine_layout=self.layout_path,
        )

    def test_builds_concrete_cdecl_and_engine_layout_plan(self) -> None:
        plan = self._build()
        payload = plan.payload()

        self.assertEqual(payload["format"], INTERPRETER_KERNEL_ABI_FORMAT)
        self.assertFalse(payload["acceptance_authority"])
        self.assertEqual(payload["failure_mode"], "none")
        self.assertEqual({row["role"] for row in payload["operations"]}, {
            "programLookup", "interpreterStep", "runFunction", "invokeCall"
        })
        step = next(
            row for row in payload["operations"] if row["role"] == "interpreterStep"
        )
        self.assertEqual(step["cdecl"]["entry_stack_offsets"], [4, 8, 12, 16])
        self.assertIn("hidden-result-pointer", step["cdecl"]["result"])
        self.assertRegex(abi_plan_payload_sha256(plan), r"[0-9a-f]{64}\Z")

        source = relational_interpreter_kernel_abi_source(plan)
        parameters_source = relational_interpreter_kernel_abi_parameters_source(
            plan
        )
        self.assertIn(
            "import StageA.GeneratedRelationalInterpreterKernelABIParameters",
            source,
        )
        self.assertNotIn("def generatedInterpreterEngineLayout", source)
        self.assertIn("def generatedInterpreterEngineLayout", parameters_source)
        self.assertIn(
            "def generatedInterpreterKernelABIParameters", parameters_source
        )
        self.assertNotIn("GeneratedInterpreterKernelDataBundle", parameters_source)
        self.assertIn("buildConcreteKernelABI?", source)
        self.assertIn("generatedInterpreterKernelABIRelation?", source)
        self.assertIn("Option KernelABIRelation", source)
        self.assertIn("generatedInterpreterKernelABIRelationChecked", source)
        self.assertIn(
            "def generatedInterpreterKernelABIRelation : KernelABIRelation",
            source,
        )
        self.assertIn(
            "theorem generatedConcreteInterpreterKernelABIChecked", source
        )
        self.assertIn("def generatedConcreteInterpreterKernelABI :=", source)
        self.assertIn(
            "generatedConcreteInterpreterKernelABI.relation", source
        )
        self.assertIn("decide +kernel", source)
        self.assertIn("#print axioms", source)
        self.assertIn("generatedInterpreterKernelDataCertificate", source)
        self.assertIn("generatedCompiledKernelProgram", source)
        self.assertNotIn("stage_b_", source)
        for marker in ("sorry", "axiom", "unsafe", "native_decide"):
            self.assertNotRegex(source, rf"\b{marker}\b")

    def test_rejects_candidate_layout_and_return_drift(self) -> None:
        self.data["candidate_sha256"] = "b" * 64
        self._write_inputs()
        with self.assertRaisesRegex(
            RelationalInterpreterKernelABIGenerationError,
            "different candidate PEs",
        ):
            self._build()

        self.data["candidate_sha256"] = "a" * 64
        function = self.kernel["kernel_functions"][0]
        function["blocks"][0]["instructions"][-1]["bytes"] = "c20400"
        self._write_inputs()
        with self.assertRaisesRegex(
            RelationalInterpreterKernelABIGenerationError,
            "unsupported cdecl return",
        ):
            self._build()

    def test_rejects_engine_layout_without_exact_required_fields(self) -> None:
        incomplete = _layout_bytes(omit=EngineField(EngineFieldKind.ORIGINAL_RVA))
        self.layout_path.write_bytes(incomplete)
        self.kernel["engine_layout"]["artifact_sha256"] = sha256_bytes(incomplete)
        self.kernel["engine_layout"]["compiled_range"]["size"] = len(incomplete)
        self._write_inputs()
        with self.assertRaisesRegex(
            RelationalInterpreterKernelABIGenerationError,
            "unsupported layout|missing required fields",
        ):
            self._build()


if __name__ == "__main__":
    unittest.main()
