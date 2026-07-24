from __future__ import annotations

import hashlib
import json
import re
import tempfile
import unittest
from pathlib import Path

from spaghetti_extractor.relational.lean.interpreter_kernel import (
    INTERPRETER_KERNEL_PLAN_FORMAT,
)
from spaghetti_extractor.relational.lean.interpreter_kernel_abi import (
    INTERPRETER_KERNEL_ABI_FORMAT,
)
from spaghetti_extractor.relational.lean.interpreter_kernel_data import (
    INTERPRETER_KERNEL_DATA_FORMAT,
)
from spaghetti_extractor.relational.lean.interpreter_kernel_program_lookup_operation import (
    INTERPRETER_KERNEL_PROGRAM_LOOKUP_OPERATION_FORMAT,
    INTERPRETER_KERNEL_PROGRAM_LOOKUP_OPERATION_LEAN_FILENAME,
    INTERPRETER_KERNEL_PROGRAM_LOOKUP_OPERATION_PLAN_FILENAME,
    RelationalInterpreterKernelProgramLookupOperationGenerationError,
    build_relational_interpreter_kernel_program_lookup_operation_plan,
    relational_interpreter_kernel_program_lookup_operation_source,
    write_relational_interpreter_kernel_program_lookup_operation_bundle,
)
from spaghetti_extractor.relational.lean.interpreter_kernel_lookup_native import (
    build_relational_interpreter_kernel_lookup_native_plan,
)
from spaghetti_extractor.relational.lean.interpreter_kernel_summary import (
    _PROGRAM_LOOKUP_TEMPLATE_BLOCKS,
    _program_lookup_template_bytes,
)
from spaghetti_extractor.util import sha256_file


def _function() -> dict[str, object]:
    start = 0x1000
    blob = _program_lookup_template_bytes(0x403020, 0x403000)
    offsets = sorted(
        offset
        for _, _, instructions in _PROGRAM_LOOKUP_TEMPLATE_BLOCKS
        for offset in instructions
    )
    ends = {
        offset: offsets[index + 1] if index + 1 < len(offsets) else len(blob)
        for index, offset in enumerate(offsets)
    }
    return {
        "role": "programLookup",
        "rva_start": start,
        "rva_end": start + len(blob),
        "size": len(blob),
        "sha256": hashlib.sha256(blob).hexdigest(),
        "blocks": [
            {
                "entry_rva": start + entry,
                "successors": [start + successor for successor in successors],
                "instructions": [
                    {
                        "rva": start + offset,
                        "bytes": blob[offset : ends[offset]].hex(),
                    }
                    for offset in instructions
                ],
            }
            for entry, successors, instructions in _PROGRAM_LOOKUP_TEMPLATE_BLOCKS
        ],
        "x87_frames": [],
    }


class StageARelationalInterpreterKernelProgramLookupOperationTests(
    unittest.TestCase
):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.candidate = self.root / "candidate.exe"
        self.kernel = self.root / "kernel.json"
        self.data = self.root / "data.json"
        self.lookup = self.root / "lookup.json"
        self.abi = self.root / "abi.json"
        candidate = b"exact candidate fixture" * 17
        self.candidate.write_bytes(candidate)
        digest = hashlib.sha256(candidate).hexdigest()
        kernel = {
            "format": INTERPRETER_KERNEL_PLAN_FORMAT,
            "candidate": {"pe_sha256": digest, "size": len(candidate)},
            "program": {"transfer_count": 7},
            "kernel_functions": [_function()],
            "issues": [],
        }
        data = {
            "format": INTERPRETER_KERNEL_DATA_FORMAT,
            "candidate_sha256": digest,
            "candidate_bytes": len(candidate),
            "table_rva": 0x3000,
            "count_rva": 0x3020,
            "counts": {"transfers": 7},
        }
        self.kernel.write_text(json.dumps(kernel), encoding="utf-8")
        self.data.write_text(json.dumps(data), encoding="utf-8")
        lookup = build_relational_interpreter_kernel_lookup_native_plan(
            kernel_plan=self.kernel,
            data_inventory=self.data,
            candidate_pe=self.candidate,
        )
        self.lookup.write_text(json.dumps(lookup.payload()), encoding="utf-8")
        self._write_abi(digest)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def _abi_payload(self, digest: str) -> dict[str, object]:
        return {
            "format": INTERPRETER_KERNEL_ABI_FORMAT,
            "candidate_pe_sha256": digest,
            "inputs": {
                "kernel_plan": {
                    "path": self.kernel.name,
                    "sha256": sha256_file(self.kernel),
                },
                "data_inventory": {
                    "path": self.data.name,
                    "sha256": sha256_file(self.data),
                },
                "engine_layout": {"path": "layout.bin", "sha256": "0" * 64},
            },
            "candidate_offsets": {
                "engine_layout": {"start": 0x4000, "size": 64},
                "program_table": 0x3000,
                "program_count": 0x3020,
            },
            "program_records": 7,
            "operations": [
                {
                    "role": "programLookup",
                    "function_index": 0,
                    "image_offset": 0x1000,
                    "return_offsets": [0x10A0],
                }
            ],
            "failure_mode": "none",
        }

    def _write_abi(self, digest: str) -> None:
        self.abi.write_text(
            json.dumps(self._abi_payload(digest)), encoding="utf-8"
        )

    def _build(self):
        return build_relational_interpreter_kernel_program_lookup_operation_plan(
            kernel_plan=self.kernel,
            data_inventory=self.data,
            candidate_pe=self.candidate,
            lookup_native_plan=self.lookup,
            abi_plan=self.abi,
        )

    def test_plan_closes_every_proof_premise_from_exact_artifacts(self) -> None:
        payload = self._build().payload()

        self.assertEqual(
            payload["format"], INTERPRETER_KERNEL_PROGRAM_LOOKUP_OPERATION_FORMAT
        )
        self.assertFalse(payload["acceptance_authority"])
        self.assertEqual(payload["remaining_proof_premises"], [])
        self.assertEqual(payload["result"]["status"], "ready-for-lean-check")
        self.assertEqual(
            payload["checked_artifact_compatibility"],
            {
                "function_symbol": "generatedKernelFunction0000",
                "entry_rva": 0x1000,
                "table_rva": 0x3000,
                "count_rva": 0x3020,
                "record_count": 7,
            },
        )

    def test_source_emits_closed_operation_term(self) -> None:
        source = relational_interpreter_kernel_program_lookup_operation_source(
            self._build()
        )
        for required in (
            "generatedConcreteInterpreterKernelABI",
            "generatedProgramLookupSummaryCore",
            "sourceRvasAdjacentSortedChecked_sound",
            "GeneratedProgramLookupNativeRefinesUsing",
            "theorem generatedProgramLookupOperationRefinesUsing",
            "(environment : NativeEnvironment)",
        ):
            self.assertIn(required, source)
        theorem = source.split(
            "theorem generatedProgramLookupOperationRefinesUsing", 1
        )[1].split("#print axioms", 1)[0]
        self.assertNotIn("(summary :", theorem)
        self.assertNotIn("(programExact :", theorem)
        self.assertNotIn("(nativeChecked :", theorem)
        for forbidden in (
            "whole_native_path",
            "caller_selected_final_state",
            "python_status_as_proof",
        ):
            self.assertNotIn(forbidden, source)
        for marker in ("sorry", "axiom", "unsafe", "native_decide"):
            self.assertIsNone(re.search(rf"\b{marker}\b", source), marker)

    def test_rejects_each_incompatible_abi_boundary(self) -> None:
        cases = (
            ("candidate_pe_sha256", "f" * 64, "candidate identity"),
            ("program_records", 8, "record count"),
        )
        for key, value, message in cases:
            with self.subTest(key=key):
                payload = self._abi_payload(hashlib.sha256(self.candidate.read_bytes()).hexdigest())
                payload[key] = value
                self.abi.write_text(json.dumps(payload), encoding="utf-8")
                with self.assertRaisesRegex(
                    RelationalInterpreterKernelProgramLookupOperationGenerationError,
                    message,
                ):
                    self._build()

        payload = self._abi_payload(hashlib.sha256(self.candidate.read_bytes()).hexdigest())
        payload["candidate_offsets"]["program_table"] = 0x3004
        self.abi.write_text(json.dumps(payload), encoding="utf-8")
        with self.assertRaisesRegex(
            RelationalInterpreterKernelProgramLookupOperationGenerationError,
            "program_table offset",
        ):
            self._build()

        payload = self._abi_payload(hashlib.sha256(self.candidate.read_bytes()).hexdigest())
        payload["inputs"]["data_inventory"]["sha256"] = "1" * 64
        self.abi.write_text(json.dumps(payload), encoding="utf-8")
        with self.assertRaisesRegex(
            RelationalInterpreterKernelProgramLookupOperationGenerationError,
            "data_inventory identity",
        ):
            self._build()

        payload = self._abi_payload(hashlib.sha256(self.candidate.read_bytes()).hexdigest())
        payload["operations"][0]["function_index"] = 1
        self.abi.write_text(json.dumps(payload), encoding="utf-8")
        with self.assertRaisesRegex(
            RelationalInterpreterKernelProgramLookupOperationGenerationError,
            "function index",
        ):
            self._build()

    def test_writer_is_deterministic_and_module_names_fail_closed(self) -> None:
        first = self.root / "first"
        second = self.root / "second"
        kwargs = {
            "kernel_plan": self.kernel,
            "data_inventory": self.data,
            "candidate_pe": self.candidate,
            "lookup_native_plan": self.lookup,
            "abi_plan": self.abi,
        }
        write_relational_interpreter_kernel_program_lookup_operation_bundle(
            out=first, **kwargs
        )
        write_relational_interpreter_kernel_program_lookup_operation_bundle(
            out=second, **kwargs
        )
        for filename in (
            INTERPRETER_KERNEL_PROGRAM_LOOKUP_OPERATION_PLAN_FILENAME,
            INTERPRETER_KERNEL_PROGRAM_LOOKUP_OPERATION_LEAN_FILENAME,
        ):
            self.assertEqual((first / filename).read_bytes(), (second / filename).read_bytes())
        with self.assertRaisesRegex(
            RelationalInterpreterKernelProgramLookupOperationGenerationError,
            "qualified StageA Lean module",
        ):
            relational_interpreter_kernel_program_lookup_operation_source(
                self._build(), abi_module="Generated.Bad"
            )


if __name__ == "__main__":
    unittest.main()
