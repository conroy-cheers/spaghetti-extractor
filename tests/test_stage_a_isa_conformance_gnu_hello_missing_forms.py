from __future__ import annotations

import shutil
import unittest

from spaghetti_extractor.isa_conformance import (
    ObservationStatus,
    ReportQualification,
    parse_isa_conformance_corpus,
)
from spaghetti_extractor.isa_conformance_lean import run_lean_isa_conformance
from spaghetti_extractor.isa_conformance_unicorn import (
    run_unicorn_corpus,
    unicorn_available,
)


GPRS = ("eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp")
BASE_GPRS = {
    "eax": 0x11223344,
    "ebx": 0x00001000,
    "ecx": 0x55667788,
    "edx": 0x99AABBCC,
    "esi": 0x2000,
    "edi": 0x3000,
    "ebp": 0x70001000,
    "esp": 0x70000FF0,
}
IMAGE_BASE = 0x00400000
EIP = 0x00401000
LOGICAL_FLAGS_MASK = 0x000008C5  # CF, PF, ZF, SF, OF; AF is undefined.


def _x87_state():
    return {
        "control_word": 0x037F,
        "status_word": 0,
        "tag_word": 0xFFFF,
        "last_opcode": 0,
        "instruction_pointer": 0,
        "data_pointer": 0,
        "registers": [[0] * 10 for _ in range(8)],
    }


def _x87_mask():
    return {
        "control_word": 0,
        "status_word": 0,
        "tag_word": 0,
        "last_opcode": 0,
        "instruction_pointer": 0,
        "data_pointer": 0,
        "registers": [[0] * 10 for _ in range(8)],
    }


def _state(*, gprs, eip=EIP, eflags=0x202):
    return {
        "gprs": dict(gprs),
        "eip": eip,
        "eflags": eflags,
        "fs": {"selector": 0, "base": 0},
        "x87": _x87_state(),
    }


def _merge_defined_flags(initial: int, mask: int, value: int) -> int:
    return (initial & ~mask) | (value & mask)


def _case(
    case_id,
    instruction,
    *,
    initial_gprs=None,
    expected_gprs=None,
    gpr_masks=None,
    initial_eflags=0x202,
    expected_eflags=None,
    eflags_mask=0,
    memory=(),
    memory_masks=(),
    expected_memory=(),
    divide_fault=False,
):
    initial = {**BASE_GPRS, **(initial_gprs or {})}
    final = {**initial, **(expected_gprs or {})}
    masks = {
        register: 0 if divide_fault else 0xFFFFFFFF
        for register in GPRS
    }
    masks.update(gpr_masks or {})
    output_masks = {
        "gprs": masks,
        "eip": 0 if divide_fault else 0xFFFFFFFF,
        "eflags": 0 if divide_fault else eflags_mask,
        "fs": {"selector": 0, "base": 0},
        "x87": _x87_mask(),
        "memory": [
            {"address": address, "mask": list(mask)}
            for address, mask in memory_masks
        ],
    }
    if divide_fault:
        expected = {
            "final_state": None,
            "memory": None,
            "control": "fault",
            "fault": "divide_error",
        }
    else:
        expected = {
            "final_state": _state(
                gprs=final,
                eip=EIP + len(instruction),
                eflags=(
                    initial_eflags
                    if expected_eflags is None
                    else expected_eflags
                ),
            ),
            "memory": [
                {"address": address, "bytes": list(data)}
                for address, data in expected_memory
            ],
            "control": "fallthrough",
            "fault": "none",
        }
    return {
        "id": case_id,
        "instruction_bytes": list(instruction),
        "profile": {
            "architecture": "x86",
            "cpu": "haswell",
            "execution_mode": "protected-32",
            "environment": "pe32",
            "features": [],
        },
        "image_base": IMAGE_BASE,
        "initial_state": _state(gprs=initial, eflags=initial_eflags),
        "memory": [
            {
                "address": address,
                "bytes": list(data),
                "permissions": permissions,
            }
            for address, data, permissions in memory
        ],
        "defined_outputs": output_masks,
        "expected": expected,
    }


def _logical_cases():
    cases = []
    initial_eflags = 0xAD7
    forms = (
        ("and", 0x22, 0x20, 0xF3, 0x5A, 0x52, 0),
        ("or", 0x0A, 0x08, 0x81, 0x42, 0xC3, 0x84),
        ("xor", 0x32, 0x30, 0xAA, 0xAA, 0x00, 0x44),
    )
    for name, register_opcode, memory_opcode, left, right, result, flags in forms:
        expected_flags = _merge_defined_flags(
            initial_eflags, LOGICAL_FLAGS_MASK, flags
        )
        cases.append(
            _case(
                f"byte-{name}-register-destination",
                [register_opcode, 0xC1],
                initial_gprs={
                    "eax": 0xA1B2C300 | left,
                    "ecx": 0x10203000 | right,
                },
                expected_gprs={"eax": 0xA1B2C300 | result},
                gpr_masks={"eax": 0xFFFFFFFF},
                initial_eflags=initial_eflags,
                expected_eflags=expected_flags,
                eflags_mask=LOGICAL_FLAGS_MASK,
            )
        )
        cases.append(
            _case(
                f"byte-{name}-memory-destination",
                [memory_opcode, 0x03],
                initial_gprs={"eax": 0xA1B2C300 | right, "ebx": 0x1000},
                gpr_masks={"eax": 0xFFFFFFFF, "ebx": 0xFFFFFFFF},
                initial_eflags=initial_eflags,
                expected_eflags=expected_flags,
                eflags_mask=LOGICAL_FLAGS_MASK,
                memory=((0x1000, bytes([left]), "rw"),),
                memory_masks=((0x1000, b"\xff"),),
                expected_memory=((0x1000, bytes([result])),),
            )
        )
    return cases


def _gnu_hello_cases():
    cases = _logical_cases()
    shr_initial_flags = 0xAD7
    cases.extend(
        [
            _case(
                "byte-shr-immediate-one-defined-flags",
                [0xC0, 0xE8, 0x01],
                initial_gprs={"eax": 0xA1B2C381},
                expected_gprs={"eax": 0xA1B2C340},
                gpr_masks={"eax": 0xFFFFFFFF},
                initial_eflags=shr_initial_flags,
                expected_eflags=_merge_defined_flags(
                    shr_initial_flags, LOGICAL_FLAGS_MASK, 0x801
                ),
                eflags_mask=LOGICAL_FLAGS_MASK,
            ),
            _case(
                "byte-shr-immediate-five-defined-flags",
                [0xC0, 0xEA, 0x05],
                initial_gprs={"edx": 0x99AABBA4},
                expected_gprs={"edx": 0x99AABB05},
                initial_eflags=shr_initial_flags,
                expected_eflags=_merge_defined_flags(
                    shr_initial_flags, 0xC5, 0x04
                ),
                eflags_mask=0xC5,
            ),
            _case(
                "mov-moffs8-store-al",
                [0xA2, 0x00, 0x10, 0x00, 0x00],
                initial_gprs={"eax": 0xA1B2C35A},
                gpr_masks={"eax": 0xFFFFFFFF},
                memory=((0x1000, b"\xa5", "rw"),),
                memory_masks=((0x1000, b"\xff"),),
                expected_memory=((0x1000, b"\x5a"),),
            ),
            _case(
                "operand-size-movsx-dx-memory-preserves-upper-half",
                [0x66, 0x0F, 0xBE, 0x16],
                initial_gprs={"edx": 0x99AA1234, "esi": 0x2000},
                expected_gprs={"edx": 0x99AAFF80},
                memory=((0x2000, b"\x80", "r"),),
                memory_masks=((0x2000, b"\xff"),),
                expected_memory=((0x2000, b"\x80"),),
            ),
            _case(
                "bt-register-index-defines-cf",
                [0x0F, 0xA3, 0xC8],
                initial_gprs={"eax": 0x20, "ecx": 5},
                gpr_masks={"eax": 0xFFFFFFFF, "ecx": 0xFFFFFFFF},
                initial_eflags=0x242,
                expected_eflags=0x243,
                eflags_mask=0x01,
            ),
            _case(
                "imul-low-clears-carry-and-overflow-when-product-fits",
                [0x0F, 0xAF, 0xC3],
                initial_gprs={"eax": 100, "ebx": 7},
                expected_gprs={"eax": 700},
                gpr_masks={"eax": 0xFFFFFFFF, "ebx": 0xFFFFFFFF},
                initial_eflags=0xA03,
                expected_eflags=0x202,
                eflags_mask=0x801,
            ),
            _case(
                "imul-low-sets-carry-and-overflow-when-product-truncates",
                [0x0F, 0xAF, 0xC3],
                initial_gprs={"eax": 0x40000000, "ebx": 4},
                expected_gprs={"eax": 0},
                gpr_masks={"eax": 0xFFFFFFFF, "ebx": 0xFFFFFFFF},
                initial_eflags=0x202,
                expected_eflags=0xA03,
                eflags_mask=0x801,
            ),
            _case(
                "idiv-register-positive-success",
                [0xF7, 0xFB],
                initial_gprs={"eax": 100, "edx": 0, "ebx": 7},
                expected_gprs={"eax": 14, "edx": 2},
                gpr_masks={
                    "eax": 0xFFFFFFFF,
                    "edx": 0xFFFFFFFF,
                    "ebx": 0xFFFFFFFF,
                },
            ),
            _case(
                "idiv-register-negative-dividend-success",
                [0xF7, 0xFB],
                initial_gprs={
                    "eax": 0xFFFFFF9C,
                    "edx": 0xFFFFFFFF,
                    "ebx": 7,
                },
                expected_gprs={"eax": 0xFFFFFFF2, "edx": 0xFFFFFFFE},
                gpr_masks={
                    "eax": 0xFFFFFFFF,
                    "edx": 0xFFFFFFFF,
                    "ebx": 0xFFFFFFFF,
                },
            ),
            _case(
                "idiv-gnu-memory-form-negative-divisor-success",
                [0xF7, 0x7C, 0x24, 0x40],
                initial_gprs={
                    "eax": 100,
                    "edx": 0,
                    "esp": 0x70000FF0,
                },
                expected_gprs={"eax": 0xFFFFFFF2, "edx": 2},
                memory=((0x70001030, (0xFFFFFFF9).to_bytes(4, "little"), "r"),),
                memory_masks=((0x70001030, b"\xff\xff\xff\xff"),),
                expected_memory=((
                    0x70001030,
                    (0xFFFFFFF9).to_bytes(4, "little"),
                ),),
            ),
            _case(
                "idiv-register-divide-by-zero-fault",
                [0xF7, 0xFB],
                initial_gprs={"eax": 100, "edx": 0, "ebx": 0},
                divide_fault=True,
            ),
            _case(
                "idiv-register-signed-quotient-overflow-fault",
                [0xF7, 0xFB],
                initial_gprs={
                    "eax": 0x80000000,
                    "edx": 0xFFFFFFFF,
                    "ebx": 0xFFFFFFFF,
                },
                divide_fault=True,
            ),
        ]
    )
    return cases


def _gnu_hello_corpus():
    return parse_isa_conformance_corpus(
        {
            "format": "stage-a-isa-conformance-corpus-v1",
            "id": "gnu-hello-missing-instruction-forms-v1",
            "cases": _gnu_hello_cases(),
        }
    )


class StageAISAConformanceGNUHelloMissingFormsTests(unittest.TestCase):
    def assertMaskedObservationsEqual(self, case, lean, unicorn):
        self.assertEqual(lean.actual, unicorn.actual, case.id)
        if case.expected.final_state is None:
            self.assertIsNone(lean.final_state, case.id)
            self.assertIsNone(unicorn.final_state, case.id)
            self.assertIsNone(lean.memory, case.id)
            self.assertIsNone(unicorn.memory, case.id)
            return

        self.assertIsNotNone(lean.final_state, case.id)
        self.assertIsNotNone(unicorn.final_state, case.id)
        assert lean.final_state is not None
        assert unicorn.final_state is not None
        masks = case.defined_outputs
        for register in GPRS:
            mask = getattr(masks.gprs, register)
            self.assertEqual(
                getattr(lean.final_state.gprs, register) & mask,
                getattr(unicorn.final_state.gprs, register) & mask,
                f"{case.id}: {register}",
            )
        self.assertEqual(
            lean.final_state.eip & masks.eip,
            unicorn.final_state.eip & masks.eip,
            f"{case.id}: eip",
        )
        self.assertEqual(
            lean.final_state.eflags & masks.eflags,
            unicorn.final_state.eflags & masks.eflags,
            f"{case.id}: eflags",
        )
        self.assertEqual(
            lean.final_state.fs.selector & masks.fs.selector,
            unicorn.final_state.fs.selector & masks.fs.selector,
            f"{case.id}: fs.selector",
        )
        self.assertEqual(
            lean.final_state.fs.base & masks.fs.base,
            unicorn.final_state.fs.base & masks.fs.base,
            f"{case.id}: fs.base",
        )

        self.assertIsNotNone(lean.memory, case.id)
        self.assertIsNotNone(unicorn.memory, case.id)
        assert lean.memory is not None
        assert unicorn.memory is not None
        lean_bytes = {
            region.address + offset: value
            for region in lean.memory
            for offset, value in enumerate(region.data)
        }
        unicorn_bytes = {
            region.address + offset: value
            for region in unicorn.memory
            for offset, value in enumerate(region.data)
        }
        for region in masks.memory:
            for offset, mask in enumerate(region.mask):
                address = region.address + offset
                self.assertEqual(
                    lean_bytes[address] & mask,
                    unicorn_bytes[address] & mask,
                    f"{case.id}: memory[0x{address:08x}]",
                )

    @unittest.skipUnless(shutil.which("lean"), "Lean is required")
    def test_authoritative_lean_semantics_cover_gnu_hello_missing_forms(self):
        corpus = _gnu_hello_corpus()

        report = run_lean_isa_conformance(corpus)

        for observation in report.observations:
            with self.subTest(case=observation.case_id):
                self.assertEqual(
                    observation.status,
                    ObservationStatus.MATCH,
                    observation.detail,
                )
        self.assertEqual(
            report.qualification, ReportQualification.QUALIFIED, report
        )
        self.assertEqual(report.counts.cases, len(corpus.cases))
        self.assertEqual(report.counts.matched, len(corpus.cases))
        self.assertFalse(report.trust.proof_authority)
        self.assertFalse(report.trust.closes_stage_a_proof)

    @unittest.skipUnless(shutil.which("lean"), "Lean is required")
    @unittest.skipUnless(unicorn_available(), "optional Unicorn binding unavailable")
    def test_optional_unicorn_agrees_with_lean_on_all_defined_outputs(self):
        corpus = _gnu_hello_corpus()

        lean_report = run_lean_isa_conformance(corpus)
        unicorn_report = run_unicorn_corpus(corpus)

        self.assertEqual(
            lean_report.qualification,
            ReportQualification.QUALIFIED,
            lean_report,
        )
        self.assertEqual(
            unicorn_report.qualification,
            ReportQualification.QUALIFIED,
            unicorn_report,
        )
        for case, lean, unicorn in zip(
            corpus.cases,
            lean_report.observations,
            unicorn_report.observations,
            strict=True,
        ):
            with self.subTest(case=case.id):
                self.assertEqual(lean.status, ObservationStatus.MATCH, lean.detail)
                self.assertEqual(
                    unicorn.status, ObservationStatus.MATCH, unicorn.detail
                )
                self.assertMaskedObservationsEqual(case, lean, unicorn)


if __name__ == "__main__":
    unittest.main()
