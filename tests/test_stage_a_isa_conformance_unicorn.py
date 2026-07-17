import copy
import unittest

from spaghetti_extractor.isa_conformance import (
    BackendKind,
    ObservationStatus,
    ReportQualification,
    isa_conformance_corpus_sha256,
    parse_isa_conformance_corpus,
)
from spaghetti_extractor.isa_conformance_unicorn import (
    UNICORN_BACKEND_ID,
    run_unicorn_case,
    run_unicorn_corpus,
    unicorn_available,
    unicorn_backend_descriptor,
)


GPR_VALUES = {
    "eax": 1,
    "ebx": 2,
    "ecx": 3,
    "edx": 4,
    "esi": 5,
    "edi": 6,
    "ebp": 0x70001000,
    "esp": 0x70000FF0,
}


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


def _state(*, eip=0x00401000, gprs=None):
    return {
        "gprs": dict(GPR_VALUES if gprs is None else gprs),
        "eip": eip,
        "eflags": 0x202,
        "fs": {"selector": 0, "base": 0},
        "x87": _x87_state(),
    }


def _case(*, case_id="mov-eax-imm32", expected_eax=0x12345678):
    expected_gprs = dict(GPR_VALUES)
    expected_gprs["eax"] = expected_eax
    return {
        "id": case_id,
        "instruction_bytes": [0xB8, 0x78, 0x56, 0x34, 0x12],
        "profile": {
            "architecture": "x86",
            "cpu": "haswell",
            "execution_mode": "protected-32",
            "environment": "pe32",
            "features": [],
        },
        "image_base": 0x00400000,
        "initial_state": _state(),
        "memory": [],
        "defined_outputs": {
            "gprs": {register: 0xFFFFFFFF for register in GPR_VALUES},
            "eip": 0xFFFFFFFF,
            "eflags": 0xFFFFFFFF,
            "fs": {"selector": 0, "base": 0},
            "x87": _x87_mask(),
            "memory": [],
        },
        "expected": {
            "final_state": _state(
                eip=0x00401005,
                gprs=expected_gprs,
            ),
            "memory": [],
            "control": "fallthrough",
            "fault": "none",
        },
    }


def _corpus(*cases):
    return parse_isa_conformance_corpus(
        {
            "format": "stage-a-isa-conformance-corpus-v1",
            "id": "unicorn-bounded-fixtures-v1",
            "cases": list(cases or (_case(),)),
        }
    )


class StageAISAConformanceUnicornTests(unittest.TestCase):
    def test_backend_descriptor_is_explicit_and_evidence_only_report_is_preserved(self):
        descriptor = unicorn_backend_descriptor()
        self.assertEqual(descriptor.id, UNICORN_BACKEND_ID)
        self.assertEqual(descriptor.kind, BackendKind.EMULATOR)
        self.assertTrue(descriptor.version)

        corpus = _corpus()
        report = run_unicorn_corpus(corpus)
        self.assertFalse(report.trust.proof_authority)
        self.assertFalse(report.trust.closes_stage_a_proof)
        self.assertEqual(
            report.input_sha256, isa_conformance_corpus_sha256(corpus)
        )
        self.assertEqual(report.backend, descriptor)
        self.assertEqual(report.counts.cases, 1)
        if unicorn_available():
            self.assertEqual(report.qualification, ReportQualification.QUALIFIED)
        else:
            self.assertEqual(report.qualification, ReportQualification.UNQUALIFIED)
            self.assertEqual(
                report.observations[0].status, ObservationStatus.UNSUPPORTED
            )

    def test_profile_fs_x87_and_system_boundaries_fail_closed(self):
        wrong_cpu = _case(case_id="wrong-cpu")
        wrong_cpu["profile"]["cpu"] = "i686"
        fs_state = _case(case_id="fs-state")
        fs_state["initial_state"]["fs"] = {
            "selector": 0x3B,
            "base": 0x7FFDF000,
        }
        fs_override = _case(case_id="fs-override")
        fs_override["instruction_bytes"] = [0x64, 0xA1, 0, 0, 0, 0]
        fs_override["expected"]["final_state"]["eip"] = 0x00401006
        x87_output = _case(case_id="x87-output")
        x87_output["defined_outputs"]["x87"]["status_word"] = 0xFFFF
        x87_opcode = _case(case_id="x87-opcode")
        x87_opcode["instruction_bytes"] = [0xD9, 0xE8]
        x87_opcode["expected"]["final_state"]["eip"] = 0x00401002
        system = _case(case_id="system")
        system["instruction_bytes"] = [0x0F, 0xA2]
        system["expected"]["final_state"]["eip"] = 0x00401002

        expected_details = {
            "wrong-cpu": "CPU profile",
            "fs-state": "FS",
            "fs-override": "segment overrides",
            "x87-output": "x87 output",
            "x87-opcode": "x87 instructions",
            "system": "system instruction",
        }
        for payload in (
            wrong_cpu,
            fs_state,
            fs_override,
            x87_output,
            x87_opcode,
            system,
        ):
            with self.subTest(case=payload["id"]):
                observation = run_unicorn_case(_corpus(payload).cases[0])
                self.assertEqual(observation.status, ObservationStatus.UNSUPPORTED)
                self.assertIn(expected_details[payload["id"]], observation.detail)

    @unittest.skipUnless(unicorn_available(), "optional Unicorn binding unavailable")
    def test_executes_one_instruction_and_sets_match_mechanically(self):
        case = _corpus(_case()).cases[0]
        observation = run_unicorn_case(case)

        self.assertEqual(observation.status, ObservationStatus.MATCH)
        self.assertTrue(case.matches(observation))
        self.assertEqual(observation.final_state.gprs.eax, 0x12345678)
        self.assertEqual(observation.final_state.eip, 0x00401005)

        mismatching = _corpus(_case(expected_eax=0x12345679)).cases[0]
        mismatch = run_unicorn_case(mismatching)
        self.assertEqual(mismatch.status, ObservationStatus.MISMATCH)
        self.assertFalse(mismatching.matches(mismatch))

        branch_payload = _case(case_id="taken-direct-branch")
        branch_payload["instruction_bytes"] = [0xEB, 0x02]
        branch_payload["expected"] = {
            "final_state": _state(eip=0x00401004),
            "memory": [],
            "control": "direct_branch",
            "fault": "none",
        }
        branch = run_unicorn_case(_corpus(branch_payload).cases[0])
        self.assertEqual(branch.status, ObservationStatus.MATCH)
        self.assertEqual(branch.final_state.eip, 0x00401004)

    @unittest.skipUnless(unicorn_available(), "optional Unicorn binding unavailable")
    def test_reports_a_distinguishable_divide_fault(self):
        payload = _case(case_id="divide-by-zero")
        payload["instruction_bytes"] = [0xF7, 0xF3]
        initial_gprs = dict(GPR_VALUES)
        initial_gprs["ebx"] = 0
        payload["initial_state"] = _state(gprs=initial_gprs)
        payload["defined_outputs"] = {
            "gprs": {register: 0 for register in GPR_VALUES},
            "eip": 0,
            "eflags": 0,
            "fs": {"selector": 0, "base": 0},
            "x87": _x87_mask(),
            "memory": [],
        }
        payload["expected"] = {
            "final_state": None,
            "memory": None,
            "control": "fault",
            "fault": "divide_error",
        }

        observation = run_unicorn_case(_corpus(payload).cases[0])

        self.assertEqual(observation.status, ObservationStatus.MATCH)
        self.assertIsNone(observation.final_state)
        self.assertEqual(observation.actual.fault.value, "divide_error")

    @unittest.skipUnless(unicorn_available(), "optional Unicorn binding unavailable")
    def test_observes_only_requested_memory_mask_ranges(self):
        payload = _case(case_id="mov-memory")
        payload["instruction_bytes"] = [0x89, 0x18]
        initial_gprs = dict(GPR_VALUES)
        initial_gprs.update(eax=0x1000, ebx=0x44332211)
        payload["initial_state"] = _state(gprs=initial_gprs)
        payload["memory"] = [
            {
                "address": 0x1000,
                "bytes": [0xAA] * 8,
                "permissions": "rw",
            }
        ]
        payload["defined_outputs"]["memory"] = [
            {"address": 0x1001, "mask": [0xFF, 0xFF]}
        ]
        payload["expected"] = {
            "final_state": _state(eip=0x00401002, gprs=initial_gprs),
            "memory": [{"address": 0x1001, "bytes": [0x22, 0x33]}],
            "control": "fallthrough",
            "fault": "none",
        }
        case = _corpus(payload).cases[0]

        observation = run_unicorn_case(case)

        self.assertEqual(observation.status, ObservationStatus.MATCH)
        self.assertEqual(
            observation.memory,
            (observation.memory[0],),
        )
        self.assertEqual(observation.memory[0].address, 0x1001)
        self.assertEqual(observation.memory[0].data, b"\x22\x33")

    @unittest.skipUnless(unicorn_available(), "optional Unicorn binding unavailable")
    def test_each_corpus_case_gets_an_independent_engine(self):
        first = _case(case_id="first")
        second = copy.deepcopy(first)
        second["id"] = "second"
        report = run_unicorn_corpus(_corpus(first, second))

        self.assertEqual(report.counts.matched, 2)
        self.assertEqual(report.qualification, ReportQualification.QUALIFIED)


if __name__ == "__main__":
    unittest.main()
