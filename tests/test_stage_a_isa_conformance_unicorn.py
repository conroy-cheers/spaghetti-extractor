import copy
import unittest
from unittest import mock

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
    unicorn_x87_capability_detail,
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


def _state(*, eip=0x00401000, gprs=None, x87=None):
    return {
        "gprs": dict(GPR_VALUES if gprs is None else gprs),
        "eip": eip,
        "eflags": 0x202,
        "fs": {"selector": 0, "base": 0},
        "x87": _x87_state() if x87 is None else x87,
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

    def test_profile_x87_and_system_boundaries_fail_closed(self):
        wrong_cpu = _case(case_id="wrong-cpu")
        wrong_cpu["profile"]["cpu"] = "pentium4"
        x87_metadata_input = _case(case_id="x87-metadata-input")
        x87_metadata_input["initial_state"]["x87"]["last_opcode"] = 1
        x87_metadata_output = _case(case_id="x87-metadata-output")
        x87_metadata_output["defined_outputs"]["x87"]["last_opcode"] = 0x7FF
        x87_opcode = _case(case_id="x87-opcode")
        x87_opcode["instruction_bytes"] = [0xD9, 0xE8]
        x87_opcode["expected"]["final_state"] = _state(
            eip=0x00401002,
            gprs=GPR_VALUES,
        )
        x87_status_opcode = _case(case_id="x87-status-opcode")
        x87_status_opcode["instruction_bytes"] = [0xDF, 0xE0]
        x87_status_opcode["expected"]["final_state"] = _state(
            eip=0x00401002,
            gprs=GPR_VALUES,
        )
        system = _case(case_id="system")
        system["instruction_bytes"] = [0x0F, 0xA2]
        system["expected"]["final_state"]["eip"] = 0x00401002

        unsupported_details = {
            "wrong-cpu": "CPU profile",
            "system": "system instruction",
        }
        for payload in (wrong_cpu, system):
            with self.subTest(case=payload["id"]):
                observation = run_unicorn_case(_corpus(payload).cases[0])
                self.assertEqual(observation.status, ObservationStatus.UNSUPPORTED)
                self.assertIn(
                    unsupported_details[payload["id"]],
                    observation.detail,
                )

        for payload in (x87_metadata_input, x87_metadata_output):
            with self.subTest(case=payload["id"]):
                observation = run_unicorn_case(_corpus(payload).cases[0])
                if unicorn_x87_capability_detail():
                    self.assertEqual(
                        observation.status,
                        ObservationStatus.UNSUPPORTED,
                    )
                else:
                    self.assertEqual(
                        observation.status,
                        ObservationStatus.MATCH,
                    )

        for payload in (x87_opcode, x87_status_opcode):
            with self.subTest(case=payload["id"]):
                x87_observation = run_unicorn_case(
                    _corpus(payload).cases[0]
                )
                if unicorn_x87_capability_detail():
                    self.assertEqual(
                        x87_observation.status,
                        ObservationStatus.UNSUPPORTED,
                    )
                    self.assertIn(
                        "x87 register API",
                        x87_observation.detail,
                    )
                else:
                    self.assertIn(
                        x87_observation.status,
                        {
                            ObservationStatus.MATCH,
                            ObservationStatus.MISMATCH,
                        },
                    )

    def test_invalid_fs_hidden_state_fails_closed(self):
        invalid = _case(case_id="invalid-fs-hidden-state")
        invalid["initial_state"]["fs"] = {
            "selector": 0,
            "base": 0x7FFDF000,
        }

        observation = run_unicorn_case(_corpus(invalid).cases[0])

        self.assertEqual(observation.status, ObservationStatus.UNSUPPORTED)
        self.assertIn("null FS selector", observation.detail)

    def test_x87_capability_probe_is_explicit(self):
        detail = unicorn_x87_capability_detail()
        if unicorn_available():
            self.assertEqual(detail, "")
        else:
            self.assertIn("unavailable", detail)

    @unittest.skipUnless(unicorn_available(), "optional Unicorn binding unavailable")
    def test_x87_capability_failure_is_unsupported_and_cannot_qualify(self):
        payload = _case(case_id="x87-capability-failure")
        payload["instruction_bytes"] = [0xD9, 0xD0]
        payload["expected"]["final_state"] = _state(
            eip=0x00401002,
            gprs=GPR_VALUES,
        )
        corpus = _corpus(payload)

        with mock.patch(
            "spaghetti_extractor.isa_conformance_unicorn._probe_x87_register_api",
            return_value="FP3 read-back truncated the exponent",
        ):
            observation = run_unicorn_case(corpus.cases[0])
            report = run_unicorn_corpus(corpus)

        self.assertEqual(observation.status, ObservationStatus.UNSUPPORTED)
        self.assertIn("FP3 read-back truncated the exponent", observation.detail)
        self.assertEqual(report.qualification, ReportQualification.UNQUALIFIED)
        self.assertEqual(report.counts.unsupported, 1)

    @unittest.skipUnless(unicorn_available(), "optional Unicorn binding unavailable")
    def test_i686_profile_uses_the_pentium2_execution_model(self):
        payload = _case(case_id="i686-mov")
        payload["profile"]["cpu"] = "i686"
        case = _corpus(payload).cases[0]

        observation = run_unicorn_case(case)

        self.assertEqual(observation.status, ObservationStatus.MATCH)
        self.assertTrue(case.matches(observation))

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
    def test_completes_return_and_repeat_without_executing_the_landing_instruction(self):
        return_gprs = dict(GPR_VALUES)
        return_gprs["esp"] = 0x00600000
        returned_gprs = dict(return_gprs)
        returned_gprs["esp"] += 4
        return_payload = _case(case_id="return-to-last-address")
        return_payload["instruction_bytes"] = [0xC3]
        return_payload["initial_state"] = _state(gprs=return_gprs)
        return_payload["memory"] = [
            {
                "address": 0x00600000,
                "bytes": [0xFF, 0xFF, 0xFF, 0xFF],
                "permissions": "r",
            }
        ]
        return_payload["expected"] = {
            "final_state": _state(eip=0xFFFFFFFF, gprs=returned_gprs),
            "memory": [],
            "control": "return",
            "fault": "none",
        }

        repeat_gprs = dict(GPR_VALUES)
        repeat_gprs.update(ecx=1, esi=0x00600000, edi=0x00601000)
        repeated_gprs = dict(repeat_gprs)
        repeated_gprs.update(ecx=0, esi=0x00600004, edi=0x00601004)
        repeat_payload = _case(case_id="rep-movsd-one-iteration")
        repeat_payload["instruction_bytes"] = [0xF3, 0xA5]
        repeat_payload["initial_state"] = _state(gprs=repeat_gprs)
        repeat_payload["memory"] = [
            {
                "address": 0x00600000,
                "bytes": [0x11, 0x22, 0x33, 0x44],
                "permissions": "r",
            },
            {
                "address": 0x00601000,
                "bytes": [0, 0, 0, 0],
                "permissions": "rw",
            },
        ]
        repeat_payload["defined_outputs"]["memory"] = [
            {"address": 0x00601000, "mask": [0xFF] * 4}
        ]
        repeat_payload["expected"] = {
            "final_state": _state(eip=0x00401002, gprs=repeated_gprs),
            "memory": [
                {
                    "address": 0x00601000,
                    "bytes": [0x11, 0x22, 0x33, 0x44],
                }
            ],
            "control": "fallthrough",
            "fault": "none",
        }

        for payload in (return_payload, repeat_payload):
            with self.subTest(case=payload["id"]):
                observation = run_unicorn_case(_corpus(payload).cases[0])
                self.assertEqual(
                    observation.status,
                    ObservationStatus.MATCH,
                    observation.detail,
                )

    @unittest.skipUnless(unicorn_available(), "optional Unicorn binding unavailable")
    def test_round_trips_noncanonical_x87_core_state_across_fnop(self):
        capability_issue = unicorn_x87_capability_detail()
        if capability_issue:
            self.skipTest(capability_issue)
        registers = [
            list(
                (0x8000000000000000 | index).to_bytes(8, "little")
                + (0x3FFF).to_bytes(2, "little")
            )
            for index in range(8)
        ]
        x87 = {
            "control_word": 0x027F,
            "status_word": 3 << 11,
            "tag_word": 0,
            "last_opcode": 0,
            "instruction_pointer": 0,
            "data_pointer": 0,
            "registers": registers,
        }
        payload = _case(case_id="x87-fnop-round-trip")
        payload["instruction_bytes"] = [0xD9, 0xD0]
        payload["initial_state"] = _state(x87=x87)
        payload["defined_outputs"]["x87"] = {
            "control_word": 0xFFFF,
            "status_word": 0xFFFF,
            "tag_word": 0xFFFF,
            "last_opcode": 0,
            "instruction_pointer": 0,
            "data_pointer": 0,
            "registers": [[0xFF] * 10 for _ in range(8)],
        }
        payload["expected"] = {
            "final_state": _state(eip=0x00401002, x87=x87),
            "memory": [],
            "control": "fallthrough",
            "fault": "none",
        }
        case = _corpus(payload).cases[0]

        observation = run_unicorn_case(case)

        self.assertEqual(observation.status, ObservationStatus.MATCH)
        self.assertEqual(observation.final_state.x87, case.initial_state.x87)

    @unittest.skipUnless(unicorn_available(), "optional Unicorn binding unavailable")
    def test_observes_x87_stack_push_status_and_tag_outputs(self):
        capability_issue = unicorn_x87_capability_detail()
        if capability_issue:
            self.skipTest(capability_issue)
        one = list(
            (0x8000000000000000).to_bytes(8, "little")
            + (0x3FFF).to_bytes(2, "little")
        )
        expected_x87 = _x87_state()
        expected_x87.update(
            status_word=7 << 11,
            tag_word=0x3FFF,
            registers=[one, *([[0] * 10] * 7)],
        )
        payload = _case(case_id="x87-fld1-output")
        payload["instruction_bytes"] = [0xD9, 0xE8]
        payload["defined_outputs"]["x87"] = {
            "control_word": 0xFFFF,
            "status_word": 0xFFFF,
            "tag_word": 0xFFFF,
            "last_opcode": 0,
            "instruction_pointer": 0,
            "data_pointer": 0,
            "registers": [[0xFF] * 10, *([[0] * 10] * 7)],
        }
        payload["expected"] = {
            "final_state": _state(eip=0x00401002, x87=expected_x87),
            "memory": [],
            "control": "fallthrough",
            "fault": "none",
        }
        case = _corpus(payload).cases[0]

        observation = run_unicorn_case(case)

        self.assertEqual(observation.status, ObservationStatus.MATCH)
        self.assertEqual(observation.final_state.x87.status_word, 7 << 11)
        self.assertEqual(observation.final_state.x87.tag_word, 0x3FFF)
        self.assertEqual(observation.final_state.x87.registers[0], bytes(one))

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
    def test_executes_popfd_at_pe32_cpl3(self):
        payload = _case(case_id="popfd-cpl3")
        payload["instruction_bytes"] = [0x9D]
        initial_gprs = dict(GPR_VALUES)
        initial_gprs["esp"] = 0x00600000
        expected_gprs = dict(initial_gprs)
        expected_gprs["esp"] += 4
        payload["initial_state"] = _state(gprs=initial_gprs)
        payload["memory"] = [
            {
                "address": 0x00600000,
                # Attempt to raise IOPL while clearing IF. CPL3 must preserve both.
                "bytes": [0x02, 0x30, 0x00, 0x00],
                "permissions": "r",
            }
        ]
        payload["expected"] = {
            "final_state": _state(
                eip=0x00401001,
                gprs=expected_gprs,
            ),
            "memory": [],
            "control": "fallthrough",
            "fault": "none",
        }
        case = _corpus(payload).cases[0]

        observation = run_unicorn_case(case)

        self.assertEqual(observation.status, ObservationStatus.MATCH)
        self.assertEqual(observation.final_state.eflags, 0x202)
        self.assertEqual(observation.final_state.gprs.esp, 0x00600004)

    @unittest.skipUnless(unicorn_available(), "optional Unicorn binding unavailable")
    def test_executes_fs_relative_memory_at_the_declared_hidden_base(self):
        payload = _case(case_id="fs-relative-load")
        payload["instruction_bytes"] = [0x64, 0xA1, 0x18, 0, 0, 0]
        payload["initial_state"]["fs"] = {
            "selector": 0x3B,
            "base": 0x00800000,
        }
        expected_gprs = dict(GPR_VALUES)
        expected_gprs["eax"] = 0x44332211
        expected_state = _state(eip=0x00401006, gprs=expected_gprs)
        expected_state["fs"] = {
            "selector": 0x3B,
            "base": 0x00800000,
        }
        payload["memory"] = [
            {
                "address": 0x00800018,
                "bytes": [0x11, 0x22, 0x33, 0x44],
                "permissions": "r",
            }
        ]
        payload["defined_outputs"]["fs"] = {
            "selector": 0xFFFF,
            "base": 0xFFFFFFFF,
        }
        payload["expected"] = {
            "final_state": expected_state,
            "memory": [],
            "control": "fallthrough",
            "fault": "none",
        }
        case = _corpus(payload).cases[0]

        observation = run_unicorn_case(case)

        self.assertEqual(observation.status, ObservationStatus.MATCH)
        self.assertEqual(observation.final_state.gprs.eax, 0x44332211)
        self.assertEqual(observation.final_state.fs, case.initial_state.fs)

    @unittest.skipUnless(unicorn_available(), "optional Unicorn binding unavailable")
    def test_observes_only_requested_memory_mask_ranges(self):
        payload = _case(case_id="mov-memory")
        payload["instruction_bytes"] = [0x89, 0x18]
        initial_gprs = dict(GPR_VALUES)
        initial_gprs.update(eax=0x6000, ebx=0x44332211)
        payload["initial_state"] = _state(gprs=initial_gprs)
        payload["memory"] = [
            {
                "address": 0x6000,
                "bytes": [0xAA] * 8,
                "permissions": "rw",
            }
        ]
        payload["defined_outputs"]["memory"] = [
            {"address": 0x6001, "mask": [0xFF, 0xFF]}
        ]
        payload["expected"] = {
            "final_state": _state(eip=0x00401002, gprs=initial_gprs),
            "memory": [{"address": 0x6001, "bytes": [0x22, 0x33]}],
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
        self.assertEqual(observation.memory[0].address, 0x6001)
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
