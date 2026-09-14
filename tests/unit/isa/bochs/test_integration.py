from __future__ import annotations

from tests.unit.isa.bochs._support import *

TESTKIT = {"fixtures": ("bochs-conformance",)}


@unittest.skipUnless(
    _REAL_BOCHS_RUNNER is not None,
    "requires a built source backend or SPAGHETTI_BOCHS_INTEGRATION_RUNNER",
)
class ISAConformanceBochsIntegrationTests(unittest.TestCase):
    def test_i686_profile_uses_the_pentium2_execution_model(self):
        case = _bochs_case(
            "i686-mov-reg-imm",
            [0xB8, 0x78, 0x56, 0x34, 0x12],
            expected_gprs={"eax": 0x12345678},
            defined_gprs={"eax"},
        )
        case["profile"]["cpu"] = "i686"
        corpus = parse_isa_conformance_corpus(
            {
                "format": "spaghetti-extractor-isa-conformance-corpus-v1",
                "id": "bochs-i686-profile-integration-v1",
                "cases": [case],
            }
        )

        report = run_bochs_corpus(
            corpus,
            runner=_REAL_BOCHS_RUNNER,
            timeout_seconds=120,
        )

        self.assertEqual(
            report.observations[0].status,
            ObservationStatus.MATCH,
            report.observations[0].detail,
        )

    def test_x87_state_is_injected_observed_and_reset_between_cases(self):
        injected = {
            "control_word": 0x027F,
            "status_word": 0x6100,
            "tag_word": 0xA55A,
            "last_opcode": 0x345,
            "instruction_pointer": 0x00123456,
            "data_pointer": 0x00654321,
            "registers": [
                list(bytes(((index * 17 + byte) & 0xFF for byte in range(10))))
                for index in range(8)
            ],
        }
        full_x87_mask = _x87(mask=True)
        one = list(bytes.fromhex("0000000000000080ff3f"))
        fld1_result = _x87()
        fld1_result.update(
            status_word=0x3800,
            tag_word=0x3FFF,
            registers=[one] + [[0] * 10 for _ in range(7)],
        )
        fld1_mask = _x87(mask=True)
        fld1_mask.update(
            last_opcode=0,
            instruction_pointer=0,
            data_pointer=0,
        )
        cases = [
            _bochs_case(
                "x87-injected-fnstsw",
                [0xDF, 0xE0],
                initial_gprs={"eax": 0xA5A50000},
                expected_gprs={"eax": 0xA5A56100},
                defined_gprs={"eax"},
                initial_x87=injected,
                expected_x87=injected,
                defined_x87=full_x87_mask,
                profile_features=("x87",),
            ),
            _bochs_case(
                "x87-fld1-after-reset",
                [0xD9, 0xE8],
                expected_x87=fld1_result,
                defined_x87=fld1_mask,
                profile_features=("x87",),
            ),
            _bochs_case(
                "x87-fld-double-memory",
                [0xDD, 0x00],
                initial_gprs={"eax": 0x00060000},
                memory=[
                    {
                        "address": 0x00060000,
                        "bytes": list(bytes.fromhex("000000000000f03f")),
                        "permissions": "r",
                    }
                ],
                expected_x87=fld1_result,
                defined_x87=fld1_mask,
                profile_features=("x87",),
            ),
            _bochs_case(
                "x87-fnsave-memory",
                [0xDD, 0x30],
                initial_gprs={"eax": 0x00060000},
                memory=[
                    {
                        "address": 0x00060000,
                        "bytes": [0] * 256,
                        "permissions": "rw",
                    }
                ],
                profile_features=("x87",),
            ),
        ]
        for case in cases:
            case["profile"]["cpu"] = "i686"
        corpus = parse_isa_conformance_corpus(
            {
                "format": "spaghetti-extractor-isa-conformance-corpus-v1",
                "id": "bochs-x87-state-integration-v1",
                "cases": cases,
            }
        )

        report = run_bochs_corpus(
            corpus,
            runner=_REAL_BOCHS_RUNNER,
            timeout_seconds=120,
        )

        self.assertEqual(
            [observation.status for observation in report.observations],
            [ObservationStatus.MATCH] * len(cases),
            {
                row.case_id: (row.status.value, row.detail)
                for row in report.observations
            },
        )
        self.assertEqual(
            report.observations[0].final_state.x87.registers[5],
            bytes(injected["registers"][5]),
        )
        self.assertEqual(
            report.observations[1].final_state.x87.registers[0],
            bytes(one),
        )
        self.assertEqual(
            report.observations[2].final_state.x87.registers[0],
            bytes(one),
        )
        self.assertFalse(report.trust.proof_authority)

    def test_divide_success_and_faults_recover_in_one_batch(self):
        divisor_memory = [
            {
                "address": 0x00060000,
                "bytes": [0, 0, 0, 0],
                "permissions": "r",
            }
        ]
        observed_divisor_memory = [
            {"address": 0x00060000, "bytes": [0, 0, 0, 0]}
        ]
        cases = [
            _bochs_case(
                "div-memory-zero",
                [0xF7, 0x31],
                initial_gprs={"eax": 10, "ecx": 0x00060000, "edx": 0},
                defined_gprs=set(GPRS),
                memory=divisor_memory,
                expected_memory=observed_divisor_memory,
                defined_memory=[
                    {"address": 0x00060000, "mask": [0xFF, 0xFF, 0xFF, 0xFF]}
                ],
                expected_fault="divide_error",
            ),
            _bochs_case(
                "div-register-success",
                [0xF7, 0xF1],
                initial_gprs={"eax": 10, "ecx": 3, "edx": 0},
                expected_gprs={"eax": 3, "edx": 1},
                defined_gprs={"eax", "edx"},
            ),
            _bochs_case(
                "idiv-register-overflow",
                [0xF7, 0xF9],
                initial_gprs={"eax": 0, "ecx": 1, "edx": 1},
                defined_gprs=set(GPRS),
                expected_fault="divide_error",
            ),
            _bochs_case(
                "idiv-register-success",
                [0xF7, 0xF9],
                initial_gprs={
                    "eax": 0xFFFFFFF6,
                    "ecx": 3,
                    "edx": 0xFFFFFFFF,
                },
                expected_gprs={"eax": 0xFFFFFFFD, "edx": 0xFFFFFFFF},
                defined_gprs={"eax", "edx"},
            ),
        ]
        corpus = parse_isa_conformance_corpus(
            {
                "format": "spaghetti-extractor-isa-conformance-corpus-v1",
                "id": "bochs-divide-error-integration-v1",
                "cases": cases,
            }
        )

        report = run_bochs_corpus(
            corpus,
            runner=_REAL_BOCHS_RUNNER,
            timeout_seconds=120,
        )

        self.assertEqual(
            [observation.status for observation in report.observations],
            [ObservationStatus.MATCH] * len(cases),
            {
                row.case_id: (row.status.value, row.detail)
                for row in report.observations
            },
        )
        self.assertEqual(
            [
                observation.actual.fault.value
                for observation in report.observations
            ],
            ["divide_error", "none", "divide_error", "none"],
        )
        self.assertFalse(report.trust.proof_authority)

    def test_cpl3_fs_and_repeat_execution_are_observed_without_special_cases(self):
        fs = {"selector": 0x3B, "base": 0x00080000}
        cases = [
            _bochs_case(
                "popfd-cpl3",
                [0x9D],
                initial_gprs={"esp": 0x00060000},
                expected_gprs={"esp": 0x00060004},
                defined_gprs={"esp"},
                initial_eflags=0x202,
                expected_eflags=0x202,
                defined_eflags=0xFFFFFFFF,
                memory=[
                    {
                        "address": 0x00060000,
                        # CPL3 may not raise IOPL or clear IF while IOPL is zero.
                        "bytes": [0x02, 0x30, 0x00, 0x00],
                        "permissions": "r",
                    }
                ],
            ),
            _bochs_case(
                "fs-relative-load",
                [0x64, 0xA1, 0x18, 0, 0, 0],
                initial_fs=fs,
                expected_fs=fs,
                defined_fs=True,
                expected_gprs={"eax": 0x44332211},
                defined_gprs={"eax"},
                memory=[
                    {
                        "address": 0x00080018,
                        "bytes": [0x11, 0x22, 0x33, 0x44],
                        "permissions": "r",
                    }
                ],
            ),
            _bochs_case(
                "rep-movsd-single-iteration",
                [0xF3, 0xA5],
                initial_gprs={
                    "ecx": 1,
                    "esi": 0x00060000,
                    "edi": 0x00061000,
                },
                expected_gprs={
                    "ecx": 0,
                    "esi": 0x00060004,
                    "edi": 0x00061004,
                },
                defined_gprs={"ecx", "esi", "edi"},
                memory=[
                    {
                        "address": 0x00060000,
                        "bytes": [0x11, 0x22, 0x33, 0x44],
                        "permissions": "r",
                    },
                    {
                        "address": 0x00061000,
                        "bytes": [0, 0, 0, 0],
                        "permissions": "rw",
                    },
                ],
                expected_memory=[
                    {
                        "address": 0x00061000,
                        "bytes": [0x11, 0x22, 0x33, 0x44],
                    }
                ],
                defined_memory=[
                    {
                        "address": 0x00061000,
                        "mask": [0xFF, 0xFF, 0xFF, 0xFF],
                    }
                ],
            ),
            _bochs_case(
                "rep-stosd-single-iteration",
                [0xF3, 0xAB],
                initial_gprs={
                    "eax": 0x44332211,
                    "ecx": 1,
                    "edi": 0x00061000,
                },
                expected_gprs={"ecx": 0, "edi": 0x00061004},
                defined_gprs={"ecx", "edi"},
                memory=[
                    {
                        "address": 0x00061000,
                        "bytes": [0, 0, 0, 0],
                        "permissions": "rw",
                    }
                ],
                expected_memory=[
                    {
                        "address": 0x00061000,
                        "bytes": [0x11, 0x22, 0x33, 0x44],
                    }
                ],
                defined_memory=[
                    {
                        "address": 0x00061000,
                        "mask": [0xFF, 0xFF, 0xFF, 0xFF],
                    }
                ],
            ),
        ]
        corpus = parse_isa_conformance_corpus(
            {
                "format": "spaghetti-extractor-isa-conformance-corpus-v1",
                "id": "bochs-cpl3-fs-repeat-integration-v1",
                "cases": cases,
            }
        )

        report = run_bochs_corpus(
            corpus,
            runner=_REAL_BOCHS_RUNNER,
            timeout_seconds=120,
        )

        self.assertEqual(
            [observation.status for observation in report.observations],
            [ObservationStatus.MATCH] * len(cases),
            {
                row.case_id: (row.status.value, row.detail)
                for row in report.observations
            },
        )
        self.assertFalse(report.trust.proof_authority)

    def test_generic_register_memory_and_branch_cases_execute_fail_closed(self):
        memory_read = [
            {
                "address": 0x00060000,
                "bytes": [0x78, 0x56, 0x34, 0x12],
                "permissions": "r",
            }
        ]
        memory_write = [
            {
                "address": 0x00060000,
                "bytes": [0, 0, 0, 0],
                "permissions": "rw",
            }
        ]
        memory_reset = [
            {
                "address": 0x00060000,
                "bytes": [0xEF, 0xBE, 0xAD, 0xDE],
                "permissions": "rw",
            }
        ]
        memory_outside_guest = [
            {
                "address": 0x00001000,
                "bytes": [0, 0, 0, 0],
                "permissions": "rw",
            }
        ]
        call_stack = [
            {
                "address": 0x00020000,
                "bytes": [0] * 16,
                "permissions": "rw",
            }
        ]
        call_stack_after = [
            {
                "address": 0x00020000,
                "bytes": [0] * 12 + [0x05, 0x10, 0x40, 0],
            }
        ]
        cases = [
            _bochs_case(
                "mov-reg-imm",
                [0xB8, 0x78, 0x56, 0x34, 0x12],
                expected_gprs={"eax": 0x12345678},
                defined_gprs={"eax"},
            ),
            _bochs_case(
                "undeclared-memory",
                [0x8B, 0x00],
                defined_gprs={"eax"},
            ),
            _bochs_case(
                "memory-read",
                [0x8B, 0x00],
                expected_gprs={"eax": 0x12345678},
                defined_gprs={"eax"},
                initial_gprs={"eax": 0x00060000},
                memory=memory_read,
                expected_memory=[
                    {"address": 0x00060000, "bytes": [0x78, 0x56, 0x34, 0x12]}
                ],
                defined_memory=[
                    {"address": 0x00060000, "mask": [0xFF, 0xFF, 0xFF, 0xFF]}
                ],
            ),
            _bochs_case(
                "memory-write",
                [0x89, 0x10],
                initial_gprs={"eax": 0x00060000},
                memory=memory_write,
                expected_memory=[
                    {"address": 0x00060000, "bytes": [0x80, 0, 0, 0]}
                ],
                defined_memory=[
                    {"address": 0x00060000, "mask": [0xFF, 0xFF, 0xFF, 0xFF]}
                ],
            ),
            _bochs_case(
                "memory-reset-between-cases",
                [0x8B, 0x00],
                initial_gprs={"eax": 0x00060000},
                expected_gprs={"eax": 0xDEADBEEF},
                defined_gprs={"eax"},
                memory=memory_reset,
                expected_memory=[
                    {"address": 0x00060000, "bytes": [0xEF, 0xBE, 0xAD, 0xDE]}
                ],
                defined_memory=[
                    {"address": 0x00060000, "mask": [0xFF, 0xFF, 0xFF, 0xFF]}
                ],
            ),
            _bochs_case(
                "write-read-only-memory",
                [0x89, 0x10],
                initial_gprs={"eax": 0x00060000},
                memory=memory_read,
                expected_memory=[
                    {"address": 0x00060000, "bytes": [0x80, 0, 0, 0]}
                ],
                defined_memory=[
                    {"address": 0x00060000, "mask": [0xFF, 0xFF, 0xFF, 0xFF]}
                ],
            ),
            _bochs_case(
                "memory-outside-controlled-guest",
                [0x89, 0x10],
                memory=memory_outside_guest,
                expected_memory=[
                    {"address": 0x00001000, "bytes": [0x80, 0, 0, 0]}
                ],
                defined_memory=[
                    {"address": 0x00001000, "mask": [0xFF, 0xFF, 0xFF, 0xFF]}
                ],
            ),
            _bochs_case(
                "mov-reg-reg",
                [0x89, 0xC1],
                expected_gprs={"ecx": 0x00006000},
                defined_gprs={"ecx"},
            ),
            _bochs_case("two-instruction-stream", [0x90, 0x90]),
            _bochs_case(
                "same-target-conditional-branch",
                [0x75, 0x00],
                expected_control="direct_branch",
            ),
            _bochs_case(
                "taken-direct-branch",
                [0xEB, 0x05],
                expected_control="direct_branch",
                expected_eip=0x00401007,
            ),
            _bochs_case(
                "not-taken-direct-branch",
                [0x75, 0x02],
                initial_eflags=0x242,
                expected_eflags=0x242,
                expected_control="direct_branch",
            ),
            _bochs_case(
                "indirect-branch",
                [0xFF, 0xE0],
                expected_control="indirect_branch",
                expected_eip=0x00006000,
            ),
            _bochs_case(
                "direct-call-with-stack-write",
                [0xE8, 0x05, 0, 0, 0],
                initial_gprs={"esp": 0x00020010},
                expected_gprs={"esp": 0x0002000C},
                defined_gprs={"esp"},
                memory=call_stack,
                expected_memory=call_stack_after,
                defined_memory=[
                    {"address": 0x00020000, "mask": [0xFF] * 16}
                ],
                expected_control="direct_call",
                expected_eip=0x0040100A,
            ),
            _bochs_case(
                "test-reg-reg",
                [0x85, 0xC0],
                expected_eflags=0x206,
                defined_gprs={"eax"},
                defined_eflags=0x8C5,
            ),
            _bochs_case("system-cli", [0xFA]),
            _bochs_case("io-in", [0xED]),
            _bochs_case("segment-load", [0x8E, 0xD8]),
            _bochs_case("x87-register", [0xD9, 0xE8]),
            _bochs_case("faulting-ud2", [0x0F, 0x0B]),
            _bochs_case(
                "xor-reg-reg",
                [0x31, 0xD2],
                expected_gprs={"edx": 0},
                expected_eflags=0x246,
                defined_gprs={"edx"},
                defined_eflags=0x8C5,
            ),
            _bochs_case(
                "add-reg-reg-16",
                [0x66, 0x01, 0xD8],
                expected_gprs={"eax": 0x0000D788},
                defined_gprs={"eax"},
            ),
        ]
        corpus = parse_isa_conformance_corpus(
            {
                "format": "spaghetti-extractor-isa-conformance-corpus-v1",
                "id": "bochs-reviewed-register-integration-v1",
                "cases": cases,
            }
        )

        report = run_bochs_corpus(
            corpus,
            runner=_REAL_BOCHS_RUNNER,
            timeout_seconds=120,
        )

        statuses = {
            observation.case_id: observation.status
            for observation in report.observations
        }
        details = {
            observation.case_id: observation.detail
            for observation in report.observations
        }
        for case_id in (
            "mov-reg-imm",
            "mov-reg-reg",
            "memory-read",
            "memory-write",
            "memory-reset-between-cases",
            "same-target-conditional-branch",
            "taken-direct-branch",
            "not-taken-direct-branch",
            "indirect-branch",
            "direct-call-with-stack-write",
            "test-reg-reg",
            "x87-register",
            "xor-reg-reg",
            "add-reg-reg-16",
        ):
            self.assertEqual(
                statuses[case_id],
                ObservationStatus.MATCH,
                msg={
                    row.case_id: (row.status.value, row.detail)
                    for row in report.observations
                },
            )
        for case_id in (
            "undeclared-memory",
            "write-read-only-memory",
            "memory-outside-controlled-guest",
            "two-instruction-stream",
            "system-cli",
            "io-in",
            "segment-load",
            "faulting-ud2",
        ):
            self.assertEqual(
                statuses[case_id],
                ObservationStatus.UNSUPPORTED,
                msg={
                    row.case_id: (row.status.value, row.detail)
                    for row in report.observations
                },
            )
        self.assertEqual(details["undeclared-memory"], "undeclared_memory_access")
        self.assertEqual(
            details["write-read-only-memory"], "write_to_read_only_memory"
        )
        self.assertEqual(
            details["memory-outside-controlled-guest"],
            "memory_bounds_not_implemented",
        )
        self.assertEqual(
            details["faulting-ud2"], "fault_not_implemented_vector_6"
        )
        self.assertFalse(report.trust.proof_authority)


if __name__ == "__main__":
    unittest.main()
