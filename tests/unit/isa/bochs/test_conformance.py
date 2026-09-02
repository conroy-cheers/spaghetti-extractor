from __future__ import annotations

from tests.unit.isa.bochs._support import *


TESTKIT = {"resources": ("tools/bochs-conformance/instrument.cc",)}


class ISAConformanceBochsTests(unittest.TestCase):
    def test_instrumentation_uses_generic_decoder_scope_not_mnemonic_rules(self):
        source = (
            _REPO_ROOT / "tools/bochs-conformance/instrument.cc"
        ).read_text(encoding="utf-8")
        self.assertNotIn("reviewed_integer_instruction", source)
        self.assertNotIn("mnemonic_is", source)
        self.assertIn("BX_DISASM_SRC_ORIGIN", source)
        self.assertIn("BX_INSTR_IS_CALL_INDIRECT", source)
        self.assertIn("set_x87_state", source)
        self.assertIn("get_x87_state", source)
        self.assertNotIn('return "x87_not_implemented"', source)

    def test_batch_is_canonical_and_match_status_is_computed_locally(self):
        corpus = _corpus("match-case", "mismatch-case")
        with tempfile.TemporaryDirectory() as temporary:
            runner = _write_runner(
                Path(temporary),
                _RUNNER_PREAMBLE
                + """
statuses = []
for sequence, case in enumerate(corpus["cases"]):
    final_state = json.loads(json.dumps(case["expected"]["final_state"]))
    if sequence == 1:
        final_state["gprs"]["eax"] ^= 1
    statuses.append("complete")
    emit({
        "format": MACHINE_FORMAT,
        "sequence": sequence,
        "case_id": case["id"],
        "status": "complete",
        "final_state": final_state,
        "memory": case["expected"]["memory"],
        "actual": {
            "control": case["expected"]["control"],
            "fault": case["expected"]["fault"],
        },
        "detail": "",
    })
terminal(statuses)
""",
            )

            first = run_bochs_corpus(corpus, runner=runner)
            second = run_bochs_corpus(corpus, runner=runner)

        self.assertEqual(first.to_payload(corpus=corpus), second.to_payload(corpus=corpus))
        self.assertEqual(first.backend.id, BOCHS_BACKEND_ID)
        self.assertEqual(first.backend.version, "2.8.1-test")
        self.assertEqual(
            first.input_sha256, isa_conformance_corpus_sha256(corpus)
        )
        self.assertEqual(
            first.to_payload(corpus=corpus)["input_sha256"],
            isa_conformance_corpus_sha256(corpus),
        )
        self.assertEqual(
            [row.status for row in first.observations],
            [ObservationStatus.MATCH, ObservationStatus.MISMATCH],
        )
        self.assertEqual(first.counts.matched, 1)
        self.assertEqual(first.counts.mismatched, 1)
        self.assertEqual(first.qualification, ReportQualification.VETOED)
        self.assertFalse(first.trust.proof_authority)

    def test_new_x87_zero_slot_is_reported_with_full_architectural_tag(self):
        expected_x87 = _x87()
        expected_x87.update(
            status_word=7 << 11,
            tag_word=0x7FFF,
            last_opcode=0x36C,
            instruction_pointer=0x00401000,
            data_pointer=0x00008E30,
        )
        case = _bochs_case(
            "fld-zero-extended",
            [0xDB, 0x6C, 0x24, 0x30],
            memory=[{
                "address": 0x00008E30,
                "bytes": [0] * 10,
                "permissions": "r",
            }],
            expected_x87=expected_x87,
            defined_x87=_x87(mask=True),
            profile_features=("x87",),
        )
        corpus = parse_isa_conformance_corpus({
            "format": "spaghetti-extractor-isa-conformance-corpus-v1",
            "id": "bochs-x87-full-tag-normalization-v1",
            "cases": [case],
        })
        with tempfile.TemporaryDirectory() as temporary:
            runner = _write_runner(
                Path(temporary),
                _RUNNER_PREAMBLE
                + """
case = corpus["cases"][0]
final_state = json.loads(json.dumps(case["expected"]["final_state"]))
final_state["x87"]["tag_word"] = 0x3fff
emit({
    "format": MACHINE_FORMAT,
    "sequence": 0,
    "case_id": case["id"],
    "status": "complete",
    "final_state": final_state,
    "memory": case["expected"]["memory"],
    "actual": {"control": "fallthrough", "fault": "none"},
    "detail": "",
})
terminal(["complete"])
""",
            )

            report = run_bochs_corpus(corpus, runner=runner)

        observation = report.observations[0]
        self.assertEqual(observation.status, ObservationStatus.MATCH)
        self.assertEqual(observation.final_state.x87.tag_word, 0x7FFF)

    def test_existing_x87_zero_slot_is_reported_with_full_architectural_tag(self):
        expected_x87 = _x87()
        expected_x87.update(
            tag_word=0xFFFD,
            registers=[[0] * 10] + [[0] * 10 for _ in range(7)],
        )
        case = _bochs_case(
            "fchs-existing-zero",
            [0xD9, 0xE0],
            expected_x87=expected_x87,
            defined_x87=_x87(mask=True),
            profile_features=("x87",),
        )
        case["initial_state"]["x87"].update(expected_x87)
        corpus = parse_isa_conformance_corpus({
            "format": "spaghetti-extractor-isa-conformance-corpus-v1",
            "id": "bochs-x87-existing-full-tag-normalization-v1",
            "cases": [case],
        })
        with tempfile.TemporaryDirectory() as temporary:
            runner = _write_runner(
                Path(temporary),
                _RUNNER_PREAMBLE
                + """
case = corpus["cases"][0]
final_state = json.loads(json.dumps(case["expected"]["final_state"]))
final_state["x87"]["tag_word"] = 0xfffc
emit({
    "format": MACHINE_FORMAT,
    "sequence": 0,
    "case_id": case["id"],
    "status": "complete",
    "final_state": final_state,
    "memory": case["expected"]["memory"],
    "actual": {"control": "fallthrough", "fault": "none"},
    "detail": "",
})
terminal(["complete"])
""",
            )

            report = run_bochs_corpus(corpus, runner=runner)

        observation = report.observations[0]
        self.assertEqual(observation.status, ObservationStatus.MATCH)
        self.assertEqual(observation.final_state.x87.tag_word, 0xFFFD)

    @unittest.skipUnless(
        _SOURCE_BOCHS_RUNNER.is_file(),
        "requires the source-tree private protocol runner",
    )
    def test_private_protocol_accepts_only_consistent_divide_error_faults(self):
        namespace = runpy.run_path(
            str(_SOURCE_BOCHS_RUNNER), run_name="bochs_runner_protocol_test"
        )
        parse_private_output = namespace["parse_private_output"]
        words = "\t".join(f"{word:08x}" for word in range(10))
        x87 = _private_x87_text(_x87())
        valid = (
            f"OBS\t00000000\tcomplete\t{words}"
            f"\tfault\tdivide_error\t00060000:00000000\t{x87}\n"
            "DONE\t00000001\n"
        )

        [record] = parse_private_output(valid, 1)

        self.assertEqual(record["status"], "complete")
        self.assertEqual(record["control"], "fault")
        self.assertEqual(record["fault"], "divide_error")
        self.assertEqual(
            record["memory"],
            [{"address": 0x00060000, "bytes": [0, 0, 0, 0]}],
        )
        for label, control, fault in (
            ("fault without fault control", "fallthrough", "divide_error"),
            ("fault control without fault", "fault", "none"),
            ("unsupported fault class", "fault", "invalid_opcode"),
        ):
            with self.subTest(label=label), self.assertRaises(
                namespace["RunnerError"]
            ):
                parse_private_output(
                    (
                        f"OBS\t00000000\tcomplete\t{words}"
                        f"\t{control}\t{fault}\t-\t{x87}\n"
                        "DONE\t00000001\n"
                    ),
                    1,
                )

    @unittest.skipUnless(
        _SOURCE_BOCHS_RUNNER.is_file(),
        "requires the source-tree private protocol runner",
    )
    def test_private_protocol_round_trips_complete_x87_state(self):
        namespace = runpy.run_path(
            str(_SOURCE_BOCHS_RUNNER), run_name="bochs_runner_x87_protocol_test"
        )
        x87 = {
            "control_word": 0x027F,
            "status_word": 0x6100,
            "tag_word": 0xA55A,
            "last_opcode": 0x345,
            "instruction_pointer": 0x12345678,
            "data_pointer": 0x89ABCDEF,
            "registers": [
                list(bytes(((index * 17 + byte) & 0xFF for byte in range(10))))
                for index in range(8)
            ],
        }
        case = _bochs_case(
            "x87-private-roundtrip",
            [0xDF, 0xE0],
            initial_x87=x87,
            profile_features=("x87",),
        )
        line = namespace["private_case_line"](0, case)
        fields = line.split("\t")

        self.assertEqual(fields[:3], ["CASE", "5", "00000000"])
        self.assertEqual(len(fields), 19)
        self.assertEqual(fields[15], "0000")
        self.assertEqual(fields[16], "00000000")
        self.assertEqual(fields[18], _private_x87_text(x87))

        words = "\t".join(f"{word:08x}" for word in range(10))
        [record] = namespace["parse_private_output"](
            (
                f"OBS\t00000000\tcomplete\t{words}"
                f"\tfallthrough\tnone\t-\t{fields[18]}\n"
                "DONE\t00000001\n"
            ),
            1,
        )
        self.assertEqual(record["x87"], x87)

    @unittest.skipUnless(
        _SOURCE_BOCHS_RUNNER.is_file(),
        "requires the source-tree private protocol runner",
    )
    def test_x87_protocol_rejects_malformed_or_unrepresentable_state(self):
        namespace = runpy.run_path(
            str(_SOURCE_BOCHS_RUNNER), run_name="bochs_runner_x87_negative_test"
        )
        invalid_opcode = _x87()
        invalid_opcode["last_opcode"] = 0x800
        with self.assertRaisesRegex(
            namespace["RunnerError"], "architectural 11 bits"
        ):
            namespace["validate_x87"](invalid_opcode, "x87")

        malformed_registers = _x87()
        malformed_registers["registers"][3] = [0] * 9
        with self.assertRaisesRegex(
            namespace["RunnerError"], "exactly 10 bytes"
        ):
            namespace["validate_x87"](malformed_registers, "x87")

        words = "\t".join(f"{word:08x}" for word in range(10))
        malformed_observations = (
            _private_x87_text(_x87()).replace("00000000000000000000", "00", 1),
            _private_x87_text(_x87()).replace("037f", "zzzz", 1),
            _private_x87_text(_x87()).replace(":0000:00000000", ":0800:00000000", 1),
        )
        for x87_field in malformed_observations:
            with self.subTest(x87=x87_field), self.assertRaises(
                namespace["RunnerError"]
            ):
                namespace["parse_private_output"](
                    (
                        f"OBS\t00000000\tcomplete\t{words}"
                        f"\tfallthrough\tnone\t-\t{x87_field}\n"
                        "DONE\t00000001\n"
                    ),
                    1,
                )

    def test_complete_divide_error_is_matched_locally_and_remains_untrusted(self):
        case = _case("divide-error")
        case["expected"]["final_state"]["eip"] = case["initial_state"]["eip"]
        case["expected"].update(control="fault", fault="divide_error")
        corpus = parse_isa_conformance_corpus(
            {
                "format": "spaghetti-extractor-isa-conformance-corpus-v1",
                "id": "bochs-divide-error-protocol-v1",
                "cases": [case],
            }
        )
        with tempfile.TemporaryDirectory() as temporary:
            runner = _write_runner(
                Path(temporary),
                _RUNNER_PREAMBLE
                + """
case = corpus["cases"][0]
emit({
    "format": MACHINE_FORMAT,
    "sequence": 0,
    "case_id": case["id"],
    "status": "complete",
    "final_state": case["expected"]["final_state"],
    "memory": case["expected"]["memory"],
    "actual": {"control": "fault", "fault": "divide_error"},
    "detail": "",
})
terminal(["complete"])
""",
            )

            report = run_bochs_corpus(corpus, runner=runner)

        self.assertEqual(report.observations[0].status, ObservationStatus.MATCH)
        self.assertEqual(report.observations[0].actual.fault.value, "divide_error")
        self.assertFalse(report.trust.proof_authority)

    def test_unsupported_observation_is_preserved_and_unqualifies_report(self):
        corpus = _corpus("unsupported-case")
        with tempfile.TemporaryDirectory() as temporary:
            runner = _write_runner(
                Path(temporary),
                _RUNNER_PREAMBLE
                + """
case = corpus["cases"][0]
emit({
    "format": MACHINE_FORMAT,
    "sequence": 0,
    "case_id": case["id"],
    "status": "unsupported",
    "final_state": None,
    "memory": None,
    "actual": None,
    "detail": "fake Bochs profile does not implement this instruction",
})
terminal(["unsupported"])
""",
            )
            report = run_bochs_corpus(corpus, runner=runner)

        self.assertEqual(report.observations[0].status, ObservationStatus.UNSUPPORTED)
        self.assertEqual(report.counts.unsupported, 1)
        self.assertEqual(report.qualification, ReportQualification.UNQUALIFIED)
        self.assertFalse(report.trust.proof_authority)

    def test_protocol_rejects_missing_malformed_and_runner_claimed_match(self):
        corpus = _corpus("only-case")
        scripts = {
            "missing machine record": _RUNNER_PREAMBLE + "terminal([])\n",
            "malformed JSON": "print('{not-json')\n",
            "runner claimed match": _RUNNER_PREAMBLE
            + """
case = corpus["cases"][0]
emit({
    "format": MACHINE_FORMAT,
    "sequence": 0,
    "case_id": case["id"],
    "status": "match",
    "final_state": case["expected"]["final_state"],
    "memory": case["expected"]["memory"],
    "actual": {"control": "fallthrough", "fault": "none"},
    "detail": "",
})
terminal(["complete"])
""",
        }
        for label, script in scripts.items():
            with self.subTest(label=label), tempfile.TemporaryDirectory() as temporary:
                runner = _write_runner(Path(temporary), script)
                with self.assertRaises(ISAConformanceError):
                    run_bochs_corpus(corpus, runner=runner)

    def test_protocol_rejects_reordered_cases_stale_digest_and_bad_counts(self):
        corpus = _corpus("first", "second")
        mutations = {
            "reordered": 'case_ids = list(reversed([case["id"] for case in corpus["cases"]]))',
            "stale digest": 'digest = "0" * 64',
            "bad counts": "complete = 1",
        }
        template = _RUNNER_PREAMBLE + """
statuses = []
for sequence, case in enumerate(corpus["cases"]):
    statuses.append("complete")
    emit({
        "format": MACHINE_FORMAT,
        "sequence": sequence,
        "case_id": case["id"],
        "status": "complete",
        "final_state": case["expected"]["final_state"],
        "memory": case["expected"]["memory"],
        "actual": {"control": "fallthrough", "fault": "none"},
        "detail": "",
    })
case_ids = [case["id"] for case in corpus["cases"]]
digest = hashlib.sha256(raw).hexdigest()
complete = 2
{mutation}
emit({
    "format": RESULT_FORMAT,
    "corpus_id": corpus["id"],
    "input_sha256": digest,
    "backend": {"id": BACKEND_ID, "kind": "emulator", "version": "2.8.1-test"},
    "case_ids": case_ids,
    "counts": {"cases": 2, "complete": complete, "unsupported": 0, "errors": 0},
})
"""
        for label, mutation in mutations.items():
            with self.subTest(label=label), tempfile.TemporaryDirectory() as temporary:
                runner = _write_runner(
                    Path(temporary), template.replace("{mutation}", mutation)
                )
                with self.assertRaises(ISAConformanceError):
                    run_bochs_corpus(corpus, runner=runner)

    def test_nonzero_runner_exit_fails_closed(self):
        corpus = _corpus("only-case")
        with tempfile.TemporaryDirectory() as temporary:
            runner = _write_runner(
                Path(temporary),
                "import sys\nprint('runner failed', file=sys.stderr)\nraise SystemExit(7)\n",
            )
            with self.assertRaisesRegex(ISAConformanceError, "status 7"):
                run_bochs_corpus(corpus, runner=runner)

    def test_invalid_runner_configuration_fails_before_subprocess(self):
        corpus = _corpus("only-case")
        with tempfile.TemporaryDirectory() as temporary:
            runner = Path(temporary) / "not-executable"
            runner.write_text("ignored\n", encoding="utf-8")
            with self.assertRaisesRegex(ISAConformanceError, "not executable"):
                run_bochs_corpus(corpus, runner=runner)
            with self.assertRaisesRegex(ISAConformanceError, "finite and positive"):
                run_bochs_corpus(corpus, runner=runner, timeout_seconds=float("nan"))


if __name__ == "__main__":
    unittest.main()
