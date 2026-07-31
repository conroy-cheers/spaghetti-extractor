import json
import os
from pathlib import Path
import runpy
import shutil
import stat
import sys
import tempfile
import textwrap
import unittest

from spaghetti_extractor.isa_conformance import (
    ISAConformanceError,
    ObservationStatus,
    ReportQualification,
    isa_conformance_corpus_sha256,
    parse_isa_conformance_corpus,
)
from spaghetti_extractor.isa_conformance_bochs import (
    BOCHS_BACKEND_ID,
    BOCHS_MACHINE_FORMAT,
    BOCHS_RESULT_FORMAT,
    run_bochs_corpus,
)


GPRS = {
    "eax": 1,
    "ebx": 2,
    "ecx": 3,
    "edx": 4,
    "esi": 5,
    "edi": 6,
    "ebp": 0x70001000,
    "esp": 0x70000FF0,
}

_REPO_ROOT = Path(__file__).resolve().parents[1]
_SOURCE_BOCHS_RUNNER = (
    _REPO_ROOT / "tools/bochs-conformance/spaghetti-bochs-conformance-runner"
)
_CONFIGURED_BOCHS_RUNNER = os.environ.get("SPAGHETTI_BOCHS_INTEGRATION_RUNNER")
_NIX_BOCHS_RUNNER = shutil.which("spaghetti-bochs-conformance-runner")
if _CONFIGURED_BOCHS_RUNNER:
    _REAL_BOCHS_RUNNER = Path(_CONFIGURED_BOCHS_RUNNER)
elif _NIX_BOCHS_RUNNER:
    _REAL_BOCHS_RUNNER = Path(_NIX_BOCHS_RUNNER)
elif (
    (_REPO_ROOT / "tools/bochs-conformance/build/source/bochs").is_file()
    and (_REPO_ROOT / "tools/bochs-conformance/build/guest/guest.img").is_file()
):
    _REAL_BOCHS_RUNNER = _SOURCE_BOCHS_RUNNER
else:
    _REAL_BOCHS_RUNNER = None


def _x87(*, mask=False):
    fill = 0xFF if mask else 0
    return {
        "control_word": 0xFFFF if mask else 0x037F,
        "status_word": 0xFFFF if mask else 0,
        "tag_word": 0xFFFF,
        "last_opcode": 0x7FF if mask else 0,
        "instruction_pointer": 0xFFFFFFFF if mask else 0,
        "data_pointer": 0xFFFFFFFF if mask else 0,
        "registers": [[fill] * 10 for _ in range(8)],
    }


def _state(*, eip=0x00401000):
    return {
        "gprs": dict(GPRS),
        "eip": eip,
        "eflags": 0x202,
        "fs": {"selector": 0x3B, "base": 0x7FFDF000},
        "x87": _x87(),
    }


def _case(case_id):
    expected_state = _state(eip=0x00401001)
    expected_state["gprs"]["eax"] = 2
    return {
        "id": case_id,
        "instruction_bytes": [0x40],
        "profile": {
            "architecture": "x86",
            "cpu": "i686",
            "execution_mode": "protected-32",
            "environment": "pe32",
            "features": ["x87"],
        },
        "image_base": 0x00400000,
        "initial_state": _state(),
        "memory": [
            {"address": 0x1000, "bytes": [0x10, 0x20], "permissions": "rw"}
        ],
        "defined_outputs": {
            "gprs": {register: 0xFFFFFFFF for register in GPRS},
            "eip": 0xFFFFFFFF,
            "eflags": 0x8D5,
            "fs": {"selector": 0xFFFF, "base": 0xFFFFFFFF},
            "x87": _x87(mask=True),
            "memory": [{"address": 0x1000, "mask": [0xFF, 0xFF]}],
        },
        "expected": {
            "final_state": expected_state,
            "memory": [{"address": 0x1000, "bytes": [0x10, 0x20]}],
            "control": "fallthrough",
            "fault": "none",
        },
    }


def _corpus(*case_ids):
    return parse_isa_conformance_corpus(
        {
            "format": "stage-a-isa-conformance-corpus-v1",
            "id": "bochs-fixture-corpus-v1",
            "cases": [_case(case_id) for case_id in case_ids],
        }
    )


def _zero_x87_mask():
    return {
        "control_word": 0,
        "status_word": 0,
        "tag_word": 0,
        "last_opcode": 0,
        "instruction_pointer": 0,
        "data_pointer": 0,
        "registers": [[0] * 10 for _ in range(8)],
    }


def _bochs_case(
    case_id,
    instruction_bytes,
    *,
    expected_gprs=None,
    expected_eflags=0x202,
    defined_gprs=(),
    defined_eflags=0,
    initial_gprs=None,
    initial_eflags=0x202,
    memory=None,
    expected_memory=None,
    defined_memory=None,
    expected_control="fallthrough",
    expected_fault="none",
    expected_eip=None,
    initial_fs=None,
    expected_fs=None,
    defined_fs=False,
    initial_x87=None,
    expected_x87=None,
    defined_x87=None,
    profile_features=(),
):
    initial = {
        "gprs": {
            "eax": 0x00006000,
            "ebx": 0x55667788,
            "ecx": 0x99AABBCC,
            "edx": 0x00000080,
            "esi": 0x01020304,
            "edi": 0x05060708,
            "ebp": 0x00008F00,
            "esp": 0x00008E00,
        },
        "eip": 0x00401000,
        "eflags": initial_eflags,
        "fs": json.loads(
            json.dumps(initial_fs or {"selector": 0, "base": 0})
        ),
        "x87": json.loads(json.dumps(initial_x87 or _x87())),
    }
    initial["gprs"].update(initial_gprs or {})
    final = json.loads(json.dumps(initial))
    final["eip"] = (
        (
            initial["eip"]
            if expected_fault != "none"
            else initial["eip"] + len(instruction_bytes)
        )
        if expected_eip is None
        else expected_eip
    )
    final["eflags"] = expected_eflags
    final["gprs"].update(expected_gprs or {})
    final["fs"] = json.loads(json.dumps(expected_fs or initial["fs"]))
    final["x87"] = json.loads(json.dumps(expected_x87 or initial["x87"]))
    return {
        "id": case_id,
        "instruction_bytes": instruction_bytes,
        "profile": {
            "architecture": "x86",
            "cpu": "haswell",
            "execution_mode": "protected-32",
            "environment": "pe32",
            "features": list(profile_features),
        },
        "image_base": 0x00400000,
        "initial_state": initial,
        "memory": memory or [],
        "defined_outputs": {
            "gprs": {
                register: 0xFFFFFFFF if register in defined_gprs else 0
                for register in GPRS
            },
            "eip": 0xFFFFFFFF,
            "eflags": defined_eflags,
            "fs": {
                "selector": 0xFFFF if defined_fs else 0,
                "base": 0xFFFFFFFF if defined_fs else 0,
            },
            "x87": json.loads(json.dumps(defined_x87 or _zero_x87_mask())),
            "memory": defined_memory or [],
        },
        "expected": {
            "final_state": final,
            "memory": expected_memory or [],
            "control": "fault" if expected_fault != "none" else expected_control,
            "fault": expected_fault,
        },
    }


def _private_x87_text(x87):
    return ":".join(
        [
            f"{x87['control_word']:04x}",
            f"{x87['status_word']:04x}",
            f"{x87['tag_word']:04x}",
            f"{x87['last_opcode']:04x}",
            f"{x87['instruction_pointer']:08x}",
            f"{x87['data_pointer']:08x}",
            *(bytes(register).hex() for register in x87["registers"]),
        ]
    )


def _write_runner(directory: Path, body: str) -> Path:
    path = directory / "fake-bochs-runner"
    path.write_text(
        f"#!{sys.executable}\n" + textwrap.dedent(body), encoding="utf-8"
    )
    path.chmod(path.stat().st_mode | stat.S_IXUSR)
    return path


_RUNNER_PREAMBLE = f"""
import hashlib
import json
import sys

MACHINE_FORMAT = {BOCHS_MACHINE_FORMAT!r}
RESULT_FORMAT = {BOCHS_RESULT_FORMAT!r}
BACKEND_ID = {BOCHS_BACKEND_ID!r}

raw = sys.stdin.buffer.read()
corpus = json.loads(raw)
canonical = (json.dumps(corpus, sort_keys=True, separators=(",", ":")) + "\\n").encode("ascii")
if raw != canonical:
    raise SystemExit("input was not canonical corpus JSON")

def emit(value):
    print(json.dumps(value, sort_keys=True, separators=(",", ":")))

def terminal(statuses):
    emit({{
        "format": RESULT_FORMAT,
        "corpus_id": corpus["id"],
        "input_sha256": hashlib.sha256(raw).hexdigest(),
        "backend": {{"id": BACKEND_ID, "kind": "emulator", "version": "2.8.1-test"}},
        "case_ids": [case["id"] for case in corpus["cases"]],
        "counts": {{
            "cases": len(statuses),
            "complete": statuses.count("complete"),
            "unsupported": statuses.count("unsupported"),
            "errors": statuses.count("error"),
        }},
    }})
"""


class StageAISAConformanceBochsTests(unittest.TestCase):
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
        self.assertFalse(first.trust.closes_stage_a_proof)

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
                "format": "stage-a-isa-conformance-corpus-v1",
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
        self.assertFalse(report.trust.closes_stage_a_proof)

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


@unittest.skipUnless(
    _REAL_BOCHS_RUNNER is not None,
    "requires a built source backend or SPAGHETTI_BOCHS_INTEGRATION_RUNNER",
)
class StageAISAConformanceBochsIntegrationTests(unittest.TestCase):
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
                "format": "stage-a-isa-conformance-corpus-v1",
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
                "format": "stage-a-isa-conformance-corpus-v1",
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
        self.assertFalse(report.trust.closes_stage_a_proof)

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
                "format": "stage-a-isa-conformance-corpus-v1",
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
        self.assertFalse(report.trust.closes_stage_a_proof)

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
                "format": "stage-a-isa-conformance-corpus-v1",
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
        self.assertFalse(report.trust.closes_stage_a_proof)

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
                "format": "stage-a-isa-conformance-corpus-v1",
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
        self.assertFalse(report.trust.closes_stage_a_proof)


if __name__ == "__main__":
    unittest.main()
