import json
import os
from pathlib import Path
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
if _CONFIGURED_BOCHS_RUNNER:
    _REAL_BOCHS_RUNNER = Path(_CONFIGURED_BOCHS_RUNNER)
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
    expected_eip=None,
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
        "fs": {"selector": 0, "base": 0},
        "x87": _x87(),
    }
    initial["gprs"].update(initial_gprs or {})
    final = json.loads(json.dumps(initial))
    final["eip"] = (
        initial["eip"] + len(instruction_bytes)
        if expected_eip is None
        else expected_eip
    )
    final["eflags"] = expected_eflags
    final["gprs"].update(expected_gprs or {})
    return {
        "id": case_id,
        "instruction_bytes": instruction_bytes,
        "profile": {
            "architecture": "x86",
            "cpu": "haswell",
            "execution_mode": "protected-32",
            "environment": "pe32",
            "features": [],
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
            "fs": {"selector": 0, "base": 0},
            "x87": _zero_x87_mask(),
            "memory": defined_memory or [],
        },
        "expected": {
            "final_state": final,
            "memory": expected_memory or [],
            "control": expected_control,
            "fault": "none",
        },
    }


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
            "system-cli",
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
            "io-in",
            "segment-load",
            "x87-register",
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
