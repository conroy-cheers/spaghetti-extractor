from __future__ import annotations

import json
import shutil
import subprocess
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SUITE = ROOT / "nix" / "gnu-hello-native-source-runtime-suite.nix"
PROGRAM_NAME = r"Z:\nix\store\candidate\bin\hello.exe"
CRLF = "\r\n"
C_LOCALE = {"LANG": "", "LANGUAGE": "", "LC_ALL": "C", "LC_MESSAGES": ""}


def _evaluate_suite() -> dict[str, object]:
    nix_instantiate = shutil.which("nix-instantiate")
    if nix_instantiate is None:
        raise unittest.SkipTest("nix-instantiate is unavailable")
    expression = f"import {SUITE} {{ programName = {json.dumps(PROGRAM_NAME)}; }}"
    completed = subprocess.run(
        [nix_instantiate, "--eval", "--strict", "--json", "--expr", expression],
        check=True,
        capture_output=True,
        text=True,
    )
    payload = json.loads(completed.stdout)
    if not isinstance(payload, dict):
        raise AssertionError("runtime suite did not evaluate to an attribute set")
    return payload


class GnuHelloNativeSourceRuntimeSuiteTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.suite = _evaluate_suite()

    def test_candidate_only_suite_metadata_and_case_schema(self) -> None:
        self.assertEqual(self.suite["format"], "stage-b-functional-suite-v1")
        self.assertEqual(self.suite["target_name"], "gnu-hello")
        self.assertTrue(self.suite["upstream_suite"])
        self.assertEqual(self.suite["suite_scope"], "upstream-applicable")

        cases = self.suite["cases"]
        self.assertIsInstance(cases, list)
        self.assertEqual(
            [case["id"] for case in cases],
            [
                "default-greeting",
                "help",
                "version",
                "invalid-option",
                "traditional-1",
                "greeting-1",
                "greeting-2",
                "last-1",
                "operand-1",
            ],
        )
        for case in cases:
            self.assertIsInstance(case["args"], list)
            self.assertEqual(case["env"], C_LOCALE)
            self.assertIsInstance(case["expected_returncode"], int)
            self.assertIsInstance(case["expected_stdout"], str)
            self.assertIsInstance(case["expected_stderr"], str)

        serialized = json.dumps(self.suite, sort_keys=True)
        self.assertNotIn("original_binary", serialized)
        self.assertNotIn("original_command", serialized)

    def test_exact_source_derived_expectations(self) -> None:
        cases = {case["id"]: case for case in self.suite["cases"]}

        self.assertEqual(cases["default-greeting"]["expected_returncode"], 0)
        self.assertEqual(cases["default-greeting"]["expected_stdout"], "Hello, world!" + CRLF)
        self.assertEqual(cases["default-greeting"]["expected_stderr"], "")

        help_output = cases["help"]["expected_stdout"]
        self.assertTrue(help_output.startswith(f"Usage: {PROGRAM_NAME} [OPTION]...{CRLF}"))
        self.assertIn(f"Report bugs to: bug-hello@gnu.org{CRLF}", help_output)
        self.assertTrue(
            help_output.endswith(
                "Report GNU Hello translation bugs to "
                f"<https://translationproject.org/team/>{CRLF}"
            )
        )

        version_output = cases["version"]["expected_stdout"]
        self.assertTrue(version_output.startswith(f"hello (GNU Hello) 2.12.3{CRLF}"))
        self.assertIn(f"Copyright (C) 2026 Free Software Foundation, Inc.{CRLF}", version_output)
        self.assertTrue(version_output.endswith(f"and Reuben Thomas.{CRLF}"))

        invalid = cases["invalid-option"]
        self.assertEqual(invalid["expected_returncode"], 1)
        self.assertEqual(invalid["expected_stdout"], "")
        self.assertEqual(
            invalid["expected_stderr"],
            f"{PROGRAM_NAME}: unrecognized option '--definitely-invalid'{CRLF}"
            f"Try '{PROGRAM_NAME} --help' for more information.{CRLF}",
        )

        self.assertEqual(cases["traditional-1"]["expected_stdout"], "hello, world" + CRLF)
        self.assertEqual(
            cases["greeting-1"]["expected_stdout"],
            "Nothing happens here." + CRLF,
        )
        self.assertEqual(len(cases["greeting-2"]["expected_stdout"]), 446)
        self.assertTrue(cases["greeting-2"]["expected_stdout"].endswith("hhh!" + CRLF))
        self.assertEqual(cases["last-1"]["expected_stdout"], "my hello" + CRLF)
        self.assertEqual(cases["operand-1"]["expected_returncode"], 1)
        self.assertEqual(cases["operand-1"]["expected_stdout"], "")
        self.assertEqual(
            cases["operand-1"]["expected_stderr"],
            f"{PROGRAM_NAME}: extra operand: first{CRLF}"
            f"Try '{PROGRAM_NAME} --help' for more information.{CRLF}",
        )

    def test_upstream_coverage_is_explicit(self) -> None:
        coverage = self.suite["coverage"]
        self.assertEqual(
            coverage["upstream_cases"],
            [
                "hello-1",
                "greeting-1",
                "greeting-2",
                "traditional-1",
                "operand-1",
                "last-1",
            ],
        )
        self.assertIn("atexit-1", coverage["excluded_upstream_cases"])


if __name__ == "__main__":
    unittest.main()
