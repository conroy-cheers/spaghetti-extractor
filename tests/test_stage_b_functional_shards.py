from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path

from spaghetti_extractor.stage_b_functional import (
    StageBFunctionalInputError,
    stage_b_aggregate_functional_cases,
    stage_b_run_functional_case,
)
from spaghetti_extractor.util import write_json


class StageBFunctionalShardTests(unittest.TestCase):
    def test_independent_cases_aggregate_to_the_standard_report(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            candidate = root / "candidate.py"
            candidate.write_text(
                "import sys\nprint('value:' + (sys.argv[1] if len(sys.argv) > 1 else 'none'))\n",
                encoding="ascii",
            )
            suite = root / "suite.json"
            write_json(
                suite,
                {
                    "format": "stage-b-functional-suite-v1",
                    "target_name": "fixture",
                    "suite_id": "fixture-shards",
                    "suite_name": "fixture shards",
                    "cases": [
                        {
                            "id": "first",
                            "args": ["one"],
                            "expected_returncode": 0,
                            "expected_stdout": "value:one\n",
                            "expected_stderr": "",
                        },
                        {
                            "id": "second",
                            "args": ["two"],
                            "expected_returncode": 0,
                            "expected_stdout": "value:two\n",
                            "expected_stderr": "",
                        },
                    ],
                },
            )
            reports = []
            for case_id in ("first", "second"):
                output = root / f"case-{case_id}"
                report = stage_b_run_functional_case(
                    suite=suite,
                    case_id=case_id,
                    candidate_command=(sys.executable, str(candidate)),
                    candidate_binary=candidate,
                    out=output,
                )
                self.assertEqual(report["status"], "pass")
                reports.append(output)

            aggregate = stage_b_aggregate_functional_cases(
                suite=suite,
                case_reports=reports,
                out=root / "aggregate",
            )
            self.assertEqual(aggregate["format"], "stage-b-functional-report-v1")
            self.assertEqual(aggregate["status"], "pass")
            self.assertEqual(aggregate["counts"], {"cases": 2, "passed": 2, "failed": 0})
            self.assertFalse(aggregate["oracle"]["original_runtime_observations"])
            for case in aggregate["cases"]:
                for stream in ("stdout", "stderr"):
                    self.assertTrue(Path(case["candidate"][stream]["path"]).is_file())

    def test_aggregate_rejects_missing_or_tampered_cases(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            candidate = root / "candidate.py"
            candidate.write_text("print('ok')\n", encoding="ascii")
            suite = root / "suite.json"
            write_json(
                suite,
                {
                    "format": "stage-b-functional-suite-v1",
                    "cases": [
                        {
                            "id": "only",
                            "expected_returncode": 0,
                            "expected_stdout": "ok\n",
                            "expected_stderr": "",
                        }
                    ],
                },
            )
            with self.assertRaisesRegex(
                StageBFunctionalInputError, "exactly cover"
            ):
                stage_b_aggregate_functional_cases(
                    suite=suite, case_reports=[], out=root / "missing"
                )
            case_out = root / "case"
            stage_b_run_functional_case(
                suite=suite,
                case_id="only",
                candidate_command=(sys.executable, str(candidate)),
                candidate_binary=candidate,
                out=case_out,
            )
            report_path = case_out / "functional-case-report.json"
            report = json.loads(report_path.read_text(encoding="utf-8"))
            report["case_id"] = "tampered"
            write_json(report_path, report)
            with self.assertRaisesRegex(StageBFunctionalInputError, "self-hash"):
                stage_b_aggregate_functional_cases(
                    suite=suite, case_reports=[case_out], out=root / "tampered"
                )


if __name__ == "__main__":
    unittest.main()
