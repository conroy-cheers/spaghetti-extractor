from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path

from spaghetti_extractor.candidate.functional import (
    CandidateTestInputError,
    aggregate_candidate_test_cases,
    run_candidate_test_case,
)
from spaghetti_extractor.util import write_json


class FunctionalShardTests(unittest.TestCase):
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
                    "format": "spaghetti-extractor-candidate-test-suite-v1",
                    "target_name": "fixture",
                    "suite_id": "fixture-shards",
                    "suite_name": "fixture shards",
                    "cases": [
                        {
                            "id": "first",
                            "kind": "expected-exit",
                            "args": ["one"],
                            "expected_returncode": 0,
                            "expected_stdout": "value:one\n",
                            "expected_stderr": "",
                        },
                        {
                            "id": "second",
                            "kind": "expected-exit",
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
                report = run_candidate_test_case(
                    suite=suite,
                    case_id=case_id,
                    candidate_command=(sys.executable, str(candidate)),
                    candidate_binary=candidate,
                    out=output,
                )
                self.assertEqual(report["status"], "pass")
                reports.append(output)

            aggregate = aggregate_candidate_test_cases(
                suite=suite,
                case_reports=reports,
                out=root / "aggregate",
            )
            self.assertEqual(
                aggregate["format"],
                "spaghetti-extractor-candidate-test-report-v1",
            )
            self.assertEqual(aggregate["status"], "pass")
            self.assertEqual(aggregate["counts"], {"cases": 2, "passed": 2, "failed": 0})
            self.assertFalse(aggregate["oracle"]["original_runtime_observations"])
            for case in aggregate["cases"]:
                for stream in ("stdout", "stderr"):
                    self.assertTrue(Path(case["candidate"][stream]["path"]).is_file())

    def test_full_device_stdout_sink_exposes_flush_failures(self) -> None:
        if not Path("/dev/full").is_char_device():
            self.skipTest("/dev/full is unavailable")
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            candidate = root / "candidate.py"
            candidate.write_text(
                "import os\n"
                "import sys\n"
                "try:\n"
                "    os.write(1, b'output')\n"
                "except OSError as error:\n"
                "    sys.stderr.write(f'write error:{error.errno}\\n')\n"
                "    raise SystemExit(1)\n",
                encoding="ascii",
            )
            suite = root / "suite.json"
            write_json(
                suite,
                {
                    "format": "spaghetti-extractor-candidate-test-suite-v1",
                    "cases": [
                        {
                            "id": "full-output",
                            "kind": "expected-exit",
                            "stdout_sink": "full_device",
                            "expected_returncode": 1,
                            "expected_stdout": "",
                            "expected_stderr": "write error:28\n",
                        }
                    ],
                },
            )

            report = run_candidate_test_case(
                suite=suite,
                case_id="full-output",
                candidate_command=(sys.executable, str(candidate)),
                candidate_binary=candidate,
                out=root / "case",
            )

            self.assertEqual(report["status"], "pass")
            case = report["case"]
            self.assertEqual(case["stdout_sink"], "full_device")
            self.assertEqual(
                case["candidate"]["stdout_sink"],
                {"kind": "full_device", "path": "/dev/full"},
            )
            self.assertEqual(case["candidate"]["stdout"]["bytes"], 0)

    def test_rejects_unknown_stdout_sink(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            suite = root / "suite.json"
            write_json(
                suite,
                {
                    "format": "spaghetti-extractor-candidate-test-suite-v1",
                    "cases": [
                        {
                            "id": "unsafe-output",
                            "kind": "expected-exit",
                            "stdout_sink": "/tmp/arbitrary",
                            "expected_returncode": 0,
                            "expected_stdout": "",
                            "expected_stderr": "",
                        }
                    ],
                },
            )
            with self.assertRaisesRegex(
                CandidateTestInputError, "stdout_sink must be capture or full_device"
            ):
                run_candidate_test_case(
                    suite=suite,
                    case_id="unsafe-output",
                    candidate_command=(sys.executable, "-c", "pass"),
                    out=root / "case",
                )

    def test_bounded_liveness_requires_process_to_remain_alive(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            suite = root / "suite.json"
            write_json(
                suite,
                {
                    "format": "spaghetti-extractor-candidate-test-suite-v1",
                    "cases": [
                        {
                            "id": "stays-alive",
                            "kind": "bounded-liveness",
                            "liveness_seconds": 0.1,
                            "candidate_timeout_seconds": 2,
                        }
                    ],
                },
            )
            report = run_candidate_test_case(
                suite=suite,
                case_id="stays-alive",
                candidate_command=(
                    sys.executable,
                    "-c",
                    "import time; time.sleep(10)",
                ),
                out=root / "case",
            )
            self.assertEqual(report["status"], "pass")
            self.assertTrue(report["case"]["candidate"]["liveness_observed"])
            self.assertTrue(report["case"]["candidate"]["terminated_by_harness"])

    def test_aggregate_rejects_missing_or_tampered_cases(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            candidate = root / "candidate.py"
            candidate.write_text("print('ok')\n", encoding="ascii")
            suite = root / "suite.json"
            write_json(
                suite,
                {
                    "format": "spaghetti-extractor-candidate-test-suite-v1",
                    "cases": [
                        {
                            "id": "only",
                            "kind": "expected-exit",
                            "expected_returncode": 0,
                            "expected_stdout": "ok\n",
                            "expected_stderr": "",
                        }
                    ],
                },
            )
            with self.assertRaisesRegex(
                CandidateTestInputError, "exactly cover"
            ):
                aggregate_candidate_test_cases(
                    suite=suite, case_reports=[], out=root / "missing"
                )
            case_out = root / "case"
            run_candidate_test_case(
                suite=suite,
                case_id="only",
                candidate_command=(sys.executable, str(candidate)),
                candidate_binary=candidate,
                out=case_out,
            )
            report_path = case_out / "candidate-test-case-report.json"
            report = json.loads(report_path.read_text(encoding="utf-8"))
            report["case_id"] = "tampered"
            write_json(report_path, report)
            with self.assertRaisesRegex(CandidateTestInputError, "self-hash"):
                aggregate_candidate_test_cases(
                    suite=suite, case_reports=[case_out], out=root / "tampered"
                )




class BoundedCaptureTests(unittest.TestCase):
    """Detached output writers must not defeat a root-process deadline."""

    def observe(self, root, code, *, timeout=0.15, data=b''):
        from spaghetti_extractor.candidate.functional import _run_observed_process
        return _run_observed_process(
            command=(sys.executable, '-c', code), stdin_bytes=data, env={},
            cwd=str(root), timeout_seconds=timeout, out_prefix=root/'capture',
            strip_stderr_line_regexes=(), stdout_sink='capture',
        )

    def test_detached_writer_does_not_block_exit_or_timeout_and_logs_are_snapshots(self):
        import os
        import signal
        import time
        for linger in (False, True):
            with self.subTest(linger=linger), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                code = (
                    'import os,sys,time\n'
                    'pid=os.fork()\n'
                    'if pid==0:\n'
                    ' os.setsid()\n'
                    ' open("detached.pid","w").write(str(os.getpid()))\n'
                    ' time.sleep(0.5)\n'
                    ' os.write(1,b"late output\\n")\n'
                    ' time.sleep(5)\n'
                    ' os._exit(0)\n'
                    'os.write(1,b"root output\\n")\n'
                    + ('time.sleep(5)\n' if linger else '')
                )
                try:
                    started = time.monotonic()
                    result = self.observe(root, code)
                    self.assertLess(time.monotonic()-started, 2.0)
                    self.assertEqual(result['timed_out'], linger)
                    self.assertFalse(result['cleanup_failed'])
                    self.assertEqual((root/'capture.stdout').read_bytes(), b'root output\n')
                    time.sleep(0.6)
                    self.assertEqual((root/'capture.stdout').read_bytes(), b'root output\n')
                finally:
                    pid_file = root/'detached.pid'
                    if pid_file.exists():
                        try:
                            os.kill(int(pid_file.read_text()), signal.SIGKILL)
                        except ProcessLookupError:
                            pass

    def test_unread_large_stdin_is_bounded_and_stdin_remains_a_pipe(self):
        import time
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            started = time.monotonic()
            result = self.observe(root, 'import time; time.sleep(5)', data=b'x'*1048576)
            self.assertTrue(result['timed_out'])
            self.assertLess(time.monotonic()-started, 2.0)
            result = self.observe(root, 'import os,stat; print(all(stat.S_ISFIFO(os.fstat(fd).st_mode) for fd in (0,1,2)))', timeout=2)
            self.assertEqual(result['returncode'], 0)
            self.assertEqual((root/'capture.stdout').read_bytes(), b'True\n')

    def test_cancellation_reaps_root_and_preserves_partial_output(self):
        import os
        import signal
        import time
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            def cancel(signum, frame):
                raise KeyboardInterrupt('test cancellation')
            previous = signal.signal(signal.SIGALRM, cancel)
            signal.setitimer(signal.ITIMER_REAL, 0.25)
            started = time.monotonic()
            try:
                with self.assertRaises(KeyboardInterrupt):
                    self.observe(root, 'import os,time; open("root.pid","w").write(str(os.getpid())); print("ready",flush=True); time.sleep(5)', timeout=10)
            finally:
                signal.setitimer(signal.ITIMER_REAL, 0)
                signal.signal(signal.SIGALRM, previous)
            self.assertLess(time.monotonic()-started, 2.0)
            self.assertEqual((root/'capture.stdout').read_bytes(), b'ready\n')
            with self.assertRaises(ProcessLookupError):
                os.kill(int((root/'root.pid').read_text()), 0)

    def test_failed_launch_retains_empty_logs(self):
        from spaghetti_extractor.candidate.functional import _run_observed_process
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            with self.assertRaises(FileNotFoundError):
                _run_observed_process(command=(str(root/'absent'),),stdin_bytes=b'',
                    env={},cwd=str(root),timeout_seconds=0.1,out_prefix=root/'capture',
                    strip_stderr_line_regexes=(),stdout_sink='capture')
            self.assertEqual((root/'capture.stdout').read_bytes(),b'')
            self.assertEqual((root/'capture.stderr').read_bytes(),b'')


if __name__ == "__main__":
    unittest.main()
