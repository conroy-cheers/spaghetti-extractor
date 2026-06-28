import contextlib
import io
import json
import sys
import tempfile
import unittest
from pathlib import Path

from haloce_catalog.behavior import (
    compare_json_spec_observations,
    compare_process_spec_observations,
    record_behavior_observation,
    record_process_behavior_observation,
    run_clean_spec_suite,
    upsert_behavior_contract,
)
from haloce_catalog.cli import main
from haloce_catalog.db import connect, initialize
from haloce_catalog.reports import tests_json as reports_tests_json
from haloce_catalog.spec_generation import specs_json


class BehaviorContractTests(unittest.TestCase):
    def test_behavior_contracts_are_reported_in_specs_and_tests(self):
        with tempfile.TemporaryDirectory() as tmp:
            db_path = Path(tmp) / "catalog.db"
            conn = connect(db_path)
            initialize(conn)
            with conn:
                contract = upsert_behavior_contract(
                    conn,
                    contract_id="fixture.behavior",
                    title="Fixture Behavior",
                    scope="deterministic JSON transcript",
                    version="1",
                    contract={
                        "format": "fixture-contract-v1",
                        "inputs": {"seed": "uint32"},
                        "outputs": {"final": {"score": "int32"}},
                    },
                    evidence="public fixture behavior contract",
                )
                observation = record_behavior_observation(
                    conn,
                    behavior_contract_label_value=contract["label"],
                    test_id="seed-7",
                    observed={"format": "fixture-transcript-v1", "seed": 7, "final": {"score": 42}},
                    input_data={"seed": 7},
                    command=["fixture.exe", "--json"],
                    evidence="fixture transcript captured from original binary",
                )

            spec = specs_json(conn)
            tests = reports_tests_json(conn)
            conn.close()

        self.assertEqual(spec["behavior_contracts"][0]["contract_id"], "fixture.behavior")
        self.assertEqual(spec["behavior_contracts"][0]["observations"][0]["test_id"], "seed-7")
        self.assertEqual(spec["behavior_contracts"][0]["observations"][0]["observed"]["final"]["score"], 42)
        self.assertEqual(tests["summary"]["behavior_contracts"], 1)
        self.assertEqual(tests["summary"]["behavior_observations"], 1)
        self.assertEqual(tests["behavior_observations"][0]["observed_sha256"], observation["observed_sha256"])

    def test_process_behavior_observations_are_reported_in_specs_and_tests(self):
        with tempfile.TemporaryDirectory() as tmp:
            db_path = Path(tmp) / "catalog.db"
            conn = connect(db_path)
            initialize(conn)
            with conn:
                contract = upsert_behavior_contract(
                    conn,
                    contract_id="fixture.behavior",
                    title="Fixture Behavior",
                    scope="stdout stderr and exit-code behavior",
                    version="1",
                    contract={"format": "fixture-contract-v1"},
                    evidence="public fixture behavior contract",
                )
                observation = record_process_behavior_observation(
                    conn,
                    behavior_contract_label_value=contract["label"],
                    test_id="help",
                    observed={"returncode": 0, "timed_out": False, "stdout": "usage: fixture\n", "stderr": ""},
                    input_data={"argv": ["--help"]},
                    command=["fixture.exe", "--help"],
                    evidence="help text captured from original binary",
                )

            spec = specs_json(conn)
            tests = reports_tests_json(conn)
            conn.close()

        process_observation = spec["behavior_contracts"][0]["process_observations"][0]
        self.assertEqual(process_observation["test_id"], "help")
        self.assertEqual(process_observation["input"]["argv"], ["--help"])
        self.assertEqual(process_observation["observed"]["stdout"], "usage: fixture\n")
        self.assertEqual(tests["summary"]["process_behavior_observations"], 1)
        self.assertEqual(tests["process_behavior_observations"][0]["observed_sha256"], observation["observed_sha256"])
        self.assertEqual(tests["process_behavior_observations"][0]["stdout_bytes"], len("usage: fixture\n"))

    def test_run_json_behavior_test_records_stdout_json(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            db_path = root / "catalog.db"
            contract_json = root / "contract.json"
            script = root / "emit_json.py"
            contract_json.write_text(json.dumps({"format": "fixture-contract-v1"}), encoding="utf-8")
            script.write_text('import json; print(json.dumps({"ok": True, "frames": 3}))\n', encoding="utf-8")
            output = io.StringIO()

            with contextlib.redirect_stdout(output):
                self.assertEqual(
                    main(
                        [
                            "upsert-behavior-contract",
                            "--db",
                            str(db_path),
                            "--contract-id",
                            "fixture.behavior",
                            "--title",
                            "Fixture Behavior",
                            "--scope",
                            "stdout JSON",
                            "--contract-json",
                            str(contract_json),
                            "--report-dir",
                            str(root / "reports"),
                        ]
                    ),
                    0,
                )
            contract_label = json.loads(output.getvalue())["behavior_contract"]["label"]
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                status = main(
                    [
                        "run-json-behavior-test",
                        "--db",
                        str(db_path),
                        "--behavior-contract-label",
                        contract_label,
                        "--test-id",
                        "json-smoke",
                        "--artifact-dir",
                        str(root / "behavior"),
                        "--report-dir",
                        str(root / "reports"),
                        "--",
                        "python",
                        str(script),
                    ]
                )

            payload = json.loads(output.getvalue())

            self.assertEqual(status, 0)
            self.assertEqual(payload["behavior_observation"]["status"], "pass")
            self.assertTrue((root / "reports" / "specs.json").exists())

    def test_run_process_behavior_test_records_stdout_stderr_and_exit_code(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            db_path = root / "catalog.db"
            contract_json = root / "contract.json"
            script = root / "emit_process.py"
            contract_json.write_text(json.dumps({"format": "fixture-contract-v1"}), encoding="utf-8")
            script.write_text(
                "import sys\n"
                "print('usage: fixture')\n"
                "print('WARNING: noisy runtime line', file=sys.stderr)\n"
                "print('bad option', file=sys.stderr)\n"
                "raise SystemExit(4)\n",
                encoding="utf-8",
            )
            output = io.StringIO()

            with contextlib.redirect_stdout(output):
                self.assertEqual(
                    main(
                        [
                            "upsert-behavior-contract",
                            "--db",
                            str(db_path),
                            "--contract-id",
                            "fixture.behavior",
                            "--title",
                            "Fixture Behavior",
                            "--scope",
                            "process behavior",
                            "--contract-json",
                            str(contract_json),
                            "--report-dir",
                            str(root / "reports"),
                        ]
                    ),
                    0,
                )
            contract_label = json.loads(output.getvalue())["behavior_contract"]["label"]
            input_json = root / "input.json"
            input_json.write_text(json.dumps({"argv": ["--bad"]}), encoding="utf-8")
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                status = main(
                    [
                        "run-process-behavior-test",
                        "--db",
                        str(db_path),
                        "--behavior-contract-label",
                        contract_label,
                        "--test-id",
                        "bad-option",
                        "--artifact-dir",
                        str(root / "process"),
                        "--input-json",
                        str(input_json),
                        "--expect-exit-code",
                        "4",
                        "--stdout-contains",
                        "usage",
                        "--stderr-contains",
                        "bad option",
                        "--strip-stderr-line-regex",
                        "^WARNING: noisy runtime line$",
                        "--report-dir",
                        str(root / "reports"),
                        "--",
                        sys.executable,
                        str(script),
                    ]
                )

            payload = json.loads(output.getvalue())
            spec = json.loads((root / "reports" / "specs.json").read_text(encoding="utf-8"))

            self.assertEqual(status, 0)
            self.assertEqual(payload["process_behavior_observation"]["status"], "pass")
            self.assertEqual(spec["behavior_contracts"][0]["process_observations"][0]["observed"]["returncode"], 4)
            self.assertEqual(
                spec["behavior_contracts"][0]["process_observations"][0]["observed"]["stderr"],
                "bad option\n",
            )

    def test_compare_json_behavior_reports_pass_and_first_mismatch(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            expected_json = root / "expected.json"
            good_script = root / "good.py"
            bad_script = root / "bad.py"
            expected_json.write_text(json.dumps({"format": "fixture-v1", "final": {"score": 42}}), encoding="utf-8")
            good_script.write_text(
                'import json; print(json.dumps({"format": "fixture-v1", "final": {"score": 42}}))\n',
                encoding="utf-8",
            )
            bad_script.write_text(
                'import json; print(json.dumps({"format": "fixture-v1", "final": {"score": 41}}))\n',
                encoding="utf-8",
            )

            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                pass_status = main(
                    [
                        "compare-json-behavior",
                        "--expected-json",
                        str(expected_json),
                        "--test-id",
                        "good",
                        "--artifact-dir",
                        str(root / "compare"),
                        "--",
                        sys.executable,
                        str(good_script),
                    ]
                )

            pass_payload = json.loads(output.getvalue())
            self.assertEqual(pass_status, 0)
            self.assertEqual(pass_payload["behavior_comparison"]["status"], "pass")

            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                fail_status = main(
                    [
                        "compare-json-behavior",
                        "--expected-json",
                        str(expected_json),
                        "--test-id",
                        "bad",
                        "--artifact-dir",
                        str(root / "compare"),
                        "--",
                        sys.executable,
                        str(bad_script),
                    ]
                )

            fail_payload = json.loads(output.getvalue())
            self.assertEqual(fail_status, 1)
            self.assertEqual(fail_payload["behavior_comparison"]["status"], "fail")
            self.assertEqual(fail_payload["behavior_comparison"]["failures"], ["$.final.score: expected 42, observed 41"])

    def test_compare_json_spec_observations_runs_candidate_from_public_spec(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            script = self._write_spec_candidate(root)
            spec = self._spec_observation_fixture()

            result = compare_json_spec_observations(
                spec=spec,
                command_template=[
                    sys.executable,
                    str(script),
                    "--contract",
                    "{contract_json}",
                    "--scenario",
                    "{observed.scenario}",
                    "--seed",
                    "{observed.seed}",
                    "--frames",
                    "{observed.frames}",
                ],
                artifact_dir=root / "spec-compare",
                contract_id="fixture.behavior",
            )
            contract_artifact_exists = (
                Path(result["artifact_dir"]) / "contracts" / "fixture-behavior-1.json"
            ).exists()

        self.assertEqual(result["status"], "pass")
        self.assertEqual(result["observations"], 2)
        self.assertEqual(result["passed"], 2)
        self.assertEqual(result["failed"], 0)
        self.assertEqual({item["observation_test_id"] for item in result["comparisons"]}, {"idle-seed7-1", "idle-seed9-2"})
        self.assertTrue(contract_artifact_exists)

    def test_compare_json_spec_observations_accepts_clean_derived_spec_records(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            script = self._write_spec_candidate(root)
            spec = {
                "schema_version": 1,
                "format": "wincr-clean-specs-v1",
                "spec_records": [
                    {
                        "entity_type": "behavior_contract",
                        "public_label": "behavior_fixture",
                        "contract_id": "fixture.behavior",
                        "version": "1",
                        "contract": {
                            "format": "fixture-contract-v1",
                            "transcript_format": "fixture-transcript-v1",
                        },
                    }
                ],
                "test_records": [
                    {
                        "entity_type": "behavior_observation",
                        "public_label": "obs_idle_seed7_1",
                        "contract_id": "fixture.behavior",
                        "test_id": "idle-seed7-1",
                        "status": "pass",
                        "inputs": {"scenario": "idle", "seed": 7, "frames": 1},
                        "outputs": {
                            "format": "fixture-transcript-v1",
                            "scenario": "idle",
                            "seed": 7,
                            "frames": 1,
                            "final": {"score": 8},
                        },
                    }
                ],
            }

            result = compare_json_spec_observations(
                spec=spec,
                command_template=[
                    sys.executable,
                    str(script),
                    "--contract",
                    "{contract_json}",
                    "--scenario",
                    "{observed.scenario}",
                    "--seed",
                    "{observed.seed}",
                    "--frames",
                    "{observed.frames}",
                ],
                artifact_dir=root / "clean-spec-compare",
                contract_id="fixture.behavior",
            )

        self.assertEqual(result["status"], "pass")
        self.assertEqual(result["observations"], 1)
        self.assertEqual(result["passed"], 1)

    def test_compare_json_spec_observations_cli_reports_mismatch(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            script = self._write_spec_candidate(root, score_offset=1)
            spec_path = root / "specs.json"
            spec_path.write_text(json.dumps(self._spec_observation_fixture()), encoding="utf-8")

            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                status = main(
                    [
                        "compare-json-spec-observations",
                        "--spec-json",
                        str(spec_path),
                        "--contract-id",
                        "fixture.behavior",
                        "--artifact-dir",
                        str(root / "spec-compare"),
                        "--",
                        sys.executable,
                        str(script),
                        "--contract",
                        "{contract_json}",
                        "--scenario",
                        "{observed.scenario}",
                        "--seed",
                        "{observed.seed}",
                        "--frames",
                        "{observed.frames}",
                    ]
                )

        payload = json.loads(output.getvalue())["spec_observation_comparison"]
        self.assertEqual(status, 1)
        self.assertEqual(payload["status"], "fail")
        self.assertEqual(payload["observations"], 2)
        self.assertEqual(payload["failed"], 2)
        self.assertIn("$.final.score", payload["comparisons"][0]["failures"][0])

    def test_compare_process_spec_observations_expands_variable_argv(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            script = self._write_process_candidate(root)
            spec = {
                "schema_version": 1,
                "behavior_contracts": [
                    {
                        "label": "behavior_fixture",
                        "contract_id": "fixture.behavior",
                        "title": "Fixture Behavior",
                        "scope": "process behavior",
                        "version": "1",
                        "contract": {"format": "fixture-contract-v1"},
                        "observations": [],
                        "process_observations": [
                            {
                                "label": "proc_help",
                                "test_id": "help",
                                "status": "pass",
                                "input": {"argv": ["--help"]},
                                "observed_sha256": "unused",
                                "observed": {
                                    "returncode": 0,
                                    "timed_out": False,
                                    "stdout": "usage: fixture\n",
                                    "stderr": "",
                                },
                            },
                            {
                                "label": "proc_bad",
                                "test_id": "bad-option",
                                "status": "pass",
                                "input": {"argv": ["--bad", "value"]},
                                "observed_sha256": "unused",
                                "observed": {
                                    "returncode": 4,
                                    "timed_out": False,
                                    "stdout": "",
                                    "stderr": "bad option: --bad value\n",
                                },
                            },
                        ],
                    }
                ],
            }

            result = compare_process_spec_observations(
                spec=spec,
                command_template=[sys.executable, str(script), "{input.argv}"],
                artifact_dir=root / "process-spec-compare",
                contract_id="fixture.behavior",
            )

        self.assertEqual(result["status"], "pass")
        self.assertEqual(result["observations"], 2)
        self.assertEqual(result["passed"], 2)

    def test_compare_process_spec_observations_accepts_clean_derived_spec_records(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            script = self._write_process_candidate(root)
            spec = {
                "schema_version": 1,
                "format": "wincr-clean-specs-v1",
                "spec_records": [
                    {
                        "entity_type": "behavior_contract",
                        "public_label": "behavior_fixture",
                        "contract_id": "fixture.behavior",
                        "version": "1",
                        "contract": {"format": "fixture-contract-v1"},
                    }
                ],
                "test_records": [
                    {
                        "entity_type": "process_behavior_observation",
                        "public_label": "proc_noargs",
                        "contract_id": "fixture.behavior",
                        "test_id": "noargs",
                        "status": "pass",
                        "inputs": {"argv": []},
                        "outputs": {
                            "returncode": 4,
                            "timed_out": False,
                            "stdout": "",
                            "stderr": "no args\n",
                        },
                    },
                    {
                        "entity_type": "process_behavior_observation",
                        "public_label": "proc_bad",
                        "contract_id": "fixture.behavior",
                        "test_id": "bad-option",
                        "status": "pass",
                        "inputs": {"argv": ["--bad", "value"]},
                        "outputs": {
                            "returncode": 4,
                            "timed_out": False,
                            "stdout": "",
                            "stderr": "bad option: --bad value\n",
                        },
                    }
                ],
            }

            result = compare_process_spec_observations(
                spec=spec,
                command_template=[sys.executable, str(script), "{input.argv}"],
                artifact_dir=root / "clean-process-spec-compare",
                contract_id="fixture.behavior",
            )

        self.assertEqual(result["status"], "pass")
        self.assertEqual(result["observations"], 2)
        self.assertEqual(result["passed"], 2)

    def test_compare_process_spec_observations_cli_reports_mismatch(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            script = self._write_process_candidate(root, wrong_help=True)
            spec = {
                "schema_version": 1,
                "behavior_contracts": [
                    {
                        "label": "behavior_fixture",
                        "contract_id": "fixture.behavior",
                        "title": "Fixture Behavior",
                        "scope": "process behavior",
                        "version": "1",
                        "contract": {},
                        "observations": [],
                        "process_observations": [
                            {
                                "label": "proc_help",
                                "test_id": "help",
                                "status": "pass",
                                "input": {"argv": ["--help"]},
                                "observed_sha256": "unused",
                                "observed": {
                                    "returncode": 0,
                                    "timed_out": False,
                                    "stdout": "usage: fixture\n",
                                    "stderr": "",
                                },
                            }
                        ],
                    }
                ],
            }
            spec_path = root / "specs.json"
            spec_path.write_text(json.dumps(spec), encoding="utf-8")

            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                status = main(
                    [
                        "compare-process-spec-observations",
                        "--spec-json",
                        str(spec_path),
                        "--contract-id",
                        "fixture.behavior",
                        "--artifact-dir",
                        str(root / "process-spec-compare"),
                        "--",
                        sys.executable,
                        str(script),
                        "{input.argv}",
                    ]
                )

        payload = json.loads(output.getvalue())["process_spec_observation_comparison"]
        self.assertEqual(status, 1)
        self.assertEqual(payload["status"], "fail")
        self.assertEqual(payload["failed"], 1)
        self.assertIn("$.stdout", payload["comparisons"][0]["failures"][0])

    def test_run_clean_spec_suite_aggregates_json_and_process_observations(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            json_script = self._write_spec_candidate(root)
            process_script = self._write_process_candidate(root)

            result = run_clean_spec_suite(
                spec=self._clean_suite_spec_fixture(),
                artifact_dir=root / "suite",
                contract_id="fixture.behavior",
                json_command_template=[
                    sys.executable,
                    str(json_script),
                    "--contract",
                    "{contract_json}",
                    "--scenario",
                    "{observed.scenario}",
                    "--seed",
                    "{observed.seed}",
                    "--frames",
                    "{observed.frames}",
                ],
                process_command_template=[sys.executable, str(process_script), "{input.argv}"],
            )
            summary_exists = (root / "suite" / "summary.json").exists()
            json_summary_exists = (root / "suite" / "json-spec-observations" / "summary.json").exists()
            process_summary_exists = (root / "suite" / "process-spec-observations" / "summary.json").exists()

        self.assertEqual(result["status"], "pass")
        self.assertEqual(result["summary"]["contracts"], 1)
        self.assertEqual(result["summary"]["json_observations"], 1)
        self.assertEqual(result["summary"]["process_observations"], 2)
        self.assertEqual(result["summary"]["passed"], 3)
        self.assertEqual(result["summary"]["failed"], 0)
        self.assertEqual({check["kind"] for check in result["checks"]}, {"json_spec_observations", "process_spec_observations"})
        self.assertTrue(summary_exists)
        self.assertTrue(json_summary_exists)
        self.assertTrue(process_summary_exists)

    def test_run_clean_spec_suite_requires_templates_for_present_observation_kinds(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            json_script = self._write_spec_candidate(root)

            result = run_clean_spec_suite(
                spec=self._clean_suite_spec_fixture(),
                artifact_dir=root / "suite",
                contract_id="fixture.behavior",
                json_command_template=[
                    sys.executable,
                    str(json_script),
                    "--contract",
                    "{contract_json}",
                    "--scenario",
                    "{observed.scenario}",
                    "--seed",
                    "{observed.seed}",
                    "--frames",
                    "{observed.frames}",
                ],
            )

        self.assertEqual(result["status"], "fail")
        self.assertEqual(result["summary"]["process_observations"], 2)
        self.assertIn("process command template", result["errors"][0])

    def test_run_clean_spec_suite_cli(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            json_script = self._write_spec_candidate(root)
            process_script = self._write_process_candidate(root)
            spec_path = root / "specs.json"
            spec_path.write_text(json.dumps(self._clean_suite_spec_fixture()), encoding="utf-8")
            output = io.StringIO()

            with contextlib.redirect_stdout(output):
                status = main(
                    [
                        "run-clean-spec-suite",
                        "--spec-json",
                        str(spec_path),
                        "--contract-id",
                        "fixture.behavior",
                        "--artifact-dir",
                        str(root / "suite"),
                        "--json-command-template-json",
                        json.dumps(
                            [
                                sys.executable,
                                str(json_script),
                                "--contract",
                                "{contract_json}",
                                "--scenario",
                                "{observed.scenario}",
                                "--seed",
                                "{observed.seed}",
                                "--frames",
                                "{observed.frames}",
                            ]
                        ),
                        "--process-command-template-json",
                        json.dumps([sys.executable, str(process_script), "{input.argv}"]),
                    ]
                )
            payload = json.loads(output.getvalue())["clean_spec_suite"]

        self.assertEqual(status, 0)
        self.assertEqual(payload["status"], "pass")
        self.assertEqual(payload["summary"]["observations"], 3)

    def _spec_observation_fixture(self):
        return {
            "schema_version": 1,
            "behavior_contracts": [
                {
                    "label": "behavior_fixture",
                    "contract_id": "fixture.behavior",
                    "title": "Fixture Behavior",
                    "scope": "deterministic JSON transcript",
                    "version": "1",
                    "contract": {
                        "format": "fixture-contract-v1",
                        "transcript_format": "fixture-transcript-v1",
                    },
                    "observations": [
                        {
                            "label": "obs_idle_seed7_1",
                            "test_id": "idle-seed7-1",
                            "status": "pass",
                            "input": {},
                            "observed_sha256": "unused",
                            "observed": {
                                "format": "fixture-transcript-v1",
                                "scenario": "idle",
                                "seed": 7,
                                "frames": 1,
                                "final": {"score": 8},
                            },
                        },
                        {
                            "label": "obs_idle_seed9_2",
                            "test_id": "idle-seed9-2",
                            "status": "pass",
                            "input": {},
                            "observed_sha256": "unused",
                            "observed": {
                                "format": "fixture-transcript-v1",
                                "scenario": "idle",
                                "seed": 9,
                                "frames": 2,
                                "final": {"score": 11},
                            },
                        },
                    ],
                }
            ],
        }

    def _clean_suite_spec_fixture(self):
        return {
            "schema_version": 1,
            "format": "wincr-clean-specs-v1",
            "spec_records": [
                {
                    "entity_type": "behavior_contract",
                    "public_label": "behavior_fixture",
                    "contract_id": "fixture.behavior",
                    "version": "1",
                    "contract": {
                        "format": "fixture-contract-v1",
                        "transcript_format": "fixture-transcript-v1",
                    },
                }
            ],
            "test_records": [
                {
                    "entity_type": "behavior_observation",
                    "public_label": "obs_idle_seed7_1",
                    "contract_id": "fixture.behavior",
                    "test_id": "idle-seed7-1",
                    "status": "pass",
                    "inputs": {"scenario": "idle", "seed": 7, "frames": 1},
                    "outputs": {
                        "format": "fixture-transcript-v1",
                        "scenario": "idle",
                        "seed": 7,
                        "frames": 1,
                        "final": {"score": 8},
                    },
                },
                {
                    "entity_type": "process_behavior_observation",
                    "public_label": "proc_noargs",
                    "contract_id": "fixture.behavior",
                    "test_id": "noargs",
                    "status": "pass",
                    "inputs": {"argv": []},
                    "outputs": {
                        "returncode": 4,
                        "timed_out": False,
                        "stdout": "",
                        "stderr": "no args\n",
                    },
                },
                {
                    "entity_type": "process_behavior_observation",
                    "public_label": "proc_bad",
                    "contract_id": "fixture.behavior",
                    "test_id": "bad-option",
                    "status": "pass",
                    "inputs": {"argv": ["--bad", "value"]},
                    "outputs": {
                        "returncode": 4,
                        "timed_out": False,
                        "stdout": "",
                        "stderr": "bad option: --bad value\n",
                    },
                },
            ],
        }

    def _write_spec_candidate(self, root: Path, *, score_offset: int = 0) -> Path:
        script = root / "spec_candidate.py"
        script.write_text(
            "\n".join(
                [
                    "import argparse, json",
                    "parser = argparse.ArgumentParser()",
                    "parser.add_argument('--contract')",
                    "parser.add_argument('--scenario')",
                    "parser.add_argument('--seed', type=int)",
                    "parser.add_argument('--frames', type=int)",
                    "args = parser.parse_args()",
                    "contract = json.loads(open(args.contract, encoding='utf-8').read())",
                    f"score_offset = {score_offset}",
                    "print(json.dumps({",
                    "    'format': contract['transcript_format'],",
                    "    'scenario': args.scenario,",
                    "    'seed': args.seed,",
                    "    'frames': args.frames,",
                    "    'final': {'score': args.seed + args.frames + score_offset},",
                    "}, separators=(',', ':')))",
                    "",
                ]
            ),
            encoding="utf-8",
        )
        return script

    def _write_process_candidate(self, root: Path, *, wrong_help: bool = False) -> Path:
        script = root / "process_candidate.py"
        help_text = "wrong usage" if wrong_help else "usage: fixture"
        script.write_text(
            "\n".join(
                [
                    "import sys",
                    "args = sys.argv[1:]",
                    "if args == ['--help']:",
                    f"    print({help_text!r})",
                    "    raise SystemExit(0)",
                    "if args == ['--bad', 'value']:",
                    "    print('bad option: --bad value', file=sys.stderr)",
                    "    raise SystemExit(4)",
                    "if args == []:",
                    "    print('no args', file=sys.stderr)",
                    "    raise SystemExit(4)",
                    "print('unexpected args: ' + ' '.join(args), file=sys.stderr)",
                    "raise SystemExit(99)",
                    "",
                ]
            ),
            encoding="utf-8",
        )
        return script


if __name__ == "__main__":
    unittest.main()
