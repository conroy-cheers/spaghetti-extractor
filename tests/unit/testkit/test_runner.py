from __future__ import annotations

import json
from contextlib import redirect_stderr
from io import StringIO
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from spaghetti_extractor.testkit import Diagnostic, TestkitError
from spaghetti_extractor.testkit.runner import (
    _canonical_json,
    _evaluate_derivations,
    _filtered_source_sha256,
    _read_evaluation_receipt,
    _receipt_core,
    _realise_derivations,
    _write_evaluation_receipt,
    build_commands,
    main,
)


class TestNixFirstRunner(unittest.TestCase):
    def test_public_scheduling_options_preserve_failure_and_smoke_gate(self) -> None:
        commands = (("nix", "build", "smoke"), ("nix", "build", "affected"))
        for failure_position in (0, 1):
            calls = []

            def run(command, repository):
                calls.append(command)
                return 7 if len(calls) - 1 == failure_position else 0

            with self.subTest(failure_position=failure_position), patch(
                "spaghetti_extractor.testkit.runner.check_repository_metadata"
            ), patch("spaghetti_extractor.testkit.runner.build_commands", return_value=commands):
                status = main(["affected", "--max-jobs", "2", "--keep-going"], run=run)
            self.assertEqual(status, 7)
            self.assertEqual(len(calls), failure_position + 1)
            for command in calls:
                self.assertEqual(command[command.index("--max-jobs") + 1], "2")
                self.assertEqual(command.count("--keep-going"), 1)

    def test_public_scheduling_options_reject_nonpositive_job_limit(self) -> None:
        for value in ("0", "-1"):
            with self.subTest(value=value), redirect_stderr(StringIO()), self.assertRaises(SystemExit) as raised:
                main(["affected", "--max-jobs", value])
            self.assertEqual(raised.exception.code, 2)

    def test_runner_fails_fast_with_canonical_metadata_remediation(self) -> None:
        error = TestkitError(
            Diagnostic(
                "error",
                "stale_repository_metadata",
                "metadata is stale",
                remediation="Run `nix run .#dev -- refresh`.",
            )
        )
        run_calls: list[tuple[object, object]] = []
        stderr = StringIO()

        with patch(
            "spaghetti_extractor.testkit.runner.check_repository_metadata",
            side_effect=error,
        ):
            with redirect_stderr(stderr):
                status = main(
                    ["smoke", "--repository", "/work/repo"],
                    run=lambda command, repository: run_calls.append(
                        (command, repository)
                    )
                    or 0,
                )

        self.assertEqual(status, 2)
        self.assertEqual(run_calls, [])
        self.assertEqual(stderr.getvalue().count("nix run .#dev -- refresh"), 1)

    def test_evaluator_materializes_large_expressions_in_a_file(self) -> None:
        expression = "[ " + " ".join("value" for _ in range(500_000)) + " ]"
        observed: dict[str, object] = {}

        def run(command: tuple[str, ...], **kwargs: object) -> SimpleNamespace:
            observed["command"] = command
            expression_path = Path(command[-1])
            observed["expression"] = expression_path.read_text(encoding="utf-8")
            return SimpleNamespace(
                returncode=0,
                stdout='["/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-example.drv"]',
                stderr="",
            )

        with patch("spaghetti_extractor.testkit.runner.subprocess.run", side_effect=run):
            with patch("pathlib.Path.is_file", return_value=True):
                result = _evaluate_derivations(
                    expression,
                    repository=Path("/work/repo"),
                    environment={},
                )

        self.assertEqual(
            result,
            ("/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-example.drv",),
        )
        command = observed["command"]
        self.assertIsInstance(command, tuple)
        self.assertIn("--file", command)
        self.assertNotIn("--expr", command)
        self.assertNotIn(expression, command)
        self.assertIn(expression, observed["expression"])

    def test_static_modes_build_canonical_cached_aggregate(self) -> None:
        command = build_commands(Path("/work/repo"), mode="smoke")

        self.assertEqual(command[0][:4], ("nix", "build", "--impure", "--expr"))
        self.assertIn(
            'flake.legacyPackages.x86_64-linux."test-smoke"',
            command[0][4],
        )
        self.assertIn('"private"', command[0][4])

    def test_affected_builds_only_selected_stable_shards(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "src/spaghetti_extractor").mkdir(parents=True)
            (root / "src/spaghetti_extractor/__init__.py").write_text("")
            (root / "src/spaghetti_extractor/value.py").write_text("VALUE = 1\n")
            (root / "tests/smoke").mkdir(parents=True)
            (root / "tests/smoke/test_smoke.py").write_text("VALUE = 1\n")
            (root / "tests/unit/value").mkdir(parents=True)
            (root / "tests/unit/value/test_value.py").write_text(
                "from spaghetti_extractor.value import VALUE\n"
            )

            rendered = build_commands(
                root,
                mode="affected",
                changed=("src/spaghetti_extractor/value.py",),
            )

            self.assertIn(
                'flake.legacyPackages.x86_64-linux."test-smoke"',
                rendered[0][4],
            )
            self.assertNotIn("test-shard-smoke", rendered[1][4])
            self.assertIn('import (source + "/nix/test-suite.nix")', rendered[1][4])
            # Affected and full validation must exercise the same native kernel;
            # the lighter developer environment silently skips its consumers.
            self.assertIn("pythonEnv = context.transferPythonEnv;", rendered[1][4])
            self.assertIn("planPayload = builtins.fromJSON", rendered[1][4])
            self.assertNotIn("legacyPackages.x86_64-linux.test-shards", rendered[1][4])
            self.assertEqual(rendered[1][-1:], ("--no-link",))
            self.assertNotIn("--keep-going", rendered[1])

    def test_public_shard_catalog_is_owned_by_checks_module(self) -> None:
        module = (Path(__file__).resolve().parents[3] / "nix/flake-modules/checks.nix").read_text(
            encoding="utf-8"
        )

        self.assertIn('catalogSuite = mkTestSuite "catalog";', module)
        self.assertIn("test-shards = catalogSuite.shards;", module)
        self.assertNotIn("test-shards = fullSuite.shards;", module)

    def test_repository_builder_inventory_overrides_unrelated_host_builders(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "nix").mkdir()
            machines = root / "nix/builders.local"
            machines.write_text("ssh-ng://builder x86_64-linux - 1 1 ca-derivations -\n")

            command = build_commands(root, mode="full")[1]

            self.assertIn("--builders", command)
            self.assertIn(f"@{machines.resolve()}", command)

    def test_evaluation_fingerprint_ignores_only_declared_source_exclusions(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "src").mkdir()
            source = root / "src/value.py"
            source.write_text("VALUE = 1\n")
            (root / "build").mkdir()
            ignored = root / "build/generated.json"
            ignored.write_text("one\n")

            initial = _filtered_source_sha256(root)
            ignored.write_text("two\n")
            self.assertEqual(_filtered_source_sha256(root), initial)
            source.write_text("VALUE = 2\n")
            self.assertNotEqual(_filtered_source_sha256(root), initial)

    def test_cached_realisation_preserves_builder_and_failure_flags(self) -> None:
        command = (
            "nix",
            "build",
            "--impure",
            "--expr",
            "let value = 1; in value",
            "--builders",
            "@/work/builders",
            "--option",
            "builders-use-substitutes",
            "true",
            "--keep-going",
            "--max-jobs",
            "2",
            "--no-link",
        )
        with patch("spaghetti_extractor.testkit.runner.subprocess.run") as run:
            run.return_value.returncode = 0
            status = _realise_derivations(
                ("/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-example.drv",),
                command,
                repository=Path("/work/repo"),
                environment={},
            )

        self.assertEqual(status, 0)
        rendered = run.call_args.args[0]
        self.assertEqual(rendered[:3], (
            "nix",
            "build",
            "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-example.drv^out",
        ))
        self.assertNotIn("--expr", rendered)
        self.assertNotIn("--impure", rendered)
        self.assertIn("--builders", rendered)
        self.assertIn("--keep-going", rendered)
        self.assertEqual(rendered[rendered.index("--max-jobs") + 1], "2")

    def test_evaluation_receipt_rejects_corruption_and_wrong_identity(self) -> None:
        derivation = "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-example.drv"
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "receipt.json"
            core = _receipt_core(
                key="k" * 64,
                source_sha256="1" * 64,
                expression_sha256="2" * 64,
                nix_version="nix (Nix) 2.35.1",
                nix_executable="/nix/store/nix/bin/nix",
                derivations=(derivation,),
            )
            expected = {**core, "derivations": []}
            _write_evaluation_receipt(path, core)
            with patch("pathlib.Path.is_file", return_value=True):
                self.assertEqual(
                    _read_evaluation_receipt(path, expected_core=expected),
                    (derivation,),
                )

                payload = json.loads(path.read_text(encoding="ascii"))
                payload["source_sha256"] = "3" * 64
                path.write_bytes(_canonical_json(payload) + b"\n")
                self.assertIsNone(
                    _read_evaluation_receipt(path, expected_core=expected)
                )


if __name__ == "__main__":
    unittest.main()
