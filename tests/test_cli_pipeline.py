import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from haloce_catalog.cli import main


class CliPipelineTests(unittest.TestCase):
    def test_analyze_reference_runs_catalog_ghidra_static_and_reports(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            install_root = root / "reference" / "basePackage"
            install_root.mkdir(parents=True)
            db_path = root / "catalog.db"
            report_dir = root / "reports"
            ghidra_out = root / "ghidra" / "exports"
            ghidra_projects = root / "ghidra" / "projects"
            output = io.StringIO()

            with (
                mock.patch("haloce_catalog.cli.build_catalog", return_value={"errors": [], "binaries_inserted": 2}) as build,
                mock.patch(
                    "haloce_catalog.cli.run_ghidra_export",
                    return_value={"failures": [], "exported": 2, "imported": {"functions": 10}},
                ) as ghidra,
                mock.patch(
                    "haloce_catalog.cli.run_static_cross_checks",
                    return_value={"failed": 0, "passed": 4, "checks": 4},
                ) as static,
                mock.patch(
                    "haloce_catalog.cli.generate_reports",
                    return_value={"manifest_json": report_dir / "manifest.json", "tests_json": report_dir / "tests.json"},
                ) as reports,
                contextlib.redirect_stdout(output),
            ):
                status = main(
                    [
                        "analyze-reference",
                        "--install-root",
                        str(install_root),
                        "--db",
                        str(db_path),
                        "--report-dir",
                        str(report_dir),
                        "--ghidra-filename",
                        "haloce.exe",
                        "--ghidra-filename",
                        "haloceded.exe",
                        "--ghidra-out-dir",
                        str(ghidra_out),
                        "--ghidra-project-dir",
                        str(ghidra_projects),
                        "--ghidra-timeout-seconds",
                        "120",
                        "--static-timeout-seconds",
                        "30",
                    ]
                )

        payload = json.loads(output.getvalue())
        self.assertEqual(status, 0)
        self.assertTrue(payload["ok"])
        build.assert_called_once()
        self.assertEqual(build.call_args.args[0], install_root.resolve())
        self.assertEqual(build.call_args.args[1], db_path)
        ghidra.assert_called_once()
        self.assertEqual(ghidra.call_args.kwargs["scopes"], ("included", "candidate"))
        self.assertEqual(ghidra.call_args.kwargs["filenames"], ["haloce.exe", "haloceded.exe"])
        self.assertEqual(ghidra.call_args.kwargs["timeout_seconds"], 120)
        static.assert_called_once()
        self.assertEqual(static.call_args.kwargs["timeout_seconds"], 30)
        reports.assert_called_once_with(db_path, report_dir)
        self.assertIn("manifest_json", payload["reports"])

    def test_analyze_reference_defaults_ghidra_to_all_gate_relevant_runtime_pes(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            install_root = root / "reference" / "basePackage"
            install_root.mkdir(parents=True)

            with (
                mock.patch("haloce_catalog.cli.build_catalog", return_value={"errors": [], "binaries_inserted": 8}),
                mock.patch("haloce_catalog.cli.run_ghidra_export", return_value={"failures": [], "exported": 8}) as ghidra,
                mock.patch("haloce_catalog.cli.run_static_cross_checks", return_value={"failed": 0, "passed": 16}),
                mock.patch("haloce_catalog.cli.generate_reports", return_value={}),
                contextlib.redirect_stdout(io.StringIO()),
            ):
                status = main(["analyze-reference", "--install-root", str(install_root)])

        self.assertEqual(status, 0)
        ghidra.assert_called_once()
        self.assertEqual(ghidra.call_args.kwargs["scopes"], ("included", "candidate"))
        self.assertIsNone(ghidra.call_args.kwargs["filenames"])

    def test_analyze_reference_fails_when_static_cross_check_fails(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            install_root = root / "reference" / "basePackage"
            install_root.mkdir(parents=True)

            with (
                mock.patch("haloce_catalog.cli.build_catalog", return_value={"errors": [], "binaries_inserted": 2}),
                mock.patch("haloce_catalog.cli.run_ghidra_export", return_value={"failures": [], "exported": 2}),
                mock.patch("haloce_catalog.cli.run_static_cross_checks", return_value={"failed": 1, "passed": 3}),
                mock.patch("haloce_catalog.cli.generate_reports", return_value={}),
                contextlib.redirect_stdout(io.StringIO()),
            ):
                status = main(["analyze-reference", "--install-root", str(install_root)])

        self.assertEqual(status, 1)


if __name__ == "__main__":
    unittest.main()
