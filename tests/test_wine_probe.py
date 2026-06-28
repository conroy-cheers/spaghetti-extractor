import os
import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from haloce_catalog.db import connect
from haloce_catalog.reports import coverage_json, coverage_markdown, gates_json
from haloce_catalog.wine_probe import _build_probe_catalog, probe_wine_trace_matrix


class WineTraceProbeTests(unittest.TestCase):
    def test_isolated_catalog_build_runs_helper_process(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            root = tmp_path / "smoke"
            db_path = tmp_path / "probe" / "catalog.db"
            out_dir = tmp_path / "probe"
            completed = subprocess_result(
                0,
                json.dumps({"catalog": {"root": str(root), "errors": [], "binaries": {"total": 1}}}),
                "helper stderr",
            )

            with (
                mock.patch("haloce_catalog.wine_probe.shutil.which", return_value="/bin/haloce-catalog"),
                mock.patch("haloce_catalog.wine_probe.subprocess.run", return_value=completed) as run,
            ):
                catalog = _build_probe_catalog(root, db_path, out_dir, isolated=True)

            command = run.call_args.args[0]
            self.assertEqual(command[:2], ["/bin/haloce-catalog", "build"])
            self.assertIn("--install-root", command)
            self.assertIn(str(root), command)
            self.assertIn("--db", command)
            self.assertIn(str(db_path), command)
            self.assertTrue(catalog["isolated_build"])
            self.assertEqual(catalog["isolated_build_stderr"], "helper stderr")

    def test_probe_runs_each_wine_command_against_one_smoke_catalog(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            smoke_root = tmp_path / "smoke"
            smoke_exe = smoke_root / "bin" / "halo-trace-win32-smoke.exe"
            smoke_exe.parent.mkdir(parents=True)
            smoke_exe.write_bytes(b"MZ")
            wrapper_root = tmp_path / "smoke-root-wrapper"
            wrapper = wrapper_root / "bin" / "halo-trace-win32-smoke-root"
            wrapper.parent.mkdir(parents=True)
            wrapper.write_text(f"#!/bin/sh\nprintf '%s\\n' {smoke_root!s}\n", encoding="utf-8")
            wrapper.chmod(0o755)
            out_dir = tmp_path / "probe"
            calls = []
            direct_calls = []
            wait_calls = []

            def fake_proof(db_path, trace_log, test_id, app, **kwargs):
                calls.append((db_path, trace_log, test_id, app, kwargs, os.environ.get("WINEDEBUG"), os.environ.get("WINEPREFIX")))
                command = ["halo-trace-run", "--", *app]
                return {
                    "ok": "wine-good" in app[0],
                    "failures": [] if "wine-good" in app[0] else ["missing expected module record"],
                    "command": command,
                    "expected": {
                        "filename": "halo-trace-win32-smoke.exe",
                        "sha256": "f" * 64,
                        "binary_id": 1,
                    },
                    "returncode": 0,
                    "timed_out": False,
                    "trace_log": str(trace_log),
                    "raw_trace": {"expected_modules": 1 if "wine-good" in app[0] else 0},
                    "mapped": {"blocks": 1 if "wine-good" in app[0] else 0, "cfg_edges": 1, "call_edges": 1},
                    "stdout": "",
                    "stderr": "",
                }

            def fake_direct(app, timeout_seconds):
                direct_calls.append((app, timeout_seconds, os.environ.get("WINEPREFIX")))
                return {
                    "command": " ".join(app),
                    "ok": True,
                    "returncode": 0,
                    "timed_out": False,
                    "stdout": "halo trace win32 smoke\n",
                    "stderr": "",
                }

            def fake_wait(app, timeout_seconds):
                wait_calls.append((app, timeout_seconds, os.environ.get("WINEPREFIX")))
                return {
                    "command": f"{app[0]}-wineserver -w",
                    "ok": True,
                    "skipped": False,
                    "returncode": 0,
                    "timed_out": False,
                    "stdout": "",
                    "stderr": "",
                }

            with (
                mock.patch.dict(os.environ, {}, clear=True),
                mock.patch("haloce_catalog.wine_probe.build_catalog", return_value={"errors": []}) as build_catalog,
                mock.patch("haloce_catalog.wine_probe.prove_halo_trace", side_effect=fake_proof),
                mock.patch("haloce_catalog.wine_probe._run_direct_wine_smoke", side_effect=fake_direct),
                mock.patch("haloce_catalog.wine_probe._run_wineserver_wait", side_effect=fake_wait),
                mock.patch("haloce_catalog.wine_probe.tool_versions", return_value={"haloce_catalog": "test", "python": "3.13"}),
                mock.patch("haloce_catalog.wine_probe.runtime_provenance", return_value={"cwd": "/work"}),
            ):
                result = probe_wine_trace_matrix(
                    smoke_root=wrapper_root,
                    smoke_exe=None,
                    out_dir=out_dir,
                    wine_commands=["/opt/wine-bad/bin/wine", "/opt/wine-good/bin/wine --no-foo"],
                    trace_runner="halo-trace-run",
                    timeout_seconds=7,
                    wait_wineserver=True,
                )

            build_catalog.assert_called_once_with(smoke_root.resolve(), out_dir / "catalog.db", static_depth="none")
            self.assertTrue(result["ok"])
            self.assertEqual(result["smoke_root"], str(smoke_root.resolve()))
            self.assertEqual(len(result["results"]), 2)
            self.assertEqual(calls[0][3], ["/opt/wine-bad/bin/wine", str(smoke_exe.resolve())])
            self.assertEqual(calls[1][3], ["/opt/wine-good/bin/wine", "--no-foo", str(smoke_exe.resolve())])
            self.assertEqual(direct_calls[0][0:2], (["/opt/wine-bad/bin/wine", str(smoke_exe.resolve())], 7))
            self.assertEqual(direct_calls[1][0:2], (["/opt/wine-good/bin/wine", "--no-foo", str(smoke_exe.resolve())], 7))
            self.assertEqual(wait_calls[0][0:2], (["/opt/wine-bad/bin/wine"], 7))
            self.assertEqual(wait_calls[1][0:2], (["/opt/wine-good/bin/wine", "--no-foo"], 7))
            self.assertEqual(calls[0][4]["trace_runner"], "halo-trace-run")
            self.assertEqual(calls[0][4]["timeout_seconds"], 7)
            self.assertEqual(calls[0][5], "-all")
            self.assertEqual(calls[0][6], str((out_dir / "wineprefixes" / "wine-probe-01-wine").resolve()))
            self.assertEqual(direct_calls[1][2], str((out_dir / "wineprefixes" / "wine-probe-02-wine").resolve()))
            self.assertFalse("WINEDEBUG" in os.environ)
            self.assertFalse("WINEPREFIX" in os.environ)
            self.assertEqual(result["probes"], {"total": 2, "passed": 1, "failed": 1})
            self.assertTrue(result["results"][0]["direct_launch"]["ok"])
            self.assertTrue(result["results"][0]["wine_prefix_isolated"])

            conn = connect(out_dir / "catalog.db")
            rows = [dict(row) for row in conn.execute("SELECT * FROM trace_probe_results ORDER BY probe_id")]
            coverage = coverage_json(conn)
            gates = gates_json(conn, coverage)
            conn.close()
            self.assertEqual([row["status"] for row in rows], ["fail", "pass"])
            self.assertEqual(rows[0]["probe_kind"], "wine-dynamorio-pe32")
            self.assertEqual(rows[0]["expected_filename"], "halo-trace-win32-smoke.exe")
            self.assertEqual(json.loads(rows[0]["failures_json"]), ["missing expected module record"])
            self.assertEqual(json.loads(rows[1]["mapped_json"])["blocks"], 1)
            provenance = json.loads(rows[1]["provenance_json"])
            self.assertEqual(provenance["wine_command"], "/opt/wine-good/bin/wine --no-foo")
            self.assertEqual(provenance["trace_wine_command"], "/opt/wine-good/bin/wine --no-foo")
            self.assertEqual(provenance["wine_debug"], "-all")
            self.assertEqual(provenance["wine_prefix"], str((out_dir / "wineprefixes" / "wine-probe-02-wine").resolve()))
            self.assertTrue(provenance["wine_prefix_isolated"])
            self.assertEqual(provenance["direct_launch"]["returncode"], 0)
            self.assertEqual(provenance["wineserver_wait"]["returncode"], 0)
            self.assertEqual(
                conn_row_count(out_dir / "catalog.db", "labels", "entity_type = 'trace_probe'"),
                2,
            )
            self.assertEqual(coverage["trace_probes"]["total"], 2)
            self.assertEqual(coverage["trace_probes"]["passed"], 1)
            self.assertEqual(gates["coverage-complete"]["trace_probe_attempts"], 2)
            self.assertIn("diagnostic evidence only", coverage_markdown(coverage, gates))

    def test_probe_requires_smoke_root_or_exe(self):
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaisesRegex(ValueError, "smoke-root or --smoke-exe"):
                probe_wine_trace_matrix(
                    smoke_root=None,
                    smoke_exe=None,
                    out_dir=Path(tmp),
                    wine_commands=[],
                )

    def test_probe_resolves_nix_wine_wrapper_to_hidden_loader(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            smoke_root = tmp_path / "smoke"
            smoke_exe = smoke_root / "bin" / "halo-trace-win32-smoke.exe"
            smoke_exe.parent.mkdir(parents=True)
            smoke_exe.write_bytes(b"MZ")
            wine_root = tmp_path / "wine"
            wrapper = wine_root / "bin" / "wine"
            loader = wine_root / "bin" / ".wine"
            wrapper.parent.mkdir(parents=True)
            loader.write_bytes(b"\x7fELF")
            wrapper.write_text(
                "#!/bin/sh\n"
                f"export WINELOADER='{loader}'\n"
                'exec -a "$0" "$WINELOADER" "$@"\n',
                encoding="utf-8",
            )
            wrapper.chmod(0o755)
            calls = []
            direct_calls = []
            wait_calls = []

            def fake_proof(db_path, trace_log, test_id, app, **kwargs):
                calls.append((app, kwargs))
                return {
                    "ok": False,
                    "failures": ["missing expected module record"],
                    "command": ["halo-trace-run", "--", *app],
                    "expected": {
                        "filename": "halo-trace-win32-smoke.exe",
                        "sha256": "f" * 64,
                        "binary_id": 1,
                    },
                    "returncode": 255,
                    "timed_out": False,
                    "trace_log": str(trace_log),
                    "raw_trace": {"modules": 0},
                    "mapped": {"blocks": 0, "cfg_edges": 0, "call_edges": 0},
                    "stdout": "",
                    "stderr": "",
                }

            def fake_direct(app, timeout_seconds):
                direct_calls.append((app, timeout_seconds))
                return {
                    "command": " ".join(app),
                    "ok": True,
                    "returncode": 0,
                    "timed_out": False,
                    "stdout": "halo trace win32 smoke\n",
                    "stderr": "",
                }

            def fake_wait(app, timeout_seconds):
                wait_calls.append((app, timeout_seconds))
                return {"command": "wineserver -w", "ok": True, "skipped": False, "returncode": 0}

            with (
                mock.patch.dict(os.environ, {}, clear=True),
                mock.patch("haloce_catalog.wine_probe.build_catalog", return_value={"errors": []}),
                mock.patch("haloce_catalog.wine_probe.prove_halo_trace", side_effect=fake_proof),
                mock.patch("haloce_catalog.wine_probe._run_direct_wine_smoke", side_effect=fake_direct),
                mock.patch("haloce_catalog.wine_probe._run_wineserver_wait", side_effect=fake_wait),
                mock.patch("haloce_catalog.wine_probe.tool_versions", return_value={"haloce_catalog": "test"}),
                mock.patch("haloce_catalog.wine_probe.runtime_provenance", return_value={"cwd": "/work"}),
                mock.patch("haloce_catalog.wine_probe._wine_command_version", return_value="wine-test"),
            ):
                result = probe_wine_trace_matrix(
                    smoke_root=smoke_root,
                    smoke_exe=None,
                    out_dir=tmp_path / "probe",
                    wine_commands=[f"{wrapper} --flag"],
                    trace_runner="halo-trace-run",
                    wait_wineserver=True,
                )

            self.assertFalse(result["ok"])
            self.assertEqual(calls[0][0], [str(loader), "--flag", str(smoke_exe.resolve())])
            self.assertEqual(direct_calls[0][0], [str(wrapper), "--flag", str(smoke_exe.resolve())])
            self.assertEqual(wait_calls[0][0], [str(wrapper), "--flag"])
            self.assertEqual(result["results"][0]["wine_wrapper"], str(wrapper))
            self.assertEqual(result["results"][0]["wine_loader"], str(loader))
            self.assertTrue(result["results"][0]["direct_launch"]["ok"])
            conn = connect(tmp_path / "probe" / "catalog.db")
            provenance = json.loads(
                conn.execute("SELECT provenance_json FROM trace_probe_results").fetchone()["provenance_json"]
            )
            conn.close()
            self.assertEqual(provenance["wine_wrapper"], str(wrapper))
            self.assertEqual(provenance["wine_loader"], str(loader))
            self.assertEqual(provenance["trace_wine_command"], f"{loader} --flag")
            self.assertEqual(provenance["direct_launch"]["command"], f"{wrapper} --flag {smoke_exe.resolve()}")


def conn_row_count(db_path: Path, table: str, where: str) -> int:
    conn = connect(db_path)
    try:
        return int(conn.execute(f"SELECT COUNT(*) AS count FROM {table} WHERE {where}").fetchone()["count"])
    finally:
        conn.close()


def subprocess_result(returncode: int, stdout: str, stderr: str):
    completed = mock.Mock()
    completed.returncode = returncode
    completed.stdout = stdout
    completed.stderr = stderr
    return completed


if __name__ == "__main__":
    unittest.main()
