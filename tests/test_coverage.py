import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from haloce_catalog import coverage
from haloce_catalog.coverage import parse_drcov_log, resolve_observed_path
from haloce_catalog.db import connect, initialize
from haloce_catalog.labels import ensure_label, ensure_oracle_mapping, module_label
from haloce_catalog.reports import coverage_json, gates_json
from haloce_catalog.util import utc_now


class DrcovParserTests(unittest.TestCase):
    def test_parse_text_log(self):
        log = parse_drcov_log(Path("tests/fixtures/drcov_text.log"))
        self.assertEqual(len(log.modules), 2)
        self.assertEqual(log.modules[0].path, r"C:\Program Files (x86)\Microsoft Games\Halo Custom Edition\haloce.exe")
        self.assertEqual(len(log.blocks), 3)
        self.assertEqual(log.blocks[1].module_id, 0)
        self.assertEqual(log.blocks[1].start, 0x1020)
        self.assertEqual(log.blocks[1].size, 12)

    def test_parse_binary_block_table(self):
        payload = (
            b"DRCOV VERSION: 2\n"
            b"DRCOV FLAVOR: drcov\n"
            b"Module Table: version 2, count 1\n"
            b"Columns: id, containing_id, start, end, entry, offset, preferred_base, path\n"
            b" 0, 0, 0x400000, 0x410000, 0x401000, 0x0, 0x400000, test.exe\n"
            b"BB Table: 1 bbs\n"
            + (0x1234).to_bytes(4, "little")
            + (9).to_bytes(2, "little")
            + (0).to_bytes(2, "little")
        )
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "drcov.log"
            path.write_bytes(payload)
            log = parse_drcov_log(path)
        self.assertEqual(len(log.modules), 1)
        self.assertEqual(len(log.blocks), 1)
        self.assertEqual(log.blocks[0].start, 0x1234)
        self.assertEqual(log.blocks[0].size, 9)

    def test_resolve_wine_c_path_against_install_root(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            target = root / "drive_c" / "Program Files (x86)" / "Microsoft Games" / "Halo Custom Edition" / "haloce.exe"
            target.parent.mkdir(parents=True)
            target.write_bytes(b"MZ")
            resolved = resolve_observed_path(
                r"C:\Program Files (x86)\Microsoft Games\Halo Custom Edition\haloce.exe",
                install_root=root,
            )
        self.assertEqual(resolved, target)

    def test_doctor_uses_resolved_true_executable(self):
        with tempfile.TemporaryDirectory() as tmp:
            true_path = Path(tmp) / "true"
            true_path.write_text("")
            true_path.chmod(0o755)

            completed = subprocess.CompletedProcess(args=[], returncode=0, stdout="", stderr="")
            with (
                mock.patch.object(coverage.shutil, "which", return_value=str(true_path)),
                mock.patch.object(coverage.subprocess, "run", return_value=completed) as run,
            ):
                result = coverage.doctor_drcov()

        command = run.call_args.args[0]
        self.assertEqual(command[-1], str(true_path))
        self.assertEqual(result["smoke_executable"], str(true_path))
        self.assertTrue(result["ok"])

    def test_prove_halo_trace_runs_runner_ingests_and_requires_mapped_edges(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            db_path = tmp_path / "catalog.db"
            log_path = tmp_path / "trace.jsonl"
            module_sha = "c" * 64
            self._seed_binary(db_path, module_sha)

            def fake_run(command, **kwargs):
                runner_name = Path(command[0]).name
                if runner_name not in {"halo-trace-run", "wincr-trace-run"}:
                    return subprocess.CompletedProcess(command, 0, stdout="tool\n", stderr="")
                if len(command) == 2 and command[1] == "--version":
                    return subprocess.CompletedProcess(command, 0, stdout="halo-trace-run 0.1.0\n", stderr="")
                self.assertIn(runner_name, {"halo-trace-run", "wincr-trace-run"})
                self.assertEqual(command[1:5], ["--out", str(log_path), "--test-id", "trace-proof"])
                self.assertIn("--arch", command)
                self.assertEqual(command[command.index("--arch") + 1], "32")
                self.assertEqual(command[-2:], ["wine", "haloce.exe"])
                self.assertEqual(kwargs["timeout"], 10)
                records = [
                    {
                        "kind": "module",
                        "test_id": "trace-proof",
                        "pid": 1,
                        "module_name": "haloce.exe",
                        "module_sha256": module_sha,
                    },
                    {
                        "kind": "block",
                        "test_id": "trace-proof",
                        "pid": 1,
                        "module_sha256": module_sha,
                        "rva_block": 0x1000,
                        "size": 5,
                    },
                    {
                        "kind": "cfg_edge",
                        "test_id": "trace-proof",
                        "pid": 1,
                        "module_sha256": module_sha,
                        "rva_edge_from": 0x1000,
                        "rva_edge_to": 0x1005,
                    },
                    {
                        "kind": "call_edge",
                        "test_id": "trace-proof",
                        "pid": 1,
                        "module_sha256": module_sha,
                        "caller_rva": 0x1000,
                        "callee_module_sha256": module_sha,
                        "callee_rva": 0x2000,
                    },
                ]
                log_path.write_text("\n".join(coverage.json.dumps(record) for record in records) + "\n", encoding="utf-8")
                return subprocess.CompletedProcess(command, 0, stdout="", stderr="")

            with mock.patch.object(coverage.subprocess, "run", side_effect=fake_run):
                result = coverage.prove_halo_trace(
                    db_path,
                    log_path,
                    "trace-proof",
                    ["wine", "haloce.exe"],
                    expected_filename="haloce.exe",
                    arch="32",
                    timeout_seconds=10,
                )

        self.assertTrue(result["ok"], result["failures"])
        self.assertEqual(result["raw_trace"]["expected_blocks"], 1)
        self.assertEqual(
            result["raw_trace"]["module_samples"][0],
            {
                "pid": 1,
                "module_name": "haloce.exe",
                "module_path": None,
                "module_sha256": module_sha,
                "expected": True,
            },
        )
        self.assertEqual(result["mapped"], {"blocks": 1, "cfg_edges": 1, "call_edges": 1})

    def test_prove_trace_passes_semantic_profile_options_to_runner(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            db_path = tmp_path / "catalog.db"
            log_path = tmp_path / "trace.jsonl"
            module_sha = "1" * 64
            self._seed_binary(db_path, module_sha)

            def fake_run(command, **kwargs):
                if command[0] != "trace-runner":
                    return subprocess.CompletedProcess(command, 0, stdout="tool\n", stderr="")
                self.assertEqual(command[0], "trace-runner")
                self.assertIn("--semantic-profile", command)
                self.assertEqual(command[command.index("--semantic-max-records") + 1], "32")
                self.assertLess(command.index("--semantic-profile"), command.index("--"))
                self._write_trace_log(log_path, "trace-semantic", module_sha)
                return subprocess.CompletedProcess(command, 0, stdout="", stderr="")

            with mock.patch.object(coverage.subprocess, "run", side_effect=fake_run):
                result = coverage.prove_trace(
                    db_path,
                    log_path,
                    "trace-semantic",
                    ["wine", "haloce.exe"],
                    expected_filename="haloce.exe",
                    arch="32",
                    trace_runner="trace-runner",
                    timeout_seconds=10,
                    semantic_profile=True,
                    semantic_max_records=32,
                )

        self.assertTrue(result["ok"], result["failures"])

    def test_prove_halo_trace_pretraced_runs_app_with_trace_environment(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            db_path = tmp_path / "catalog.db"
            log_path = tmp_path / "trace.jsonl"
            module_sha = "b" * 64
            self._seed_binary(db_path, module_sha)

            def fake_run(command, **kwargs):
                if command[0] != "haloce-traced":
                    return subprocess.CompletedProcess(command, 0, stdout="tool\n", stderr="")
                self.assertEqual(command, ["haloce-traced", "-window"])
                self.assertEqual(kwargs["env"]["HALOCE_TRACE_OUT"], str(log_path.resolve()))
                self.assertEqual(kwargs["env"]["HALOCE_TRACE_TEST_ID"], "trace-pretraced")
                records = [
                    {
                        "kind": "module",
                        "test_id": "trace-pretraced",
                        "pid": 1,
                        "module_name": "haloce.exe",
                        "module_sha256": module_sha,
                    },
                    {
                        "kind": "block",
                        "test_id": "trace-pretraced",
                        "pid": 1,
                        "module_sha256": module_sha,
                        "rva_block": 0x1000,
                        "size": 5,
                    },
                    {
                        "kind": "cfg_edge",
                        "test_id": "trace-pretraced",
                        "pid": 1,
                        "module_sha256": module_sha,
                        "rva_edge_from": 0x1000,
                        "rva_edge_to": 0x1005,
                    },
                    {
                        "kind": "call_edge",
                        "test_id": "trace-pretraced",
                        "pid": 1,
                        "module_sha256": module_sha,
                        "caller_rva": 0x1000,
                        "callee_module_sha256": module_sha,
                        "callee_rva": 0x2000,
                    },
                ]
                log_path.write_text("\n".join(coverage.json.dumps(record) for record in records) + "\n", encoding="utf-8")
                return subprocess.CompletedProcess(command, 0, stdout="", stderr="")

            with mock.patch.object(coverage.subprocess, "run", side_effect=fake_run):
                result = coverage.prove_halo_trace(
                    db_path,
                    log_path,
                    "trace-pretraced",
                    ["haloce-traced", "-window"],
                    expected_filename="haloce.exe",
                    timeout_seconds=10,
                    pretraced=True,
                )

        self.assertTrue(result["ok"], result["failures"])
        self.assertTrue(result["pretraced"])

    def test_prove_trace_log_accepts_expected_nonzero_returncode(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            db_path = tmp_path / "catalog.db"
            log_path = tmp_path / "trace.jsonl"
            module_sha = "8" * 64
            self._seed_binary(db_path, module_sha)
            self._write_trace_log(log_path, "expected-nonzero", module_sha)

            result = coverage.prove_trace_log(
                db_path,
                log_path,
                "expected-nonzero",
                expected_filename="haloce.exe",
                returncode=4,
                expected_returncode=4,
            )

        self.assertTrue(result["ok"], result["failures"])
        self.assertEqual(result["returncode"], 4)
        self.assertEqual(result["expected_returncode"], 4)

    def test_prove_trace_log_rejects_unexpected_returncode(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            db_path = tmp_path / "catalog.db"
            log_path = tmp_path / "trace.jsonl"
            module_sha = "9" * 64
            self._seed_binary(db_path, module_sha)
            self._write_trace_log(log_path, "unexpected-nonzero", module_sha)

            result = coverage.prove_trace_log(
                db_path,
                log_path,
                "unexpected-nonzero",
                expected_filename="haloce.exe",
                returncode=4,
            )

        self.assertFalse(result["ok"])
        self.assertIn("trace command exited with 4; expected 0", result["failures"])

    def test_prove_halo_trace_accepts_utf8_bom_jsonl(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            db_path = tmp_path / "catalog.db"
            log_path = tmp_path / "trace.jsonl"
            module_sha = "9" * 64
            self._seed_binary(db_path, module_sha)

            def fake_run(command, **kwargs):
                records = [
                    {
                        "kind": "module",
                        "test_id": "trace-bom",
                        "pid": 1,
                        "module_name": "haloce.exe",
                        "module_sha256": module_sha,
                    },
                    {
                        "kind": "block",
                        "test_id": "trace-bom",
                        "pid": 1,
                        "module_sha256": module_sha,
                        "rva_block": 0x1000,
                        "size": 5,
                    },
                    {
                        "kind": "cfg_edge",
                        "test_id": "trace-bom",
                        "pid": 1,
                        "module_sha256": module_sha,
                        "rva_edge_from": 0x1000,
                        "rva_edge_to": 0x1005,
                    },
                    {
                        "kind": "call_edge",
                        "test_id": "trace-bom",
                        "pid": 1,
                        "module_sha256": module_sha,
                        "caller_rva": 0x1000,
                        "callee_module_sha256": module_sha,
                        "callee_rva": 0x2000,
                    },
                ]
                payload = "\n".join(coverage.json.dumps(record) for record in records) + "\n"
                log_path.write_text("\ufeff" + payload, encoding="utf-8")
                return subprocess.CompletedProcess(command, 0, stdout="", stderr="")

            with mock.patch.object(coverage.subprocess, "run", side_effect=fake_run):
                result = coverage.prove_halo_trace(
                    db_path,
                    log_path,
                    "trace-bom",
                    ["haloce-traced"],
                    expected_filename="haloce.exe",
                    timeout_seconds=10,
                    pretraced=True,
                )

        self.assertTrue(result["ok"], result["failures"])
        self.assertEqual(result["raw_trace"]["expected_modules"], 1)

    def test_prove_halo_trace_fails_without_expected_call_edges(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            db_path = tmp_path / "catalog.db"
            log_path = tmp_path / "trace.jsonl"
            module_sha = "d" * 64
            self._seed_binary(db_path, module_sha)

            def fake_run(command, **kwargs):
                if command[0] != "halo-trace-run":
                    return subprocess.CompletedProcess(command, 0, stdout="tool\n", stderr="")
                if command == ["halo-trace-run", "--version"]:
                    return subprocess.CompletedProcess(command, 0, stdout="halo-trace-run 0.1.0\n", stderr="")
                records = [
                    {
                        "kind": "module",
                        "test_id": "trace-no-calls",
                        "pid": 1,
                        "module_name": "haloce.exe",
                        "module_sha256": module_sha,
                    },
                    {
                        "kind": "block",
                        "test_id": "trace-no-calls",
                        "pid": 1,
                        "module_sha256": module_sha,
                        "rva_block": 0x1000,
                        "size": 5,
                    },
                    {
                        "kind": "cfg_edge",
                        "test_id": "trace-no-calls",
                        "pid": 1,
                        "module_sha256": module_sha,
                        "rva_edge_from": 0x1000,
                        "rva_edge_to": 0x1005,
                    },
                ]
                log_path.write_text("\n".join(coverage.json.dumps(record) for record in records) + "\n", encoding="utf-8")
                return subprocess.CompletedProcess(command, 0, stdout="", stderr="")

            with mock.patch.object(coverage.subprocess, "run", side_effect=fake_run):
                result = coverage.prove_halo_trace(
                    db_path,
                    log_path,
                    "trace-no-calls",
                    ["wine", "haloce.exe"],
                    expected_filename="haloce.exe",
                    timeout_seconds=10,
                )

        self.assertFalse(result["ok"])
        self.assertTrue(any("call-edge" in failure or "call edge" in failure for failure in result["failures"]))

    def test_ingest_halo_trace_keeps_synthesized_module_ids_unique(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            db_path = tmp_path / "catalog.db"
            log_path = tmp_path / "trace.jsonl"
            first_sha = "e" * 64
            second_sha = "f" * 64
            self._seed_binary(db_path, first_sha)
            self._seed_binary(db_path, second_sha)
            records = [
                {
                    "kind": "block",
                    "test_id": "out-of-order",
                    "pid": 7,
                    "module_name": "first.dll",
                    "module_sha256": first_sha,
                    "rva_block": 0x1000,
                    "size": 5,
                },
                {
                    "kind": "module",
                    "test_id": "out-of-order",
                    "pid": 7,
                    "module_name": "second.dll",
                    "module_sha256": second_sha,
                },
                {
                    "kind": "block",
                    "test_id": "out-of-order",
                    "pid": 7,
                    "module_name": "second.dll",
                    "module_sha256": second_sha,
                    "rva_block": 0x2000,
                    "size": 5,
                },
            ]
            log_path.write_text("\n".join(coverage.json.dumps(record) for record in records) + "\n", encoding="utf-8")

            result = coverage.ingest_halo_trace(db_path, log_path)

            self.assertEqual(result["blocks"], 2)
            conn = connect(db_path)
            module_ids = [
                row["drcov_module_id"]
                for row in conn.execute("SELECT drcov_module_id FROM observed_modules ORDER BY id").fetchall()
            ]
            conn.close()
        self.assertEqual(module_ids, [0, 1])

    def test_ingest_halo_trace_records_value_trace_records(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            db_path = tmp_path / "catalog.db"
            log_path = tmp_path / "trace.jsonl"
            sha256 = "e" * 64
            self._seed_binary(db_path, sha256)
            conn = connect(db_path)
            created = utc_now()
            binary = conn.execute("SELECT id FROM binaries WHERE sha256 = ?", (sha256,)).fetchone()
            assert binary is not None
            with conn:
                ensure_label(conn, "fn:mapped", "function", "mapped function", created_at=created)
                function_id = conn.execute(
                    """
                    INSERT INTO functions(label, binary_id, rva, name, source, subsystem, purity, side_effects)
                    VALUES ('fn:mapped', ?, 0x1000, 'mapped', 'test', 'logic', 'pure', 'none')
                    """,
                    (binary["id"],),
                ).lastrowid
                ensure_label(conn, "bb:mapped", "basic_block", "mapped block", created_at=created)
                conn.execute(
                    """
                    INSERT INTO basic_blocks(label, binary_id, function_id, rva_start, rva_end, size, source, classification, confidence)
                    VALUES ('bb:mapped', ?, ?, 0x1000, 0x1010, 16, 'test', 'code', 'high')
                    """,
                    (binary["id"], function_id),
                )
            conn.close()
            records = [
                {
                    "kind": "module",
                    "test_id": "semantic-profile",
                    "pid": 7,
                    "module_name": "first.dll",
                    "module_sha256": sha256,
                },
                {
                    "kind": "value_trace",
                    "test_id": "semantic-profile",
                    "pid": 7,
                    "module_name": "first.dll",
                    "module_sha256": sha256,
                    "routine_label": "fn_entry",
                    "block_label": "bb_entry",
                    "rva": "0x1000",
                    "profile": "hot-routines",
                    "values": {
                        "registers": {"eax": "0x2a"},
                        "call_args": ["0x1", "0x2"],
                        "return": "0x2a",
                    },
                },
                {
                    "kind": "value_trace",
                    "test_id": "semantic-profile",
                    "pid": 7,
                    "module_name": "first.dll",
                    "module_sha256": sha256,
                    "rva": "0x1004",
                    "profile": "bounded-block-entry-registers",
                    "values": {"registers": {"xax": 42}},
                },
            ]
            log_path.write_text("\n".join(coverage.json.dumps(record) for record in records) + "\n", encoding="utf-8")

            result = coverage.ingest_halo_trace(db_path, log_path)
            conn = connect(db_path)
            rows = [
                dict(row)
                for row in conn.execute("SELECT * FROM value_traces ORDER BY routine_label, block_label").fetchall()
            ]
            mapping = conn.execute(
                """
                SELECT om.*
                FROM oracle_mappings om
                JOIN value_traces vt ON vt.label = om.label
                WHERE om.entity_type = 'value_trace'
                  AND vt.routine_label = 'fn_entry'
                """
            ).fetchone()
            conn.close()

        self.assertEqual(result["value_traces"], 2)
        self.assertEqual(rows[0]["routine_label"], "fn:mapped")
        self.assertEqual(rows[0]["block_label"], "bb:mapped")
        self.assertEqual(rows[1]["routine_label"], "fn_entry")
        self.assertIn("call_args", rows[1]["values_json"])
        self.assertEqual(mapping["rva_start"], 0x1000)

    def test_coverage_gate_allows_targets_without_static_call_edges(self):
        with tempfile.TemporaryDirectory() as tmp:
            db_path = Path(tmp) / "catalog.db"
            sha256 = "a" * 64
            self._seed_binary(db_path, sha256)
            conn = connect(db_path)
            created = utc_now()
            binary = conn.execute("SELECT id, label FROM binaries WHERE sha256 = ?", (sha256,)).fetchone()
            assert binary is not None
            with conn:
                for label, entity_type in [
                    ("bb:test", "basic_block"),
                    ("cfg:test", "cfg_edge"),
                    ("test:coverage", "test"),
                    ("cov:block", "coverage_block"),
                    ("cov:edge", "coverage_edge"),
                ]:
                    ensure_label(conn, label, entity_type, label, created_at=created)
                conn.execute(
                    """
                    INSERT INTO basic_blocks(label, binary_id, rva_start, rva_end, size, source, classification, confidence)
                    VALUES ('bb:test', ?, 0x1000, 0x1005, 5, 'test', 'code', 'high')
                    """,
                    (binary["id"],),
                )
                conn.execute(
                    """
                    INSERT INTO cfg_edges(label, binary_id, from_rva, to_rva, edge_type, source, confidence)
                    VALUES ('cfg:test', ?, 0x1000, 0x1005, 'fallthrough', 'test', 'high')
                    """,
                    (binary["id"],),
                )
                test_run_id = conn.execute(
                    """
                    INSERT INTO test_runs(label, test_id, suite, command, status, started_at, finished_at,
                                          tool_versions_json, provenance_json)
                    VALUES ('test:coverage', 'coverage', 'trace', 'trace target.exe', 'imported', ?, ?, '{}', '{"cwd":"/tmp"}')
                    """,
                    (created, created),
                ).lastrowid
                observed_module_id = conn.execute(
                    """
                    INSERT INTO observed_modules(test_run_id, drcov_module_id, path, sha256, binary_id)
                    VALUES (?, 0, 'target.exe', ?, ?)
                    """,
                    (test_run_id, sha256, binary["id"]),
                ).lastrowid
                conn.execute(
                    """
                    INSERT INTO coverage_blocks(label, test_run_id, observed_module_id, binary_id,
                                                rva_start, rva_end, size, source_log)
                    VALUES ('cov:block', ?, ?, ?, 0x1000, 0x1005, 5, 'trace.jsonl')
                    """,
                    (test_run_id, observed_module_id, binary["id"]),
                )
                conn.execute(
                    """
                    INSERT INTO coverage_edges(label, test_run_id, observed_module_id, binary_id,
                                               from_rva, to_rva, source_log)
                    VALUES ('cov:edge', ?, ?, ?, 0x1000, 0x1005, 'trace.jsonl')
                    """,
                    (test_run_id, observed_module_id, binary["id"]),
                )
            gate = gates_json(conn)["coverage-complete"]
            conn.close()

        self.assertEqual(gate["static_call_edges"], 0)
        self.assertEqual(gate["status"], "pass")

    def test_coverage_gate_excludes_padding_blocks_from_static_obligations(self):
        with tempfile.TemporaryDirectory() as tmp:
            db_path = Path(tmp) / "catalog.db"
            sha256 = "d" * 64
            self._seed_binary(db_path, sha256)
            conn = connect(db_path)
            created = utc_now()
            binary = conn.execute("SELECT id, label FROM binaries WHERE sha256 = ?", (sha256,)).fetchone()
            assert binary is not None
            with conn:
                for label, entity_type in [
                    ("bb:code", "basic_block"),
                    ("bb:padding", "basic_block"),
                    ("cfg:code", "cfg_edge"),
                    ("test:coverage", "test"),
                    ("cov:block", "coverage_block"),
                    ("cov:edge", "coverage_edge"),
                ]:
                    ensure_label(conn, label, entity_type, label, created_at=created)
                conn.execute(
                    """
                    INSERT INTO basic_blocks(label, binary_id, rva_start, rva_end, size, source, classification, confidence)
                    VALUES ('bb:code', ?, 0x1000, 0x1005, 5, 'test', 'code', 'high')
                    """,
                    (binary["id"],),
                )
                conn.execute(
                    """
                    INSERT INTO basic_blocks(label, binary_id, rva_start, rva_end, size, source, classification, confidence)
                    VALUES ('bb:padding', ?, 0x1005, 0x1010, 11, 'test', 'padding/alignment', 'high')
                    """,
                    (binary["id"],),
                )
                conn.execute(
                    """
                    INSERT INTO cfg_edges(label, binary_id, from_rva, to_rva, edge_type, source, confidence)
                    VALUES ('cfg:code', ?, 0x1000, 0x1005, 'fallthrough', 'test', 'high')
                    """,
                    (binary["id"],),
                )
                test_run_id = conn.execute(
                    """
                    INSERT INTO test_runs(label, test_id, suite, command, status, started_at, finished_at,
                                          tool_versions_json, provenance_json)
                    VALUES ('test:coverage', 'coverage', 'trace', 'trace target.exe', 'imported', ?, ?, '{}', '{"cwd":"/tmp"}')
                    """,
                    (created, created),
                ).lastrowid
                observed_module_id = conn.execute(
                    """
                    INSERT INTO observed_modules(test_run_id, drcov_module_id, path, sha256, binary_id)
                    VALUES (?, 0, 'target.exe', ?, ?)
                    """,
                    (test_run_id, sha256, binary["id"]),
                ).lastrowid
                conn.execute(
                    """
                    INSERT INTO coverage_blocks(label, test_run_id, observed_module_id, binary_id,
                                                rva_start, rva_end, size, source_log)
                    VALUES ('cov:block', ?, ?, ?, 0x1000, 0x1005, 5, 'trace.jsonl')
                    """,
                    (test_run_id, observed_module_id, binary["id"]),
                )
                conn.execute(
                    """
                    INSERT INTO coverage_edges(label, test_run_id, observed_module_id, binary_id,
                                               from_rva, to_rva, source_log)
                    VALUES ('cov:edge', ?, ?, ?, 0x1000, 0x1005, 'trace.jsonl')
                    """,
                    (test_run_id, observed_module_id, binary["id"]),
                )
            coverage_report = coverage_json(conn)
            gate = gates_json(conn, coverage_report)["coverage-complete"]
            conn.close()

        self.assertEqual(coverage_report["static_blocks"], 1)
        self.assertEqual(coverage_report["covered_static_blocks"], 1)
        self.assertEqual(gate["status"], "pass")

    def test_coverage_report_uses_block_entry_and_filters_runtime_unresolved_modules(self):
        with tempfile.TemporaryDirectory() as tmp:
            db_path = Path(tmp) / "catalog.db"
            sha256 = "e" * 64
            self._seed_binary(db_path, sha256)
            conn = connect(db_path)
            created = utc_now()
            binary = conn.execute("SELECT id, label FROM binaries WHERE sha256 = ?", (sha256,)).fetchone()
            assert binary is not None
            with conn:
                for label, entity_type in [
                    ("bb:wide", "basic_block"),
                    ("test:coverage", "test"),
                    ("cov:block", "coverage_block"),
                ]:
                    ensure_label(conn, label, entity_type, label, created_at=created)
                conn.execute(
                    """
                    INSERT INTO basic_blocks(label, binary_id, rva_start, rva_end, size, source, classification, confidence)
                    VALUES ('bb:wide', ?, 0x1000, 0x1020, 32, 'ghidra', 'code', 'high')
                    """,
                    (binary["id"],),
                )
                test_run_id = conn.execute(
                    """
                    INSERT INTO test_runs(label, test_id, suite, command, status, started_at, finished_at,
                                          tool_versions_json, provenance_json)
                    VALUES ('test:coverage', 'coverage', 'trace', 'trace target.exe', 'imported', ?, ?, '{}', '{"cwd":"/tmp"}')
                    """,
                    (created, created),
                ).lastrowid
                observed_module_id = conn.execute(
                    """
                    INSERT INTO observed_modules(test_run_id, drcov_module_id, path, sha256, binary_id)
                    VALUES (?, 0, '/tmp/ref/haloce.exe', ?, ?)
                    """,
                    (test_run_id, sha256, binary["id"]),
                ).lastrowid
                conn.execute(
                    """
                    INSERT INTO coverage_blocks(label, test_run_id, observed_module_id, binary_id,
                                                rva_start, rva_end, size, source_log)
                    VALUES ('cov:block', ?, ?, ?, 0x1000, 0x1005, 5, 'trace.jsonl')
                    """,
                    (test_run_id, observed_module_id, binary["id"]),
                )
                conn.execute(
                    """
                    INSERT INTO observed_modules(test_run_id, drcov_module_id, path, sha256, binary_id)
                    VALUES (?, 1, '/nix/store/wine/lib/wine/i386-windows/conhost.exe', 'f', NULL)
                    """,
                    (test_run_id,),
                )
                conn.execute(
                    """
                    INSERT INTO observed_modules(test_run_id, drcov_module_id, path, sha256, binary_id)
                    VALUES (?, 2, '/tmp/ref/plugin.dll', 'a', NULL)
                    """,
                    (test_run_id,),
                )
            coverage_report = coverage_json(conn)
            conn.close()

        self.assertEqual(coverage_report["covered_static_blocks"], 1)
        self.assertEqual(len(coverage_report["unresolved_modules"]), 1)
        self.assertEqual(coverage_report["unresolved_modules"][0]["path"], "/tmp/ref/plugin.dll")

    def test_coverage_report_counts_observed_fallthrough_source_blocks(self):
        with tempfile.TemporaryDirectory() as tmp:
            db_path = Path(tmp) / "catalog.db"
            sha256 = "f" * 64
            self._seed_binary(db_path, sha256)
            conn = connect(db_path)
            created = utc_now()
            binary = conn.execute("SELECT id, label FROM binaries WHERE sha256 = ?", (sha256,)).fetchone()
            assert binary is not None
            with conn:
                for label, entity_type in [
                    ("bb:fallthrough", "basic_block"),
                    ("cfg:fallthrough", "cfg_edge"),
                    ("test:coverage", "test"),
                    ("cov:block", "coverage_block"),
                ]:
                    ensure_label(conn, label, entity_type, label, created_at=created)
                conn.execute(
                    """
                    INSERT INTO basic_blocks(label, binary_id, rva_start, rva_end, size, source, classification, confidence)
                    VALUES ('bb:fallthrough', ?, 0x1000, 0x1005, 5, 'ghidra', 'code', 'high')
                    """,
                    (binary["id"],),
                )
                conn.execute(
                    """
                    INSERT INTO cfg_edges(label, binary_id, from_rva, to_rva, edge_type, source, confidence)
                    VALUES ('cfg:fallthrough', ?, 0x1004, 0x1005, 'FALL_THROUGH', 'ghidra', 'high')
                    """,
                    (binary["id"],),
                )
                test_run_id = conn.execute(
                    """
                    INSERT INTO test_runs(label, test_id, suite, command, status, started_at, finished_at,
                                          tool_versions_json, provenance_json)
                    VALUES ('test:coverage', 'coverage', 'trace', 'trace target.exe', 'imported', ?, ?, '{}', '{"cwd":"/tmp"}')
                    """,
                    (created, created),
                ).lastrowid
                observed_module_id = conn.execute(
                    """
                    INSERT INTO observed_modules(test_run_id, drcov_module_id, path, sha256, binary_id)
                    VALUES (?, 0, 'target.exe', ?, ?)
                    """,
                    (test_run_id, sha256, binary["id"]),
                ).lastrowid
                conn.execute(
                    """
                    INSERT INTO coverage_blocks(label, test_run_id, observed_module_id, binary_id,
                                                rva_start, rva_end, size, source_log)
                    VALUES ('cov:block', ?, ?, ?, 0x1000, 0x1005, 5, 'trace.jsonl')
                    """,
                    (test_run_id, observed_module_id, binary["id"]),
                )
            coverage_report = coverage_json(conn)
            gate = gates_json(conn, coverage_report)["coverage-complete"]
            conn.close()

        self.assertEqual(coverage_report["static_cfg_edges"], 1)
        self.assertEqual(coverage_report["covered_static_cfg_edges"], 1)
        self.assertEqual(gate["status"], "pass")

    def test_coverage_report_normalizes_import_and_direct_call_evidence(self):
        with tempfile.TemporaryDirectory() as tmp:
            db_path = Path(tmp) / "catalog.db"
            sha256 = "0" * 64
            self._seed_binary(db_path, sha256)
            conn = connect(db_path)
            created = utc_now()
            binary = conn.execute("SELECT id, label FROM binaries WHERE sha256 = ?", (sha256,)).fetchone()
            assert binary is not None
            with conn:
                for label, entity_type in [
                    ("bb:caller", "basic_block"),
                    ("bb:callee", "basic_block"),
                    ("call:import", "call_edge"),
                    ("call:direct", "call_edge"),
                    ("test:coverage", "test"),
                    ("cov:block:caller", "coverage_block"),
                    ("cov:block:callee", "coverage_block"),
                    ("cov:call:import", "coverage_call_edge"),
                ]:
                    ensure_label(conn, label, entity_type, label, created_at=created)
                conn.execute(
                    """
                    INSERT INTO basic_blocks(label, binary_id, rva_start, rva_end, size, source, classification, confidence)
                    VALUES ('bb:caller', ?, 0x1000, 0x1010, 16, 'ghidra', 'code', 'high')
                    """,
                    (binary["id"],),
                )
                conn.execute(
                    """
                    INSERT INTO basic_blocks(label, binary_id, rva_start, rva_end, size, source, classification, confidence)
                    VALUES ('bb:callee', ?, 0x2000, 0x2010, 16, 'ghidra', 'code', 'high')
                    """,
                    (binary["id"],),
                )
                conn.execute(
                    """
                    INSERT INTO call_edges(label, binary_id, caller_rva, callee_symbol, call_type, source, confidence)
                    VALUES ('call:import', ?, 0x1004, 'KERNEL32.DLL::WriteFile', 'COMPUTED_CALL', 'ghidra', 'high')
                    """,
                    (binary["id"],),
                )
                conn.execute(
                    """
                    INSERT INTO call_edges(label, binary_id, caller_rva, callee_rva, call_type, source, confidence)
                    VALUES ('call:direct', ?, 0x1008, 0x2000, 'UNCONDITIONAL_CALL', 'ghidra', 'high')
                    """,
                    (binary["id"],),
                )
                test_run_id = conn.execute(
                    """
                    INSERT INTO test_runs(label, test_id, suite, command, status, started_at, finished_at,
                                          tool_versions_json, provenance_json)
                    VALUES ('test:coverage', 'coverage', 'trace', 'trace target.exe', 'imported', ?, ?, '{}', '{"cwd":"/tmp"}')
                    """,
                    (created, created),
                ).lastrowid
                observed_module_id = conn.execute(
                    """
                    INSERT INTO observed_modules(test_run_id, drcov_module_id, path, sha256, binary_id)
                    VALUES (?, 0, 'target.exe', ?, ?)
                    """,
                    (test_run_id, sha256, binary["id"]),
                ).lastrowid
                conn.execute(
                    """
                    INSERT INTO coverage_blocks(label, test_run_id, observed_module_id, binary_id,
                                                rva_start, rva_end, size, source_log)
                    VALUES ('cov:block:caller', ?, ?, ?, 0x1000, 0x1010, 16, 'trace.jsonl')
                    """,
                    (test_run_id, observed_module_id, binary["id"]),
                )
                conn.execute(
                    """
                    INSERT INTO coverage_blocks(label, test_run_id, observed_module_id, binary_id,
                                                rva_start, rva_end, size, source_log)
                    VALUES ('cov:block:callee', ?, ?, ?, 0x2000, 0x2010, 16, 'trace.jsonl')
                    """,
                    (test_run_id, observed_module_id, binary["id"]),
                )
                conn.execute(
                    """
                    INSERT INTO coverage_call_edges(label, test_run_id, observed_module_id, binary_id,
                                                    caller_rva, source_log)
                    VALUES ('cov:call:import', ?, ?, ?, 0x1004, 'trace.jsonl')
                    """,
                    (test_run_id, observed_module_id, binary["id"]),
                )
            coverage_report = coverage_json(conn)
            conn.close()

        self.assertEqual(coverage_report["static_call_edges"], 2)
        self.assertEqual(coverage_report["covered_static_call_edges"], 2)

    def _write_trace_log(self, path: Path, test_id: str, module_sha: str) -> None:
        records = [
            {
                "kind": "module",
                "test_id": test_id,
                "pid": 1,
                "module_name": "haloce.exe",
                "module_sha256": module_sha,
            },
            {
                "kind": "block",
                "test_id": test_id,
                "pid": 1,
                "module_sha256": module_sha,
                "rva_block": 0x1000,
                "size": 5,
            },
            {
                "kind": "cfg_edge",
                "test_id": test_id,
                "pid": 1,
                "module_sha256": module_sha,
                "rva_edge_from": 0x1000,
                "rva_edge_to": 0x1005,
            },
            {
                "kind": "call_edge",
                "test_id": test_id,
                "pid": 1,
                "module_sha256": module_sha,
                "caller_rva": 0x1000,
                "callee_module_sha256": module_sha,
                "callee_rva": 0x2000,
            },
        ]
        path.write_text("\n".join(coverage.json.dumps(record) for record in records) + "\n", encoding="utf-8")

    def _seed_binary(self, db_path: Path, sha256: str) -> None:
        conn = connect(db_path)
        initialize(conn)
        label = module_label("drive_c/game/haloce.exe", sha256)
        created = utc_now()
        with conn:
            ensure_label(conn, label, "module", "drive_c/game/haloce.exe", created_at=created)
            cursor = conn.execute(
                """
                INSERT INTO binaries(
                  label, path, filename, sha256, size, kind, machine, timestamp, image_base,
                  entrypoint_rva, size_of_image, subsystem, linker_version, pe_checksum,
                  role, scope, role_reason, source_root, catalog_version, discovered_at
                )
                VALUES (?, 'drive_c/game/haloce.exe', 'haloce.exe', ?, 1, 'exe', 'i386', 0,
                        4194304, 4096, 8192, 'windows_gui', '0.0', 0,
                        'closed_runtime', 'included', 'test binary', '/tmp/ref', 'test', ?)
                """,
                (label, sha256, created),
            )
            ensure_oracle_mapping(
                conn,
                label=label,
                entity_type="module",
                binary_id=int(cursor.lastrowid),
                module_sha256=sha256,
                rva_start=0,
                rva_end=8192,
            )
        conn.close()


if __name__ == "__main__":
    unittest.main()
