import json
import tempfile
import unittest
from pathlib import Path

from haloce_catalog.behavior import record_behavior_observation, upsert_behavior_contract
from haloce_catalog.data_state import record_data_state_test_case, upsert_data_structure
from haloce_catalog.db import connect, initialize
from haloce_catalog.interfaces import record_interface_test_case
from haloce_catalog.labels import (
    basic_block_label,
    call_edge_label,
    coverage_block_label,
    coverage_call_label,
    coverage_edge_label,
    cfg_edge_label,
    data_ref_label,
    ensure_label,
    executable_byte_class_label,
    executable_range_label,
    function_label,
    global_label,
    module_label,
    platform_endpoint_label,
    test_run_label as make_test_run_label,
    trace_probe_label,
    waiver_label,
)
from haloce_catalog.mutation import record_mutation_test_case
from haloce_catalog.oracle import record_oracle_test_case
from haloce_catalog.reports import generate_reports
from haloce_catalog.spec_generation import specs_json
from haloce_catalog.util import json_dumps, utc_now


class SpecGenerationTests(unittest.TestCase):
    def test_generate_reports_writes_label_first_specs(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            db_path = root / "catalog.db"
            report_dir = root / "reports"
            conn = connect(db_path)
            initialize(conn)
            self._seed_observed_catalog(conn)
            conn.close()

            reports = generate_reports(db_path, report_dir)
            spec = json.loads(reports["specs_json"].read_text(encoding="utf-8"))
            test_report = json.loads(reports["tests_json"].read_text(encoding="utf-8"))
            markdown = reports["specs_markdown"].read_text(encoding="utf-8")
            test_markdown = reports["tests_markdown"].read_text(encoding="utf-8")

        self.assertIn("specs_json", reports)
        self.assertIn("specs_markdown", reports)
        self.assertIn("tests_json", reports)
        self.assertIn("tests_markdown", reports)
        self.assertEqual(len(spec["modules"]), 1)
        self.assertEqual(len(spec["functions"]), 1)
        self.assertEqual(len(spec["basic_blocks"]), 1)
        self.assertEqual(len(spec["cfg_edges"]), 1)
        self.assertEqual(len(spec["call_edges"]), 1)
        self.assertEqual(len(spec["coverage_blocks"]), 1)
        self.assertEqual(len(spec["coverage_edges"]), 1)
        self.assertEqual(len(spec["coverage_call_edges"]), 1)
        self.assertEqual(len(spec["data_refs"]), 1)
        self.assertEqual(len(spec["globals"]), 1)
        self.assertEqual(len(spec["waivers"]), 1)
        self.assertEqual(len(spec["trace_probes"]), 1)
        self.assertEqual(len(spec["platform_endpoints"]), 1)
        self.assertEqual(len(spec["platform_endpoints"][0]["test_cases"]), 1)
        self.assertEqual(len(spec["data_structures"][0]["test_cases"]), 1)
        self.assertEqual(spec["oracle_tests"][0]["suite_id"], "client-startup")
        self.assertEqual(spec["waivers"][0]["category"], "proven-padding-data")
        self.assertEqual(spec["trace_probes"][0]["probe_id"], "wine-probe-01-wine")
        self.assertEqual(spec["trace_probes"][0]["counts"]["raw_expected_modules"], 1)
        self.assertEqual(spec["trace_probes"][0]["counts"]["mapped_blocks"], 1)
        self.assertEqual(spec["coverage_blocks"][0]["test_id"], "trace-proof")
        self.assertEqual(spec["coverage_edges"][0]["module_label"], module_label("drive_c/game/haloce.exe", "a" * 64))
        self.assertEqual(spec["coverage_call_edges"][0]["callee_module_label"], spec["modules"][0]["label"])
        self.assertIn("Label-First Specifications", markdown)
        self.assertIn("## Dynamic Coverage Summary", markdown)
        self.assertIn("## Waivers", markdown)
        self.assertIn("## Trace Probes", markdown)
        self.assertIn("sample.game", markdown)
        self.assertIn("Scenario Inputs", markdown)
        self.assertIn("state increments one frame per step", markdown)
        self.assertIn("aggregate_hash=12345", markdown)
        self.assertIn("| `trace-proof` | 1 | 1 | 1 |", markdown)
        self.assertNotIn("private/traces/trace-proof.jsonl", markdown)
        self.assertNotIn("source_log", json.dumps(spec["coverage_blocks"], sort_keys=True))
        self.assertNotIn("fixture_path", json.dumps(spec, sort_keys=True))
        self.assertNotIn("trace_log", json.dumps(spec, sort_keys=True))
        self.assertEqual(test_report["summary"]["test_runs"], 1)
        self.assertEqual(test_report["summary"]["interface_test_cases"], 1)
        self.assertEqual(test_report["summary"]["data_state_test_cases"], 1)
        self.assertEqual(test_report["summary"]["oracle_test_cases"], 1)
        self.assertEqual(test_report["summary"]["mutation_test_cases"], 1)
        self.assertEqual(test_report["summary"]["trace_probe_results"], 1)
        self.assertEqual(test_report["test_runs"][0]["coverage_blocks"], 1)
        self.assertEqual(test_report["test_runs"][0]["coverage_edges"], 1)
        self.assertEqual(test_report["test_runs"][0]["coverage_call_edges"], 1)
        self.assertEqual(test_report["trace_probe_results"][0]["counts"]["mapped_blocks"], 1)
        self.assertTrue(test_report["trace_probe_results"][0]["direct_launch"]["ok"])
        self.assertIn("Test Evidence Report", test_markdown)
        self.assertIn("## Oracle Tests", test_markdown)
        self.assertIn("direct=`pass`", test_markdown)
        self._assert_label_first(spec)
        self._assert_label_first_test_report(test_report)

    def test_specs_json_can_be_called_directly(self):
        with tempfile.TemporaryDirectory() as tmp:
            conn = connect(Path(tmp) / "catalog.db")
            initialize(conn)
            self._seed_observed_catalog(conn)

            spec = specs_json(conn)
            conn.close()

        self.assertEqual(spec["schema_version"], 1)
        self.assertTrue(spec["functions"][0]["label"].startswith("fn_"))
        self.assertTrue(spec["executable_byte_classes"][0]["label"].startswith("ebyte_"))
        self.assertTrue(spec["trace_probes"][0]["label"].startswith("traceprobe_"))

    def _seed_observed_catalog(self, conn):
        created = utc_now()
        module_sha = "a" * 64
        module = module_label("drive_c/game/haloce.exe", module_sha)
        with conn:
            conn.executemany(
                "INSERT OR REPLACE INTO metadata(key, value) VALUES (?, ?)",
                [
                    ("catalog_version", "test"),
                    ("created_at", created),
                ],
            )
            ensure_label(conn, module, "module", "drive_c/game/haloce.exe", created_at=created)
            binary_id = int(
                conn.execute(
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
                    (module, module_sha, created),
                ).lastrowid
            )

            range_label = executable_range_label(module, 0x1000, 0x1010, "unknown")
            ensure_label(conn, range_label, "executable_range", "text", "test executable range")
            range_id = int(
                conn.execute(
                    """
                    INSERT INTO executable_ranges(
                      label, binary_id, rva_start, rva_end, file_offset_start, file_offset_end,
                      classification, evidence
                    )
                    VALUES (?, ?, 4096, 4112, 512, 528, 'unknown', 'test range')
                    """,
                    (range_label, binary_id),
                ).lastrowid
            )

            byte_label = executable_byte_class_label(module, 0x1000, 0x1010, "code", "ghidra")
            ensure_label(conn, byte_label, "executable_byte_class", "text code", "ghidra code")
            conn.execute(
                """
                INSERT INTO executable_byte_classes(
                  label, binary_id, executable_range_id, rva_start, rva_end,
                  classification, source, evidence, confidence
                )
                VALUES (?, ?, ?, 4096, 4112, 'code', 'ghidra', 'basic block evidence', 'high')
                """,
                (byte_label, binary_id, range_id),
            )

            function = function_label(module, 0x1000, "ghidra", "main_loop")
            ensure_label(conn, function, "function", "main_loop", "function spec")
            function_id = int(
                conn.execute(
                    """
                    INSERT INTO functions(
                      label, binary_id, rva, name, source, calling_convention, signature,
                      subsystem, purity, side_effects, confidence, test_status, clean_room_status
                    )
                    VALUES (?, ?, 4096, 'main_loop', 'ghidra', '__cdecl', 'unknown',
                            'stateful engine logic', 'stateful', 'uses globals', 'high',
                            'oracle-covered', 'ready-for-spec')
                    """,
                    (function, binary_id),
                ).lastrowid
            )

            block = basic_block_label(module, 0x1000, 0x1008, "ghidra")
            ensure_label(conn, block, "basic_block", "main_loop block", "block spec")
            conn.execute(
                """
                INSERT INTO basic_blocks(
                  label, binary_id, function_id, rva_start, rva_end, size,
                  source, classification, confidence
                )
                VALUES (?, ?, ?, 4096, 4104, 8, 'ghidra', 'code', 'high')
                """,
                (block, binary_id, function_id),
            )

            cfg = cfg_edge_label(module, 0x1000, 0x1004, "fallthrough", "ghidra")
            ensure_label(conn, cfg, "cfg_edge", "main_loop cfg", "cfg spec")
            conn.execute(
                """
                INSERT INTO cfg_edges(
                  label, binary_id, function_id, from_rva, to_rva, edge_type, source, confidence
                )
                VALUES (?, ?, ?, 4096, 4100, 'fallthrough', 'ghidra', 'high')
                """,
                (cfg, binary_id, function_id),
            )

            call = call_edge_label(module, 0x1000, None, None, "kernel32.dll!CreateFileA", "CALL", "ghidra")
            ensure_label(conn, call, "call_edge", "CreateFileA call", "call spec")
            conn.execute(
                """
                INSERT INTO call_edges(
                  label, binary_id, caller_rva, callee_symbol, call_type, source, confidence
                )
                VALUES (?, ?, 4096, 'kernel32.dll!CreateFileA', 'CALL', 'ghidra', 'high')
                """,
                (call, binary_id),
            )

            test_run = make_test_run_label("trace-proof", "halo-trace", created)
            ensure_label(conn, test_run, "test", "trace-proof", "coverage test")
            test_run_id = int(
                conn.execute(
                    """
                    INSERT INTO test_runs(
                      label, test_id, suite, command, status, started_at, finished_at,
                      tool_versions_json, provenance_json
                    )
                    VALUES (?, 'trace-proof', 'halo-trace', 'halo-trace-run', 'imported',
                            ?, ?, '{}', '{"cwd":"/tmp"}')
                    """,
                    (test_run, created, created),
                ).lastrowid
            )
            observed_module_id = int(
                conn.execute(
                    """
                    INSERT INTO observed_modules(
                      test_run_id, drcov_module_id, path, sha256, binary_id
                    )
                    VALUES (?, 0, 'drive_c/game/haloce.exe', ?, ?)
                    """,
                    (test_run_id, module_sha, binary_id),
                ).lastrowid
            )
            coverage_block = coverage_block_label(test_run, module, 0x1000, 0x1008)
            ensure_label(conn, coverage_block, "coverage_block", "trace-proof:block", "dynamic block")
            conn.execute(
                """
                INSERT INTO coverage_blocks(
                  label, test_run_id, observed_module_id, binary_id, rva_start, rva_end, size, source_log
                )
                VALUES (?, ?, ?, ?, 4096, 4104, 8, 'private/traces/trace-proof.jsonl')
                """,
                (coverage_block, test_run_id, observed_module_id, binary_id),
            )
            coverage_edge = coverage_edge_label(test_run, module, 0x1000, 0x1004)
            ensure_label(conn, coverage_edge, "coverage_edge", "trace-proof:cfg", "dynamic cfg edge")
            conn.execute(
                """
                INSERT INTO coverage_edges(
                  label, test_run_id, observed_module_id, binary_id, from_rva, to_rva, source_log
                )
                VALUES (?, ?, ?, ?, 4096, 4100, 'private/traces/trace-proof.jsonl')
                """,
                (coverage_edge, test_run_id, observed_module_id, binary_id),
            )
            coverage_call = coverage_call_label(test_run, module, 0x1000, module, 0x2000, None)
            ensure_label(conn, coverage_call, "coverage_call_edge", "trace-proof:call", "dynamic call edge")
            conn.execute(
                """
                INSERT INTO coverage_call_edges(
                  label, test_run_id, observed_module_id, binary_id, caller_rva,
                  callee_binary_id, callee_rva, callee_symbol, source_log
                )
                VALUES (?, ?, ?, ?, 4096, ?, 8192, NULL, 'private/traces/trace-proof.jsonl')
                """,
                (coverage_call, test_run_id, observed_module_id, binary_id, binary_id),
            )

            data_ref = data_ref_label(module, 0x1000, 0x3000, "read", "ghidra")
            ensure_label(conn, data_ref, "data_ref", "global read", "data ref spec")
            conn.execute(
                """
                INSERT INTO data_refs(label, binary_id, from_rva, to_rva, ref_type, source, confidence)
                VALUES (?, ?, 4096, 12288, 'read', 'ghidra', 'medium')
                """,
                (data_ref, binary_id),
            )

            global_state = global_label(module, 0x3000, "g_main_state")
            ensure_label(conn, global_state, "global", "g_main_state", "global spec")
            conn.execute(
                """
                INSERT INTO globals(label, binary_id, rva, name, data_type, subsystem, confidence)
                VALUES (?, ?, 12288, 'g_main_state', 'uint32', 'stateful engine logic', 'medium')
                """,
                (global_state, binary_id),
            )

            waiver = waiver_label(module, 0x1008, 0x1010, "proven-padding-data", "alignment padding")
            ensure_label(conn, waiver, "waiver", "alignment padding", "waiver spec")
            conn.execute(
                """
                INSERT INTO waivers(
                  label, binary_id, rva_start, rva_end, category, reason, evidence,
                  reviewer, revalidation_trigger, created_at
                )
                VALUES (?, ?, 4104, 4112, 'proven-padding-data', 'alignment padding',
                        'static disassembly plus Ghidra agree', 'tests', 'module hash changes', ?)
                """,
                (waiver, binary_id, created),
            )

            endpoint = platform_endpoint_label("kernel32.dll", "CreateFileA", None)
            ensure_label(conn, endpoint, "platform_endpoint", "kernel32.dll!CreateFileA")
            endpoint_id = int(
                conn.execute(
                    """
                    INSERT INTO platform_endpoints(
                      label, dll, symbol, ordinal, endpoint_kind, subsystem, mock_status, test_status
                    )
                    VALUES (?, 'kernel32.dll', 'CreateFileA', NULL, 'import', 'win32', 'complete', 'tested')
                    """,
                    (endpoint,),
                ).lastrowid
            )
            conn.execute(
                "INSERT INTO binary_platform_endpoints(binary_id, endpoint_id, thunk_rva) VALUES (?, ?, 8192)",
                (binary_id, endpoint_id),
            )

        with conn:
            record_interface_test_case(
                conn,
                endpoint_label=endpoint,
                case_kind="success",
                test_id="createfile-success",
                status="pass",
                evidence="mock behavior asserted",
            )
            structure = upsert_data_structure(
                conn,
                name="cache_file_header",
                structure_kind="map",
                spec_status="complete",
                fixture_status="complete",
                description="cache header behavior",
            )
            record_data_state_test_case(
                conn,
                data_structure_label_value=structure["label"],
                case_kind="fixture",
                test_id="cache-header-fixture",
                status="pass",
                evidence="fixture parsed",
                fixture_path="private/fixtures/cache-header.json",
            )
            behavior_contract = upsert_behavior_contract(
                conn,
                contract_id="sample.game",
                title="Sample game transcript contract",
                scope="deterministic transcript",
                version="1",
                contract={
                    "format": "wincr-behavior-contract-v1",
                    "scope": "sample public behavior",
                    "command_line": {
                        "usage": "sample-game.exe --json [--scenario idle]",
                        "defaults": {"scenario": "idle", "frames": 1, "seed": 7},
                    },
                    "constants": {"screen_w": 320, "screen_h": 200},
                    "scenario_inputs": {"idle": "always zero input"},
                    "state_transition": ["state increments one frame per step"],
                    "json_transcript": {
                        "format": "sample-transcript-v1",
                        "required_top_level_fields": ["format", "scenario", "final", "aggregate_hash"],
                    },
                },
                evidence="public test contract",
            )
            record_behavior_observation(
                conn,
                behavior_contract_label_value=behavior_contract["label"],
                test_id="idle-seed7-1",
                observed={
                    "format": "sample-transcript-v1",
                    "scenario": "idle",
                    "seed": 7,
                    "frames": 1,
                    "aggregate_hash": 12345,
                    "final": {"frame": 1, "score": 0, "energy": 100},
                },
                command=["sample-game.exe", "--json", "--scenario", "idle"],
                evidence="sample observation",
                fixture_path="public/fixtures/idle-seed7-1.json",
            )
            record_oracle_test_case(
                conn,
                suite_id="client-startup",
                test_id="windowed-start",
                case_kind="black_box_process",
                status="pass",
                evidence="startup reached menu",
                command="private/oracle/client-startup",
                fixture_path="private/oracle/client-startup.json",
            )
            record_mutation_test_case(
                conn,
                mutation_kind="wrong_implementation",
                target_label=function,
                test_id="main-loop-wrong-implementation",
                status="killed",
                evidence="oracle test failed mutation",
                command="private/mutations/main-loop",
            )
            trace_probe = trace_probe_label("wine-probe-01-wine", "halo-trace-run -- wine smoke.exe", created)
            ensure_label(conn, trace_probe, "trace_probe", "wine-probe-01-wine", "trace probe spec")
            conn.execute(
                """
                INSERT INTO trace_probe_results(
                  label, probe_id, probe_kind, command, status, started_at, finished_at,
                  trace_log, expected_filename, expected_sha256, returncode, timed_out,
                  raw_trace_json, mapped_json, failures_json, stdout, stderr,
                  tool_versions_json, provenance_json
                )
                VALUES (?, 'wine-probe-01-wine', 'wine-dynamorio-pe32',
                        'halo-trace-run -- wine smoke.exe', 'pass', ?, ?,
                        'private/traces/wine-probe.jsonl', 'halo-trace-win32-smoke.exe', ?,
                        0, 0, ?, ?, '[]', '', '', '{}', ?)
                """,
                (
                    trace_probe,
                    created,
                    created,
                    "b" * 64,
                    json_dumps(
                        {
                            "modules": 2,
                            "blocks": 3,
                            "cfg_edges": 4,
                            "call_edges": 5,
                            "expected_modules": 1,
                            "expected_blocks": 1,
                            "expected_cfg_edges": 1,
                            "expected_call_edges": 1,
                            "expected_sha256": "b" * 64,
                        }
                    ),
                    json_dumps({"blocks": 1, "cfg_edges": 1, "call_edges": 1}),
                    json_dumps(
                        {
                            "direct_launch": {
                                "command": "wine smoke.exe",
                                "ok": True,
                                "returncode": 0,
                                "timed_out": False,
                                "stdout": "halo trace win32 smoke\n",
                                "stderr": "",
                            }
                        }
                    ),
                ),
            )

    def _assert_label_first(self, spec):
        payload = json.dumps(spec, sort_keys=True)
        self.assertNotIn("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", payload)
        self.assertNotIn('"rva', payload)
        self.assertNotIn("image_base", payload)
        self.assertNotIn("binary_id", payload)
        self.assertNotIn("module_sha256", payload)
        self.assertNotIn("expected_sha256", payload)
        self.assertNotIn("fixture_path", payload)
        self.assertNotIn("trace_log", payload)
        self.assertNotIn("source_log", payload)
        self.assertNotIn("private/", payload)
        self.assertNotIn("/tmp", payload)
        self.assertNotIn("4096", payload)
        self.assertNotIn("12288", payload)

    def _assert_label_first_test_report(self, report):
        payload = json.dumps(report, sort_keys=True)
        self.assertNotIn("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", payload)
        self.assertNotIn("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", payload)
        self.assertNotIn('"rva', payload)
        self.assertNotIn("image_base", payload)
        self.assertNotIn("binary_id", payload)
        self.assertNotIn("module_sha256", payload)
        self.assertNotIn("expected_sha256", payload)
        self.assertNotIn('"command"', payload)
        self.assertNotIn("fixture_path", payload)
        self.assertNotIn("trace_log", payload)
        self.assertNotIn("source_log", payload)
        self.assertNotIn("provenance", payload)
        self.assertNotIn("tool_versions", payload)
        self.assertNotIn("private/", payload)
        self.assertNotIn("/tmp", payload)
        self.assertNotIn("4096", payload)
        self.assertNotIn("12288", payload)


if __name__ == "__main__":
    unittest.main()
