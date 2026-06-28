import json
import tempfile
import unittest
from contextlib import redirect_stdout
from io import StringIO
from pathlib import Path

from haloce_catalog.behavior import (
    record_behavior_observation,
    record_process_behavior_observation,
    upsert_behavior_contract,
)
from haloce_catalog.cli import main
from haloce_catalog.data_state import record_data_state_test_case, upsert_data_structure
from haloce_catalog.db import connect, initialize
from haloce_catalog.interfaces import record_interface_test_case, upsert_platform_endpoint
from haloce_catalog.labels import basic_block_label, cfg_edge_label, ensure_label, function_label, module_label
from haloce_catalog.mutation import record_mutation_test_case
from haloce_catalog.oracle import record_oracle_test_case
from haloce_catalog.private_artifacts import export_private_artifacts, validate_dirty_corpus
from haloce_catalog.reports import gates_json
from haloce_catalog.routines import upsert_internal_routine_contract
from haloce_catalog.spec_generation import specs_json
from haloce_catalog.util import utc_now


class PrivateArtifactTests(unittest.TestCase):
    def test_export_private_artifacts_writes_dirty_review_packets_and_gate_evidence(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            install_root = root / "install"
            (install_root / "bin").mkdir(parents=True)
            (install_root / "bin" / "game.exe").write_bytes(b"MZ private test fixture\n")
            db_path = root / "catalog.db"
            conn = connect(db_path)
            initialize(conn)
            fn_label = self._seed_catalog(conn, install_root)
            self._seed_review_evidence(conn, root, fn_label)
            out_dir = root / "private-artifacts"
            (out_dir / "modules" / "stale-module").mkdir(parents=True)
            (out_dir / "modules" / "stale-module" / "manifest.json").write_text("stale", encoding="utf-8")

            with conn:
                result = export_private_artifacts(
                    conn,
                    out_dir,
                    scopes=("included",),
                    objdump="definitely-not-a-real-objdump",
                )
                gates = gates_json(conn)
                artifact_rows = [
                    dict(row)
                    for row in conn.execute(
                        "SELECT artifact_kind, path, taint_level FROM private_artifacts ORDER BY path"
                    )
                ]
            conn.close()

            bundle_root = Path(result["root_path"])
            content = json.loads((bundle_root / "content-manifest.json").read_text(encoding="utf-8"))
            validation = validate_dirty_corpus(
                bundle_root,
                report_json=root / "dirty-corpus-validation.json",
                report_md=root / "dirty-corpus-validation.md",
            )
            self.assertEqual(result["summary"]["modules"], 1)
            self.assertGreater(result["summary"]["artifacts"], 8)
            self.assertFalse(content["includes_self"])
            self.assertEqual(content["format"], "wincr-dirty-corpus-v2")
            self.assertEqual(validation["status"], "pass")
            self.assertEqual(validation["summary"]["errors"], 0)
            self.assertTrue((root / "dirty-corpus-validation.json").exists())
            self.assertTrue((root / "dirty-corpus-validation.md").exists())
            self.assertTrue((bundle_root / "manifest.json").exists())
            self.assertTrue((bundle_root / "dirty-specs.json").exists())
            self.assertTrue((bundle_root / "dirty-specs.md").exists())
            self.assertTrue((bundle_root / "dirty-tests.json").exists())
            self.assertTrue((bundle_root / "dirty-tests.md").exists())
            self.assertTrue((bundle_root / "reimplementation-plan.json").exists())
            self.assertTrue((bundle_root / "reimplementation-plan.md").exists())
            self.assertTrue((bundle_root / "cli-index.json").exists())
            self.assertTrue((bundle_root / "review-html" / "index.html").exists())
            self.assertTrue((bundle_root / "review-html" / "search-index.json").exists())
            self.assertTrue((bundle_root / "modules" / f"game_exe-{'d' * 12}" / "manifest.json").exists())
            self.assertFalse((bundle_root / "modules" / "stale-module" / "manifest.json").exists())
            self.assertTrue(
                (bundle_root / "modules" / f"game_exe-{'d' * 12}" / "static" / "disassembly.asm").exists()
            )
            block_root = bundle_root / "modules" / f"game_exe-{'d' * 12}" / "blocks" / basic_block_label(
                module_label("bin/game.exe", "d" * 64),
                0x1000,
                0x1010,
                "seed",
            )
            self.assertTrue((block_root / "manifest.json").exists())
            self.assertTrue((block_root / "static" / "context.json").exists())
            self.assertTrue((block_root / "static" / "disassembly.asm").exists())
            self.assertTrue((block_root / "static" / "decompiler-status.json").exists())
            self.assertTrue((block_root / "static" / "instructions.json").exists())
            self.assertTrue((block_root / "static" / "pcode.json").exists())
            self.assertTrue((block_root / "static" / "data-flow.json").exists())
            self.assertTrue((block_root / "static" / "xrefs.json").exists())
            self.assertTrue((block_root / "semantic-summary.md").exists())
            self.assertTrue((block_root / "draft" / "clean-template.json").exists())
            block_manifest = json.loads((block_root / "manifest.json").read_text(encoding="utf-8"))
            block_disassembly = (block_root / "static" / "disassembly.asm").read_text(encoding="utf-8")
            block_template = json.loads((block_root / "draft" / "clean-template.json").read_text(encoding="utf-8"))
            block_instructions = json.loads((block_root / "static" / "instructions.json").read_text(encoding="utf-8"))
            self.assertEqual(block_manifest["entity_type"], "basic_block")
            self.assertEqual(block_manifest["rva_start"], 0x1000)
            self.assertEqual(block_manifest["decompiler"]["status"], "not_available")
            self.assertEqual(block_instructions["artifact_role"], "block_instruction_metadata")
            self.assertIn("PRIVATE DIRTY BASIC BLOCK DISASSEMBLY", block_disassembly)
            self.assertEqual(block_template["entity_type"], "basic_block_contract")
            self.assertEqual(block_template["review_status"], "draft")
            routine_root = bundle_root / "modules" / f"game_exe-{'d' * 12}" / "routines" / fn_label
            self.assertTrue((routine_root / "static" / "semantics.json").exists())
            self.assertTrue((routine_root / "static" / "decompiler-status.json").exists())
            self.assertTrue((routine_root / "static" / "pcode.json").exists())
            dirty_specs = json.loads((bundle_root / "dirty-specs.json").read_text(encoding="utf-8"))
            dirty_tests = json.loads((bundle_root / "dirty-tests.json").read_text(encoding="utf-8"))
            reimpl_plan = json.loads((bundle_root / "reimplementation-plan.json").read_text(encoding="utf-8"))
            cli_index = json.loads((bundle_root / "cli-index.json").read_text(encoding="utf-8"))
            self.assertEqual(dirty_specs["format"], "wincr-dirty-spec-suite-v1")
            self.assertEqual(dirty_specs["artifact_role"], "private_dirty_intermediate")
            self.assertEqual(dirty_specs["publication_status"], "private_intermediate_not_for_publication")
            self.assertIn("label_first_draft", dirty_specs)
            self.assertIn("review_surfaces", dirty_specs)
            self.assertIn("label_first_draft", dirty_tests)
            self.assertIn("gate_snapshot", dirty_tests)
            self.assertEqual(dirty_tests["gate_snapshot"]["dirty-reimplementation-ready"]["status"], "pass")
            self.assertGreaterEqual(len(reimpl_plan["tasks"]), 1)
            self.assertIn(fn_label, cli_index["labels"])
            self.assertTrue(any(row["artifact_kind"] == "routine_dirty_contract_draft" for row in artifact_rows))
            self.assertTrue(any(row["artifact_kind"] == "routine_semantics" for row in artifact_rows))
            self.assertTrue(any(row["artifact_kind"] == "routine_decompiler_status" for row in artifact_rows))
            self.assertTrue(any(row["artifact_kind"] == "block_manifest" for row in artifact_rows))
            self.assertTrue(any(row["artifact_kind"] == "block_disassembly" for row in artifact_rows))
            self.assertTrue(any(row["artifact_kind"] == "block_instruction_metadata" for row in artifact_rows))
            self.assertTrue(any(row["artifact_kind"] == "block_pcode" for row in artifact_rows))
            self.assertTrue(any(row["artifact_kind"] == "block_semantic_summary" for row in artifact_rows))
            self.assertTrue(any(row["artifact_kind"] == "block_clean_template" for row in artifact_rows))
            self.assertTrue(any(row["artifact_kind"] == "review_dirty_packet" for row in artifact_rows))
            self.assertTrue(any(row["artifact_kind"] == "review_clean_template" for row in artifact_rows))
            self.assertTrue(any(row["artifact_kind"] == "review_raw_evidence" for row in artifact_rows))
            self.assertTrue(any(row["artifact_kind"] == "dirty_spec_suite" for row in artifact_rows))
            self.assertTrue(any(row["artifact_kind"] == "dirty_test_suite" for row in artifact_rows))
            self.assertTrue(any(row["artifact_kind"] == "reimplementation_plan_json" for row in artifact_rows))
            self.assertTrue(any(row["artifact_kind"] == "dirty_corpus_cli_index" for row in artifact_rows))
            self.assertTrue(any(row["artifact_kind"] == "dirty_corpus_review_html" for row in artifact_rows))
            self.assertGreaterEqual(result["summary"]["by_kind"]["review_dirty_packet"], 8)
            self.assertGreaterEqual(result["summary"]["by_kind"]["review_clean_template"], 8)
            self.assertIn("clean_candidate", result["summary"]["by_taint_level"])
            self.assertIn("behavioral_dirty", result["summary"]["by_taint_level"])
            self.assertIn("decompiler_high_taint", result["summary"]["by_taint_level"])
            self.assertTrue((bundle_root / "review" / "behavior-observations").exists())
            self.assertTrue((bundle_root / "review" / "process-behavior-observations").exists())
            self.assertTrue((bundle_root / "review" / "internal-routine-contracts").exists())
            behavior_templates = list((bundle_root / "review" / "behavior-observations").glob("*/clean-template.json"))
            process_templates = list(
                (bundle_root / "review" / "process-behavior-observations").glob("*/clean-template.json")
            )
            routine_contract_templates = list(
                (bundle_root / "review" / "internal-routine-contracts").glob("*/clean-template.json")
            )
            self.assertEqual(len(behavior_templates), 1)
            self.assertEqual(len(process_templates), 1)
            self.assertEqual(len(routine_contract_templates), 1)
            behavior_template = json.loads(behavior_templates[0].read_text(encoding="utf-8"))
            process_template = json.loads(process_templates[0].read_text(encoding="utf-8"))
            routine_contract_template = json.loads(routine_contract_templates[0].read_text(encoding="utf-8"))
            self.assertEqual(behavior_template["review_status"], "draft")
            self.assertEqual(behavior_template["inputs"]["seed"], 7)
            self.assertEqual(behavior_template["outputs"]["score"], 42)
            self.assertEqual(behavior_template["test_vectors"][0]["expected"]["score"], 42)
            self.assertEqual(process_template["outputs"]["returncode"], 4)
            self.assertIn("usage", process_template["outputs"]["stderr"])
            self.assertEqual(routine_contract_template["entity_type"], "internal_routine_contract")
            self.assertEqual(routine_contract_template["public_name"], "entrypoint_behavior_v1")
            self.assertEqual(routine_contract_template["calling_convention"], "cdecl")
            self.assertEqual(routine_contract_template["inputs"]["seed"], "u32")
            self.assertEqual(routine_contract_template["outputs"]["score"], "u32")
            self.assertEqual(routine_contract_template["evidence_source"], "dynamic_observation")
            template_payload = json.dumps(
                [behavior_template, process_template, routine_contract_template],
                sort_keys=True,
            )
            self.assertNotIn(str(root), template_payload)
            self.assertNotIn("fixture_path", template_payload)
            self.assertNotIn("result_path", template_payload)
            self.assertEqual(gates["private-artifact-complete"]["status"], "pass")
            self.assertGreaterEqual(gates["private-artifact-complete"]["dirty_spec_suites"], 1)
            self.assertGreaterEqual(gates["private-artifact-complete"]["dirty_test_suites"], 1)
            self.assertEqual(gates["private-artifact-complete"]["required_basic_blocks"], 1)
            self.assertEqual(gates["private-artifact-complete"]["block_packets"], 1)
            self.assertEqual(gates["private-artifact-complete"]["block_disassembly_packets"], 1)
            self.assertEqual(gates["private-artifact-complete"]["block_clean_templates"], 1)
            self.assertGreaterEqual(gates["private-artifact-complete"]["required_review_packets"], 8)
            self.assertEqual(gates["private-artifact-complete"]["missing_review_packets"], 0)
            self.assertEqual(gates["private-artifact-complete"]["missing_review_templates"], 0)
            self.assertEqual(gates["dirty-reimplementation-ready"]["status"], "pass")
            self.assertEqual(gates["dirty-reimplementation-ready"]["missing_files"], [])
            self.assertEqual(gates["dirty-reimplementation-ready"]["missing_artifact_kinds"], [])

    def test_validate_dirty_corpus_rejects_broken_packet_and_evidence_links(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            install_root = root / "install"
            (install_root / "bin").mkdir(parents=True)
            (install_root / "bin" / "game.exe").write_bytes(b"MZ private test fixture\n")
            conn = connect(root / "catalog.db")
            initialize(conn)
            fn_label = self._seed_catalog(conn, install_root)
            self._seed_review_evidence(conn, root, fn_label)
            with conn:
                result = export_private_artifacts(
                    conn,
                    root / "private-artifacts",
                    scopes=("included",),
                    objdump="definitely-not-a-real-objdump",
                )
            conn.close()
            bundle_root = Path(result["root_path"])
            next(bundle_root.glob("review/behavior-observations/*/clean-template.json")).unlink()
            next(bundle_root.glob("review/behavior-observations/*/evidence/*.txt")).unlink()

            validation = validate_dirty_corpus(bundle_root)
            errors = "\n".join(validation["errors"])

        self.assertEqual(validation["status"], "fail")
        self.assertIn("missing sibling clean template", errors)
        self.assertIn("copied_path is missing", errors)

    def test_cli_validates_dirty_corpus(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            install_root = root / "install"
            (install_root / "bin").mkdir(parents=True)
            (install_root / "bin" / "game.exe").write_bytes(b"MZ private test fixture\n")
            conn = connect(root / "catalog.db")
            initialize(conn)
            fn_label = self._seed_catalog(conn, install_root)
            self._seed_review_evidence(conn, root, fn_label)
            with conn:
                result = export_private_artifacts(
                    conn,
                    root / "private-artifacts",
                    scopes=("included",),
                    objdump="definitely-not-a-real-objdump",
                )
            conn.close()
            stdout = StringIO()

            with redirect_stdout(stdout):
                code = main(
                    [
                        "validate-dirty-corpus",
                        "--corpus-dir",
                        result["root_path"],
                        "--report-json",
                        str(root / "validation.json"),
                    ],
                    prog="wincr",
                )
            payload = json.loads(stdout.getvalue())
            validation_report_exists = (root / "validation.json").exists()

        self.assertEqual(code, 0)
        self.assertEqual(payload["dirty_corpus_validation"]["status"], "pass")
        self.assertTrue(validation_report_exists)

    def test_cli_renders_and_reviews_dirty_corpus(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            install_root = root / "install"
            (install_root / "bin").mkdir(parents=True)
            (install_root / "bin" / "game.exe").write_bytes(b"MZ private test fixture\n")
            conn = connect(root / "catalog.db")
            initialize(conn)
            fn_label = self._seed_catalog(conn, install_root)
            self._seed_review_evidence(conn, root, fn_label)
            with conn:
                result = export_private_artifacts(
                    conn,
                    root / "private-artifacts",
                    scopes=("included",),
                    objdump="definitely-not-a-real-objdump",
                )
            conn.close()

            render_stdout = StringIO()
            with redirect_stdout(render_stdout):
                render_code = main(
                    [
                        "render-dirty-corpus",
                        "--corpus-dir",
                        result["root_path"],
                        "--out-dir",
                        str(root / "rendered-html"),
                    ],
                    prog="wincr",
                )
            review_stdout = StringIO()
            with redirect_stdout(review_stdout):
                review_code = main(
                    [
                        "review-dirty-corpus",
                        "--corpus-dir",
                        result["root_path"],
                        "--label",
                        fn_label,
                        "--todos",
                    ],
                    prog="wincr",
                )
            render_payload = json.loads(render_stdout.getvalue())
            review_payload = json.loads(review_stdout.getvalue())
            render_index_exists = Path(render_payload["dirty_corpus_html"]["index_html"]).exists()
            validation = validate_dirty_corpus(Path(result["root_path"]))

        self.assertEqual(render_code, 0)
        self.assertTrue(render_index_exists)
        self.assertEqual(render_payload["dirty_corpus_html"]["content_manifest"]["missing"], 0)
        self.assertEqual(validation["status"], "pass")
        self.assertEqual(review_code, 0)
        self.assertEqual(review_payload["dirty_corpus_review"]["label"]["kind"], "routine")
        self.assertGreaterEqual(len(review_payload["dirty_corpus_review"]["todos"]), 1)

    def test_public_spec_excludes_unreviewed_dirty_internal_contracts(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            db_path = root / "catalog.db"
            conn = connect(db_path)
            initialize(conn)
            fn_label = self._seed_catalog(conn, root)

            with conn:
                upsert_internal_routine_contract(
                    conn,
                    label="routine_draft_contract",
                    function_label=fn_label,
                    public_name="draft_entrypoint",
                    purpose_summary="Draft behavior inferred from private evidence.",
                    calling_convention="cdecl",
                    signature="int entry(void)",
                    input_shape={},
                    output_shape={},
                    preconditions=[],
                    postconditions=[],
                    side_effects=[],
                    state_transitions=[],
                    fixtures=[],
                    evidence_labels=[],
                    evidence_source="disassembly_inferred",
                    confidence="medium",
                    taint_level="static_inferred_public",
                    review_status="draft",
                )
                spec = specs_json(conn)
                gate = gates_json(conn)["publication-clean"]
            conn.close()

        self.assertEqual(spec["internal_routine_contracts"], [])
        self.assertEqual(gate["status"], "open")
        self.assertEqual(gate["unreviewed_public_candidates"], 1)

    def _seed_catalog(self, conn, install_root: Path) -> str:
        created = utc_now()
        module_sha = "d" * 64
        module = module_label("bin/game.exe", module_sha)
        fn_label = function_label(module, 0x1000, "seed", "entrypoint")
        with conn:
            conn.executemany(
                "INSERT OR REPLACE INTO metadata(key, value) VALUES (?, ?)",
                [
                    ("catalog_version", "test"),
                    ("created_at", created),
                    ("install_root", str(install_root)),
                    ("target_project_id", "private-artifact-test"),
                    ("target_project_name", "Private Artifact Test"),
                    ("tool_versions", "{}"),
                    ("target_config_json", "{}"),
                ],
            )
            ensure_label(conn, module, "module", "bin/game.exe", created_at=created)
            binary_id = int(
                conn.execute(
                    """
                    INSERT INTO binaries(
                      label, path, filename, sha256, size, kind, machine, timestamp, image_base,
                      entrypoint_rva, size_of_image, subsystem, linker_version, pe_checksum,
                      role, scope, role_reason, source_root, catalog_version, discovered_at
                    )
                    VALUES (?, 'bin/game.exe', 'game.exe', ?, 32, 'exe', 'i386', 0,
                            4194304, 4096, 8192, 'windows_cui', '0.0', 0,
                            'closed_runtime', 'included', 'test binary', ?, 'test', ?)
                    """,
                    (module, module_sha, str(install_root), created),
                ).lastrowid
            )
            ensure_label(conn, fn_label, "function", "entrypoint", created_at=created)
            function_id = int(
                conn.execute(
                    """
                    INSERT INTO functions(
                      label, binary_id, rva, name, source, calling_convention, signature,
                      subsystem, purity, side_effects, confidence, test_status, clean_room_status
                    )
                    VALUES (?, ?, 4096, 'entrypoint', 'seed', 'cdecl', 'int entry(void)',
                            'stateful engine logic', 'stateful', 'writes stdout', 'high',
                            'specified', 'ready')
                    """,
                    (fn_label, binary_id),
                ).lastrowid
            )
            block = basic_block_label(module, 0x1000, 0x1010, "seed")
            ensure_label(conn, block, "basic_block", "entry block", created_at=created)
            conn.execute(
                """
                INSERT INTO basic_blocks(
                  label, binary_id, function_id, rva_start, rva_end, size,
                  source, classification, confidence
                )
                VALUES (?, ?, ?, 4096, 4112, 16, 'seed', 'code', 'high')
                """,
                (block, binary_id, function_id),
            )
            edge = cfg_edge_label(module, 0x1000, 0x1008, "fallthrough", "seed")
            ensure_label(conn, edge, "cfg_edge", "entry edge", created_at=created)
            conn.execute(
                """
                INSERT INTO cfg_edges(
                  label, binary_id, function_id, from_rva, to_rva, edge_type, source, confidence
                )
                VALUES (?, ?, ?, 4096, 4104, 'fallthrough', 'seed', 'high')
                """,
                (edge, binary_id, function_id),
            )
        return fn_label

    def _seed_review_evidence(self, conn, root: Path, function_label: str) -> None:
        evidence_dir = root / "evidence"
        evidence_dir.mkdir()
        stdout_path = evidence_dir / "stdout.txt"
        stderr_path = evidence_dir / "stderr.txt"
        result_path = evidence_dir / "result.json"
        trace_path = evidence_dir / "trace.log"
        stdout_path.write_text("score=42\n", encoding="utf-8")
        stderr_path.write_text("", encoding="utf-8")
        trace_path.write_text("block 0x1000\n", encoding="utf-8")
        result_path.write_text(
            json.dumps(
                {
                    "status": "pass",
                    "stdout_path": str(stdout_path),
                    "stderr_path": str(stderr_path),
                    "trace_log": str(trace_path),
                },
                sort_keys=True,
            ),
            encoding="utf-8",
        )
        with conn:
            contract = upsert_behavior_contract(
                conn,
                contract_id="private.artifact.behavior",
                title="Private artifact behavior",
                scope="review packet fixture",
                version="1",
                contract={"inputs": {"seed": "integer"}, "outputs": {"score": "integer"}},
                evidence="seeded test contract",
            )
            record_behavior_observation(
                conn,
                behavior_contract_label_value=contract["label"],
                test_id="json-observation",
                observed={"seed": 7, "score": 42},
                command=["fixture.exe", "--json"],
                input_data={"seed": 7},
                evidence="json fixture result",
                fixture_path=result_path,
            )
            record_process_behavior_observation(
                conn,
                behavior_contract_label_value=contract["label"],
                test_id="usage-observation",
                observed={"returncode": 4, "stdout": "", "stderr": "usage\n", "timed_out": False},
                command=["fixture.exe"],
                input_data={"argv": []},
                evidence="process fixture result",
                fixture_path=result_path,
            )
            upsert_internal_routine_contract(
                conn,
                label="routine_entrypoint_behavior_v1",
                function_label=function_label,
                public_name="entrypoint_behavior_v1",
                purpose_summary="Computes a deterministic score from the supplied seed.",
                calling_convention="cdecl",
                signature="uint32 entrypoint(uint32 seed)",
                input_shape={"seed": "u32"},
                output_shape={"score": "u32"},
                preconditions=["seed is a 32-bit unsigned integer"],
                postconditions=["score is deterministic for a fixed seed"],
                side_effects=["writes a score line to stdout"],
                state_transitions=[],
                fixtures=["json-observation"],
                evidence_labels=["json-observation"],
                evidence_source="dynamic_observation",
                confidence="medium",
                taint_level="behavioral_public",
                review_status="draft",
            )
            record_oracle_test_case(
                conn,
                suite_id="client-startup",
                test_id="windowed",
                case_kind="black_box_process",
                evidence="startup process fixture",
                command="fixture.exe --windowed",
                fixture_path=result_path,
                trace_log=trace_path,
            )
            endpoint = upsert_platform_endpoint(
                conn,
                dll="kernel32.dll",
                symbol="GetTickCount",
                mock_status="complete",
                test_status="complete",
            )
            record_interface_test_case(
                conn,
                endpoint_label=endpoint["label"],
                case_kind="success",
                test_id="tick-count-success",
                evidence="mock returns monotonic tick count",
                fixture_path=result_path,
            )
            structure = upsert_data_structure(
                conn,
                name="settings",
                structure_kind="config",
                spec_status="specified",
                fixture_status="present",
                description="configuration fixture",
            )
            record_data_state_test_case(
                conn,
                data_structure_label_value=structure["label"],
                case_kind="fixture",
                test_id="settings-fixture",
                evidence="config fixture parses",
                fixture_path=result_path,
            )
            record_mutation_test_case(
                conn,
                mutation_kind="wrong_implementation",
                test_id="wrong-score",
                status="killed",
                evidence="score mismatch fails",
                command="mutant --wrong-score",
                fixture_path=result_path,
            )


if __name__ == "__main__":
    unittest.main()
