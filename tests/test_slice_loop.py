import contextlib
import io
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from wincr import slice_loop
from wincr.util import write_json


class SliceLoopTests(unittest.TestCase):
    def test_prepare_writes_workspace_manifest_and_caches_stage_a_feedback(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            stage_a_root = self._stage_a_check_root(root)
            candidate_dir = self._candidate_dir(root)

            with self._patched_prepare_contracts():
                code = self._run_main(
                    [
                        "--work-dir",
                        str(root / "work"),
                        "prepare",
                        "jq",
                        "--stage-a-check-root",
                        str(stage_a_root),
                        "--candidate-dir",
                        str(candidate_dir),
                    ]
                )

            self.assertEqual(code, 0)
            workspace = root / "work" / "jq"
            manifest = json.loads((workspace / "workspace.json").read_text(encoding="utf-8"))
            self.assertEqual(manifest["format"], slice_loop.WORKSPACE_FORMAT)
            self.assertEqual(manifest["policy"]["original_runtime_tracing"], False)
            self.assertTrue((workspace / "contracts" / "reference_contract.json").exists())
            self.assertTrue((workspace / "contracts" / "contract-smoke.json").exists())
            self.assertTrue((workspace / "contracts" / "semantic-coverage.json").exists())
            self.assertTrue((workspace / "contracts" / "work-items.json").exists())
            self.assertTrue((workspace / "packets" / "index.json").exists())
            self.assertTrue((workspace / "candidate" / "src" / "jq_stage_b_skeleton.c").exists())
            current = json.loads((workspace / "candidate" / "current-candidate.json").read_text(encoding="utf-8"))
            self.assertEqual(Path(current["candidate"]).name, "jq-stage-b-generated-closure-candidate.exe")
            packets = json.loads((workspace / "packets" / "index.json").read_text(encoding="utf-8"))
            self.assertEqual(packets["format"], slice_loop.SLICE_PACKET_INDEX_FORMAT)
            self.assertEqual(packets["counts"]["packets"], 4)
            self.assertEqual(packets["counts"]["by_pattern_family"]["source_progress_gap"], 2)
            self.assertEqual(packets["counts"]["by_pattern_family"]["section_gap_helper"], 1)
            packet = json.loads(Path(packets["packets"][0]["path"]).read_text(encoding="utf-8"))
            self.assertEqual(packet["format"], slice_loop.SLICE_PACKET_FORMAT)
            self.assertEqual(packet["function"]["instruction_evidence"]["status"], "full")
            self.assertEqual(packet["function"]["instruction_evidence"]["instructions"], 2)

    def test_next_lists_cached_work_items(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            stage_a_root = self._stage_a_check_root(root)
            candidate_dir = self._candidate_dir(root)

            with self._patched_prepare_contracts():
                self.assertEqual(
                    self._run_main(
                        [
                            "--work-dir",
                            str(root / "work"),
                            "prepare",
                            "jq",
                            "--stage-a-check-root",
                            str(stage_a_root),
                            "--candidate-dir",
                            str(candidate_dir),
                        ]
                    ),
                    0,
                )

            result = slice_loop.slice_next(target="jq", work_dir=root / "work", top_k=1)

            self.assertEqual(result["status"], "pass")
            self.assertEqual(result["counts"]["returned"], 1)
            self.assertEqual(result["items"][0]["id"], "semantic-region:selected")
            self.assertEqual(result["source_progress"]["status"], "available")
            self.assertEqual(result["source_progress"]["counts"]["concrete"], 1)
            self.assertEqual(result["source_progress"]["counts"]["placeholder"], 3)
            self.assertEqual(result["source_progress"]["counts"]["boundary"], 1)
            self.assertEqual(result["source_progress"]["counts"]["omitted"], 0)
            self.assertEqual(result["items"][0]["stage_b_source"]["function"], "selected")
            self.assertEqual(result["items"][0]["stage_b_source"]["source_kind"], "generated_contract_guided_leaf")
            self.assertEqual(result["items"][0]["stage_b_packet"]["pattern_family"], "leaf")
            self.assertTrue(Path(result["items"][0]["stage_b_packet"]["path"]).is_file())

    def test_next_can_filter_to_todo_source_progress(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            stage_a_root = self._stage_a_check_root(root)
            candidate_dir = self._candidate_dir(root)

            with self._patched_prepare_contracts():
                self.assertEqual(
                    self._run_main(
                        [
                            "--work-dir",
                            str(root / "work"),
                            "prepare",
                            "jq",
                            "--stage-a-check-root",
                            str(stage_a_root),
                            "--candidate-dir",
                            str(candidate_dir),
                        ]
                    ),
                    0,
                )
            work_items = root / "work" / "jq" / "contracts" / "work-items.json"
            write_json(
                work_items,
                {
                    "format": "stage-a-work-items-v1",
                    "status": "pass",
                    "work_items": [
                        {"id": "selected", "family": "semantic", "function": "selected"},
                        {"id": "printf", "family": "import_thunks", "function": "printf"},
                        {"id": "needs-work", "family": "semantic", "function": "needs_work"},
                    ],
                    "counts": {"work_items": 3},
                },
            )

            result = slice_loop.slice_next(target="jq", work_dir=root / "work", top_k=10, todo_only=True)

            self.assertEqual(result["counts"]["matched"], 3)
            self.assertEqual(
                [item["id"] for item in result["items"]],
                [
                    "needs-work",
                    "work:source-progress-gap:stage_b_contract_section_gap__text_0058:4000-4010",
                    "work:source-progress-gap:umain:5000-5100",
                ],
            )
            self.assertTrue(all(item["stage_b_source"]["progress_class"] == "placeholder" for item in result["items"]))

    def test_next_groups_todo_work_by_pattern_and_function(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            stage_a_root = self._stage_a_check_root(root)
            candidate_dir = self._candidate_dir(root)

            with self._patched_prepare_contracts():
                self.assertEqual(
                    self._run_main(
                        [
                            "--work-dir",
                            str(root / "work"),
                            "prepare",
                            "jq",
                            "--stage-a-check-root",
                            str(stage_a_root),
                            "--candidate-dir",
                            str(candidate_dir),
                        ]
                    ),
                    0,
                )
            work_items = root / "work" / "jq" / "contracts" / "work-items.json"
            write_json(
                work_items,
                {
                    "format": "stage-a-work-items-v1",
                    "status": "pass",
                    "work_items": [
                        {
                            "id": "work:cluster:function-pointer:callsite:umain-0000:24b4",
                            "family": "abi_callsites",
                            "original_function": "umain",
                            "repair_class": "function_pointer_target",
                        },
                        {
                            "id": "work:cluster:function-pointer:callsite:section-gap--text-0058:14e3",
                            "family": "abi_callsites",
                            "original_function": "section-gap--text-0058",
                            "repair_class": "function_pointer_target",
                        },
                    ],
                    "counts": {"work_items": 2},
                },
            )
            slice_loop._write_slice_packets(
                workspace=root / "work" / "jq",
                target="jq",
                work_items=json.loads(work_items.read_text(encoding="utf-8")),
                current_candidate=json.loads(
                    (root / "work" / "jq" / "candidate" / "current-candidate.json").read_text(encoding="utf-8")
                ),
                source_anchors=slice_loop._slice_source_progress(
                    root / "work" / "jq",
                    json.loads((root / "work" / "jq" / "candidate" / "current-candidate.json").read_text(encoding="utf-8")),
                    json.loads((root / "work" / "jq" / "workspace.json").read_text(encoding="utf-8")),
                )[1],
            )

            by_pattern = slice_loop.slice_next(
                target="jq",
                work_dir=root / "work",
                top_k=10,
                todo_only=True,
                group_by="pattern",
            )
            by_function = slice_loop.slice_next(
                target="jq",
                work_dir=root / "work",
                top_k=10,
                todo_only=True,
                group_by="function",
            )

            self.assertEqual(
                {item["key"] for item in by_pattern["groups"]},
                {"application_dispatch", "section_gap_helper", "source_progress_gap"},
            )
            self.assertEqual(
                {item["key"] for item in by_function["groups"]},
                {"needs_work", "umain", "stage_b_contract_section_gap__text_0058"},
            )

    def test_prepare_can_cache_source_only_skeleton_for_next_progress(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            stage_a_root = self._stage_a_check_root(root)
            skeleton_root = self._skeleton_root(root)

            with self._patched_prepare_contracts():
                code = self._run_main(
                    [
                        "--work-dir",
                        str(root / "work"),
                        "prepare",
                        "jq",
                        "--stage-a-check-root",
                        str(stage_a_root),
                        "--skeleton-root",
                        str(skeleton_root),
                    ]
                )

            self.assertEqual(code, 0)
            workspace = root / "work" / "jq"
            current = json.loads((workspace / "candidate" / "current-candidate.json").read_text(encoding="utf-8"))
            self.assertEqual(current["source"], "prepared-skeleton-root")
            self.assertTrue((workspace / "candidate" / "src" / "jq_stage_b_skeleton.c").exists())

            result = slice_loop.slice_next(target="jq", work_dir=root / "work", top_k=1)

            self.assertEqual(result["source_progress"]["status"], "available")
            self.assertEqual(result["source_progress"]["counts"]["concrete"], 1)
            self.assertEqual(result["source_progress"]["counts"]["placeholder"], 3)
            self.assertEqual(result["source_progress"]["counts"]["boundary"], 1)
            self.assertEqual(result["items"][0]["stage_b_source"]["progress_class"], "concrete")

    def test_build_command_updates_current_candidate(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            workspace = self._prepared_workspace(root)
            script = (
                "import json, os; "
                "from pathlib import Path; "
                "out=Path(os.environ['WINCR_SLICE_OUT_DIR']); out.mkdir(parents=True, exist_ok=True); "
                "(out/'jq-stage-b-generated-closure-candidate.exe').write_bytes(b'candidate'); "
                "(out/'jq-stage-b-generated-closure-candidate.map').write_text('map', encoding='utf-8'); "
                "(out/'skeleton-manifest.json').write_text(json.dumps({'format':'stage-b-skeleton-v1'}), encoding='utf-8'); "
                "(out/'decompiled-c-generated-closure-link-report.json').write_text(json.dumps({'format':'stage-b-decompiled-c-link-diagnostic-v1'}), encoding='utf-8')"
            )

            code = self._run_main(
                [
                    "--work-dir",
                    str(root / "work"),
                    "build",
                    "jq",
                    "--region",
                    "selected",
                    "--command-json",
                    json.dumps([sys.executable, "-c", script]),
                ]
            )

            self.assertEqual(code, 0)
            current = json.loads((workspace / "candidate" / "current-candidate.json").read_text(encoding="utf-8"))
            self.assertEqual(current["source"], "local-build")
            self.assertEqual(Path(current["candidate"]).parent, workspace / "candidate" / "out")
            self.assertTrue(Path(current["candidate"]).exists())
            self.assertTrue((workspace / "builds" / "selected" / "current" / "build.json").exists())

    def test_check_exits_before_delta_when_contract_smoke_fails(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self._prepared_workspace(root)

            def smoke_failure(*, reference_contract, out):
                payload = {"format": "stage-a-contract-smoke-v1", "status": "incomplete", "counts": {"issues": 1}}
                write_json(out, payload)
                return payload

            with patch("wincr.slice_loop.stage_a_smoke_contract", side_effect=smoke_failure), patch(
                "wincr.slice_loop.stage_b_explain_delta"
            ) as explain:
                code = self._run_main(
                    [
                        "--work-dir",
                        str(root / "work"),
                        "check",
                        "jq",
                        "--region",
                        "selected",
                        "--json",
                    ]
                )

            self.assertEqual(code, 1)
            explain.assert_not_called()
            report = json.loads(
                (root / "work" / "jq" / "checks" / "selected" / "fast" / "wincr-slice-check.json").read_text(
                    encoding="utf-8"
                )
            )
            self.assertTrue(report["early_exit"])
            self.assertEqual(report["issues"][0]["category"], "contract_smoke_failed")

    def test_focused_check_passes_when_global_delta_has_only_unrelated_items(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self._prepared_workspace(root)

            with patch("wincr.slice_loop.stage_a_smoke_contract", side_effect=self._smoke_pass), patch(
                "wincr.slice_loop.stage_a_validate_contract_candidate", side_effect=self._contract_candidate_validation
            ) as validate_candidate, patch(
                "wincr.slice_loop.stage_a_validate_unit", side_effect=self._unit_incomplete
            ) as validate_unit, patch("wincr.slice_loop.stage_b_explain_delta", side_effect=self._unrelated_delta) as explain:
                code = self._run_main(
                    [
                        "--work-dir",
                        str(root / "work"),
                        "check",
                        "jq",
                        "--region",
                        "selected",
                        "--json",
                    ]
                )

            self.assertEqual(code, 0)
            self.assertEqual(validate_candidate.call_count, 1)
            self.assertTrue(Path(validate_unit.call_args.kwargs["contract_candidate_validation"]).is_file())
            self.assertTrue(explain.call_args.kwargs["focused_only"])
            focused = json.loads(
                (root / "work" / "jq" / "checks" / "selected" / "fast" / "focused-delta.json").read_text(
                    encoding="utf-8"
                )
            )
            self.assertEqual(focused["status"], "pass")
            self.assertEqual(focused["counts"]["repair_items"], 0)
            report = json.loads(
                (root / "work" / "jq" / "checks" / "selected" / "fast" / "wincr-slice-check.json").read_text(
                    encoding="utf-8"
                )
            )
            self.assertEqual(report["contract_candidate_validation"]["cache"]["status"], "miss")

    def test_check_reuses_contract_candidate_validation_cache_and_invalidates_on_candidate_change(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self._prepared_workspace(root)
            candidate = root / "candidate" / "jq-stage-b-generated-closure-candidate.exe"

            with patch("wincr.slice_loop.stage_a_smoke_contract", side_effect=self._smoke_pass), patch(
                "wincr.slice_loop.stage_a_validate_contract_candidate", side_effect=self._contract_candidate_validation
            ) as validate_candidate, patch(
                "wincr.slice_loop.stage_a_validate_unit", side_effect=self._unit_incomplete
            ), patch("wincr.slice_loop.stage_b_explain_delta", side_effect=self._unrelated_delta):
                self.assertEqual(
                    self._run_main(
                        [
                            "--work-dir",
                            str(root / "work"),
                            "check",
                            "jq",
                            "--region",
                            "selected",
                            "--json",
                        ]
                    ),
                    0,
                )
                self.assertEqual(
                    self._run_main(
                        [
                            "--work-dir",
                            str(root / "work"),
                            "check",
                            "jq",
                            "--region",
                            "selected",
                            "--json",
                        ]
                    ),
                    0,
                )
                candidate.write_bytes(b"changed candidate")
                self.assertEqual(
                    self._run_main(
                        [
                            "--work-dir",
                            str(root / "work"),
                            "check",
                            "jq",
                            "--region",
                            "selected",
                            "--json",
                        ]
                    ),
                    0,
                )

            self.assertEqual(validate_candidate.call_count, 2)
            report = json.loads(
                (root / "work" / "jq" / "checks" / "selected" / "fast" / "wincr-slice-check.json").read_text(
                    encoding="utf-8"
                )
            )
            self.assertEqual(report["contract_candidate_validation"]["cache"]["status"], "miss")

    def test_skip_delta_still_runs_contract_candidate_validation(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self._prepared_workspace(root)

            with patch("wincr.slice_loop.stage_a_smoke_contract", side_effect=self._smoke_pass), patch(
                "wincr.slice_loop.stage_a_validate_contract_candidate", side_effect=self._contract_candidate_validation
            ) as validate_candidate, patch("wincr.slice_loop.stage_b_explain_delta") as explain:
                code = self._run_main(
                    [
                        "--work-dir",
                        str(root / "work"),
                        "check",
                        "jq",
                        "--skip-delta",
                        "--json",
                    ]
                )

            self.assertEqual(code, 1)
            self.assertEqual(validate_candidate.call_count, 1)
            explain.assert_not_called()
            report = json.loads(
                (root / "work" / "jq" / "checks" / "all" / "fast" / "wincr-slice-check.json").read_text(
                    encoding="utf-8"
                )
            )
            self.assertEqual(report["contract_candidate_validation"]["cache"]["status"], "miss")
            self.assertNotIn("stage_b_delta", report["artifacts"])

    def test_copytree_force_replaces_read_only_cached_source(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source_a = root / "source-a"
            source_b = root / "source-b"
            dest = root / "dest"
            source_a.mkdir()
            source_b.mkdir()
            (source_a / "slice.c").write_text("old\n", encoding="utf-8")
            (source_b / "slice.c").write_text("new\n", encoding="utf-8")

            slice_loop._copytree_once(source_a, dest)
            (dest / "slice.c").chmod(0o400)
            dest.chmod(0o500)

            slice_loop._copytree_once(source_b, dest, force=True)

            self.assertEqual((dest / "slice.c").read_text(encoding="utf-8"), "new\n")
            self.assertTrue(dest.stat().st_mode & 0o200)
            self.assertTrue((dest / "slice.c").stat().st_mode & 0o200)

    def test_link_or_copy_same_path_is_noop(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            contract = root / "reference_contract.json"
            contract.write_text('{"format":"stage-a-reference-contract-v1"}\n', encoding="utf-8")

            slice_loop._link_or_copy(contract, contract)

            self.assertTrue(contract.is_file())
            self.assertFalse(contract.is_symlink())
            self.assertEqual(contract.read_text(encoding="utf-8"), '{"format":"stage-a-reference-contract-v1"}\n')

    def _run_main(self, argv):
        with contextlib.redirect_stdout(io.StringIO()):
            return slice_loop.main(argv)

    def _stage_a_check_root(self, root: Path) -> Path:
        stage_a_root = root / "stage-a-check"
        generated = stage_a_root / "generated"
        generated.mkdir(parents=True)
        write_json(
            generated / "jq-reference-contract.json",
            {"format": "stage-a-reference-contract-v1", "status": "pass", "families": []},
        )
        return stage_a_root

    def _candidate_dir(self, root: Path) -> Path:
        candidate_dir = root / "candidate"
        (candidate_dir / "src").mkdir(parents=True)
        (candidate_dir / "jq-stage-b-generated-closure-candidate.exe").write_bytes(b"candidate")
        (candidate_dir / "jq-stage-b-generated-closure-candidate.map").write_text("map", encoding="utf-8")
        write_json(
            candidate_dir / "skeleton-manifest.json",
            {
                "format": "stage-b-skeleton-v1",
                "target_name": "jq",
                "implementation_mode": "contract-guided-c",
                "source_map": {
                    "format": "stage-b-source-map-v1",
                    "source": "src/jq_stage_b_skeleton.c",
                    "functions": [
                        {
                            "function": "selected",
                            "aliases": ["semantic-region:selected"],
                            "file": "src/jq_stage_b_skeleton.c",
                            "line_start": 1,
                            "line_end": 1,
                            "source_kind": "generated_contract_guided_leaf",
                            "rva_start": 0x1000,
                            "rva_end": 0x1003,
                        },
                        {
                            "function": "printf",
                            "aliases": ["_printf"],
                            "file": "src/jq_stage_b_skeleton.c",
                            "line_start": 2,
                            "line_end": 2,
                            "source_kind": "omitted_import_thunk",
                            "rva_start": 0x2000,
                            "rva_end": 0x2006,
                        },
                        {
                            "function": "needs_work",
                            "aliases": ["semantic-region:needs-work"],
                            "file": "src/jq_stage_b_skeleton.c",
                            "line_start": 3,
                            "line_end": 3,
                            "source_kind": "generated_contract_placeholder",
                            "rva_start": 0x3000,
                            "rva_end": 0x3010,
                        },
                        {
                            "function": "stage_b_contract_section_gap__text_0058",
                            "aliases": ["section-gap--text-0058"],
                            "file": "src/jq_stage_b_skeleton.c",
                            "line_start": 4,
                            "line_end": 4,
                            "source_kind": "generated_contract_placeholder_from_section_gap",
                            "rva_start": 0x4000,
                            "rva_end": 0x4010,
                        },
                        {
                            "function": "umain",
                            "aliases": ["umain"],
                            "file": "src/jq_stage_b_skeleton.c",
                            "line_start": 5,
                            "line_end": 5,
                            "source_kind": "generated_contract_placeholder",
                            "rva_start": 0x5000,
                            "rva_end": 0x5100,
                        }
                    ],
                },
            },
        )
        write_json(candidate_dir / "candidate-provenance.json", {"format": "stage-b-candidate-provenance-v1"})
        write_json(candidate_dir / "decompiled-c-generated-closure-link-report.json", {"format": "stage-b-link-report-v1"})
        write_json(
            candidate_dir / "functions.json",
            {
                "format": "stage-b-functions-v1",
                "functions": self._fixture_functions(),
            },
        )
        (candidate_dir / "src" / "jq_stage_b_skeleton.c").write_text("int main(void) { return 0; }\n", encoding="utf-8")
        (candidate_dir / "libjq-1.dll").write_bytes(b"dll")
        (candidate_dir / "libjq-1.generated-closure.link.map").write_text("map", encoding="utf-8")
        write_json(candidate_dir / "libjq-1-skeleton-manifest.json", {"format": "stage-b-skeleton-v1"})
        return candidate_dir

    def _skeleton_root(self, root: Path) -> Path:
        skeleton_root = root / "skeleton"
        (skeleton_root / "src").mkdir(parents=True)
        (skeleton_root / "src" / "jq_stage_b_skeleton.c").write_text("int main(void) { return 0; }\n", encoding="utf-8")
        write_json(
            skeleton_root / "manifest.json",
            {
                "format": "stage-b-skeleton-v1",
                "target_name": "jq",
                "implementation_mode": "contract-guided-c",
                "source_map": {
                    "format": "stage-b-source-map-v1",
                    "source": "src/jq_stage_b_skeleton.c",
                    "functions": [
                        {
                            "function": "selected",
                            "aliases": ["semantic-region:selected"],
                            "file": "src/jq_stage_b_skeleton.c",
                            "line_start": 1,
                            "line_end": 1,
                            "source_kind": "generated_contract_guided_leaf",
                            "rva_start": 0x1000,
                            "rva_end": 0x1003,
                        },
                        {
                            "function": "printf",
                            "aliases": ["_printf"],
                            "file": "src/jq_stage_b_skeleton.c",
                            "line_start": 2,
                            "line_end": 2,
                            "source_kind": "omitted_import_thunk",
                            "rva_start": 0x2000,
                            "rva_end": 0x2006,
                        },
                        {
                            "function": "needs_work",
                            "aliases": ["semantic-region:needs-work"],
                            "file": "src/jq_stage_b_skeleton.c",
                            "line_start": 3,
                            "line_end": 3,
                            "source_kind": "generated_contract_placeholder",
                            "rva_start": 0x3000,
                            "rva_end": 0x3010,
                        },
                        {
                            "function": "stage_b_contract_section_gap__text_0058",
                            "aliases": ["section-gap--text-0058"],
                            "file": "src/jq_stage_b_skeleton.c",
                            "line_start": 4,
                            "line_end": 4,
                            "source_kind": "generated_contract_placeholder_from_section_gap",
                            "rva_start": 0x4000,
                            "rva_end": 0x4010,
                        },
                        {
                            "function": "umain",
                            "aliases": ["umain"],
                            "file": "src/jq_stage_b_skeleton.c",
                            "line_start": 5,
                            "line_end": 5,
                            "source_kind": "generated_contract_placeholder",
                            "rva_start": 0x5000,
                            "rva_end": 0x5100,
                        }
                    ],
                },
            },
        )
        write_json(skeleton_root / "functions.json", {"format": "stage-b-functions-v1", "functions": self._fixture_functions()})
        return skeleton_root

    def _fixture_functions(self):
        return [
            {
                "id": "selected",
                "name": "selected",
                "aliases": ["semantic-region:selected"],
                "section": ".text",
                "rva_start": 0x1000,
                "rva_end": 0x1003,
                "size": 3,
                "bytes_sha256": "selected-sha",
                "decode_complete": True,
                "decoded_bytes": 3,
                "instruction_count": 2,
                "direct_cfg_edges": [],
                "instructions": [
                    {"rva": 0x1000, "size": 1, "mnemonic": "xor", "op_str": "eax, eax"},
                    {"rva": 0x1001, "size": 1, "mnemonic": "ret", "op_str": ""},
                ],
                "instruction_preview": [
                    {"rva": 0x1000, "size": 1, "mnemonic": "xor", "op_str": "eax, eax"},
                    {"rva": 0x1001, "size": 1, "mnemonic": "ret", "op_str": ""},
                ],
                "reference_contract": {"abi_callsites": []},
            },
            {
                "id": "needs_work",
                "name": "needs_work",
                "aliases": ["semantic-region:needs-work"],
                "section": ".text",
                "rva_start": 0x3000,
                "rva_end": 0x3010,
                "size": 0x10,
                "instruction_count": 1,
                "instructions": [{"rva": 0x3000, "size": 1, "mnemonic": "call", "op_str": "eax"}],
                "instruction_preview": [{"rva": 0x3000, "size": 1, "mnemonic": "call", "op_str": "eax"}],
            },
            {
                "id": "stage_b_contract_section_gap__text_0058",
                "name": "stage_b_contract_section_gap__text_0058",
                "aliases": ["section-gap--text-0058"],
                "section": ".text",
                "rva_start": 0x4000,
                "rva_end": 0x4010,
                "size": 0x10,
                "instruction_count": 1,
                "instructions": [{"rva": 0x4000, "size": 1, "mnemonic": "call", "op_str": "eax"}],
                "instruction_preview": [{"rva": 0x4000, "size": 1, "mnemonic": "call", "op_str": "eax"}],
            },
            {
                "id": "umain",
                "name": "umain",
                "aliases": ["umain"],
                "section": ".text",
                "rva_start": 0x5000,
                "rva_end": 0x5100,
                "size": 0x100,
                "instruction_count": 1,
                "instructions": [{"rva": 0x5000, "size": 1, "mnemonic": "call", "op_str": "eax"}],
                "instruction_preview": [{"rva": 0x5000, "size": 1, "mnemonic": "call", "op_str": "eax"}],
            },
        ]

    def _prepared_workspace(self, root: Path) -> Path:
        workspace = root / "work" / "jq"
        (workspace / "contracts").mkdir(parents=True)
        (workspace / "candidate").mkdir(parents=True)
        ref = workspace / "contracts" / "reference_contract.json"
        write_json(ref, {"format": "stage-a-reference-contract-v1", "status": "pass", "families": []})
        candidate = self._candidate_dir(root)
        current = slice_loop._candidate_artifacts(candidate, slice_loop.TARGET_DEFAULTS["jq"])
        write_json(workspace / "candidate" / "current-candidate.json", current)
        write_json(
            workspace / "workspace.json",
            {
                "format": slice_loop.WORKSPACE_FORMAT,
                "target": "jq",
                "cached": {"reference_contract": str(ref), "unit_contract_dir": None},
                "build": {"target": "i686-w64-mingw32", "compiler": "i686-w64-mingw32-cc"},
                "target_closure_manifest": None,
            },
        )
        return workspace

    def _patched_prepare_contracts(self):
        return _PatchGroup(
            patch("wincr.slice_loop.stage_a_smoke_contract", side_effect=self._smoke_pass),
            patch("wincr.slice_loop.stage_a_semantic_coverage", side_effect=self._semantic_incomplete),
            patch("wincr.slice_loop.stage_a_extract_work_items", side_effect=self._work_items),
        )

    def _smoke_pass(self, *, reference_contract, out):
        payload = {"format": "stage-a-contract-smoke-v1", "status": "pass", "counts": {"issues": 0}}
        write_json(out, payload)
        return payload

    def _semantic_incomplete(self, *, reference_contract, unit_contract_dir=None, out):
        payload = {
            "format": "stage-a-semantic-coverage-v1",
            "status": "incomplete",
            "next_work": [{"id": "semantic-region:selected", "family": "semantic"}],
            "counts": {},
        }
        write_json(out, payload)
        return payload

    def _work_items(self, *, reference_contract, unit_contract_dir=None, out):
        payload = {
            "format": "stage-a-work-items-v1",
            "status": "pass",
            "work_items": [
                {
                    "id": "semantic-region:selected",
                    "family": "semantic",
                    "function": "selected",
                    "repair_class": "region_contract",
                    "next_action": "repair selected region",
                }
            ],
            "counts": {"work_items": 1},
        }
        write_json(out, payload)
        return payload

    def _contract_candidate_validation(self, **kwargs):
        out = Path(kwargs["out"])
        payload = {
            "format": "stage-a-contract-candidate-validation-v1",
            "status": "incomplete",
            "verdict": "incomplete",
            "families": [],
            "issues": [],
            "counts": {"families": 0, "issues": 0, "candidate_functions": 0},
        }
        write_json(out / "verdict.json", payload)
        write_json(out / "contract-candidate.json", payload)
        return payload

    def _unit_incomplete(self, **kwargs):
        validation = kwargs["contract_candidate_validation"]
        if isinstance(validation, (str, Path)):
            self.assertTrue(Path(validation).is_file())
        else:
            self.assertEqual(validation["format"], "stage-a-contract-candidate-validation-v1")
        out = Path(kwargs["out"])
        payload = {"format": "stage-a-unit-validation-v1", "status": "incomplete", "counts": {"unit_contracts": 1}}
        write_json(out / "unit-validation.json", payload)
        return payload

    def _unrelated_delta(self, **kwargs):
        validation = kwargs["contract_candidate_validation"]
        if isinstance(validation, (str, Path)):
            self.assertTrue(Path(validation).is_file())
        else:
            self.assertEqual(validation["format"], "stage-a-contract-candidate-validation-v1")
        out = Path(kwargs["out"])
        payload = {
            "format": "stage-b-delta-explanation-v1",
            "status": "incomplete",
            "scope": "focused" if kwargs.get("focused_only") else "full",
            "repair_items": [
                {
                    "id": "repair:unrelated",
                    "violated_contract_family": "cfg",
                    "likely_repair_class": "unrelated",
                    "concrete_next_action": "repair a different region",
                }
            ],
            "counts": {"repair_items": 1},
        }
        write_json(out / "stage-b-delta.json", payload)
        return payload


class _PatchGroup:
    def __init__(self, *patches):
        self._patches = patches
        self._started = []

    def __enter__(self):
        for item in self._patches:
            self._started.append(item.__enter__())
        return self

    def __exit__(self, exc_type, exc, tb):
        while self._patches:
            self._patches[-1].__exit__(exc_type, exc, tb)
            self._patches = self._patches[:-1]
        return False


if __name__ == "__main__":
    unittest.main()
