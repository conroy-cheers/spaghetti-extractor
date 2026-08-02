from __future__ import annotations

import copy
import json
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

from spaghetti_extractor.region_replacement import (
    REGION_OBSERVATIONS_FORMAT,
    REGION_OVERRIDE_TABLE_FORMAT,
    REGION_REPLACEMENT_FORMAT,
    REGION_REPLACEMENT_VALIDATION_FORMAT,
    generate_region_override_table,
    load_region_replacement_manifest,
    validate_region_replacement,
    write_region_replacement_manifest,
)
from spaghetti_extractor.stage_binary import StageAInputError
from spaghetti_extractor.util import sha256_file


SHA = {
    "machine": "1" * 64,
    "baseline": "2" * 64,
    "cluster": "3" * 64,
    "evidence": "4" * 64,
}


def _source(root: Path, name: str = "replacement.c", symbol: str = "replace_loop") -> Path:
    path = root / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        '#include "state-machine-runtime.h"\n'
        f"stage_b_step_result {symbol}(stage_b_runtime *rt, stage_b_machine_state *state) {{\n"
        "  (void)rt;\n"
        "  state->eax += 1U;\n"
        "  return (stage_b_step_result){ STAGE_B_RETURN, 0U, state->eax };\n"
        "}\n",
        encoding="utf-8",
    )
    return path


def _manifest_payload(
    root: Path,
    *,
    replacement_id: str = "replace-loop",
    cluster_id: str = "cluster:loop",
    entry_unit: str = "unit:1000",
    entry_rva: int = 0x1000,
    rva_end: int = 0x1020,
    source_name: str = "replacement.c",
    symbol: str = "replace_loop",
    evidence_status: str = "qualified",
) -> dict:
    source = root / source_name
    evidence_ids = ["evidence:cluster"]
    return {
        "format": REGION_REPLACEMENT_FORMAT,
        "id": replacement_id,
        "bindings": {
            "machine_ir_sha256": SHA["machine"],
            "baseline_program_sha256": SHA["baseline"],
            "cluster_contract_sha256": SHA["cluster"],
        },
        "cluster": {
            "id": cluster_id,
            "entry_unit_id": entry_unit,
            "entry_rva": entry_rva,
            "unit_ids": [f"unit:{entry_rva + 8:x}", entry_unit],
            "rva_spans": [{"start": entry_rva, "end": rva_end}],
        },
        "source": {
            "path": source_name,
            "sha256": sha256_file(source),
            "symbol": symbol,
            "line_start": 2,
            "line_end": 6,
        },
        "abi": {
            "calling_convention": "machine_state",
            "stack_delta": 0,
            "parameters": [
                {
                    "id": "abi:input-buffer",
                    "ordinal": 0,
                    "name": "input_buffer",
                    "c_type": "const uint8_t *",
                    "direction": "in",
                    "location": "esi",
                    "width_bits": 32,
                    "evidence_ids": evidence_ids,
                }
            ],
            "results": [
                {
                    "id": "abi:result",
                    "name": "result",
                    "c_type": "uint32_t",
                    "location": "eax",
                    "width_bits": 32,
                    "evidence_ids": evidence_ids,
                }
            ],
            "preserved_registers": ["ebx", "ebp"],
            "clobbered_registers": ["eax", "ecx"],
            "evidence_ids": evidence_ids,
        },
        "type_hypotheses": [
            {
                "id": "type:buffer",
                "subject": "esi and memory:view-buffer",
                "c_type": "const uint8_t *",
                "basis": "inferred",
                "evidence_ids": evidence_ids,
            }
        ],
        "live_state": {
            "inputs": [
                {
                    "id": "live:esi",
                    "kind": "register",
                    "location": "esi",
                    "width_bits": 32,
                    "encoding": "uint32",
                    "evidence_ids": evidence_ids,
                }
            ],
            "outputs": [
                {
                    "id": "live:eax",
                    "kind": "register",
                    "location": "eax",
                    "width_bits": 32,
                    "encoding": "uint32",
                    "evidence_ids": evidence_ids,
                },
                {
                    "id": "live:zf",
                    "kind": "flag",
                    "location": "zf",
                    "width_bits": 1,
                    "encoding": "bit",
                    "evidence_ids": evidence_ids,
                },
            ],
        },
        "memory_views": [
            {
                "id": "view:buffer",
                "base_expression": "input.esi",
                "byte_length": 4,
                "length_expression": None,
                "access": "read_write",
                "representation": "opaque bytes",
                "evidence_ids": evidence_ids,
            }
        ],
        "expectations": {
            "control": [
                {
                    "id": "exit:return",
                    "kind": "return",
                    "target_unit_ids": [],
                    "target_rvas": [],
                    "evidence_ids": evidence_ids,
                }
            ],
            "fault": {"allow_none": True, "variants": []},
            "external_events": [
                {
                    "id": "event:write-file",
                    "kind": "import_call",
                    "identity": "kernel32.dll!WriteFile",
                    "evidence_ids": evidence_ids,
                }
            ],
        },
        "evidence": [
            {
                "id": "evidence:cluster",
                "class": "differential",
                "status": evidence_status,
                "artifact_sha256": SHA["evidence"],
                "detail": "candidate-only generated vectors cover the cluster boundary",
            }
        ],
    }


def _write_manifest(root: Path, **updates):
    source_name = updates.get("source_name", "replacement.c")
    symbol = updates.get("symbol", "replace_loop")
    _source(root, source_name, symbol)
    payload = _manifest_payload(root, **updates)
    path = root / f"{payload['id'].replace(':', '-')}.json"
    manifest = write_region_replacement_manifest(path, payload, source_root=root)
    return path, manifest


def _observations(manifest_sha256: str) -> dict:
    return {
        "format": REGION_OBSERVATIONS_FORMAT,
        "manifest_sha256": manifest_sha256,
        "cases": [
            {
                "id": "case:one",
                "entry_unit_id": "unit:1000",
                "live_inputs": [{"id": "live:esi", "value": 0x70001000}],
                "live_outputs": [
                    {"id": "live:zf", "value": False},
                    {
                        "id": "live:eax",
                        "value": {"defined": True, "bits": "0000002a"},
                    },
                ],
                "memory_views": [
                    {
                        "id": "view:buffer",
                        "base": 0x70001000,
                        "before": "01020304",
                        "after": "0102ff04",
                    }
                ],
                "control": {
                    "id": "exit:return",
                    "kind": "return",
                    "target_unit_id": None,
                    "target_rva": None,
                    "value": 42,
                },
                "fault": None,
                "external_events": [
                    {
                        "id": "event:write-file",
                        "kind": "import_call",
                        "identity": "kernel32.dll!WriteFile",
                        "arguments": [1, {"bytes": "6869"}, 2],
                        "memory_reads": [{"address": 0x70001000, "bytes": "6869"}],
                        "result": {"eax": 1},
                        "memory_writes": [{"address": 0x70001010, "bytes": "02000000"}],
                        "callbacks": [],
                    }
                ],
            }
        ],
    }


class RegionReplacementTests(unittest.TestCase):
    def test_manifest_is_canonical_self_bound_and_source_verified(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            path, manifest = _write_manifest(root)

            loaded = load_region_replacement_manifest(path, source_root=root)

            self.assertEqual(loaded.manifest_sha256, manifest.manifest_sha256)
            self.assertEqual(loaded.cluster["unit_ids"], ["unit:1000", "unit:1008"])
            self.assertRegex(loaded.manifest_sha256, r"^[0-9a-f]{64}$")
            persisted = json.loads(path.read_text(encoding="utf-8"))
            self.assertEqual(persisted, loaded.to_payload())
            self.assertNotIn("original", json.dumps(persisted).lower())

            root.joinpath("replacement.c").write_text("tampered\n", encoding="utf-8")
            with self.assertRaisesRegex(StageAInputError, "source hash"):
                load_region_replacement_manifest(path, source_root=root)

    def test_manifest_rejects_bad_hash_unknown_evidence_and_overlapping_spans(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            path, _manifest = _write_manifest(root)
            payload = json.loads(path.read_text(encoding="utf-8"))

            bad_hash = copy.deepcopy(payload)
            bad_hash["source"]["symbol"] = "different_symbol"
            bad_hash_path = root / "bad-hash.json"
            bad_hash_path.write_text(json.dumps(bad_hash), encoding="utf-8")
            with self.assertRaisesRegex(StageAInputError, "manifest hash"):
                load_region_replacement_manifest(
                    bad_hash_path, source_root=root
                )

            unknown = _manifest_payload(root)
            unknown["live_state"]["outputs"][0]["evidence_ids"] = ["evidence:missing"]
            with self.assertRaisesRegex(StageAInputError, "unknown evidence"):
                write_region_replacement_manifest(
                    root / "unknown.json", unknown, source_root=root
                )

            overlap = _manifest_payload(root)
            overlap["cluster"]["rva_spans"].append(
                {"start": 0x1010, "end": 0x1030}
            )
            with self.assertRaisesRegex(StageAInputError, "overlapping RVA"):
                write_region_replacement_manifest(
                    root / "overlap.json", overlap, source_root=root
                )

            wrong_format = _manifest_payload(root)
            wrong_format["format"] = "stage-b-region-replacement-v0"
            with self.assertRaisesRegex(StageAInputError, "must use"):
                write_region_replacement_manifest(
                    root / "wrong-format.json", wrong_format, source_root=root
                )

            wrong_symbol = _manifest_payload(root)
            wrong_symbol["source"]["symbol"] = "symbol_not_in_declared_lines"
            with self.assertRaisesRegex(StageAInputError, "outside its declared"):
                write_region_replacement_manifest(
                    root / "wrong-symbol.json", wrong_symbol, source_root=root
                )

            symlink = root / "replacement-link.c"
            symlink.symlink_to(root / "replacement.c")
            symlinked = _manifest_payload(root)
            symlinked["source"]["path"] = symlink.name
            with self.assertRaisesRegex(StageAInputError, "non-symlink"):
                write_region_replacement_manifest(
                    root / "symlinked.json", symlinked, source_root=root
                )

    def test_identical_candidate_only_observations_qualify(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            path, manifest = _write_manifest(root)
            baseline = _observations(manifest.manifest_sha256)
            replacement = copy.deepcopy(baseline)
            report_path = root / "validation.json"

            report = validate_region_replacement(
                manifest=path,
                baseline_observations=baseline,
                replacement_observations=replacement,
                source_root=root,
                out=report_path,
            )

            self.assertEqual(report["format"], REGION_REPLACEMENT_VALIDATION_FORMAT)
            self.assertEqual(report["status"], "qualified")
            self.assertEqual(report["counts"], {
                "compared_cases": 1,
                "deltas": 0,
                "violated": 0,
                "incomplete": 0,
            })
            self.assertFalse(report["executes_original_binary"])
            self.assertEqual(json.loads(report_path.read_text(encoding="utf-8")), report)

    def test_semantic_mismatches_are_violated_and_precisely_source_mapped(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            path, manifest = _write_manifest(root)
            baseline = _observations(manifest.manifest_sha256)
            replacement = copy.deepcopy(baseline)
            case = replacement["cases"][0]
            case["live_outputs"][1]["value"]["bits"] = "0000002b"
            case["memory_views"][0]["after"] = "0102aa04"
            case["control"]["value"] = 43
            case["external_events"][0]["arguments"][2] = 3

            first = validate_region_replacement(
                manifest=path,
                baseline_observations=baseline,
                replacement_observations=replacement,
                source_root=root,
            )
            second = validate_region_replacement(
                manifest=path,
                baseline_observations=baseline,
                replacement_observations=replacement,
                source_root=root,
            )

            self.assertEqual(first, second)
            self.assertEqual(first["status"], "violated")
            families = {delta["family"] for delta in first["deltas"]}
            self.assertTrue(
                {"live_output", "memory_output", "control", "external_event"}
                <= families
            )
            output_delta = next(
                delta for delta in first["deltas"]
                if delta["family"] == "live_output"
            )
            self.assertEqual(output_delta["case_id"], "case:one")
            self.assertEqual(output_delta["expected"], "0000002a")
            self.assertEqual(output_delta["observed"], "0000002b")
            self.assertEqual(output_delta["location"]["cluster_id"], "cluster:loop")
            self.assertEqual(output_delta["location"]["source"], {
                "path": "replacement.c",
                "symbol": "replace_loop",
                "line_start": 2,
                "line_end": 6,
            })
            self.assertRegex(output_delta["id"], r"^region-delta-[0-9a-f]{20}$")
            memory_delta = next(
                delta for delta in first["deltas"]
                if delta["family"] == "memory_output"
            )
            self.assertEqual(memory_delta["path"], "/memory_views/view:buffer/after/2")
            self.assertEqual(memory_delta["expected"], "ff")
            self.assertEqual(memory_delta["observed"], "aa")

    def test_input_drift_missing_case_and_incomplete_evidence_fail_incomplete(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            path, manifest = _write_manifest(root, evidence_status="incomplete")
            baseline = _observations(manifest.manifest_sha256)
            replacement = copy.deepcopy(baseline)
            replacement["cases"][0]["live_inputs"][0]["value"] += 4
            replacement["cases"][0]["memory_views"][0]["before"] = "00000000"

            report = validate_region_replacement(
                manifest=path,
                baseline_observations=baseline,
                replacement_observations=replacement,
                source_root=root,
            )

            self.assertEqual(report["status"], "incomplete")
            self.assertEqual(
                {delta["family"] for delta in report["deltas"]},
                {"evidence", "live_input", "memory_input"},
            )
            self.assertTrue(all(delta["status"] == "incomplete" for delta in report["deltas"]))

            replacement["cases"] = []
            missing = validate_region_replacement(
                manifest=path,
                baseline_observations=baseline,
                replacement_observations=replacement,
                source_root=root,
            )
            self.assertEqual(missing["status"], "incomplete")
            self.assertIn("case_inventory", {item["family"] for item in missing["deltas"]})

    def test_malformed_or_wrongly_bound_observations_report_incomplete(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            path, manifest = _write_manifest(root)
            baseline = _observations(manifest.manifest_sha256)
            replacement = copy.deepcopy(baseline)
            replacement["manifest_sha256"] = "f" * 64

            report = validate_region_replacement(
                manifest=path,
                baseline_observations=baseline,
                replacement_observations=replacement,
                source_root=root,
            )

            self.assertEqual(report["status"], "incomplete")
            self.assertEqual(report["counts"]["compared_cases"], 0)
            self.assertEqual(report["deltas"][0]["family"], "observation_schema")
            self.assertIn("not bound", report["deltas"][0]["observed"])

    def test_undeclared_candidate_control_fault_and_event_are_violations(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            path, manifest = _write_manifest(root)
            baseline = _observations(manifest.manifest_sha256)
            replacement = copy.deepcopy(baseline)
            case = replacement["cases"][0]
            case["control"]["id"] = "exit:unknown"
            case["fault"] = {
                "id": "fault:access",
                "kind": "access_violation",
                "instruction_rva": 0x1008,
                "code": 0xC0000005,
            }
            case["external_events"][0]["identity"] = "kernel32.dll!ReadFile"

            report = validate_region_replacement(
                manifest=path,
                baseline_observations=baseline,
                replacement_observations=replacement,
                source_root=root,
            )

            self.assertEqual(report["status"], "violated")
            self.assertTrue(
                {"control", "fault", "external_event"}
                <= {item["family"] for item in report["deltas"]}
            )

    def test_declared_control_target_cannot_be_omitted(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            _source(root)
            payload = _manifest_payload(root)
            payload["expectations"]["control"] = [
                {
                    "id": "exit:jump",
                    "kind": "jump",
                    "target_unit_ids": ["unit:2000"],
                    "target_rvas": [0x2000],
                    "evidence_ids": ["evidence:cluster"],
                }
            ]
            path = root / "jump.json"
            manifest = write_region_replacement_manifest(path, payload, source_root=root)
            baseline = _observations(manifest.manifest_sha256)
            baseline_control = baseline["cases"][0]["control"]
            baseline_control.update({
                "id": "exit:jump",
                "kind": "jump",
                "target_unit_id": "unit:2000",
                "target_rva": 0x2000,
            })
            replacement = copy.deepcopy(baseline)
            replacement["cases"][0]["control"]["target_unit_id"] = None
            replacement["cases"][0]["control"]["target_rva"] = None

            report = validate_region_replacement(
                manifest=path,
                baseline_observations=baseline,
                replacement_observations=replacement,
                source_root=root,
            )

            self.assertEqual(report["status"], "violated")
            self.assertTrue(any(
                item["family"] == "control"
                and "does not satisfy" in item["message"]
                for item in report["deltas"]
            ))

    def test_indirect_control_accepts_declared_concrete_machine_target(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            _source(root)
            payload = _manifest_payload(root)
            payload["expectations"]["control"] = [
                {
                    "id": "exit:indirect",
                    "kind": "indirect_jump",
                    "target_unit_ids": ["unit:2000"],
                    "target_rvas": [0x2000],
                    "target_values": [0x402000],
                    "evidence_ids": ["evidence:cluster"],
                }
            ]
            path = root / "indirect.json"
            manifest = write_region_replacement_manifest(
                path, payload, source_root=root
            )
            baseline = _observations(manifest.manifest_sha256)
            baseline["cases"][0]["control"].update(
                {
                    "id": "exit:indirect",
                    "kind": "indirect_jump",
                    "target_unit_id": None,
                    "target_rva": None,
                    "value": 0x402000,
                }
            )

            report = validate_region_replacement(
                manifest=path,
                baseline_observations=baseline,
                replacement_observations=copy.deepcopy(baseline),
                source_root=root,
            )

            self.assertEqual(report["status"], "qualified")

    def test_override_table_is_deterministic_sorted_and_compiler_consumable(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            _write_runtime_header(root)
            second_path, _ = _write_manifest(
                root,
                replacement_id="replace-second",
                cluster_id="cluster:second",
                entry_unit="unit:2000",
                entry_rva=0x2000,
                rva_end=0x2020,
                source_name="second.c",
                symbol="replace_second",
            )
            first_path, _ = _write_manifest(root)
            out_a = root / "out-a"
            out_b = root / "out-b"

            artifacts_a = generate_region_override_table(
                manifests=[second_path, first_path], source_root=root, out_dir=out_a
            )
            artifacts_b = generate_region_override_table(
                manifests=[first_path, second_path], source_root=root, out_dir=out_b
            )

            self.assertEqual(artifacts_a.count, 2)
            self.assertEqual(
                artifacts_a.source.read_bytes(), artifacts_b.source.read_bytes()
            )
            manifest = json.loads(artifacts_a.manifest.read_text(encoding="utf-8"))
            self.assertEqual(manifest["format"], REGION_OVERRIDE_TABLE_FORMAT)
            self.assertEqual(
                [entry["entry_rva"] for entry in manifest["entries"]],
                [0x1000, 0x2000],
            )
            self.assertFalse(manifest["executes_original_binary"])
            self.assertEqual(manifest["checks"]["source_hashes"], "verified")
            source_text = artifacts_a.source.read_text(encoding="ascii")
            self.assertLess(source_text.index("replace_loop"), source_text.index("replace_second"))

            compiler = shutil.which("cc")
            if compiler is not None:
                subprocess.run(
                    [
                        compiler, "-std=c11", "-Wall", "-Wextra", "-Werror",
                        "-I", str(root), "-I", str(out_a), "-c",
                        str(artifacts_a.source), "-o", str(root / "overrides.o"),
                    ],
                    check=True,
                    capture_output=True,
                    text=True,
                )

    def test_override_table_rejects_duplicate_overlap_binding_and_tampering(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            first_path, _ = _write_manifest(root)
            overlap_path, _ = _write_manifest(
                root,
                replacement_id="replace-overlap",
                cluster_id="cluster:overlap",
                entry_unit="unit:1010",
                entry_rva=0x1010,
                rva_end=0x1030,
                source_name="overlap.c",
                symbol="replace_overlap",
            )
            with self.assertRaisesRegex(StageAInputError, "RVA spans overlap"):
                generate_region_override_table(
                    manifests=[first_path, overlap_path],
                    source_root=root,
                    out_dir=root / "overlap-out",
                )

            duplicate_path, _ = _write_manifest(
                root,
                replacement_id="replace-duplicate",
                cluster_id="cluster:duplicate",
                entry_unit="unit:1000",
                entry_rva=0x3000,
                rva_end=0x3020,
                source_name="duplicate.c",
                symbol="replace_duplicate",
            )
            with self.assertRaisesRegex(StageAInputError, "entry unit ids"):
                generate_region_override_table(
                    manifests=[first_path, duplicate_path],
                    source_root=root,
                    out_dir=root / "duplicate-out",
                )

            mismatch_source = _source(root, "mismatch.c", "replace_mismatch")
            mismatch_payload = _manifest_payload(
                root,
                replacement_id="replace-mismatch",
                cluster_id="cluster:mismatch",
                entry_unit="unit:4000",
                entry_rva=0x4000,
                rva_end=0x4020,
                source_name=mismatch_source.name,
                symbol="replace_mismatch",
            )
            mismatch_payload["bindings"]["machine_ir_sha256"] = "9" * 64
            mismatch_path = root / "mismatch.json"
            write_region_replacement_manifest(
                mismatch_path, mismatch_payload, source_root=root
            )
            with self.assertRaisesRegex(StageAInputError, "same machine IR"):
                generate_region_override_table(
                    manifests=[first_path, mismatch_path],
                    source_root=root,
                    out_dir=root / "mismatch-out",
                )

            root.joinpath("replacement.c").write_text("tampered\n", encoding="utf-8")
            with self.assertRaisesRegex(StageAInputError, "source hash"):
                generate_region_override_table(
                    manifests=[first_path], source_root=root,
                    out_dir=root / "tampered-out",
                )

    def test_override_table_rejects_nonqualified_contract(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            path, _ = _write_manifest(root, evidence_status="incomplete")
            with self.assertRaisesRegex(StageAInputError, "non-qualified evidence"):
                generate_region_override_table(
                    manifests=[path], source_root=root, out_dir=root / "out"
                )


def _write_runtime_header(root: Path) -> None:
    root.joinpath("state-machine-runtime.h").write_text(
        """#ifndef TEST_STATE_MACHINE_RUNTIME_H
#define TEST_STATE_MACHINE_RUNTIME_H
#include <stdint.h>
typedef struct stage_b_runtime { uint32_t unused; } stage_b_runtime;
typedef struct stage_b_machine_state { uint32_t eax; } stage_b_machine_state;
typedef enum stage_b_control_kind { STAGE_B_RETURN = 3 } stage_b_control_kind;
typedef struct stage_b_step_result {
  stage_b_control_kind kind;
  uint32_t target_rva;
  uint32_t value;
} stage_b_step_result;
#endif
""",
        encoding="ascii",
    )


if __name__ == "__main__":
    unittest.main()
