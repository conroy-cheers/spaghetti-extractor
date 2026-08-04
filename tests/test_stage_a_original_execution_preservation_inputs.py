from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from spaghetti_extractor_target_gnu_hello.gnu_hello_original_execution_preservation_inputs import (
    ORIGINAL_EXECUTION_PRESERVATION_CONTEXT_FORMAT,
    ORIGINAL_EXECUTION_PRESERVATION_FRONTIER_FORMAT,
    OriginalExecutionPreservationInputsError,
    generate_gnu_hello_original_execution_preservation_inputs,
)
from spaghetti_extractor.relational.lean.original_execution_evidence import (
    ORIGINAL_EXECUTION_PRESERVATION_INPUTS_FORMAT,
)
from spaghetti_extractor.util import sha256_file


_TARGET_COUNT = 3490


def _write(path: Path, value: object) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="ascii"
    )
    return path


def _ref(name: str, module: str = "StageA.CheckedPreservationFixture") -> dict[str, str]:
    return {
        "module": module,
        "declaration": f"StageA.CheckedPreservationFixture.{name}",
    }


def _fact(name: str) -> dict[str, str]:
    return {
        "module": "StageA.CheckedFrontierFixture",
        "namespace": "StageA.CheckedFrontierFixture",
        "symbol": name,
    }


class _Fixture:
    def __init__(self, root: Path) -> None:
        self.root = root
        self.paths: dict[str, Path] = {}
        self.documents: dict[str, dict[str, object]] = {}
        self.original_hash = "1" * 64
        self.state_hash = "2" * 64
        self._build()

    def put(self, name: str, value: dict[str, object]) -> Path:
        self.documents[name] = value
        path = _write(self.root / f"{name}.json", value)
        self.paths[name] = path
        return path

    def rewrite(self, name: str) -> None:
        _write(self.paths[name], self.documents[name])

    def refresh_combined_inputs(self) -> None:
        self.documents["combined"]["inputs"] = {
            name: sha256_file(self.paths[name])
            for name in (
                "mixed_original_plan",
                "writable_authority_report",
                "register_authority_report",
                "stack_dynamic_authority_report",
            )
        }
        self.rewrite("combined")

    def _build(self) -> None:
        targets = []
        for target_id in range(_TARGET_COUNT):
            if target_id == _TARGET_COUNT - 1:
                evidence = {
                    "facts": _ref(f"x87Facts{target_id}"),
                    "successful_components": _ref(f"x87Components{target_id}"),
                }
                kind = "x87"
            else:
                evidence = {"checked_effect": _ref(f"checkedEffect{target_id}")}
                kind = "ordinary"
            targets.append(
                {
                    "target_id": target_id,
                    "source_rva": 0x401000 + 16 * target_id,
                    "kind": kind,
                    "evidence": evidence,
                }
            )
        effects = self.put(
            "effects",
            {
                "format": "stage-a-gnu-hello-source-transition-index-declarations-v1",
                "namespace": "StageA.GeneratedRelational.GnuHelloSourceTransitionIndex",
                "module_prefix": "GeneratedGnuHelloSourceTransitionIndex",
                "shard_span": 256,
                "targets": targets,
            },
        )
        shard_names = sorted(
            {
                f"GeneratedGnuHelloSourceTransitionIndexShard{target_id // 256:06d}"
                for target_id in range(_TARGET_COUNT)
            }
        )
        self.put(
            "transition",
            {
                "format": "stage-a-gnu-hello-source-transition-index-v1",
                "inputs": {
                    "declaration_inventory": {
                        "path": effects.name,
                        "sha256": sha256_file(effects),
                    }
                },
                "counts": {"targets": _TARGET_COUNT},
                "modules": [
                    "GeneratedGnuHelloSourceTransitionIndexData",
                    *shard_names,
                    "GeneratedGnuHelloSourceTransitionIndex",
                ],
                "exports": {},
            },
        )
        self.put(
            "combined",
            {
                "format": "stage-a-original-combined-execution-inventory-declarations-v1",
                "inputs": {},
                "counts": {
                    "reachable_targets": _TARGET_COUNT,
                    "static_word_slots": 3,
                    "register_requirements": 9,
                    "stack_dynamic_requirements": 3,
                    "call_frame_facts": 17,
                    "value_flow_facts": 23,
                },
                "lean": {
                    "module": "StageA.GeneratedRelationalOriginalCombinedInventory",
                    "inventory": (
                        "StageA.GeneratedRelational.OriginalCombinedInventory."
                        "generatedInventory"
                    ),
                    "original_context": (
                        "StageA.GeneratedRelational.OriginalCombinedInventory."
                        "generatedOriginalContext"
                    ),
                },
            },
        )

        blockers: list[dict[str, object]] = []
        writable_sites: list[dict[str, object]] = []
        register_sites: list[dict[str, object]] = []
        stack_sites: list[dict[str, object]] = []
        for index in range(19):
            source_rva = 0x5000 + index * 4
            blockers.append(
                {
                    "reason_code": "unresolved_indirect_control",
                    "rva": source_rva,
                    "detail": f"static_pointer_slot at 0x{source_rva:x}: fixture",
                }
            )
            writable_sites.append(
                {
                    "source_rva": source_rva,
                    "source_target_id": 100 + index,
                    "slot_rva": (0x9000, 0x9004, 0x9008)[index % 3],
                    "authorizing_lean_term": _fact(f"writable{index}"),
                }
            )
        for index in range(9):
            source_rva = 0x6000 + index * 4
            blockers.append(
                {
                    "reason_code": "unresolved_indirect_control",
                    "rva": source_rva,
                    "detail": f"register_function_pointer at 0x{source_rva:x}: fixture",
                }
            )
            register_sites.append(
                {
                    "source_rva": source_rva,
                    "source_target_id": 200 + index,
                    "authorizing_lean_term": _fact(f"register{index}"),
                }
            )
        modes = (
            "finite_stack_target",
            "empty_indexed_source",
            "uninhabited_dynamic_source",
        )
        for index, mode in enumerate(modes):
            source_rva = 0x7000 + index * 4
            blockers.append(
                {
                    "reason_code": "unresolved_indirect_control",
                    "rva": source_rva,
                    "detail": f"stack_or_dynamic_pointer at 0x{source_rva:x}: fixture",
                }
            )
            stack_sites.append(
                {
                    "source_rva": source_rva,
                    "source_target_id": 300 + index,
                    "closure_mode": mode,
                    "static_authority": "lean_checked",
                }
            )
        plan = self.put(
            "mixed_original_plan",
            {
                "format": "stage-a-interpreter-mixed-original-v1",
                "state_machine_sha256": self.state_hash,
                "reachable_target_ids": list(range(_TARGET_COUNT)),
                "blockers": blockers,
            },
        )
        self.put(
            "writable_authority_report",
            {
                "format": "stage-a-relocated-writable-static-pointer-slot-authorities-v2",
                "inputs": {
                    "mixed_original_plan_sha256": sha256_file(plan),
                    "state_machine_sha256": self.state_hash,
                    "original_sha256": self.original_hash,
                },
                "sites": writable_sites,
            },
        )
        self.put(
            "register_authority_report",
            {
                "format": "stage-a-register-indirect-control-authorities-v1",
                "inputs": {
                    "mixed_original_plan_sha256": sha256_file(plan),
                    "state_machine_sha256": self.state_hash,
                    "original_sha256": self.original_hash,
                },
                "blockers": [],
                "sites": register_sites,
            },
        )
        self.put(
            "stack_dynamic_authority_report",
            {
                "format": "stage-a-original-stack-dynamic-control-closure-v1",
                "inputs": {
                    "state_machine_sha256": self.state_hash,
                    "original_pe_sha256": self.original_hash,
                },
                "sites": stack_sites,
            },
        )
        self.refresh_combined_inputs()
        self._write_context()

    def _write_context(self) -> None:
        input_names = (
            "combined",
            "effects",
            "transition",
            "mixed_original_plan",
            "writable_authority_report",
            "register_authority_report",
            "stack_dynamic_authority_report",
        )
        path_names = {
            "combined": "combined_inventory_manifest",
            "effects": "source_target_effect_declarations",
            "transition": "transition_index_manifest",
        }
        inputs = {
            path_names.get(name, name): sha256_file(self.paths[name])
            for name in input_names
        }
        declarations = {
            name: _ref(name)
            for name in (
                "source_program",
                "target_ids_exact",
                "instruction_semantics_adequate",
                "protocol_responses",
                "project",
                "launch_inventory_holds",
                "launch_realizable",
                "compatibility_program_record_kernel_matches",
            )
        }
        self.put(
            "preservation_context",
            {
                "format": ORIGINAL_EXECUTION_PRESERVATION_CONTEXT_FORMAT,
                "namespace": (
                    "StageA.GeneratedRelational."
                    "GnuHelloOriginalExecutionEvidence"
                ),
                "module_prefix": "GeneratedGnuHelloOriginalExecutionEvidence",
                "shard_size": 256,
                "inputs": inputs,
                "declarations": declarations,
            },
        )

    def generate(self, out: Path):
        return generate_gnu_hello_original_execution_preservation_inputs(
            out,
            combined_inventory_manifest=self.paths["combined"],
            source_target_effect_declarations=self.paths["effects"],
            transition_index_manifest=self.paths["transition"],
            mixed_original_plan=self.paths["mixed_original_plan"],
            writable_authority_report=self.paths["writable_authority_report"],
            register_authority_report=self.paths["register_authority_report"],
            stack_dynamic_authority_report=self.paths[
                "stack_dynamic_authority_report"
            ],
            preservation_context=self.paths["preservation_context"],
        )


class StageAOriginalExecutionPreservationInputsTests(unittest.TestCase):
    def test_validates_all_targets_and_frontiers_and_reports_exact_blockers(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            fixture = _Fixture(root)
            first = fixture.generate(root / "first")
            second = fixture.generate(root / "second")
            first_bytes = first.manifest.read_bytes()
            second_bytes = second.manifest.read_bytes()
            frontier = json.loads(first.manifest.read_text(encoding="ascii"))

        self.assertEqual(first_bytes, second_bytes)
        self.assertEqual(frontier["format"], ORIGINAL_EXECUTION_PRESERVATION_FRONTIER_FORMAT)
        self.assertFalse(frontier["ready"])
        self.assertFalse(frontier["proof_authority"])
        self.assertEqual(
            frontier["requested_output_format"],
            ORIGINAL_EXECUTION_PRESERVATION_INPUTS_FORMAT,
        )
        self.assertEqual(frontier["counts"]["reachable_targets"], _TARGET_COUNT)
        self.assertEqual(frontier["counts"]["validated_frontiers"], 31)
        self.assertEqual(frontier["counts"]["missing_target_cases"], _TARGET_COUNT)
        self.assertEqual(len(frontier["blockers"]), _TARGET_COUNT)
        self.assertEqual(len(frontier["frontiers"]), 31)
        self.assertEqual(frontier["blockers"][0]["target_id"], 0)
        self.assertEqual(frontier["blockers"][-1]["target_id"], 3489)
        self.assertEqual(
            frontier["blockers"][-1]["checked_transition_certificate"]["declaration"],
            "StageA.GeneratedRelational.GnuHelloSourceTransitionIndex."
            "generatedActiveTargetTransitionCertificate_3489",
        )
        self.assertIn("checked_effect_case", frontier["blockers"][0]["missing_checked_evidence"])
        self.assertIn("static_word_post", frontier["blockers"][0]["missing_checked_evidence"])
        self.assertIn("call_frame_post", frontier["blockers"][0]["missing_checked_evidence"])
        self.assertIn("value_flow_post", frontier["blockers"][0]["missing_checked_evidence"])
        self.assertEqual(
            set(frontier["counts"]["missing_by_family"].values()),
            {_TARGET_COUNT},
        )
        self.assertFalse((root / "first/original-execution-preservation-inputs.json").exists())

    def test_blocked_generation_removes_stale_final_inputs(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            fixture = _Fixture(root)
            out = root / "out"
            out.mkdir()
            stale = out / "original-execution-preservation-inputs.json"
            stale_manifest = (
                out / "original-execution-preservation-inputs-manifest.json"
            )
            stale.write_text('{"format":"stale"}\n', encoding="ascii")
            stale_manifest.write_text('{"format":"stale"}\n', encoding="ascii")

            result = fixture.generate(out)

            self.assertTrue(result.manifest.is_file())
            self.assertFalse(stale.exists())
            self.assertFalse(stale_manifest.exists())

            fixture.documents["effects"]["targets"].pop()
            fixture.rewrite("effects")
            fixture.documents["transition"]["inputs"]["declaration_inventory"][
                "sha256"
            ] = sha256_file(fixture.paths["effects"])
            fixture.rewrite("transition")
            fixture._write_context()
            with self.assertRaises(OriginalExecutionPreservationInputsError):
                fixture.generate(out)
            self.assertFalse(result.manifest.exists())

    def test_missing_effect_or_transition_shard_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = _Fixture(Path(temporary))
            del fixture.documents["effects"]["targets"][0]["evidence"][
                "checked_effect"
            ]
            fixture.rewrite("effects")
            fixture.documents["transition"]["inputs"]["declaration_inventory"][
                "sha256"
            ] = sha256_file(fixture.paths["effects"])
            fixture.rewrite("transition")
            fixture._write_context()
            with self.assertRaises(OriginalExecutionPreservationInputsError):
                fixture.generate(fixture.root / "out")

        with tempfile.TemporaryDirectory() as temporary:
            fixture = _Fixture(Path(temporary))
            fixture.documents["effects"]["targets"].pop()
            fixture.rewrite("effects")
            fixture.documents["transition"]["inputs"]["declaration_inventory"][
                "sha256"
            ] = sha256_file(fixture.paths["effects"])
            fixture.rewrite("transition")
            fixture._write_context()
            with self.assertRaisesRegex(
                OriginalExecutionPreservationInputsError,
                "exactly 3490 reachable targets",
            ):
                fixture.generate(fixture.root / "out")

        with tempfile.TemporaryDirectory() as temporary:
            fixture = _Fixture(Path(temporary))
            fixture.documents["transition"]["modules"].remove(
                "GeneratedGnuHelloSourceTransitionIndexShard000013"
            )
            fixture.rewrite("transition")
            fixture._write_context()
            with self.assertRaisesRegex(
                OriginalExecutionPreservationInputsError,
                "transition index omits shard",
            ):
                fixture.generate(fixture.root / "out")

    def test_exact_hash_corruption_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = _Fixture(Path(temporary))
            fixture.documents["preservation_context"]["inputs"][
                "combined_inventory_manifest"
            ] = "f" * 64
            fixture.rewrite("preservation_context")
            with self.assertRaisesRegex(
                OriginalExecutionPreservationInputsError,
                "does not bind exact combined_inventory_manifest",
            ):
                fixture.generate(fixture.root / "out")

        with tempfile.TemporaryDirectory() as temporary:
            fixture = _Fixture(Path(temporary))
            fixture.documents["combined"]["inputs"][
                "mixed_original_plan"
            ] = "d" * 64
            fixture.rewrite("combined")
            fixture._write_context()
            with self.assertRaisesRegex(
                OriginalExecutionPreservationInputsError,
                "combined inventory does not bind exact mixed_original_plan",
            ):
                fixture.generate(fixture.root / "out")

        with tempfile.TemporaryDirectory() as temporary:
            fixture = _Fixture(Path(temporary))
            fixture.documents["transition"]["inputs"]["declaration_inventory"][
                "sha256"
            ] = "e" * 64
            fixture.rewrite("transition")
            fixture._write_context()
            with self.assertRaisesRegex(
                OriginalExecutionPreservationInputsError,
                "does not bind the exact target-effect declarations",
            ):
                fixture.generate(fixture.root / "out")

    def test_reachable_target_inventory_mismatch_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = _Fixture(Path(temporary))
            target_ids = fixture.documents["mixed_original_plan"][
                "reachable_target_ids"
            ]
            target_ids[0], target_ids[1] = target_ids[1], target_ids[0]
            fixture.rewrite("mixed_original_plan")
            fixture.documents["combined"]["inputs"][
                "mixed_original_plan"
            ] = sha256_file(fixture.paths["mixed_original_plan"])
            fixture.rewrite("combined")
            fixture._write_context()

            with self.assertRaisesRegex(
                OriginalExecutionPreservationInputsError,
                "target-effect declarations differ from exact mixed-plan reachability",
            ):
                fixture.generate(fixture.root / "out")

    def test_frontier_omission_and_unchecked_stack_authority_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = _Fixture(Path(temporary))
            fixture.documents["writable_authority_report"]["sites"].pop()
            fixture.rewrite("writable_authority_report")
            fixture.refresh_combined_inputs()
            fixture._write_context()
            with self.assertRaisesRegex(
                OriginalExecutionPreservationInputsError,
                "exactly 19 sites",
            ):
                fixture.generate(fixture.root / "out")

        with tempfile.TemporaryDirectory() as temporary:
            fixture = _Fixture(Path(temporary))
            fixture.documents["stack_dynamic_authority_report"]["sites"][0][
                "static_authority"
            ] = "unchecked"
            fixture.rewrite("stack_dynamic_authority_report")
            fixture.refresh_combined_inputs()
            fixture._write_context()
            with self.assertRaisesRegex(
                OriginalExecutionPreservationInputsError,
                "lacks Lean-checked static authority",
            ):
                fixture.generate(fixture.root / "out")

    def test_context_cannot_smuggle_status_or_preservation_family(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = _Fixture(Path(temporary))
            fixture.documents["preservation_context"]["status"] = "pass"
            fixture.rewrite("preservation_context")
            with self.assertRaisesRegex(
                OriginalExecutionPreservationInputsError,
                "preservation context fields differ",
            ):
                fixture.generate(fixture.root / "out")

        with tempfile.TemporaryDirectory() as temporary:
            fixture = _Fixture(Path(temporary))
            fixture.documents["preservation_context"]["declarations"][
                "preservation_family"
            ] = _ref("preservation_family")
            fixture.rewrite("preservation_context")
            with self.assertRaisesRegex(
                OriginalExecutionPreservationInputsError,
                "context declarations fields differ",
            ):
                fixture.generate(fixture.root / "out")

    def test_production_module_has_no_named_family_authority_api(self) -> None:
        source = (
            Path(__file__).parents[1]
            / "src/spaghetti_extractor/relational/lean/"
            "original_execution_preservation_inputs.py"
        ).read_text(encoding="utf-8")
        self.assertNotIn("preservation_authority", source)
        self.assertNotIn("preservation_family", source)
        self.assertNotIn("GeneratedPreservationInputs", source)


if __name__ == "__main__":
    unittest.main()
