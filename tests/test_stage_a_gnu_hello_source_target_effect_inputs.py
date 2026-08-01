from __future__ import annotations

import copy
import hashlib
import json
import re
import tempfile
import unittest
from pathlib import Path

from spaghetti_extractor.relational.lean.gnu_hello_source_target_effect_inputs import (
    GNU_HELLO_SOURCE_TARGET_EFFECT_INPUTS_MANIFEST_FORMAT,
    GnuHelloSourceTargetEffectInputsError,
    _Target,
    _x87_target_source,
    generate_gnu_hello_source_target_effect_inputs,
)
from spaghetti_extractor.relational.lean.gnu_hello_source_target_effects import (
    GNU_HELLO_SOURCE_TARGET_EFFECT_INPUTS_FORMAT,
    GnuHelloSourceTargetEffectsError,
    generate_gnu_hello_source_target_effects,
)
from spaghetti_extractor.relational.lean.gnu_hello_source_transition_index import (
    LeanDeclaration,
)


_HASH = re.compile(r"[0-9a-f]{64}\Z")
_FORBIDDEN = re.compile(
    r"^\s*(?:axiom|opaque)\b|\b(?:admit|sorry)\b", re.MULTILINE
)


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _write_json(path: Path, value: object) -> Path:
    path.write_text(
        json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    return path


def _ret_row(index: int) -> dict[str, object]:
    rva = 0x1000 + index * 0x10
    return {
        "stage_b_format": "stage-b-state-machine-transfer-v1",
        "format": "stage-a-semantic-transfer-contract-v1",
        "id": f"semantic-transfer:ret-{index:04d}",
        "status": "must-not-authorize",
        "contract_sha256": f"{index:064x}"[-64:],
        "instruction_bytes_sha256": hashlib.sha256(b"\xc3").hexdigest(),
        "original": {"rva_start": rva, "rva_end": rva + 1, "size": 1},
        "instructions": [{
            "rva": rva,
            "size": 1,
            "bytes": "c3",
            "mnemonic": "ret",
            "op_str": "",
        }],
        "ordered_events": [{
            "family": "memory",
            "kind": "read",
            "width": 4,
            "instruction_rva": rva,
            "address": {"op": "reg", "name": "esp", "width": 32},
        }],
        "register_writes": [{
            "register": "esp",
            "value": {
                "op": "add32",
                "args": [
                    {"op": "const", "value": 4, "width": 32},
                    {"op": "reg", "name": "esp", "width": 32},
                ],
            },
        }],
        "flag_writes": [],
        "fpu_state": None,
        "outcome": {
            "kind": "return",
            "value": {
                "op": "load",
                "width": 4,
                "address": {"op": "reg", "name": "esp", "width": 32},
            },
        },
    }


def _module(root: Path, name: str, source: str) -> Path:
    stage_a = root / "StageA"
    stage_a.mkdir(parents=True, exist_ok=True)
    path = stage_a / f"{name}.lean"
    path.write_text(source, encoding="utf-8")
    return path


def _phase(root: Path, phase: str, machine_hash: str) -> Path:
    return _write_json(
        root / "phase-manifest.json",
        {
            "format": "stage-a-relational-phase-v1",
            "phase": phase,
            "inputs": {"state_machine": {"sha256": machine_hash}},
        },
    )


def _artifacts(root: Path, count: int) -> dict[str, Path]:
    rows = [_ret_row(index) for index in range(count)]
    machine = root / "state-machine.jsonl"
    machine.write_text(
        "".join(json.dumps(row, sort_keys=True) + "\n" for row in rows),
        encoding="utf-8",
    )
    machine_hash = _sha256(machine)

    source_root = root / "source"
    source_declarations = [
        "def semanticInterpreterProgramRecords : Nat := 0",
        "theorem semanticInterpreterProgramSourceRvasUnique : True := by trivial",
    ]
    for index in range(count):
        source_declarations.extend((
            f"def semanticInterpreterProgramRecord{index} : Nat := 0",
            f"def semanticInterpreterTransfer{index} : Nat := 0",
        ))
    _module(
        source_root,
        "GeneratedSemanticInterpreterProgram",
        "\n".join(source_declarations) + "\n",
    )
    source_manifest = _write_json(
        source_root / "phase-manifest.json",
        {
            "format": "stage-a-relational-phase-v1",
            "phase": "semantic-program-lean",
            "inputs": {"state_machine": {"sha256": machine_hash}},
            "modules": ["GeneratedSemanticInterpreterProgram"],
            "counts": {
                "transfers": count,
                "ordinary_transfers": count,
                "x87_transfers": 0,
            },
        },
    )

    normalization_root = root / "normalization"
    normalization_declarations = [
        "def exactNormalizedOrdinaryRecordBindings : Nat := 0"
    ]
    for index in range(count):
        normalization_declarations.extend((
            f"def exactNormalizedTransferPath{index} : Nat := 0",
            f"def exactNormalizedTransferPath{index}Certificate : Nat := 0",
        ))
    normalization_source = _module(
        normalization_root,
        "GeneratedNormalization",
        "\n".join(normalization_declarations) + "\n",
    )
    normalization_inventory = _write_json(
        normalization_root / "module-inventory.json",
        {
            "format": "stage-a-relational-interpreter-normalization-v1",
            "modules": {
                "GeneratedNormalization": {
                    "source_sha256": _sha256(normalization_source)
                }
            },
        },
    )
    _phase(normalization_root, "normalization-lean", machine_hash)

    semantic_root = root / "semantic"
    semantic_source = _module(
        semantic_root,
        "GeneratedSemanticRefinement",
        "\n".join(
            f"theorem exactNormalizedTransferFusedMachineRefinement{index} : True := by trivial"
            for index in range(count)
        ) + "\n",
    )
    semantic_inventory = _write_json(
        semantic_root / "module-inventory.json",
        {
            "format": "stage-a-relational-interpreter-semantic-refinement-v2",
            "modules": {
                "GeneratedSemanticRefinement": {
                    "source_sha256": _sha256(semantic_source)
                }
            },
        },
    )
    _phase(semantic_root, "semantic-refinement-lean", machine_hash)

    x87_root = root / "x87"
    x87_source = _module(
        x87_root,
        "GeneratedX87",
        """def checkedInterpreterX87ScheduleBundleWitnesses : Nat := 0
def checkedInterpreterX87ScheduleBundleSourceRvas : Nat := 0
theorem checkedInterpreterX87ScheduleBundleSourceRvasNodup : True := by trivial
""",
    )
    x87_inventory = _write_json(
        x87_root / "module-inventory.json",
        {
            "format": "stage-a-relational-interpreter-x87-module-inventory-v1",
            "modules": {
                "GeneratedX87": {"source_sha256": _sha256(x87_source)}
            },
        },
    )
    _phase(x87_root, "x87-lean", machine_hash)

    exact_root = root / "mixed"
    target_rows = "\n".join(
        f"-- {{ id := {index}, regionIndex := {index}, "
        f"rva := {0x1000 + index * 0x10}, aliases := [] }}"
        for index in range(count)
    )
    _module(
        exact_root,
        "GeneratedMixed",
        f"""def generatedOriginalStateMachineSha256 : String := "{machine_hash}"
def generatedOriginalCombinedProgram : Nat := 0
def generatedOriginalCombinedReachableTargetIds : List Nat := {list(range(count))}
theorem generatedOriginalCombinedReachableTargetIdsUnique :
    generatedOriginalCombinedReachableTargetIds.Nodup := by decide
{target_rows}
""",
    )
    mixed_plan = _write_json(
        root / "mixed.json",
        {
            "format": "stage-a-interpreter-mixed-original-v1",
            "state_machine_sha256": machine_hash,
            "counts": {"regions": count, "reachable_targets": count},
            "reachable_target_ids": list(range(count)),
        },
    )
    return {
        "state_machine": machine,
        "mixed_original_plan": mixed_plan,
        "source_program_root": source_root,
        "source_program_manifest": source_manifest,
        "normalization_root": normalization_root,
        "normalization_inventory": normalization_inventory,
        "semantic_refinement_root": semantic_root,
        "semantic_refinement_inventory": semantic_inventory,
        "x87_root": x87_root,
        "x87_inventory": x87_inventory,
        "exact_original_root": exact_root,
    }


class GnuHelloSourceTargetEffectInputsTests(unittest.TestCase):
    def test_full_3490_target_authority_shape_is_deterministic(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            artifacts = _artifacts(root, 3490)
            first = generate_gnu_hello_source_target_effect_inputs(
                root / "first", **artifacts
            )
            second = generate_gnu_hello_source_target_effect_inputs(
                root / "second", **artifacts
            )

            self.assertEqual(first.target_count, 3490)
            self.assertEqual(first.ordinary_count, 3490)
            self.assertEqual(first.x87_count, 0)
            authority = json.loads(first.authority_inventory.read_text())
            manifest = json.loads(first.manifest.read_text())
            self.assertEqual(
                set(authority),
                {
                    "format", "imports", "namespace", "module_prefix",
                    "shard_span", "artifact_bindings", "authority_modules",
                    "world_program",
                    "original_pe", "original_side", "original_pe_exact",
                    "source_program_constructor", "exact_binding_constructor",
                    "instruction_semantics_adequate",
                    "target_inventory", "target_inventory_unique",
                    "submitted_target_ids_exact", "targets",
                },
            )
            self.assertEqual(
                authority["format"], GNU_HELLO_SOURCE_TARGET_EFFECT_INPUTS_FORMAT
            )
            self.assertEqual(
                [target["target_id"] for target in authority["targets"]],
                list(range(3490)),
            )
            self.assertEqual(manifest["format"], GNU_HELLO_SOURCE_TARGET_EFFECT_INPUTS_MANIFEST_FORMAT)
            self.assertEqual(manifest["counts"]["targets"], 3490)
            self.assertEqual(manifest["authority"]["sha256"], _sha256(first.authority_inventory))
            self.assertTrue(_HASH.fullmatch(manifest["state_machine_sha256"]))

            imported = set(authority["imports"])
            declaration_inventory = {
                module: set(metadata["declarations"])
                for module, metadata in manifest["modules"].items()
            }
            for target in authority["targets"]:
                self.assertEqual(set(target), {"target_id", "source_rva", "kind", "evidence"})
                evidence = target["evidence"]
                self.assertEqual(set(evidence), {"region", "static", "dynamic"})
                self.assertEqual(set(evidence["dynamic"]), {"semantic_replay"})
                references = [
                    evidence["region"],
                    *evidence["static"].values(),
                    *evidence["dynamic"].values(),
                ]
                for reference in references:
                    self.assertIn(reference["module"], imported)
                    local = reference["declaration"].rsplit(".", 1)[-1]
                    self.assertIn(local, declaration_inventory[reference["module"]])

            first_bytes = {
                path.relative_to(root / "first"): path.read_bytes()
                for path in (root / "first").rglob("*") if path.is_file()
            }
            second_bytes = {
                path.relative_to(root / "second"): path.read_bytes()
                for path in (root / "second").rglob("*") if path.is_file()
            }
            self.assertEqual(first_bytes, second_bytes)
            for path in first.modules:
                source = path.read_text(encoding="ascii")
                self.assertIsNone(_FORBIDDEN.search(source), path)
                self.assertNotIn("must-not-authorize", source)

    def test_corrupt_generated_source_hash_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            artifacts = _artifacts(root, 3)
            source = artifacts["normalization_root"] / "StageA/GeneratedNormalization.lean"
            source.write_text(source.read_text() + "\n-- changed\n")
            with self.assertRaisesRegex(
                GnuHelloSourceTargetEffectInputsError,
                "source hash differs",
            ):
                generate_gnu_hello_source_target_effect_inputs(
                    root / "out", **artifacts
                )

    def test_authority_is_consumed_without_manual_declaration_inputs(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            artifacts = _artifacts(root, 3)
            inputs = generate_gnu_hello_source_target_effect_inputs(
                root / "inputs", **artifacts
            )
            effects = generate_gnu_hello_source_target_effects(
                root / "effects",
                authority_inventory=inputs.authority_inventory,
                **artifacts,
            )

            self.assertEqual(effects.target_count, 3)
            self.assertEqual(effects.ordinary_count, 3)
            self.assertEqual(effects.x87_count, 0)
            declarations = json.loads(effects.declaration_inventory.read_text())
            self.assertEqual(
                [target["target_id"] for target in declarations["targets"]],
                [0, 1, 2],
            )
            generated = "\n".join(
                path.read_text(encoding="ascii") for path in effects.modules
            )
            self.assertIn("generatedOrdinary0CheckedEffect", generated)
            self.assertIsNone(_FORBIDDEN.search(generated))

    def test_modified_authority_shard_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            artifacts = _artifacts(root, 3)
            inputs = generate_gnu_hello_source_target_effect_inputs(
                root / "inputs", **artifacts
            )
            shard = inputs.modules[-1]
            shard.write_text(shard.read_text() + "\n-- modified\n")
            with self.assertRaisesRegex(
                GnuHelloSourceTargetEffectsError,
                "authority module hash differs",
            ):
                generate_gnu_hello_source_target_effects(
                    root / "effects",
                    authority_inventory=inputs.authority_inventory,
                    **artifacts,
                )

    def test_reachable_target_without_semantic_partition_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            artifacts = _artifacts(root, 3)
            mixed_source = artifacts["exact_original_root"] / "StageA/GeneratedMixed.lean"
            text = mixed_source.read_text()
            text = text.replace("rva := 4128, aliases := []", "rva := 57005, aliases := []")
            mixed_source.write_text(text)
            with self.assertRaisesRegex(
                GnuHelloSourceTargetEffectInputsError,
                "does not select exactly one semantic-source partition",
            ):
                generate_gnu_hello_source_target_effect_inputs(
                    root / "out", **artifacts
                )

    def test_x87_shard_references_checked_schedule_and_partition(self) -> None:
        module = "StageA.GeneratedX87Fixture"
        target = _Target(
            target_id=7,
            source_rva=0x2000,
            kind="x87",
            source_index=0,
            continuation_target_id=8,
            dependencies=(
                LeanDeclaration(module, f"{module}.witness"),
                LeanDeclaration(module, f"{module}.schedule"),
            ),
        )
        source, fields = _x87_target_source(
            target, "GeneratedGnuHelloSourceTargetEffectInputsShard000000"
        )
        self.assertIn("generatedExactBindingPartition", source)
        self.assertIn("witness.schedule.sourceRva", source)
        self.assertIn("normalizeCodeTarget false", source)
        self.assertIn("some 8", source)
        self.assertEqual(
            set(fields),
            {
                "source_rva_exact", "classification_exact", "classified",
                "partition", "witness_member", "region", "region_exact",
                "region_span_exact", "source_continuation_exact",
                "decoded_continuation_exact",
            },
        )
        self.assertIsNone(_FORBIDDEN.search(source))


if __name__ == "__main__":
    unittest.main()
