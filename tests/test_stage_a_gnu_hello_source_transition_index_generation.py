from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

from spaghetti_extractor.relational.lean.gnu_hello_source_transition_index import (
    GNU_HELLO_SOURCE_TRANSITION_DECLARATIONS_FORMAT,
    GNU_HELLO_SOURCE_TRANSITION_MODULE,
    GnuHelloSourceTransitionIndexError,
    generate_gnu_hello_source_transition_index,
)


_HASH = "1" * 64
_IMPORT = re.compile(r"^import StageA\.([A-Za-z0-9_]+)$", re.MULTILINE)
_UNCHECKED_DECLARATION = re.compile(
    r"^\s*(?:axiom|opaque)\b|\b(?:admit|native_decide|sorry|unsafe)\b",
    re.MULTILINE,
)
_AXIOM_REPORT = re.compile(r"depends on axioms:\s*\[([^]]*)\]", re.DOTALL)
_APPROVED_LOGICAL_AXIOMS = frozenset(
    {"propext", "Quot.sound", "Classical.choice"}
)
_FIXTURE_AXIOM_PREFIX = "StageA.SourceTransitionIndexFixture."
_BINDING_FIXTURE_AXIOMS = frozenset(
    _FIXTURE_AXIOM_PREFIX + name
    for name in (
        "exactBindingConstructor",
        "originalPeExact",
        "originalSide",
        "pe",
        "sourceProgramConstructor",
        "worldProgram",
    )
)
_SEMANTICS_FIXTURE_AXIOMS = frozenset(
    _FIXTURE_AXIOM_PREFIX + name
    for name in (
        "instructionSemanticsAdequate",
        "sourceProgramConstructor",
        "worldProgram",
    )
)
_TARGET_FIXTURE_AXIOMS = _BINDING_FIXTURE_AXIOMS | frozenset(
    _FIXTURE_AXIOM_PREFIX + name
    for name in (
        "ordinaryBinding",
        "ordinaryCheckedEffect",
        "ordinaryDecoded",
        "ordinaryNotX87",
        "ordinaryPath",
        "ordinaryRecord",
        "ordinaryRecordMember",
        "ordinaryRegion",
        "ordinaryTransfer",
        "x87Facts",
        "x87Schedule",
        "x87Witness",
    )
)
_ALL_FIXTURE_AXIOMS = _TARGET_FIXTURE_AXIOMS | _SEMANTICS_FIXTURE_AXIOMS


def _write_json(path: Path, value: object) -> Path:
    path.write_text(json.dumps(value, sort_keys=True) + "\n", encoding="utf-8")
    return path


def _declaration(name: str) -> dict[str, str]:
    return {
        "module": "StageA.SourceTransitionIndexFixture",
        "declaration": f"StageA.SourceTransitionIndexFixture.{name}",
    }


def _manifests(root: Path) -> dict[str, Path]:
    return {
        "mixed_original_manifest": _write_json(
            root / "mixed.json",
            {
                "format": "stage-a-interpreter-mixed-original-v1",
                "state_machine_sha256": _HASH,
                "reachable_target_ids": [3, 7],
                "status": "violated",
            },
        ),
        "source_program_manifest": _write_json(
            root / "source.json",
            {
                "format": "stage-a-relational-phase-v1",
                "phase": "semantic-program-lean",
                "status": "incomplete",
                "inputs": {"state_machine": {"sha256": _HASH}},
                "counts": {
                    "transfers": 2,
                    "ordinary_transfers": 1,
                    "x87_transfers": 1,
                },
            },
        ),
        "normalization_manifest": _write_json(
            root / "normalization.json",
            {
                "format": (
                    "stage-a-relational-interpreter-normalization-inventory-v1"
                ),
                "status": "incomplete",
                "proof_authority": False,
                "total_transfers": 2,
                "ready_for_lean_check": 1,
                "blocked": 1,
            },
        ),
        "x87_manifest": _write_json(
            root / "x87.json",
            {
                "format": "stage-a-relational-phase-v1",
                "phase": "x87-lean",
                "status": "source-ready",
                "inputs": {"state_machine": {"sha256": _HASH}},
            },
        ),
    }


def _inventory() -> dict[str, object]:
    ordinary = {
        name: _declaration(name)
        for name in (
            "ordinaryBinding",
            "ordinaryCheckedEffect",
            "ordinaryRecord",
            "ordinaryRecordMember",
            "ordinaryNotX87",
        )
    }
    return {
        "format": GNU_HELLO_SOURCE_TRANSITION_DECLARATIONS_FORMAT,
        "imports": ["StageA.SourceTransitionIndexFixture"],
        "world_program": _declaration("worldProgram"),
        "original_pe": _declaration("pe"),
        "original_side": _declaration("originalSide"),
        "original_pe_exact": _declaration("originalPeExact"),
        "source_program_constructor": _declaration("sourceProgramConstructor"),
        "instruction_semantics_adequate": _declaration(
            "instructionSemanticsAdequate"
        ),
        "exact_binding_constructor": _declaration("exactBindingConstructor"),
        "target_inventory": _declaration("targetIds"),
        "target_inventory_unique": _declaration("targetIdsUnique"),
        "submitted_target_ids_exact": _declaration("submittedTargetIdsExact"),
        "namespace": "StageA.GeneratedRelational.GnuHelloSourceTransitionIndex",
        "module_prefix": "GeneratedGnuHelloSourceTransitionIndex",
        "shard_span": 4,
        "targets": [
            {
                "target_id": 3,
                "source_rva": 100,
                "kind": "ordinary",
                "evidence": {
                    "binding": ordinary["ordinaryBinding"],
                    "checked_effect": ordinary["ordinaryCheckedEffect"],
                    "record": ordinary["ordinaryRecord"],
                    "record_member": ordinary["ordinaryRecordMember"],
                    "not_x87": ordinary["ordinaryNotX87"],
                },
            },
            {
                "target_id": 7,
                "source_rva": 200,
                "kind": "x87",
                "evidence": {"facts": _declaration("x87Facts")},
            },
        ],
    }


def _copy_module_closure(source_root: Path, destination: Path, module: str) -> None:
    pending = [module]
    copied: set[str] = set()
    while pending:
        current = pending.pop()
        if current in copied:
            continue
        source = source_root / f"{current}.lean"
        text = source.read_text(encoding="utf-8")
        shutil.copyfile(source, destination / source.name)
        copied.add(current)
        pending.extend(_IMPORT.findall(text))


def _compile_lean_module(root: Path, module: str) -> subprocess.CompletedProcess[str]:
    lean = shutil.which("lean")
    if lean is None:
        raise AssertionError("focused Lean test requires lean in PATH")
    stage_a = root / "StageA"
    order: list[str] = []
    visiting: set[str] = set()
    visited: set[str] = set()

    def visit(current: str) -> None:
        if current in visited:
            return
        if current in visiting:
            raise AssertionError(f"cyclic fixture import at StageA.{current}")
        source = stage_a / f"{current}.lean"
        if not source.is_file():
            raise AssertionError(f"missing fixture module StageA.{current}")
        visiting.add(current)
        for imported in _IMPORT.findall(source.read_text(encoding="utf-8")):
            visit(imported)
        visiting.remove(current)
        visited.add(current)
        order.append(current)

    visit(module)
    completed: subprocess.CompletedProcess[str] | None = None
    for current in order:
        command = [lean, "--tstack=65536"]
        if current != module:
            command.extend(["-o", f"StageA/{current}.olean"])
        command.append(f"StageA/{current}.lean")
        completed = subprocess.run(
            command,
            cwd=root,
            env={**os.environ, "LEAN_PATH": "."},
            check=False,
            capture_output=True,
            text=True,
        )
        if completed.returncode != 0:
            raise AssertionError(
                f"Lean failed for StageA.{current}:\n"
                f"stdout:\n{completed.stdout}\nstderr:\n{completed.stderr}"
            )
    if completed is None:
        raise AssertionError(f"empty Lean module closure for StageA.{module}")
    return completed


def _reported_axioms(output: str) -> list[frozenset[str]]:
    reports: list[frozenset[str]] = []
    for body in _AXIOM_REPORT.findall(output):
        reports.append(
            frozenset(
                item.strip()
                for item in body.replace("\n", " ").split(",")
                if item.strip()
            )
        )
    return reports


_FIXTURE = r'''import StageA.RelationalSourceOrdinaryTargetRouting
import StageA.RelationalSourceProgramCertificate
import StageA.RelationalSourceX87TargetRouting

namespace StageA.SourceTransitionIndexFixture

open StageA.Formal StageA.Relational
open StageA.Relational.Interpreter
open StageA.Relational.InterpreterNormalization
open StageA.Relational.InterpreterX87
open StageA.Relational.SourceWorld.InterpreterKernel
open StageA.Relational.SourceWorld.OrdinaryTargetRouting

axiom pe : PE32
axiom worldProgram : DecodedWorldProgram
axiom originalSide : worldProgram.candidate = false
axiom originalPeExact : worldProgram.context.originalPe = pe
axiom sourceProgramConstructor : DecodedWorldProgram -> Program
axiom instructionSemanticsAdequate :
  (sourceProgramConstructor worldProgram).worldProgram.InstructionSemanticsAdequate
axiom exactBindingConstructor : forall input,
  input.candidate = false -> input.context.originalPe = pe ->
    ExactBinding pe (sourceProgramConstructor input)

def targetIds : List Nat := [3, 7]
theorem targetIdsUnique : targetIds.Nodup := by decide
theorem submittedTargetIdsExact : [3, 7] = targetIds := rfl

axiom ordinaryRecord : ProgramRecord
axiom ordinaryPath : ExactNormalizedTransferPath
axiom ordinaryTransfer : SemanticTransfer
axiom ordinaryRegion : RegionRelation
axiom ordinaryBinding : ExactOrdinaryTargetBinding pe
  (sourceProgramConstructor worldProgram) 3 100 ordinaryRecord ordinaryPath
  ordinaryTransfer ordinaryRegion
axiom ordinaryDecoded : ExactDecodedOrdinaryTargetEvaluator ordinaryBinding
axiom ordinaryCheckedEffect :
  CheckedOrdinaryTargetEffect ordinaryBinding ordinaryDecoded
axiom ordinaryRecordMember :
  List.Mem ordinaryRecord (sourceProgramConstructor worldProgram).records
axiom ordinaryNotX87 :
  Not (List.Mem 100 (sourceProgramConstructor worldProgram).x87SourceRvas)

axiom x87Witness : ExactInterpreterX87ScheduleWitness pe
axiom x87Schedule : ExactX87SingletonScheduleFacts pe x87Witness
axiom x87Facts : ExactX87SingletonTargetFacts pe
  (sourceProgramConstructor worldProgram) 7 x87Witness x87Schedule

end StageA.SourceTransitionIndexFixture
'''


class GnuHelloSourceTransitionIndexGenerationTests(unittest.TestCase):
    def test_generates_shardable_exact_index_and_compiles(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            inputs = _manifests(root)
            inventory = _write_json(root / "declarations.json", _inventory())
            result = generate_gnu_hello_source_transition_index(
                root,
                declaration_inventory=inventory,
                **inputs,
            )

            self.assertEqual(result.target_count, 2)
            self.assertEqual(result.ordinary_count, 1)
            self.assertEqual(result.x87_count, 1)
            module_names = [path.stem for path in result.modules]
            self.assertEqual(
                module_names,
                [
                    "GeneratedGnuHelloSourceTransitionIndexData",
                    "GeneratedGnuHelloSourceTransitionIndexShard000000",
                    "GeneratedGnuHelloSourceTransitionIndexShard000001",
                    GNU_HELLO_SOURCE_TRANSITION_MODULE,
                ],
            )

            generated = "\n".join(
                path.read_text(encoding="ascii") for path in result.modules
            )
            for required in (
                "generatedConcreteExactBinding",
                "exactBindingConstructor",
                "generatedBoundTargetSelection_3",
                "CheckedOrdinaryTargetEffect.toLocalEffectExact",
                "generatedBoundTargetSelection_7",
                "ExactX87SingletonTargetFacts.toLocalEffectExact",
                "ActiveTargetTransitionCertificate.ofExactBound",
                "generatedActiveTargetTransitionIndex",
                "generatedActiveTargetIdsExact",
            ):
                self.assertIn(required, generated)
            for forbidden in (
                "ActiveTargetDomainCoverage",
                "RuntimeClosure",
                "native_decide",
                "status ==",
                "axiom ",
                "sorry",
            ):
                self.assertNotIn(forbidden, generated)

            source_root = (
                Path(__file__).parents[1] / "src/spaghetti_extractor/lean/StageA"
            )
            stage_a = root / "StageA"
            for module in (
                "RelationalSourceOrdinaryTargetRouting",
                "RelationalSourceProgramCertificate",
                "RelationalSourceX87TargetRouting",
            ):
                _copy_module_closure(source_root, stage_a, module)
            (stage_a / "SourceTransitionIndexFixture.lean").write_text(
                _FIXTURE,
                encoding="ascii",
            )
            generated_sources = (*result.modules, result.audit)
            for path in generated_sources:
                self.assertIsNone(
                    _UNCHECKED_DECLARATION.search(path.read_text(encoding="ascii")),
                    path,
                )

            audit = _compile_lean_module(root, result.audit.stem)
            self.assertEqual(audit.returncode, 0, audit.stderr)
            reported = _reported_axioms(audit.stdout + audit.stderr)
            self.assertEqual(len(reported), 4, audit.stdout + audit.stderr)
            expected_fixture_dependencies = (
                _SEMANTICS_FIXTURE_AXIOMS,
                _BINDING_FIXTURE_AXIOMS,
                _TARGET_FIXTURE_AXIOMS,
                _TARGET_FIXTURE_AXIOMS,
            )
            for used, fixture_dependencies in zip(
                reported, expected_fixture_dependencies, strict=True
            ):
                self.assertEqual(
                    used & _ALL_FIXTURE_AXIOMS,
                    fixture_dependencies,
                    audit.stdout + audit.stderr,
                )
                logical_axioms = used - _ALL_FIXTURE_AXIOMS
                self.assertLessEqual(
                    logical_axioms,
                    _APPROVED_LOGICAL_AXIOMS,
                    audit.stdout + audit.stderr,
                )
                self.assertLessEqual(
                    {"propext", "Quot.sound"},
                    logical_axioms,
                    audit.stdout + audit.stderr,
                )
            self.assertNotIn("sorryAx", audit.stdout + audit.stderr)

            manifest = json.loads(result.manifest.read_text(encoding="ascii"))
            self.assertFalse(manifest["executes_original_binary"])
            self.assertFalse(manifest["executes_candidate_binary"])
            self.assertEqual(manifest["counts"]["shards"], 2)

    def test_status_fields_do_not_authorize_or_block_generation(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            inputs = _manifests(root)
            inventory = _write_json(root / "declarations.json", _inventory())
            result = generate_gnu_hello_source_transition_index(
                root / "out",
                declaration_inventory=inventory,
                **inputs,
            )
            self.assertEqual(result.target_count, 2)

    def test_missing_duplicate_or_mistyped_effect_evidence_fails_closed(self) -> None:
        mutations = []
        missing = _inventory()
        missing["targets"] = missing["targets"][:1]
        mutations.append(missing)

        duplicate = _inventory()
        duplicate["targets"] = [duplicate["targets"][0], duplicate["targets"][0]]
        mutations.append(duplicate)

        mistyped = _inventory()
        mistyped["targets"][0]["evidence"].pop("checked_effect")
        mutations.append(mistyped)

        for index, inventory_value in enumerate(mutations):
            with self.subTest(index=index), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                inputs = _manifests(root)
                inventory = _write_json(
                    root / "declarations.json", inventory_value
                )
                with self.assertRaises(GnuHelloSourceTransitionIndexError):
                    generate_gnu_hello_source_transition_index(
                        root / "out",
                        declaration_inventory=inventory,
                        **inputs,
                    )

    def test_cross_generation_hash_or_structural_count_mismatch_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            inputs = _manifests(root)
            source = json.loads(
                inputs["source_program_manifest"].read_text(encoding="utf-8")
            )
            source["inputs"]["state_machine"]["sha256"] = "2" * 64
            _write_json(inputs["source_program_manifest"], source)
            inventory = _write_json(root / "declarations.json", _inventory())
            with self.assertRaisesRegex(
                GnuHelloSourceTransitionIndexError, "hashes differ"
            ):
                generate_gnu_hello_source_transition_index(
                    root / "out",
                    declaration_inventory=inventory,
                    **inputs,
                )

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            inputs = _manifests(root)
            normalization = json.loads(
                inputs["normalization_manifest"].read_text(encoding="utf-8")
            )
            normalization["ready_for_lean_check"] = 0
            _write_json(inputs["normalization_manifest"], normalization)
            inventory = _write_json(root / "declarations.json", _inventory())
            with self.assertRaisesRegex(
                GnuHelloSourceTransitionIndexError, "inventories differ"
            ):
                generate_gnu_hello_source_transition_index(
                    root / "out",
                    declaration_inventory=inventory,
                    **inputs,
                )


if __name__ == "__main__":
    unittest.main()
