from __future__ import annotations

import dataclasses
import re
import shutil
import tempfile
import unittest
from pathlib import Path

from spaghetti_extractor.relational.lean.compiler import _run_lean_relational
from spaghetti_extractor.relational.lean.source_target_routing import (
    SOURCE_TARGET_ROUTING_AUDIT_MODULE,
    SourceTargetRoutingGenerationError,
    SourceTargetRoutingSpec,
    TargetRoutingComponentSpec,
    source_target_routing_audit_source,
    source_target_routing_source,
    write_source_target_routing,
)


_IMPORT = re.compile(r"^import StageA\.([A-Za-z0-9_]+)$", re.MULTILINE)


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


def _target(target_id: int) -> TargetRoutingComponentSpec:
    prefix = f"StageA.SourceTargetRoutingFixture.target{target_id}"
    return TargetRoutingComponentSpec(
        target_id=target_id,
        source_step=f"{prefix}SourceStep",
        decoded_behavior=f"{prefix}DecodedBehavior",
        source_step_exact=f"{prefix}SourceStepExact",
        decoded_behavior_exact=f"{prefix}DecodedBehaviorExact",
        effects_exact=f"{prefix}EffectsExact",
    )


def _spec(**changes: object) -> SourceTargetRoutingSpec:
    base = SourceTargetRoutingSpec(
        imports=("StageA.SourceTargetRoutingFixture",),
        program="StageA.SourceTargetRoutingFixture.program",
        targets=(_target(3), _target(7)),
    )
    return dataclasses.replace(base, **changes)


class StageASourceTargetRoutingGenerationTests(unittest.TestCase):
    def test_emits_data_only_component_assembly_and_detached_audit(self) -> None:
        source = source_target_routing_source(_spec())
        audit = source_target_routing_audit_source(_spec())

        self.assertIn("SuccessfulTargetEffectComponents", source)
        self.assertIn(".toLocalEffectExact", source)
        self.assertLess(
            source.index("generatedTargetEffectComponents_3"),
            source.index("generatedTargetEffectComponents_7"),
        )
        self.assertNotIn("#print axioms", source)
        self.assertEqual(audit.count("#print axioms"), 2)
        for forbidden in (
            r"\baxiom\b",
            r"\bsorry\b",
            r"\badmit\b",
            r"\bunsafe\b",
            r"\bnative_decide\b",
            r"\bGNU\b",
            r"\bhello\b",
        ):
            self.assertNotRegex(source, forbidden)

    def test_malformed_duplicate_and_unstable_inputs_fail_closed(self) -> None:
        invalid_specs = (
            _spec(imports=()),
            _spec(imports=("Fixture",)),
            _spec(targets=()),
            _spec(targets=(_target(7), _target(3))),
            _spec(targets=(_target(3), _target(3))),
            _spec(program="program; axiom injected : False"),
            _spec(output_module="../Escape"),
        )
        for spec in invalid_specs:
            with self.subTest(spec=spec):
                with self.assertRaises(SourceTargetRoutingGenerationError):
                    source_target_routing_source(spec)

        malformed = dataclasses.replace(
            _target(3), effects_exact="by rfl"
        )
        with self.assertRaisesRegex(
            SourceTargetRoutingGenerationError, "canonical"
        ):
            source_target_routing_source(_spec(targets=(malformed, _target(7))))

    def test_writer_is_byte_reproducible(self) -> None:
        spec = _spec()
        expected_proof = source_target_routing_source(spec).encode("ascii")
        expected_audit = source_target_routing_audit_source(spec).encode("ascii")
        with tempfile.TemporaryDirectory() as temporary:
            first = write_source_target_routing(temporary, spec)
            first_proof = first.proof.read_bytes()
            first_audit = first.audit.read_bytes()
            second = write_source_target_routing(temporary, spec)
            second_proof = second.proof.read_bytes()
            second_audit = second.audit.read_bytes()

        self.assertEqual(first_proof, expected_proof)
        self.assertEqual(first_audit, expected_audit)
        self.assertEqual(second_proof, expected_proof)
        self.assertEqual(second_audit, expected_audit)

    @unittest.skipUnless(shutil.which("lean"), "Lean is required")
    def test_generated_components_and_audit_compile_against_kernel(self) -> None:
        source_root = (
            Path(__file__).parents[1] / "src/spaghetti_extractor/lean/StageA"
        )
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            stage_a = root / "StageA"
            stage_a.mkdir()
            _copy_module_closure(
                source_root, stage_a, "RelationalSourceInterpreterKernel"
            )
            (stage_a / "SourceTargetRoutingFixture.lean").write_text(
                _LEAN_FIXTURE, encoding="ascii"
            )
            write_source_target_routing(root, _spec())
            result = _run_lean_relational(
                root, bundle=SOURCE_TARGET_ROUTING_AUDIT_MODULE
            )

        self.assertEqual(result["status"], "unchecked_marker", result)
        self.assertIn("SourceTargetRoutingFixture.lean", result["stderr"])
        self.assertNotIn("GeneratedSourceTargetRouting.lean", result["stderr"])
        output = result["stdout"] + result["stderr"]
        self.assertNotIn("sorryAx", output)
        self.assertIn("generatedTargetLocalEffectExact_3", output)
        self.assertIn("generatedTargetLocalEffectExact_7", output)


_LEAN_FIXTURE = r'''import StageA.RelationalSourceInterpreterKernel

namespace StageA.SourceTargetRoutingFixture

open StageA.Relational
open StageA.Relational.SourceWorld.InterpreterKernel

axiom program : Program

axiom target3SourceStep : MachineState -> EvaluatedStep
axiom target3DecodedBehavior : MachineState -> List Nat -> RelationalBehavior
axiom target3SourceStepExact : forall state,
  targetStep? program 3 state = some (target3SourceStep state)
axiom target3DecodedBehaviorExact : forall state calls,
  decodedWorldRegionBehaviorWithCalls program.worldProgram 3 state calls =
    some (target3DecodedBehavior state calls)
axiom target3EffectsExact : forall state calls,
  (target3SourceStep state).effect =
    evaluatedEffectOfBehavior state (target3DecodedBehavior state calls)

axiom target7SourceStep : MachineState -> EvaluatedStep
axiom target7DecodedBehavior : MachineState -> List Nat -> RelationalBehavior
axiom target7SourceStepExact : forall state,
  targetStep? program 7 state = some (target7SourceStep state)
axiom target7DecodedBehaviorExact : forall state calls,
  decodedWorldRegionBehaviorWithCalls program.worldProgram 7 state calls =
    some (target7DecodedBehavior state calls)
axiom target7EffectsExact : forall state calls,
  (target7SourceStep state).effect =
    evaluatedEffectOfBehavior state (target7DecodedBehavior state calls)

end StageA.SourceTargetRoutingFixture
'''


if __name__ == "__main__":
    unittest.main()
