from __future__ import annotations

import dataclasses
import re
import shutil
import tempfile
import unittest
from pathlib import Path

from spaghetti_extractor.relational.lean.compiler import _run_lean_relational
from spaghetti_extractor.relational.lean.source_program_certificate import (
    SOURCE_PROGRAM_CERTIFICATE_MODULE,
    ActiveTargetCertificateSpec,
    SourceProgramCertificateGenerationError,
    SourceProgramCertificateSpec,
    source_program_certificate_source,
    write_source_program_certificate,
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


def _target(target_id: int) -> ActiveTargetCertificateSpec:
    return ActiveTargetCertificateSpec(
        target_id=target_id,
        selection_exact=(
            f"StageA.SourceCertificateFixture.selection{target_id}"
        ),
        local_effect_exact=(
            f"StageA.SourceCertificateFixture.localEffect{target_id}"
        ),
    )


def _spec(**changes: object) -> SourceProgramCertificateSpec:
    base = SourceProgramCertificateSpec(
        imports=("StageA.SourceCertificateFixture",),
        program="StageA.SourceCertificateFixture.program",
        exact_binding="StageA.SourceCertificateFixture.binding",
        domain="StageA.SourceCertificateFixture.domain",
        target_inventory="StageA.SourceCertificateFixture.targetIds",
        target_inventory_exact=(
            "StageA.SourceCertificateFixture.targetIdsExact"
        ),
        target_inventory_nodup=(
            "StageA.SourceCertificateFixture.targetIdsNodup"
        ),
        running_target_member=(
            "StageA.SourceCertificateFixture.runningTargetMember"
        ),
        callback_target_member=(
            "StageA.SourceCertificateFixture.callbackTargetMember"
        ),
        target_ids=(3, 7),
        targets=(_target(7), _target(3)),
    )
    return dataclasses.replace(base, **changes)


class StageASourceProgramCertificateGenerationTests(unittest.TestCase):
    def test_generates_deterministic_exact_bound_index_and_coverage(self) -> None:
        source = source_program_certificate_source(_spec())

        self.assertLess(
            source.index("generatedActiveTargetTransitionCertificate_3"),
            source.index("generatedActiveTargetTransitionCertificate_7"),
        )
        for required in (
            "ActiveTargetTransitionCertificate",
            "ActiveTargetTransitionCertificate.ofExactBound",
            "ExactBoundTargetStepEquality.ofSelectionAndRouting",
            "TargetLocalEffectExact.toWorldRoutingExact",
            "ActiveTargetTransitionIndex",
            "ExactBoundActiveTargetTransitionIndex",
            "ActiveTargetDomainCoverage.ofTargetMembership",
            "ProgramRecordKernelMatchesDecodedSemantics",
            "StageA.SourceCertificateFixture.binding",
            "StageA.SourceCertificateFixture.targetIdsExact",
            "StageA.SourceCertificateFixture.targetIdsNodup",
            "StageA.SourceCertificateFixture.runningTargetMember",
            "StageA.SourceCertificateFixture.callbackTargetMember",
        ):
            self.assertIn(required, source)

        self.assertNotIn("native_decide", source)
        for forbidden in (
            r"\baxiom\b",
            r"\bsorry\b",
            r"\badmit\b",
            r"\bunsafe\b",
            r"\bGNU\b",
            r"\bhello\b",
        ):
            self.assertNotRegex(source, forbidden)

    def test_missing_duplicate_and_unstable_targets_fail_closed(self) -> None:
        invalid_specs = (
            _spec(targets=(_target(3),)),
            _spec(targets=(_target(3), _target(3), _target(7))),
            _spec(target_ids=(7, 3)),
            _spec(target_ids=(3, 3, 7)),
            _spec(target_ids=(3, 7), targets=(_target(3), _target(9))),
        )
        for spec in invalid_specs:
            with self.subTest(spec=spec):
                with self.assertRaises(SourceProgramCertificateGenerationError):
                    source_program_certificate_source(spec)

    def test_all_submitted_declaration_names_fail_closed(self) -> None:
        invalid = {
            "imports": ("Fixture",),
            "program": "program; axiom injected : False",
            "exact_binding": "by exact binding",
            "domain": "domain -- comment",
            "target_inventory": "[3, 7]",
            "target_inventory_exact": "proof term",
            "target_inventory_nodup": "by decide",
            "running_target_member": "sorry",
            "callback_target_member": "callback()",
            "namespace": "StageA.Generated; end StageA",
            "output_module": "../Escaped",
            "index_name": "StageA.index",
        }
        for field, value in invalid.items():
            with self.subTest(field=field):
                with self.assertRaisesRegex(
                    SourceProgramCertificateGenerationError,
                    "canonical",
                ):
                    source_program_certificate_source(_spec(**{field: value}))

        malformed_target = dataclasses.replace(
            _target(3), local_effect_exact="by rfl"
        )
        with self.assertRaisesRegex(
            SourceProgramCertificateGenerationError,
            "canonical",
        ):
            source_program_certificate_source(
                _spec(targets=(malformed_target, _target(7)))
            )

    def test_writer_is_byte_reproducible(self) -> None:
        spec = _spec(output_module="GeneratedAlternateSourceCertificate")
        expected = source_program_certificate_source(spec).encode("ascii")
        with tempfile.TemporaryDirectory() as temporary:
            first = write_source_program_certificate(temporary, spec)
            first_bytes = first.read_bytes()
            second = write_source_program_certificate(temporary, spec)
            second_bytes = second.read_bytes()

        self.assertEqual(first.name, "GeneratedAlternateSourceCertificate.lean")
        self.assertEqual(first_bytes, expected)
        self.assertEqual(second_bytes, expected)

    @unittest.skipUnless(shutil.which("lean"), "Lean is required")
    def test_generated_module_compiles_against_kernel_interface(self) -> None:
        source_root = (
            Path(__file__).parents[1] / "src/spaghetti_extractor/lean/StageA"
        )
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            stage_a = root / "StageA"
            stage_a.mkdir()
            _copy_module_closure(
                source_root,
                stage_a,
                "RelationalSourceProgramCertificate",
            )
            (stage_a / "SourceCertificateFixture.lean").write_text(
                _LEAN_FIXTURE,
                encoding="ascii",
            )
            write_source_program_certificate(root, _spec())
            result = _run_lean_relational(
                root,
                bundle=SOURCE_PROGRAM_CERTIFICATE_MODULE,
            )

        # The synthetic provider declares its proof inputs as axioms so this
        # test can exercise only the generated module interface.  The runner
        # compiles both modules before correctly rejecting that fixture marker.
        self.assertEqual(result["status"], "unchecked_marker", result)
        self.assertIn("SourceCertificateFixture.lean", result["stderr"])
        self.assertNotIn(
            "GeneratedSourceProgramCertificate.lean", result["stderr"]
        )
        output = result["stdout"] + result["stderr"]
        self.assertNotIn("sorryAx", output)
        self.assertNotIn("declaration uses 'sorry'", output)
        self.assertIn("generatedActiveTargetIdsExact", output)
        self.assertIn(
            "generatedProgramRecordKernelMatchesDecodedSemantics",
            output,
        )


_LEAN_FIXTURE = r'''import StageA.RelationalSourceProgramCertificate

namespace StageA.SourceCertificateFixture

open StageA.Formal
open StageA.Relational
open StageA.Relational.SourceWorld
open StageA.Relational.SourceWorld.InterpreterKernel

axiom pe : PE32
axiom program : Program
axiom binding : ExactBinding pe program
axiom root : WorldExecution
axiom domain : CheckedExecutionDomain program.worldProgram root

def targetIds : List Nat := [3, 7]

theorem targetIdsExact : targetIds = [3, 7] := by rfl

theorem targetIdsNodup : targetIds.Nodup := by decide

axiom selection3 : BoundTargetSelection program 3
axiom localEffect3 : TargetLocalEffectExact program 3
axiom selection7 : BoundTargetSelection program 7
axiom localEffect7 : TargetLocalEffectExact program 7

axiom runningTargetMember : forall targetId state calls eventIndex world,
  domain.holds (.running targetId state calls eventIndex world) ->
    List.Mem targetId targetIds

axiom callbackTargetMember :
  forall targetId state calls eventIndex world callbacks,
    domain.holds
      (.callbackRunning targetId state calls eventIndex world callbacks) ->
      List.Mem targetId targetIds

end StageA.SourceCertificateFixture
'''


if __name__ == "__main__":
    unittest.main()
