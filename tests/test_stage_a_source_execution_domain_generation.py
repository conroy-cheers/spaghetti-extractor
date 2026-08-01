from __future__ import annotations

import dataclasses
import re
import shutil
import tempfile
import unittest
from pathlib import Path

from spaghetti_extractor.relational.lean.compiler import _run_lean_relational
from spaghetti_extractor.relational.lean.source_execution_domain import (
    SOURCE_EXECUTION_DOMAIN_AUDIT_MODULE,
    SOURCE_EXECUTION_DOMAIN_MODULE,
    SourceExecutionDomainGenerationError,
    SourceExecutionDomainSpec,
    source_execution_domain_audit_source,
    source_execution_domain_source,
    write_source_execution_domain,
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


def _spec(**changes: object) -> SourceExecutionDomainSpec:
    base = SourceExecutionDomainSpec(
        imports=("StageA.SourceExecutionDomainGenerationFixture",),
        program="StageA.SourceExecutionDomainGenerationFixture.program",
        root="StageA.SourceExecutionDomainGenerationFixture.root",
        invariant="StageA.SourceExecutionDomainGenerationFixture.invariant",
        root_holds="StageA.SourceExecutionDomainGenerationFixture.rootHolds",
        blocks_excluded=(
            "StageA.SourceExecutionDomainGenerationFixture.blocksExcluded"
        ),
        raw_concretizable=(
            "StageA.SourceExecutionDomainGenerationFixture.rawConcretizable"
        ),
        instruction_semantics_adequate=(
            "StageA.SourceExecutionDomainGenerationFixture.adequate"
        ),
    )
    return dataclasses.replace(base, **changes)


class StageASourceExecutionDomainGenerationTests(unittest.TestCase):
    def test_generates_certificate_and_detached_audit(self) -> None:
        proof = source_execution_domain_source(_spec())
        audit = source_execution_domain_audit_source(_spec())

        for required in (
            "OriginalInvariantDomainCertificate",
            "invariant := StageA.SourceExecutionDomainGenerationFixture.invariant",
            "rootHolds := StageA.SourceExecutionDomainGenerationFixture.rootHolds",
            "blocksExcluded := StageA.SourceExecutionDomainGenerationFixture.blocksExcluded",
            "rawConcretizable := StageA.SourceExecutionDomainGenerationFixture.rawConcretizable",
            "DecodedSemanticStepsAdmissible",
            "RawEipLeftStepClosed",
        ):
            self.assertIn(required, proof)
        self.assertNotIn("#print axioms", proof)
        self.assertEqual(audit.count("#print axioms"), 4)
        self.assertIn(f"import StageA.{SOURCE_EXECUTION_DOMAIN_MODULE}", audit)

        for source in (proof, audit):
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

    def test_every_submitted_name_and_module_fails_closed(self) -> None:
        invalid: dict[str, object] = {
            "imports": ("Fixture",),
            "program": "program; axiom injected : False",
            "root": "by exact root",
            "invariant": "invariant -- comment",
            "root_holds": "proof term",
            "blocks_excluded": "blocks()",
            "raw_concretizable": "sorry",
            "instruction_semantics_adequate": "adequate value",
            "namespace": "StageA.Generated; end StageA",
            "output_module": "../Escaped",
            "audit_module": "StageA.Audit",
            "certificate_name": "StageA.certificate",
            "domain_name": "def",
            "decoded_admissibility_name": "decoded-admissible",
            "raw_eip_closure_name": "raw closure",
        }
        for field, value in invalid.items():
            with self.subTest(field=field):
                with self.assertRaisesRegex(
                    SourceExecutionDomainGenerationError, "canonical"
                ):
                    source_execution_domain_source(_spec(**{field: value}))

        for changes, message in (
            ({"imports": ()}, "at least one"),
            (
                {
                    "imports": (
                        "StageA.SourceExecutionDomainGenerationFixture",
                        "StageA.SourceExecutionDomainGenerationFixture",
                    )
                },
                "duplicates",
            ),
            (
                {"audit_module": SOURCE_EXECUTION_DOMAIN_MODULE},
                "must be distinct",
            ),
            (
                {"domain_name": "generatedOriginalInvariantDomainCertificate"},
                "declaration names must be distinct",
            ),
        ):
            with self.subTest(changes=changes):
                with self.assertRaisesRegex(
                    SourceExecutionDomainGenerationError, message
                ):
                    source_execution_domain_source(_spec(**changes))

    def test_writer_is_byte_reproducible(self) -> None:
        spec = _spec(
            output_module="GeneratedAlternateSourceExecutionDomain",
            audit_module="GeneratedAlternateSourceExecutionDomainAudit",
        )
        expected_proof = source_execution_domain_source(spec).encode("ascii")
        expected_audit = source_execution_domain_audit_source(spec).encode(
            "ascii"
        )
        with tempfile.TemporaryDirectory() as temporary:
            first = write_source_execution_domain(temporary, spec)
            first_bytes = (first.proof.read_bytes(), first.audit.read_bytes())
            second = write_source_execution_domain(temporary, spec)
            second_bytes = (second.proof.read_bytes(), second.audit.read_bytes())

        self.assertEqual(
            first.proof.name, "GeneratedAlternateSourceExecutionDomain.lean"
        )
        self.assertEqual(
            first.audit.name,
            "GeneratedAlternateSourceExecutionDomainAudit.lean",
        )
        self.assertEqual(first_bytes, (expected_proof, expected_audit))
        self.assertEqual(second_bytes, (expected_proof, expected_audit))

    @unittest.skipUnless(shutil.which("lean"), "Lean is required")
    def test_generated_proof_and_audit_compile_against_kernel(self) -> None:
        source_root = (
            Path(__file__).parents[1] / "src/spaghetti_extractor/lean/StageA"
        )
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            stage_a = root / "StageA"
            stage_a.mkdir()
            _copy_module_closure(
                source_root, stage_a, "RelationalSourceExecutionDomain"
            )
            _copy_module_closure(source_root, stage_a, "RelationalSourceRawEIP")
            (stage_a / "SourceExecutionDomainGenerationFixture.lean").write_text(
                _LEAN_FIXTURE, encoding="ascii"
            )
            write_source_execution_domain(root, _spec())
            result = _run_lean_relational(
                root, bundle=SOURCE_EXECUTION_DOMAIN_AUDIT_MODULE
            )

        # Only the synthetic provider owns axioms.  Both generated modules must
        # compile before the runner rejects that deliberate fixture marker.
        self.assertEqual(result["status"], "unchecked_marker", result)
        self.assertIn(
            "SourceExecutionDomainGenerationFixture.lean", result["stderr"]
        )
        self.assertNotIn(
            f"{SOURCE_EXECUTION_DOMAIN_MODULE}.lean", result["stderr"]
        )
        self.assertNotIn(
            f"{SOURCE_EXECUTION_DOMAIN_AUDIT_MODULE}.lean", result["stderr"]
        )
        output = result["stdout"] + result["stderr"]
        self.assertNotIn("sorryAx", output)
        self.assertNotIn("declaration uses 'sorry'", output)
        self.assertIn("generatedOriginalInvariantDomainCertificate", output)
        self.assertIn("generatedDecodedSemanticStepsAdmissible", output)
        self.assertIn("generatedRawEipLeftStepClosed", output)


_LEAN_FIXTURE = r'''import StageA.RelationalSourceExecutionDomain
import StageA.RelationalSourceRawEIP

namespace StageA.SourceExecutionDomainGenerationFixture

open StageA.Relational
open StageA.Relational.OriginalExecutionInvariant
open StageA.Relational.SourceWorld
open StageA.Relational.SourceWorld.InterpreterKernel

axiom program : DecodedWorldProgram
axiom root : WorldExecution
axiom invariant : OriginalWorldExecutionInvariant program
axiom rootHolds : invariant.holds root
axiom blocksExcluded : invariant.BlocksExcluded
axiom rawConcretizable : invariant.RawConcretizable
axiom adequate : program.InstructionSemanticsAdequate

end StageA.SourceExecutionDomainGenerationFixture
'''


if __name__ == "__main__":
    unittest.main()
