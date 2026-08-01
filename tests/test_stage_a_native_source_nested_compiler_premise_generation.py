from __future__ import annotations

import dataclasses
import re
import shutil
import tempfile
import unittest
from pathlib import Path

from spaghetti_extractor.relational.lean.compiler import _run_lean_relational
from spaghetti_extractor.relational.lean.native_source_nested_compiler_premise import (
    NATIVE_SOURCE_NESTED_COMPILER_PREMISE_AUDIT_MODULE,
    NATIVE_SOURCE_NESTED_COMPILER_PREMISE_MODULE,
    NativeSourceNestedCompilerPremiseGenerationError,
    NativeSourceNestedCompilerPremiseSpec,
    native_source_nested_compiler_premise_audit_source,
    native_source_nested_compiler_premise_source,
    write_native_source_nested_compiler_premise,
)


_IMPORT = re.compile(r"^import StageA\.([A-Za-z0-9_]+)$", re.MULTILINE)
_FIXTURE_MODULE = "StageA.NativeSourceNestedCompilerPremiseFixture"
_FIXTURE_PREMISE = (
    "StageA.NativeSourceNestedCompilerPremiseFixture."
    "PinnedNestedCompilerStackPremise"
)


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


def _spec(**changes: object) -> NativeSourceNestedCompilerPremiseSpec:
    return dataclasses.replace(
        NativeSourceNestedCompilerPremiseSpec(
            response_family_module=_FIXTURE_MODULE,
            premise_type=_FIXTURE_PREMISE,
        ),
        **changes,
    )


class StageANativeSourceNestedCompilerPremiseGenerationTests(
    unittest.TestCase
):
    def test_emits_exactly_one_canonical_compiler_axiom(self) -> None:
        spec = _spec()
        source = native_source_nested_compiler_premise_source(spec)

        self.assertTrue(source.startswith(f"import {_FIXTURE_MODULE}\n"))
        self.assertEqual(
            len(re.findall(r"(?m)^axiom\s", source)),
            1,
        )
        self.assertEqual(
            source.count("axiom pinnedCompilerLoweringCorrect"),
            1,
        )
        self.assertIn(f"  {_FIXTURE_PREMISE}\n", source)
        for forbidden in (
            r"\bsorry\b",
            r"\badmit\b",
            r"\bunsafe\b",
            r"\bnative_decide\b",
            r"\bstatus\b",
            r"\bproof_authority\b",
            r"\bacceptance_authority\b",
        ):
            self.assertNotRegex(source, forbidden)

    def test_detached_audit_names_only_the_compiler_axiom(self) -> None:
        source = native_source_nested_compiler_premise_audit_source(_spec())

        self.assertEqual(
            source,
            "import StageA.GeneratedNativeSourceNestedCompilerPremise\n\n"
            "#print axioms "
            "StageA.GeneratedRelational.NativeSourceNestedCompilerPremise."
            "pinnedCompilerLoweringCorrect\n",
        )
        self.assertEqual(source.count("#print axioms"), 1)

    def test_canonical_module_and_declaration_names_fail_closed(self) -> None:
        malformed = (
            _spec(response_family_module="Fixture"),
            _spec(response_family_module="StageA.Fixture; import StageA.Bad"),
            _spec(premise_type="PinnedNestedCompilerStackPremise"),
            _spec(premise_type="StageA.Fixture.Premise -- injected"),
            _spec(namespace="StageA.Generated; end StageA"),
            _spec(output_module="../Escaped"),
            _spec(audit_output_module="Audit.Module"),
            _spec(axiom_name="compilerCorrect"),
            _spec(
                output_module="GeneratedSameModule",
                audit_output_module="GeneratedSameModule",
            ),
        )
        for spec in malformed:
            with self.subTest(spec=spec):
                with self.assertRaises(
                    NativeSourceNestedCompilerPremiseGenerationError
                ):
                    native_source_nested_compiler_premise_source(spec)

    def test_schema_cannot_carry_status_or_extra_axioms(self) -> None:
        with self.assertRaises(TypeError):
            NativeSourceNestedCompilerPremiseSpec(
                response_family_module=_FIXTURE_MODULE,
                premise_type=_FIXTURE_PREMISE,
                status="pass",
            )
        with self.assertRaises(TypeError):
            dataclasses.replace(_spec(), extra_axiom="unchecked")

    def test_writer_is_byte_reproducible_and_ascii(self) -> None:
        spec = _spec(
            output_module="GeneratedAlternateNestedCompilerPremise",
            audit_output_module=(
                "GeneratedAlternateNestedCompilerPremiseAudit"
            ),
        )
        expected = (
            native_source_nested_compiler_premise_source(spec).encode("ascii"),
            native_source_nested_compiler_premise_audit_source(spec).encode(
                "ascii"
            ),
        )
        with tempfile.TemporaryDirectory() as temporary:
            first = write_native_source_nested_compiler_premise(temporary, spec)
            first_bytes = tuple(path.read_bytes() for path in first)
            second = write_native_source_nested_compiler_premise(temporary, spec)
            second_bytes = tuple(path.read_bytes() for path in second)

        self.assertEqual(
            tuple(path.name for path in first),
            (
                "GeneratedAlternateNestedCompilerPremise.lean",
                "GeneratedAlternateNestedCompilerPremiseAudit.lean",
            ),
        )
        self.assertEqual(first_bytes, expected)
        self.assertEqual(second_bytes, first_bytes)

    @unittest.skipUnless(shutil.which("lean"), "Lean is required")
    def test_generated_premise_and_detached_audit_compile(self) -> None:
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
                "RelationalNativeSourceNestedAdmittedResponseFamily",
            )
            (stage_a / "NativeSourceNestedCompilerPremiseFixture.lean").write_text(
                _LEAN_FIXTURE,
                encoding="ascii",
            )
            write_native_source_nested_compiler_premise(root, _spec())
            premise = _run_lean_relational(
                root, bundle=NATIVE_SOURCE_NESTED_COMPILER_PREMISE_MODULE
            )
            audit = _run_lean_relational(
                root,
                bundle=NATIVE_SOURCE_NESTED_COMPILER_PREMISE_AUDIT_MODULE,
            )

        self.assertEqual(premise["status"], "unchecked_marker", premise)
        self.assertEqual(audit["status"], "unchecked_marker", audit)
        output = (
            premise["stdout"]
            + premise["stderr"]
            + audit["stdout"]
            + audit["stderr"]
        )
        self.assertNotIn("declaration uses 'sorry'", output)
        self.assertNotIn(
            "GeneratedNativeSourceNestedCompilerPremise.lean:", output
        )
        self.assertNotIn(
            "GeneratedNativeSourceNestedCompilerPremiseAudit.lean:", output
        )
        self.assertIn("pinnedCompilerLoweringCorrect", output)


_LEAN_FIXTURE = r'''import StageA.RelationalNativeSourceNestedAdmittedResponseFamily

namespace StageA.NativeSourceNestedCompilerPremiseFixture

open StageA.Relational
open StageA.Relational.InterpreterMixedContext
open StageA.Relational.InterpreterMixedEnvironment
open StageA.Relational.NativeSource

axiom context : StaticProofContext
axiom classifiedSites : List CheckedMachineExternalSite
axiom ordinarySites : List OpaqueLockstepCallSite
axiom staticCompilation : ExactNativeCompilation
axiom mixedContract : MixedRelationContract
axiom nestedFrames : MixedNestedExternalFrameContract
axiom responseFamily :
  CheckedWorldNativeAdmittedProtocolResponseFamily context classifiedSites
    ordinarySites staticCompilation mixedContract nestedFrames

abbrev PairRelated := responseFamily.Related

abbrev PinnedNestedCompilerStackPremise :=
  forall sourceEnvironment nativeEnvironment,
    PairRelated sourceEnvironment nativeEnvironment ->
      CorrectPinnedNestedNativeSourceStackHypothesis
        (exactNativeCompilationAtResponseEnvironments staticCompilation
          sourceEnvironment nativeEnvironment.ordinary)
        (exactNestedNativeCompilationAtResponseEnvironments staticCompilation
          sourceEnvironment nativeEnvironment)

end StageA.NativeSourceNestedCompilerPremiseFixture
'''


if __name__ == "__main__":
    unittest.main()
