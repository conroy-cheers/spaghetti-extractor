from __future__ import annotations

import re
import shutil
import tempfile
import unittest
from pathlib import Path

from tests.stage_a_relational_support import _pe32_tls_image

from spaghetti_extractor.relational.lean.common import (
    _lean_byte_tree_definitions,
    _lean_pe,
)
from spaghetti_extractor.relational.lean.compiler import _run_lean_relational
from spaghetti_extractor.relational.schema import RELATIONAL_APPROVED_AXIOMS
from spaghetti_extractor.stage_binary import _parse_stage_a_pe


_IMPORT = re.compile(r"^import StageA\.([A-Za-z0-9_]+)$", re.MULTILINE)
_AXIOM_REPORT = re.compile(r"depends on axioms:\s*\[([^]]*)\]", re.DOTALL)


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


def _pe_literal(root: Path, name: str, image: bytes) -> tuple[str, str]:
    path = root / f"{name}.exe"
    path.write_bytes(image)
    binary = _parse_stage_a_pe(path)
    try:
        bytes_name = f"{name}Bytes"
        definitions = _lean_byte_tree_definitions(bytes_name, image)
        literal = _lean_pe(binary, bytes_name)
    finally:
        binary.pe.close()
    return definitions, literal


class StageARelationalInterpreterMixedLaunchAnchorTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.source = (
            Path(__file__).parents[1]
            / "src/spaghetti_extractor/lean/StageA"
            / "RelationalInterpreterMixedProfile.lean"
        ).read_text(encoding="utf-8")

    def test_constructor_is_parser_derived_and_keeps_validity_separate(self) -> None:
        start = self.source.index("def canonicalMixedLaunchAnchors?")
        end = self.source.index(
            "/-- Successful construction is sufficient", start
        )
        constructor = self.source[start:end]
        self.assertIn("candidatePELaunchRoots? candidate.pe", constructor)
        self.assertIn("roots.tlsCallbackRvas.length", constructor)
        self.assertIn("launch.rootTargetId != launch.initialTargetId", constructor)
        self.assertIn("candidatePELaunchRootsAddressable", constructor)
        self.assertIn("mixedNativeLaunchAnchorInventory", constructor)
        self.assertNotIn("MixedNativeLaunchAnchorsComplete", constructor)
        self.assertNotIn("MixedNativeCodeAnchorsValid", constructor)

    def test_completeness_theorem_consumes_exact_original_root_evidence(self) -> None:
        start = self.source.index("theorem canonicalMixedLaunchAnchors?_complete")
        end = self.source.index("def mixedRangeDisjointFromImages", start)
        theorem = self.source[start:end]
        self.assertIn("DirectExactOriginalDecodedLaunchRoot original launch", theorem)
        self.assertIn("originalRoot.initialExact", theorem)
        self.assertIn(
            "MixedNativeLaunchAnchorsComplete candidate launch anchors = true",
            theorem,
        )
        for forbidden in ("native_decide", "sorry", "axiom ", "opaque "):
            self.assertNotIn(forbidden, theorem)

    @unittest.skipUnless(shutil.which("lean"), "Lean is required for kernel checks")
    def test_constructor_and_fail_closed_cases_kernel_check(self) -> None:
        source_root = (
            Path(__file__).parents[1]
            / "src/spaghetti_extractor/lean/StageA"
        )
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            stage_a = root / "StageA"
            stage_a.mkdir()
            _copy_module_closure(
                source_root, stage_a, "RelationalInterpreterMixedProfile"
            )

            valid_defs, valid_pe = _pe_literal(
                root, "valid", _pe32_tls_image((0x1020, 0x1010))
            )
            mutable_defs, mutable_pe = _pe_literal(
                root,
                "mutable",
                _pe32_tls_image(
                    (0x1020, 0x1010), callback_array_writable=True
                ),
            )
            malformed_defs, malformed_pe = _pe_literal(
                root,
                "malformed",
                _pe32_tls_image((0x1020,), terminate_callbacks=False),
            )
            absent_defs, absent_pe = _pe_literal(
                root, "absent", _pe32_tls_image((), include_tls=False)
            )
            duplicate_defs, duplicate_pe = _pe_literal(
                root, "duplicate", _pe32_tls_image((0x1020, 0x1020))
            )
            fixture = _KERNEL_FIXTURE.format(
                valid_defs=valid_defs,
                valid_pe=valid_pe,
                mutable_defs=mutable_defs,
                mutable_pe=mutable_pe,
                malformed_defs=malformed_defs,
                malformed_pe=malformed_pe,
                absent_defs=absent_defs,
                absent_pe=absent_pe,
                duplicate_defs=duplicate_defs,
                duplicate_pe=duplicate_pe,
            )
            (
                stage_a
                / "RelationalInterpreterMixedLaunchAnchorsKernel.lean"
            ).write_text(fixture, encoding="utf-8")
            result = _run_lean_relational(
                root, bundle="RelationalInterpreterMixedLaunchAnchorsKernel"
            )

        self.assertEqual(result["status"], "checked", result)
        output = result["stdout"] + result["stderr"]
        self.assertNotIn("sorryAx", output)
        self.assertNotIn("native_decide.ax", output)
        reports = _AXIOM_REPORT.findall(output)
        self.assertGreaterEqual(len(reports), 1, output)
        for report in reports:
            used = {item.strip() for item in report.split(",") if item.strip()}
            self.assertLessEqual(used, RELATIONAL_APPROVED_AXIOMS, report)


_KERNEL_FIXTURE = r"""import StageA.RelationalInterpreterMixedProfile

namespace StageA.Relational.InterpreterMixedLaunchAnchorsKernel

set_option maxRecDepth 1000000
set_option maxHeartbeats 0

open StageA.Formal StageA.Relational
open StageA.Relational.InterpreterMixedContext
open StageA.Relational.InterpreterMixedProfile
open StageA.Relational.InterpreterMixedWorldBridge
open StageA.Relational.InterpreterNativeLaunch
open StageA.Relational.InterpreterNativeWorld

{valid_defs}
{mutable_defs}
{malformed_defs}
{absent_defs}
{duplicate_defs}

def validPe : PE32 := {valid_pe}
def mutablePe : PE32 := {mutable_pe}
def malformedPe : PE32 := {malformed_pe}
def absentPe : PE32 := {absent_pe}
def duplicatePe : PE32 := {duplicate_pe}

def blockingEnvironment : NativeWorldEnvironment := {{
  action := fun _ _ _ => .blocked (.unclassifiedNativeFault 0)
}}

def candidate (pe : PE32) : ExactNativeWorldProgram := {{
  pe
  imports := []
  environment := blockingEnvironment
}}

def validLaunch : PE32ConsoleLaunchV2 := {{
  rootNodeId := 10
  rootTargetId := 10
  entryNodeId := 20
  entryTargetId := 20
  tlsCallbackNodeIds := [10, 11]
  tlsCallbackTargetIds := [10, 11]
  rootInvariant := {{ registerRelations := [] }}
  frameOffsets := []
}}

def wrongCountLaunch : PE32ConsoleLaunchV2 :=
  {{ validLaunch with
    tlsCallbackNodeIds := [10]
    tlsCallbackTargetIds := [10]
  }}

def wrongRootLaunch : PE32ConsoleLaunchV2 :=
  {{ validLaunch with rootTargetId := 99 }}

def noTlsLaunch : PE32ConsoleLaunchV2 := {{
  rootNodeId := 20
  rootTargetId := 20
  entryNodeId := 20
  entryTargetId := 20
  tlsCallbackNodeIds := []
  tlsCallbackTargetIds := []
  rootInvariant := {{ registerRelations := [] }}
  frameOffsets := []
}}

def expectedAnchors : List MixedNativeCodeAnchor := [
  {{ originalTargetId := 20, candidateRva := 0x1000 }},
  {{ originalTargetId := 10, candidateRva := 0x1020 }},
  {{ originalTargetId := 11, candidateRva := 0x1010 }}
]

example :
    canonicalMixedLaunchAnchors? (candidate validPe) validLaunch =
      some expectedAnchors := by
  decide +kernel

example :
    MixedNativeLaunchAnchorsComplete (candidate validPe) validLaunch
      expectedAnchors = true := by
  decide +kernel

example :
    canonicalMixedLaunchAnchors? (candidate validPe) wrongCountLaunch = none := by
  decide +kernel

example :
    canonicalMixedLaunchAnchors? (candidate validPe) wrongRootLaunch = none := by
  decide +kernel

example :
    canonicalMixedLaunchAnchors?
      (candidate {{ validPe with entrypointRva := 0 }}) validLaunch = none := by
  decide +kernel

example :
    canonicalMixedLaunchAnchors? (candidate mutablePe) validLaunch = none := by
  decide +kernel

example :
    candidatePELaunchRoots? malformedPe = none := by
  decide +kernel

example :
    canonicalMixedLaunchAnchors? (candidate malformedPe) wrongCountLaunch =
      none := by
  decide +kernel

def overflowingPe : PE32 :=
  {{ absentPe with imageBase := 0xfffff000, sizeOfImage := 0x3000 }}

example :
    candidatePELaunchRoots? overflowingPe =
      some {{ entryRva := 0x1000, tlsCallbackRvas := [] }} := by
  decide +kernel

example :
    canonicalMixedLaunchAnchors? (candidate overflowingPe) noTlsLaunch = none := by
  decide +kernel

example :
    (canonicalMixedLaunchAnchors? (candidate duplicatePe) validLaunch).map
      (fun anchors => decide (anchors.map (·.candidateRva)).Nodup) =
        some false := by
  decide +kernel

example
    {{original : OriginalDecodedStaticContext}}
    {{launch : PE32ConsoleLaunchV2}}
    (originalRoot : DirectExactOriginalDecodedLaunchRoot original launch)
    {{anchors : List MixedNativeCodeAnchor}}
    (built :
      canonicalMixedLaunchAnchors? (candidate validPe) launch = some anchors) :
    MixedNativeLaunchAnchorsComplete (candidate validPe) launch anchors = true :=
  canonicalMixedLaunchAnchors?_complete originalRoot built

#print axioms canonicalMixedLaunchAnchors?_complete

end StageA.Relational.InterpreterMixedLaunchAnchorsKernel
"""


if __name__ == "__main__":
    unittest.main()
