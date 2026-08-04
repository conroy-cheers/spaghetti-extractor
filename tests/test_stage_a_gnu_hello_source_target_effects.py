from __future__ import annotations

import re
import shutil
import tempfile
import unittest
from pathlib import Path

from spaghetti_extractor.relational.lean.compiler import _run_lean_relational
from spaghetti_extractor_target_gnu_hello.gnu_hello_source_target_effects import (
    _ordinary_source,
)
from spaghetti_extractor_target_gnu_hello.gnu_hello_source_transition_index import (
    LeanDeclaration,
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


def _declaration(name: str) -> LeanDeclaration:
    module = "StageA.GnuHelloSourceTargetEffectsFixture"
    return LeanDeclaration(module=module, declaration=f"{module}.{name}")


@unittest.skipUnless(shutil.which("lean"), "Lean is required for kernel checks")
class GnuHelloSourceTargetEffectsTests(unittest.TestCase):
    def test_ordinary_replay_emits_transition_index_certificates(self) -> None:
        declarations = {
            name: _declaration(name)
            for name in (
                "region",
                "sourceExact",
                "classificationExact",
                "recordLookupExact",
                "regionExact",
                "pathRecordExact",
                "pathSourceExact",
                "regionStartExact",
                "regionStopExact",
                "nonX87",
                "recordMember",
                "notX87",
                "semanticReplayBuilder",
            )
        }
        declarations.update(
            {
                "source_exact": declarations.pop("sourceExact"),
                "classification_exact": declarations.pop(
                    "classificationExact"
                ),
                "record_lookup_exact": declarations.pop("recordLookupExact"),
                "region_exact": declarations.pop("regionExact"),
                "path_record_exact": declarations.pop("pathRecordExact"),
                "path_source_exact": declarations.pop("pathSourceExact"),
                "region_start_exact": declarations.pop("regionStartExact"),
                "region_stop_exact": declarations.pop("regionStopExact"),
                "non_x87": declarations.pop("nonX87"),
                "record_member": declarations.pop("recordMember"),
                "not_x87": declarations.pop("notX87"),
                "semantic_replay": declarations.pop("semanticReplayBuilder"),
            }
        )
        target = {
            "target_id": 3,
            "source_rva": 100,
            "ordinary_index": 0,
            "declarations": declarations,
            "dependencies": tuple(
                _declaration(name)
                for name in ("record", "transfer", "path", "normalization")
            ),
        }
        generated = _ordinary_source(
            target,
            "StageA.GnuHelloSourceTargetEffectsFixture",
        )
        for required in (
            "generatedOrdinary3Binding",
            "generatedOrdinary3Replay",
            "ExactOrdinaryTargetSemanticReplay",
            "generatedOrdinary3Decoded",
            "toCheckedOrdinaryTargetEffect",
            "generatedOrdinary3CheckedEffect",
            "generatedOrdinary3RecordMember",
            "generatedOrdinary3NotX87",
        ):
            self.assertIn(required, generated)
        self.assertNotRegex(
            generated,
            r"\b(?:axiom|opaque|sorry|admit|unsafe|native_decide|noncomputable)\b",
        )

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
                "RelationalSourceOrdinaryTargetRouting",
            )
            fixture = _FIXTURE_PREFIX + generated + _FIXTURE_SUFFIX
            (stage_a / "GnuHelloSourceTargetEffectsFixture.lean").write_text(
                fixture,
                encoding="utf-8",
            )
            result = _run_lean_relational(
                root,
                bundle="GnuHelloSourceTargetEffectsFixture",
            )

        # This wiring fixture supplies abstract upstream evidence as axioms;
        # the generated source itself is checked above for unchecked markers.
        self.assertEqual(result["status"], "unchecked_marker", result)
        output = result["stdout"] + result["stderr"]
        self.assertNotIn("sorryAx", output)
        self.assertIn("generatedOrdinary3CheckedEffect", output)


_FIXTURE_PREFIX = r'''import StageA.RelationalSourceOrdinaryTargetRouting

namespace StageA.GnuHelloSourceTargetEffectsFixture

open StageA.Formal StageA.Relational
open StageA.Relational.Interpreter
open StageA.Relational.InterpreterNormalization
open StageA.Relational.InterpreterSemanticRefinement
open StageA.Relational.SourceWorld.InterpreterKernel
open StageA.Relational.SourceWorld.OrdinaryTargetRouting

noncomputable section

axiom pe : PE32
axiom program : Program
axiom originalRole : program.worldProgram.candidate = false
axiom originalPeExact : program.worldProgram.context.originalPe = pe
axiom record : ProgramRecord
axiom transfer : SemanticTransfer
axiom path : ExactNormalizedTransferPath
axiom region : RegionRelation
axiom sourceExact : sourceRvaForTarget? program 3 = some 100
axiom classificationExact : x87Classified program 100 = some false
axiom recordLookupExact : lookupRecord? program.records 100 = some record
axiom regionExact : regionById program.worldProgram.regions 3 = some region
axiom pathRecordExact : path.record = record
axiom pathSourceExact : path.sourceRva = 100
axiom regionStartExact : region.original.start = path.sourceRva
axiom regionStopExact : region.original.stop = path.stopRva
axiom nonX87 :
  StageA.Relational.X87.spanStartsWithX87Command pe region.original = false
axiom normalization :
  ExactProgramRecordNormalizationCertificate pe path transfer
axiom recordMember : List.Mem record program.records
axiom notX87 : Not (List.Mem 100 program.x87SourceRvas)
axiom semanticReplayBuilder : forall
  (binding : ExactOrdinaryTargetBinding pe program 3 100 record path transfer
    region), ExactOrdinaryTargetSemanticReplay binding

abbrev generatedOriginalPe : PE32 := pe
abbrev generatedSourceProgram : Program := program
theorem generatedOriginalSide : generatedSourceProgram.worldProgram.candidate =
    false := originalRole
theorem generatedOriginalPeExact :
    generatedSourceProgram.worldProgram.context.originalPe =
      generatedOriginalPe := originalPeExact

'''

_FIXTURE_SUFFIX = r'''

#print axioms generatedOrdinary3CheckedEffect

end
end StageA.GnuHelloSourceTargetEffectsFixture
'''


if __name__ == "__main__":
    unittest.main()
