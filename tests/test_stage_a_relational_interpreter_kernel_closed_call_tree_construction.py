from __future__ import annotations

import re
import shutil
import tempfile
import unittest
from pathlib import Path

from spaghetti_extractor.relational.lean.compiler import _run_lean_relational
from spaghetti_extractor.relational.lean.interpreter_kernel_closed_call_tree import (
    INTERPRETER_KERNEL_CLOSED_CALL_TREE_FORMAT,
    INTERPRETER_KERNEL_CLOSED_CALL_TREE_LEAN_FILENAME,
    ClosedCallTreeCallSpec,
    ExactCheckedSemanticFunctionSpec,
    RelationalInterpreterKernelClosedCallTreeGenerationError,
    build_relational_interpreter_kernel_closed_call_tree_plan,
    exact_checked_semantic_function_specs_from_record_packs,
    relational_interpreter_kernel_closed_call_tree_source,
    write_relational_interpreter_kernel_closed_call_tree_bundle,
)


_IMPORT = re.compile(r"^import StageA\.([A-Za-z0-9_]+)$", re.MULTILINE)
_AXIOMS = re.compile(r"depends on axioms:\s*\[([^]]*)\]", re.DOTALL)
_APPROVED_AXIOMS = {"propext", "Quot.sound", "Classical.choice"}


def _function(
    name: str,
    source_rva: int,
    rank: int | None = None,
    *,
    calls: tuple[ClosedCallTreeCallSpec, ...] = (),
) -> ExactCheckedSemanticFunctionSpec:
    return ExactCheckedSemanticFunctionSpec(
        name=name,
        source_rva=source_rva,
        rank=rank,
        program_record=f"{name}Record",
        semantic_transfer=f"{name}Transfer",
        lookup_exact=f"{name}LookupExact",
        decode_exact=f"{name}DecodeExact",
        checked_exact=f"{name}CheckedExact",
        calls=calls,
    )


def _plan(
    functions: tuple[ExactCheckedSemanticFunctionSpec, ...],
):
    return build_relational_interpreter_kernel_closed_call_tree_plan(
        source_module="GeneratedClosedCallTreeFixture",
        records_term="semanticRecords",
        functions=functions,
    )


def _copy_module_closure(
    source_root: Path, destination: Path, module: str
) -> None:
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


class StageARelationalInterpreterKernelClosedCallTreeConstructionTests(
    unittest.TestCase
):
    def test_generic_constructor_exposes_rank_free_finite_evidence(
        self,
    ) -> None:
        source = (
            Path(__file__).parents[1]
            / "src/spaghetti_extractor/lean/StageA"
            / "RelationalInterpreterKernelClosedCallTree.lean"
        ).read_text(encoding="utf-8")
        construction = source.split(
            "/-! ## Rank-free construction from finite nested evidence", 1
        )[1].split(
            "/-! ## Well-founded construction from exact semantic records", 1
        )[0]

        for required in (
            "inductive FiniteCheckedRunFunctionEvidence",
            "inductive FiniteCheckedInvokeCallEvidence",
            "run : AbstractRunFunction",
            "targetExact : resolveCodeTarget event.targetRva = some target",
            "toCheckedRunFunctionDerivation",
            "toCheckedInvokeCallDerivation",
        ):
            self.assertIn(required, construction)
        for forbidden in (
            "KernelOperationRefinesUsing",
            "CheckedSemanticCallRanking",
            "ranking.",
            "GNU",
            "axiom ",
            "sorry",
            "unsafe ",
            "environmentExact : environment.invokeCall event state = result",
        ):
            self.assertNotIn(forbidden, construction)

    def test_builds_finite_nested_generic_function_inventory(self) -> None:
        leaf = _function("leaf", 0x200)
        root = _function(
            "root",
            0x100,
            calls=(
                ClosedCallTreeCallSpec(0, "external"),
                ClosedCallTreeCallSpec(1, "internal", 0x200),
                ClosedCallTreeCallSpec(
                    2,
                    "indirect",
                    0x200,
                ),
            ),
        )

        plan = _plan((leaf, root))
        payload = plan.payload()

        self.assertEqual(
            payload["format"], INTERPRETER_KERNEL_CLOSED_CALL_TREE_FORMAT
        )
        self.assertFalse(payload["acceptance_authority"])
        self.assertEqual(
            payload["control_mode"],
            "finite-nested-semantic-evidence",
        )
        self.assertEqual(
            [function.source_rva for function in plan.functions],
            [0x100, 0x200],
        )
        self.assertIn(
            "rank_free_checked_call_tree_construction",
            payload["closed_components"],
        )
        self.assertNotIn("rank", payload["functions"][0])
        self.assertEqual(
            payload["remaining_proof_premises"],
            [],
        )

    def test_builds_exact_inventory_from_checked_semantic_record_packs(
        self,
    ) -> None:
        functions = exact_checked_semantic_function_specs_from_record_packs(
            source_rvas=(0x100, 0x200, 0x300),
            shard_size=2,
            calls_by_source_rva={
                0x100: (ClosedCallTreeCallSpec(0, "internal", 0x300),)
            },
        )

        self.assertEqual(
            [function.name for function in functions],
            ["function0000", "function0001", "function0002"],
        )
        self.assertEqual(
            functions[2].program_record,
            "StageA.GeneratedRelational.InterpreterKernelData."
            "generatedInterpreterKernelSemanticRecordPack0001Entry0000.record",
        )
        self.assertEqual(
            functions[2].semantic_transfer,
            "StageA.GeneratedRelational.InterpreterKernelData."
            "generatedInterpreterKernelSemanticRecordPack0001Entry0000."
            "semantic.transfer",
        )
        self.assertEqual(functions[0].calls[0].target_source_rva, 0x300)

        with self.assertRaisesRegex(
            RelationalInterpreterKernelClosedCallTreeGenerationError,
            "unknown source RVA",
        ):
            exact_checked_semantic_function_specs_from_record_packs(
                source_rvas=(0x100,),
                shard_size=64,
                calls_by_source_rva={
                    0x200: (ClosedCallTreeCallSpec(0, "external"),)
                },
            )

    def test_rejects_unresolved_targets(self) -> None:
        with self.assertRaisesRegex(
            RelationalInterpreterKernelClosedCallTreeGenerationError,
            "target RVA",
        ):
            _plan(
                (
                    _function(
                        "root",
                        0x100,
                        calls=(
                            ClosedCallTreeCallSpec(0, "indirect"),
                        ),
                    ),
                    _function("leaf", 0x200),
                )
            )

        with self.assertRaisesRegex(
            RelationalInterpreterKernelClosedCallTreeGenerationError,
            "unresolved indirect call",
        ):
            _plan(
                (
                    _function(
                        "root",
                        0x100,
                        calls=(
                            ClosedCallTreeCallSpec(
                                0,
                                "indirect",
                                0x300,
                            ),
                        ),
                    ),
                )
            )

        with self.assertRaisesRegex(
            RelationalInterpreterKernelClosedCallTreeGenerationError,
            "unresolved internal call",
        ):
            _plan(
                (
                    _function(
                        "root",
                        0x100,
                        calls=(
                            ClosedCallTreeCallSpec(
                                0,
                                "internal",
                                0x300,
                            ),
                        ),
                    ),
                )
            )

    def test_accepts_recursive_graphs_and_ignores_legacy_ranks(self) -> None:
        first = _function(
            "first",
            0x100,
            -1,
            calls=(ClosedCallTreeCallSpec(0, "internal", 0x200),),
        )
        second = _function(
            "second",
            0x200,
            999,
            calls=(ClosedCallTreeCallSpec(0, "internal", 0x100),),
        )
        plan = _plan((first, second))

        self.assertEqual(
            [function.source_rva for function in plan.functions],
            [0x100, 0x200],
        )
        self.assertEqual(
            [function.rank for function in plan.functions],
            [None, None],
        )
        self.assertTrue(
            all("rank" not in function for function in plan.payload()["functions"])
        )

    def test_source_uses_exact_records_and_checked_constructors(self) -> None:
        source = relational_interpreter_kernel_closed_call_tree_source(
            _plan(
                (
                    _function(
                        "root",
                        0x100,
                        calls=(
                            ClosedCallTreeCallSpec(
                                0, "internal", 0x200
                            ),
                            ClosedCallTreeCallSpec(
                                1,
                                "indirect",
                                0x200,
                            ),
                        ),
                    ),
                    _function("leaf", 0x200),
                )
            )
        )

        for required in (
            "GeneratedExactCheckedSemanticFunctionInventory",
            "function0000LookupExact :",
            "function0000DecodeExact :",
            "function0000CheckedExact :",
            "GeneratedFiniteCheckedSemanticFunctionBindings",
            "generatedFiniteCheckedSemanticFunctionBindings",
            "GeneratedFiniteCheckedSemanticFunctionBindings.toClosure",
            "CheckedSemanticCallTreeClosure",
            "checkedSemanticCallTreeClosure semanticRecords",
        ):
            self.assertIn(required, source)
        for forbidden in (
            "CheckedSemanticCallRanking",
            "Nat.lt_wfRel.wf",
            "generatedClosedCallTreeRank",
            "Decreases",
            "ExactCheckedRunFunctionRecord",
            "ExactCheckedSemanticFunctionRecords",
            "GeneratedExactCheckedSemanticFunctionDomains",
            "GeneratedClosedCallTreeAvailable",
            "KernelOperationRefinesUsing",
            "statusExact",
            "status :=",
            "universal",
            "GNU",
            "native_decide",
            "axiom ",
            "sorry",
            "unsafe ",
        ):
            self.assertNotIn(forbidden, source)

    def test_writer_is_deterministic(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            first = root / "first"
            second = root / "second"
            kwargs = {
                "source_module": "GeneratedClosedCallTreeFixture",
                "records_term": "semanticRecords",
                "functions": (_function("leaf", 0x200),),
            }
            write_relational_interpreter_kernel_closed_call_tree_bundle(
                out=first, **kwargs
            )
            write_relational_interpreter_kernel_closed_call_tree_bundle(
                out=second, **kwargs
            )

            self.assertEqual(
                sorted(path.name for path in first.iterdir()),
                sorted(path.name for path in second.iterdir()),
            )
            for path in first.iterdir():
                self.assertEqual(
                    path.read_bytes(), (second / path.name).read_bytes()
                )


@unittest.skipUnless(shutil.which("lean"), "Lean is required")
class StageARelationalInterpreterKernelClosedCallTreeGeneratedLeanTests(
    unittest.TestCase
):
    def test_generated_finite_evidence_catalog_compiles_without_bad_axioms(
        self,
    ) -> None:
        fixture = """import StageA.RelationalInterpreterKernelClosedCallTree

namespace StageA.GeneratedClosedCallTreeFixture

open StageA.Relational.Interpreter
open StageA.Relational.InterpreterKernel

def fixtureRecord : ProgramRecord := {
  sourceRva := 256
  wordNodes := [
    { op := 0, arity := 0, aux := 0, immediate := 7, args := [] }
  ]
  x87Nodes := []
  calls := []
  actions := [
    { op := 0, arity := 1, aux := 0, args := [0] },
    { op := 22, arity := 1, aux := 0, args := [0] }
  ]
}

def fixtureTransfer : SemanticTransfer := {
  sourceRva := 256
  wordNodes := [
    { op := .constant, aux := 0, immediate := 7, args := [] }
  ]
  calls := []
  body := [.evalWord 0]
  outcome := .returned 0
}

def leafRecord : ProgramRecord := {
  sourceRva := 512
  wordNodes := [
    { op := 0, arity := 0, aux := 0, immediate := 9, args := [] }
  ]
  x87Nodes := []
  calls := []
  actions := [
    { op := 0, arity := 1, aux := 0, args := [0] },
    { op := 22, arity := 1, aux := 0, args := [0] }
  ]
}

def leafTransfer : SemanticTransfer := {
  sourceRva := 512
  wordNodes := [
    { op := .constant, aux := 0, immediate := 9, args := [] }
  ]
  calls := []
  body := [.evalWord 0]
  outcome := .returned 0
}

def semanticRecords : List ProgramRecord := [fixtureRecord, leafRecord]

theorem fixtureLookupExact :
    lookupProgramRecord semanticRecords 256 = some fixtureRecord := by
  decide

theorem fixtureDecodeExact :
    fixtureRecord.decode = some fixtureTransfer := by
  decide

theorem fixtureCheckedExact :
    fixtureTransfer.checked = true := by
  decide

theorem leafLookupExact :
    lookupProgramRecord semanticRecords 512 = some leafRecord := by
  decide

theorem leafDecodeExact :
    leafRecord.decode = some leafTransfer := by
  decide

theorem leafCheckedExact :
    leafTransfer.checked = true := by
  decide

end StageA.GeneratedClosedCallTreeFixture
"""
        function = ExactCheckedSemanticFunctionSpec(
            name="fixture",
            source_rva=0x100,
            program_record=(
                "StageA.GeneratedClosedCallTreeFixture.fixtureRecord"
            ),
            semantic_transfer=(
                "StageA.GeneratedClosedCallTreeFixture.fixtureTransfer"
            ),
            lookup_exact=(
                "StageA.GeneratedClosedCallTreeFixture.fixtureLookupExact"
            ),
            decode_exact=(
                "StageA.GeneratedClosedCallTreeFixture.fixtureDecodeExact"
            ),
            checked_exact=(
                "StageA.GeneratedClosedCallTreeFixture.fixtureCheckedExact"
            ),
            calls=(
                ClosedCallTreeCallSpec(0, "internal", 0x200),
                ClosedCallTreeCallSpec(
                    1,
                    "indirect",
                    0x200,
                ),
            ),
        )
        leaf = ExactCheckedSemanticFunctionSpec(
            name="leaf",
            source_rva=0x200,
            program_record=(
                "StageA.GeneratedClosedCallTreeFixture.leafRecord"
            ),
            semantic_transfer=(
                "StageA.GeneratedClosedCallTreeFixture.leafTransfer"
            ),
            lookup_exact=(
                "StageA.GeneratedClosedCallTreeFixture.leafLookupExact"
            ),
            decode_exact=(
                "StageA.GeneratedClosedCallTreeFixture.leafDecodeExact"
            ),
            checked_exact=(
                "StageA.GeneratedClosedCallTreeFixture.leafCheckedExact"
            ),
        )
        plan = build_relational_interpreter_kernel_closed_call_tree_plan(
            source_module="GeneratedClosedCallTreeFixture",
            records_term=(
                "StageA.GeneratedClosedCallTreeFixture.semanticRecords"
            ),
            functions=(function, leaf),
        )

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            stage_a = root / "StageA"
            stage_a.mkdir()
            source_root = (
                Path(__file__).parents[1]
                / "src/spaghetti_extractor/lean/StageA"
            )
            _copy_module_closure(
                source_root,
                stage_a,
                "RelationalInterpreterKernelClosedCallTree",
            )
            (
                stage_a / "GeneratedClosedCallTreeFixture.lean"
            ).write_text(fixture, encoding="ascii")
            generated = (
                stage_a / INTERPRETER_KERNEL_CLOSED_CALL_TREE_LEAN_FILENAME
            )
            generated.write_text(
                relational_interpreter_kernel_closed_call_tree_source(plan),
                encoding="ascii",
            )
            result = _run_lean_relational(
                root,
                bundle=generated.stem,
            )

        self.assertEqual(result["status"], "checked", result)
        output = result["stdout"] + result["stderr"]
        self.assertNotIn("sorryAx", output)
        self.assertNotIn("native_decide.ax", output)
        self.assertNotIn("declaration uses 'sorry'", output)
        for match in _AXIOMS.findall(output):
            axioms = {
                item.strip() for item in match.split(",") if item.strip()
            }
            self.assertLessEqual(axioms, _APPROVED_AXIOMS)
        for theorem in (
            "generatedExactCheckedSemanticFunctionInventory",
            "generatedFiniteCheckedSemanticFunctionBindings",
            "GeneratedFiniteCheckedSemanticFunctionBindings.toClosure",
        ):
            self.assertIn(theorem, output)


if __name__ == "__main__":
    unittest.main()
