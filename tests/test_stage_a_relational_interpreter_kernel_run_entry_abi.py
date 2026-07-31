from __future__ import annotations

import unittest

from spaghetti_extractor.relational.lean.interpreter_kernel_run_entry_abi import (
    run_entry_abi_base_lean_source,
    run_entry_abi_lean_source,
)


class RunEntryABIGenerationTests(unittest.TestCase):
    def test_uses_compact_projection_kernel(self) -> None:
        source = run_entry_abi_base_lean_source()
        self.assertIn(
            "import StageA.RelationalInterpreterKernelOperationProjection",
            source,
        )
        self.assertIn(
            "open StageA.Relational."
            "InterpreterKernelOperationProjection",
            source,
        )
        operand_proof = source.split(
            "theorem generatedRunEntryDecodedBulkOperands", 1
        )[1].split(
            "/-- The concrete ABI instantiation", 1
        )[0]
        self.assertNotIn("SymbolicBehavior.eval,", operand_proof)
        self.assertNotIn("concreteBehaviorNextMachineState,", operand_proof)
        self.assertNotIn("simp_all", operand_proof)

    def test_splits_operand_projection_from_abi_source_facts(self) -> None:
        base = run_entry_abi_base_lean_source()
        source_facts = run_entry_abi_lean_source()
        self.assertIn(
            "theorem generatedRunEntryDecodedBulkOperands",
            base,
        )
        self.assertNotIn("generatedRunEntryABIBulkSourceFacts", base)
        self.assertIn(
            "import StageA.GeneratedRelationalInterpreterKernelRunEntryABIBase",
            source_facts,
        )
        self.assertNotIn(
            "theorem generatedRunEntryDecodedBulkOperands",
            source_facts,
        )
        self.assertIn("generatedRunEntryABIBulkSourceFacts", source_facts)
        self.assertIn(
            "import StageA."
            "GeneratedRelationalInterpreterKernelRunEntryFootprints",
            source_facts,
        )
        self.assertIn(
            "import StageA."
            "GeneratedRelationalInterpreterKernelRunOperation",
            source_facts,
        )
        theorem = source_facts.split(
            "theorem generatedRunEntryABIBulkSourceFacts", 1
        )[1]
        signature, body = theorem.split(" := by", 1)
        self.assertNotIn("(controlDisjoint :", signature)
        self.assertNotIn("(bulkDisjoint :", signature)
        self.assertIn(
            "generatedRunEntryControlFootprintsDisjoint",
            body,
        )
        self.assertIn(
            "generatedRunEntryBulkFootprintsDisjoint",
            body,
        )
        self.assertIn(
            "theorem generatedRunEntryABIControlFacts",
            source_facts,
        )
        self.assertIn(
            "theorem generatedRunEntryABIExactEnginePath",
            source_facts,
        )
        self.assertIn(
            "executeOfControlInvariant",
            source_facts,
        )
        self.assertIn(
            "executeOfTerminalHolds",
            source_facts,
        )
        entry = source_facts.split(
            "noncomputable def generatedRunFunctionCheckedEntryAuthority", 1
        )[1].split("#print axioms", 1)[0]
        for required in (
            "generatedRunEntryABIExactEnginePath",
            "RunFunctionNativeEntryPhase.ofExactPath",
            "invariantExact",
            "exactPath.1",
            "exactPath.2",
        ):
            self.assertIn(required, entry)


if __name__ == "__main__":
    unittest.main()
