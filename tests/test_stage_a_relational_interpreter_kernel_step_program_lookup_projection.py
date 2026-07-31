from __future__ import annotations

from pathlib import Path
import unittest

from spaghetti_extractor.relational.lean.interpreter_kernel_step_program_lookup_projection import (
    interpreter_step_program_lookup_projection_source,
)
from spaghetti_extractor.relational.lean.interpreter_kernel_step_world_program_lookup import (
    InterpreterKernelStepWorldProgramLookupPlan,
)


class InterpreterStepProgramLookupProjectionTests(unittest.TestCase):
    def test_direct_entry_projection_is_bound_to_all_exact_instructions(
        self,
    ) -> None:
        step_entry = 285378
        call_site = step_entry + 11
        spans = tuple(
            (ordinal, step_entry + ordinal, 1) for ordinal in range(9)
        )
        plan = InterpreterKernelStepWorldProgramLookupPlan(
            candidate_path=Path("candidate.exe"),
            candidate_sha256="a" * 64,
            candidate_size=4096,
            bridge_plan_path=Path("bridge.json"),
            bridge_plan_sha256="b" * 64,
            step_operation_plan_path=Path("step.json"),
            step_operation_plan_sha256="c" * 64,
            operation_instantiation_plan_path=Path("operation.json"),
            operation_instantiation_plan_sha256="d" * 64,
            step_entry_rva=step_entry,
            step_function_ordinal=37,
            step_entry_block_ordinal=0,
            step_entry_instruction_count=9,
            prefix_kind="direct_entry_call",
            helper_target_rva=None,
            helper_continuation_rva=None,
            helper_function_ordinal=None,
            helper_entry_block_ordinal=None,
            helper_return_block_ordinal=None,
            helper_return_block_rva=None,
            helper_block_ordinals=(),
            helper_route_budget=4096,
            call_site_rva=call_site,
            call_block_entry_rva=step_entry,
            call_block_ordinal=0,
            call_block_instruction_count=9,
            target_rva=285217,
            continuation_rva=call_site + 5,
            call_block_instruction_spans=spans,
        )
        source = interpreter_step_program_lookup_projection_source(
            plan
        )

        for ordinal in range(9):
            self.assertIn(
                "generatedInterpreterStepProgramLookupCall"
                f"Instruction{ordinal:04d}MaterializedBehavior"
                "EdgeBehaviorExact",
                source,
            )
        self.assertIn(
            "generatedInterpreterStepProgramLookupProjectionNestedEntry",
            source,
        )
        self.assertIn(
            "generatedInterpreterStepProgramLookupProjectionBlockEndpointExact",
            source,
        )
        self.assertIn(
            "generatedInterpreterStepProgramLookupStackUse.Fits", source
        )
        self.assertIn("checkedNativeOperationBlock_memoryAgreesOutside_at", source)
        self.assertNotIn("sorry", source)
        self.assertNotIn("native_decide", source)


if __name__ == "__main__":
    unittest.main()
