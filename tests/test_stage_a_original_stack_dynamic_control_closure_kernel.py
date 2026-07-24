from __future__ import annotations

import hashlib
import re
import shutil
import struct
import tempfile
import unittest
from pathlib import Path

from spaghetti_extractor.relational.lean.compiler import _run_lean_relational
from spaghetti_extractor.relational.lean.original_indirect_control_authority import (
    OriginalIndirectControlAuthorityBinding,
    OriginalTargetExpressionSpec,
)
from spaghetti_extractor.relational.lean.original_stack_dynamic_control_closure import (
    DynamicCallbackAuthorityHint,
    OriginalStackDynamicControlClosureSpec,
    StackCarryAuthorityHint,
    original_stack_dynamic_control_closure_source,
    plan_original_stack_dynamic_control_closure,
)
from spaghetti_extractor.relational.lean.stack_dynamic_indirect_control import (
    IndexedEmptyTableProposal,
    StackDynamicBlocker,
    StackDynamicIndirectControlPlan,
    StackDynamicSiteFinding,
)
from spaghetti_extractor.relational.lean.stack_fixed_code_pointer import (
    LeanStackAdjustment,
)
from tests.test_stage_a_nullable_code_pointer_table import (
    DATA_RVA,
    IMAGE_BASE,
    TEXT_RAW,
    TEXT_RVA,
    _nullable_table_pe,
)
from tests.test_stage_a_reachable_static_pointer_slot_kernel import (
    _authority_source,
)


_IMPORT = re.compile(r"^import StageA\.([A-Za-z0-9_]+)$", re.MULTILINE)
_AXIOMS = re.compile(r"depends on axioms:\s*\[([^]]*)\]", re.DOTALL)
_APPROVED_AXIOMS = {"propext", "Quot.sound", "Classical.choice"}


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


_KERNEL = r"""import StageA.RelationalOriginalStackDynamicControlClosure

namespace StageA.OriginalStackDynamicControlClosureKernel

open StageA.Relational.OriginalStackDynamicControlClosure

#print axioms originalResolvedCodeTarget_of_checked
#print axioms stackCarryClosure_of_complete
#print axioms indexedTableClosure_of_empty_checked_interval
#print axioms dynamicCallbackClosure_of_complete
#print axioms dynamicSourceClosure_of_uninhabited

end StageA.OriginalStackDynamicControlClosureKernel
"""


def _generated_fixture() -> tuple[bytes, StackDynamicIndirectControlPlan]:
    target_rva = TEXT_RVA + 0x30
    words = (0xFFFFFFFF, 0) + (0,) * 6 + (IMAGE_BASE + target_rva,)
    image = bytearray(_nullable_table_pe(
        words=words,
        relocation_offsets=(0x20,),
    ))
    stack_call = bytes.fromhex("ff542420")
    indexed_call = b"\xff\x14\x9d" + struct.pack(
        "<I", IMAGE_BASE + DATA_RVA
    )
    dynamic_region = bytes.fromhex("8b4304ffd0")
    image[TEXT_RAW : TEXT_RAW + len(stack_call)] = stack_call
    image[TEXT_RAW + 4] = 0xC3
    image[TEXT_RAW + 0x10 : TEXT_RAW + 0x10 + len(indexed_call)] = indexed_call
    image[TEXT_RAW + 0x17] = 0xC3
    image[TEXT_RAW + 0x20 : TEXT_RAW + 0x20 + len(dynamic_region)] = (
        dynamic_region
    )
    image[TEXT_RAW + 0x25] = 0xC3
    image[TEXT_RAW + 0x30] = 0xC3
    pe_bytes = bytes(image)
    blocker = (
        StackDynamicBlocker("runtime_missing", "typed premise", "prove it"),
    )
    proposal = StackDynamicIndirectControlPlan(
        original_pe_sha256=hashlib.sha256(pe_bytes).hexdigest(),
        state_machine_sha256="d" * 64,
        original_pe_bytes=pe_bytes,
        findings=(
            StackDynamicSiteFinding(
                stable_id="fixture-stack",
                source_target_id=0,
                source_rva=TEXT_RVA,
                instruction_rva=TEXT_RVA,
                instruction_bytes=stack_call,
                continuation_target_id=1,
                provenance_class="stack_slot",
                target=OriginalTargetExpressionSpec(
                    "stack_read",
                    "esp",
                    adjustment=LeanStackAdjustment("add", 32),
                ),
                static_facts={"stack_register": "esp"},
                indexed_empty_table=None,
                blockers=blocker,
            ),
            StackDynamicSiteFinding(
                stable_id="fixture-table",
                source_target_id=2,
                source_rva=TEXT_RVA + 0x10,
                instruction_rva=TEXT_RVA + 0x10,
                instruction_bytes=indexed_call,
                continuation_target_id=3,
                provenance_class="indexed_immutable_table",
                target=OriginalTargetExpressionSpec(
                    "indexed_table",
                    "ebx",
                    base_address=IMAGE_BASE + DATA_RVA,
                    scale=4,
                ),
                static_facts={"word_0": 0xFFFFFFFF, "word_1": 0},
                indexed_empty_table=IndexedEmptyTableProposal(
                    table_rva=DATA_RVA,
                    range_rva=DATA_RVA + 4,
                    index_register="ebx",
                    lower_inclusive=1,
                    address_scale=4,
                    header_words=(0xFFFFFFFF,),
                ),
                blockers=blocker,
            ),
            StackDynamicSiteFinding(
                stable_id="fixture-dynamic",
                source_target_id=4,
                source_rva=TEXT_RVA + 0x20,
                instruction_rva=TEXT_RVA + 0x23,
                instruction_bytes=bytes.fromhex("ffd0"),
                continuation_target_id=5,
                provenance_class="dynamic_range_field",
                target=OriginalTargetExpressionSpec(
                    "dynamic_field", "ebx", offset=4
                ),
                static_facts={"base_register": "ebx", "field_offset": 4},
                indexed_empty_table=None,
                blockers=blocker,
            ),
        ),
    )
    return pe_bytes, proposal


@unittest.skipUnless(shutil.which("lean"), "Lean is required for kernel checks")
class StageAOriginalStackDynamicControlClosureKernelTests(unittest.TestCase):
    def test_reviewed_closure_compiles_and_uses_only_approved_axioms(
        self,
    ) -> None:
        source_root = (
            Path(__file__).parents[1]
            / "src/spaghetti_extractor/lean/StageA"
        )
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            stage_a = root / "StageA"
            stage_a.mkdir()
            _copy_module_closure(
                source_root,
                stage_a,
                "RelationalOriginalStackDynamicControlClosure",
            )
            (stage_a / "OriginalStackDynamicControlClosureKernel.lean").write_text(
                _KERNEL, encoding="utf-8"
            )
            result = _run_lean_relational(
                root, bundle="OriginalStackDynamicControlClosureKernel"
            )

        self.assertEqual(result["status"], "checked", result)
        output = result["stdout"] + result["stderr"]
        self.assertNotIn("sorryAx", output)
        reports = _AXIOMS.findall(output)
        self.assertGreaterEqual(len(reports), 5, output)
        for report in reports:
            used = {item.strip() for item in report.split(",") if item.strip()}
            self.assertLessEqual(used, _APPROVED_AXIOMS, report)

    def test_generated_static_authorities_compile_against_exact_fixture(
        self,
    ) -> None:
        source_root = (
            Path(__file__).parents[1]
            / "src/spaghetti_extractor/lean/StageA"
        )
        pe_bytes, proposal = _generated_fixture()
        spec = OriginalStackDynamicControlClosureSpec(
            stack_hints=(
                StackCarryAuthorityHint(
                    "fixture-stack", DATA_RVA + 0x20, 6
                ),
            ),
            dynamic_hints=(
                DynamicCallbackAuthorityHint(
                    "fixture-dynamic", "source_uninhabited"
                ),
            ),
        )
        plan = plan_original_stack_dynamic_control_closure(
            proposal,
            spec,
            original_pe_sha256=proposal.original_pe_sha256,
            state_machine_sha256=proposal.state_machine_sha256,
        )
        binding = OriginalIndirectControlAuthorityBinding(
            dependency_module="StageA.GeneratedReachableSlotFixture",
            namespace="StageA.Generated.StackDynamicClosureFixture",
            context_name=(
                "StageA.GeneratedReachableSlotFixture.originalContext"
            ),
            authority_name=(
                "StageA.GeneratedReachableSlotFixture.originalAuthority"
            ),
        )
        entries = ", ".join(
            f"{{ id := {target_id}, regionIndex := {target_id}, rva := {rva} }}"
            for target_id, rva in (
                (0, TEXT_RVA),
                (1, TEXT_RVA + 4),
                (2, TEXT_RVA + 0x10),
                (3, TEXT_RVA + 0x17),
                (4, TEXT_RVA + 0x20),
                (5, TEXT_RVA + 0x25),
                (6, TEXT_RVA + 0x30),
            )
        )
        addresses = ", ".join(
            f"{{ targetId := {target_id}, kind := .canonical }}"
            for target_id in range(7)
        )
        regions = ", ".join((
            f"{{ id := 0, span := {{ start := {TEXT_RVA}, size := 4 }}, "
            "root := true, targets := [1] }",
            f"{{ id := 1, span := {{ start := {TEXT_RVA + 4}, size := 1 }}, "
            "root := false, targets := [] }",
            f"{{ id := 2, span := {{ start := {TEXT_RVA + 0x10}, size := 7 }}, "
            "root := true, targets := [3] }",
            f"{{ id := 3, span := {{ start := {TEXT_RVA + 0x17}, size := 1 }}, "
            "root := false, targets := [] }",
            f"{{ id := 4, span := {{ start := {TEXT_RVA + 0x20}, size := 5 }}, "
            "root := true, targets := [5] }",
            f"{{ id := 5, span := {{ start := {TEXT_RVA + 0x25}, size := 1 }}, "
            "root := false, targets := [] }",
            f"{{ id := 6, span := {{ start := {TEXT_RVA + 0x30}, size := 1 }}, "
            "root := false, targets := [] }",
        ))

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            stage_a = root / "StageA"
            stage_a.mkdir()
            pe_path = root / "fixture.exe"
            pe_path.write_bytes(pe_bytes)
            _copy_module_closure(
                source_root,
                stage_a,
                "RelationalOriginalStackDynamicControlClosure",
            )
            (stage_a / "GeneratedReachableSlotFixture.lean").write_text(
                _authority_source(
                    pe_path,
                    pe_bytes,
                    1,
                    entries=entries,
                    addresses=addresses,
                    regions=regions,
                    check_size=7,
                ),
                encoding="utf-8",
            )
            (
                stage_a
                / "GeneratedRelationalOriginalStackDynamicControlClosure.lean"
            ).write_text(
                original_stack_dynamic_control_closure_source(plan, binding)
                + r"""

namespace StageA.Generated.StackDynamicClosureFixture

example :
    ({ generatedOriginalStackDynamicClosure0Site with
      instructionBytes := [255, 84, 36, 36] }).checked
      StageA.GeneratedReachableSlotFixture.originalContext = false := by
  decide +kernel

example :
    ({ generatedOriginalStackDynamicClosure0Site with
      sourceTargetId := 6 }).checked
      StageA.GeneratedReachableSlotFixture.originalContext = false := by
  decide +kernel

example :
    ({ generatedOriginalStackDynamicClosure0Site with
      transfer := .call 6 }).checked
      StageA.GeneratedReachableSlotFixture.originalContext = false := by
  decide +kernel

example :
    ({ generatedOriginalStackDynamicClosure1Site with
      instructionBytes := [255, 20, 157, 0, 0, 0, 0] }).checked
      StageA.GeneratedReachableSlotFixture.originalContext = false := by
  decide +kernel

example :
    StageA.Relational.OriginalIndirectControlAuthority.codeTargetInventoryChecked
      StageA.GeneratedReachableSlotFixture.originalContext [999] = false := by
  decide +kernel

end StageA.Generated.StackDynamicClosureFixture
""",
                encoding="utf-8",
            )
            result = _run_lean_relational(
                root,
                bundle="GeneratedRelationalOriginalStackDynamicControlClosure",
            )

        self.assertEqual(result["status"], "checked", result)
        output = result["stdout"] + result["stderr"]
        self.assertNotIn("sorryAx", output)
        reports = _AXIOMS.findall(output)
        self.assertGreaterEqual(len(reports), 11, output)
        for report in reports:
            used = {item.strip() for item in report.split(",") if item.strip()}
            self.assertLessEqual(used, _APPROVED_AXIOMS, report)


if __name__ == "__main__":
    unittest.main()
