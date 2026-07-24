from __future__ import annotations

import re
import shutil
import tempfile
import unittest
from pathlib import Path

from spaghetti_extractor.relational.lean.compiler import _run_lean_relational
from spaghetti_extractor.relational.lean.register_indirect_control_proposal import (
    LeanBindings,
    ProducerEvidence,
    ProposalPlan,
    SiteProposal,
    TargetInventory,
    write_register_indirect_control_authorities,
)
from tests.test_stage_a_nullable_code_pointer_table import (
    IMAGE_BASE,
    TEXT_RVA,
)
from tests.test_stage_a_reachable_static_pointer_slot_kernel import (
    _authority_source,
    _copy_module_closure,
    _fixture_pe,
)
from tests.test_stage_a_relocated_writable_static_pointer_slot_proposal import (
    SLOT_RVA,
    TARGET_RVA,
    TARGET_VA,
)


_APPROVED_AXIOMS = {"propext", "Quot.sound", "Classical.choice"}
_AXIOMS = re.compile(r"depends on axioms:\s*\[([^]]*)\]", re.DOTALL)


def _fixture_context_source(pe_path: Path, pe_bytes: bytes) -> str:
    source_rva = TEXT_RVA + 5
    continuation_rva = source_rva + 2
    entries = ", ".join(
        (
            f"{{ id := 0, regionIndex := 0, rva := {source_rva} }}",
            f"{{ id := 1, regionIndex := 1, rva := {continuation_rva} }}",
            f"{{ id := 2, regionIndex := 2, rva := {TARGET_RVA} }}",
        )
    )
    addresses = ", ".join(
        f"{{ targetId := {index}, kind := .canonical }}" for index in range(3)
    )
    regions = ", ".join(
        (
            f"{{ id := 0, span := {{ start := {source_rva}, size := 2 }}, "
            "root := true, targets := [1] }",
            f"{{ id := 1, span := {{ start := {continuation_rva}, size := 1 }}, "
            "root := false, targets := [] }",
            f"{{ id := 2, span := {{ start := {TARGET_RVA}, size := 1 }}, "
            "root := false, targets := [] }",
        )
    )
    return (
        _authority_source(
            pe_path,
            pe_bytes,
            2,
            entries=entries,
            addresses=addresses,
            regions=regions,
            check_size=3,
        )
        + f"""

namespace StageA.GeneratedReachableSlotFixture

open StageA.Formal StageA.Relational
open StageA.Relational.InterpreterMixedContext

def fixtureTarget : OriginalCodeTarget :=
  {{ id := 2, regionIndex := 2, rva := {TARGET_RVA} }}

theorem fixtureTargetFound :
    originalContext.codeMap.get? 2 = some fixtureTarget := by
  decide +kernel

def fixtureReachable
    (_world : RelationalWorld) (_sourceEip : Word)
    (state : MachineState) : Prop :=
  state.registers.get .eax = BitVec.ofNat 32 {TARGET_VA}

end StageA.GeneratedReachableSlotFixture
"""
    )


def _proposal() -> ProposalPlan:
    site = SiteProposal(
        site_id=0,
        source_target_id=0,
        source_rva=TEXT_RVA + 5,
        instruction_rva=TEXT_RVA + 5,
        instruction_bytes=b"\xff\xd0",
        transfer="call",
        target_register="eax",
        continuation_target_id=1,
        continuation_rva=TEXT_RVA + 7,
        inventory=TargetInventory(
            kind="internal_code",
            target_ids=(2,),
            target_rvas=(TARGET_RVA,),
            slot_rva=SLOT_RVA,
            slot_va=IMAGE_BASE + SLOT_RVA,
            producers=(
                ProducerEvidence(
                    kind="absolute_slot",
                    instruction_rva=TEXT_RVA,
                    instruction_bytes=(
                        b"\xa1" + (IMAGE_BASE + SLOT_RVA).to_bytes(4, "little")
                    ),
                    register="eax",
                    slot_rva=SLOT_RVA,
                ),
            ),
        ),
        carries=(),
        blocker_detail="register_function_pointer fixture",
    )
    return ProposalPlan(
        original_sha256="0" * 64,
        state_machine_sha256="1" * 64,
        machine_import_report_sha256="2" * 64,
        mixed_original_plan_sha256="3" * 64,
        writable_slot_report_sha256="4" * 64,
        sites=(site,),
        blockers=(),
        untouched_blockers=(),
    )


def _runtime_term() -> str:
    return f"""by
  intro world sourceEip state reachable atSource
  have valueExact :
      state.registers.get .eax = BitVec.ofNat 32 {TARGET_VA} := by
    simpa [StageA.GeneratedReachableSlotFixture.fixtureReachable] using reachable
  refine {{
    sourceExact := atSource
    carryExecutions := []
    carryInventory := rfl
    targetMember := ?_
  }}
  exact RuntimeTargetMember.relocatedWritableCode
    {SLOT_RVA} 2
    StageA.GeneratedReachableSlotFixture.fixtureTarget
    StageA.GeneratedReachableSlotFixture.fixtureTargetFound
    valueExact"""


@unittest.skipUnless(shutil.which("lean"), "Lean is required for kernel checks")
class StageARegisterIndirectControlKernelTests(unittest.TestCase):
    def test_generated_authority_and_mutations_are_kernel_checked(self) -> None:
        source_root = Path(__file__).parents[1] / "src/spaghetti_extractor/lean/StageA"
        layer = (
            source_root / "RelationalRegisterIndirectControlAuthority.lean"
        ).read_text(encoding="utf-8")
        for marker in ("sorry", "axiom", "unsafe", "native_decide"):
            self.assertIsNone(re.search(rf"\b{marker}\b", layer), marker)

        code = bytearray(b"\x90" * 0x20)
        code[0:5] = b"\xa1" + (IMAGE_BASE + SLOT_RVA).to_bytes(4, "little")
        code[5:7] = b"\xff\xd0"
        code[7] = 0xC3
        code[TARGET_RVA - TEXT_RVA] = 0xC3
        pe_bytes = _fixture_pe(
            slot_word=TARGET_VA,
            code=bytes(code),
            relocation=True,
        )

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            stage_a = root / "StageA"
            stage_a.mkdir()
            _copy_module_closure(
                source_root,
                stage_a,
                "RelationalRegisterIndirectControlAuthority",
            )
            pe_path = root / "fixture.exe"
            pe_path.write_bytes(pe_bytes)
            (stage_a / "GeneratedReachableSlotFixture.lean").write_text(
                _fixture_context_source(pe_path, pe_bytes),
                encoding="utf-8",
            )
            write_register_indirect_control_authorities(
                root,
                _proposal(),
                {
                    0: LeanBindings(
                        context_module=("StageA.GeneratedReachableSlotFixture"),
                        context_term=(
                            "StageA.GeneratedReachableSlotFixture.originalContext"
                        ),
                        exact_authority_term=(
                            "StageA.GeneratedReachableSlotFixture.originalAuthority"
                        ),
                        runtime_premise_module=("StageA.GeneratedReachableSlotFixture"),
                        runtime_reachability_term=(
                            "StageA.GeneratedReachableSlotFixture.fixtureReachable"
                        ),
                        runtime_premise_term=_runtime_term(),
                    )
                },
            )
            generated = stage_a / "GeneratedRegisterIndirectControlAuthority0000.lean"
            generated.write_text(
                generated.read_text(encoding="utf-8")
                + f"""

namespace StageA.GeneratedRegisterIndirectControlAuthority0000

open StageA.Relational.RegisterIndirectControlAuthority

theorem changedInstructionRejected :
    ({{ generatedCertificate with
      site := {{ generatedSite with instructionBytes := [255, 209] }} }}).checked
        generatedContext = false := by
  decide +kernel

theorem changedSlotRejected :
    ({{ generatedCertificate with
      inventory := .relocatedWritableCode {SLOT_RVA + 4} 2 }}).checked
        generatedContext = false := by
  decide +kernel

#print axioms changedInstructionRejected
#print axioms changedSlotRejected

end StageA.GeneratedRegisterIndirectControlAuthority0000
""",
                encoding="utf-8",
            )
            result = _run_lean_relational(
                root,
                bundle="GeneratedRegisterIndirectControlAuthority0000",
            )

        self.assertEqual(result["status"], "checked", result)
        output = result["stdout"] + result["stderr"]
        self.assertNotIn("sorryAx", output)
        self.assertNotIn("native_decide.ax", output)
        for match in _AXIOMS.findall(output):
            axioms = {item.strip() for item in match.split(",") if item.strip()}
            self.assertLessEqual(axioms, _APPROVED_AXIOMS)


if __name__ == "__main__":
    unittest.main()
