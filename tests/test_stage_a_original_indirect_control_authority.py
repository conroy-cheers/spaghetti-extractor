from __future__ import annotations

import re
import unittest
from pathlib import Path

from spaghetti_extractor.relational.lean.interpreter_mixed_original import (
    OriginalImportIdentity,
)
from spaghetti_extractor.relational.lean.original_indirect_control_authority import (
    DynamicCallbackControlSpec,
    NullableTableControlSpec,
    OriginalIndirectControlAuthorityBinding,
    OriginalIndirectControlAuthorityGenerationError,
    OriginalIndirectControlAuthorityModuleSpec,
    OriginalIndirectControlSiteSpec,
    OriginalTargetExpressionSpec,
    RelocatedCodePointerSeedSpec,
    SavedImportControlSpec,
    original_indirect_control_authority_source,
)
from spaghetti_extractor.relational.lean.stack_fixed_code_pointer import (
    LeanStackAdjustment,
)


def _binding() -> OriginalIndirectControlAuthorityBinding:
    return OriginalIndirectControlAuthorityBinding(
        dependency_module="StageA.GeneratedOriginalFixture",
        namespace="StageA.Generated.OriginalIndirectAuthority",
        context_name="StageA.GeneratedOriginalFixture.originalContext",
        authority_name="StageA.GeneratedOriginalFixture.originalAuthority",
    )


def _site(
    name: str = "stackSite",
    target: OriginalTargetExpressionSpec | None = None,
) -> OriginalIndirectControlSiteSpec:
    return OriginalIndirectControlSiteSpec(
        definition_name=name,
        source_target_id=7,
        instruction_rva=0x203C,
        instruction_bytes=bytes.fromhex("ff542420"),
        target=target or OriginalTargetExpressionSpec(
            "stack_read", "esp", adjustment=LeanStackAdjustment("add", 32)
        ),
        transfer="call",
        continuation_target_id=8,
    )


class StageAOriginalIndirectControlAuthorityTests(unittest.TestCase):
    def test_emits_named_checked_terms_for_each_authority_family(self) -> None:
        register_site = _site(
            "savedImportSite", OriginalTargetExpressionSpec("register", "ecx")
        )
        callback_site = _site(
            "callbackSite",
            OriginalTargetExpressionSpec("dynamic_field", "ebx", offset=4),
        )
        table_site = _site(
            "tableSite",
            OriginalTargetExpressionSpec(
                "indexed_table", "ebx", base_address=0x4280EC, scale=4
            ),
        )
        spec = OriginalIndirectControlAuthorityModuleSpec(
            sites=(_site(), register_site, callback_site, table_site),
            seeds=(RelocatedCodePointerSeedSpec("stackSeed", 0x200D0, 17),),
            nullable_tables=(NullableTableControlSpec(
                "tableClaim", "tableSite", "Fixture.tableCertificate"
            ),),
            saved_imports=(SavedImportControlSpec(
                definition_name="savedImportClaim",
                save_source_target_id=3,
                restore_source_target_id=4,
                site_name="savedImportSite",
                binding_source_target_id=3,
                binding_instruction_rva=0x14140,
                iat_va=0x432184,
                iat_rva=0x32184,
                identity=OriginalImportIdentity(
                    "KERNEL32.dll", "GetProcAddress"
                ),
                stack_register="esp",
                stack_adjustment=LeanStackAdjustment("add", 24),
                target_register="ecx",
            ),),
            callbacks=(DynamicCallbackControlSpec(
                "callbackClaim", "callbackSite", 4, (21, 22)
            ),),
        )

        source = original_indirect_control_authority_source(spec, _binding())

        for name in (
            "stackSite", "savedImportSite", "callbackSite", "tableSite",
            "stackSeed", "tableClaim", "savedImportClaim", "callbackClaim",
        ):
            self.assertIn(f"theorem {name}Checked", source)
            self.assertIn(f"def {name}Evidence", source)
        self.assertIn("instructionBytes := [255, 84, 36, 32]", source)
        self.assertIn(".stackRead .esp .add 32", source)
        self.assertIn(".dynamicField .ebx 4", source)
        self.assertIn(".indexedTable 4358380 .ebx 4", source)
        self.assertIn(
            "71, 101, 116, 80, 114, 111, 99, 65, 100, 100, 114, 101, 115, 115",
            source,
        )
        for marker in ("sorry", "axiom", "unsafe", "native_decide"):
            self.assertIsNone(re.search(rf"\b{marker}\b", source), marker)

    def test_fail_closed_specs_reject_ambiguous_or_unbounded_inputs(self) -> None:
        with self.assertRaisesRegex(
            OriginalIndirectControlAuthorityGenerationError,
            "continuation",
        ):
            _site().__class__(**{
                **_site().__dict__, "continuation_target_id": None
            }).lean()
        with self.assertRaisesRegex(
            OriginalIndirectControlAuthorityGenerationError,
            "supported IA-32 register",
        ):
            _site(target=OriginalTargetExpressionSpec("register", "rip")).lean()
        with self.assertRaisesRegex(
            OriginalIndirectControlAuthorityGenerationError,
            "names must be unique",
        ):
            OriginalIndirectControlAuthorityModuleSpec(
                sites=(_site(), _site())
            ).validate()
        with self.assertRaisesRegex(
            OriginalIndirectControlAuthorityGenerationError,
            "requires a base and scale",
        ):
            _site(target=OriginalTargetExpressionSpec(
                "indexed_table", "eax"
            )).lean()

    def test_reviewed_lean_authority_keeps_runtime_membership_explicit(self) -> None:
        source = (
            Path(__file__).parents[1]
            / "src/spaghetti_extractor/lean/StageA/RelationalOriginalIndirectControlAuthority.lean"
        ).read_text(encoding="utf-8")
        for required in (
            "exactRvaBytes context.pe site.instructionRva",
            "decodeInstructionExact bytes",
            "relocationCountAt context.relocations",
            "stackRangeMember : stackRange ∈ world.stackRanges",
            "importAddressMember : importAddress ∈ world.importAddresses",
            "dynamicRangeMember : dynamicRange ∈ world.dynamicRanges",
            "callbackMember : callback ∈ world.registeredCallbacks",
            "NullableTableTargetBound",
            "codeTargetInventoryChecked",
        ):
            self.assertIn(required, source)
        for marker in ("sorry", "axiom", "unsafe", "native_decide"):
            self.assertIsNone(re.search(rf"\b{marker}\b", source), marker)


if __name__ == "__main__":
    unittest.main()
