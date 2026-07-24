from __future__ import annotations

import dataclasses
import unittest

from spaghetti_extractor.relational.lean import (
    external_tail_static_pointer_slot_composition as composition,
)


def _binding(
    **changes,
) -> composition.ExternalTailStaticPointerSlotCompositionBinding:
    values = {
        "context_term": "StageA.GnuHello.context",
        "original_context_term": "StageA.GnuHello.originalContext",
        "certificate_term": "StageA.GnuHello.userMathErrorSlotCertificate",
        "authority_term": "StageA.GnuHello.userMathErrorTailAuthority",
        "original_decoded_authority_term": (
            "StageA.GnuHello.originalDecodedAuthority"
        ),
        "source_target_id": 64,
        "wrapper_target_id": 2714,
        "continuation_target_id": 65,
        "source_rva": 0x13BD,
        "callsite_rva": 0x13C4,
        "call_instruction_size": 5,
        "wrapper_rva": 0xA980,
        "continuation_rva": 0x13C9,
        "route_kind": "direct_import",
        "iat_rva": None,
        "slot_rva": 0x30358,
        "slot_target_id": 2620,
        "slot_value": 0x40A390,
        "site_id": 76,
        "machine_contract_id": 23,
        "imported": composition.ExternalImportIdentity(
            dll="msvcrt.dll", symbol="__setusermatherr"
        ),
        "original_frame_argument_offset": 4,
        "candidate_frame_argument_offset": 4,
        "stack_argument_offsets": (0,),
        "stack_result_delta": 0,
        "preserved_registers": ("ebp", "ebx", "edi", "esi"),
        "clobbered_registers": ("eax", "ecx", "edx"),
        "imports": ("StageA.GnuHello",),
        "namespace": "StageA.Generated.GnuHelloUserMathErrorTail",
    }
    values.update(changes)
    return composition.ExternalTailStaticPointerSlotCompositionBinding(**values)


def _static_binding(
    **changes,
) -> composition.ExternalTailStaticPointerSlotStaticAuthorityBinding:
    runtime = _binding(**changes)
    names = {
        field.name
        for field in dataclasses.fields(
            composition.ExternalTailStaticPointerSlotStaticAuthorityBinding
        )
    }
    return composition.ExternalTailStaticPointerSlotStaticAuthorityBinding(
        **{name: getattr(runtime, name) for name in names}
    )


class StageAExternalTailStaticPointerSlotCompositionTests(unittest.TestCase):
    def test_gnu_shaped_binding_is_indexed_by_exact_request(self) -> None:
        source = composition.external_tail_static_pointer_slot_composition_source(
            _binding()
        )

        for expected in (
            "CheckedExternalTailStaticPointerSlotReturn generatedContext",
            "sourceRva := 5053",
            "callsiteRva := 5060",
            "callInstructionSize := 5",
            "wrapperRva := 43392",
            "routeKind := .directImport",
            "iatRva := none",
            "slotRva := 197464",
            "slotValue := 4236176",
            "originalFrameArgumentOffset := 4",
            "stackArgumentOffsets := [0]",
            "stackResultDelta := 0",
            "preservedRegisters := [.ebp, .ebx, .edi, .esi]",
            "msvcrt",  # rendered as bytes; the module still carries the identity
            "generatedOriginalCallEntry",
            "generatedCandidateSourceState",
            "generatedExactWorldExecutionMacroPath",
            "generatedStaticPointerSlotEqualsExpectedAtBoundary",
            "generatedStaticPointerSlotAllowedAfterExternal",
            "generatedExternalResultsRelated",
            "generatedRuntimeCallFrameAfterExternal",
        ):
            if expected == "msvcrt":
                self.assertIn(
                    "dll := [109, 115, 118, 99, 114, 116, 46, 100, 108, 108]",
                    source,
                )
            else:
                self.assertIn(expected, source)
        self.assertNotIn("proof_status", source)
        self.assertNotIn("acceptance_authority", source)
        self.assertNotIn("native_decide", source)
        self.assertNotIn("sorry", source)

    def test_static_authority_is_locally_checked_without_global_slot_claim(
        self,
    ) -> None:
        source = (
            composition.external_tail_static_pointer_slot_static_authority_source(
                _static_binding()
            )
        )

        for expected in (
            "generatedStaticPointerSlotCertificate",
            "reachableTargetIds := .unknown",
            "allowedTargetIds := .exact [2620]",
            "generatedInitialSlotChecked",
            "generatedAllowedTargetsChecked",
            "generatedCanonicalSlotTarget",
            "generatedLocalSlotEvidence",
            "generatedCodeBinding",
            "generatedStaticAuthority",
            "source := { id := 64, regionIndex := 64, rva := 5053",
            "wrapper := { id := 2714, regionIndex := 2714, rva := 43392",
            "continuation := { id := 65, regionIndex := 65, rva := 5065",
        ):
            self.assertIn(expected, source)
        self.assertNotIn("KernelEvidence", source)
        self.assertNotIn("certificate.checked", source)
        self.assertNotIn("native_decide", source)
        self.assertNotIn("sorry", source)

    def test_termination_binding_exports_only_terminal_macro_api(self) -> None:
        source = composition.external_tail_static_pointer_slot_composition_source(
            _binding(outcome="terminates")
        )

        self.assertIn("CheckedExternalTailStaticPointerSlotTermination", source)
        self.assertIn("generatedExactWorldExecutionMacroPath", source)
        self.assertIn("generatedCandidateEvent", source)
        self.assertIn(
            "generatedStaticPointerSlotEqualsExpectedAtBoundary", source
        )
        self.assertNotIn("generatedStaticPointerSlotAllowedAfterExternal", source)
        self.assertNotIn("generatedExternalResultsRelated", source)

    def test_route_import_and_abi_shape_fail_closed(self) -> None:
        cases = (
            (
                {"route_kind": "iat_indirect", "iat_rva": None},
                "requires an exact IAT RVA",
            ),
            (
                {"route_kind": "direct_import", "iat_rva": 0x321D4},
                "must not carry an IAT RVA",
            ),
            (
                {"call_instruction_size": 6},
                "must equal continuation_rva",
            ),
            (
                {
                    "imported": composition.ExternalImportIdentity(
                        dll="MSVCRT.dll", symbol="__setusermatherr"
                    )
                },
                "ASCII-lowercase",
            ),
            (
                {
                    "imported": composition.ExternalImportIdentity(
                        dll="msvcrt.dll",
                        symbol="__setusermatherr",
                        ordinal=1,
                    )
                },
                "exactly one",
            ),
            (
                {
                    "preserved_registers": ("ebx", "eax"),
                    "clobbered_registers": ("eax",),
                },
                "overlap",
            ),
            (
                {"stack_argument_offsets": (0, 0)},
                "contains duplicates",
            ),
            (
                {"stack_argument_offsets": (2,)},
                "aligned 32-bit words",
            ),
            (
                {"original_frame_argument_offset": 2},
                "aligned 32-bit frame word",
            ),
            (
                {
                    "preserved_registers": ("ebp", "ebx", "edi"),
                    "clobbered_registers": ("eax", "ecx", "edx"),
                },
                "omits registers: esi",
            ),
            (
                {"outcome": "terminates", "stack_result_delta": 4},
                "requires zero stack_result_delta",
            ),
        )
        for changes, message in cases:
            with self.subTest(changes=changes):
                with self.assertRaisesRegex(
                    composition.ExternalTailStaticPointerSlotCompositionError,
                    message,
                ):
                    composition.external_tail_static_pointer_slot_composition_source(
                        _binding(**changes)
                    )

    def test_invalid_term_or_namespace_cannot_be_rendered(self) -> None:
        for changes in (
            {"authority_term": "not a term"},
            {"namespace": "bad namespace"},
        ):
            with self.subTest(changes=changes):
                with self.assertRaises(
                    composition.ExternalTailStaticPointerSlotCompositionError
                ):
                    composition.external_tail_static_pointer_slot_composition_source(
                        _binding(**changes)
                    )


if __name__ == "__main__":
    unittest.main()
