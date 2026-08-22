from __future__ import annotations

import unittest

from spaghetti_extractor.abi.compatibility import compare_physical_abis
from spaghetti_extractor.abi.legacy import physical_profile_from_library_v3
from spaghetti_extractor.libraries.abi_records import (
    BoundaryEffectV3,
    CallbackSlotV3,
    LibraryAbiProfileV3,
    StackCleanupV3,
    ValueLocationV3,
    VariadicPolicyV3,
)


def legacy_profile(
    *,
    profile_id: str = "legacy-cdecl",
    calling_convention: str = "cdecl",
    stack_cleanup: StackCleanupV3 | None = None,
    arguments: tuple[ValueLocationV3, ...] | None = None,
    hidden_sret: bool = False,
    callback_slots: tuple[CallbackSlotV3, ...] = (),
    structure_layout_ids: tuple[str, ...] = (),
    boundary_effects: tuple[BoundaryEffectV3, ...] = (),
) -> LibraryAbiProfileV3:
    selected_arguments = (
        (ValueLocationV3("stack", 32, stack_offset=4),)
        if arguments is None
        else arguments
    )
    return LibraryAbiProfileV3(
        profile_id=profile_id,
        architecture="x86",
        object_format="pe32",
        calling_convention=calling_convention,
        stack_cleanup=stack_cleanup or StackCleanupV3("caller", 0),
        arguments=selected_arguments,
        returns=(ValueLocationV3("register", 32, register="eax"),),
        hidden_sret=hidden_sret,
        variadic=VariadicPolicyV3("none", len(selected_arguments), None),
        preserved_registers=("ebp", "ebx", "edi", "esi"),
        callback_slots=callback_slots,
        structure_layout_ids=structure_layout_ids,
        boundary_effects=boundary_effects,
    )


class LegacyLibraryAbiAdapterTests(unittest.TestCase):
    def test_cdecl_profile_maps_legacy_locations_and_cleanup(self) -> None:
        converted = physical_profile_from_library_v3(legacy_profile())

        self.assertEqual(converted.target.architecture, "x86")
        self.assertEqual(converted.target.object_format, "pe32")
        self.assertEqual(converted.calling_convention, "cdecl")
        self.assertEqual(converted.stack_cleanup.kind, "caller")
        self.assertEqual(converted.arguments[0].value_id, "arg0")
        self.assertEqual(converted.arguments[0].fragments[0].stack_offset, 4)
        self.assertEqual(converted.results[0].fragments[0].register, "eax")

    def test_stdcall_profile_retains_callee_cleanup(self) -> None:
        profile = legacy_profile(
            profile_id="legacy-stdcall",
            calling_convention="stdcall",
            stack_cleanup=StackCleanupV3("callee", 8),
            arguments=(
                ValueLocationV3("stack", 32, stack_offset=4),
                ValueLocationV3("stack", 32, stack_offset=8),
            ),
        )

        converted = physical_profile_from_library_v3(profile)

        self.assertEqual(converted.calling_convention, "stdcall")
        self.assertEqual(converted.stack_cleanup.kind, "callee")
        self.assertEqual(converted.stack_cleanup.bytes, 8)

    def test_hidden_sret_and_callback_slots_retain_physical_roles(self) -> None:
        profile = legacy_profile(
            profile_id="legacy-callback",
            arguments=(
                ValueLocationV3("stack", 32, stack_offset=4),
                ValueLocationV3("stack", 32, stack_offset=8),
            ),
            hidden_sret=True,
            callback_slots=(CallbackSlotV3(1, "callback-profile-v1", False),),
        )

        converted = physical_profile_from_library_v3(profile)

        self.assertEqual(converted.arguments[0].role, "hidden_sret")
        self.assertEqual(converted.arguments[1].role, "callback")
        self.assertEqual(
            converted.arguments[1].callback_abi_id, "callback-profile-v1"
        )

    def test_effect_and_type_fields_do_not_change_physical_compatibility(self) -> None:
        first = legacy_profile(
            profile_id="legacy-a",
            structure_layout_ids=("layout.widget-v1",),
            boundary_effects=(
                BoundaryEffectV3("memory", "argument:0", "read"),
            ),
        )
        second = legacy_profile(
            profile_id="legacy-b",
            structure_layout_ids=("layout.completely-different-v2",),
            boundary_effects=(
                BoundaryEffectV3("resource", "result:0", "create"),
            ),
        )

        first_physical = physical_profile_from_library_v3(first)
        second_physical = physical_profile_from_library_v3(second)

        self.assertEqual(first_physical.profile_id, second_physical.profile_id)
        self.assertEqual(
            compare_physical_abis(first_physical, second_physical).kind,
            "exact",
        )

    def test_callback_slot_cannot_reference_a_missing_argument(self) -> None:
        profile = legacy_profile(
            callback_slots=(CallbackSlotV3(1, "callback-profile-v1", True),)
        )

        with self.assertRaisesRegex(ValueError, "exceeds the ABI argument"):
            physical_profile_from_library_v3(profile)


if __name__ == "__main__":
    unittest.main()
