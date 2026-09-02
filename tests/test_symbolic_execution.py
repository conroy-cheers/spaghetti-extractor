from __future__ import annotations

from types import SimpleNamespace
import unittest

from spaghetti_extractor.pe32.model import BlockSide
from spaghetti_extractor.static_program.model import StaticUnitContext
from spaghetti_extractor.static_program.semantics.symbolic_execution import (
    _symbolic_execute,
)
from spaghetti_extractor.static_program.semantics.transfer import semantic_transfer


def _execute(encoded: bytes) -> dict[str, object]:
    side = BlockSide(0x1000, 0x1000 + len(encoded))
    mapping = StaticUnitContext(
        id="fixture",
        span=side,
        kind="fixture",
        invariant_checked=True,
        source={},
    )
    binary = SimpleNamespace(bitness=32, image_base=0x400000)
    return _symbolic_execute(binary, side, encoded, "fixture", mapping)


class SymbolicExecutionInstructionTests(unittest.TestCase):
    def test_single_instruction_transfer_emits_exact_effect_schedule(self) -> None:
        encoded = b"\x90"
        side = BlockSide(0x1000, 0x1001)
        mapping = StaticUnitContext(
            id="fixture",
            span=side,
            kind="fixture",
            invariant_checked=True,
            source={},
        )
        binary = SimpleNamespace(
            bitness=32,
            image_base=0x400000,
            pe=SimpleNamespace(get_data=lambda rva, size: encoded),
        )

        contract = semantic_transfer(
            binary,
            mapping,
            "fixture",
        )

        self.assertEqual(contract["status"], "reimplementable")
        schedule = contract["instruction_effect_schedule"]
        self.assertEqual(schedule["status"], "complete")
        self.assertEqual(schedule["counts"]["instructions"], 1)
        self.assertEqual(schedule["records"][0]["rva_start"], 0x1000)

    def test_fabs_is_exported_as_checked_x87_replay(self) -> None:
        encoded = b"\xd9\xe1"
        side = BlockSide(0x1000, 0x1002)
        mapping = StaticUnitContext(
            id="fixture",
            span=side,
            kind="fixture",
            invariant_checked=True,
            source={},
        )
        binary = SimpleNamespace(
            bitness=32,
            image_base=0x400000,
            pe=SimpleNamespace(get_data=lambda rva, size: encoded),
        )

        symbolic = _execute(encoded)
        self.assertEqual(symbolic["status"], "ok")
        self.assertEqual(symbolic["observables"]["fpu_stack"][0][0], "fpu_abs")

        contract = semantic_transfer(binary, mapping, "fixture")
        self.assertEqual(contract["status"], "incomplete")
        self.assertEqual(
            contract["blocker_category"],
            "x87_physical_state_requires_native_exact_command_replay",
        )
        schedule = contract["instruction_effect_schedule"]
        self.assertEqual(schedule["status"], "complete")
        self.assertEqual(schedule["counts"]["x87_singletons"], 1)
        self.assertEqual(
            schedule["records"][0]["instruction_class"],
            "x87_singleton_checked_replay",
        )

    def test_unmodeled_register_only_x87_is_typed_without_claiming_authority(self) -> None:
        encoded = b"\xda\xc9"  # fcmove st(0), st(1)
        side = BlockSide(0x1000, 0x1002)
        mapping = StaticUnitContext(
            id="fixture",
            span=side,
            kind="fixture",
            invariant_checked=True,
            source={},
        )
        binary = SimpleNamespace(
            bitness=32,
            image_base=0x400000,
            pe=SimpleNamespace(get_data=lambda rva, size: encoded),
        )

        symbolic = _execute(encoded)
        self.assertEqual(symbolic["status"], "ok")
        self.assertEqual(
            symbolic["observables"]["fpu_stack"][0],
            ("x87_exact_replay_output", 0x1000, "stack", 0),
        )

        contract = semantic_transfer(binary, mapping, "fixture")
        self.assertEqual(contract["status"], "incomplete")
        self.assertEqual(
            contract["blocker_category"],
            "x87_physical_state_requires_native_exact_command_replay",
        )
        schedule = contract["instruction_effect_schedule"]
        self.assertEqual(schedule["status"], "complete")
        self.assertEqual(schedule["counts"]["x87_singletons"], 1)
        self.assertFalse(schedule["records"][0]["classification"]["proof_authority"])

    def test_unmodeled_x87_memory_effect_stays_fail_closed(self) -> None:
        # fldenv has a memory effect whose exact occurrence projection is not
        # modeled by the static memory-action frontend.
        result = _execute(b"\xd9\x20")

        self.assertEqual(result["status"], "incomplete")
        self.assertIn("typed occurrence projection", result["blocker"])

    def test_byte_register_increment_preserves_parent_bits_and_carry(self) -> None:
        result = _execute(b"\xfe\xc0")  # inc al

        self.assertEqual(result["status"], "ok")
        observables = result["observables"]
        eax = observables["reg:eax"]
        self.assertEqual(eax[:4], ("write_bits", ("reg", "eax"), 0, 8))
        self.assertEqual(observables["flag:cf"], ("flag", "cf"))
        self.assertEqual(observables["flag:sf"][0:2], ("msb_w", 8))
        self.assertEqual(observables["flag:pf"][0:2], ("parity", 8))

    def test_word_memory_increment_uses_word_accesses_and_preserves_carry(self) -> None:
        result = _execute(b"\x66\xff\x00")  # inc word ptr [eax]

        self.assertEqual(result["status"], "ok")
        observables = result["observables"]
        events = observables["memory_events"]
        self.assertEqual(events[0], ("read", ("mem", 16, ("reg", "eax"))))
        self.assertEqual(events[1][0:2], ("write", ("mem", 16, ("reg", "eax"))))
        self.assertEqual(observables["flag:cf"], ("flag", "cf"))
        self.assertEqual(observables["flag:sf"][0:2], ("msb_w", 16))

    def test_rotate_through_carry_right_one_updates_only_cf_of_and_destination(self) -> None:
        result = _execute(b"\xd1\xdb")  # rcr ebx, 1

        self.assertEqual(result["status"], "ok")
        observables = result["observables"]
        self.assertEqual(observables["reg:ebx"][0], "or")
        self.assertEqual(observables["flag:cf"][0], "bool_eq")
        self.assertEqual(observables["flag:of"][0], "bool_xor")
        for flag in ("zf", "sf", "pf", "df"):
            self.assertEqual(observables[f"flag:{flag}"], ("flag", flag))

    def test_rotate_right_immediate_preserves_unaffected_flags(self) -> None:
        result = _execute(b"\xc1\xcb\x04")  # ror ebx, 4

        self.assertEqual(result["status"], "ok")
        observables = result["observables"]
        self.assertEqual(observables["reg:ebx"][0], "or")
        self.assertEqual(observables["flag:cf"][0], "ite")
        self.assertEqual(observables["flag:of"][0], "ite")
        for flag in ("zf", "sf", "pf", "df"):
            self.assertEqual(observables[f"flag:{flag}"], ("flag", flag))

    def test_rotate_left_cl_is_represented_without_enumerating_counts(self) -> None:
        result = _execute(b"\xd3\xc0")  # rol eax, cl

        self.assertEqual(result["status"], "ok")
        self.assertEqual(result["observables"]["reg:eax"][0], "or")

    def test_sahf_projects_ah_into_all_five_defined_status_bits(self) -> None:
        result = _execute(b"\x9e")

        self.assertEqual(result["status"], "ok")
        observables = result["observables"]
        for flag in ("cf", "pf", "af", "zf", "sf"):
            self.assertEqual(observables[f"flag:{flag}"][0], "bool_eq")
        self.assertEqual(observables["flag:of"], ("flag", "of"))

    def test_word_imul_preserves_parent_register_and_checks_signed_overflow(self) -> None:
        result = _execute(b"\x66\x69\xef\x18\xfc")  # imul bp, di, -1000

        self.assertEqual(result["status"], "ok")
        observables = result["observables"]
        self.assertEqual(observables["reg:ebp"][:4], ("write_bits", ("reg", "ebp"), 0, 16))
        self.assertEqual(observables["flag:cf"][0], "not")
        self.assertEqual(observables["flag:of"], observables["flag:cf"])
        self.assertEqual(observables["flag:af"][0], "undefined_flag")

    def test_pop_fs_memory_reads_stack_then_writes_segmented_destination(self) -> None:
        result = _execute(b"\x64\x8f\x05\x00\x00\x00\x00")

        self.assertEqual(result["status"], "ok")
        observables = result["observables"]
        self.assertEqual(
            observables["memory_events"],
            (
                ("read", ("mem32", ("reg", "esp"))),
                (
                    "write",
                    ("mem32", ("fs_base",)),
                    ("mem32", ("reg", "esp")),
                ),
            ),
        )
        self.assertEqual(observables["reg:esp"][0], "add")

    def test_pop_esp_uses_popped_value_without_postincrementing_it(self) -> None:
        result = _execute(b"\x5c")

        self.assertEqual(result["status"], "ok")
        self.assertEqual(
            result["observables"]["reg:esp"],
            ("mem32", ("reg", "esp")),
        )


if __name__ == "__main__":
    unittest.main()
