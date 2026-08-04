from __future__ import annotations

import unittest

from spaghetti_extractor.finite_value_domain import FiniteU32Dataflow


def _unit(
    identity: str,
    rva: int,
    *,
    targets: tuple[int, ...] = (),
    writes: tuple[tuple[str, dict], ...] = (),
    guards: tuple[tuple[int, dict], ...] = (),
    external: bool = False,
) -> dict:
    return {
        "id": identity,
        "source": {"original": {"rva_start": rva, "rva_end": rva + 1}},
        "control": {"direct_targets": list(targets)},
        "semantics": {
            "edge_conditions": [
                {"target_rva": target, "condition": condition}
                for target, condition in guards
            ],
            "external_events": [{"kind": "fixture"}] if external else [],
            "register_writes": [
                {"register": register, "value": value}
                for register, value in writes
            ],
        },
    }


def _reg(name: str) -> dict:
    return {"op": "reg", "name": name, "width": 32}


def _const(value: int) -> dict:
    return {"op": "const", "value": value, "width": 32}


class FiniteU32DataflowTests(unittest.TestCase):
    def test_mask_has_finite_domain_from_unknown_root_state(self) -> None:
        analysis = FiniteU32Dataflow(
            units=[_unit("root", 0x1000)],
            roots=["root"],
        )

        result = analysis.expression_domain(
            "root",
            {"op": "and32", "args": [_reg("eax"), _const(3)]},
        )

        self.assertEqual(result["status"], "complete")
        self.assertEqual(result["values"], [0, 1, 2, 3])

    def test_guard_bounds_input_before_wrapping_subtraction(self) -> None:
        root = _unit(
            "root",
            0x1000,
            targets=(0x1010,),
            writes=(("ecx", {"op": "sub32", "args": [_reg("ecx"), _const(4)]}),),
            guards=((
                0x1010,
                {"op": "ult32", "args": [_reg("ecx"), _const(4)]},
            ),),
        )
        analysis = FiniteU32Dataflow(
            units=[root, _unit("dispatch", 0x1010)],
            roots=["root"],
        )

        result = analysis.expression_domain("dispatch", _reg("ecx"))

        self.assertEqual(
            result["values"],
            [0xFFFFFFFC, 0xFFFFFFFD, 0xFFFFFFFE, 0xFFFFFFFF],
        )

    def test_finite_assignment_survives_loop_and_join(self) -> None:
        units = [
            _unit(
                "root",
                0x1000,
                targets=(0x1010,),
                writes=(("edx", _const(3)),),
            ),
            _unit("loop", 0x1010, targets=(0x1010, 0x1020)),
            _unit("dispatch", 0x1020),
        ]
        analysis = FiniteU32Dataflow(units=units, roots=["root"])

        result = analysis.expression_domain("dispatch", _reg("edx"))

        self.assertEqual(result["status"], "complete")
        self.assertEqual(result["values"], [3])

    def test_recovered_indirect_edge_propagates_register_state(self) -> None:
        source = _unit(
            "source",
            0x1000,
            writes=(("ecx", _const(0)),),
        )
        analysis = FiniteU32Dataflow(
            units=[source, _unit("dispatch", 0x2000)],
            roots=["source"],
            recovered_indirect_targets=[{
                "status": "recovered",
                "source_unit_id": "source",
                "target_unit_ids": ["dispatch"],
            }],
        )

        result = analysis.expression_domain(
            "dispatch",
            {"op": "neg32", "args": [_reg("ecx")]},
        )

        self.assertEqual(result["values"], [0])

    def test_unknown_join_and_external_transition_fail_closed(self) -> None:
        units = [
            _unit(
                "finite",
                0x1000,
                targets=(0x1020,),
                writes=(("eax", _const(1)),),
            ),
            _unit("external", 0x1010, targets=(0x1020,), external=True),
            _unit("join", 0x1020),
        ]
        analysis = FiniteU32Dataflow(
            units=units,
            roots=["finite", "external"],
        )

        result = analysis.expression_domain("join", _reg("eax"))

        self.assertEqual(result["status"], "incomplete")
        self.assertEqual(
            result["failure"]["code"],
            "expression_domain_unbounded",
        )

    def test_internal_call_reaches_callee_with_unknown_entry_state(self) -> None:
        caller = _unit("caller", 0x1000)
        caller["semantics"]["external_events"] = [
            {"kind": "internal_call", "target_rva": 0x2000}
        ]
        analysis = FiniteU32Dataflow(
            units=[caller, _unit("callee", 0x2000)],
            roots=["caller"],
        )

        masked = analysis.expression_domain(
            "callee",
            {"op": "and32", "args": [_reg("eax"), _const(3)]},
        )
        unmasked = analysis.expression_domain("callee", _reg("eax"))

        self.assertEqual(masked["values"], [0, 1, 2, 3])
        self.assertEqual(unmasked["status"], "incomplete")

    def test_nonzero_mask_guard_survives_register_copy(self) -> None:
        nonzero_low_bits = {
            "op": "not",
            "args": [{
                "op": "eq",
                "args": [
                    {"op": "and32", "args": [_reg("edi"), _const(3)]},
                    _const(0),
                ],
            }],
        }
        units = [
            _unit(
                "guard",
                0x1000,
                targets=(0x1010,),
                guards=((0x1010, nonzero_low_bits),),
            ),
            _unit(
                "copy",
                0x1010,
                targets=(0x1020,),
                writes=(("eax", _reg("edi")),),
            ),
            _unit("dispatch", 0x1020),
        ]
        analysis = FiniteU32Dataflow(units=units, roots=["guard"])

        result = analysis.expression_domain(
            "dispatch",
            {"op": "and32", "args": [_reg("eax"), _const(3)]},
        )

        self.assertEqual(result["values"], [1, 2, 3])

    def test_unsigned_guard_bounds_preserved_register(self) -> None:
        units = [
            _unit(
                "guard",
                0x1000,
                targets=(0x1010,),
                guards=((
                    0x1010,
                    {"op": "ult32", "args": [_reg("ecx"), _const(8)]},
                ),),
            ),
            _unit("dispatch", 0x1010),
        ]
        analysis = FiniteU32Dataflow(units=units, roots=["guard"])

        result = analysis.expression_domain("dispatch", _reg("ecx"))

        self.assertEqual(result["values"], list(range(8)))

    def test_masked_guard_constrains_register_written_from_expression(self) -> None:
        adjusted_pointer = {
            "op": "add32",
            "args": [_const(0xFFFFFFFC), _reg("ecx"), _reg("edi")],
        }
        nonzero_low_bits = {
            "op": "not",
            "args": [{
                "op": "eq",
                "args": [
                    {"op": "and32", "args": [adjusted_pointer, _const(3)]},
                    _const(0),
                ],
            }],
        }
        units = [
            _unit(
                "adjust",
                0x1000,
                targets=(0x1010,),
                writes=(("edi", adjusted_pointer),),
                guards=((0x1010, nonzero_low_bits),),
            ),
            _unit(
                "copy",
                0x1010,
                targets=(0x1020,),
                writes=(("eax", _reg("edi")),),
            ),
            _unit("dispatch", 0x1020),
        ]
        analysis = FiniteU32Dataflow(units=units, roots=["adjust"])

        result = analysis.expression_domain(
            "dispatch",
            {"op": "and32", "args": [_reg("eax"), _const(3)]},
        )

        self.assertEqual(result["values"], [1, 2, 3])

    def test_bitwise_and_with_unknown_preserves_finite_submask_invariant(self) -> None:
        units = [
            _unit(
                "root",
                0x1000,
                targets=(0x1010,),
                writes=(("edx", _const(3)),),
            ),
            _unit(
                "loop",
                0x1010,
                targets=(0x1010, 0x1020),
                writes=((
                    "edx",
                    {"op": "and32", "args": [_reg("ecx"), _reg("edx")]},
                ),),
            ),
            _unit("dispatch", 0x1020),
        ]
        analysis = FiniteU32Dataflow(units=units, roots=["root"])

        result = analysis.expression_domain("dispatch", _reg("edx"))

        self.assertEqual(result["values"], [0, 1, 2, 3])


if __name__ == "__main__":
    unittest.main()
