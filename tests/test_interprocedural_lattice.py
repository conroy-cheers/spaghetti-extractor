from __future__ import annotations

import itertools
import unittest

from spaghetti_extractor.analysis.interprocedural_lattice import (
    Bottom,
    Conflict,
    Exact,
    Finite,
    InterproceduralFact,
    MustPreservedRegisters,
    NoExactValue,
    ReturnBehavior,
    Taint,
    Top,
    bounded_may_join,
    finite,
)


class MayValueTests(unittest.TestCase):
    def test_bottom_finite_and_top_are_explicit(self) -> None:
        self.assertIsInstance(finite([]), Bottom)
        concrete_none = Finite(frozenset({None}))
        self.assertNotEqual(concrete_none, Bottom())
        self.assertEqual(
            concrete_none.project(),
            {"kind": "finite", "complete": True, "values": [None]},
        )
        with self.assertRaisesRegex(ValueError, "Bottom"):
            Finite(frozenset())

    def test_bounded_join_promotes_overflow_to_incomplete_top(self) -> None:
        joined = bounded_may_join(
            Finite(frozenset({1, 2})),
            Finite(frozenset({2, 3})),
            maximum=2,
        )
        self.assertIsInstance(joined, Top)
        self.assertFalse(joined.complete)
        self.assertEqual(joined.project(), {"kind": "top", "complete": False})

    def test_bounded_may_join_obeys_semilattice_laws(self) -> None:
        values = (
            Bottom(),
            Finite(frozenset({1})),
            Finite(frozenset({2})),
            Finite(frozenset({1, 2})),
            Top(),
        )
        join = lambda left, right: left.join(right, maximum=2)
        for value in values:
            self.assertEqual(join(value, value), value)
        for left, right in itertools.product(values, repeat=2):
            self.assertEqual(join(left, right), join(right, left))
        for left, middle, right in itertools.product(values, repeat=3):
            self.assertEqual(
                join(join(left, middle), right),
                join(left, join(middle, right)),
            )

    def test_projection_sorts_structured_values(self) -> None:
        value = Finite(frozenset({("z", 2), ("a", 1)}))
        self.assertEqual(
            value.project(),
            {
                "kind": "finite",
                "complete": True,
                "values": [["a", 1], ["z", 2]],
            },
        )


class ComponentLatticeTests(unittest.TestCase):
    def test_must_preserved_registers_meet_by_intersection(self) -> None:
        left = MustPreservedRegisters(frozenset({"EAX", "ebx", "esi"}))
        right = MustPreservedRegisters(frozenset({"ebx", "edi", "esi"}))

        self.assertEqual(
            left.meet(right),
            MustPreservedRegisters(frozenset({"ebx", "esi"})),
        )
        self.assertTrue(left.leq(MustPreservedRegisters(frozenset({"ebx"}))))
        self.assertEqual(
            left.project(),
            {"kind": "must", "registers": ["eax", "ebx", "esi"]},
        )

    def test_exact_facts_keep_equal_values_and_expose_conflicts(self) -> None:
        bottom = NoExactValue[int]()
        four = Exact(4)
        twelve = Exact(12)

        self.assertEqual(bottom.join(four), four)
        self.assertEqual(four.join(Exact(4)), four)
        self.assertIsInstance(four.join(twelve), Conflict)
        self.assertEqual(
            four.join(twelve).project(),
            {"kind": "conflict", "complete": False},
        )

    def test_return_behavior_and_taint_only_grow(self) -> None:
        returning = ReturnBehavior(may_return=True)
        terminating = ReturnBehavior(may_not_return=True, incomplete=True)
        joined = returning.join(terminating)

        self.assertEqual(joined, ReturnBehavior(True, True, True))
        self.assertTrue(returning.leq(joined))
        self.assertFalse(joined.leq(returning))

        clean = Taint[str]()
        first = Taint.of(["indirect-edge"])
        both = first.join(Taint.of(["external-summary"]))
        self.assertTrue(clean.leq(first))
        self.assertTrue(first.leq(both))
        self.assertEqual(
            both.project(),
            {
                "tainted": True,
                "labels": ["external-summary", "indirect-edge"],
            },
        )


class ProductLatticeTests(unittest.TestCase):
    _REGISTERS = frozenset({"eax", "ebx", "esi"})

    def _fact(
        self,
        values: frozenset[int],
        preserved: frozenset[str],
        cleanup: int,
        result: str,
        *,
        may_return: bool = False,
        taint: str | None = None,
    ) -> InterproceduralFact[int, int, str, str]:
        return InterproceduralFact(
            may_values=Finite(values),
            preserved_registers=MustPreservedRegisters(preserved),
            stack_cleanup=Exact(cleanup),
            results=Exact(result),
            return_behavior=ReturnBehavior(may_return=may_return),
            taint=Taint.of([] if taint is None else [taint]),
        )

    def test_product_join_combines_each_domain_conservatively(self) -> None:
        left = self._fact(
            frozenset({1}),
            frozenset({"eax", "ebx"}),
            4,
            "eax:argument-0",
            may_return=True,
            taint="proposal",
        )
        right = self._fact(
            frozenset({2}),
            frozenset({"ebx", "esi"}),
            8,
            "eax:constant-0",
        )

        joined = left.join(right, maximum=2)

        self.assertEqual(joined.may_values, Finite(frozenset({1, 2})))
        self.assertEqual(
            joined.preserved_registers,
            MustPreservedRegisters(frozenset({"ebx"})),
        )
        self.assertIsInstance(joined.stack_cleanup, Conflict)
        self.assertIsInstance(joined.results, Conflict)
        self.assertEqual(joined.return_behavior, ReturnBehavior(may_return=True))
        self.assertEqual(joined.taint, Taint.of(["proposal"]))
        self.assertFalse(joined.complete)

    def test_product_obeys_lattice_laws_and_has_explicit_bottom(self) -> None:
        bottom = InterproceduralFact.bottom(self._REGISTERS)
        values = (
            bottom,
            self._fact(
                frozenset({1}),
                frozenset({"eax", "ebx"}),
                4,
                "eax:argument-0",
            ),
            self._fact(
                frozenset({2}),
                frozenset({"ebx", "esi"}),
                4,
                "eax:argument-0",
                may_return=True,
                taint="edge-growth",
            ),
            self._fact(
                frozenset({1, 2}),
                frozenset({"ebx"}),
                8,
                "eax:constant-0",
            ),
        )
        join = lambda left, right: left.join(right, maximum=3)

        for value in values:
            self.assertEqual(join(bottom, value), value)
            self.assertEqual(join(value, value), value)
        for left, right in itertools.product(values, repeat=2):
            self.assertEqual(join(left, right), join(right, left))
        for left, middle, right in itertools.product(values, repeat=3):
            self.assertEqual(
                join(join(left, middle), right),
                join(left, join(middle, right)),
            )

    def test_product_projection_is_stable_and_explicit(self) -> None:
        fact = self._fact(
            frozenset({9, 3}),
            frozenset({"esi", "eax"}),
            4,
            "eax:argument-0",
            may_return=True,
            taint="recursive",
        )

        self.assertEqual(
            fact.project(),
            {
                "complete": True,
                "may_values": {
                    "kind": "finite",
                    "complete": True,
                    "values": [3, 9],
                },
                "preserved_registers": {
                    "kind": "must",
                    "registers": ["eax", "esi"],
                },
                "stack_cleanup": {
                    "kind": "exact",
                    "complete": True,
                    "value": 4,
                },
                "results": {
                    "kind": "exact",
                    "complete": True,
                    "value": "eax:argument-0",
                },
                "return_behavior": {
                    "status": "complete",
                    "may_return": True,
                    "may_not_return": False,
                },
                "taint": {"tainted": True, "labels": ["recursive"]},
            },
        )


if __name__ == "__main__":
    unittest.main()
