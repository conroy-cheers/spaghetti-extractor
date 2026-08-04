from __future__ import annotations

import unittest

from spaghetti_extractor.roundtrip_fuzz.model import CaseExpectation
from spaghetti_extractor.roundtrip_fuzz.runner import _semantic_difference
from spaghetti_extractor.roundtrip_fuzz.semantic import (
    Nop,
    Return,
    SemanticBlock,
    SemanticProgram,
)
from spaghetti_extractor.stage_binary import StageAInputError


def _program(*, with_nop: bool) -> SemanticProgram:
    operations = (Nop(),) if with_nop else ()
    return SemanticProgram(
        id="roundtrip-fixture",
        entry="entry",
        blocks=(
            SemanticBlock(
                id="entry",
                operations=operations,
                terminator=Return(),
            ),
        ),
        static_objects=(),
        observations=(),
        capabilities=(),
    )


class StaticRoundtripTests(unittest.TestCase):
    def test_qualified_expectation_cannot_hide_a_witness(self) -> None:
        with self.assertRaisesRegex(StageAInputError, "cannot name a witness"):
            CaseExpectation.parse(
                {
                    "disposition": "qualified",
                    "witness_family": "semantic-model",
                    "reason_family": None,
                },
                context="fixture expectation",
            )

    def test_semantic_difference_localizes_the_changed_block(self) -> None:
        difference = _semantic_difference(
            _program(with_nop=False),
            _program(with_nop=True),
        )

        self.assertIsNotNone(difference)
        assert difference is not None
        self.assertEqual(difference["family"], "semantic-model")
        self.assertEqual(difference["location_id"], "entry")

    def test_identical_semantic_programs_have_no_difference(self) -> None:
        program = _program(with_nop=False)
        self.assertIsNone(_semantic_difference(program, program))


if __name__ == "__main__":
    unittest.main()
