import json
import re
import tempfile
import unittest
from pathlib import Path

from spaghetti_extractor.relational.lean.interpreter_mixed_chunked_acceptance import (
    INTERPRETER_MIXED_CHUNKED_ACCEPTANCE_INVENTORY,
    INTERPRETER_MIXED_CHUNKED_ACCEPTANCE_MODULE,
    InterpreterMixedChunkedAcceptanceGenerationError,
    InterpreterMixedChunkedAcceptanceSpec,
    relational_interpreter_mixed_chunked_acceptance_inventory,
    relational_interpreter_mixed_chunked_acceptance_source,
    write_relational_interpreter_mixed_chunked_acceptance,
)
from spaghetti_extractor.relational.schema import (
    RELATIONAL_MIXED_CHUNKED_ACCEPTANCE_PROFILE,
    RELATIONAL_MIXED_CHUNKED_ACCEPTANCE_THEOREM,
    RELATIONAL_MIXED_CHUNKED_ACCEPTANCE_TYPE,
    RELATIONAL_MIXED_CHUNKED_PROFILE_TERM,
)


def _spec(**changes: str) -> InterpreterMixedChunkedAcceptanceSpec:
    values = {
        "binding_module": "StageA.GeneratedConcreteMixedBinding",
        "source_parameter_type": (
            "StageA.GeneratedConcreteMixedBinding.Parameters"
        ),
        "source_profile": (
            "StageA.GeneratedConcreteMixedBinding."
            "generatedCanonicalMixedRelationProfile"
        ),
        "source_theorem": (
            "StageA.GeneratedConcreteMixedBinding."
            "generatedMixedWorldProgramsEquivalent"
        ),
    }
    values.update(changes)
    return InterpreterMixedChunkedAcceptanceSpec(**values)


class StageARelationalInterpreterMixedChunkedAcceptanceTests(
    unittest.TestCase
):
    def test_source_exposes_only_the_closed_public_theorem(self) -> None:
        source = relational_interpreter_mixed_chunked_acceptance_source(_spec())

        self.assertIn(
            "abbrev candidatePE32CanonicalMixedRelationProfile", source
        )
        self.assertIn(
            "def candidatePE32CanonicalMixedRelationFamily", source
        )
        self.assertIn(
            "theorem candidatePE32ProgramsEquivalentMixedChunked :", source
        )
        self.assertIn(
            "CanonicalMixedWorldProgramsChunkObservationallyEquivalent", source
        )
        self.assertIn("intro parameters", source)
        self.assertNotIn("requirements", source)
        for forbidden in ("axiom", "sorry", "native_decide", "unsafe"):
            self.assertIsNone(re.search(rf"\b{forbidden}\b", source))

    def test_inventory_is_typed_but_never_report_authority(self) -> None:
        inventory = relational_interpreter_mixed_chunked_acceptance_inventory(
            _spec()
        )

        self.assertFalse(inventory["acceptance_authority"])
        self.assertFalse(inventory["report_authority"])
        self.assertTrue(inventory["lean_check_required"])
        self.assertEqual(
            inventory["theorem"], RELATIONAL_MIXED_CHUNKED_ACCEPTANCE_THEOREM
        )
        self.assertEqual(
            inventory["profile"], RELATIONAL_MIXED_CHUNKED_ACCEPTANCE_PROFILE
        )
        self.assertEqual(
            inventory["profile_term"], RELATIONAL_MIXED_CHUNKED_PROFILE_TERM
        )
        self.assertEqual(
            inventory["canonical_type"], RELATIONAL_MIXED_CHUNKED_ACCEPTANCE_TYPE
        )

    def test_writer_emits_source_and_matching_inventory(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source_path, inventory_path = (
                write_relational_interpreter_mixed_chunked_acceptance(
                    root, _spec()
                )
            )

            self.assertEqual(
                source_path.name,
                f"{INTERPRETER_MIXED_CHUNKED_ACCEPTANCE_MODULE}.lean",
            )
            self.assertEqual(
                inventory_path.name,
                INTERPRETER_MIXED_CHUNKED_ACCEPTANCE_INVENTORY,
            )
            payload = json.loads(inventory_path.read_text(encoding="utf-8"))
            self.assertEqual(
                payload["theorem"],
                RELATIONAL_MIXED_CHUNKED_ACCEPTANCE_THEOREM,
            )

    def test_rejects_unqualified_source_terms(self) -> None:
        for field in (
            "source_parameter_type",
            "source_profile",
            "source_theorem",
        ):
            with self.subTest(field=field):
                with self.assertRaisesRegex(
                    InterpreterMixedChunkedAcceptanceGenerationError,
                    field,
                ):
                    relational_interpreter_mixed_chunked_acceptance_source(
                        _spec(**{field: "unqualified"})
                    )
