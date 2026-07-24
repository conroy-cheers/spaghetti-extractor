from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from spaghetti_extractor.relational.lean.interpreter_original_carrier_binding import (
    ORIGINAL_CARRIER_BINDING_MODULE,
    OriginalCarrierBindingGenerationError,
    OriginalCarrierBindingSpec,
    generate_original_carrier_binding,
    write_original_carrier_binding,
)


class StageARelationalInterpreterOriginalCarrierBindingTests(unittest.TestCase):
    def test_generator_emits_compact_stable_binding_api(self) -> None:
        generated = generate_original_carrier_binding(_spec())

        self.assertEqual(generated.module, ORIGINAL_CARRIER_BINDING_MODULE)
        self.assertIn("ranges := [{ start := 0, size := 521 }]", generated.source)
        self.assertIn("ranges := [{ start := 0, size := 524 }]", generated.source)
        self.assertIn("decide +kernel", generated.source)
        self.assertIn(".indexedResolution address", generated.source)
        self.assertIn(".returnResolution address", generated.source)
        self.assertIn(".toExactBinding", generated.source)
        self.assertIn(".toMixedBinding", generated.source)
        self.assertNotIn("forall address", generated.source)
        self.assertNotIn("native_decide", generated.source)
        self.assertNotIn("sorry", generated.source)
        self.assertNotIn("candidatePe", generated.source)
        self.assertNotIn("candidateRecords", generated.source)

        terms = generated.terms
        self.assertEqual(
            terms.certificate, "generatedOriginalCarrierBindingCertificate"
        )
        self.assertEqual(
            terms.indexed_resolution, "generatedOriginalIndexedResolution"
        )
        self.assertEqual(
            terms.return_resolution, "generatedOriginalReturnResolution"
        )
        self.assertEqual(
            terms.finite_binding, "generatedOriginalFiniteCarrierBinding"
        )
        self.assertEqual(
            terms.exact_binding, "generatedOriginalExactCarrierBinding"
        )
        self.assertEqual(
            terms.mixed_binding,
            "generatedOriginalExactMixedProgramBinding",
        )

    def test_zero_sized_inventory_uses_empty_range_certificate(self) -> None:
        generated = generate_original_carrier_binding(
            _spec(target_count=0, address_count=0)
        )
        self.assertEqual(generated.source.count("ranges := []"), 2)

    def test_writer_places_the_declared_module_under_stage_a(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            path = write_original_carrier_binding(root, _spec())
            self.assertEqual(
                path,
                root / "StageA" / f"{ORIGINAL_CARRIER_BINDING_MODULE}.lean",
            )
            self.assertIn(
                "generatedOriginalExactMixedProgramBinding",
                path.read_text(encoding="utf-8"),
            )

    def test_rejects_injected_names_and_invalid_inventory_counts(self) -> None:
        invalid = (
            {"original_module": "GeneratedOriginal"},
            {"original_module": "StageA.Original\naxiom escape : False"},
            {"original_namespace": "StageA.Original; unsafe def escape := 0"},
            {"context_symbol": "context value"},
            {"authority_symbol": "axiom"},
            {"output_module": "Generated.Binding"},
            {"namespace": "StageA.Generated\nend StageA"},
            {"term_prefix": "theorem"},
            {"target_count": -1},
            {"address_count": 2**32},
            {"target_count": True},
        )
        for replacement in invalid:
            with self.subTest(replacement=replacement):
                values = _spec().__dict__ | replacement
                with self.assertRaises(OriginalCarrierBindingGenerationError):
                    generate_original_carrier_binding(
                        OriginalCarrierBindingSpec(**values)
                    )


def _spec(
    *, target_count: int = 521, address_count: int = 524
) -> OriginalCarrierBindingSpec:
    return OriginalCarrierBindingSpec(
        original_module="StageA.GeneratedRelationalInterpreterMixedOriginal",
        original_namespace="StageA.GeneratedRelational.InterpreterMixedOriginal",
        target_count=target_count,
        address_count=address_count,
    )


if __name__ == "__main__":
    unittest.main()
