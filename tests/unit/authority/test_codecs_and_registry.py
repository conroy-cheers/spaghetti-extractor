from __future__ import annotations

import unittest

from spaghetti_extractor.authority._schema import AnalysisV3Error
from spaghetti_extractor.authority.exact_units import (
    EXACT_UNIT_CODEC_V3,
    ExactUnitV3,
)
from spaghetti_extractor.authority.registry import (
    AUTHORITY_PHASE_REGISTRY_V3,
    AuthorityPhaseRegistryV3,
)
from spaghetti_extractor.artifacts.artifact_set import (
    ArtifactV3Error,
    CanonicalValueV3,
    PlainJsonCodecV3,
    canonical_sha256_v3,
    value_codec_v3,
)


class AnalysisV3CodecAndRegistryTests(unittest.TestCase):
    def test_plain_json_codec_round_trips_without_interned_nodes(self) -> None:
        value = CanonicalValueV3.of(
            {"large": [{"unit": index, "register": "eax"} for index in range(32)]}
        )
        codec = PlainJsonCodecV3()
        encoded = codec.encode(value)

        self.assertEqual(encoded.nodes, ())
        self.assertEqual(codec.decode(encoded.root, {}), value)
        self.assertIsInstance(value_codec_v3(codec.identity), PlainJsonCodecV3)

        with self.assertRaises(ArtifactV3Error) as raised:
            codec.decode(encoded.root, {"value-node:stale": {}})
        self.assertEqual(raised.exception.code, "invalid_plain_json_value")

    def test_exact_unit_codec_rejects_stale_record_identity(self) -> None:
        unit = {
            "id": "unit:one",
            "source": {
                "original": {"rva_start": 0x1000, "rva_end": 0x1008},
                "instruction_bytes_sha256": "b" * 64,
            },
        }
        exact = ExactUnitV3(
            record_id="unit:one",
            unit_id="unit:one",
            pe_sha256="a" * 64,
            unit_ir_sha256=canonical_sha256_v3(unit),
            unit_sha256=canonical_sha256_v3(unit),
            instruction_bytes_sha256="b" * 64,
            rva_start=0x1000,
            rva_end=0x1008,
            unit=CanonicalValueV3.of(unit),
        )
        record = EXACT_UNIT_CODEC_V3.write(exact.record_id, exact)
        payload = record.value.to_value()
        payload["id"] = "unit:stale"

        with self.assertRaises(AnalysisV3Error) as raised:
            EXACT_UNIT_CODEC_V3.decode(payload)

        self.assertEqual(raised.exception.code, "stale_record_id")

    def test_registry_is_complete_and_rejects_partial_family(self) -> None:
        self.assertEqual(
            AUTHORITY_PHASE_REGISTRY_V3.names,
            (
                "call-boundary-contracts-v3",
                "callback-authority-v4",
                "canonical-external-sites-v3",
                "exact-units-v3",
                "exceptional-transitions-v3",
                "fallback-coverage-v3",
                "final-authority-v3",
                "incoming-call-frames-v3",
                "indirect-target-certificates-v3",
                "inductive-authority-v3",
                "isa-qualification-v3",
                "launch-root-closure-v3",
            "memory-versions-v3",
            "parametric-scc-summaries-v3",
            "parametric-unit-facts-v3",
            "semantic-index-v3",
                "structural-target-proposals-v3",
                "transition-summaries-v3",
            ),
        )
        partial = AuthorityPhaseRegistryV3.create(
            (AUTHORITY_PHASE_REGISTRY_V3.get("exact-units-v3"),)
        )

        with self.assertRaises(AnalysisV3Error) as raised:
            partial.require_complete_family()

        self.assertEqual(raised.exception.code, "incomplete_phase_registry")


if __name__ == "__main__":
    unittest.main()
