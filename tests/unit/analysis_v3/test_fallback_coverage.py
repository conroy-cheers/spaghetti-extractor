from __future__ import annotations

import tempfile
import unittest
from dataclasses import replace
from pathlib import Path

from spaghetti_extractor.analysis_v3.fallback_coverage import (
    FALLBACK_COVERAGE_CODEC_V3,
    FALLBACK_COVERAGE_PHASE_V3,
    IMPLEMENTATION_CAPABILITIES_ARTIFACT_KIND_V3,
    IMPLEMENTATION_CAPABILITY_CODEC_V3,
    ImplementationCapabilityV3,
    implementation_capability_sha256_v3,
)
from spaghetti_extractor.analysis_v3.isa_qualification import (
    ISA_QUALIFICATION_EVIDENCE_ARTIFACT_KIND_V3,
    ISA_QUALIFICATION_EVIDENCE_CODEC_V3,
    ISA_QUALIFICATION_PHASE_V3,
)
from spaghetti_extractor.artifact_set_v3 import ArtifactSetReaderV3
from tests.unit.analysis_v3.test_isa_qualification import (
    BINDING,
    _base_inputs,
    _evidence,
    _write,
)


def _capability(exact) -> ImplementationCapabilityV3:
    provisional = ImplementationCapabilityV3(
        record_id=exact.unit_id,
        capability_id="machine-ir-fallback-v3",
        implementation_kind="machine_ir_fallback",
        implementation_sha256="1" * 64,
        pe_sha256=exact.pe_sha256,
        unit_ir_sha256=exact.unit_ir_sha256,
        unit_id=exact.unit_id,
        unit_sha256=exact.unit_sha256,
        selected_form_ids=("form:push-r32",),
        capability_sha256="0" * 64,
    )
    return replace(
        provisional,
        capability_sha256=implementation_capability_sha256_v3(provisional),
    )


class FallbackCoverageV3Tests(unittest.TestCase):
    def _run(self, root: Path, capability: ImplementationCapabilityV3):
        _exact_path, semantic_path, closure_path, exact = _base_inputs(root)
        evidence = _evidence(exact)
        evidence_path = _write(
            root / "isa-evidence",
            ISA_QUALIFICATION_EVIDENCE_ARTIFACT_KIND_V3,
            (
                ISA_QUALIFICATION_EVIDENCE_CODEC_V3.write(
                    evidence.record_id, evidence
                ),
            ),
        )
        isa_path = ISA_QUALIFICATION_PHASE_V3.run(
            output_directory=root / "isa",
            inputs={
                "isa_evidence": evidence_path,
                "root_closure": closure_path,
                "semantic_index": semantic_path,
            },
            bindings=(BINDING,),
        ).output_directory
        capability_path = _write(
            root / "capabilities",
            IMPLEMENTATION_CAPABILITIES_ARTIFACT_KIND_V3,
            (
                IMPLEMENTATION_CAPABILITY_CODEC_V3.write(
                    capability.record_id, capability
                ),
            ),
        )
        output = FALLBACK_COVERAGE_PHASE_V3.run(
            output_directory=root / "fallback",
            inputs={
                "implementation_capabilities": capability_path,
                "isa_qualification": isa_path,
                "semantic_index": semantic_path,
            },
            bindings=(BINDING,),
        ).output_directory
        record = ArtifactSetReaderV3(output).get_record(exact.unit_id)
        return FALLBACK_COVERAGE_CODEC_V3.read(record).value

    def test_positive_capability_covers_selected_forms_and_exact_unit(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            _exact_path, _semantic_path, _closure_path, exact = _base_inputs(root / "seed")
            checked = self._run(root / "run", _capability(exact))
            self.assertEqual(checked.status, "complete")
            self.assertTrue(checked.authorizing)
            self.assertEqual(
                checked.selected_form_ids, ("form:push-r32",)
            )
            self.assertEqual(
                checked.capability_id, "machine-ir-fallback-v3"
            )

    def test_binding_form_and_hash_mismatches_are_violations(self) -> None:
        for label, mutate, expected_code in (
            (
                "binding",
                lambda row: replace(row, unit_sha256="8" * 64),
                "implementation_capability_binding_contradiction",
            ),
            (
                "forms",
                lambda row: replace(row, selected_form_ids=()),
                "implementation_capability_form_mismatch",
            ),
            (
                "hash",
                lambda row: replace(row, capability_sha256="9" * 64),
                "implementation_capability_hash_mismatch",
            ),
        ):
            with self.subTest(label=label), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                _exact_path, _semantic_path, _closure_path, exact = _base_inputs(root / "seed")
                capability = mutate(_capability(exact))
                if label != "hash":
                    capability = replace(
                        capability,
                        capability_sha256=implementation_capability_sha256_v3(
                            capability
                        ),
                    )
                checked = self._run(root / "run", capability)
                self.assertEqual(checked.status, "violated")
                self.assertFalse(checked.authorizing)
                self.assertEqual(checked.primary_blocker.code, expected_code)
                self.assertEqual(checked.selected_form_ids, ())
                self.assertIsNone(checked.capability_id)


if __name__ == "__main__":
    unittest.main()
