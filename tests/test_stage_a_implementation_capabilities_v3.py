from __future__ import annotations

import json
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path

from spaghetti_extractor.analysis_v3.exact_units import ExactUnitV3
from spaghetti_extractor.analysis_v3.fallback_coverage import (
    FALLBACK_COVERAGE_CODEC_V3,
    FALLBACK_COVERAGE_PHASE_V3,
    IMPLEMENTATION_CAPABILITY_CODEC_V3,
)
from spaghetti_extractor.analysis_v3.isa_qualification import (
    ISA_QUALIFICATION_EVIDENCE_ARTIFACT_KIND_V3,
    ISA_QUALIFICATION_EVIDENCE_CODEC_V3,
    ISA_QUALIFICATION_PHASE_V3,
    isa_qualification_sha256_v3,
)
from spaghetti_extractor.analysis_v3.semantic_index import (
    SEMANTIC_INDEX_ARTIFACT_KIND_V3,
    SEMANTIC_INDEX_CODEC_V3,
    derive_semantic_index_v3,
)
from spaghetti_extractor.artifact_set_v3 import (
    ArtifactRecordV3,
    ArtifactSetReaderV3,
    ArtifactSetWriterV3,
    canonical_json_bytes_v3,
)
from spaghetti_extractor.stage_a_implementation_capabilities_v3 import (
    ImplementationCapabilitiesV3Error,
    emit_implementation_capabilities_v3,
    validate_implementation_capabilities_v3,
)
from spaghetti_extractor.stage_b_fallback_coverage import (
    write_stage_b_fallback_coverage_receipt,
)
from spaghetti_extractor.util import sha256_file
from tests.unit.analysis_v3.test_isa_qualification import (
    BINDING,
    _evidence,
    _unit,
)


def _write_json(path: Path, value: object) -> None:
    path.write_text(
        json.dumps(value, sort_keys=True, indent=2) + "\n", encoding="utf-8"
    )


class _Fixture:
    def __init__(self, root: Path, *, fallback_capability_id: str) -> None:
        self.root = root
        root.mkdir()
        unit = _unit()
        unit["source"]["contract_sha256"] = "b" * 64  # type: ignore[index]
        self.unit = unit
        self.exact = ExactUnitV3.create(unit, pe_sha256=BINDING.sha256)

        self.semantic = root / "semantic-index"
        ArtifactSetWriterV3(
            artifact_kind=SEMANTIC_INDEX_ARTIFACT_KIND_V3,
            bindings=(BINDING,),
        ).write(
            self.semantic,
            (
                SEMANTIC_INDEX_CODEC_V3.write(
                    self.exact.unit_id, derive_semantic_index_v3(self.exact)
                ),
            ),
        )
        evidence = _evidence(self.exact)
        if fallback_capability_id != "machine-ir-fallback-v3":
            evidence = replace(
                evidence,
                fallback_capability_id=fallback_capability_id,
                qualification_sha256="0" * 64,
            )
            evidence = replace(
                evidence,
                qualification_sha256=isa_qualification_sha256_v3(evidence),
            )
        evidence_path = root / "isa-evidence"
        ArtifactSetWriterV3(
            artifact_kind=ISA_QUALIFICATION_EVIDENCE_ARTIFACT_KIND_V3,
            bindings=(BINDING,),
        ).write(
            evidence_path,
            (
                ISA_QUALIFICATION_EVIDENCE_CODEC_V3.write(
                    evidence.record_id, evidence
                ),
            ),
        )
        self.isa = ISA_QUALIFICATION_PHASE_V3.run(
            output_directory=root / "isa",
            inputs={
                "isa_evidence": evidence_path,
                "semantic_index": self.semantic,
            },
            bindings=(BINDING,),
        ).output_directory

        self.machine_ir = root / "machine-ir.jsonl"
        self.machine_ir.write_bytes(canonical_json_bytes_v3(unit) + b"\n")
        self.machine_manifest = root / "machine-ir-manifest.json"
        _write_json(
            self.machine_manifest,
            {
                "format": "stage-a-machine-ir-v2",
                "counts": {"units": 1},
                "artifacts": {
                    "machine_ir": {
                        "format": "stage-a-machine-ir-v2",
                        "path": self.machine_ir.name,
                        "sha256": sha256_file(self.machine_ir),
                    }
                },
            },
        )
        self.interpreter = root / "interpreter"
        self.interpreter.mkdir()
        source = self.interpreter / "state-machine-program.c"
        source.write_text("void fallback_unit(void) {}\n", encoding="ascii")
        adapted = self.interpreter / "machine-ir-adapted-semantics.jsonl"
        adapted.write_bytes(self.machine_ir.read_bytes())
        counts = {
            "input_transfers": 1,
            "transfers": 1,
            "blocked_transfers": 0,
            "deferred_transfers": 0,
        }
        program = self.interpreter / "state-machine-interpreter-program.json"
        _write_json(
            program,
            {
                "format": "stage-b-semantic-interpreter-program-v1",
                "status": "ready",
                "state_machine_sha256": sha256_file(self.machine_ir),
                "counts": counts,
                "blockers": [],
                "semantic_coverage": {
                    "status": "complete",
                    "deferred_transfers": 0,
                    "acceptance_authority": False,
                },
                "execution_policy": "complete_transfer_inventory_v1",
                "transfers": [
                    {
                        "id": self.exact.unit_id,
                        "rva_start": 0x1000,
                        "contract_sha256": "b" * 64,
                        "source_span_sha256": "c" * 64,
                    }
                ],
            },
        )
        package = self.interpreter / "state-machine-interpreter-package.json"
        _write_json(
            package,
            {
                "format": "stage-b-semantic-interpreter-package-v1",
                "status": "ready",
                "machine_ir": {
                    "path": self.machine_ir.name,
                    "sha256": sha256_file(self.machine_ir),
                },
                "input_mode": "sanitized_machine_ir_v2",
                "program": {"path": program.name, "sha256": sha256_file(program)},
                "sources": [
                    {
                        "role": "program_source",
                        "path": source.name,
                        "sha256": sha256_file(source),
                    }
                ],
                "adapted_semantics": {
                    "role": "byte_free_definedness_analysis_input",
                    "path": adapted.name,
                    "sha256": sha256_file(adapted),
                },
                "counts": counts,
                "blockers": [],
                "semantic_coverage": {
                    "status": "complete",
                    "deferred_transfers": 0,
                    "acceptance_authority": False,
                },
                "execution_policy": "complete_transfer_inventory_v1",
            },
        )
        self.receipt = root / "fallback-coverage-receipt.json"
        write_stage_b_fallback_coverage_receipt(
            machine_ir=self.machine_ir,
            machine_ir_manifest=self.machine_manifest,
            interpreter_package=self.interpreter,
            out=self.receipt,
        )
        self.object = root / "fallback-engine.o"
        self.object.write_bytes(b"deterministic compiled fallback engine\x00")

    def emit(
        self,
        output: Path,
        *,
        capability_id: str = "machine-ir-fallback-v3",
        include_object: bool = True,
    ) -> dict:
        return emit_implementation_capabilities_v3(
            machine_ir=self.machine_ir,
            machine_ir_manifest=self.machine_manifest,
            semantic_index_path=self.semantic,
            isa_qualification_path=self.isa,
            interpreter_package=self.interpreter,
            fallback_coverage_receipt=self.receipt,
            implementation_files=(
                {"fallback-engine": self.object} if include_object else {}
            ),
            capability_id=capability_id,
            output_directory=output,
            build_package_identity="fixture-compiler-package",
        )


class ImplementationCapabilitiesV3Tests(unittest.TestCase):
    def test_complete_manifest_projects_exact_checked_unit(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            fixture = _Fixture(root / "fixture", fallback_capability_id="machine-ir-fallback-v3")
            output = root / "output"
            manifest = fixture.emit(output)
            checked = validate_implementation_capabilities_v3(
                output_directory=output,
                expected_implementation_files={"fallback-engine": fixture.object},
            )
            self.assertEqual(manifest, checked)
            self.assertEqual(manifest["status"], "complete")
            self.assertEqual(
                manifest["selected_qualified_form_ids"], ["form:push-r32"]
            )
            projections = ArtifactSetReaderV3(
                output / "implementation-capabilities"
            )
            self.assertEqual(projections.manifest.record_count, 1)
            capability = IMPLEMENTATION_CAPABILITY_CODEC_V3.read(
                projections.get_record(fixture.exact.unit_id)
            ).value
            self.assertEqual(
                capability.implementation_sha256,
                manifest["implementation_sha256"],
            )
            self.assertEqual(
                capability.unit_sha256, fixture.exact.unit_sha256
            )
            fallback_path = FALLBACK_COVERAGE_PHASE_V3.run(
                output_directory=root / "checked-fallback",
                inputs={
                    "implementation_capabilities": (
                        output / "implementation-capabilities"
                    ),
                    "isa_qualification": fixture.isa,
                    "semantic_index": fixture.semantic,
                },
                bindings=(BINDING,),
            ).output_directory
            checked_fallback = FALLBACK_COVERAGE_CODEC_V3.read(
                ArtifactSetReaderV3(fallback_path).get_record(
                    fixture.exact.unit_id
                )
            ).value
            self.assertEqual(checked_fallback.status, "complete")
            self.assertTrue(checked_fallback.authorizing)

    def test_missing_built_engine_is_incomplete_and_projects_nothing(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            fixture = _Fixture(root / "fixture", fallback_capability_id="machine-ir-fallback-v3")
            output = root / "output"
            manifest = fixture.emit(output, include_object=False)
            self.assertEqual(manifest["status"], "incomplete")
            self.assertEqual(
                manifest["issues"][0]["code"], "fallback_engine_bytes_missing"
            )
            self.assertEqual(
                ArtifactSetReaderV3(
                    output / "implementation-capabilities"
                ).manifest.record_count,
                0,
            )

    def test_checked_form_capability_mismatch_is_violated(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            fixture = _Fixture(root / "fixture", fallback_capability_id="different-engine-v3")
            output = root / "output"
            manifest = fixture.emit(output)
            self.assertEqual(manifest["status"], "violated")
            self.assertEqual(
                {row["code"] for row in manifest["issues"]},
                {"fallback_capability_id_mismatch"},
            )
            self.assertEqual(
                ArtifactSetReaderV3(
                    output / "implementation-capabilities"
                ).manifest.record_count,
                0,
            )

    def test_corrupt_built_engine_bytes_fail_validation(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            fixture = _Fixture(root / "fixture", fallback_capability_id="machine-ir-fallback-v3")
            output = root / "output"
            fixture.emit(output)
            (output / "engine/fallback-engine.o").write_bytes(b"corrupt")
            with self.assertRaisesRegex(
                ImplementationCapabilitiesV3Error,
                "implementation hash mismatch",
            ):
                validate_implementation_capabilities_v3(
                    output_directory=output,
                    expected_implementation_files={
                        "fallback-engine": fixture.object
                    },
                )

    def test_stale_interpreter_package_binding_is_violated(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            fixture = _Fixture(root / "fixture", fallback_capability_id="machine-ir-fallback-v3")
            (fixture.interpreter / "state-machine-program.c").write_text(
                "void fallback_unit(void) { for (;;) {} }\n", encoding="ascii"
            )
            manifest = fixture.emit(root / "output")
            self.assertEqual(manifest["status"], "violated")
            self.assertIn(
                "fallback_lowering_binding_contradiction",
                {row["code"] for row in manifest["issues"]},
            )
            self.assertEqual(
                ArtifactSetReaderV3(
                    root / "output/implementation-capabilities"
                ).manifest.record_count,
                0,
            )


if __name__ == "__main__":
    unittest.main()
