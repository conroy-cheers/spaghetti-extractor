from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from typing import Any, cast

from spaghetti_extractor.authority._schema import AnalysisV3Error
from spaghetti_extractor.authority.callbacks import (
    CALLBACK_AUTHORITY_CODEC_V3,
    CALLBACK_AUTHORITY_PHASE_V3,
    CALLBACK_EVIDENCE_ARTIFACT_KIND_V3,
    CALLBACK_EVIDENCE_CODEC_V3,
    CallbackEvidenceV3,
)
from spaghetti_extractor.authority.exact_units import (
    EXACT_UNIT_CODEC_V3,
    ExactUnitV3,
)
from spaghetti_extractor.authority.external_site_checker import (
    CANONICAL_EXTERNAL_SITES_PHASE_V3,
)
from spaghetti_extractor.authority.external_site_records import (
    CANONICAL_EXTERNAL_SITE_CODEC_V3,
    EXTERNAL_SITE_EVIDENCE_ARTIFACT_KIND_V3,
    EXTERNAL_SITE_EVIDENCE_CODEC_V3,
    EXTERNAL_PROFILE_ARTIFACT_KIND_V3,
    EXTERNAL_PROFILE_CODEC_V3,
    CallbackRequirementV3,
    ExternalContractV3,
    ExternalProfileV3,
    ExternalSiteEvidenceV3,
    external_site_id_v3,
)
from spaghetti_extractor.authority.semantic_index import (
    SEMANTIC_INDEX_CODEC_V3,
    SEMANTIC_INDEX_PHASE_V3,
)
from spaghetti_extractor.authority.target_certificate_records import (
    INDIRECT_TARGET_CERTIFICATE_UNIT_CODEC_V3,
    IndirectTargetCertificateUnitV3,
)
from spaghetti_extractor.authority.transition_summaries import (
    TRANSITION_SUMMARIES_PHASE_V3,
)
from spaghetti_extractor.artifact_set_v3 import (
    ArtifactBindingV3,
    ArtifactRecordV3,
    ArtifactSetReaderV3,
    ArtifactSetWriterV3,
    CanonicalValueV3,
    canonical_sha256_v3,
)


PE_SHA256 = "a" * 64
PROFILE_SHA256 = "c" * 64
ABI_SHA256 = "d" * 64
BINDING = ArtifactBindingV3("binary", "pe32", "fixture.exe", PE_SHA256)


def _reg(name: str) -> dict[str, object]:
    return {"op": "reg", "name": name, "width": 32}


def _unit(
    unit_id: str,
    rva: int,
    *,
    external_events: list[dict[str, object]] | None = None,
) -> dict[str, object]:
    events = external_events or []
    return {
        "format": "stage-a-machine-ir-v2",
        "record_kind": "unit",
        "id": unit_id,
        "status": "qualified",
        "source": {
            "original": {"rva_start": rva, "rva_end": rva + 8},
            "instruction_bytes_sha256": f"{rva:064x}",
        },
        "expression_model": "stage-a-semantic-ir-v1",
        "instructions": [],
        "semantics": {
            "pre_state": {
                "registers": {"eax": _reg("eax")},
                "flags": {},
                "memory": {
                    "op": "memory",
                    "name": "mem0",
                    "address_width": 32,
                    "value_width": 8,
                },
            },
            "register_writes": [],
            "flag_writes": [],
            "memory_events": [],
            "external_events": events,
            "faults": [],
            "ordered_events": events,
            "edge_conditions": [],
            "outcome": {"kind": "return"},
            "stack_delta": None,
            "counts": {
                "register_writes": 0,
                "flag_writes": 0,
                "memory_events": 0,
                "external_events": len(events),
                "faults": 0,
                "ordered_events": len(events),
                "edge_conditions": 0,
            },
        },
        "control": {
            "kind": "return",
            "direct_targets": [],
            "has_indirect_target": False,
        },
    }


def _write(
    path: Path,
    kind: str,
    records: tuple[ArtifactRecordV3, ...],
    *,
    status: str = "complete",
) -> Path:
    ArtifactSetWriterV3(
        artifact_kind=kind,
        bindings=(BINDING,),
        status=status,
    ).write(path, records)
    return path


def _empty_target_certificates(path: Path, semantic: Path) -> Path:
    records = []
    for source in ArtifactSetReaderV3(semantic).iter_records():
        unit = SEMANTIC_INDEX_CODEC_V3.read(source).value
        checked = IndirectTargetCertificateUnitV3(
            record_id=unit.record_id,
            source_unit_id=unit.record_id,
            unit_sha256=unit.unit_sha256,
            status="complete",
            authorizing=True,
            certificates=(),
            dependencies=(),
            primary_blocker=None,
        )
        records.append(
            INDIRECT_TARGET_CERTIFICATE_UNIT_CODEC_V3.write(
                checked.record_id, checked
            )
        )
    return _write(path, "indirect-target-certificates-v3", tuple(records))


class ExternalAndCallbackAuthorityV3Tests(unittest.TestCase):
    def _inputs(self, root: Path, *, evidence_unit_sha256: str | None = None):
        callback_unit = _unit("callback:unit", 0x2000)
        callback_exact = ExactUnitV3.create(
            callback_unit,
            pe_sha256=PE_SHA256,
        )
        event: dict[str, object] = {
            "kind": "external_call",
            "dll": "Fixture.DLL",
            "symbol": "RegisterCallback",
            "arguments": [],
            "abi_contract": {
                "argument_words": 0,
                "profile_binding": {
                    "profile_id": "fixture-profile",
                    "profile_sha256": PROFILE_SHA256,
                },
                "callback_effect": "registers",
            },
            "callback_requirements": [
                {
                    "target_unit_id": callback_exact.unit_id,
                    "target_rva": callback_exact.rva_start,
                    "abi_sha256": ABI_SHA256,
                    "lifetime": "process",
                }
            ],
        }
        source_unit = _unit("source:unit", 0x1000, external_events=[event])
        source_exact = ExactUnitV3.create(
            source_unit,
            pe_sha256=PE_SHA256,
        )
        exact = _write(
            root / "exact",
            "exact-units-v3",
            (
                EXACT_UNIT_CODEC_V3.write(source_exact.record_id, source_exact),
                EXACT_UNIT_CODEC_V3.write(callback_exact.record_id, callback_exact),
            ),
        )
        transitions = TRANSITION_SUMMARIES_PHASE_V3.run(
            output_directory=root / "transitions",
            inputs={"exact_units": exact},
            bindings=(BINDING,),
        ).output_directory
        semantic = SEMANTIC_INDEX_PHASE_V3.run(
            output_directory=root / "semantic-index",
            inputs={"exact_units": exact},
            bindings=(BINDING,),
        ).output_directory
        target_certificates = _empty_target_certificates(
            root / "target-certificates", semantic
        )
        identity = {
            "kind": "import",
            "dll": "fixture.dll",
            "symbol": "RegisterCallback",
            "ordinal": None,
        }
        site_id = external_site_id_v3("source:unit", 0, 0, event)
        callback = CallbackRequirementV3.create(
            site_id=site_id,
            ordinal=0,
            target_unit_id=callback_exact.unit_id,
            target_rva=callback_exact.rva_start,
            abi_sha256=ABI_SHA256,
            lifetime="process",
        )
        contract = ExternalContractV3.create(
            identity=identity,
            transfer_kind="call",
            disposition="returns",
            profile_id="fixture-profile",
            profile_sha256=PROFILE_SHA256,
            argument_words=0,
            arguments=(),
            memory_effect="none",
            world_effect="registers-callback",
            callback_effect="registers",
            machine_contract={
                "abi_template": "pe32-cdecl-v1",
                "argument_words": 0,
                "disposition": "returns",
                "memory_effect": "none",
                "world_effect": "registers-callback",
                "callback_effect": "registers",
            },
            callbacks=(callback,),
        )
        profile = ExternalProfileV3.create(
            profile_id="fixture-profile",
            profile_sha256=PROFILE_SHA256,
            identity=identity,
            allowed_transfers=("call",),
            allowed_dispositions=("returns",),
            argument_words=0,
            memory_effect="none",
            world_effect="registers-callback",
            callback_effect="registers",
            machine_contract={
                "abi_template": "pe32-cdecl-v1",
                "argument_words": 0,
                "disposition": "returns",
                "memory_effect": "none",
                "world_effect": "registers-callback",
                "callback_effect": "registers",
            },
        )
        profiles = _write(
            root / "external-profiles",
            EXTERNAL_PROFILE_ARTIFACT_KIND_V3,
            (EXTERNAL_PROFILE_CODEC_V3.write(profile.record_id, profile),),
        )
        evidence = ExternalSiteEvidenceV3(
            record_id=site_id,
            unit_id=source_exact.unit_id,
            unit_sha256=(
                source_exact.unit_sha256
                if evidence_unit_sha256 is None
                else evidence_unit_sha256
            ),
            event_index=0,
            event_sha256=canonical_sha256_v3(event),
            alternative_index=0,
            target_sha256=canonical_sha256_v3(event),
            identity=CanonicalValueV3.of(identity),
            status="complete",
            contract=contract,
            primary_blocker=None,
        )
        return (
            semantic,
            transitions,
            target_certificates,
            profiles,
            source_exact,
            callback_exact,
            evidence,
            callback,
        )

    def test_valid_external_site_and_callback_are_exactly_bound(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (
                semantic,
                transitions,
                target_certificates,
                profiles,
                _source_exact,
                callback_exact,
                evidence,
                callback,
            ) = self._inputs(root)
            external_evidence = _write(
                root / "external-evidence",
                EXTERNAL_SITE_EVIDENCE_ARTIFACT_KIND_V3,
                (EXTERNAL_SITE_EVIDENCE_CODEC_V3.write(evidence.record_id, evidence),),
            )
            external = CANONICAL_EXTERNAL_SITES_PHASE_V3.run(
                output_directory=root / "external",
                inputs={
                    "external_profiles": profiles,
                    "external_site_evidence": external_evidence,
                    "semantic_index": semantic,
                    "target_certificates": target_certificates,
                    "transition_summaries": transitions,
                },
                bindings=(BINDING,),
            ).output_directory
            source_external_record = ArtifactSetReaderV3(external).get_record(
                "source:unit"
            )
            source_external = CANONICAL_EXTERNAL_SITE_CODEC_V3.read(
                source_external_record
            ).value
            self.assertEqual(source_external.status, "complete")
            self.assertTrue(source_external.authorizing)
            self.assertEqual(source_external.sites[0].site_id, evidence.record_id)
            self.assertEqual(
                source_external.dependencies, source_external_record.dependencies
            )

            callback_evidence = CallbackEvidenceV3(
                record_id=callback.callback_id,
                external_site_id=evidence.record_id,
                target_unit_id=callback.target_unit_id,
                target_unit_sha256=callback_exact.unit_sha256,
                target_rva=callback.target_rva,
                abi_sha256=callback.abi_sha256,
                lifetime=callback.lifetime,
                status="complete",
                entry_state=CanonicalValueV3.of({"ecx": {"kind": "callback"}}),
                primary_blocker=None,
            )
            callback_inputs = _write(
                root / "callback-evidence",
                CALLBACK_EVIDENCE_ARTIFACT_KIND_V3,
                (
                    CALLBACK_EVIDENCE_CODEC_V3.write(
                        callback_evidence.record_id, callback_evidence
                    ),
                ),
            )
            callback_authority = CALLBACK_AUTHORITY_PHASE_V3.run(
                output_directory=root / "callbacks",
                inputs={
                    "callback_evidence": callback_inputs,
                    "external_sites": external,
                    "semantic_index": semantic,
                },
                bindings=(BINDING,),
            ).output_directory
            callback_record = ArtifactSetReaderV3(callback_authority).get_record(
                "source:unit"
            )
            checked = CALLBACK_AUTHORITY_CODEC_V3.read(callback_record).value
            self.assertEqual(checked.status, "complete")
            self.assertEqual(checked.callbacks[0].callback_id, callback.callback_id)
            self.assertEqual(checked.dependencies, callback_record.dependencies)

    def test_noncomplete_profile_manifest_cannot_authorize_a_site(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (
                semantic,
                transitions,
                target_certificates,
                profiles,
                _source_exact,
                _callback_exact,
                evidence,
                _callback,
            ) = self._inputs(root)
            incomplete_profiles = _write(
                root / "incomplete-profiles",
                EXTERNAL_PROFILE_ARTIFACT_KIND_V3,
                tuple(ArtifactSetReaderV3(profiles).iter_records()),
                status="incomplete",
            )
            external_evidence = _write(
                root / "profile-status-evidence",
                EXTERNAL_SITE_EVIDENCE_ARTIFACT_KIND_V3,
                (EXTERNAL_SITE_EVIDENCE_CODEC_V3.write(evidence.record_id, evidence),),
            )
            external = CANONICAL_EXTERNAL_SITES_PHASE_V3.run(
                output_directory=root / "external-profile-status",
                inputs={
                    "external_profiles": incomplete_profiles,
                    "external_site_evidence": external_evidence,
                    "semantic_index": semantic,
                    "target_certificates": target_certificates,
                    "transition_summaries": transitions,
                },
                bindings=(BINDING,),
            ).output_directory
            checked = CANONICAL_EXTERNAL_SITE_CODEC_V3.read(
                ArtifactSetReaderV3(external).get_record("source:unit")
            ).value
            self.assertEqual(checked.status, "incomplete")
            self.assertIsNotNone(checked.primary_blocker)
            assert checked.primary_blocker is not None
            self.assertEqual(
                checked.primary_blocker.code,
                "external_profile_artifact_not_complete",
            )

    def test_missing_evidence_is_incomplete_and_binding_contradiction_is_violated(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            semantic, transitions, target_certificates, profiles, *_rest = self._inputs(root)
            missing = _write(
                root / "missing-evidence",
                EXTERNAL_SITE_EVIDENCE_ARTIFACT_KIND_V3,
                (),
            )
            external = CANONICAL_EXTERNAL_SITES_PHASE_V3.run(
                output_directory=root / "external-missing",
                inputs={
                    "external_profiles": profiles,
                    "external_site_evidence": missing,
                    "semantic_index": semantic,
                    "target_certificates": target_certificates,
                    "transition_summaries": transitions,
                },
                bindings=(BINDING,),
            ).output_directory
            incomplete = CANONICAL_EXTERNAL_SITE_CODEC_V3.read(
                ArtifactSetReaderV3(external).get_record("source:unit")
            ).value
            self.assertEqual(incomplete.status, "incomplete")
            self.assertIsNotNone(incomplete.primary_blocker)
            assert incomplete.primary_blocker is not None
            self.assertEqual(
                incomplete.primary_blocker.code, "external_site_evidence_missing"
            )
            self.assertFalse(incomplete.authorizing)

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (
                semantic,
                transitions,
                target_certificates,
                profiles,
                _source_exact,
                _callback_exact,
                stale,
                _callback,
            ) = self._inputs(root, evidence_unit_sha256="f" * 64)
            evidence_artifact = _write(
                root / "stale-evidence",
                EXTERNAL_SITE_EVIDENCE_ARTIFACT_KIND_V3,
                (EXTERNAL_SITE_EVIDENCE_CODEC_V3.write(stale.record_id, stale),),
            )
            external = CANONICAL_EXTERNAL_SITES_PHASE_V3.run(
                output_directory=root / "external-stale",
                inputs={
                    "external_profiles": profiles,
                    "external_site_evidence": evidence_artifact,
                    "semantic_index": semantic,
                    "target_certificates": target_certificates,
                    "transition_summaries": transitions,
                },
                bindings=(BINDING,),
            ).output_directory
            violated = CANONICAL_EXTERNAL_SITE_CODEC_V3.read(
                ArtifactSetReaderV3(external).get_record("source:unit")
            ).value
            self.assertEqual(violated.status, "violated")
            self.assertIsNotNone(violated.primary_blocker)
            assert violated.primary_blocker is not None
            self.assertEqual(
                violated.primary_blocker.code,
                "external_site_evidence_binding_contradiction",
            )

    def test_external_evidence_codec_rejects_stale_stable_id(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            *_inputs, evidence, _callback = self._inputs(root)
            payload = EXTERNAL_SITE_EVIDENCE_CODEC_V3.write(
                evidence.record_id, evidence
            ).value.to_value()
            payload = cast(dict[str, Any], payload)
            payload["id"] = "external-site-v3:" + "0" * 64
            with self.assertRaises(AnalysisV3Error) as raised:
                EXTERNAL_SITE_EVIDENCE_CODEC_V3.decode(payload)
            self.assertEqual(raised.exception.code, "stale_record_id")


if __name__ == "__main__":
    unittest.main()
