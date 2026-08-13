from __future__ import annotations

import copy
import tempfile
import unittest
from pathlib import Path

from spaghetti_extractor.analysis_v3.exact_units import (
    EXACT_UNIT_CODEC_V3,
    ExactUnitV3,
)
from spaghetti_extractor.analysis_v3.external_sites import (
    CANONICAL_EXTERNAL_SITE_CODEC_V3,
    CANONICAL_EXTERNAL_SITES_PHASE_V3,
    EXTERNAL_PROFILE_ARTIFACT_KIND_V3,
    EXTERNAL_PROFILE_CODEC_V3,
    EXTERNAL_SITE_EVIDENCE_ARTIFACT_KIND_V3,
    EXTERNAL_SITE_EVIDENCE_CODEC_V3,
    ExternalProfileV3,
    external_site_id_v3,
)
from spaghetti_extractor.analysis_v3.semantic_index import (
    SEMANTIC_INDEX_CODEC_V3,
    SEMANTIC_INDEX_PHASE_V3,
)
from spaghetti_extractor.analysis_v3.target_certificates import (
    INDIRECT_TARGET_CERTIFICATE_UNIT_CODEC_V3,
    INDIRECT_TARGET_CERTIFICATES_ARTIFACT_KIND_V3,
    IndirectTargetCertificateV3,
    IndirectTargetCertificateUnitV3,
)
from spaghetti_extractor.analysis_v3.transition_summaries import (
    TRANSITION_SUMMARIES_PHASE_V3,
)
from spaghetti_extractor.artifact_set_v3 import (
    ArtifactBindingV3,
    ArtifactRecordV3,
    ArtifactSetReaderV3,
    ArtifactSetWriterV3,
    ArtifactV3Error,
    CanonicalValueV3,
    canonical_sha256_v3,
)
from spaghetti_extractor.stage_a_external_site_evidence_v3 import (
    generate_standard_external_site_evidence_v3,
    main,
)


PE_SHA256 = "a" * 64
PROFILE_SHA256 = "b" * 64
BINDING = ArtifactBindingV3("binary", "pe32", "fixture.exe", PE_SHA256)


def _register(name: str) -> dict[str, object]:
    return {"op": "reg", "name": name, "width": 32}


def _event() -> dict[str, object]:
    return {
        "kind": "external_call",
        "dll": "Fixture.DLL",
        "symbol": "Update",
        "ordinal": None,
        "arguments": [_register("eax")],
        "stack_inputs": [],
        "abi_contract": {
            "template": "pe32-cdecl-v1",
            "argument_words": 1,
            "profile_binding": {
                "profile_id": "fixture-profile",
                "profile_sha256": PROFILE_SHA256,
            },
            "disposition": "returns",
            "memory_effect": "none",
            "memory_footprints": [],
            "world_effect": "none",
            "callback_effect": "none",
            "result_register_relations": [],
            "out_pointer_relations": [],
            "out_interface_relations": [],
        },
        "callback_requirements": [],
    }


def _unit(event: dict[str, object]) -> dict[str, object]:
    return {
        "format": "stage-a-machine-ir-v2",
        "record_kind": "unit",
        "id": "source:unit",
        "status": "qualified",
        "source": {
            "original": {"rva_start": 0x1000, "rva_end": 0x1008},
            "instruction_bytes_sha256": "c" * 64,
        },
        "expression_model": "stage-a-semantic-ir-v1",
        "instructions": [],
        "semantics": {
            "pre_state": {
                "registers": {"eax": _register("eax")},
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
            "external_events": [event],
            "faults": [],
            "ordered_events": [event],
            "edge_conditions": [],
            "outcome": {"kind": "return"},
            "stack_delta": None,
            "counts": {
                "register_writes": 0,
                "flag_writes": 0,
                "memory_events": 0,
                "external_events": 1,
                "faults": 0,
                "ordered_events": 1,
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


class StandardExternalSiteEvidenceV3Tests(unittest.TestCase):
    def _inputs(
        self,
        root: Path,
        *,
        event: dict[str, object] | None = None,
        profile: ExternalProfileV3 | None = None,
        external_target: dict[str, object] | None = None,
    ) -> tuple[Path, Path, Path, Path, ExactUnitV3, dict[str, object]]:
        exact_event = _event() if event is None else event
        exact_unit = ExactUnitV3.create(_unit(exact_event), pe_sha256=PE_SHA256)
        exact = _write(
            root / "exact",
            "exact-units-v3",
            (EXACT_UNIT_CODEC_V3.write(exact_unit.record_id, exact_unit),),
        )
        transitions = TRANSITION_SUMMARIES_PHASE_V3.run(
            output_directory=root / "transitions",
            inputs={"exact_units": exact},
            bindings=(BINDING,),
        ).output_directory
        semantic = SEMANTIC_INDEX_PHASE_V3.run(
            output_directory=root / "semantic",
            inputs={"exact_units": exact},
            bindings=(BINDING,),
        ).output_directory
        certificates: tuple[IndirectTargetCertificateV3, ...] = ()
        if external_target is not None:
            semantic_record = SEMANTIC_INDEX_CODEC_V3.read(
                ArtifactSetReaderV3(semantic).get_record(exact_unit.unit_id)
            ).value
            occurrence = semantic_record.indirect_exits[0]
            certificates = (
                IndirectTargetCertificateV3.create(
                    occurrence=occurrence,
                    source=semantic_record,
                    status="complete",
                    external_targets=(CanonicalValueV3.of(external_target),),
                    evaluation_method="exact_constant",
                    evidence_sha256="d" * 64,
                    dependencies=(),
                    primary_blocker=None,
                ),
            )
        certificate_unit = IndirectTargetCertificateUnitV3(
            record_id=exact_unit.unit_id,
            source_unit_id=exact_unit.unit_id,
            unit_sha256=exact_unit.unit_sha256,
            status="complete",
            authorizing=True,
            certificates=certificates,
            dependencies=(),
            primary_blocker=None,
        )
        targets = _write(
            root / "targets",
            INDIRECT_TARGET_CERTIFICATES_ARTIFACT_KIND_V3,
            (
                INDIRECT_TARGET_CERTIFICATE_UNIT_CODEC_V3.write(
                    certificate_unit.record_id, certificate_unit
                ),
            ),
        )
        selected_profile = profile or ExternalProfileV3.create(
            profile_id="fixture-profile",
            profile_sha256=PROFILE_SHA256,
            identity={
                "kind": "import",
                "dll": "fixture.dll",
                "symbol": "Update",
                "ordinal": None,
            },
            allowed_transfers=("call",),
            allowed_dispositions=("returns",),
            argument_words=1,
            memory_effect="none",
            world_effect="none",
            callback_effect="none",
            machine_contract={
                "abi_template": "pe32-cdecl-v1",
                "argument_words": 1,
                "disposition": "returns",
                "memory_effect": "none",
                "memory_footprints": [],
                "world_effect": "none",
                "callback_effect": "none",
                "result_register_relations": [],
                "out_pointer_relations": [],
                "out_interface_relations": [],
            },
        )
        profiles = _write(
            root / "profiles",
            EXTERNAL_PROFILE_ARTIFACT_KIND_V3,
            (
                EXTERNAL_PROFILE_CODEC_V3.write(
                    selected_profile.record_id, selected_profile
                ),
            ),
        )
        return semantic, transitions, targets, profiles, exact_unit, exact_event

    def _generate(
        self,
        root: Path,
        *,
        event: dict[str, object] | None = None,
        profile: ExternalProfileV3 | None = None,
        external_target: dict[str, object] | None = None,
    ):
        semantic, transitions, targets, profiles, exact, exact_event = self._inputs(
            root,
            event=event,
            profile=profile,
            external_target=external_target,
        )
        output = root / "evidence"
        manifest = generate_standard_external_site_evidence_v3(
            semantic_index_path=semantic,
            transition_summaries_path=transitions,
            target_certificates_path=targets,
            external_profiles_path=profiles,
            output_directory=output,
        )
        site_id = external_site_id_v3(
            exact.unit_id,
            0,
            0,
            exact_event if external_target is None else external_target,
        )
        evidence = EXTERNAL_SITE_EVIDENCE_CODEC_V3.read(
            ArtifactSetReaderV3(output).get_record(site_id)
        ).value
        return (
            manifest,
            evidence,
            output,
            semantic,
            transitions,
            targets,
            profiles,
            exact,
            exact_event,
        )

    def test_indirect_external_target_is_bound_as_an_exact_alternative(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            event = _event()
            event.pop("dll")
            event.pop("symbol")
            event.pop("ordinal")
            event["kind"] = "indirect_call"
            event["target"] = _register("ebx")
            target = {
                "import": {
                    "dll": "Fixture.DLL",
                    "symbol": "Update",
                    "ordinal": None,
                },
                "profile_binding": {
                    "profile_id": "fixture-profile",
                    "profile_sha256": PROFILE_SHA256,
                },
            }
            (
                _manifest,
                evidence,
                output,
                _semantic,
                _transitions,
                _targets,
                _profiles,
                _exact,
                exact_event,
            ) = self._generate(
                Path(temporary), event=event, external_target=target
            )
            self.assertEqual(evidence.status, "complete")
            self.assertEqual(evidence.event_sha256, canonical_sha256_v3(exact_event))
            self.assertEqual(evidence.target_sha256, canonical_sha256_v3(target))
            self.assertEqual(
                {row.input_name for row in ArtifactSetReaderV3(output).get_record(
                    evidence.record_id
                ).dependencies},
                {
                    "external_profiles",
                    "semantic_index",
                    "target_certificates",
                    "transition_summaries",
                },
            )

    def test_complete_evidence_is_exactly_bound_and_authorizes(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (
                manifest,
                evidence,
                output,
                semantic,
                transitions,
                targets,
                profiles,
                exact,
                event,
            ) = self._generate(root)
            self.assertEqual(
                manifest.artifact_kind, EXTERNAL_SITE_EVIDENCE_ARTIFACT_KIND_V3
            )
            self.assertEqual(manifest.status, "complete")
            self.assertEqual(evidence.status, "complete")
            self.assertIsNone(evidence.primary_blocker)
            self.assertEqual(evidence.unit_id, exact.unit_id)
            self.assertEqual(evidence.unit_sha256, exact.unit_sha256)
            self.assertEqual(evidence.event_sha256, canonical_sha256_v3(event))
            self.assertEqual(evidence.target_sha256, canonical_sha256_v3(event))
            self.assertIsNotNone(evidence.contract)
            assert evidence.contract is not None
            self.assertEqual(evidence.contract.argument_words, 1)
            self.assertEqual(evidence.contract.profile_id, "fixture-profile")
            repeated = generate_standard_external_site_evidence_v3(
                semantic_index_path=semantic,
                transition_summaries_path=transitions,
                target_certificates_path=targets,
                external_profiles_path=profiles,
                output_directory=root / "evidence-repeated",
            )
            self.assertEqual(repeated.artifact_id, manifest.artifact_id)
            dependencies = ArtifactSetReaderV3(output).get_record(
                evidence.record_id
            ).dependencies
            self.assertEqual(
                {row.input_name for row in dependencies},
                {"external_profiles", "semantic_index", "transition_summaries"},
            )

            canonical = CANONICAL_EXTERNAL_SITES_PHASE_V3.run(
                output_directory=root / "canonical",
                inputs={
                    "external_profiles": profiles,
                    "external_site_evidence": output,
                    "semantic_index": semantic,
                    "target_certificates": targets,
                    "transition_summaries": transitions,
                },
                bindings=(BINDING,),
            ).output_directory
            checked = CANONICAL_EXTERNAL_SITE_CODEC_V3.read(
                ArtifactSetReaderV3(canonical).get_record(exact.unit_id)
            ).value
            self.assertEqual(checked.status, "complete")
            self.assertTrue(checked.authorizing)
            self.assertTrue(checked.sites[0].authorizing)

    def test_argument_recovery_requires_an_exact_call_boundary(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            event = copy.deepcopy(_event())
            event.pop("arguments")
            evidence = self._generate(Path(temporary), event=event)[1]
            self.assertEqual(evidence.status, "incomplete")
            self.assertIsNone(evidence.contract)
            self.assertIsNotNone(evidence.primary_blocker)
            assert evidence.primary_blocker is not None
            self.assertEqual(
                evidence.primary_blocker.code, "external_call_boundary_esp_missing"
            )

    def test_profile_recovers_arguments_from_exact_call_boundary(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            event = copy.deepcopy(_event())
            event["arguments"] = []
            event["register_inputs"] = {
                "esp": {"op": "reg", "name": "esp", "width": 32}
            }
            evidence = self._generate(Path(temporary), event=event)[1]
            self.assertEqual(evidence.status, "complete")
            self.assertIsNotNone(evidence.contract)
            assert evidence.contract is not None
            self.assertEqual(
                [row.to_value() for row in evidence.contract.arguments],
                [
                    {
                        "op": "load",
                        "width": 4,
                        "address": {"op": "reg", "name": "esp", "width": 32},
                    }
                ],
            )

    def test_profile_supplies_omitted_effects_and_empty_callback_inventory(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            event = copy.deepcopy(_event())
            abi = event["abi_contract"]
            assert isinstance(abi, dict)
            for field in (
                "profile_binding",
                "memory_effect",
                "memory_footprints",
                "world_effect",
                "callback_effect",
                "result_register_relations",
                "out_pointer_relations",
                "out_interface_relations",
            ):
                abi.pop(field)
            event.pop("callback_requirements")
            evidence = self._generate(Path(temporary), event=event)[1]
            self.assertEqual(evidence.status, "complete")
            self.assertIsNotNone(evidence.contract)
            assert evidence.contract is not None
            self.assertEqual(evidence.contract.memory_effect, "none")
            self.assertEqual(evidence.contract.callback_effect, "none")
            self.assertEqual(evidence.contract.callbacks, ())
            self.assertEqual(
                evidence.contract.machine_contract.to_value(),
                {
                    "abi_template": "pe32-cdecl-v1",
                    "argument_words": 1,
                    "callback_effect": "none",
                    "disposition": "returns",
                    "memory_effect": "none",
                    "memory_footprints": [],
                    "out_interface_relations": [],
                    "out_pointer_relations": [],
                    "result_register_relations": [],
                    "world_effect": "none",
                },
            )

    def test_unique_profile_supplies_semantic_abi_when_event_has_only_arguments(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            event = copy.deepcopy(_event())
            event.pop("abi_contract")
            event.pop("callback_requirements")
            evidence = self._generate(Path(temporary), event=event)[1]
            self.assertEqual(evidence.status, "complete")
            self.assertIsNotNone(evidence.contract)
            assert evidence.contract is not None
            self.assertEqual(evidence.contract.argument_words, 1)
            self.assertEqual(evidence.contract.disposition, "returns")
            self.assertEqual(evidence.contract.profile_id, "fixture-profile")

    def test_profile_contradiction_is_violated(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            event = _event()
            abi = event["abi_contract"]
            assert isinstance(abi, dict)
            abi["memory_effect"] = "argumentRanges"
            evidence = self._generate(Path(temporary), event=event)[1]
            self.assertEqual(evidence.status, "violated")
            self.assertIsNone(evidence.contract)
            self.assertIsNotNone(evidence.primary_blocker)
            assert evidence.primary_blocker is not None
            self.assertEqual(
                evidence.primary_blocker.code,
                "external_profile_contract_contradiction",
            )

    def test_control_disposition_binding_selects_unique_semantic_profile(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            event = _event()
            abi = event["abi_contract"]
            assert isinstance(abi, dict)
            abi["profile_binding"] = {
                "profile_id": "pe32-control-dispositions-v1",
                "profile_sha256": "c" * 64,
            }
            abi["disposition"] = "terminates"
            profile = ExternalProfileV3.create(
                profile_id="fixture-profile",
                profile_sha256=PROFILE_SHA256,
                identity={
                    "kind": "import",
                    "dll": "fixture.dll",
                    "symbol": "Update",
                    "ordinal": None,
                },
                allowed_transfers=("call",),
                allowed_dispositions=("noreturn",),
                argument_words=1,
                memory_effect="none",
                world_effect="none",
                callback_effect="none",
                machine_contract={
                    "abi_template": "pe32-cdecl-v1",
                    "argument_words": 1,
                    "disposition": "noreturn",
                    "memory_effect": "none",
                    "memory_footprints": [],
                    "world_effect": "none",
                    "callback_effect": "none",
                    "result_register_relations": [],
                    "out_pointer_relations": [],
                    "out_interface_relations": [],
                },
            )
            root = Path(temporary)
            (
                _manifest,
                evidence,
                output,
                semantic,
                transitions,
                targets,
                profiles,
                exact,
                _exact_event,
            ) = self._generate(root, event=event, profile=profile)
            self.assertEqual(evidence.status, "complete")
            self.assertIsNotNone(evidence.contract)
            assert evidence.contract is not None
            self.assertEqual(evidence.contract.disposition, "noreturn")
            self.assertEqual(evidence.contract.profile_id, "fixture-profile")
            canonical = CANONICAL_EXTERNAL_SITES_PHASE_V3.run(
                output_directory=root / "canonical",
                inputs={
                    "external_profiles": profiles,
                    "external_site_evidence": output,
                    "semantic_index": semantic,
                    "target_certificates": targets,
                    "transition_summaries": transitions,
                },
                bindings=(BINDING,),
            ).output_directory
            checked = CANONICAL_EXTERNAL_SITE_CODEC_V3.read(
                ArtifactSetReaderV3(canonical).get_record(exact.unit_id)
            ).value
            self.assertEqual(checked.status, "complete")
            self.assertTrue(checked.authorizing)

    def test_corrupt_profile_pack_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            semantic, transitions, targets, profiles, _exact, _event_value = (
                self._inputs(root)
            )
            pack = next((profiles / "packs").glob("*.gz"))
            data = bytearray(pack.read_bytes())
            data[len(data) // 2] ^= 0x01
            pack.write_bytes(bytes(data))
            with self.assertRaises(ArtifactV3Error):
                generate_standard_external_site_evidence_v3(
                    semantic_index_path=semantic,
                    transition_summaries_path=transitions,
                    target_certificates_path=targets,
                    external_profiles_path=profiles,
                    output_directory=root / "evidence",
                )

    def test_module_cli_writes_the_standard_artifact(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            semantic, transitions, targets, profiles, _exact, _event_value = (
                self._inputs(root)
            )
            output = root / "evidence"
            self.assertEqual(
                main(
                    [
                        "--semantic-index",
                        str(semantic),
                        "--transition-summaries",
                        str(transitions),
                        "--target-certificates",
                        str(targets),
                        "--external-profiles",
                        str(profiles),
                        "--out",
                        str(output),
                    ]
                ),
                0,
            )
            self.assertEqual(
                ArtifactSetReaderV3(output).manifest.artifact_kind,
                EXTERNAL_SITE_EVIDENCE_ARTIFACT_KIND_V3,
            )


if __name__ == "__main__":
    unittest.main()
