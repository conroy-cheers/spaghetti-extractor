from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from typing import Any, cast

from spaghetti_extractor.authority._schema import AnalysisV3Error
from spaghetti_extractor.authority.callbacks import (
    CALLBACK_AUTHORITY_ARTIFACT_KIND_V3,
)
from spaghetti_extractor.authority.exact_units import (
    EXACT_UNIT_CODEC_V3,
    ExactUnitV3,
)
from spaghetti_extractor.authority.exceptional_transitions import (
    EXCEPTION_CLOSURE_CERTIFICATE_V3,
    EXCEPTIONAL_TRANSITION_CODEC_V3,
    EXCEPTIONAL_TRANSITIONS_PHASE_V3,
    EXCEPTION_EVIDENCE_ARTIFACT_KIND_V3,
    EXCEPTION_EVIDENCE_CODEC_V3,
    LAUNCH_ASSUMPTION_TEMPLATE_FORMAT_V1,
    TERMINAL_SYNCHRONOUS_FAULT_MODEL_V1,
    ExceptionEvidenceV3,
    exceptional_transition_id_v3,
)
from spaghetti_extractor.authority.root_closure import (
    LAUNCH_ROOT_CLOSURE_CODEC_V3,
    LAUNCH_ROOT_CLOSURE_PHASE_V3,
    LAUNCH_ROOT_EVIDENCE_ARTIFACT_KIND_V3,
    LAUNCH_ROOT_EVIDENCE_CODEC_V3,
    LaunchRootEvidenceV3,
    launch_root_id_v3,
)
from spaghetti_extractor.authority.semantic_index import (
    SEMANTIC_INDEX_ARTIFACT_KIND_V3,
    SEMANTIC_INDEX_CODEC_V3,
    derive_semantic_index_v3,
)
from spaghetti_extractor.authority.target_certificate_records import (
    INDIRECT_TARGET_CERTIFICATE_UNIT_CODEC_V3,
    IndirectTargetCertificateUnitV3,
)
from spaghetti_extractor.artifact_set_v3 import (
    ArtifactBindingV3,
    ArtifactRecordV3,
    ArtifactSetReaderV3,
    ArtifactSetWriterV3,
    CanonicalValueV3,
    canonical_sha256_v3,
)


PE_SHA256 = "1" * 64
PROFILE_SHA256 = "2" * 64
BINDING = ArtifactBindingV3("binary", "pe32", "fixture.exe", PE_SHA256)
PROFILE_BINDING = ArtifactBindingV3(
    "launch-profile-source",
    "launch-assumption-template",
    LAUNCH_ASSUMPTION_TEMPLATE_FORMAT_V1,
    PROFILE_SHA256,
)


def _reg(name: str) -> dict[str, object]:
    return {"op": "reg", "name": name, "width": 32}


def _unit(
    unit_id: str,
    rva: int,
    *,
    target_rva: int | None = None,
    faults: list[dict[str, object]] | None = None,
) -> dict[str, object]:
    fault_rows = faults or []
    direct_targets = [] if target_rva is None else [target_rva]
    outcome: dict[str, object] = (
        {"kind": "return"}
        if target_rva is None
        else {"kind": "direct_jump", "target_rva": target_rva}
    )
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
        "instructions": [
            {
                "mnemonic": "fixture",
                "rva_start": rva,
                "rva_end": rva + 8,
                "size": 8,
            }
        ],
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
            "external_events": [],
            "faults": fault_rows,
            "ordered_events": fault_rows,
            "edge_conditions": [],
            "outcome": outcome,
            "stack_delta": None,
            "counts": {
                "register_writes": 0,
                "flag_writes": 0,
                "memory_events": 0,
                "external_events": 0,
                "faults": len(fault_rows),
                "ordered_events": len(fault_rows),
                "edge_conditions": 0,
            },
        },
        "control": {
            "kind": outcome["kind"],
            "direct_targets": direct_targets,
            "has_indirect_target": False,
        },
    }


def _write(
    path: Path,
    kind: str,
    records: tuple[ArtifactRecordV3, ...],
    *,
    bindings: tuple[ArtifactBindingV3, ...] = (BINDING,),
) -> Path:
    ArtifactSetWriterV3(
        artifact_kind=kind,
        bindings=bindings,
    ).write(path, records)
    return path


def _terminal_certificate(fault: dict[str, object]) -> CanonicalValueV3:
    return CanonicalValueV3.of(
        {
            "environment_model": TERMINAL_SYNCHRONOUS_FAULT_MODEL_V1,
            "fault_kind": fault["kind"],
            "fault_sha256": canonical_sha256_v3(fault),
            "feature_inventory": {
                "direct_syscalls": [],
                "executable_writes": [],
                "threads": [],
                "unknown_async_callbacks": [],
                "unmodelled_seh": [],
            },
            "format": EXCEPTION_CLOSURE_CERTIFICATE_V3,
            "launch_profile_format": LAUNCH_ASSUMPTION_TEMPLATE_FORMAT_V1,
            "launch_profile_sha256": PROFILE_SHA256,
            "method": "conditional-unhandled-synchronous-fault-v1",
        }
    )


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


class RootAndExceptionAuthorityV3Tests(unittest.TestCase):
    def _base_inputs(self, root: Path, *, with_root: bool = True):
        fault = {
            "kind": "divide_error",
            "instruction_rva": 0x1002,
            "condition": {"op": "eq", "args": [_reg("ecx"), {"op": "const", "value": 0, "width": 32}]},
        }
        source_unit = _unit(
            "root:unit",
            0x1000,
            target_rva=0x2000,
            faults=[fault],
        )
        target_unit = _unit("target:unit", 0x2000)
        source_exact = ExactUnitV3.create(
            source_unit,
            pe_sha256=PE_SHA256,
        )
        target_exact = ExactUnitV3.create(
            target_unit,
            pe_sha256=PE_SHA256,
        )
        exact = _write(
            root / "exact",
            "exact-units-v3",
            (
                EXACT_UNIT_CODEC_V3.write(source_exact.record_id, source_exact),
                EXACT_UNIT_CODEC_V3.write(target_exact.record_id, target_exact),
            ),
        )
        semantic_index = _write(
            root / "semantic-index",
            SEMANTIC_INDEX_ARTIFACT_KIND_V3,
            tuple(
                SEMANTIC_INDEX_CODEC_V3.write(
                    row.record_id, derive_semantic_index_v3(row)
                )
                for row in (source_exact, target_exact)
            ),
        )
        callbacks = _write(
            root / "callbacks",
            CALLBACK_AUTHORITY_ARTIFACT_KIND_V3,
            (),
        )
        target_certificates = _empty_target_certificates(
            root / "target-certificates", semantic_index
        )
        launch_root = LaunchRootEvidenceV3(
            record_id=launch_root_id_v3(
                "pe_entrypoint", "entrypoint", source_exact.unit_id
            ),
            root_kind="pe_entrypoint",
            identity="entrypoint",
            unit_id=source_exact.unit_id,
            unit_sha256=source_exact.unit_sha256,
            entry_state=CanonicalValueV3.of({"loader": "explicit-fixture"}),
            callback_id=None,
            status="complete",
            primary_blocker=None,
        )
        roots = _write(
            root / "roots",
            LAUNCH_ROOT_EVIDENCE_ARTIFACT_KIND_V3,
            (
                (LAUNCH_ROOT_EVIDENCE_CODEC_V3.write(launch_root.record_id, launch_root),)
                if with_root
                else ()
            ),
        )
        closure = LAUNCH_ROOT_CLOSURE_PHASE_V3.run(
            output_directory=root / "closure",
            inputs={
                "callbacks": callbacks,
                "launch_roots": roots,
                "semantic_index": semantic_index,
                "target_certificates": target_certificates,
            },
            bindings=(BINDING,),
        ).output_directory
        return semantic_index, closure, source_exact, target_exact, fault, launch_root

    def test_valid_root_closure_and_terminating_exception(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            exact, closure, source_exact, _target_exact, fault, _root = (
                self._base_inputs(root)
            )
            closure_record = next(ArtifactSetReaderV3(closure).iter_records())
            checked_closure = LAUNCH_ROOT_CLOSURE_CODEC_V3.read(
                closure_record
            ).value
            self.assertEqual(checked_closure.status, "complete")
            self.assertEqual(
                checked_closure.reachable_unit_ids,
                ("root:unit", "target:unit"),
            )
            self.assertEqual(checked_closure.dependencies, closure_record.dependencies)

            fault_sha256 = canonical_sha256_v3(fault)
            transition_id = exceptional_transition_id_v3(
                source_exact.unit_id, 0, fault_sha256
            )
            evidence = ExceptionEvidenceV3(
                record_id=transition_id,
                unit_id=source_exact.unit_id,
                unit_sha256=source_exact.unit_sha256,
                fault_index=0,
                fault_sha256=fault_sha256,
                status="complete",
                disposition="terminates",
                handler_unit_id=None,
                handler_unit_sha256=None,
                fault=CanonicalValueV3.of(fault),
                guard=CanonicalValueV3.of(fault["condition"]),
                certificate=_terminal_certificate(fault),
                primary_blocker=None,
            )
            corrupted_payload = cast(
                dict[str, Any],
                EXCEPTION_EVIDENCE_CODEC_V3.write(
                    evidence.record_id, evidence
                ).value.to_value(),
            )
            corrupted_payload["guard"] = {"op": "true"}
            with self.assertRaises(AnalysisV3Error) as raised:
                EXCEPTION_EVIDENCE_CODEC_V3.decode(corrupted_payload)
            self.assertEqual(
                raised.exception.code, "exception_guard_binding_contradiction"
            )
            exception_evidence = _write(
                root / "exception-evidence",
                EXCEPTION_EVIDENCE_ARTIFACT_KIND_V3,
                (EXCEPTION_EVIDENCE_CODEC_V3.write(evidence.record_id, evidence),),
                bindings=(BINDING, PROFILE_BINDING),
            )
            exceptional = EXCEPTIONAL_TRANSITIONS_PHASE_V3.run(
                output_directory=root / "exceptional",
                inputs={
                    "exception_evidence": exception_evidence,
                    "semantic_index": exact,
                },
                bindings=(BINDING,),
            ).output_directory
            source_record = ArtifactSetReaderV3(exceptional).get_record("root:unit")
            checked = EXCEPTIONAL_TRANSITION_CODEC_V3.read(source_record).value
            self.assertEqual(checked.status, "complete")
            self.assertTrue(checked.authorizing)
            self.assertEqual(checked.transitions[0].disposition, "terminates")
            self.assertEqual(checked.dependencies, source_record.dependencies)

    def test_missing_exact_indirect_target_record_is_an_incomplete_frontier(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            unit = _unit("dispatch:unit", 0x3000)
            unit["control"] = {
                "kind": "indirect_jump",
                "direct_targets": [],
                "has_indirect_target": True,
            }
            semantics = unit["semantics"]
            assert isinstance(semantics, dict)
            semantics["outcome"] = {
                "kind": "indirect_jump",
                "target": _reg("eax"),
            }
            exact_unit = ExactUnitV3.create(
                unit,
                pe_sha256=PE_SHA256,
            )
            exact = _write(
                root / "exact-indirect",
                "exact-units-v3",
                (EXACT_UNIT_CODEC_V3.write(exact_unit.record_id, exact_unit),),
            )
            semantic_index = _write(
                root / "semantic-index-indirect",
                SEMANTIC_INDEX_ARTIFACT_KIND_V3,
                (
                    SEMANTIC_INDEX_CODEC_V3.write(
                        exact_unit.record_id,
                        derive_semantic_index_v3(exact_unit),
                    ),
                ),
            )
            callbacks = _write(
                root / "callbacks-indirect",
                CALLBACK_AUTHORITY_ARTIFACT_KIND_V3,
                (),
            )
            target_certificates = _empty_target_certificates(
                root / "target-certificates-indirect", semantic_index
            )
            launch_root = LaunchRootEvidenceV3(
                record_id=launch_root_id_v3(
                    "pe_entrypoint", "entrypoint", exact_unit.unit_id
                ),
                root_kind="pe_entrypoint",
                identity="entrypoint",
                unit_id=exact_unit.unit_id,
                unit_sha256=exact_unit.unit_sha256,
                entry_state=CanonicalValueV3.of({"loader": "explicit-fixture"}),
                callback_id=None,
                status="complete",
                primary_blocker=None,
            )
            roots = _write(
                root / "roots-indirect",
                LAUNCH_ROOT_EVIDENCE_ARTIFACT_KIND_V3,
                (
                    LAUNCH_ROOT_EVIDENCE_CODEC_V3.write(
                        launch_root.record_id, launch_root
                    ),
                ),
            )
            closure = LAUNCH_ROOT_CLOSURE_PHASE_V3.run(
                output_directory=root / "closure-indirect",
                inputs={
                    "callbacks": callbacks,
                    "launch_roots": roots,
                    "semantic_index": semantic_index,
                    "target_certificates": target_certificates,
                },
                bindings=(BINDING,),
            ).output_directory
            checked = LAUNCH_ROOT_CLOSURE_CODEC_V3.read(
                next(ArtifactSetReaderV3(closure).iter_records())
            ).value
            self.assertEqual(checked.status, "incomplete")
            self.assertIsNotNone(checked.primary_blocker)
            assert checked.primary_blocker is not None
            self.assertEqual(
                checked.primary_blocker.code,
                "indirect_target_certificate_missing",
            )
            self.assertEqual(len(checked.frontier_ids), 1)

    def test_exception_analysis_is_root_independent_and_binding_contradictions_violate(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            exact, closure, *_rest = self._base_inputs(root, with_root=False)
            closure_record = next(ArtifactSetReaderV3(closure).iter_records())
            checked_closure = LAUNCH_ROOT_CLOSURE_CODEC_V3.read(
                closure_record
            ).value
            self.assertEqual(checked_closure.status, "incomplete")
            self.assertIsNotNone(checked_closure.primary_blocker)
            assert checked_closure.primary_blocker is not None
            self.assertEqual(
                checked_closure.primary_blocker.code, "launch_root_inventory_empty"
            )
            evidence = _write(
                root / "empty-exception-evidence",
                EXCEPTION_EVIDENCE_ARTIFACT_KIND_V3,
                (),
            )
            exceptional = EXCEPTIONAL_TRANSITIONS_PHASE_V3.run(
                output_directory=root / "exceptional-incomplete",
                inputs={
                    "exception_evidence": evidence,
                    "semantic_index": exact,
                },
                bindings=(BINDING,),
            ).output_directory
            checked = EXCEPTIONAL_TRANSITION_CODEC_V3.read(
                ArtifactSetReaderV3(exceptional).get_record("root:unit")
            ).value
            self.assertEqual(checked.status, "incomplete")
            self.assertIsNotNone(checked.primary_blocker)
            assert checked.primary_blocker is not None
            self.assertEqual(checked.primary_blocker.code, "exception_evidence_missing")

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            exact, closure, source_exact, _target_exact, fault, _root = (
                self._base_inputs(root)
            )
            fault_sha256 = canonical_sha256_v3(fault)
            transition_id = exceptional_transition_id_v3(
                source_exact.unit_id, 0, fault_sha256
            )
            stale = ExceptionEvidenceV3(
                record_id=transition_id,
                unit_id=source_exact.unit_id,
                unit_sha256="f" * 64,
                fault_index=0,
                fault_sha256=fault_sha256,
                status="complete",
                disposition="terminates",
                handler_unit_id=None,
                handler_unit_sha256=None,
                fault=CanonicalValueV3.of(fault),
                guard=CanonicalValueV3.of(fault["condition"]),
                certificate=_terminal_certificate(fault),
                primary_blocker=None,
            )
            evidence = _write(
                root / "stale-exception-evidence",
                EXCEPTION_EVIDENCE_ARTIFACT_KIND_V3,
                (EXCEPTION_EVIDENCE_CODEC_V3.write(stale.record_id, stale),),
            )
            exceptional = EXCEPTIONAL_TRANSITIONS_PHASE_V3.run(
                output_directory=root / "exceptional-violated",
                inputs={
                    "exception_evidence": evidence,
                    "semantic_index": exact,
                },
                bindings=(BINDING,),
            ).output_directory
            checked = EXCEPTIONAL_TRANSITION_CODEC_V3.read(
                ArtifactSetReaderV3(exceptional).get_record("root:unit")
            ).value
            self.assertEqual(checked.status, "violated")
            self.assertIsNotNone(checked.primary_blocker)
            assert checked.primary_blocker is not None
            self.assertEqual(
                checked.primary_blocker.code,
                "exception_evidence_binding_contradiction",
            )

    def test_terminal_exception_requires_exact_launch_profile_binding(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            exact, _closure, source_exact, _target_exact, fault, _root = (
                self._base_inputs(root)
            )
            fault_sha256 = canonical_sha256_v3(fault)
            transition_id = exceptional_transition_id_v3(
                source_exact.unit_id, 0, fault_sha256
            )
            evidence = ExceptionEvidenceV3(
                record_id=transition_id,
                unit_id=source_exact.unit_id,
                unit_sha256=source_exact.unit_sha256,
                fault_index=0,
                fault_sha256=fault_sha256,
                status="complete",
                disposition="terminates",
                handler_unit_id=None,
                handler_unit_sha256=None,
                fault=CanonicalValueV3.of(fault),
                guard=CanonicalValueV3.of(fault["condition"]),
                certificate=_terminal_certificate(fault),
                primary_blocker=None,
            )
            # Omitting the profile binding cannot authorize a terminal claim,
            # even though the record itself is otherwise internally valid.
            evidence_path = _write(
                root / "unbound-terminal-evidence",
                EXCEPTION_EVIDENCE_ARTIFACT_KIND_V3,
                (EXCEPTION_EVIDENCE_CODEC_V3.write(evidence.record_id, evidence),),
            )
            exceptional = EXCEPTIONAL_TRANSITIONS_PHASE_V3.run(
                output_directory=root / "unbound-terminal-checked",
                inputs={
                    "exception_evidence": evidence_path,
                    "semantic_index": exact,
                },
                bindings=(BINDING,),
            ).output_directory
            checked = EXCEPTIONAL_TRANSITION_CODEC_V3.read(
                ArtifactSetReaderV3(exceptional).get_record(source_exact.unit_id)
            ).value
            self.assertEqual(checked.status, "violated")
            self.assertIsNotNone(checked.primary_blocker)
            assert checked.primary_blocker is not None
            self.assertEqual(
                checked.primary_blocker.code,
                "exception_terminal_profile_binding_contradiction",
            )

    def test_launch_root_codec_rejects_stale_stable_id(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            *_inputs, launch_root = self._base_inputs(root)
            payload = LAUNCH_ROOT_EVIDENCE_CODEC_V3.write(
                launch_root.record_id, launch_root
            ).value.to_value()
            payload = cast(dict[str, Any], payload)
            payload["id"] = "launch-root-v3:" + "0" * 64
            with self.assertRaises(AnalysisV3Error) as raised:
                LAUNCH_ROOT_EVIDENCE_CODEC_V3.decode(payload)
            self.assertEqual(raised.exception.code, "stale_record_id")


if __name__ == "__main__":
    unittest.main()
