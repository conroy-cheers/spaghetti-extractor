"""ABI evidence extraction from checked, root-independent authority artifacts.

This module does not rediscover instruction behavior.  It projects facts from
the checked parametric summaries and canonical external sites, preserving their
dependency identities.  Missing information stays absent for the constraint
solver to report as an actionable incomplete field.
"""

from __future__ import annotations

from dataclasses import dataclass
import json
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence

from ..artifacts.formats import ABI_ANALYSIS_BUNDLE_FORMAT
from ..artifacts.io import open_artifact_reader_v3
from ..authority.external_site_records import (
    CANONICAL_EXTERNAL_SITE_CODEC_V3,
    CANONICAL_EXTERNAL_SITES_ARTIFACT_KIND_V3,
    CanonicalExternalSiteRecordV3,
    CanonicalExternalSiteV3,
)
from ..authority.parametric_summary_records import (
    PARAMETRIC_SCC_SUMMARIES_ARTIFACT_KIND_V3,
    PARAMETRIC_SCC_SUMMARY_CODEC_V3,
    PE32_CALLEE_PRESERVED_REGISTERS_V3,
    ParametricSccSummaryV3,
)
from .model import (
    AbiEvidenceV1,
    AbiFactV1,
    AbiLocationV1,
    AbiModelError,
    AbiValueV1,
    PE32_TARGET_V1,
    StackCleanupV1,
    VariadicPolicyV1,
    canonical_json_bytes,
    stable_id,
)
from .solver import PHYSICAL_PROFILE_FIELDS, AbiEqualityConstraintV1


@dataclass(frozen=True)
class AbiExtractionResultV1:
    status: str
    subjects: Mapping[str, str]
    evidence: tuple[AbiEvidenceV1, ...]
    facts: tuple[AbiFactV1, ...]
    equalities: tuple[AbiEqualityConstraintV1, ...]
    issues: tuple[Mapping[str, Any], ...]

    def to_payload(self) -> dict[str, object]:
        return {
            "format": ABI_ANALYSIS_BUNDLE_FORMAT,
            "status": self.status,
            "subjects": dict(sorted(self.subjects.items())),
            "evidence": [item.to_payload() for item in self.evidence],
            "facts": [item.to_payload() for item in self.facts],
            "equalities": [item.to_payload() for item in self.equalities],
            "issues": list(self.issues),
        }

    def write(self, path: Path | str) -> None:
        destination = Path(path)
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(canonical_json_bytes(self.to_payload()) + b"\n")

    @classmethod
    def read(cls, path: Path | str) -> "AbiExtractionResultV1":
        payload = json.loads(Path(path).read_text(encoding="utf-8"))
        if not isinstance(payload, Mapping) or set(payload) != {
            "format",
            "status",
            "subjects",
            "evidence",
            "facts",
            "equalities",
            "issues",
        }:
            raise AbiModelError("ABI extraction bundle fields are malformed")
        if payload["format"] != ABI_ANALYSIS_BUNDLE_FORMAT:
            raise AbiModelError("ABI extraction bundle format is unsupported")
        subjects = payload["subjects"]
        if not isinstance(subjects, Mapping):
            raise AbiModelError("ABI extraction subjects must be an object")
        for field in ("evidence", "facts", "equalities", "issues"):
            if not isinstance(payload[field], list):
                raise AbiModelError(f"ABI extraction {field} must be an array")
        return cls(
            str(payload["status"]),
            {str(key): str(value) for key, value in subjects.items()},
            tuple(AbiEvidenceV1.parse(item) for item in payload["evidence"]),
            tuple(AbiFactV1.parse(item) for item in payload["facts"]),
            tuple(
                AbiEqualityConstraintV1.parse(item)
                for item in payload["equalities"]
            ),
            tuple(
                dict(item)
                if isinstance(item, Mapping)
                else _raise_extraction_issue()
                for item in payload["issues"]
            ),
        )


def _raise_extraction_issue() -> Mapping[str, Any]:
    raise AbiModelError("ABI extraction issue must be an object")


class _ExtractionBuilder:
    def __init__(self, *, binary_sha256: str | None) -> None:
        self.binary_sha256 = binary_sha256
        self.subjects: dict[str, str] = {}
        self.evidence: dict[str, AbiEvidenceV1] = {}
        self.facts: list[AbiFactV1] = []
        self.equalities: set[AbiEqualityConstraintV1] = set()
        self.issues: list[Mapping[str, Any]] = []

    def subject(self, subject_id: str, kind: str) -> None:
        previous = self.subjects.get(subject_id)
        if previous is not None and previous != kind:
            raise AbiModelError(f"ABI subject {subject_id!r} has conflicting kinds")
        self.subjects[subject_id] = kind

    def add_evidence(
        self,
        *,
        kind: str,
        producer: str,
        subject_kind: str,
        subject_id: str,
        payload: Mapping[str, Any],
        dependencies: Iterable[str],
    ) -> AbiEvidenceV1:
        self.subject(subject_id, subject_kind)
        evidence = AbiEvidenceV1.create(
            kind=kind,
            producer=producer,
            subject_kind=subject_kind,
            subject_id=subject_id,
            binary_sha256=self.binary_sha256,
            dependencies=dependencies,
            payload=payload,
        )
        self.evidence[evidence.evidence_id] = evidence
        return evidence

    def exact(
        self,
        subject_id: str,
        field: str,
        value: object,
        evidence: AbiEvidenceV1,
        *,
        dependencies: Iterable[str] = (),
    ) -> None:
        self.facts.append(
            AbiFactV1.create(
                subject_id=subject_id,
                field=field,
                status="exact",
                values=(value,),
                evidence_ids=(evidence.evidence_id,),
                dependency_ids=dependencies,
            )
        )

    def alternatives(
        self,
        subject_id: str,
        field: str,
        values: Iterable[object],
        evidence: AbiEvidenceV1,
        *,
        dependencies: Iterable[str] = (),
    ) -> None:
        values = tuple(values)
        if len(values) < 2:
            raise AbiModelError("ABI alternatives require at least two values")
        self.facts.append(
            AbiFactV1.create(
                subject_id=subject_id,
                field=field,
                status="alternatives",
                values=values,
                evidence_ids=(evidence.evidence_id,),
                dependency_ids=dependencies,
            )
        )

    def equal(self, left: str, right: str, evidence: AbiEvidenceV1) -> None:
        for field in PHYSICAL_PROFILE_FIELDS:
            self.equalities.add(
                AbiEqualityConstraintV1(
                    left,
                    field,
                    right,
                    field,
                    (evidence.evidence_id,),
                )
            )

    def issue(
        self,
        *,
        status: str,
        code: str,
        subject_id: str,
        detail: str,
        dependency_id: str | None = None,
    ) -> None:
        row: dict[str, Any] = {
            "status": status,
            "code": code,
            "subject_id": subject_id,
            "detail": detail,
        }
        if dependency_id is not None:
            row["dependency_id"] = dependency_id
        self.issues.append(row)

    def finish(self) -> AbiExtractionResultV1:
        status = (
            "violated"
            if any(item["status"] == "violated" for item in self.issues)
            else "incomplete"
            if self.issues
            else "complete"
        )
        return AbiExtractionResultV1(
            status,
            dict(sorted(self.subjects.items())),
            tuple(sorted(self.evidence.values())),
            tuple(
                sorted(
                    self.facts,
                    key=lambda row: (
                        row.subject_id,
                        row.field,
                        canonical_json_bytes(row.to_payload()),
                    ),
                )
            ),
            tuple(sorted(self.equalities)),
            tuple(
                sorted(
                    self.issues,
                    key=lambda row: (
                        str(row["status"]),
                        str(row["subject_id"]),
                        str(row["code"]),
                    ),
                )
            ),
        )


def _dependency_ids(summary: ParametricSccSummaryV3) -> tuple[str, ...]:
    return tuple(
        sorted(
            {
                summary.record_id,
                *(f"{item.input_name}:{item.record_id}" for item in summary.dependencies),
            }
        )
    )


def _base_machine_facts(
    builder: _ExtractionBuilder,
    *,
    subject_id: str,
    evidence: AbiEvidenceV1,
    dependencies: Iterable[str],
) -> None:
    builder.exact(subject_id, "target", PE32_TARGET_V1.to_payload(), evidence, dependencies=dependencies)
    builder.exact(subject_id, "stack_coordinate", "callee_entry_esp_v1", evidence, dependencies=dependencies)
    builder.exact(subject_id, "stack_alignment_bytes", 4, evidence, dependencies=dependencies)


def _extract_summary(
    builder: _ExtractionBuilder, summary: ParametricSccSummaryV3
) -> None:
    dependencies = _dependency_ids(summary)
    for unit_id in summary.member_unit_ids:
        builder.subject(unit_id, "function")
        if summary.status != "complete" or not summary.authorizing:
            builder.issue(
                status="incomplete" if summary.status != "violated" else "violated",
                code="abi_checked_summary_not_authorizing",
                subject_id=unit_id,
                detail="physical ABI extraction requires a complete checked parametric summary",
                dependency_id=summary.record_id,
            )
            continue
        unit_returns = tuple(row for row in summary.returns if row.unit_id == unit_id)
        unit_stack = tuple(row for row in summary.stack_accesses if row.unit_id == unit_id)
        unit_relations = tuple(
            row for row in summary.register_relations if row.unit_id == unit_id
        )
        evidence = builder.add_evidence(
            kind="checked_parametric_summary",
            producer="authority.parametric_scc_summary_v3",
            subject_kind="function",
            subject_id=unit_id,
            dependencies=dependencies,
            payload={
                "summary_id": summary.record_id,
                "scc_id": summary.scc_id,
                "stack_accesses": [row.to_payload() for row in unit_stack],
                "returns": [row.to_payload() for row in unit_returns],
                "register_relations": [row.to_payload() for row in unit_relations],
            },
        )
        _base_machine_facts(
            builder,
            subject_id=unit_id,
            evidence=evidence,
            dependencies=dependencies,
        )
        returning = tuple(row for row in unit_returns if row.may_return)
        cleanup_values = {row.cleanup_bytes for row in returning}
        if returning and len(cleanup_values) == 1 and None not in cleanup_values:
            cleanup_bytes = next(iter(cleanup_values))
            assert cleanup_bytes is not None
            cleanup = StackCleanupV1(
                "caller" if cleanup_bytes == 0 else "callee",
                0 if cleanup_bytes == 0 else cleanup_bytes,
            )
            builder.exact(
                unit_id,
                "stack_cleanup",
                cleanup.to_payload(),
                evidence,
                dependencies=dependencies,
            )
            conventions = (
                ("cdecl",)
                if cleanup_bytes == 0
                else ("fastcall", "stdcall", "thiscall")
            )
            if len(conventions) == 1:
                builder.exact(
                    unit_id,
                    "calling_convention",
                    conventions[0],
                    evidence,
                    dependencies=dependencies,
                )
            else:
                builder.alternatives(
                    unit_id,
                    "calling_convention",
                    conventions,
                    evidence,
                    dependencies=dependencies,
                )
        preserved = tuple(
            sorted(
                row.register
                for row in unit_relations
                if row.kind == "preserved"
                and row.register in PE32_CALLEE_PRESERVED_REGISTERS_V3
            )
        )
        if set(PE32_CALLEE_PRESERVED_REGISTERS_V3).issubset(preserved):
            builder.exact(
                unit_id,
                "preserved_state",
                list(PE32_CALLEE_PRESERVED_REGISTERS_V3),
                evidence,
                dependencies=dependencies,
            )

        for call in summary.call_effects:
            if call.source_unit_id != unit_id or not call.target_unit_ids:
                continue
            callsite_id = stable_id(
                "abi-callsite-v1",
                {
                    "source_unit_id": unit_id,
                    "event_index": call.event_index,
                    "call_id": call.call_id,
                },
            )
            builder.subject(callsite_id, "callsite")
            call_evidence = builder.add_evidence(
                kind="checked_internal_call",
                producer="authority.parametric_scc_summary_v3",
                subject_kind="callsite",
                subject_id=callsite_id,
                dependencies=dependencies,
                payload=call.to_payload(),
            )
            _base_machine_facts(
                builder,
                subject_id=callsite_id,
                evidence=call_evidence,
                dependencies=dependencies,
            )
            if call.preserved_registers is not None:
                builder.exact(
                    callsite_id,
                    "preserved_state",
                    list(call.preserved_registers),
                    call_evidence,
                    dependencies=dependencies,
                )
            for target in call.target_unit_ids:
                builder.subject(target, "function")
                builder.equal(callsite_id, target, call_evidence)


def _stack_arguments(words: int) -> tuple[AbiValueV1, ...]:
    return tuple(
        AbiValueV1(
            value_id=f"arg{index}",
            width_bits=32,
            role="ordinary",
            fragments=(
                AbiLocationV1(
                    "stack",
                    32,
                    stack_offset=4 + index * 4,
                ),
            ),
        )
        for index in range(words)
    )


def _external_subject(site: CanonicalExternalSiteV3) -> str:
    assert site.contract is not None
    return f"external-profile:{site.contract.profile_id}"


def _extract_external_site(
    builder: _ExtractionBuilder,
    record: CanonicalExternalSiteRecordV3,
    site: CanonicalExternalSiteV3,
) -> None:
    if site.status != "complete" or not site.authorizing or site.contract is None:
        builder.issue(
            status="violated" if site.status == "violated" else "incomplete",
            code="abi_external_site_not_authorizing",
            subject_id=site.site_id,
            detail="physical ABI extraction requires a complete canonical external site",
            dependency_id=record.record_id,
        )
        return
    contract = site.contract
    machine = contract.machine_contract.to_value()
    if not isinstance(machine, Mapping):
        builder.issue(
            status="violated",
            code="abi_external_machine_contract_malformed",
            subject_id=site.site_id,
            detail="canonical external machine contract is not an object",
            dependency_id=contract.contract_id,
        )
        return
    template = machine.get("abi_template")
    convention = {
        "pe32-cdecl-v1": "cdecl",
        "pe32-stdcall-v1": "stdcall",
    }.get(template)
    if convention is None:
        builder.issue(
            status="incomplete",
            code="abi_external_template_unsupported",
            subject_id=site.site_id,
            detail=f"external ABI template {template!r} has no canonical projection",
            dependency_id=contract.contract_id,
        )
        return
    external_id = _external_subject(site)
    builder.subject(external_id, "import")
    builder.subject(site.site_id, "callsite")
    dependencies = (
        record.record_id,
        contract.contract_id,
        contract.profile_id,
        contract.profile_sha256,
    )
    evidence = builder.add_evidence(
        kind="canonical_external_site",
        producer="authority.canonical_external_site_v3",
        subject_kind="callsite",
        subject_id=site.site_id,
        dependencies=dependencies,
        payload={
            "site_id": site.site_id,
            "identity": site.identity.to_value(),
            "contract": contract.to_payload(),
        },
    )
    import_evidence = builder.add_evidence(
        kind="canonical_external_profile",
        producer="authority.canonical_external_site_v3",
        subject_kind="import",
        subject_id=external_id,
        dependencies=dependencies,
        payload={
            "profile_id": contract.profile_id,
            "profile_sha256": contract.profile_sha256,
            "identity": contract.identity.to_value(),
            "machine_contract": machine,
        },
    )
    _base_machine_facts(
        builder,
        subject_id=external_id,
        evidence=import_evidence,
        dependencies=dependencies,
    )
    arguments = list(_stack_arguments(contract.minimum_argument_words))
    if contract.callback_source_decision is not None:
        decision = contract.callback_source_decision
        if decision.kind == "callback_target" and decision.argument_index < len(arguments):
            old = arguments[decision.argument_index]
            callback_ids = tuple(row.abi_sha256 for row in contract.callbacks)
            if len(set(callback_ids)) == 1:
                arguments[decision.argument_index] = AbiValueV1(
                    old.value_id,
                    old.width_bits,
                    "callback",
                    old.fragments,
                    callback_abi_id=f"callback-abi:{callback_ids[0]}",
                )
    builder.exact(external_id, "calling_convention", convention, import_evidence, dependencies=dependencies)
    builder.exact(external_id, "arguments", [row.to_payload() for row in arguments], import_evidence, dependencies=dependencies)
    builder.exact(
        external_id,
        "stack_cleanup",
        StackCleanupV1(
            "caller" if convention == "cdecl" else "callee",
            0 if convention == "cdecl" else contract.minimum_argument_words * 4,
        ).to_payload(),
        import_evidence,
        dependencies=dependencies,
    )
    builder.exact(
        external_id,
        "variadic",
        VariadicPolicyV1(
            "none" if contract.arity.kind == "fixed" else "c_varargs",
            contract.minimum_argument_words,
        ).to_payload(),
        import_evidence,
        dependencies=dependencies,
    )
    builder.exact(
        external_id,
        "preserved_state",
        list(PE32_CALLEE_PRESERVED_REGISTERS_V3),
        import_evidence,
        dependencies=dependencies,
    )
    raw_results = machine.get("results")
    if isinstance(raw_results, list):
        try:
            results = tuple(AbiValueV1.parse(item) for item in raw_results)
        except AbiModelError as error:
            builder.issue(
                status="violated",
                code="abi_external_result_contract_malformed",
                subject_id=external_id,
                detail=str(error),
                dependency_id=contract.contract_id,
            )
        else:
            builder.exact(external_id, "results", [row.to_payload() for row in results], import_evidence, dependencies=dependencies)
    builder.equal(site.site_id, external_id, evidence)


def extract_checked_abi_evidence(
    *,
    summaries: Sequence[ParametricSccSummaryV3] = (),
    external_site_records: Sequence[CanonicalExternalSiteRecordV3] = (),
    binary_sha256: str | None = None,
) -> AbiExtractionResultV1:
    builder = _ExtractionBuilder(binary_sha256=binary_sha256)
    for summary in sorted(summaries, key=lambda row: row.record_id):
        _extract_summary(builder, summary)
    for record in sorted(external_site_records, key=lambda row: row.record_id):
        for site in sorted(record.sites, key=lambda row: row.site_id):
            _extract_external_site(builder, record, site)
    return builder.finish()


def extract_checked_abi_evidence_from_artifacts(
    *,
    parametric_summaries: Path | str,
    canonical_external_sites: Path | str,
    out: Path | str,
    binary_sha256: str | None = None,
) -> AbiExtractionResultV1:
    summary_reader = open_artifact_reader_v3(parametric_summaries)
    external_reader = open_artifact_reader_v3(canonical_external_sites)
    if summary_reader.manifest.artifact_kind != PARAMETRIC_SCC_SUMMARIES_ARTIFACT_KIND_V3:
        raise AbiModelError("ABI extraction input is not checked parametric summaries")
    if external_reader.manifest.artifact_kind != CANONICAL_EXTERNAL_SITES_ARTIFACT_KIND_V3:
        raise AbiModelError("ABI extraction input is not canonical external sites")
    result = extract_checked_abi_evidence(
        summaries=tuple(
            PARAMETRIC_SCC_SUMMARY_CODEC_V3.read(row).value
            for row in summary_reader.iter_records()
        ),
        external_site_records=tuple(
            CANONICAL_EXTERNAL_SITE_CODEC_V3.read(row).value
            for row in external_reader.iter_records()
        ),
        binary_sha256=binary_sha256,
    )
    result.write(out)
    return result


__all__ = [
    "AbiExtractionResultV1",
    "extract_checked_abi_evidence",
    "extract_checked_abi_evidence_from_artifacts",
]
