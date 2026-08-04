"""Package GNU hello's checked lockstep external-response family.

The generated Lean module admits every source/native environment pair carrying
the exact response, ABI, continuation, nested-callback, and launch evidence
checked by ``RelationalNativeSourceAdmittedProtocolResponseFamily``.  Static
site coverage is generated here.  Constructive non-vacuity remains a separate
checked completion until exact reachable-domain, response-replay,
protocol-preservation, and launch evidence are available.

This producer does not infer API semantics from import names and does not fix
runtime response values.  JSON cannot name an admission or simulation proof;
the generated Lean declaration exposes those remaining premises explicitly.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Mapping, Sequence

from spaghetti_extractor.artifact_formats import STATIC_MACHINE_IMPORT_CONTRACTS_FORMAT
from spaghetti_extractor.errors import StageAInputError


GNU_HELLO_CHECKED_RESPONSE_FAMILY_INPUT_FORMAT = (
    "stage-a-gnu-hello-checked-response-family-input-v3"
)
GNU_HELLO_ENVIRONMENT_FAMILY_EVIDENCE_PROFILE_FORMAT = (
    "stage-a-gnu-hello-nested-environment-family-evidence-profile-v2"
)
GNU_HELLO_CONCRETE_ENVIRONMENT_PAIR_INPUT_FORMAT = (
    "stage-a-gnu-hello-response-family-completion-input-v1"
)
GNU_HELLO_CHECKED_RESPONSE_FAMILY_REPORT_FORMAT = (
    "stage-a-gnu-hello-checked-response-family-v3"
)
GNU_HELLO_CHECKED_RESPONSE_FAMILY_MODULE = (
    "GeneratedGnuHelloCheckedResponseFamily"
)
GNU_HELLO_CHECKED_RESPONSE_FAMILY_NAMESPACE = (
    "StageA.GeneratedRelational.GnuHelloCheckedResponseFamily"
)
GNU_HELLO_REACHABLE_EXTERNAL_SITE_COUNT = 194
GNU_HELLO_REACHABLE_IMPORT_COUNT = 60

_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_LEAN_NAME = re.compile(
    r"[A-Za-z_][A-Za-z0-9_']*(?:\.[A-Za-z_][A-Za-z0-9_']*)*\Z"
)
_STAGE_A_MODULE = re.compile(
    r"StageA\.[A-Za-z_][A-Za-z0-9_']*(?:\.[A-Za-z_][A-Za-z0-9_']*)*\Z"
)
_IMPORT_IDENTITY = re.compile(r"[a-z0-9_.-]+![^!\s]+\Z")
_UNCHECKED_DECLARATION = re.compile(
    r"(?m)^\s*(?:axiom|opaque)\s+[A-Za-z_][A-Za-z0-9_']*\b"
)
_UNCHECKED_TERM = re.compile(r"\b(?:sorry|admit)\b")

_LEAN_REFS = {
    "context",
    "ordinary_sites",
    "static_compilation",
    "static_authority",
    "mixed_contract",
    "nested_frames",
    "machine_signatures",
    "machine_boundaries",
    "machine_boundary_contracts",
}


class GnuHelloCheckedResponseFamilyError(StageAInputError):
    """The response-family inventory or checked declaration set is invalid."""


@dataclass(frozen=True)
class GnuHelloCheckedResponseFamilyOutputs:
    module: Path
    profile: Path
    concrete_pair_input: Path
    artifact_needs: Path
    report: Path


@dataclass(frozen=True)
class _LeanRef:
    module: str
    declaration: str


def write_gnu_hello_checked_response_family(
    out: Path | str, *, input_manifest: Path | str
) -> GnuHelloCheckedResponseFamilyOutputs:
    input_path = Path(input_manifest)
    payload = _read_json(input_path)
    _exact_keys(
        payload,
        {
            "format",
            "candidate_sha256",
            "reachable_external_site_ids",
            "reachable_import_identities",
            "lockstep_sites",
            "machine_import_report",
            "lean",
        },
        "checked response-family input",
    )
    if payload["format"] != GNU_HELLO_CHECKED_RESPONSE_FAMILY_INPUT_FORMAT:
        raise GnuHelloCheckedResponseFamilyError(
            "unsupported checked response-family input format"
        )

    candidate_sha256 = _sha(payload["candidate_sha256"], "candidate_sha256")
    reachable_ids = _natural_inventory(
        payload["reachable_external_site_ids"], "reachable_external_site_ids"
    )
    if len(reachable_ids) != GNU_HELLO_REACHABLE_EXTERNAL_SITE_COUNT:
        raise GnuHelloCheckedResponseFamilyError(
            "GNU hello response family must cover exactly "
            f"{GNU_HELLO_REACHABLE_EXTERNAL_SITE_COUNT} reachable external sites"
        )

    imports = _import_inventory(payload["reachable_import_identities"])
    if len(imports) != GNU_HELLO_REACHABLE_IMPORT_COUNT:
        raise GnuHelloCheckedResponseFamilyError(
            "GNU hello response family must cover exactly "
            f"{GNU_HELLO_REACHABLE_IMPORT_COUNT} reachable imports"
        )

    sites = _lockstep_sites(payload["lockstep_sites"])
    site_ids = tuple(int(site["id"]) for site in sites)
    if site_ids != reachable_ids:
        missing = sorted(set(reachable_ids) - set(site_ids))
        extra = sorted(set(site_ids) - set(reachable_ids))
        raise GnuHelloCheckedResponseFamilyError(
            "lockstep sites are not exact for reachable external sites: "
            f"missing={missing}, extra={extra}"
        )
    used_imports = tuple(sorted({str(site["import_identity"]) for site in sites}))
    if used_imports != imports:
        missing = sorted(set(imports) - set(used_imports))
        extra = sorted(set(used_imports) - set(imports))
        raise GnuHelloCheckedResponseFamilyError(
            "lockstep sites are not exact for reachable imports: "
            f"missing={missing}, extra={extra}"
        )
    dispositions = {str(site["disposition"]) for site in sites}
    if dispositions != {"returns", "terminates", "protocol"}:
        raise GnuHelloCheckedResponseFamilyError(
            "GNU hello response family must cover returning, terminating, and "
            "protocol sites"
        )
    machine_report = _load_machine_import_report(
        payload["machine_import_report"], input_path.parent
    )
    _cross_check_machine_import_report(machine_report, imports, sites)
    completion_blockers = _response_completion_effect_blockers(machine_report)

    lean = _object(payload["lean"], "checked response-family Lean input")
    _exact_keys(
        lean,
        {"module_sources"} | _LEAN_REFS,
        "checked response-family Lean input",
    )
    sources = _module_sources(
        lean["module_sources"], input_path.parent, "checked response-family"
    )
    refs = {
        name: _lean_ref(lean[name], name, sources)
        for name in sorted(_LEAN_REFS)
    }

    root = Path(out)
    stage_a = root / "StageA"
    stage_a.mkdir(parents=True, exist_ok=True)
    module_path = stage_a / f"{GNU_HELLO_CHECKED_RESPONSE_FAMILY_MODULE}.lean"
    module_path.write_text(
        _lean_source(refs, sites=sites, machine_report=machine_report),
        encoding="ascii",
    )
    generated_module = f"StageA.{GNU_HELLO_CHECKED_RESPONSE_FAMILY_MODULE}"
    generated_row = {
        "module": generated_module,
        "path": str(module_path.resolve()),
        "sha256": _file_sha256(module_path),
    }
    module_rows = [
        {
            "module": module,
            "path": str(path),
            "sha256": _file_sha256(path),
        }
        for module, path in sorted(sources.items())
    ] + [generated_row]

    profile_path = root / "environment-family-profile.json"
    profile = {
        "format": GNU_HELLO_ENVIRONMENT_FAMILY_EVIDENCE_PROFILE_FORMAT,
        "candidate_sha256": candidate_sha256,
        "lockstep": {
            "mode": "exact-1:1-machine-import-nested-callback-v1",
            "sites": sites,
        },
        "lean": {
            "module_sources": module_rows,
            "source_family_scope": "admitted_pairs",
            "launch_scope": "admitted_pairs",
            **{
                name: {
                    "module": generated_module,
                    "declaration": (
                        f"{GNU_HELLO_CHECKED_RESPONSE_FAMILY_NAMESPACE}.{decl}"
                    ),
                }
                for name, decl in {
                    "context": "context",
                    "machine_signatures": "machineSignatures",
                    "machine_boundaries": "machineBoundaries",
                    "classified_sites": "classifiedSites",
                    "classified_site_inventory": "classifiedSiteInventory",
                    "ordinary_sites": "ordinarySites",
                    "static_authority": "staticAuthority",
                    "checked_static_family": "responseFamily",
                    "pair_relation": "PairRelated",
                    "completion_type": "ResponseFamilyCompletion",
                    "completion_definitions_type": (
                        "ResponseFamilyCompletionDefinitions"
                    ),
                    "completion_constructor": "responseFamilyCompletion",
                    "completion_requirements": "completionRequirements",
                    "pair_realizable_from_completion": "pairRealizable",
                    "protocol_response_at": "protocolResponseAt",
                    "checked_original_protocol_responses_at": (
                        "checkedOriginalProtocolResponsesAt"
                    ),
                    "source_family_at": "sourceFamilyAt",
                    "launch_realizable_at": "launchRealizableAt",
                    "nested_acceptance_from_completion": "nestedAcceptanceEvidence",
                    "nested_final_theorem_conditional": (
                        "nestedAdmittedEnvironmentFamilyEquivalent"
                    ),
                    "pinned_compiler_stack_premise": (
                        "PinnedNestedCompilerStackPremise"
                    ),
                    "production_acceptance_evidence": (
                        "productionAcceptanceEvidence"
                    ),
                    "production_acceptance_theorem": (
                        "productionAdmittedEnvironmentFamilyEquivalent"
                    ),
                    "axiom_audit_declaration": (
                        "productionAdmittedEnvironmentFamilyEquivalent"
                    ),
                }.items()
            },
        },
    }
    _write_json(profile_path, profile)

    artifact_needs_path = root / "response-family-completion-artifact-needs.json"
    artifact_needs = _response_completion_artifact_needs(machine_report)
    _write_json(
        artifact_needs_path,
        {
            "format": "stage-a-gnu-hello-response-completion-artifact-needs-v1",
            "candidate_sha256": candidate_sha256,
            "status": "incomplete",
            "lean_requirement_inventory": (
                f"{GNU_HELLO_CHECKED_RESPONSE_FAMILY_NAMESPACE}."
                "completionRequirements"
            ),
            **artifact_needs,
        },
    )

    concrete_input_path = root / "response-family-completion-input.json"
    _write_json(
        concrete_input_path,
        {
            "format": GNU_HELLO_CONCRETE_ENVIRONMENT_PAIR_INPUT_FORMAT,
            "candidate_sha256": candidate_sha256,
            "status": "incomplete",
            "reachable_external_site_ids": list(reachable_ids),
            "lockstep_sites": sites,
            "blockers": [
                *completion_blockers,
                {
                    "category": "reachable_response_domain_not_closed",
                    "affected_site_ids": list(reachable_ids),
                    "required": (
                        "checked invariant-reachable boundary-domain claims, "
                        "canonical response replay, protocol preservation, and "
                        "exact source/native launch specializations"
                    ),
                    "artifact_needs": artifact_needs_path.name,
                    "required_lean_type": (
                        f"{GNU_HELLO_CHECKED_RESPONSE_FAMILY_NAMESPACE}."
                        "ResponseFamilyCompletionDefinitions"
                    ),
                }
            ],
            "lean": {
                "imports": [generated_module],
                "context": (
                    f"{GNU_HELLO_CHECKED_RESPONSE_FAMILY_NAMESPACE}.context"
                ),
                "classified_sites": (
                    f"{GNU_HELLO_CHECKED_RESPONSE_FAMILY_NAMESPACE}.classifiedSites"
                ),
                "ordinary_sites": (
                    f"{GNU_HELLO_CHECKED_RESPONSE_FAMILY_NAMESPACE}.ordinarySites"
                ),
                "static_compilation": (
                    f"{GNU_HELLO_CHECKED_RESPONSE_FAMILY_NAMESPACE}.staticCompilation"
                ),
                "static_authority": (
                    f"{GNU_HELLO_CHECKED_RESPONSE_FAMILY_NAMESPACE}.staticAuthority"
                ),
                "checked_static_family": (
                    f"{GNU_HELLO_CHECKED_RESPONSE_FAMILY_NAMESPACE}.responseFamily"
                ),
                "completion_type": (
                    f"{GNU_HELLO_CHECKED_RESPONSE_FAMILY_NAMESPACE}."
                    "ResponseFamilyCompletion"
                ),
                "completion_definitions_type": (
                    f"{GNU_HELLO_CHECKED_RESPONSE_FAMILY_NAMESPACE}."
                    "ResponseFamilyCompletionDefinitions"
                ),
                "completion_constructor": (
                    f"{GNU_HELLO_CHECKED_RESPONSE_FAMILY_NAMESPACE}."
                    "responseFamilyCompletion"
                ),
                "pinned_compiler_stack_premise": (
                    f"{GNU_HELLO_CHECKED_RESPONSE_FAMILY_NAMESPACE}."
                    "PinnedNestedCompilerStackPremise"
                ),
                "production_acceptance_theorem": (
                    f"{GNU_HELLO_CHECKED_RESPONSE_FAMILY_NAMESPACE}."
                    "productionAdmittedEnvironmentFamilyEquivalent"
                ),
            },
        },
    )

    report_path = root / "checked-response-family.json"
    _write_json(
        report_path,
        {
            "format": GNU_HELLO_CHECKED_RESPONSE_FAMILY_REPORT_FORMAT,
            "status": "incomplete",
            "executes_original_binary": False,
            "executes_candidate_binary": False,
            "proof_authority": False,
            "acceptance_authority": False,
            "candidate_sha256": candidate_sha256,
            "reachable_external_sites": len(sites),
            "reachable_imports": len(imports),
            "returning_sites": sum(
                site["disposition"] == "returns" for site in sites
            ),
            "terminating_sites": sum(
                site["disposition"] == "terminates" for site in sites
            ),
            "protocol_sites": sum(
                site["disposition"] == "protocol" for site in sites
            ),
            "registration_sites": sum(
                site["response_mode"] == "registration" for site in sites
            ),
            "admission_scope": "all-checked-response-schedules",
            "accepted_axiom_policy": "pinned-native-compiler-stack-only",
            "completion_constructor_emitted": True,
            "concrete_completion_emitted": False,
            "checked_protocol_responses_emitted": False,
            "production_acceptance_declarations_emitted": True,
            "canonical_pair_role": "required-checked-nonvacuity-completion",
            "callbacks": "checked-registration-and-nested-frames",
            "footprints": "explicit-complete",
            "required_lean_inputs": sorted(_LEAN_REFS),
            "completion_requirement_inventory": (
                f"{GNU_HELLO_CHECKED_RESPONSE_FAMILY_NAMESPACE}."
                "completionRequirements"
            ),
            "completion_artifact_needs_sha256": _file_sha256(artifact_needs_path),
            "conditional_declaration": (
                f"{GNU_HELLO_CHECKED_RESPONSE_FAMILY_NAMESPACE}."
                "nestedAdmittedEnvironmentFamilyEquivalent"
            ),
            "completion_constructor": (
                f"{GNU_HELLO_CHECKED_RESPONSE_FAMILY_NAMESPACE}."
                "responseFamilyCompletion"
            ),
            "production_acceptance_declaration": (
                f"{GNU_HELLO_CHECKED_RESPONSE_FAMILY_NAMESPACE}."
                "productionAdmittedEnvironmentFamilyEquivalent"
            ),
            "remaining_premises": [
                {
                    "category": "checked_response_completion_artifacts",
                    "lean_type": (
                        f"{GNU_HELLO_CHECKED_RESPONSE_FAMILY_NAMESPACE}."
                        "ResponseFamilyCompletionDefinitions"
                    ),
                    "required_fields": [
                        "reachableBoundaryDomain",
                        "protocolBoundaryDomain",
                        "sourceEnvironment",
                        "nativeEnvironment",
                        "responseSchedule",
                        "sourceAwaitingExternalResponses",
                        "sourceFamily",
                        "launchRealizable",
                    ],
                    "source": "lean_checked_exact_artifacts_not_declaration_names",
                    "artifact_needs": artifact_needs_path.name,
                },
                {
                    "category": "pinned_nested_compiler_stack_correctness",
                    "lean_type": (
                        f"{GNU_HELLO_CHECKED_RESPONSE_FAMILY_NAMESPACE}."
                        "PinnedNestedCompilerStackPremise"
                    ),
                    "approved_axiom_boundary": True,
                },
            ],
            "unapproved_axioms_allowed": False,
            "formal_blockers": [
                *completion_blockers,
                {
                    "category": "reachable_response_domain_not_closed",
                    "affected_site_count": len(sites),
                    "detail": (
                        "the supplied static contracts and lockstep sites do not "
                        "establish state-indexed effect inputs, result resources, "
                        "or continuation facts at every combined-invariant-reachable "
                        "request"
                    ),
                    "obstruction_theorems": [
                        "StageA.Relational.NativeSource."
                        "noDynamicRangeReleaseWithoutOwnedArgument",
                        "StageA.Relational.NativeSource."
                        "noCallbackRegistrationWithoutCheckedTarget",
                    ],
                    "artifact_needs": artifact_needs_path.name,
                    "required_lean_type": (
                        f"{GNU_HELLO_CHECKED_RESPONSE_FAMILY_NAMESPACE}."
                        "ResponseFamilyCompletionDefinitions"
                    ),
                }
            ],
            "machine_import_report_sha256": _sha(
                _object(
                    payload["machine_import_report"], "machine_import_report"
                )["sha256"],
                "machine_import_report.sha256",
            ),
            "module": generated_module,
            "module_sha256": generated_row["sha256"],
            "profile_sha256": _file_sha256(profile_path),
            "canonical_pair_input_sha256": _file_sha256(concrete_input_path),
        },
    )
    return GnuHelloCheckedResponseFamilyOutputs(
        module=module_path,
        profile=profile_path,
        concrete_pair_input=concrete_input_path,
        artifact_needs=artifact_needs_path,
        report=report_path,
    )


def inspect_gnu_hello_checked_response_frontier(
    machine_import_report: Path | str,
) -> dict[str, object]:
    """Classify response-oracle blockers in one exact machine-call report."""

    path = Path(machine_import_report)
    report = _read_json(path)
    _validate_machine_import_report_header(report)
    signatures = _signature_index(report)
    boundaries = _machine_boundaries(report)
    blockers: list[dict[str, object]] = []
    blocked_sites: set[int] = set()
    for boundary in boundaries:
        site_id = _natural(boundary.get("id"), "machine boundary id")
        signature_id = _natural(
            boundary.get("signature_id"), f"machine boundary {site_id} signature_id"
        )
        signature = signatures.get(signature_id)
        if signature is None:
            blockers.append(
                {
                    "category": "missing_signature",
                    "site_id": site_id,
                    "signature_id": signature_id,
                }
            )
            blocked_sites.add(site_id)
            continue
        identity = _report_import_identity(
            signature.get("import"), f"signature {signature_id} import"
        )
        response_mode = _machine_signature_response_mode(signature)
        if response_mode is None:
            blockers.append(
                {
                    "category": "unknown_callback_protocol_form",
                    "site_id": site_id,
                    "import_identity": identity,
                    "observed": {
                        "callback_mode": signature.get("callback_mode"),
                        "disposition": signature.get("disposition"),
                        "memory_effect": signature.get("memory_effect"),
                        "world_effect": signature.get("world_effect"),
                    },
                }
            )
            blocked_sites.add(site_id)
    imports = {
        _report_import_identity(signature.get("import"), "signature import")
        for signature in signatures.values()
    }
    blocked_imports = {
        str(blocker["import_identity"])
        for blocker in blockers
        if "import_identity" in blocker
    }
    completion_blockers = _response_completion_effect_blockers(report)
    return {
        "format": "stage-a-gnu-hello-checked-response-frontier-v2",
        "status": "ready" if not blockers else "incomplete",
        "machine_import_report_sha256": _file_sha256(path),
        "reachable_external_sites": len(boundaries),
        "reachable_imports": len(imports),
        "supported_external_sites": len(boundaries) - len(blocked_sites),
        "supported_imports": len(imports - blocked_imports),
        "blocked_external_sites": len(blocked_sites),
        "blocked_imports": len(blocked_imports),
        "response_modes": {
            mode: sum(
                1
                for boundary in boundaries
                if (signature := signatures.get(
                    _natural(boundary.get("signature_id"), "signature_id")
                )) is not None
                and _machine_signature_response_mode(signature) == mode
            )
            for mode in ("synchronous", "registration", "nestedFrames")
        },
        "response_mode_site_ids": {
            mode: [
                _natural(boundary.get("id"), "machine boundary id")
                for boundary in boundaries
                if (signature := signatures.get(
                    _natural(boundary.get("signature_id"), "signature_id")
                )) is not None
                and _machine_signature_response_mode(signature) == mode
            ]
            for mode in ("synchronous", "registration", "nestedFrames")
        },
        "completion_status": (
            "blocked" if completion_blockers else "unrealized"
        ),
        "completion_blockers": completion_blockers,
        "blockers": blockers,
    }


def _response_completion_effect_blockers(
    report: Mapping[str, Any],
) -> list[dict[str, object]]:
    """Report state-indexed obligations absent from static call contracts.

    Classification uses only the checked machine world-effect class.  Imported
    API identities are intentionally irrelevant.
    """

    signatures = _signature_index(report)
    grouped: dict[str, list[dict[str, int]]] = {
        "dynamicRangeRelease": [],
        "callbackRegistration": [],
    }
    for boundary in _machine_boundaries(report):
        site_id = _natural(boundary.get("id"), "machine boundary id")
        signature_id = _natural(
            boundary.get("signature_id"),
            f"machine boundary {site_id} signature_id",
        )
        signature = signatures.get(signature_id)
        if signature is None:
            continue
        effect = signature.get("world_effect")
        if effect not in grouped:
            continue
        location = {"site_id": site_id, "signature_id": signature_id}
        for field in (
            "source_rva",
            "instruction_rva",
            "continuation_rva",
            "execution_source_rva",
        ):
            value = boundary.get(field)
            if isinstance(value, int) and not isinstance(value, bool) and value >= 0:
                location[field] = value
        grouped[str(effect)].append(location)

    blockers: list[dict[str, object]] = []
    release_sites = grouped["dynamicRangeRelease"]
    if release_sites:
        blockers.append(
            {
                "category": "dynamic_range_release_input_evidence_missing",
                "machine_effect_class": "dynamicRangeRelease",
                "affected_site_count": len(release_sites),
                "affected_site_ids": [site["site_id"] for site in release_sites],
                "locations": release_sites,
                "required_lean_predicate": (
                    "StageA.Relational.NativeSource."
                    "DynamicRangeReleaseInputAdmissible"
                ),
                "necessity_theorem": (
                    "StageA.Relational.NativeSource."
                    "machineCallResultConforms_inputAdmissible"
                ),
                "impossibility_theorem": (
                    "StageA.Relational.NativeSource."
                    "noMachineCallResultConformsOfInadmissible"
                ),
                "counterexample_theorem": (
                    "StageA.Relational.NativeSource."
                    "noDynamicRangeReleaseWithoutOwnedArgument"
                ),
                "detail": (
                    "the exact boundary relation proves related argument words "
                    "but does not prove null-or-owned dynamic-range provenance"
                ),
            }
        )
    registration_sites = grouped["callbackRegistration"]
    if registration_sites:
        blockers.append(
            {
                "category": "callback_registration_target_evidence_missing",
                "machine_effect_class": "callbackRegistration",
                "affected_site_count": len(registration_sites),
                "affected_site_ids": [
                    site["site_id"] for site in registration_sites
                ],
                "locations": registration_sites,
                "required_lean_predicate": (
                    "StageA.Relational.NativeSource."
                    "CallbackRegistrationInputAdmissible"
                ),
                "necessity_theorem": (
                    "StageA.Relational.NativeSource."
                    "machineCallResultConforms_inputAdmissible"
                ),
                "impossibility_theorem": (
                    "StageA.Relational.NativeSource."
                    "noMachineCallResultConformsOfInadmissible"
                ),
                "counterexample_theorem": (
                    "StageA.Relational.NativeSource."
                    "noCallbackRegistrationWithoutCheckedTarget"
                ),
                "detail": (
                    "the exact boundary relation proves related argument words "
                    "but does not prove a checked mapped callback target"
                ),
            }
        )
    return blockers


def _response_completion_artifact_needs(
    report: Mapping[str, Any],
) -> dict[str, object]:
    """Describe exact checked artifacts required to close the response family.

    The Python report exposes locations for iteration.  The authoritative
    requirement inventory is computed in Lean from resolved machine contracts,
    including result relations not duplicated in this diagnostic report.
    """

    signatures = _signature_index(report)
    boundaries = _machine_boundaries(report)

    def locations(
        predicate: Callable[[Mapping[str, Any]], bool],
    ) -> list[dict[str, int]]:
        rows: list[dict[str, int]] = []
        for boundary in boundaries:
            site_id = _natural(boundary.get("id"), "machine boundary id")
            signature_id = _natural(
                boundary.get("signature_id"),
                f"machine boundary {site_id} signature_id",
            )
            signature = signatures.get(signature_id)
            if signature is None or not predicate(signature):
                continue
            row = {"site_id": site_id, "signature_id": signature_id}
            for field in (
                "source_rva",
                "instruction_rva",
                "continuation_rva",
                "execution_source_rva",
            ):
                value = boundary.get(field)
                if isinstance(value, int) and not isinstance(value, bool) and value >= 0:
                    row[field] = value
            rows.append(row)
        return rows

    footprint_sites = locations(
        lambda signature: signature.get("memory_effect")
        in {"readOnly", "argumentRanges"}
    )
    release_sites = locations(
        lambda signature: signature.get("world_effect") == "dynamicRangeRelease"
    )
    registration_sites = locations(
        lambda signature: signature.get("world_effect") == "callbackRegistration"
    )
    return {
        "machine_contract_requirements": {
            "runtime_memory_footprints": footprint_sites,
            "dynamic_range_release": release_sites,
            "callback_registration": registration_sites,
            "result_resources": {
                "source": "lean_requirement_inventory",
                "reason": (
                    "result-register relations are checked in the resolved Lean "
                    "contracts and are not duplicated by this report schema"
                ),
            },
        },
        "required_checked_artifacts": [
            {
                "kind": "reachable-response-boundary-domain-inventory",
                "coverage": "all-invariant-reachable-ordinary-and-protocol-sites",
                "proves": [
                    "runtime_memory_footprints",
                    "world_effect_input_admissibility",
                    "nonnullable_result_resource_availability",
                ],
            },
            {
                "kind": "checked-original-machine-protocol-responses",
                "coverage": "every-invariant-reachable-awaiting-external-state",
                "lean_type": (
                    "CheckedOriginalCombinedMachineProtocolResponses"
                ),
                "proves": [
                    "returned_post_families",
                    "callback_entry_post_families",
                    "terminated_post_families",
                    "runtime_memory_preservation",
                ],
            },
            {
                "kind": "canonical-response-replay-inventory",
                "coverage": "all-194-machine-sites",
                "proves": [
                    "abi_results",
                    "memory_effects",
                    "world_updates",
                    "result_register_relations",
                    "continuation_state_rel",
                    "runtime_frames",
                    "nested_callbacks",
                    "termination",
                ],
            },
            {
                "kind": "response-specialized-source-launch-family",
                "coverage": "all-checked-pe32-console-launches",
            },
            {
                "kind": "response-specialized-native-launch-realizability",
                "coverage": "exact-compiled-pe",
            },
        ],
    }


def _machine_signature_response_mode(
    signature: Mapping[str, Any],
) -> str | None:
    """Classify only machine-contract shapes; import names are irrelevant."""

    callback_mode = signature.get("callback_mode")
    disposition = signature.get("disposition")
    memory_effect = signature.get("memory_effect")
    world_effect = signature.get("world_effect")
    footprints = signature.get("memory_footprints")
    if not isinstance(footprints, list):
        return None
    if callback_mode == "none":
        if disposition not in {"returns", "terminates"}:
            return None
        if world_effect == "callbackRegistration":
            return None
        if disposition == "terminates" and (
            memory_effect != "none" or footprints or world_effect != "none"
        ):
            return None
        return "synchronous"
    if callback_mode == "registration":
        if disposition != "returns" or world_effect != "callbackRegistration":
            return None
        return "registration"
    if callback_mode == "nestedFrames":
        if not (
            disposition == "protocol"
            and memory_effect == "relationalState"
            and not footprints
            and world_effect == "none"
        ):
            return None
        return "nestedFrames"
    return None


def write_gnu_hello_checked_response_frontier(
    out: Path | str, *, machine_import_report: Path | str
) -> Path:
    path = Path(out)
    path.parent.mkdir(parents=True, exist_ok=True)
    _write_json(
        path,
        inspect_gnu_hello_checked_response_frontier(machine_import_report),
    )
    return path


def _lean_classified_sites(
    sites: Sequence[Mapping[str, object]],
    machine_report: Mapping[str, Any],
) -> str:
    signature_by_boundary = {
        _natural(boundary.get("id"), "machine boundary id"): _natural(
            boundary.get("signature_id"), "machine boundary signature_id"
        )
        for boundary in _machine_boundaries(machine_report)
    }
    rows: list[str] = []
    for site in sites:
        site_id = int(site["id"])
        mode = str(site["response_mode"])
        if mode == "synchronous":
            lean_mode = ".synchronous"
        elif mode == "nestedFrames":
            lean_mode = ".nestedFrames"
        elif mode == "registration":
            callbacks = site["callbacks"]
            assert isinstance(callbacks, list) and len(callbacks) == 1
            argument_index = int(callbacks[0]["argument_index"])
            lean_mode = f".registration {argument_index}"
        else:
            raise GnuHelloCheckedResponseFamilyError(
                f"unsupported checked response mode at site {site_id}: {mode}"
            )
        rows.append(
            "  { boundaryId := "
            f"{site_id}, signatureId := {signature_by_boundary[site_id]}, "
            f"mode := {lean_mode} }}"
        )
    return "[\n" + ",\n".join(rows) + "\n]"


def _lean_source(
    refs: Mapping[str, _LeanRef],
    *,
    sites: Sequence[Mapping[str, object]],
    machine_report: Mapping[str, Any],
) -> str:
    imported_modules = sorted({ref.module for ref in refs.values()})
    import_lines = "\n".join(
        [
            "import StageA.RelationalNativeSourceNestedAdmittedResponseFamily",
            "import StageA.RelationalNativeSourceResponseRequirements",
        ]
        + [f"import {module}" for module in imported_modules]
    )
    ns = GNU_HELLO_CHECKED_RESPONSE_FAMILY_NAMESPACE
    declaration = lambda name: refs[name].declaration
    classified_sites = _lean_classified_sites(sites, machine_report)
    return f"""{import_lines}

namespace {ns}

open StageA.Relational
open StageA.Relational.InterpreterMixedContext
open StageA.Relational.InterpreterMixedEnvironment
open StageA.Relational.NativeSource
open StageA.Relational.OriginalCombinedAwaitingExternalPreservation
open StageA.Relational.StaticMachineImportContracts

abbrev context : StaticProofContext := {declaration('context')}
def machineSignatures : List StaticMachineImportSignature :=
  {declaration('machine_signatures')}
def machineBoundaries : List StaticMachineImportBoundary :=
  {declaration('machine_boundaries')}
abbrev machineBoundaryContracts :
    CheckedStaticMachineImportBoundaryContracts context.originalPe
      context.originalImports machineSignatures machineBoundaries :=
  {declaration('machine_boundary_contracts')}
def classifiedSites : List CheckedMachineExternalSite :=
{classified_sites}
def ordinarySites : List OpaqueLockstepCallSite :=
  {declaration('ordinary_sites')}
abbrev staticCompilation : ExactNativeCompilation :=
  {declaration('static_compilation')}
def staticAuthority :
    StaticNativeSourceEnvironmentFamilyAuthority context staticCompilation :=
  {declaration('static_authority')}
abbrev mixedContract : MixedRelationContract := {declaration('mixed_contract')}
abbrev nestedFrames : MixedNestedExternalFrameContract :=
  {declaration('nested_frames')}

def classifiedSiteInventory :
    CheckedMachineExternalSiteInventory context.originalPe
      context.originalImports machineSignatures machineBoundaries := {{
  boundaryContracts := machineBoundaryContracts
  sites := classifiedSites
  checked := by native_decide
}}

/-- Lean-derived requirements from the exact resolved contracts.  This is the
authoritative inventory for response-domain artifact generation. -/
def completionRequirements : List MachineResponseRequirement :=
  checkedMachineResponseRequirements machineBoundaryContracts.inventory

def responseFamily :
    CheckedWorldNativeAdmittedProtocolResponseFamily context classifiedSites
      ordinarySites staticCompilation mixedContract nestedFrames := {{
  classificationChecked :=
    Exists.intro machineSignatures
      (Exists.intro machineBoundaries
        (Exists.intro classifiedSiteInventory rfl))
  completeCoverage := by native_decide
  ordinaryUnique := by native_decide
  ordinaryValid := by native_decide
}}

/-- Every checked response schedule is admitted.  Static classification does
not assert that an admitted response schedule exists. -/
abbrev PairRelated := responseFamily.Related

abbrev ResponseFamilyCompletion := responseFamily.Completion

/-- Exact source/native response functions plus their Lean-checked machine,
world, callback, continuation, and launch evidence.  This is data supplied to
the generated constructor, never a proof declaration named by JSON. -/
abbrev ResponseFamilyCompletionDefinitions :=
  CheckedTotalProtocolResponseDefinitions responseFamily

/-- The only compiler-side premise retained by production acceptance. -/
abbrev PinnedNestedCompilerStackPremise :=
  forall sourceEnvironment nativeEnvironment,
    PairRelated sourceEnvironment nativeEnvironment ->
      CorrectPinnedNestedNativeSourceStackHypothesis
        (exactNativeCompilationAtResponseEnvironments staticCompilation
          sourceEnvironment nativeEnvironment.ordinary)
        (exactNestedNativeCompilationAtResponseEnvironments staticCompilation
          sourceEnvironment nativeEnvironment)

/-- Concrete checked completion constructor exported for Nix proof wiring. -/
def responseFamilyCompletion
    (definitions : ResponseFamilyCompletionDefinitions) :
    ResponseFamilyCompletion :=
  definitions.toCompletion

theorem pairRealizable (completion : ResponseFamilyCompletion) :
    exists sourceEnvironment nativeEnvironment,
    PairRelated sourceEnvironment nativeEnvironment :=
  completion.realizable

theorem protocolResponseAt : forall sourceEnvironment nativeEnvironment,
    PairRelated sourceEnvironment nativeEnvironment ->
    CheckedWorldNativeProtocolResponseSchedule context
      (exactNativeCompilationAtResponseEnvironments staticCompilation
        sourceEnvironment
        nativeEnvironment.ordinary).project.worldProgram
      (nativeEnvironment.nestedProgram
        (exactNativeCompilationAtResponseEnvironments staticCompilation
          sourceEnvironment
          nativeEnvironment.ordinary).machineAuthority.program)
      classifiedSites ordinarySites sourceEnvironment.ordinary mixedContract
        nestedFrames := by
  intro sourceEnvironment nativeEnvironment related
  cases related with
  | intro admitted => exact admitted.responseSchedule

theorem checkedOriginalProtocolResponsesAt
    (sourceEnvironment : SourceWorldResponseEnvironment)
    (nativeEnvironment : NativeWorldResponseEnvironment)
    (related : PairRelated sourceEnvironment nativeEnvironment) :
    let schedule := protocolResponseAt sourceEnvironment nativeEnvironment related
    CheckedOriginalCombinedMachineProtocolResponses
      (exactNativeCompilationAtResponseEnvironments staticCompilation
        sourceEnvironment nativeEnvironment.ordinary).project.worldProgram
      schedule.originalContext schedule.sourceInventory := by
  dsimp only
  exact (protocolResponseAt sourceEnvironment nativeEnvironment related).
    sourceAwaitingExternalResponses

theorem sourceFamilyAt : forall sourceEnvironment nativeEnvironment,
    PairRelated sourceEnvironment nativeEnvironment ->
    CheckedNativeSourceLaunchFamily
      (exactNativeCompilationAtResponseEnvironments staticCompilation
        sourceEnvironment
        nativeEnvironment.ordinary).project := by
  intro sourceEnvironment nativeEnvironment related
  cases related with
  | intro admitted => exact admitted.sourceFamily

theorem launchRealizableAt : forall sourceEnvironment nativeEnvironment,
    PairRelated sourceEnvironment nativeEnvironment ->
    NativeCompilationLaunchRealizable
      (exactNativeCompilationAtResponseEnvironments staticCompilation
        sourceEnvironment
        nativeEnvironment.ordinary).machineAuthority := by
  intro sourceEnvironment nativeEnvironment related
  cases related with
  | intro admitted => exact admitted.launchRealizable

def nestedAcceptanceEvidence
    (completion : ResponseFamilyCompletion)
    (nestedToolchainCorrectAt : forall sourceEnvironment nativeEnvironment,
      PairRelated sourceEnvironment nativeEnvironment ->
        CorrectPinnedNestedNativeSourceStackHypothesis
          (exactNativeCompilationAtResponseEnvironments staticCompilation
            sourceEnvironment nativeEnvironment.ordinary)
          (exactNestedNativeCompilationAtResponseEnvironments staticCompilation
            sourceEnvironment nativeEnvironment)) :
    CheckedNestedNativeSourceAdmittedEnvironmentFamily context classifiedSites
      ordinarySites staticCompilation mixedContract nestedFrames PairRelated :=
  responseFamily.toNestedAcceptance completion nestedToolchainCorrectAt

/-- Final launch-universal theorem over the callback-capable compiled carrier.
The exact response schedule remains quantified by `PairRelated`. -/
theorem nestedAdmittedEnvironmentFamilyEquivalent
    (completion : ResponseFamilyCompletion)
    (nestedToolchainCorrectAt : forall sourceEnvironment nativeEnvironment,
      PairRelated sourceEnvironment nativeEnvironment ->
        CorrectPinnedNestedNativeSourceStackHypothesis
          (exactNativeCompilationAtResponseEnvironments staticCompilation
            sourceEnvironment nativeEnvironment.ordinary)
          (exactNestedNativeCompilationAtResponseEnvironments staticCompilation
            sourceEnvironment nativeEnvironment)) :
    ExactRawOriginalPENestedCompiledArtifactAdmittedEnvironmentFamilyEquivalence
      context classifiedSites ordinarySites staticCompilation mixedContract
      nestedFrames PairRelated :=
  compiledNestedArtifactAdmittedEnvironmentFamilyEquivalentUnderPinnedNativeSourceStackHypothesis
    (nestedAcceptanceEvidence completion nestedToolchainCorrectAt)

/-- Production acceptance package with no string-selected proof authority. -/
def productionAcceptanceEvidence
    (definitions : ResponseFamilyCompletionDefinitions)
    (compilerStack : PinnedNestedCompilerStackPremise) :
    CheckedNestedNativeSourceAdmittedEnvironmentFamily context classifiedSites
      ordinarySites staticCompilation mixedContract nestedFrames PairRelated :=
  nestedAcceptanceEvidence (responseFamilyCompletion definitions) compilerStack

/-- Production whole-family theorem.  Nix needs only this module, one checked
response-definition value, and the approved pinned compiler-stack premise. -/
theorem productionAdmittedEnvironmentFamilyEquivalent
    (definitions : ResponseFamilyCompletionDefinitions)
    (compilerStack : PinnedNestedCompilerStackPremise) :
    ExactRawOriginalPENestedCompiledArtifactAdmittedEnvironmentFamilyEquivalence
      context classifiedSites ordinarySites staticCompilation mixedContract
      nestedFrames PairRelated :=
  nestedAdmittedEnvironmentFamilyEquivalent
    (responseFamilyCompletion definitions) compilerStack

end {ns}
"""


def _load_machine_import_report(
    value: object, root: Path
) -> Mapping[str, Any]:
    row = _object(value, "machine_import_report")
    _exact_keys(row, {"path", "sha256"}, "machine_import_report")
    raw_path = Path(_string(row["path"], "machine_import_report.path"))
    path = (raw_path if raw_path.is_absolute() else root / raw_path).resolve()
    if not path.is_file():
        raise GnuHelloCheckedResponseFamilyError(
            "machine_import_report.path is not a file"
        )
    observed = _file_sha256(path)
    expected = _sha(row["sha256"], "machine_import_report.sha256")
    if observed != expected:
        raise GnuHelloCheckedResponseFamilyError(
            "machine import report source hash mismatch"
        )
    report = _read_json(path)
    _validate_machine_import_report_header(report)
    frontier = inspect_gnu_hello_checked_response_frontier(path)
    if frontier["status"] != "ready":
        blocked_sites = sorted(
            {
                int(blocker["site_id"])
                for blocker in frontier["blockers"]
                if "site_id" in blocker
            }
        )
        raise GnuHelloCheckedResponseFamilyError(
            "machine import report contains unsupported protocol/callback "
            f"sites: {blocked_sites}"
        )
    return report


def _validate_machine_import_report_header(report: Mapping[str, Any]) -> None:
    if report.get("format") != STATIC_MACHINE_IMPORT_CONTRACTS_FORMAT:
        raise GnuHelloCheckedResponseFamilyError(
            "unsupported machine import report format"
        )
    if report.get("status") != "ready":
        raise GnuHelloCheckedResponseFamilyError(
            "machine import report is not ready"
        )
    blockers = report.get("blockers")
    if not isinstance(blockers, list) or blockers:
        raise GnuHelloCheckedResponseFamilyError(
            "machine import report contains unresolved blockers"
        )
    counts = _object(report.get("counts"), "machine import report counts")
    expected = {
        "checked_boundary_proposals": GNU_HELLO_REACHABLE_EXTERNAL_SITE_COUNT,
        "required_reachable_imports": GNU_HELLO_REACHABLE_IMPORT_COUNT,
        "lean_profile_signatures": GNU_HELLO_REACHABLE_IMPORT_COUNT,
        "imports_with_boundary_proposals": GNU_HELLO_REACHABLE_IMPORT_COUNT,
    }
    for name, wanted in expected.items():
        if counts.get(name) != wanted:
            raise GnuHelloCheckedResponseFamilyError(
                f"machine import report {name} must equal {wanted}"
            )


def _signature_index(report: Mapping[str, Any]) -> dict[int, Mapping[str, Any]]:
    raw = report.get("signatures")
    if not isinstance(raw, list) or len(raw) != GNU_HELLO_REACHABLE_IMPORT_COUNT:
        raise GnuHelloCheckedResponseFamilyError(
            "machine import report must contain exactly 60 signatures"
        )
    result: dict[int, Mapping[str, Any]] = {}
    for index, value in enumerate(raw):
        signature = _object(value, f"machine signature {index}")
        signature_id = _natural(signature.get("id"), f"machine signature {index} id")
        if signature_id in result:
            raise GnuHelloCheckedResponseFamilyError(
                "machine import report contains duplicate signature IDs"
            )
        result[signature_id] = signature
    return result


def _machine_boundaries(report: Mapping[str, Any]) -> list[Mapping[str, Any]]:
    raw = report.get("boundaries")
    if not isinstance(raw, list) or len(raw) != GNU_HELLO_REACHABLE_EXTERNAL_SITE_COUNT:
        raise GnuHelloCheckedResponseFamilyError(
            "machine import report must contain exactly 194 boundaries"
        )
    result = [
        _object(value, f"machine boundary {index}")
        for index, value in enumerate(raw)
    ]
    ids = tuple(
        _natural(boundary.get("id"), f"machine boundary {index} id")
        for index, boundary in enumerate(result)
    )
    if ids != tuple(sorted(set(ids))):
        raise GnuHelloCheckedResponseFamilyError(
            "machine boundary IDs must be unique and canonically sorted"
        )
    return result


def _cross_check_machine_import_report(
    report: Mapping[str, Any],
    imports: tuple[str, ...],
    sites: Sequence[Mapping[str, object]],
) -> None:
    signatures = _signature_index(report)
    boundaries = _machine_boundaries(report)
    report_imports_raw = report.get("required_imports")
    if not isinstance(report_imports_raw, list):
        raise GnuHelloCheckedResponseFamilyError(
            "machine import report required_imports must be an array"
        )
    report_imports = tuple(
        sorted(
            _report_import_identity(value, f"required import {index}")
            for index, value in enumerate(report_imports_raw)
        )
    )
    if report_imports != imports:
        raise GnuHelloCheckedResponseFamilyError(
            "reachable import inventory differs from the machine import report"
        )

    by_id = {int(site["id"]): site for site in sites}
    for boundary in boundaries:
        site_id = _natural(boundary.get("id"), "machine boundary id")
        site = by_id.get(site_id)
        if site is None:
            raise GnuHelloCheckedResponseFamilyError(
                f"machine boundary {site_id} is missing from lockstep sites"
            )
        signature_id = _natural(
            boundary.get("signature_id"), f"machine boundary {site_id} signature_id"
        )
        signature = signatures.get(signature_id)
        if signature is None:
            raise GnuHelloCheckedResponseFamilyError(
                f"machine boundary {site_id} references a missing signature"
            )
        boundary_identity = _report_import_identity(
            boundary.get("import"), f"machine boundary {site_id} import"
        )
        signature_identity = _report_import_identity(
            signature.get("import"), f"machine signature {signature_id} import"
        )
        if not (
            site["import_identity"] == boundary_identity == signature_identity
        ):
            raise GnuHelloCheckedResponseFamilyError(
                f"machine boundary {site_id} import identity mismatch"
            )
        if site["disposition"] != signature.get("disposition"):
            raise GnuHelloCheckedResponseFamilyError(
                f"machine boundary {site_id} disposition mismatch"
            )
        response_mode = _machine_signature_response_mode(signature)
        if response_mode is None or site["response_mode"] != response_mode:
            raise GnuHelloCheckedResponseFamilyError(
                f"machine boundary {site_id} callback/protocol mode mismatch"
            )
        argument_words = _natural(
            boundary.get("argument_words"),
            f"machine boundary {site_id} argument_words",
        )
        if len(site["argument_sources"]) != argument_words:
            raise GnuHelloCheckedResponseFamilyError(
                f"machine boundary {site_id} argument inventory mismatch"
            )
        if response_mode == "registration":
            callback = _object(site["callbacks"][0], "registration callback")
            argument_index = _natural(
                callback.get("argument_index"), "registration argument_index"
            )
            if argument_index >= argument_words:
                raise GnuHelloCheckedResponseFamilyError(
                    f"machine boundary {site_id} callback argument is out of range"
                )
        footprints = signature.get("memory_footprints")
        if not isinstance(footprints, list):
            raise GnuHelloCheckedResponseFamilyError(
                f"machine signature {signature_id} memory_footprints is not an array"
            )
        expected_read = [
            footprint for footprint in footprints
            if isinstance(footprint, Mapping) and footprint.get("access") == "read"
        ]
        expected_write = [
            footprint for footprint in footprints
            if isinstance(footprint, Mapping) and footprint.get("access") == "write"
        ]
        if len(expected_read) + len(expected_write) != len(footprints):
            raise GnuHelloCheckedResponseFamilyError(
                f"machine signature {signature_id} has an unsupported footprint"
            )
        if site["read_footprints"] != expected_read:
            raise GnuHelloCheckedResponseFamilyError(
                f"machine boundary {site_id} read footprint mismatch"
            )
        if site["write_footprints"] != expected_write:
            raise GnuHelloCheckedResponseFamilyError(
                f"machine boundary {site_id} write footprint mismatch"
            )


def _report_import_identity(value: object, label: str) -> str:
    imported = _object(value, label)
    if set(imported) != {"dll", "symbol"}:
        raise GnuHelloCheckedResponseFamilyError(
            f"{label} must contain exactly dll and symbol"
        )
    dll = _string(imported["dll"], f"{label}.dll").lower()
    symbol = imported["symbol"]
    if isinstance(symbol, int) and not isinstance(symbol, bool) and symbol >= 0:
        rendered = f"#{symbol}"
    else:
        rendered = _string(symbol, f"{label}.symbol")
    return _import_identity(f"{dll}!{rendered}", label)


def _lockstep_sites(value: object) -> list[dict[str, object]]:
    if not isinstance(value, list) or not value:
        raise GnuHelloCheckedResponseFamilyError(
            "lockstep_sites must be a non-empty array"
        )
    expected = {
        "id",
        "import_identity",
        "disposition",
        "response_mode",
        "argument_sources",
        "read_footprints",
        "write_footprints",
        "callbacks",
        "footprints_complete",
        "callbacks_complete",
    }
    result: list[dict[str, object]] = []
    for index, raw in enumerate(value):
        label = f"lockstep_sites[{index}]"
        site = _object(raw, label)
        _exact_keys(site, expected, label)
        site_id = _natural(site["id"], f"{label}.id")
        import_identity = _import_identity(
            site["import_identity"], f"{label}.import_identity"
        )
        disposition = site["disposition"]
        if disposition not in {"returns", "terminates", "protocol"}:
            raise GnuHelloCheckedResponseFamilyError(
                f"{label}.disposition is unsupported"
            )
        response_mode = site["response_mode"]
        if response_mode not in {"synchronous", "registration", "nestedFrames"}:
            raise GnuHelloCheckedResponseFamilyError(
                f"{label}.response_mode is unsupported"
            )
        arrays: dict[str, list[object]] = {}
        for field in (
            "argument_sources",
            "read_footprints",
            "write_footprints",
            "callbacks",
        ):
            raw_array = site[field]
            if not isinstance(raw_array, list):
                raise GnuHelloCheckedResponseFamilyError(
                    f"{label}.{field} must be an explicit array"
                )
            if any(not isinstance(item, Mapping) for item in raw_array):
                raise GnuHelloCheckedResponseFamilyError(
                    f"{label}.{field} entries must be objects"
                )
            fingerprints = [
                json.dumps(item, sort_keys=True, separators=(",", ":"))
                for item in raw_array
            ]
            if len(fingerprints) != len(set(fingerprints)):
                raise GnuHelloCheckedResponseFamilyError(
                    f"{label}.{field} contains duplicate entries"
                )
            arrays[field] = list(raw_array)
        if site["footprints_complete"] is not True:
            raise GnuHelloCheckedResponseFamilyError(
                f"{label} has incomplete memory footprints"
            )
        if site["callbacks_complete"] is not True:
            raise GnuHelloCheckedResponseFamilyError(
                f"{label} has incomplete callback coverage"
            )
        callbacks = arrays["callbacks"]
        if response_mode == "synchronous" and callbacks:
            raise GnuHelloCheckedResponseFamilyError(
                f"{label} synchronous response cannot declare callbacks"
            )
        if response_mode == "registration":
            if disposition != "returns" or len(callbacks) != 1:
                raise GnuHelloCheckedResponseFamilyError(
                    f"{label} registration response must return and declare one callback"
                )
            callback = _object(callbacks[0], f"{label}.callbacks[0]")
            _exact_keys(
                callback, {"kind", "argument_index"}, f"{label}.callbacks[0]"
            )
            if callback["kind"] != "registration":
                raise GnuHelloCheckedResponseFamilyError(
                    f"{label} registration callback kind mismatch"
                )
            _natural(
                callback["argument_index"],
                f"{label}.callbacks[0].argument_index",
            )
        if response_mode == "nestedFrames":
            if disposition != "protocol" or len(callbacks) != 1:
                raise GnuHelloCheckedResponseFamilyError(
                    f"{label} nested-frame response must be protocol and explicit"
                )
            callback = _object(callbacks[0], f"{label}.callbacks[0]")
            _exact_keys(
                callback, {"kind", "target_ids"}, f"{label}.callbacks[0]"
            )
            if callback["kind"] != "registered_nested_frames":
                raise GnuHelloCheckedResponseFamilyError(
                    f"{label} nested-frame callback kind mismatch"
                )
            _natural_inventory(
                callback["target_ids"], f"{label}.callbacks[0].target_ids"
            )
        if response_mode == "synchronous" and disposition == "protocol":
            raise GnuHelloCheckedResponseFamilyError(
                f"{label} protocol disposition requires nested frames"
            )
        result.append(
            {
                "id": site_id,
                "import_identity": import_identity,
                "disposition": disposition,
                "response_mode": response_mode,
                **arrays,
                "footprints_complete": True,
                "callbacks_complete": True,
            }
        )
    ids = tuple(int(site["id"]) for site in result)
    if ids != tuple(sorted(set(ids))):
        raise GnuHelloCheckedResponseFamilyError(
            "lockstep site IDs must be unique and canonically sorted"
        )
    return result


def _natural_inventory(value: object, label: str) -> tuple[int, ...]:
    if not isinstance(value, list) or not value:
        raise GnuHelloCheckedResponseFamilyError(
            f"{label} must be a non-empty array"
        )
    result = tuple(_natural(item, f"{label}[{index}]") for index, item in enumerate(value))
    if result != tuple(sorted(set(result))):
        raise GnuHelloCheckedResponseFamilyError(
            f"{label} must be unique and canonically sorted"
        )
    return result


def _import_inventory(value: object) -> tuple[str, ...]:
    if not isinstance(value, list) or not value:
        raise GnuHelloCheckedResponseFamilyError(
            "reachable_import_identities must be a non-empty array"
        )
    result = tuple(
        _import_identity(item, f"reachable_import_identities[{index}]")
        for index, item in enumerate(value)
    )
    if result != tuple(sorted(set(result))):
        raise GnuHelloCheckedResponseFamilyError(
            "reachable_import_identities must be unique and canonically sorted"
        )
    return result


def _import_identity(value: object, label: str) -> str:
    if not isinstance(value, str) or _IMPORT_IDENTITY.fullmatch(value) is None:
        raise GnuHelloCheckedResponseFamilyError(
            f"{label} must be a normalized dll!symbol identity"
        )
    dll, _separator, symbol = value.partition("!")
    if dll != dll.lower() or not symbol:
        raise GnuHelloCheckedResponseFamilyError(
            f"{label} must use a lowercase normalized DLL name"
        )
    return value


def _module_sources(
    value: object, root: Path, label: str
) -> dict[str, Path]:
    if not isinstance(value, list) or not value:
        raise GnuHelloCheckedResponseFamilyError(
            f"{label} module_sources must be a non-empty array"
        )
    result: dict[str, Path] = {}
    for index, raw in enumerate(value):
        row_label = f"{label} module_sources[{index}]"
        row = _object(raw, row_label)
        _exact_keys(row, {"module", "path", "sha256"}, row_label)
        module = _module(row["module"], f"{row_label}.module")
        raw_path = Path(_string(row["path"], f"{row_label}.path"))
        path = (raw_path if raw_path.is_absolute() else root / raw_path).resolve()
        if module in result or not path.is_file() or path.suffix != ".lean":
            raise GnuHelloCheckedResponseFamilyError(
                f"{row_label} is duplicate or not a Lean source"
            )
        if _file_sha256(path) != _sha(row["sha256"], f"{row_label}.sha256"):
            raise GnuHelloCheckedResponseFamilyError(
                f"{row_label} source hash mismatch"
            )
        text = path.read_text(encoding="utf-8")
        if _UNCHECKED_DECLARATION.search(text) or _UNCHECKED_TERM.search(text):
            raise GnuHelloCheckedResponseFamilyError(
                f"{row_label} contains an unchecked Lean declaration or term"
            )
        result[module] = path
    return result


def _lean_ref(
    value: object, label: str, sources: Mapping[str, Path]
) -> _LeanRef:
    row = _object(value, f"Lean reference {label}")
    _exact_keys(row, {"module", "declaration"}, f"Lean reference {label}")
    module = _module(row["module"], f"Lean reference {label}.module")
    declaration = _lean_name(
        row["declaration"], f"Lean reference {label}.declaration"
    )
    source = sources.get(module)
    if source is None:
        raise GnuHelloCheckedResponseFamilyError(
            f"Lean reference {label} module is absent from module_sources"
        )
    terminal = declaration.rsplit(".", 1)[-1]
    declaration_pattern = re.compile(
        rf"(?m)^\s*(?:abbrev|def|theorem|structure)\s+{re.escape(terminal)}\b"
    )
    if declaration_pattern.search(source.read_text(encoding="utf-8")) is None:
        raise GnuHelloCheckedResponseFamilyError(
            f"Lean reference {label} declaration is absent from its source"
        )
    return _LeanRef(module=module, declaration=declaration)


def _read_json(path: Path) -> Mapping[str, Any]:
    try:
        return _object(json.loads(path.read_text(encoding="utf-8")), str(path))
    except (OSError, json.JSONDecodeError) as exc:
        raise GnuHelloCheckedResponseFamilyError(
            f"cannot read checked response-family input {path}: {exc}"
        ) from exc


def _write_json(path: Path, value: object) -> None:
    path.write_text(
        json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n",
        encoding="ascii",
    )


def _object(value: object, label: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping) or any(not isinstance(key, str) for key in value):
        raise GnuHelloCheckedResponseFamilyError(f"{label} must be an object")
    return value


def _exact_keys(value: Mapping[str, Any], expected: set[str], label: str) -> None:
    missing = sorted(expected - set(value))
    extra = sorted(set(value) - expected)
    if missing or extra:
        raise GnuHelloCheckedResponseFamilyError(
            f"{label} fields differ: missing={missing}, extra={extra}"
        )


def _natural(value: object, label: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise GnuHelloCheckedResponseFamilyError(
            f"{label} must be a natural number"
        )
    return value


def _string(value: object, label: str) -> str:
    if not isinstance(value, str) or not value:
        raise GnuHelloCheckedResponseFamilyError(
            f"{label} must be a non-empty string"
        )
    return value


def _sha(value: object, label: str) -> str:
    if not isinstance(value, str) or _SHA256.fullmatch(value) is None:
        raise GnuHelloCheckedResponseFamilyError(
            f"{label} must be a lowercase SHA-256"
        )
    return value


def _module(value: object, label: str) -> str:
    if not isinstance(value, str) or _STAGE_A_MODULE.fullmatch(value) is None:
        raise GnuHelloCheckedResponseFamilyError(
            f"{label} must be a canonical StageA module"
        )
    return value


def _lean_name(value: object, label: str) -> str:
    if not isinstance(value, str) or _LEAN_NAME.fullmatch(value) is None:
        raise GnuHelloCheckedResponseFamilyError(
            f"{label} must be a canonical Lean declaration"
        )
    return value


def _file_sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main(argv: Sequence[str] | None = None) -> int:
    import argparse

    parser = argparse.ArgumentParser()
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--input", type=Path)
    mode.add_argument("--inspect-machine-import-report", type=Path)
    parser.add_argument("--out", required=True, type=Path)
    args = parser.parse_args(argv)
    if args.inspect_machine_import_report is not None:
        output = write_gnu_hello_checked_response_frontier(
            args.out,
            machine_import_report=args.inspect_machine_import_report,
        )
        print(output)
        return 0
    outputs = write_gnu_hello_checked_response_family(
        args.out, input_manifest=args.input
    )
    print(outputs.profile)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())


__all__ = [
    "GNU_HELLO_CHECKED_RESPONSE_FAMILY_INPUT_FORMAT",
    "GNU_HELLO_CHECKED_RESPONSE_FAMILY_MODULE",
    "GNU_HELLO_CHECKED_RESPONSE_FAMILY_NAMESPACE",
    "GNU_HELLO_REACHABLE_EXTERNAL_SITE_COUNT",
    "GNU_HELLO_REACHABLE_IMPORT_COUNT",
    "GnuHelloCheckedResponseFamilyError",
    "GnuHelloCheckedResponseFamilyOutputs",
    "inspect_gnu_hello_checked_response_frontier",
    "write_gnu_hello_checked_response_frontier",
    "write_gnu_hello_checked_response_family",
]
