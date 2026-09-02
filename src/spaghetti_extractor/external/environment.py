"""Content-bound external-environment intent, projection, and resolution.

The intent and its early projection are non-authorizing.  Resolution binds
them to the exact module and checked boundary packages and remains incomplete
whenever a reachable physical boundary lacks one unambiguous contract.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, Mapping, Sequence

from ..artifacts.artifact_set import canonical_sha256_v3
from ..artifacts.formats import LAUNCH_ASSUMPTION_TEMPLATE_FORMAT
from ..boundary import BoundarySchemaV1, TargetDataLayoutV1
from ..calls.dialects.ia32 import IA32DialectCheckerV1
from ..calls.frame import (
    PhysicalCallFrameV3,
    physical_frame_abi_sha256_v1,
)
from ..errors import ToolkitInputError
from ..transfer.operations import EFFECT_OPERATIONS_V2
from ..transfer.plan import load_executable_transfer_plan
from ..util import sha256_file, write_json
from .environment_boundaries import (
    _identity_from_row,
    _identity_payload,
    _interface_callback_catalogs,
    _machine_boundary_catalogs,
    _machine_callback_catalogs,
    _module_export_boundary_catalogs,
    lower_machine_import_boundary_v1,
)
from .formats import (
    EXTERNAL_ENVIRONMENT_ANALYSIS_PROJECTION_FORMAT,
    EXTERNAL_ENVIRONMENT_INTENT_FORMAT,
    RESOLVED_EXTERNAL_ENVIRONMENT_FORMAT,
)
from .boundary_bindings import (
    schema_callback_links_v1,
    schema_frame_machine_bindings_v1,
)
from .interface_profiles import (
    ExternalInterfaceProfileError,
    load_external_interface_profile,
)
from .machine_import_profiles import (
    MachineImportIdentity,
    MachineImportProfileError,
    SelectedMachineImportContract,
    load_machine_import_profile_set,
)
from .service_protocols import (
    external_service_outcomes_v1,
    parse_checked_external_service_protocol_v1,
)
from .machine_callback_boundary import (
    MachineCallbackBoundaryError,
    interface_callback_boundary_catalog_v1,
    machine_callback_boundary_catalog_v1,
)
from .resolved import (
    ExternalEnvironmentError,
    ResolvedExternalEnvironmentV1,
    bind_launch_policy_v1,
)


_SUBJECT = re.compile(
    r"^(?:call|callback|export|component_operation|service):"
    r"[a-z0-9](?:[a-z0-9._-]*[a-z0-9])?$"
)
_PE32_ABIS = frozenset({"pe32-i686-msvc", "pe32-i686-mingw32"})
_PE32_LAYOUTS = frozenset({"pe32-ilp32-v1"})
def _canonical_runtime_support_requirements(
    static_authority_paths: Mapping[str, Path],
) -> tuple[str, ...]:
    transfer_path = static_authority_paths.get("executable_transfer_plan")
    if transfer_path is None:
        raise ExternalEnvironmentError(
            "resolved environment has no canonical executable transfer plan"
        )
    try:
        # Resolution must remain available to an incomplete semantic module so
        # that the linker can report its exact blockers.  The transfer codec
        # still validates the whole artifact; support discovery only inspects
        # the successfully compiled transfer rows that are present.
        _payload, transfers = load_executable_transfer_plan(
            Path(transfer_path), require_complete=False
        )
    except ToolkitInputError as exc:
        raise ExternalEnvironmentError(
            f"cannot derive runtime support from canonical transfer plan: {exc}"
        ) from exc
    requirements = set()
    if any(
        EFFECT_OPERATIONS_V2[action.op].native_exception is not None
        for transfer in transfers
        for action in transfer.actions[:-1]
        if action.op in EFFECT_OPERATIONS_V2
    ):
        requirements.add("exception_escape")
    return tuple(sorted(requirements))


def _load(path: Path, context: str) -> Mapping[str, Any]:
    try:
        value = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ExternalEnvironmentError(f"cannot read {context}: {exc}") from exc
    if not isinstance(value, Mapping):
        raise ExternalEnvironmentError(f"{context} must be a JSON object")
    return value


def _text(value: object, context: str) -> str:
    if not isinstance(value, str) or not value:
        raise ExternalEnvironmentError(f"{context} must be nonempty text")
    return value


def _profile_record(path: Path, *, pack_kind: str) -> dict[str, Any]:
    payload = _load(path, f"{pack_kind} profile pack")
    return {
        "pack_kind": pack_kind,
        "id": _text(payload.get("id"), f"{pack_kind} profile pack ID"),
        "format": _text(
            payload.get("format"), f"{pack_kind} profile pack format"
        ),
        "sha256": sha256_file(path),
        "filename": Path(path).name,
    }


def _bound_record(path: Path, *, record_kind: str, record_id: str) -> dict[str, Any]:
    payload = _load(path, record_kind)
    return {
        "kind": record_kind,
        "id": record_id,
        "format": _text(payload.get("format"), f"{record_kind} format"),
        "sha256": sha256_file(path),
        "filename": Path(path).name,
    }


















def write_external_environment_intent(
    *,
    environment_id: str,
    runtime_profile_packs: Sequence[Path],
    interface_profile_packs: Sequence[Path],
    launch_profile: Path,
    boundary_intents: Mapping[str, Path],
    process_termination: Mapping[str, Any] | None,
    target_abi: str,
    target_data_layout: str,
    out: Path,
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Compile immutable operator intent and its non-authorizing projection."""

    environment_id = _text(environment_id, "external environment ID")
    if target_abi not in _PE32_ABIS:
        raise ExternalEnvironmentError("target ABI selection is unsupported")
    if target_data_layout not in _PE32_LAYOUTS:
        raise ExternalEnvironmentError("target data-layout selection is unsupported")
    if not runtime_profile_packs:
        raise ExternalEnvironmentError("at least one runtime profile pack is required")
    invalid_subjects = sorted(
        subject for subject in boundary_intents if _SUBJECT.fullmatch(subject) is None
    )
    if invalid_subjects:
        raise ExternalEnvironmentError(
            f"boundary intent subjects are not stable kind:id values: {invalid_subjects!r}"
        )
    runtime_rows = [
        _profile_record(Path(path), pack_kind="runtime")
        for path in runtime_profile_packs
    ]
    interface_rows = [
        _profile_record(Path(path), pack_kind="interface")
        for path in interface_profile_packs
    ]
    if len({row["sha256"] for row in runtime_rows}) != len(runtime_rows):
        raise ExternalEnvironmentError("runtime profile packs contain duplicates")
    if len({row["sha256"] for row in interface_rows}) != len(interface_rows):
        raise ExternalEnvironmentError("interface profile packs contain duplicates")
    launch_payload = dict(_load(Path(launch_profile), "launch policy"))
    if launch_payload.get("format") != LAUNCH_ASSUMPTION_TEMPLATE_FORMAT:
        raise ExternalEnvironmentError("launch-policy format is unsupported")
    launch_row = bind_launch_policy_v1(
        launch_payload,
        source_sha256=sha256_file(Path(launch_profile)),
        filename=Path(launch_profile).name,
    )
    boundary_rows = [
        _bound_record(
            Path(path), record_kind="boundary_intent", record_id=subject
        )
        for subject, path in sorted(boundary_intents.items())
    ]
    termination = None
    if process_termination is not None:
        termination = _identity_payload(
            _identity_from_row(
                process_termination, context="process-termination support import"
            )
        )
    payload: dict[str, Any] = {
        "format": EXTERNAL_ENVIRONMENT_INTENT_FORMAT,
        "status": "complete",
        "id": environment_id,
        "profile_packs": {
            "runtime": runtime_rows,
            "interface": interface_rows,
        },
        "launch_policy": launch_row,
        "boundary_intents": boundary_rows,
        "runtime_support_policy": {
            "process_termination": termination,
        },
        "target": {
            "abi": target_abi,
            "data_layout": target_data_layout,
        },
        "authority": "intent_only",
    }
    payload["intent_sha256"] = canonical_sha256_v3(payload)

    blockers: list[dict[str, Any]] = []
    import_rows: list[dict[str, Any]] = []
    try:
        selected = load_machine_import_profile_set(runtime_profile_packs)
        for contract in selected.contracts:
            row = contract.contract
            import_rows.append({
                "identity": _identity_payload(contract.identity),
                "profile_id": contract.profile_id,
                "profile_sha256": contract.profile_sha256,
                "entry_key": contract.entry_key,
                "entry_index": contract.entry_index,
                "control_disposition": {
                    "abi_template": row.get("abi_template"),
                    "arity": row.get("arity"),
                    "callback_protocol": row.get("callback_protocol"),
                    "world_effect": row.get("world_effect"),
                },
            })
    except MachineImportProfileError as exc:
        blockers.append({
            "category": "conflicting_runtime_profile_packs",
            "detail": str(exc),
        })
    projection: dict[str, Any] = {
        "format": EXTERNAL_ENVIRONMENT_ANALYSIS_PROJECTION_FORMAT,
        "status": "complete" if not blockers else "incomplete",
        "environment_intent_sha256": payload["intent_sha256"],
        "authority": "none",
        "imports": sorted(
            import_rows,
            key=lambda row: (
                row["identity"]["dll"],
                row["identity"]["symbol"] or "",
                row["identity"]["ordinal"]
                if row["identity"]["ordinal"] is not None
                else -1,
            ),
        ),
        "blockers": blockers,
    }
    projection["projection_sha256"] = canonical_sha256_v3(projection)
    output = Path(out)
    output.mkdir(parents=True, exist_ok=True)
    write_json(output / "external-environment-intent.json", payload)
    write_json(output / "analysis-projection.json", projection)
    return payload, projection


def _verify_pack_bindings(
    *,
    expected: object,
    paths: Sequence[Path],
    pack_kind: str,
) -> None:
    if not isinstance(expected, list):
        raise ExternalEnvironmentError(f"{pack_kind} pack binding is malformed")
    observed = [
        _profile_record(Path(path), pack_kind=pack_kind) for path in paths
    ]
    expected_keys = sorted(
        (row.get("id"), row.get("format"), row.get("sha256"))
        for row in expected
        if isinstance(row, Mapping)
    )
    observed_keys = sorted(
        (row["id"], row["format"], row["sha256"]) for row in observed
    )
    if len(expected_keys) != len(expected) or expected_keys != observed_keys:
        raise ExternalEnvironmentError(f"{pack_kind} profile-pack binding is stale")


def _boundary_catalog(
    subject: str, package: Path, *,
    machine_imports: Sequence[Mapping[str, Any]],
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    blockers: list[dict[str, Any]] = []
    package = Path(package)
    status_path = package / "call-status.json"
    machine_checked = status_path.is_file()
    if not machine_checked:
        status_path = package / "boundary-status.json"
    if not status_path.is_file():
        return {}, [{
            "category": "boundary_package_status_missing",
            "subject": subject,
        }]
    status = _load(status_path, f"{subject} boundary status")
    if status.get("status") != "complete":
        blockers.append({
            "category": "boundary_protocol_incomplete",
            "subject": subject,
            "observed_status": status.get("status"),
        })
    files: dict[str, Any] = {}
    for name in (
        "boundary-schema.json",
        "target-data-layout.json",
        "physical-call-frame-v3.json",
        "boundary-lifecycle.json",
        "boundary-lifecycle-receipt.json",
        "checked-call-protocol.json",
    ):
        path = package / name
        if path.is_file():
            value = _load(path, f"{subject} {name}")
            files[name.removesuffix(".json").replace("-", "_")] = {
                "sha256": sha256_file(path),
                "payload": value,
            }
    if "boundary_schema" not in files or "target_data_layout" not in files:
        blockers.append({
            "category": "canonical_boundary_catalog_incomplete",
            "subject": subject,
        })
    physical_frames: list[dict[str, Any]] = []
    callback_links: list[dict[str, Any]] = []
    if not machine_checked and not blockers:
        try:
            schema = BoundarySchemaV1.parse(
                files["boundary_schema"]["payload"]
            )
            layout = TargetDataLayoutV1.parse(
                files["target_data_layout"]["payload"], schema=schema
            )
            frame_paths = sorted(package.glob("physical-call-frame-*.json"))
            parsed_frames: dict[str, PhysicalCallFrameV3] = {}
            bindings_by_frame: dict[str, list[dict[str, Any]]] = {}
            if not frame_paths:
                blockers.append({
                    "category": "boundary_machine_binding_unresolved",
                    "subject": subject,
                })
            for path in frame_paths:
                payload = _load(path, f"{subject} {path.name}")
                frame = PhysicalCallFrameV3.parse(
                    payload, schema=schema, layout=layout
                )
                bindings = schema_frame_machine_bindings_v1(
                    frame, machine_imports=machine_imports
                )
                frame_name = path.name.removeprefix(
                    "physical-call-frame-"
                ).removesuffix(".json")
                physical_frames.append({
                    "frame_name": frame_name,
                    "frame_sha256": sha256_file(path),
                    "physical_frame": payload,
                    "machine_bindings": bindings,
                })
                parsed_frames[frame_name] = frame
                bindings_by_frame[frame_name] = bindings
                if not bindings:
                    blockers.append({
                        "category": "boundary_frame_machine_binding_unresolved",
                        "subject": subject,
                        "frame_name": frame_name,
                        "physical_frame_id": frame.frame_id,
                    })
                elif len(bindings) != 1:
                    blockers.append({
                        "category": "boundary_frame_machine_binding_ambiguous",
                        "subject": subject,
                        "frame_name": frame_name,
                        "physical_frame_id": frame.frame_id,
                        "binding_count": len(bindings),
                    })
            callback_links, callback_issues = schema_callback_links_v1(
                schema=schema,
                layout=layout,
                frames=parsed_frames,
                frame_bindings=bindings_by_frame,
                machine_imports=machine_imports,
            )
            blockers.extend({
                "subject": subject,
                **issue,
            } for issue in callback_issues)
        except (ExternalEnvironmentError, ValueError) as exc:
            blockers.append({
                "category": "boundary_frame_machine_binding_malformed",
                "subject": subject,
                "detail": str(exc),
            })
    if machine_checked:
        missing = sorted({
            "physical_call_frame_v3",
            "boundary_lifecycle",
            "boundary_lifecycle_receipt",
            "checked_call_protocol",
        } - set(files))
        if missing:
            blockers.append({
                "category": "checked_boundary_artifacts_incomplete",
                "subject": subject,
                "missing": missing,
            })
    catalog = {
        "subject": subject,
        "kind": "checked_protocol" if machine_checked else "checked_schema",
        "status_sha256": sha256_file(status_path),
        "artifacts": files,
    }
    if not machine_checked:
        catalog["physical_frames"] = physical_frames
        catalog["callback_links"] = callback_links
    return catalog, blockers


def _interface_catalog(paths: Sequence[Path]) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    catalogs: list[dict[str, Any]] = []
    blockers: list[dict[str, Any]] = []
    seen: set[str] = set()
    for path in paths:
        try:
            profile = load_external_interface_profile(path)
        except ExternalInterfaceProfileError as exc:
            blockers.append({
                "category": "interface_profile_unsupported",
                "detail": str(exc),
            })
            continue
        for interface in profile.interfaces:
            if interface.interface_id in seen:
                blockers.append({
                    "category": "duplicate_interface_identity",
                    "interface_id": interface.interface_id,
                })
                continue
            seen.add(interface.interface_id)
            catalogs.append({
                "interface_id": interface.interface_id,
                "profile_id": profile.profile_id,
                "profile_sha256": profile.sha256,
                "vtable": interface.vtable,
                "methods": [
                    method.target_json(
                        profile_id=profile.profile_id,
                        profile_sha256=profile.sha256,
                    )
                    for method in interface.methods
                ],
            })
    return sorted(catalogs, key=lambda row: row["interface_id"]), blockers


def write_resolved_external_environment(
    *,
    intent_path: Path,
    module_interface_path: Path,
    runtime_profile_packs: Sequence[Path],
    interface_profile_packs: Sequence[Path],
    boundary_intent_paths: Mapping[str, Path],
    boundary_packages: Mapping[str, Path],
    static_authority_paths: Mapping[str, Path],
    out: Path,
) -> dict[str, Any]:
    """Resolve intent against exact module and checked static authority."""

    if not static_authority_paths:
        raise ExternalEnvironmentError(
            "resolved external environment requires static authority bindings"
        )
    intent = _load(Path(intent_path), "external-environment intent")
    if (
        intent.get("format") != EXTERNAL_ENVIRONMENT_INTENT_FORMAT
        or intent.get("status") != "complete"
    ):
        raise ExternalEnvironmentError("external-environment intent is incomplete")
    expected_intent_sha = canonical_sha256_v3({
        key: value for key, value in intent.items() if key != "intent_sha256"
    })
    if intent.get("intent_sha256") != expected_intent_sha:
        raise ExternalEnvironmentError("external-environment intent hash is stale")
    packs = intent.get("profile_packs")
    if not isinstance(packs, Mapping):
        raise ExternalEnvironmentError("external-environment profile packs are malformed")
    _verify_pack_bindings(
        expected=packs.get("runtime"),
        paths=runtime_profile_packs,
        pack_kind="runtime",
    )
    _verify_pack_bindings(
        expected=packs.get("interface"),
        paths=interface_profile_packs,
        pack_kind="interface",
    )
    module = _load(Path(module_interface_path), "PE32 module interface")
    blockers: list[dict[str, Any]] = []
    if module.get("format") != "spaghetti-extractor-pe32-module-interface-v2":
        raise ExternalEnvironmentError("module interface format is unsupported")
    expected_interface_sha = canonical_sha256_v3({
        key: value for key, value in module.items() if key != "interface_sha256"
    })
    if module.get("interface_sha256") != expected_interface_sha:
        raise ExternalEnvironmentError("module-interface content hash is stale")
    if module.get("status") != "complete":
        blockers.append({
            "category": "module_interface_incomplete",
            "module_blockers": module.get("blockers", []),
        })
    selected_target = intent.get("target")
    if not isinstance(selected_target, Mapping):
        raise ExternalEnvironmentError("external-environment target is malformed")
    expected_dialect = {
        "pe32-i686-mingw32": "pe32-i386-gnu-v1",
        "pe32-i686-msvc": "pe32-i386-ms-v1",
    }[str(selected_target.get("abi"))]
    try:
        # Interface packs carry the checked physical contracts for their
        # factory imports as ``machine_import_signatures``.  They are not a
        # second contract namespace: ordinary IAT resolution must select from
        # the union of runtime and interface packs so a DirectX-style factory
        # and an ordinary runtime import are lowered through the same checked
        # boundary path.  Duplicate identities across either pack class remain
        # ambiguous and therefore fail closed in the shared loader.
        profiles = load_machine_import_profile_set([
            *runtime_profile_packs,
            *interface_profile_packs,
        ])
        contracts = profiles.by_identity()
    except MachineImportProfileError as exc:
        profiles = None
        contracts = {}
        blockers.append({
            "category": "conflicting_runtime_profile_packs",
            "detail": str(exc),
        })
    semantic_imports: list[dict[str, Any]] = []
    for index, raw in enumerate(module.get("imports", [])):
        if not isinstance(raw, Mapping):
            blockers.append({
                "category": "module_import_identity_malformed",
                "index": index,
            })
            continue
        identity = _identity_from_row(raw, context=f"module import {index}")
        contract = contracts.get(identity)
        row = {
            "import_kind": "ordinary",
            "identity": _identity_payload(identity),
            "descriptor_index": raw.get("descriptor_index"),
            "cell_index": raw.get("cell_index"),
            "iat_rva": raw.get("iat_rva"),
            "contract": None,
            "boundary": None,
        }
        if contract is None:
            blockers.append({
                "category": "reachable_import_contract_unresolved",
                "identity": row["identity"],
                "iat_rva": raw.get("iat_rva"),
            })
        else:
            row["contract"] = {
                "profile_id": contract.profile_id,
                "profile_sha256": contract.profile_sha256,
                "entry_key": contract.entry_key,
                "entry_index": contract.entry_index,
                "payload": contract.contract,
            }
            try:
                row["boundary"] = lower_machine_import_boundary_v1(
                    contract, abi_dialect=expected_dialect
                )
            except (ExternalEnvironmentError, ValueError) as exc:
                blockers.append({
                    "category": "machine_import_boundary_unresolved",
                    "identity": row["identity"],
                    "iat_rva": raw.get("iat_rva"),
                    "detail": str(exc),
                })
        semantic_imports.append(row)
    for descriptor_index, descriptor in enumerate(module.get("delay_imports", [])):
        if not isinstance(descriptor, Mapping):
            blockers.append({
                "category": "module_delay_import_descriptor_malformed",
                "descriptor_index": descriptor_index,
            })
            continue
        cells = descriptor.get("cells")
        if not isinstance(cells, list):
            blockers.append({
                "category": "module_delay_import_descriptor_malformed",
                "descriptor_index": descriptor_index,
            })
            continue
        for cell_index, raw in enumerate(cells):
            if not isinstance(raw, Mapping):
                blockers.append({
                    "category": "module_delay_import_identity_malformed",
                    "descriptor_index": descriptor_index,
                    "cell_index": cell_index,
                })
                continue
            identity = _identity_from_row(
                raw,
                context=(
                    f"module delay import {descriptor_index}:{cell_index}"
                ),
            )
            contract = contracts.get(identity)
            row = {
                "import_kind": "delay",
                "identity": _identity_payload(identity),
                "descriptor_index": raw.get("descriptor_index"),
                "cell_index": raw.get("cell_index"),
                "iat_rva": raw.get("iat_rva"),
                "contract": None,
                "boundary": None,
            }
            if contract is None:
                blockers.append({
                    "category": "reachable_delay_import_contract_unresolved",
                    "identity": row["identity"],
                    "iat_rva": raw.get("iat_rva"),
                })
            else:
                row["contract"] = {
                    "profile_id": contract.profile_id,
                    "profile_sha256": contract.profile_sha256,
                    "entry_key": contract.entry_key,
                    "entry_index": contract.entry_index,
                    "payload": contract.contract,
                }
                try:
                    row["boundary"] = lower_machine_import_boundary_v1(
                        contract, abi_dialect=expected_dialect
                    )
                except (ExternalEnvironmentError, ValueError) as exc:
                    blockers.append({
                        "category": "machine_import_boundary_unresolved",
                        "identity": row["identity"],
                        "iat_rva": raw.get("iat_rva"),
                        "detail": str(exc),
                    })
            semantic_imports.append(row)
    support_policy = intent.get("runtime_support_policy")
    if not isinstance(support_policy, Mapping):
        raise ExternalEnvironmentError("runtime-support policy is malformed")
    support_imports: list[dict[str, Any]] = []

    def append_support_import(
        support: str, identity_row: Mapping[str, Any]
    ) -> None:
        identity = _identity_from_row(
            identity_row, context=f"{support} support import"
        )
        contract = contracts.get(identity)
        if contract is None:
            blockers.append({
                "category": "runtime_support_contract_unresolved",
                "support": support,
                "identity": _identity_payload(identity),
            })
        support_boundary = None
        if contract is not None:
            try:
                support_boundary = lower_machine_import_boundary_v1(
                    contract, abi_dialect=expected_dialect
                )
            except (ExternalEnvironmentError, ValueError) as exc:
                blockers.append({
                    "category": "runtime_support_boundary_unresolved",
                    "support": support,
                    "identity": _identity_payload(identity),
                    "detail": str(exc),
                })
        support_imports.append({
            "support": support,
            "identity": _identity_payload(identity),
            "contract": None if contract is None else {
                "profile_id": contract.profile_id,
                "profile_sha256": contract.profile_sha256,
                "entry_key": contract.entry_key,
                "entry_index": contract.entry_index,
                "payload": contract.contract,
            },
            "boundary": support_boundary,
        })

    termination = support_policy.get("process_termination")
    if termination is not None:
        if not isinstance(termination, Mapping):
            raise ExternalEnvironmentError("process-termination policy is malformed")
        append_support_import("process_termination", termination)
    for requirement in _canonical_runtime_support_requirements(
        static_authority_paths
    ):
        if requirement == "exception_escape":
            append_support_import(
                "exception_escape",
                {"dll": "kernel32.dll", "symbol": "RaiseException"},
            )
        else:  # pragma: no cover - helper returns a closed internal inventory
            raise ExternalEnvironmentError(
                f"canonical runtime support {requirement!r} is unsupported"
            )
    support_imports.sort(key=lambda row: str(row["support"]))
    dynamic_export_catalog: list[dict[str, Any]] = []
    if profiles is not None:
        for contract in profiles.contracts:
            dynamic_export = contract.contract.get("dynamic_export")
            if not isinstance(dynamic_export, Mapping):
                continue
            boundary = None
            if dynamic_export.get("kind") == "code":
                try:
                    boundary = lower_machine_import_boundary_v1(
                        contract, abi_dialect=expected_dialect
                    )
                except (ExternalEnvironmentError, ValueError) as exc:
                    blockers.append({
                        "category": "dynamic_export_boundary_unresolved",
                        "identity": _identity_payload(contract.identity),
                        "detail": str(exc),
                    })
            dynamic_export_catalog.append({
                "import_kind": "dynamic_export",
                "dynamic_export_kind": dynamic_export.get("kind"),
                "identity": _identity_payload(contract.identity),
                "profile_id": contract.profile_id,
                "profile_sha256": contract.profile_sha256,
                "entry_key": contract.entry_key,
                "entry_index": contract.entry_index,
                "contract": {
                    "profile_id": contract.profile_id,
                    "profile_sha256": contract.profile_sha256,
                    "entry_key": contract.entry_key,
                    "entry_index": contract.entry_index,
                    "payload": contract.contract,
                },
                "boundary": boundary,
            })
    intended_rows = {
        str(row.get("id")): row
        for row in intent.get("boundary_intents", [])
        if isinstance(row, Mapping) and isinstance(row.get("id"), str)
    }
    intended_subjects = set(intended_rows)
    if set(boundary_intent_paths) != intended_subjects:
        blockers.append({
            "category": "boundary_intent_identity_mismatch",
            "expected": sorted(intended_subjects),
            "observed": sorted(boundary_intent_paths),
        })
    for subject, path in sorted(boundary_intent_paths.items()):
        expected = intended_rows.get(subject)
        if expected is not None and expected.get("sha256") != sha256_file(path):
            blockers.append({
                "category": "boundary_intent_binding_stale",
                "subject": subject,
            })
    if set(boundary_packages) != intended_subjects:
        blockers.append({
            "category": "boundary_package_identity_mismatch",
            "expected": sorted(str(value) for value in intended_subjects),
            "observed": sorted(boundary_packages),
        })
    boundary_catalogs: list[dict[str, Any]] = []
    for subject, package in sorted(boundary_packages.items()):
        catalog, catalog_blockers = _boundary_catalog(
            subject, package, machine_imports=semantic_imports
        )
        if catalog:
            boundary_catalogs.append(catalog)
        blockers.extend(catalog_blockers)
    boundary_catalogs.extend(_machine_boundary_catalogs([
        *semantic_imports, *support_imports, *dynamic_export_catalog,
    ]))
    module_export_catalogs, module_export_blockers = (
        _module_export_boundary_catalogs(
            module=module,
            contracts=contracts,
            abi_dialect=expected_dialect,
        )
    )
    boundary_catalogs.extend(module_export_catalogs)
    blockers.extend(module_export_blockers)
    boundary_catalogs.extend(_machine_callback_catalogs(
        [*semantic_imports, *support_imports],
        abi_dialect=expected_dialect,
        authored_subjects={
            "callback:" + str(
                row.get("artifacts", {})
                .get("physical_call_frame_v3", {})
                .get("payload", {})
                .get("transport", {})
                .get("subject", {})
                .get("id")
            )
            for row in boundary_catalogs
            if row.get("kind") == "checked_protocol"
            and isinstance(
                row.get("artifacts", {})
                .get("physical_call_frame_v3", {})
                .get("payload", {})
                .get("transport", {})
                .get("subject", {})
                .get("id"),
                str,
            )
            and row.get("artifacts", {})
            .get("physical_call_frame_v3", {})
            .get("payload", {})
            .get("transport", {})
            .get("subject", {})
            .get("kind") == "callback"
        },
    ))
    interfaces, interface_blockers = _interface_catalog(
        interface_profile_packs
    )
    blockers.extend(interface_blockers)
    boundary_catalogs.extend(_interface_callback_catalogs(
        interfaces, abi_dialect=expected_dialect
    ))
    boundary_catalogs.sort(key=lambda row: row["subject"])
    schema_ids: dict[str, str] = {}
    for catalog in boundary_catalogs:
        artifacts = catalog["artifacts"]
        schema_binding = artifacts.get("boundary_schema")
        layout_binding = artifacts.get("target_data_layout")
        if not isinstance(schema_binding, Mapping) or not isinstance(
            layout_binding, Mapping
        ):
            continue
        schema = schema_binding.get("payload")
        layout = layout_binding.get("payload")
        if not isinstance(schema, Mapping) or not isinstance(layout, Mapping):
            continue
        schema_id = schema.get("schema_id")
        schema_sha = schema.get("schema_sha256")
        if isinstance(schema_id, str) and isinstance(schema_sha, str):
            previous = schema_ids.setdefault(schema_id, schema_sha)
            if previous != schema_sha:
                blockers.append({
                    "category": "conflicting_boundary_schema_identity",
                    "schema_id": schema_id,
                })
        if (
            selected_target.get("data_layout") == "pe32-ilp32-v1"
            and (
                layout.get("pointer_width_bits") != 32
                or layout.get("byte_order") != "little"
            )
        ):
            blockers.append({
                "category": "boundary_data_layout_disagreement",
                "subject": catalog["subject"],
            })
        if layout.get("abi_dialect") != expected_dialect:
            blockers.append({
                "category": "boundary_abi_disagreement",
                "subject": catalog["subject"],
                "expected": expected_dialect,
                "observed": layout.get("abi_dialect"),
            })
    authority_bindings: list[dict[str, Any]] = []
    for name, path in sorted(static_authority_paths.items()):
        authority_path = Path(path)
        if authority_path.is_dir():
            authority_path = authority_path / "manifest.json"
        value = _load(authority_path, f"static authority {name}")
        authority_bindings.append({
            "name": name,
            "format": value.get("format"),
            "status": value.get("status"),
            "sha256": sha256_file(authority_path),
        })
        if value.get("status") not in {"complete", "qualified"}:
            blockers.append({
                "category": "static_authority_incomplete",
                "authority": name,
                "observed_status": value.get("status"),
            })
    module_identity = module.get("identity")
    if not isinstance(module_identity, Mapping):
        raise ExternalEnvironmentError("module-interface identity is malformed")
    loader_service_contracts = []
    for row in semantic_imports:
        contract = row.get("contract")
        contract_payload = (
            contract.get("payload") if isinstance(contract, Mapping) else None
        )
        loader_service = (
            contract_payload.get("loader_service")
            if isinstance(contract_payload, Mapping) else None
        )
        if not isinstance(loader_service, Mapping):
            continue
        loader_row = dict(row)
        if loader_service.get("kind") == "dynamic_export_resolution":
            loader_row["resolution_catalog"] = dynamic_export_catalog
        loader_service_contracts.append(loader_row)
    payload: dict[str, Any] = {
        "format": RESOLVED_EXTERNAL_ENVIRONMENT_FORMAT,
        "status": "complete" if not blockers else "incomplete",
        "bindings": {
            "module_interface_sha256": module.get("interface_sha256"),
            "module_pe_sha256": module_identity.get("pe_sha256"),
            "environment_intent_sha256": intent["intent_sha256"],
            "runtime_profile_pack_sha256s": sorted(
                row["sha256"] for row in packs["runtime"]
            ),
            "interface_profile_pack_sha256s": sorted(
                row["sha256"] for row in packs["interface"]
            ),
        },
        "target": intent["target"],
        "launch_policy": intent["launch_policy"],
        "canonical_boundaries": boundary_catalogs,
        "interface_method_catalogs": interfaces,
        "machine_import_contracts": semantic_imports,
        "original_semantic_imports": semantic_imports,
        "generated_runtime_support_imports": support_imports,
        "loader_service_contracts": loader_service_contracts,
        "static_authority_bindings": authority_bindings,
        "checked_exception_protocols": [],
        "blockers": blockers,
        "authority": "checked_static_environment" if not blockers else "none",
    }
    payload["resolved_environment_sha256"] = canonical_sha256_v3(payload)
    ResolvedExternalEnvironmentV1.parse(payload, module_interface=module)
    output = Path(out)
    output.mkdir(parents=True, exist_ok=True)
    write_json(output / "resolved-external-environment.json", payload)
    return payload


__all__ = [
    "ExternalEnvironmentError",
    "ResolvedExternalEnvironmentV1",
    "write_external_environment_intent",
    "write_resolved_external_environment",
]
