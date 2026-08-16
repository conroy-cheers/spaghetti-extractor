"""Package and authority validation for interpreter-native builds."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any, Mapping

from ..components.region_replacement import REGION_OVERRIDE_TABLE_FORMAT
from ..util import sha256_file
from . import native_build
from .authority import (
    SPX_CANDIDATE_AUTHORITY_V3_FORMAT,
    CandidateAuthorityV3Error,
    CandidateAuthorityV3Receipt,
    validate_candidate_authority,
)
from .build_model import (
    CandidateNativeBuildError,
    _Artifact,
    _C_IDENTIFIER,
    _Package,
)
from .build_values import (
    _artifact,
    _file,
    _read_json_object,
)
from .runtime import plan_spx_native_runtime
from .policy_gates import (
    CandidatePolicyError,
    STRUCTURAL_EXECUTABLE_V1,
    load_policy_receipt,
)


def _validate_candidate_authority_v3(
    *,
    receipt: Path | str,
    final_authority: Path | str,
    machine_ir: Path | str,
    machine_ir_manifest: Path | str,
    fallback_coverage_receipt: Path | str,
    component_runtime_package: Path | str,
) -> CandidateAuthorityV3Receipt:
    try:
        return validate_candidate_authority(
            receipt=receipt,
            final_authority=final_authority,
            machine_ir=machine_ir,
            machine_ir_manifest=machine_ir_manifest,
            fallback_coverage_receipt=fallback_coverage_receipt,
            component_runtime_package=component_runtime_package,
            require_authorized=True,
        )
    except CandidateAuthorityV3Error as exc:
        raise CandidateNativeBuildError(str(exc)) from exc


def _validate_structural_execution_v1(
    *,
    receipt: Path | str,
    machine_ir: Path | str,
    machine_ir_manifest: Path | str,
) -> dict[str, Any]:
    """Recheck the execution policy and its exact machine-input bindings."""

    try:
        parsed = load_policy_receipt(receipt)
    except CandidatePolicyError as exc:
        raise CandidateNativeBuildError(str(exc)) from exc
    if (
        parsed.format != STRUCTURAL_EXECUTABLE_V1
        or parsed.status != "complete"
        or not parsed.executable
        or parsed.release_accepted
    ):
        raise CandidateNativeBuildError(
            "candidate construction requires a complete structural-executable receipt"
        )
    machine_path = _file(machine_ir, "machine IR")
    manifest_path = _file(machine_ir_manifest, "machine-IR manifest")
    expected = {
        "machine_ir_sha256": sha256_file(machine_path),
        "machine_ir_manifest_sha256": sha256_file(manifest_path),
    }
    for name, digest in expected.items():
        if parsed.bindings.get(name) != digest:
            raise CandidateNativeBuildError(
                f"structural-executable receipt binds a different {name}"
            )
    receipt_path = _file(receipt, "structural-executable receipt")
    return {
        "format": parsed.format,
        "artifact_sha256": sha256_file(receipt_path),
        "receipt_sha256": parsed.receipt_sha256,
        "status": parsed.status,
        "executable": parsed.executable,
        "release_accepted": parsed.release_accepted,
        "bindings": dict(parsed.bindings),
    }


def _validate_candidate_authority_package_bindings(
    receipt: CandidateAuthorityV3Receipt,
    interpreter: _Package,
    engine: _Package,
) -> None:
    machine_ir_sha256 = _candidate_input_sha256(receipt, "machine_ir")
    machine_ir_manifest_sha256 = _candidate_input_sha256(
        receipt, "machine_ir_manifest"
    )
    for package in (interpreter, engine):
        if package.payload.get("input_mode") != "sanitized_machine_ir_v2":
            raise CandidateNativeBuildError(
                f"{package.owner} package is not derived from strict machine IR"
            )
        machine_ir = package.payload.get("machine_ir")
        if (
            not isinstance(machine_ir, Mapping)
            or machine_ir.get("sha256") != machine_ir_sha256
        ):
            raise CandidateNativeBuildError(
                f"{package.owner} package binds a different machine IR than "
                "the v3 candidate-authority receipt"
            )
        if package.payload.get("execution_policy") != "complete_transfer_inventory_v1":
            raise CandidateNativeBuildError(
                f"{package.owner} package does not require complete transfer coverage"
            )
        semantic_coverage = package.payload.get("semantic_coverage")
        if (
            not isinstance(semantic_coverage, Mapping)
            or semantic_coverage.get("status") != "complete"
            or semantic_coverage.get("acceptance_authority") is not False
        ):
            raise CandidateNativeBuildError(
                f"{package.owner} package has incomplete semantic coverage"
            )
    manifest = engine.payload.get("machine_ir_manifest")
    if (
        not isinstance(manifest, Mapping)
        or manifest.get("sha256") != machine_ir_manifest_sha256
    ):
        raise CandidateNativeBuildError(
            "native_engine package binds a different machine-IR manifest than "
            "the v3 candidate-authority receipt"
        )


def _validate_structural_candidate_package_bindings(
    *,
    machine_ir: Path | str,
    machine_ir_manifest: Path | str,
    interpreter: _Package,
    engine: _Package,
    runtime: _Package,
    runtime_plan: Any,
) -> dict[str, Any]:
    """Bind executable scope without granting behavioral acceptance authority."""

    machine_ir_path = _file(machine_ir, "machine IR")
    manifest_path = _file(machine_ir_manifest, "machine-IR manifest")
    machine_ir_sha256 = sha256_file(machine_ir_path)
    manifest_sha256 = sha256_file(manifest_path)
    for package in (interpreter, engine):
        if package.payload.get("input_mode") != "sanitized_machine_ir_v2":
            raise CandidateNativeBuildError(
                f"{package.owner} package is not derived from strict machine IR"
            )
        binding = package.payload.get("machine_ir")
        if (
            not isinstance(binding, Mapping)
            or binding.get("sha256") != machine_ir_sha256
        ):
            raise CandidateNativeBuildError(
                f"{package.owner} package binds a different machine IR"
            )

    engine_manifest = engine.payload.get("machine_ir_manifest")
    if (
        not isinstance(engine_manifest, Mapping)
        or engine_manifest.get("sha256") != manifest_sha256
    ):
        raise CandidateNativeBuildError(
            "native_engine package binds a different machine-IR manifest"
        )
    engine_policy = engine.payload.get("policy")
    runtime_policy = runtime.payload.get("policy")
    runtime_inputs = runtime.payload.get("inputs")
    if (
        not isinstance(engine_policy, Mapping)
        or not isinstance(runtime_policy, Mapping)
        or not isinstance(runtime_inputs, Mapping)
        or engine_policy.get("execution_scope") != "structural-executable-v1"
        or runtime_policy.get("execution_scope") != "structural-executable-v1"
    ):
        raise CandidateNativeBuildError(
            "native package closure does not require structural executability"
        )

    interpreter_coverage = interpreter.payload.get("semantic_coverage")
    engine_coverage = engine.payload.get("semantic_coverage")
    if not isinstance(interpreter_coverage, Mapping) or not isinstance(
        engine_coverage, Mapping
    ):
        raise CandidateNativeBuildError(
            "candidate package closure omits semantic coverage"
        )
    dispatch = engine.payload.get("implementation_dispatch_receipt")
    if not isinstance(dispatch, Mapping):
        raise CandidateNativeBuildError(
            "native_engine package omits its implementation-dispatch receipt"
        )
    dispatch_policy = dispatch.get("policy")
    reachability = dispatch.get("reachability")
    if (
        not isinstance(dispatch_policy, Mapping)
        or not isinstance(reachability, Mapping)
        or dispatch_policy.get("acceptance_authority") is not False
        or dispatch.get("blockers") != []
    ):
        raise CandidateNativeBuildError(
            "implementation-dispatch receipt is not a complete static binding"
        )
    if (
        interpreter_coverage.get("status") != "complete"
        or interpreter_coverage.get("acceptance_authority") is not False
        or engine_coverage.get("status") != "complete"
        or engine_coverage.get("acceptance_authority") is not False
        or dispatch.get("status") != "complete"
        or reachability.get("status") != "complete"
    ):
        raise CandidateNativeBuildError(
            "candidate package closure retains incomplete execution scope"
        )

    core = {
        "format": "spaghetti-extractor-structural-candidate-binding-v1",
        "execution_scope": "structural-executable-v1",
        "acceptance_authority": "none",
        "machine_ir_sha256": machine_ir_sha256,
        "machine_ir_manifest_sha256": manifest_sha256,
        "interpreter_package_sha256": interpreter.manifest_sha256,
        "native_engine_package_sha256": engine.manifest_sha256,
        "native_runtime_package_sha256": runtime.manifest_sha256,
        "dispatch_receipt_sha256": dispatch.get("receipt_sha256"),
        "reachability_status": reachability.get("status"),
        "runtime_unknown_target_disposition": "fail-closed-as-unimplemented",
    }
    return {**core, "binding_sha256": native_build._canonical_sha256(core)}


def _candidate_input_sha256(
    receipt: CandidateAuthorityV3Receipt, name: str
) -> str:
    binding = receipt.inputs.get(name)
    if name == "fallback_coverage_receipt":
        field = "artifact_sha256"
    else:
        field = "sha256"
    value = binding.get(field) if isinstance(binding, Mapping) else None
    if not isinstance(value, str) or re.fullmatch(r"[0-9a-f]{64}", value) is None:
        raise CandidateNativeBuildError(
            f"v3 candidate-authority receipt has no exact {name} binding"
        )
    return value


def _candidate_manifest_pe_sha256(manifest_path: Path | str) -> str:
    manifest = _read_json_object(
        _file(manifest_path, "machine-IR manifest"), "machine-IR manifest"
    )
    authority = manifest.get("authority_bindings")
    binary = authority.get("binary") if isinstance(authority, Mapping) else None
    value = binary.get("pe_sha256") if isinstance(binary, Mapping) else None
    if not isinstance(value, str) or re.fullmatch(r"[0-9a-f]{64}", value) is None:
        raise CandidateNativeBuildError(
            "machine-IR manifest has no exact PE binding"
        )
    return value


def _candidate_authority_manifest_binding(
    receipt_path: Path | str, receipt: CandidateAuthorityV3Receipt
) -> dict[str, Any]:
    path = _file(receipt_path, "v3 candidate-authority receipt")
    return {
        "format": SPX_CANDIDATE_AUTHORITY_V3_FORMAT,
        "artifact_sha256": sha256_file(path),
        "content_id": receipt.content_id,
        "status": receipt.status.value,
        "authorizes": receipt.authorizes,
        "machine_ir_sha256": _candidate_input_sha256(receipt, "machine_ir"),
        "machine_ir_manifest_sha256": _candidate_input_sha256(
            receipt, "machine_ir_manifest"
        ),
        "fallback_coverage_receipt_sha256": _candidate_input_sha256(
            receipt, "fallback_coverage_receipt"
        ),
    }


def _load_package(
    value: Path | str,
    *,
    filename: str,
    owner: str,
    expected_format: str,
    require_roles: bool,
) -> _Package:
    manifest_path = Path(value)
    if manifest_path.is_dir():
        manifest_path = manifest_path / filename
    manifest_path = _file(manifest_path, f"{owner} package manifest")
    root = manifest_path.parent
    payload = _read_json_object(manifest_path, f"{owner} package manifest")
    if payload.get("format") != expected_format:
        raise CandidateNativeBuildError(
            f"{owner} package has an unsupported format"
        )
    if payload.get("status") != "ready":
        raise CandidateNativeBuildError(f"{owner} package is not ready")
    blockers = payload.get("blockers", [] if owner == "native_runtime" else None)
    if not isinstance(blockers, list) or blockers:
        raise CandidateNativeBuildError(
            f"{owner} package has malformed or nonempty blockers"
        )
    sources = payload.get("sources")
    if not isinstance(sources, list) or not sources:
        raise CandidateNativeBuildError(
            f"{owner} package has no source inventory"
        )
    artifacts: list[_Artifact] = []
    seen_paths: set[str] = set()
    seen_roles: set[str] = set()
    for index, raw in enumerate(sources):
        if not isinstance(raw, Mapping):
            raise CandidateNativeBuildError(
                f"{owner} source {index} is not an object"
            )
        role_value = raw.get("role")
        if require_roles:
            if not isinstance(role_value, str) or not role_value:
                raise CandidateNativeBuildError(
                    f"{owner} source {index} has no role"
                )
            role = role_value
        else:
            role = role_value if isinstance(role_value, str) else f"source_{index:03d}"
        artifact = _artifact(root, owner, role, raw)
        if artifact.relative_path in seen_paths or role in seen_roles:
            raise CandidateNativeBuildError(
                f"{owner} source inventory has duplicate paths or roles"
            )
        seen_paths.add(artifact.relative_path)
        seen_roles.add(role)
        artifacts.append(artifact)
    extra_bindings = (
        (("program", payload.get("program")),)
        if owner == "interpreter"
        else (("plan", payload.get("plan")),)
        if owner == "native_engine"
        else ()
    )
    for role, raw in extra_bindings:
        if not isinstance(raw, Mapping):
            raise CandidateNativeBuildError(
                f"{owner} package has no {role} binding"
            )
        artifact = _artifact(root, owner, role, raw)
        if artifact.relative_path in seen_paths or role in seen_roles:
            raise CandidateNativeBuildError(
                f"{owner} artifact inventory has duplicate paths or roles"
            )
        seen_paths.add(artifact.relative_path)
        seen_roles.add(role)
        artifacts.append(artifact)
    return _Package(
        owner=owner,
        root=root,
        manifest_path=manifest_path,
        manifest_sha256=sha256_file(manifest_path),
        payload=payload,
        artifacts=tuple(artifacts),
    )


def _load_region_override_package(value: Path | str) -> _Package:
    manifest_path = Path(value)
    if manifest_path.is_dir():
        manifest_path = manifest_path / "region-overrides-manifest.json"
    manifest_path = _file(manifest_path, "region override package manifest")
    root = manifest_path.parent
    payload = _read_json_object(manifest_path, "region override package manifest")
    if payload.get("format") != REGION_OVERRIDE_TABLE_FORMAT:
        raise CandidateNativeBuildError(
            "region override package has an unsupported format"
        )
    if payload.get("status") != "ready":
        raise CandidateNativeBuildError(
            "region override package is not ready"
        )
    if payload.get("executes_original_binary") is not False:
        raise CandidateNativeBuildError(
            "region override package does not enforce zero original execution"
        )
    checks = payload.get("checks")
    if not isinstance(checks, Mapping) or not checks or any(
        value != "verified" for value in checks.values()
    ):
        raise CandidateNativeBuildError(
            "region override package checks are incomplete"
        )
    entries = payload.get("entries")
    if not isinstance(entries, list) or not entries:
        raise CandidateNativeBuildError(
            "region override package has no entries"
        )
    artifacts_raw = payload.get("artifacts")
    if not isinstance(artifacts_raw, Mapping) or set(artifacts_raw) != {
        "header", "source"
    }:
        raise CandidateNativeBuildError(
            "region override package artifact inventory is malformed"
        )
    artifacts = [
        _artifact(root, "region_overrides", f"table_{role}", artifacts_raw[role])
        for role in ("header", "source")
    ]
    seen_artifacts = {item.relative_path: item.sha256 for item in artifacts}

    def add_once(artifact: _Artifact) -> None:
        observed = seen_artifacts.get(artifact.relative_path)
        if observed is not None:
            if observed != artifact.sha256:
                raise CandidateNativeBuildError(
                    "region override package binds one path to different content"
                )
            return
        seen_artifacts[artifact.relative_path] = artifact.sha256
        artifacts.append(artifact)
    seen_symbols: set[str] = set()
    for index, entry in enumerate(entries):
        if not isinstance(entry, Mapping):
            raise CandidateNativeBuildError(
                f"region override entry {index} is not an object"
            )
        source = entry.get("source")
        if not isinstance(source, Mapping):
            raise CandidateNativeBuildError(
                f"region override entry {index} has no source binding"
            )
        symbol = source.get("symbol")
        if not isinstance(symbol, str) or _C_IDENTIFIER.fullmatch(symbol) is None:
            raise CandidateNativeBuildError(
                f"region override entry {index} source symbol is malformed"
            )
        if symbol in seen_symbols:
            raise CandidateNativeBuildError(
                "region override package has duplicate source symbols"
            )
        seen_symbols.add(symbol)
        artifact = _artifact(
            root,
            "region_overrides",
            f"replacement_source_{index:03d}",
            source,
        )
        add_once(artifact)
        support_sources = entry.get("support_sources", [])
        if not isinstance(support_sources, list):
            raise CandidateNativeBuildError(
                f"region override entry {index} support sources are malformed"
            )
        for support_index, support in enumerate(support_sources):
            if not isinstance(support, Mapping):
                raise CandidateNativeBuildError(
                    f"region override entry {index} support source {support_index} "
                    "is not an object"
                )
            support_artifact = _artifact(
                root,
                "region_overrides",
                f"replacement_support_{index:03d}_{support_index:03d}",
                support,
            )
            add_once(support_artifact)
    return _Package(
        owner="region_overrides",
        root=root,
        manifest_path=manifest_path,
        manifest_sha256=sha256_file(manifest_path),
        payload=payload,
        artifacts=tuple(artifacts),
    )


def _validate_region_override_closure(
    interpreter: _Package, region_overrides: _Package
) -> None:
    machine_ir = interpreter.payload.get("machine_ir")
    if not isinstance(machine_ir, Mapping):
        raise CandidateNativeBuildError(
            "region overrides require a machine-IR interpreter package"
        )
    machine_ir_sha256 = native_build._digest(
        machine_ir.get("sha256"), "interpreter machine-IR SHA-256"
    )
    program = next(
        (item for item in interpreter.artifacts if item.role == "program"), None
    )
    if program is None:
        raise CandidateNativeBuildError(
            "interpreter package has no baseline program artifact"
        )
    if (
        region_overrides.payload.get("machine_ir_sha256") != machine_ir_sha256
        or region_overrides.payload.get("baseline_program_sha256")
        != program.sha256
    ):
        raise CandidateNativeBuildError(
            "region override package binds a different machine IR or baseline program"
        )


def _validate_package_closure(
    interpreter: _Package, engine: _Package, runtime: _Package
) -> Any:
    runtime_inputs = runtime.payload.get("inputs")
    if not isinstance(runtime_inputs, Mapping):
        raise CandidateNativeBuildError(
            "native-runtime package has malformed inputs"
        )
    external_binding = runtime_inputs.get("external_range_contracts")
    if not isinstance(external_binding, Mapping):
        raise CandidateNativeBuildError(
            "native-runtime package has no external-range contract binding"
        )
    profile_binding = external_binding.get("profile")
    profile_artifacts = [
        artifact for artifact in runtime.artifacts
        if artifact.role == "external_profile"
    ]
    external_profile: Path | None = None
    if profile_binding is None:
        if profile_artifacts:
            raise CandidateNativeBuildError(
                "native-runtime package has an unbound external profile"
            )
    else:
        if not isinstance(profile_binding, Mapping) or len(profile_artifacts) != 1:
            raise CandidateNativeBuildError(
                "native-runtime external profile binding is incomplete"
            )
        profile_artifact = profile_artifacts[0]
        if (
            profile_binding.get("path") != profile_artifact.relative_path
            or profile_binding.get("sha256") != profile_artifact.sha256
        ):
            raise CandidateNativeBuildError(
                "native-runtime external profile binding differs from its artifact"
            )
        external_profile = profile_artifact.path
    try:
        plan = plan_spx_native_runtime(
            interpreter_package=interpreter.root,
            native_engine_package=engine.root,
            external_profile=external_profile,
        )
    except Exception as exc:
        raise CandidateNativeBuildError(
            f"interpreter/native-engine closure is incomplete: {exc}"
        ) from exc

    program_ref = interpreter.payload.get("program")
    if not isinstance(program_ref, Mapping):
        raise CandidateNativeBuildError(
            "interpreter package has no program binding"
        )
    program = _artifact(interpreter.root, "interpreter", "program", program_ref)
    program_payload = _read_json_object(program.path, "interpreter program manifest")
    if program_payload.get("status") != "ready" or program_payload.get("blockers") != []:
        raise CandidateNativeBuildError("interpreter program is incomplete")
    counts = program_payload.get("counts")
    if not isinstance(counts, Mapping):
        raise CandidateNativeBuildError("interpreter program counts are malformed")
    transfer_count = len(plan.transfer_rvas)
    if (
        counts.get("input_transfers") != transfer_count
        or counts.get("transfers") != transfer_count
        or counts.get("blocked_transfers") != 0
    ):
        raise CandidateNativeBuildError(
            "interpreter program transfer coverage is incomplete"
        )
    coverage = program_payload.get("semantic_coverage")
    execution_policy = program_payload.get("execution_policy")
    if (
        not isinstance(coverage, Mapping)
        or coverage.get("status") != "complete"
        or coverage.get("acceptance_authority") is not False
        or execution_policy != "complete_transfer_inventory_v1"
    ):
        raise CandidateNativeBuildError(
            "interpreter complete-transfer policy is malformed"
        )

    if runtime.payload.get("acceptance_authority") is not False:
        raise CandidateNativeBuildError(
            "native-runtime package has unexpected acceptance authority"
        )
    if runtime.payload.get("inputs") != plan.payload():
        raise CandidateNativeBuildError(
            "native-runtime package does not bind the exact interpreter/engine closure"
        )
    runtime_counts = runtime.payload.get("counts")
    if (
        not isinstance(runtime_counts, Mapping)
        or runtime_counts.get("transfers") != transfer_count
    ):
        raise CandidateNativeBuildError(
            "native-runtime transfer count differs from the interpreter"
        )
    return plan
