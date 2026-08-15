"""Public candidate reconstruction native runtime generation API."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from ..artifacts.formats import (
    NATIVE_ENGINE_PACKAGE_FORMAT,
    NATIVE_RUNTIME_PACKAGE_FORMAT,
    SPX_INTERPRETER_PACKAGE_FORMAT,
)
from ..external.machine_import_profiles import (
    MachineImportProfileError,
    load_machine_import_profile_set,
)
from ..util import sha256_file, write_json
from .runtime_model import (
    DEFINEDNESS_USE_FORMAT,
    NATIVE_RUNTIME_BINDINGS_FILENAME,
    NATIVE_RUNTIME_EXTERNAL_PROFILE_FILENAME,
    NATIVE_RUNTIME_HEADER_FILENAME,
    NATIVE_RUNTIME_MANIFEST_FILENAME,
    NATIVE_RUNTIME_SOURCE_FILENAME,
    NativeRuntimePlan,
    NativeUndefinedPolicy,
    CandidateRuntimeError,
    _INTERPRETER_MANIFEST_FILENAME,
    _NATIVE_ENGINE_MANIFEST_FILENAME,
)
from .runtime_plan_validation import (
    _external_range_rules,
    _validate_native_plan,
    _validate_native_termination,
)
from .runtime_program_validation import (
    _semantic_input_binding,
    _validate_complete_semantic_coverage,
    _validate_program_manifest,
    _validate_typed_x87_operations,
)
from .runtime_render import (
    _native_runtime_bindings_source,
    _native_runtime_header,
    _native_runtime_source,
)
from .runtime_values import (
    _bound_artifact,
    _manifest_path,
    _read_json_object,
    _required_list,
    _required_object,
    _required_sha256,
    _verify_artifact_inventory,
)


def plan_spx_native_runtime(
    *,
    interpreter_package: Path | str,
    native_engine_package: Path | str,
    external_profile: Path | str | None = None,
) -> NativeRuntimePlan:
    """Validate and bind exact interpreter and native-engine packages."""

    interpreter_manifest_path = _manifest_path(
        interpreter_package,
        _INTERPRETER_MANIFEST_FILENAME,
        "interpreter package",
    )
    native_manifest_path = _manifest_path(
        native_engine_package,
        _NATIVE_ENGINE_MANIFEST_FILENAME,
        "native-engine package",
    )
    interpreter = _read_json_object(
        interpreter_manifest_path, "interpreter package manifest"
    )
    native = _read_json_object(native_manifest_path, "native-engine package manifest")

    if interpreter.get("format") != SPX_INTERPRETER_PACKAGE_FORMAT:
        raise CandidateRuntimeError(
            "interpreter package has an unsupported format"
        )
    if interpreter.get("status") != "ready":
        raise CandidateRuntimeError("interpreter package is not ready")
    input_mode, interpreter_state = _semantic_input_binding(
        interpreter, "interpreter package"
    )
    state_machine_sha256 = _required_sha256(
        interpreter_state.get("sha256"), "interpreter semantic-input SHA-256"
    )
    interpreter_sources = _verify_artifact_inventory(
        interpreter_manifest_path.parent,
        interpreter.get("sources"),
        "interpreter source",
        require_role=True,
    )
    runtime_header_path = interpreter_sources.get("runtime_header")
    if runtime_header_path is None:
        raise CandidateRuntimeError(
            "interpreter source inventory has no runtime_header role"
        )
    try:
        runtime_header = runtime_header_path.read_text(encoding="ascii")
    except (OSError, UnicodeError) as exc:
        raise CandidateRuntimeError(
            "cannot read the bound interpreter runtime header"
        ) from exc
    interpreter_has_typed_x87_abi = "execute_typed_x87_operation" in runtime_header
    program_ref = _required_object(interpreter.get("program"), "interpreter program")
    program_path = _bound_artifact(
        interpreter_manifest_path.parent, program_ref, "interpreter program"
    )
    program = _read_json_object(program_path, "interpreter program manifest")
    (
        transfer_rvas,
        transfer_bindings,
        undefined_policies,
        definedness_metadata_sha256,
    ) = (
        _validate_program_manifest(program, state_machine_sha256)
    )

    if native.get("format") != NATIVE_ENGINE_PACKAGE_FORMAT:
        raise CandidateRuntimeError(
            "native-engine package has an unsupported format"
        )
    if native.get("status") != "ready":
        raise CandidateRuntimeError("native-engine package is not ready")
    native_input_mode, native_input = _semantic_input_binding(
        native, "native-engine package"
    )
    if (
        native_input_mode != input_mode
        or _required_sha256(
            native_input.get("sha256"), "native-engine semantic-input SHA-256"
        ) != state_machine_sha256
    ):
        raise CandidateRuntimeError(
            "interpreter and native-engine packages bind different semantic inputs"
        )
    _verify_artifact_inventory(
        native_manifest_path.parent,
        native.get("sources"),
        "native-engine source",
        require_role=False,
    )
    plan_ref = _required_object(native.get("plan"), "native-engine plan")
    native_plan_path = _bound_artifact(
        native_manifest_path.parent, plan_ref, "native-engine plan"
    )
    native_plan = _read_json_object(native_plan_path, "native-engine plan")
    native_policy = _required_object(native.get("policy"), "native-engine policy")
    if native_policy.get("execution_scope") != "complete-static-authority":
        raise CandidateRuntimeError(
            "native-engine package does not require complete static authority"
        )
    if native.get("callback_adapter_receipts") != native_plan.get(
        "callback_adapter_receipts"
    ):
        raise CandidateRuntimeError(
            "native-engine manifest and plan bind different callback adapter receipts"
        )
    if native.get("implementation_dispatch_receipt") != native_plan.get(
        "implementation_dispatch_receipt"
    ):
        raise CandidateRuntimeError(
            "native-engine manifest and plan bind different implementation dispatch receipts"
        )
    _validate_complete_semantic_coverage(
        native_plan, label="native-engine plan"
    )
    operations = _required_list(
        native_plan.get("x87_operations"), "native-engine typed x87 operations"
    )
    _validate_typed_x87_operations(operations)
    x87_handler_mode = "typed" if operations else "none"
    if x87_handler_mode == "typed" and not interpreter_has_typed_x87_abi:
        raise CandidateRuntimeError(
            "native-engine typed x87 operations require the interpreter typed ABI"
        )
    (
        entry_rva,
        callback_abis,
        callback_adapter_receipts,
        implementation_dispatch_receipt,
        implementation_dispatches,
        recovered_executable_data_ranges,
    ) = _validate_native_plan(
        native_plan,
        state_machine_sha256=state_machine_sha256,
        input_mode=input_mode,
        transfer_rvas=transfer_rvas,
        transfer_bindings=transfer_bindings,
    )
    has_modeled_termination = _validate_native_termination(
        native_plan.get("termination_import")
    )
    external_profile_path = (
        None if external_profile is None else Path(external_profile).resolve()
    )
    if external_profile_path is None:
        external_profile_graph: tuple[tuple[Path, str, str], ...] = ()
    else:
        try:
            profile_set = load_machine_import_profile_set([external_profile_path])
        except MachineImportProfileError as exc:
            raise CandidateRuntimeError(str(exc)) from exc
        profile_root = external_profile_path.parent
        graph: list[tuple[Path, str, str]] = []
        for profile in profile_set.profiles:
            try:
                profile.path.relative_to(profile_root)
            except ValueError as exc:
                raise CandidateRuntimeError(
                    "external profile includes must remain beneath the root profile directory"
                ) from exc
            graph.append((profile.path, profile.profile_id, profile.sha256))
        external_profile_graph = tuple(graph)
    (
        external_range_rules,
        authorized_external_site_rvas,
        blocked_external_sites,
    ) = _external_range_rules(
        native_plan,
        external_profile_path,
    )

    return NativeRuntimePlan(
        entry_rva=entry_rva,
        transfer_rvas=transfer_rvas,
        recovered_executable_data_ranges=recovered_executable_data_ranges,
        callback_abis=callback_abis,
        callback_adapter_receipts=callback_adapter_receipts,
        implementation_dispatch_receipt=implementation_dispatch_receipt,
        implementation_dispatches=implementation_dispatches,
        external_range_rules=external_range_rules,
        authorized_external_site_rvas=authorized_external_site_rvas,
        blocked_external_sites=blocked_external_sites,
        external_profile_path=external_profile_path,
        external_profile_sha256=(
            None
            if external_profile_path is None
            else sha256_file(external_profile_path)
        ),
        external_profile_graph=external_profile_graph,
        undefined_policies=undefined_policies,
        definedness_metadata_sha256=definedness_metadata_sha256,
        state_machine_sha256=state_machine_sha256,
        interpreter_manifest_path=interpreter_manifest_path,
        interpreter_manifest_sha256=sha256_file(interpreter_manifest_path),
        interpreter_program_path=program_path,
        interpreter_program_sha256=sha256_file(program_path),
        native_engine_manifest_path=native_manifest_path,
        native_engine_manifest_sha256=sha256_file(native_manifest_path),
        native_engine_plan_path=native_plan_path,
        native_engine_plan_sha256=sha256_file(native_plan_path),
        x87_handler_mode=x87_handler_mode,
        has_modeled_termination=has_modeled_termination,
    )


def write_spx_native_runtime_package(
    *,
    interpreter_package: Path | str,
    native_engine_package: Path | str,
    external_profile: Path | str | None = None,
    out: Path | str,
) -> dict[str, Any]:
    """Write deterministic freestanding runtime sources and their manifest."""

    plan = plan_spx_native_runtime(
        interpreter_package=interpreter_package,
        native_engine_package=native_engine_package,
        external_profile=external_profile,
    )
    out_path = Path(out)
    out_path.mkdir(parents=True, exist_ok=True)
    header_path = out_path / NATIVE_RUNTIME_HEADER_FILENAME
    source_path = out_path / NATIVE_RUNTIME_SOURCE_FILENAME
    bindings_path = out_path / NATIVE_RUNTIME_BINDINGS_FILENAME
    header_path.write_text(_native_runtime_header(), encoding="ascii")
    source_path.write_text(_native_runtime_source(plan), encoding="ascii")
    bindings_path.write_text(_native_runtime_bindings_source(plan), encoding="ascii")
    profile_source: dict[str, Any] | None = None
    profile_dependencies: list[dict[str, Any]] = []
    if plan.external_profile_path is not None:
        profile_path = out_path / NATIVE_RUNTIME_EXTERNAL_PROFILE_FILENAME
        try:
            profile_path.write_bytes(plan.external_profile_path.read_bytes())
        except OSError as exc:
            raise CandidateRuntimeError(
                "cannot copy the external environment profile into the runtime package"
            ) from exc
        if sha256_file(profile_path) != plan.external_profile_sha256:
            raise CandidateRuntimeError(
                "copied external environment profile SHA-256 mismatch"
            )
        profile_source = {
            "role": "external_profile",
            "path": profile_path.name,
            "sha256": plan.external_profile_sha256,
        }
        profile_root = plan.external_profile_path.parent
        for index, (source, _profile_id, expected_sha256) in enumerate(
            plan.external_profile_graph
        ):
            if source == plan.external_profile_path:
                continue
            relative = source.relative_to(profile_root)
            target = out_path / relative
            if target.exists():
                raise CandidateRuntimeError(
                    f"included external profile collides with package artifact {relative}"
                )
            target.parent.mkdir(parents=True, exist_ok=True)
            try:
                target.write_bytes(source.read_bytes())
            except OSError as exc:
                raise CandidateRuntimeError(
                    "cannot copy an included external profile into the runtime package"
                ) from exc
            if sha256_file(target) != expected_sha256:
                raise CandidateRuntimeError(
                    "copied included external profile SHA-256 mismatch"
                )
            profile_dependencies.append({
                "role": f"external_profile_dependency_{index:03d}",
                "path": str(relative),
                "sha256": expected_sha256,
            })
    result = {
        "format": NATIVE_RUNTIME_PACKAGE_FORMAT,
        "status": "ready",
        "acceptance_authority": False,
        "inputs": plan.payload(),
        "sources": [
            {
                "role": "native_runtime_header",
                "path": header_path.name,
                "sha256": sha256_file(header_path),
            },
            {
                "role": "native_runtime_source",
                "path": source_path.name,
                "sha256": sha256_file(source_path),
            },
            {
                "role": "native_runtime_bindings_source",
                "path": bindings_path.name,
                "sha256": sha256_file(bindings_path),
            },
        ] + ([] if profile_source is None else [profile_source]) + profile_dependencies,
        "counts": {
            "transfers": len(plan.transfer_rvas),
            "implementation_dispatches": len(plan.implementation_dispatches),
            "authorized_external_sites": len(
                plan.authorized_external_site_rvas
            ),
            "blocked_external_sites": len(plan.blocked_external_sites),
        },
        "policy": {
            "architecture": "i686-pe32",
            "execution_scope": "complete-static-authority",
            "freestanding": True,
            "static_hybrid_closure_receipt_required": True,
            "implementation_dispatch": (
                "exact-linked-class-per-interpreter-transfer-v1"
            ),
            "flat_memory": "exact-little-endian-widths-1-2-4",
            "read_domains": (
                "checked-image-headers-and-sections; captured-stack; "
                "read-only-4KiB-teb-window-at-captured-fs-base; "
                "bounded-profile-derived-external-ranges"
            ),
            "undefined_values": (
                "hash-bound-zero-only-after-semantic-noninterference; "
                "synchronized-slots-use-a-checked-instruction-local-input-expression; "
                "unknown-or-unsupported-slots-latch-unimplemented"
            ),
            "code_targets": (
                "absolute-image-va-in-checked-transfer-table-or-"
                "canonical-external-site-target-set"
            ),
            "threads": "fail-closed-on-concurrent-entry",
            "engine_stack": (
                "dedicated-64KiB-private-stack-disjoint-from-modeled-program-stack"
            ),
            "executable_writes": (
                "only-checked-nonexecuting-image-sections, captured-stack, or "
                "bounded-profile-derived-external-ranges"
            ),
            "external_ranges": (
                "machine-call-profile-bound-result-and-release-rules; "
                "8192-live-range-limit; bounded-profile-declared-pointee-shapes; "
                "overflow-and-missing-arguments-fail-closed"
            ),
            "terminal_control": (
                "record-status-and-modeled-environment-termination"
                if plan.has_modeled_termination
                else "record-status-and-unsupported-native-halt"
            ),
        },
        "authority": "candidate generation only; candidate assurance remains required",
    }
    write_json(out_path / NATIVE_RUNTIME_MANIFEST_FILENAME, result)
    return result


__all__ = [
    "DEFINEDNESS_USE_FORMAT",
    "NATIVE_RUNTIME_BINDINGS_FILENAME",
    "NATIVE_RUNTIME_HEADER_FILENAME",
    "NATIVE_RUNTIME_MANIFEST_FILENAME",
    "NATIVE_RUNTIME_PACKAGE_FORMAT",
    "NATIVE_RUNTIME_SOURCE_FILENAME",
    "NativeRuntimePlan",
    "NativeUndefinedPolicy",
    "CandidateRuntimeError",
    "plan_spx_native_runtime",
    "write_spx_native_runtime_package",
]
