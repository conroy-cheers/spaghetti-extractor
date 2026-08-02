"""Content-bound native-interpreter source-equivalence artifacts.

This module deliberately has no proof authority.  It turns the complete Stage B
native-interpreter source package and one pinned native build into deterministic,
fail-closed evidence that a later Lean source-equivalence proof can consume.
Nix metadata is injected by the caller so this layer remains deterministic and
does not execute ``nix`` or any compiler.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, Mapping

import pefile

from .artifact_formats import (
    INTERPRETER_NATIVE_BUILD_FORMAT,
    NATIVE_ENGINE_PACKAGE_FORMAT,
    NATIVE_ENGINE_PLAN_FORMAT,
    NATIVE_RUNTIME_PACKAGE_FORMAT,
    NATIVE_SOURCE_BUNDLE_FORMAT,
    NATIVE_SOURCE_COMPILATION_ATTESTATION_FORMAT,
    PAYLOAD_RELOCATION_INVENTORY_FORMAT,
    PE_COMPOSITION_MANIFEST_FORMAT,
)
from .errors import StageAInputError
from .roundtrip_fuzz.image_contract import load_stage_a_load_image_contract
from .stage_b_interpreter_backend import (
    STAGE_B_INTERPRETER_PACKAGE_FORMAT,
    STAGE_B_INTERPRETER_PROGRAM_FORMAT,
)
from .stage_b_typed_x87 import (
    TYPED_NATIVE_X87_OPERATION_FORMAT,
    TYPED_NATIVE_X87_PROGRAM_FORMAT,
    X87_CHECKED_DECODER,
    X87_CHECKED_EXECUTOR,
    typed_x87_operation_from_payload,
)
from .util import sha256_bytes, sha256_file


_INTERPRETER_MANIFEST = "state-machine-interpreter-package.json"
_ENGINE_MANIFEST = "native-engine-package.json"
_RUNTIME_MANIFEST = "native-runtime-package.json"
_SHA256_RE = re.compile(r"[0-9a-f]{64}\Z")
_NAR_HASH_RE = re.compile(r"sha256-[A-Za-z0-9+/=]+\Z")
_STORE_NAME_RE = re.compile(r"[0-9a-z]{32}-.+\Z")

_SOURCE_TRUST = {
    "acceptance_authority": False,
    "package_manifests_are_proposals": True,
    "original_binary_executed": False,
    "original_binary_consumed_statically": True,
    "lean_whole_program_proof_required": True,
    "compiler_correctness_assumed_by_source_equivalence": True,
}
_ATTESTATION_TRUST = {
    "acceptance_authority": False,
    "build_manifest_is_provenance_not_proof": True,
    "nix_metadata_requires_independent_store_validation": True,
    "compiler_assembler_linker_correctness_assumed": True,
    "lean_whole_program_proof_required": True,
}


class NativeSourceEquivalenceError(StageAInputError):
    """A native source-equivalence artifact failed closed validation."""


def build_native_source_bundle_manifest(
    *,
    state_machine: Path | str,
    interpreter_package: Path | str,
    native_engine_package: Path | str,
    native_runtime_package: Path | str,
    load_image_contract: Path | str,
) -> dict[str, Any]:
    """Validate and hash-bind one complete native-interpreter source bundle."""

    state_path = _file(state_machine, "augmented state machine")
    interpreter_root = _directory(interpreter_package, "interpreter package")
    engine_root = _directory(native_engine_package, "native-engine package")
    runtime_root = _directory(native_runtime_package, "native-runtime package")
    contract_path = _file(load_image_contract, "load-image contract")

    interpreter = _package_binding(
        root=interpreter_root,
        manifest_name=_INTERPRETER_MANIFEST,
        expected_format=STAGE_B_INTERPRETER_PACKAGE_FORMAT,
        owner="interpreter",
        extra_role="program",
        require_source_roles=True,
    )
    engine = _package_binding(
        root=engine_root,
        manifest_name=_ENGINE_MANIFEST,
        expected_format=NATIVE_ENGINE_PACKAGE_FORMAT,
        owner="native_engine",
        extra_role="plan",
        require_source_roles=False,
    )
    runtime = _package_binding(
        root=runtime_root,
        manifest_name=_RUNTIME_MANIFEST,
        expected_format=NATIVE_RUNTIME_PACKAGE_FORMAT,
        owner="native_runtime",
        extra_role=None,
        require_source_roles=True,
    )

    try:
        from .stage_b_native_runtime import plan_stage_b_native_runtime

        runtime_plan = plan_stage_b_native_runtime(
            interpreter_package=interpreter_root,
            native_engine_package=engine_root,
        )
    except Exception as exc:
        raise NativeSourceEquivalenceError(
            f"interpreter/native-engine closure is incomplete: {exc}"
        ) from exc
    if runtime["payload"].get("inputs") != runtime_plan.payload():
        raise NativeSourceEquivalenceError(
            "native-runtime package does not bind the exact interpreter/engine closure"
        )
    if runtime["payload"].get("acceptance_authority") is not False:
        raise NativeSourceEquivalenceError(
            "native-runtime package has unexpected acceptance authority"
        )

    state_digest = sha256_file(state_path)
    state_rows = _read_jsonl(state_path, "augmented state machine")
    state_binding = _object(
        interpreter["payload"].get("state_machine"),
        "interpreter state-machine binding",
    )
    if state_binding.get("path") != state_path.name:
        raise NativeSourceEquivalenceError(
            "interpreter package names a different state-machine artifact"
        )
    if state_binding.get("sha256") != state_digest:
        raise NativeSourceEquivalenceError(
            "interpreter package binds a different state-machine digest"
        )

    program_artifact = _artifact_for_role(interpreter, "program")
    program = _read_json_object(program_artifact["absolute_path"], "interpreter program")
    inventory = _validate_transfer_inventory(
        state_rows=state_rows,
        state_machine_sha256=state_digest,
        program=program,
        runtime_transfer_rvas=runtime_plan.transfer_rvas,
    )

    engine_plan_artifact = _artifact_for_role(engine, "plan")
    engine_plan = _read_json_object(engine_plan_artifact["absolute_path"], "native-engine plan")
    if engine_plan.get("format") != NATIVE_ENGINE_PLAN_FORMAT:
        raise NativeSourceEquivalenceError("native-engine plan has an unsupported format")
    if engine_plan.get("status") != "ready" or engine_plan.get("blockers") != []:
        raise NativeSourceEquivalenceError("native-engine plan is incomplete")
    if engine_plan.get("state_machine_sha256") != state_digest:
        raise NativeSourceEquivalenceError("native-engine plan binds a different state machine")
    if engine_plan.get("entry_rva") != runtime_plan.entry_rva:
        raise NativeSourceEquivalenceError("native-engine and runtime entry RVAs differ")

    contract = load_stage_a_load_image_contract(contract_path)
    if (
        contract.identity.machine != "i386"
        or contract.identity.bitness != 32
        or contract.identity.pointer_width != 4
        or not contract.completeness.complete
    ):
        raise NativeSourceEquivalenceError(
            "source-equivalence load-image contract must be complete i386 PE32"
        )
    if runtime_plan.entry_rva != contract.identity.entry_rva:
        raise NativeSourceEquivalenceError(
            "native-interpreter entry RVA differs from the load-image entry RVA"
        )

    core: dict[str, Any] = {
        "format": NATIVE_SOURCE_BUNDLE_FORMAT,
        "status": "ready",
        "profile": "native-interpreter-pe32-source-v1",
        "entry_rva": runtime_plan.entry_rva,
        "state_machine": {
            "path": str(state_path.resolve()),
            "size": state_path.stat().st_size,
            "sha256": state_digest,
        },
        "packages": {
            "interpreter": _public_package_binding(interpreter),
            "native_engine": _public_package_binding(engine),
            "native_runtime": _public_package_binding(runtime),
        },
        "load_image_contract": {
            "path": str(contract_path.resolve()),
            "size": contract_path.stat().st_size,
            "artifact_sha256": sha256_file(contract_path),
            "canonical_sha256": _canonical_sha256(
                _read_json_object(contract_path, "load-image contract")
            ),
            "contract_sha256": contract.hashes.contract_sha256,
            "bound_original_pe_sha256": contract.identity.pe_sha256,
            "entry_rva": contract.identity.entry_rva,
            "preferred_base": contract.identity.preferred_base,
        },
        "transfer_inventory": inventory,
        "trust": dict(_SOURCE_TRUST),
    }
    return _close(core, "source_bundle_sha256")


def validate_native_source_bundle_manifest(
    manifest: Path | str | Mapping[str, Any],
) -> dict[str, Any]:
    """Revalidate a bundle against every live artifact it names."""

    payload = _load_payload(manifest, "native source bundle")
    _validate_closed(payload, NATIVE_SOURCE_BUNDLE_FORMAT, "source_bundle_sha256")
    if payload.get("status") != "ready" or payload.get("trust") != _SOURCE_TRUST:
        raise NativeSourceEquivalenceError("native source bundle trust/status changed")
    packages = _object(payload.get("packages"), "native source bundle packages")
    rebuilt = build_native_source_bundle_manifest(
        state_machine=_path_binding(payload.get("state_machine"), "state machine"),
        interpreter_package=_package_root(packages.get("interpreter"), "interpreter"),
        native_engine_package=_package_root(packages.get("native_engine"), "native_engine"),
        native_runtime_package=_package_root(packages.get("native_runtime"), "native_runtime"),
        load_image_contract=_path_binding(
            payload.get("load_image_contract"), "load-image contract"
        ),
    )
    if rebuilt != payload:
        raise NativeSourceEquivalenceError(
            "native source bundle differs from its revalidated artifact closure"
        )
    return payload


def build_native_source_compilation_attestation(
    *,
    source_bundle_manifest: Path | str,
    native_build_manifest: Path | str,
    nix_provenance: Mapping[str, Any],
    additional_tools: Mapping[str, Path | str] | None = None,
    nix_store_root: Path | str = "/nix/store",
) -> dict[str, Any]:
    """Validate and bind a native build to its source bundle and Nix output."""

    source_path = _file(source_bundle_manifest, "native source bundle manifest")
    source = validate_native_source_bundle_manifest(source_path)
    build_path = _file(native_build_manifest, "interpreter native-build manifest")
    build_root = build_path.parent.resolve()
    build = _read_json_object(build_path, "interpreter native-build manifest")
    _validate_closed(build, INTERPRETER_NATIVE_BUILD_FORMAT, "manifest_core_sha256")
    if (
        build.get("status") != "candidate-generated"
        or build.get("acceptance_authority") != "none"
    ):
        raise NativeSourceEquivalenceError(
            "native build has unexpected status or acceptance authority"
        )
    _validate_build_source_closure(source, build)

    inputs = _object(build.get("inputs"), "native build inputs")
    contract = _object(
        inputs.get("load_image_contract"), "native build load-image contract"
    )
    if contract != {
        "artifact_sha256": source["load_image_contract"]["artifact_sha256"],
        "contract_sha256": source["load_image_contract"]["contract_sha256"],
        "bound_original_pe_sha256": source["load_image_contract"][
            "bound_original_pe_sha256"
        ],
    }:
        raise NativeSourceEquivalenceError(
            "native build binds a different load-image contract"
        )
    if inputs.get("runtime_plan") != _runtime_plan_from_source(source):
        raise NativeSourceEquivalenceError("native build runtime plan changed")

    outputs = _object(build.get("outputs"), "native build outputs")
    checked_outputs = {
        name: _validate_output_binding(build_root, value, f"native build output {name}")
        for name, value in outputs.items()
    }
    required_outputs = {
        "candidate",
        "payload",
        "composition_manifest",
        "payload_relocation_inventory",
    }
    if not required_outputs.issubset(checked_outputs):
        raise NativeSourceEquivalenceError("native build omits mandatory output evidence")

    object_rows = _list(build.get("objects"), "native build objects")
    if not object_rows:
        raise NativeSourceEquivalenceError("native build has no compiled object evidence")
    source_artifacts = {
        (item["owner"], item["role"], item["path"], item["sha256"])
        for package in _object(source.get("packages"), "source packages").values()
        for item in _list(_object(package, "source package").get("artifacts"), "package artifacts")
    }
    for index, raw in enumerate(object_rows):
        row = _object(raw, f"native build object {index}")
        source_row = _object(row.get("source"), f"native build object {index} source")
        source_key = tuple(
            source_row.get(field) for field in ("owner", "role", "path", "sha256")
        )
        if source_row.get("owner") != "generated" and source_key not in source_artifacts:
            raise NativeSourceEquivalenceError(
                f"native build object {index} source is outside the source bundle"
            )
        flags = _list(row.get("flags"), f"native build object {index} flags")
        if not flags or not all(isinstance(flag, str) and flag for flag in flags):
            raise NativeSourceEquivalenceError(
                f"native build object {index} compile flags are incomplete"
            )
        object_path = _within(build_root, row.get("object"), f"native build object {index}")
        if sha256_file(object_path) != _sha256(
            row.get("object_sha256"), f"native build object {index} SHA-256"
        ):
            raise NativeSourceEquivalenceError(
                f"native build object {index} SHA-256 mismatch"
            )

    commands = _object(build.get("commands"), "native build commands")
    if (
        commands.get("compile_flags_policy")
        != "deterministic-freestanding-proof-o0-v1"
        or not _list(commands.get("link_flags"), "native build link flags")
    ):
        raise NativeSourceEquivalenceError("native build command policy is incomplete")
    policy = _object(build.get("policy"), "native build policy")
    if (
        policy.get("architecture") != "i686-pe32"
        or policy.get("image_base")
        != source["load_image_contract"]["preferred_base"]
        or policy.get("dynamic_base") is not True
        or policy.get("freestanding") is not True
    ):
        raise NativeSourceEquivalenceError("native build policy changed")
    qualification = _object(build.get("qualification"), "native build qualification")
    required_qualification = {
        "machine": "i386",
        "bitness": 32,
        "dynamic_base": True,
        "relocation_inventory_complete": True,
        "payload_imports": 0,
        "unresolved_symbols": [],
        "compiler_materialized_layout_parsed": True,
        "package_closure_revalidated_after_compile": True,
    }
    if any(qualification.get(key) != value for key, value in required_qualification.items()):
        raise NativeSourceEquivalenceError("native build qualification is incomplete")

    candidate = checked_outputs["candidate"]
    _validate_candidate_pe(candidate)
    relocation = _validate_relocation_artifact(
        checked_outputs["payload_relocation_inventory"],
        payload_sha256=checked_outputs["payload"]["sha256"],
        output_binding=_object(
            outputs.get("payload_relocation_inventory"),
            "payload relocation output binding",
        ),
    )
    composition = _validate_composition_artifact(
        checked_outputs["composition_manifest"],
        source=source,
        payload_sha256=checked_outputs["payload"]["sha256"],
        relocation=relocation,
        output_binding=_object(
            outputs.get("composition_manifest"), "composition output binding"
        ),
    )
    tools = _validate_tools(build, additional_tools or {})
    nix = _validate_nix_provenance(
        nix_provenance,
        build_root=build_root,
        store_root=Path(nix_store_root).resolve(),
    )

    core: dict[str, Any] = {
        "format": NATIVE_SOURCE_COMPILATION_ATTESTATION_FORMAT,
        "status": "complete",
        "source_bundle": {
            "path": str(source_path.resolve()),
            "size": source_path.stat().st_size,
            "artifact_sha256": sha256_file(source_path),
            "source_bundle_sha256": source["hashes"]["source_bundle_sha256"],
        },
        "native_build": {
            "path": str(build_path.resolve()),
            "size": build_path.stat().st_size,
            "artifact_sha256": sha256_file(build_path),
            "manifest_core_sha256": build["hashes"]["manifest_core_sha256"],
        },
        "candidate": candidate,
        "composition": composition,
        "relocations": relocation,
        "nix": nix,
        "tools": tools,
        "trust": dict(_ATTESTATION_TRUST),
    }
    return _close(core, "attestation_core_sha256")


def validate_native_source_compilation_attestation(
    attestation: Path | str | Mapping[str, Any],
    *,
    nix_store_root: Path | str = "/nix/store",
) -> dict[str, Any]:
    """Revalidate an attestation and its complete live build closure."""

    payload = _load_payload(attestation, "native source compilation attestation")
    _validate_closed(
        payload,
        NATIVE_SOURCE_COMPILATION_ATTESTATION_FORMAT,
        "attestation_core_sha256",
    )
    if payload.get("status") != "complete" or payload.get("trust") != _ATTESTATION_TRUST:
        raise NativeSourceEquivalenceError("compilation attestation trust/status changed")
    source = _object(payload.get("source_bundle"), "attestation source bundle")
    build = _object(payload.get("native_build"), "attestation native build")
    source_path = _bound_absolute_artifact(source, "source bundle")
    build_path = _bound_absolute_artifact(build, "native build")
    additional = {
        row["role"]: row["path"]
        for row in _list(payload.get("tools"), "attestation tools")
        if _object(row, "attestation tool")["role"]
        not in {"compiler", "assembler", "linker", "nm", "compiler_runtime"}
    }
    rebuilt = build_native_source_compilation_attestation(
        source_bundle_manifest=source_path,
        native_build_manifest=build_path,
        nix_provenance=_object(payload.get("nix"), "attestation nix provenance"),
        additional_tools=additional,
        nix_store_root=nix_store_root,
    )
    if rebuilt != payload:
        raise NativeSourceEquivalenceError(
            "compilation attestation differs from its revalidated build closure"
        )
    return payload


def _package_binding(
    *,
    root: Path,
    manifest_name: str,
    expected_format: str,
    owner: str,
    extra_role: str | None,
    require_source_roles: bool,
) -> dict[str, Any]:
    manifest_path = _file(root / manifest_name, f"{owner} package manifest")
    payload = _read_json_object(manifest_path, f"{owner} package manifest")
    if payload.get("format") != expected_format or payload.get("status") != "ready":
        raise NativeSourceEquivalenceError(f"{owner} package is not ready")
    blockers = payload.get("blockers", [] if owner == "native_runtime" else None)
    if blockers != []:
        raise NativeSourceEquivalenceError(f"{owner} package has blockers")
    rows = _list(payload.get("sources"), f"{owner} sources")
    if not rows:
        raise NativeSourceEquivalenceError(f"{owner} package has no source artifacts")
    artifacts: list[dict[str, Any]] = []
    seen_paths: set[str] = set()
    seen_roles: set[str] = set()
    for index, raw in enumerate(rows):
        item = _object(raw, f"{owner} source {index}")
        role = item.get("role")
        if require_source_roles:
            role = _string(role, f"{owner} source {index} role")
        elif not isinstance(role, str) or not role:
            role = f"source_{index:03d}"
        artifacts.append(_package_artifact(root, owner, role, item))
        if artifacts[-1]["path"] in seen_paths or role in seen_roles:
            raise NativeSourceEquivalenceError(
                f"{owner} package has duplicate artifact paths or roles"
            )
        seen_paths.add(artifacts[-1]["path"])
        seen_roles.add(role)
    if extra_role is not None:
        item = _object(payload.get(extra_role), f"{owner} {extra_role}")
        artifact = _package_artifact(root, owner, extra_role, item)
        if artifact["path"] in seen_paths or extra_role in seen_roles:
            raise NativeSourceEquivalenceError(
                f"{owner} package has duplicate {extra_role} artifact"
            )
        artifacts.append(artifact)
    return {
        "root": root.resolve(),
        "manifest_path": manifest_path,
        "payload": payload,
        "artifacts": artifacts,
    }


def _package_artifact(
    root: Path, owner: str, role: str, payload: Mapping[str, Any]
) -> dict[str, Any]:
    relative = _relative_path(payload.get("path"), f"{owner} {role} path")
    path = _within(root, relative, f"{owner} {role}")
    digest = _sha256(payload.get("sha256"), f"{owner} {role} SHA-256")
    if sha256_file(path) != digest:
        raise NativeSourceEquivalenceError(f"{owner} {role} artifact SHA-256 mismatch")
    return {
        "owner": owner,
        "role": role,
        "path": relative,
        "size": path.stat().st_size,
        "sha256": digest,
        "absolute_path": path,
    }


def _public_package_binding(package: Mapping[str, Any]) -> dict[str, Any]:
    manifest_path = package["manifest_path"]
    return {
        "root": str(package["root"]),
        "manifest": {
            "path": manifest_path.name,
            "size": manifest_path.stat().st_size,
            "sha256": sha256_file(manifest_path),
        },
        "artifacts": [
            {key: value for key, value in item.items() if key != "absolute_path"}
            for item in package["artifacts"]
        ],
    }


def _artifact_for_role(package: Mapping[str, Any], role: str) -> Mapping[str, Any]:
    matches = [item for item in package["artifacts"] if item["role"] == role]
    if len(matches) != 1:
        raise NativeSourceEquivalenceError(
            f"{package['payload'].get('format')} has no unique {role} artifact"
        )
    return matches[0]


def _validate_transfer_inventory(
    *,
    state_rows: list[dict[str, Any]],
    state_machine_sha256: str,
    program: Mapping[str, Any],
    runtime_transfer_rvas: tuple[int, ...],
) -> dict[str, Any]:
    if (
        program.get("format") != STAGE_B_INTERPRETER_PROGRAM_FORMAT
        or program.get("status") != "ready"
        or program.get("blockers") != []
        or program.get("state_machine_sha256") != state_machine_sha256
    ):
        raise NativeSourceEquivalenceError("interpreter program is incomplete or stale")
    program_rows = _list(program.get("transfers"), "interpreter program transfers")
    counts = _object(program.get("counts"), "interpreter program counts")
    if not state_rows or any(
        counts.get(field) != len(state_rows)
        for field in ("input_transfers", "transfers")
    ) or counts.get("blocked_transfers") != 0:
        raise NativeSourceEquivalenceError("interpreter transfer coverage is incomplete")
    if len(program_rows) != len(state_rows):
        raise NativeSourceEquivalenceError("interpreter transfer inventory is incomplete")

    result: list[dict[str, Any]] = []
    rvas: list[int] = []
    x87_transfer_count = 0
    x87_replay_count = 0
    for index, (raw_state, raw_program) in enumerate(
        zip(state_rows, program_rows, strict=True)
    ):
        state = _object(raw_state, f"state-machine transfer {index}")
        record = _object(raw_program, f"interpreter transfer {index}")
        original = _object(state.get("original"), f"state-machine transfer {index} span")
        expected = {
            "id": _string(state.get("id"), f"state-machine transfer {index} id"),
            "rva_start": _u32(original.get("rva_start"), f"transfer {index} RVA"),
            "contract_sha256": _sha256(
                state.get("contract_sha256"), f"transfer {index} contract SHA-256"
            ),
            "instruction_bytes_sha256": _sha256(
                state.get("instruction_bytes_sha256"),
                f"transfer {index} instruction SHA-256",
            ),
        }
        for field, value in expected.items():
            if record.get(field) != value:
                raise NativeSourceEquivalenceError(
                    f"interpreter transfer {index} {field} differs from state machine"
                )
        transfer_counts = _object(record.get("counts"), f"transfer {index} counts")
        replay_count = _count(
            transfer_counts.get("x87_operations"), f"transfer {index} x87 count"
        )
        replays = _list(
            record.get("x87_operations"), f"transfer {index} x87 operations"
        )
        if replay_count != len(replays):
            raise NativeSourceEquivalenceError(
                f"interpreter transfer {index} x87 operation inventory is incomplete"
            )
        for replay_index, replay in enumerate(replays):
            _validate_typed_x87_operation(
                _object(replay, f"transfer {index} x87 operation {replay_index}"),
                expected_contract_sha256=expected["contract_sha256"],
            )
        fpu_state = state.get("fpu_state")
        requires_x87_replay = (
            isinstance(fpu_state, Mapping)
            and fpu_state.get("model")
            == "native_exact_x87_command_replay_obligation_v1"
        )
        if requires_x87_replay != bool(replay_count):
            raise NativeSourceEquivalenceError(
                f"interpreter transfer {index} does not completely represent its x87 evidence"
            )
        if replay_count:
            x87_transfer_count += 1
            x87_replay_count += replay_count
        result.append({
            **expected,
            "x87_replay_count": replay_count,
            "x87_replays_sha256": _canonical_sha256(replays),
        })
        rvas.append(expected["rva_start"])
    if rvas != sorted(rvas) or len(rvas) != len(set(rvas)):
        raise NativeSourceEquivalenceError("transfer RVAs must be sorted and unique")
    if tuple(rvas) != runtime_transfer_rvas:
        raise NativeSourceEquivalenceError("runtime transfer inventory differs")
    if counts.get("x87_operations") != x87_replay_count:
        raise NativeSourceEquivalenceError(
            "program x87 operation count differs from inventory"
        )
    capability = _object(program.get("capability"), "interpreter capability")
    if x87_replay_count:
        replay = _object(
            capability.get("typed_native_x87"), "typed x87 capability"
        )
        if (
            replay.get("format") != TYPED_NATIVE_X87_PROGRAM_FORMAT
            or replay.get("operation_format") != TYPED_NATIVE_X87_OPERATION_FORMAT
            or replay.get("mode") != "sanitized_typed_native_v1"
            or replay.get("action") != "typed_x87"
            or replay.get("runtime_handler") != "execute_typed_x87_operation"
            or replay.get("checked_decoder") != X87_CHECKED_DECODER
            or replay.get("checked_executor") != X87_CHECKED_EXECUTOR
        ):
            raise NativeSourceEquivalenceError("typed x87 capability is not checked")
    return {
        "count": len(result),
        "x87_transfer_count": x87_transfer_count,
        "x87_replay_count": x87_replay_count,
        "inventory_sha256": _canonical_sha256(result),
        "transfers": result,
    }


def _validate_typed_x87_operation(
    replay: Mapping[str, Any], *, expected_contract_sha256: str
) -> None:
    if replay.get("format") != TYPED_NATIVE_X87_PROGRAM_FORMAT:
        raise NativeSourceEquivalenceError("typed x87 program format is unsupported")
    if replay.get("contract_sha256") != expected_contract_sha256:
        raise NativeSourceEquivalenceError(
            "typed x87 program does not bind its complete transfer contract"
        )
    if (
        replay.get("checked_decoder") != X87_CHECKED_DECODER
        or replay.get("checked_executor") != X87_CHECKED_EXECUTOR
    ):
        raise NativeSourceEquivalenceError(
            "typed x87 program omits checked semantics identities"
        )
    image_base = _u32(replay.get("image_base"), "typed x87 image base")
    rva_start = _u32(replay.get("rva_start"), "typed x87 start RVA")
    rva_end = _u32(replay.get("rva_end"), "typed x87 end RVA")
    if rva_end <= rva_start:
        raise NativeSourceEquivalenceError("typed x87 span is empty or reversed")
    operation = _object(replay.get("operation"), "typed x87 operation")
    try:
        parsed = typed_x87_operation_from_payload(operation, image_base=image_base)
    except StageAInputError as exc:
        raise NativeSourceEquivalenceError(str(exc)) from exc
    if parsed.source_size != rva_end - rva_start:
        raise NativeSourceEquivalenceError(
            "typed x87 source size differs from its checked span"
        )


def _validate_build_source_closure(
    source: Mapping[str, Any], build: Mapping[str, Any]
) -> None:
    source_packages = _object(source.get("packages"), "source packages")
    build_inputs = _object(build.get("inputs"), "native build inputs")
    names = {
        "interpreter": "interpreter_package",
        "native_engine": "native_engine_package",
        "native_runtime": "native_runtime_package",
    }
    for source_name, build_name in names.items():
        package = _object(source_packages.get(source_name), f"source {source_name}")
        manifest = _object(package.get("manifest"), f"source {source_name} manifest")
        expected = {
            "manifest": manifest["path"],
            "manifest_sha256": manifest["sha256"],
            "artifacts": [
                {key: item[key] for key in ("owner", "role", "path", "sha256")}
                for item in _list(package.get("artifacts"), f"source {source_name} artifacts")
            ],
        }
        if build_inputs.get(build_name) != expected:
            raise NativeSourceEquivalenceError(
                f"native build {build_name} differs from source bundle"
            )


def _runtime_plan_from_source(source: Mapping[str, Any]) -> dict[str, Any]:
    from .stage_b_native_runtime import plan_stage_b_native_runtime

    packages = _object(source.get("packages"), "source packages")
    return plan_stage_b_native_runtime(
        interpreter_package=_package_root(packages["interpreter"], "interpreter"),
        native_engine_package=_package_root(packages["native_engine"], "native_engine"),
    ).payload()


def _validate_output_binding(
    root: Path, raw: Any, label: str
) -> dict[str, Any]:
    row = _object(raw, label)
    path = _within(root, row.get("path"), label)
    digest = _sha256(row.get("sha256"), f"{label} SHA-256")
    size = _count(row.get("size"), f"{label} size")
    if path.stat().st_size != size or sha256_file(path) != digest:
        raise NativeSourceEquivalenceError(f"{label} artifact differs from its binding")
    return {"path": str(path), "size": size, "sha256": digest}


def _validate_candidate_pe(binding: Mapping[str, Any]) -> None:
    try:
        pe = pefile.PE(binding["path"], fast_load=True)
    except (OSError, pefile.PEFormatError) as exc:
        raise NativeSourceEquivalenceError(f"candidate is not a PE image: {exc}") from exc
    try:
        if pe.FILE_HEADER.Machine != 0x14C or pe.OPTIONAL_HEADER.Magic != 0x10B:
            raise NativeSourceEquivalenceError("candidate is not i386 PE32")
    finally:
        pe.close()


def _validate_relocation_artifact(
    binding: Mapping[str, Any], *, payload_sha256: str, output_binding: Mapping[str, Any]
) -> dict[str, Any]:
    from .stage_b_pe_composer import PayloadRelocationInventory

    payload = _read_json_object(Path(binding["path"]), "payload relocation inventory")
    try:
        inventory = PayloadRelocationInventory.parse(payload)
    except Exception as exc:
        raise NativeSourceEquivalenceError(str(exc)) from exc
    if inventory.payload_sha256 != payload_sha256:
        raise NativeSourceEquivalenceError("relocation inventory binds a different payload")
    if (
        output_binding.get("complete") is not True
        or output_binding.get("count") != len(inventory.relocations)
    ):
        raise NativeSourceEquivalenceError("relocation output summary is incomplete")
    if output_binding.get("payload_sha256") != payload_sha256:
        raise NativeSourceEquivalenceError("relocation output summary changed payload")
    return {
        **dict(binding),
        "format": PAYLOAD_RELOCATION_INVENTORY_FORMAT,
        "canonical_sha256": _canonical_sha256(payload),
        "count": len(inventory.relocations),
        "complete": True,
        "payload_sha256": payload_sha256,
    }


def _validate_composition_artifact(
    binding: Mapping[str, Any], *, source: Mapping[str, Any], payload_sha256: str,
    relocation: Mapping[str, Any], output_binding: Mapping[str, Any]
) -> dict[str, Any]:
    payload = _read_json_object(Path(binding["path"]), "composition manifest")
    _validate_closed(payload, PE_COMPOSITION_MANIFEST_FORMAT, "manifest_core_sha256")
    if payload.get("status") != "composed" or payload.get("acceptance_authority") != "none":
        raise NativeSourceEquivalenceError("composition manifest has unexpected authority")
    inputs = _object(payload.get("inputs"), "composition inputs")
    contract = _object(inputs.get("load_image_contract"), "composition load-image input")
    expected_contract = source["load_image_contract"]
    if (
        contract.get("artifact_sha256") != expected_contract["canonical_sha256"]
        or contract.get("contract_sha256") != expected_contract["contract_sha256"]
        or contract.get("bound_original_pe_sha256")
        != expected_contract["bound_original_pe_sha256"]
    ):
        raise NativeSourceEquivalenceError("composition binds a different load-image contract")
    if _object(inputs.get("payload_pe"), "composition payload").get("sha256") != payload_sha256:
        raise NativeSourceEquivalenceError("composition binds a different payload")
    relocation_input = _object(
        inputs.get("payload_relocation_inventory"), "composition relocation input"
    )
    if (
        relocation_input.get("format") != PAYLOAD_RELOCATION_INVENTORY_FORMAT
        or relocation_input.get("sha256") != relocation["canonical_sha256"]
        or relocation_input.get("complete") is not True
    ):
        raise NativeSourceEquivalenceError("composition relocation binding is incomplete")
    if output_binding.get("manifest_core_sha256") != payload["hashes"]["manifest_core_sha256"]:
        raise NativeSourceEquivalenceError("composition output core hash mismatch")
    return {
        **dict(binding),
        "format": PE_COMPOSITION_MANIFEST_FORMAT,
        "manifest_core_sha256": payload["hashes"]["manifest_core_sha256"],
    }


def _validate_tools(
    build: Mapping[str, Any], additional: Mapping[str, Path | str]
) -> list[dict[str, Any]]:
    toolchain = _object(build.get("toolchain"), "native build toolchain")
    if toolchain.get("target") != "i686-w64-mingw32":
        raise NativeSourceEquivalenceError("native build toolchain target changed")
    runtime = _object(toolchain.get("compiler_runtime"), "compiler runtime")
    mandatory = {
        "compiler": (toolchain.get("compiler"), toolchain.get("compiler_sha256")),
        "assembler": (
            toolchain.get("assembler"),
            toolchain.get("assembler_sha256"),
        ),
        "linker": (toolchain.get("linker"), toolchain.get("linker_sha256")),
        "nm": (toolchain.get("nm"), toolchain.get("nm_sha256")),
        "compiler_runtime": (runtime.get("path"), runtime.get("sha256")),
    }
    rows: list[dict[str, Any]] = []
    for role, (raw_path, raw_digest) in mandatory.items():
        path = _file(_string(raw_path, f"{role} path"), role)
        digest = _sha256(raw_digest, f"{role} SHA-256")
        if sha256_file(path) != digest:
            raise NativeSourceEquivalenceError(f"{role} tool hash mismatch")
        rows.append({"role": role, "path": str(path.resolve()), "sha256": digest})
    for role in sorted(additional):
        if role in mandatory or not role:
            raise NativeSourceEquivalenceError("additional tool role is empty or duplicate")
        path = _file(additional[role], f"additional tool {role}")
        rows.append({
            "role": role,
            "path": str(path.resolve()),
            "sha256": sha256_file(path),
        })
    return rows


def _validate_nix_provenance(
    payload: Mapping[str, Any], *, build_root: Path, store_root: Path
) -> dict[str, Any]:
    expected_fields = {"output", "derivation", "registered_deriver", "nar_hash"}
    if set(payload) != expected_fields:
        raise NativeSourceEquivalenceError("Nix provenance is missing mandatory evidence")
    output = Path(_string(payload.get("output"), "Nix output")).resolve()
    if output != build_root:
        raise NativeSourceEquivalenceError("Nix output differs from native build root")
    _require_store_member(output, store_root, "Nix output", suffix=None, file=False)
    derivation = Path(_string(payload.get("derivation"), "Nix derivation")).resolve()
    registered = Path(
        _string(payload.get("registered_deriver"), "registered Nix deriver")
    ).resolve()
    _require_store_member(derivation, store_root, "Nix derivation", suffix=".drv", file=True)
    _require_store_member(
        registered,
        store_root,
        "registered Nix deriver",
        suffix=".drv",
        file=True,
    )
    if derivation != registered:
        raise NativeSourceEquivalenceError("planned and registered Nix derivations differ")
    nar_hash = _string(payload.get("nar_hash"), "Nix NAR hash")
    if _NAR_HASH_RE.fullmatch(nar_hash) is None:
        raise NativeSourceEquivalenceError("Nix NAR hash is not an SRI SHA-256")
    return {
        "output": str(output),
        "derivation": str(derivation),
        "registered_deriver": str(registered),
        "nar_hash": nar_hash,
    }


def _require_store_member(
    path: Path, root: Path, label: str, *, suffix: str | None, file: bool
) -> None:
    try:
        relative = path.relative_to(root)
    except ValueError as exc:
        raise NativeSourceEquivalenceError(f"{label} is outside the Nix store") from exc
    if len(relative.parts) != 1 or _STORE_NAME_RE.fullmatch(relative.name) is None:
        raise NativeSourceEquivalenceError(f"{label} is not a top-level Nix store path")
    if suffix is not None and not relative.name.endswith(suffix):
        raise NativeSourceEquivalenceError(f"{label} has the wrong suffix")
    if (not path.is_file()) if file else (not path.is_dir()):
        raise NativeSourceEquivalenceError(f"{label} is not realized")


def _bound_absolute_artifact(binding: Mapping[str, Any], label: str) -> Path:
    path = _file(_string(binding.get("path"), f"{label} path"), label)
    if path.stat().st_size != _count(binding.get("size"), f"{label} size"):
        raise NativeSourceEquivalenceError(f"{label} size mismatch")
    if sha256_file(path) != _sha256(binding.get("artifact_sha256"), f"{label} SHA-256"):
        raise NativeSourceEquivalenceError(f"{label} SHA-256 mismatch")
    return path


def _package_root(value: Any, label: str) -> Path:
    return _directory(
        _string(_object(value, f"{label} package").get("root"), f"{label} root"),
        f"{label} package",
    )


def _path_binding(value: Any, label: str) -> Path:
    return _file(
        _string(_object(value, label).get("path"), f"{label} path"), label
    )


def _load_payload(value: Path | str | Mapping[str, Any], label: str) -> dict[str, Any]:
    if isinstance(value, Mapping):
        return dict(value)
    return _read_json_object(_file(value, label), label)


def _close(core: Mapping[str, Any], hash_field: str) -> dict[str, Any]:
    return {
        **core,
        "hashes": {"algorithm": "sha256", hash_field: _canonical_sha256(core)},
    }


def _validate_closed(
    payload: Mapping[str, Any], expected_format: str, hash_field: str
) -> None:
    if payload.get("format") != expected_format:
        raise NativeSourceEquivalenceError("artifact has an unsupported format")
    hashes = _object(payload.get("hashes"), "artifact hashes")
    if hashes.get("algorithm") != "sha256":
        raise NativeSourceEquivalenceError("artifact hash algorithm changed")
    expected = _sha256(hashes.get(hash_field), f"artifact {hash_field}")
    core = {key: value for key, value in payload.items() if key != "hashes"}
    if _canonical_sha256(core) != expected:
        raise NativeSourceEquivalenceError("artifact deterministic hash does not close")


def _canonical_sha256(value: Any) -> str:
    return sha256_bytes(
        json.dumps(
            value, sort_keys=True, separators=(",", ":"), ensure_ascii=True
        ).encode("ascii")
    )


def _read_json_object(path: Path, label: str) -> dict[str, Any]:
    try:
        value = json.loads(
            path.read_text(encoding="utf-8"), object_pairs_hook=_reject_duplicate_keys
        )
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise NativeSourceEquivalenceError(f"cannot read {label} {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise NativeSourceEquivalenceError(f"{label} must be an object")
    return value


def _read_jsonl(path: Path, label: str) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    try:
        for line_number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            if not line.strip():
                continue
            value = json.loads(line, object_pairs_hook=_reject_duplicate_keys)
            if not isinstance(value, dict):
                raise NativeSourceEquivalenceError(
                    f"{label} line {line_number} must be an object"
                )
            rows.append(value)
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise NativeSourceEquivalenceError(f"cannot read {label} {path}: {exc}") from exc
    return rows


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise NativeSourceEquivalenceError(f"duplicate JSON field {key!r}")
        result[key] = value
    return result


def _object(value: Any, label: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping) or not all(isinstance(key, str) for key in value):
        raise NativeSourceEquivalenceError(f"{label} must be an object")
    return value


def _list(value: Any, label: str) -> list[Any]:
    if not isinstance(value, list):
        raise NativeSourceEquivalenceError(f"{label} must be a list")
    return value


def _string(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value:
        raise NativeSourceEquivalenceError(f"{label} must be a nonempty string")
    return value


def _sha256(value: Any, label: str) -> str:
    text = _string(value, label)
    if _SHA256_RE.fullmatch(text) is None:
        raise NativeSourceEquivalenceError(f"{label} must be a lowercase SHA-256")
    return text


def _count(value: Any, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise NativeSourceEquivalenceError(f"{label} must be a nonnegative integer")
    return value


def _u32(value: Any, label: str) -> int:
    result = _count(value, label)
    if result > 0xFFFFFFFF:
        raise NativeSourceEquivalenceError(f"{label} must fit uint32")
    return result


def _hex_bytes(value: Any, label: str) -> bytes:
    text = _string(value, label)
    try:
        result = bytes.fromhex(text)
    except ValueError as exc:
        raise NativeSourceEquivalenceError(f"{label} must be hexadecimal") from exc
    if result.hex() != text:
        raise NativeSourceEquivalenceError(f"{label} must be canonical lowercase hexadecimal")
    return result


def _relative_path(value: Any, label: str) -> str:
    text = _string(value, label)
    path = Path(text)
    if path.is_absolute() or ".." in path.parts or path.as_posix() != text:
        raise NativeSourceEquivalenceError(f"{label} must be a normalized relative path")
    return text


def _within(root: Path, value: Any, label: str) -> Path:
    relative = (
        _relative_path(value, f"{label} path")
        if not isinstance(value, Path)
        else value.as_posix()
    )
    path = root / relative
    try:
        path.resolve().relative_to(root.resolve())
    except ValueError as exc:
        raise NativeSourceEquivalenceError(f"{label} escapes its root") from exc
    return _file(path, label)


def _file(value: Path | str, label: str) -> Path:
    path = Path(value)
    if not path.is_file() or path.is_symlink():
        raise NativeSourceEquivalenceError(f"{label} is not a regular file: {path}")
    return path


def _directory(value: Path | str, label: str) -> Path:
    path = Path(value)
    if not path.is_dir() or path.is_symlink():
        raise NativeSourceEquivalenceError(f"{label} is not a directory: {path}")
    return path


__all__ = [
    "NATIVE_SOURCE_BUNDLE_FORMAT",
    "NATIVE_SOURCE_COMPILATION_ATTESTATION_FORMAT",
    "NativeSourceEquivalenceError",
    "build_native_source_bundle_manifest",
    "build_native_source_compilation_attestation",
    "validate_native_source_bundle_manifest",
    "validate_native_source_compilation_attestation",
]
