"""Deterministic source-package emission for a planned candidate engine."""

from __future__ import annotations

from pathlib import Path
from typing import Any, Iterable, Mapping

from ..artifacts.formats import NATIVE_ENGINE_PACKAGE_FORMAT
from ..errors import ToolkitInputError
from ..util import sha256_file, write_json
from .engine_layout import render_spx_engine_layout_c
from .engine_render import _bridge_assembly, _wrapper_header, _wrapper_source
from .x87 import TYPED_NATIVE_X87_OPERATION_FORMAT
from .imports import NativeImportSlot
from .native_ingress_runtime import (
    render_native_ingress_assembly,
    render_native_ingress_header,
    render_native_ingress_source,
)


def write_spx_native_engine_package(
    *,
    machine_ir: Path,
    machine_ir_manifest: Path,
    recovered_executable_data: Path | str | None = None,
    out: Path,
    native_ingress_plan: Path | str,
    import_slots: Iterable[NativeImportSlot | Mapping[str, Any]] | None = None,
    import_iat_vas: Mapping[tuple[str, str | int], int] | None = None,
    termination_import: Mapping[str, Any] | None = None,
    base_relocation_evidence: Mapping[str, Any] | None = None,
    canonical_external_sites: Path | str,
    callback_authority: Path | str,
    root_closure: Path | str,
    target_certificates: Path | str,
    parametric_summaries: Path | str,
    fixed_image_base: int | None = None,
    preferred_image_base: int | None = None,
    initial_zero_ranges: Iterable[tuple[int, int]] = (),
    selected_portable_components: Iterable[Mapping[str, Any]] = (),
) -> dict[str, Any]:
    """Write deterministic wrapper sources and a fail-closed build plan."""

    from .engine import plan_spx_native_engine

    input_path = Path(machine_ir)
    out = Path(out)
    import json
    from ..artifacts.artifact_set import canonical_sha256_v3
    from ..artifacts.formats import NATIVE_INGRESS_PLAN_FORMAT

    ingress_path = Path(native_ingress_plan)
    try:
        ingress = json.loads(ingress_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ToolkitInputError(f"cannot read native ingress plan: {exc}") from exc
    if not isinstance(ingress, Mapping) or ingress.get("format") != NATIVE_INGRESS_PLAN_FORMAT:
        raise ToolkitInputError("native ingress plan has unsupported format")
    ingress_core = {key: value for key, value in ingress.items() if key != "plan_sha256"}
    if ingress.get("plan_sha256") != canonical_sha256_v3(ingress_core) or ingress.get("status") != "complete":
        raise ToolkitInputError("native ingress plan is stale or incomplete")
    ingress_binding = {
        "path": "native-ingress-plan.json",
        "sha256": sha256_file(ingress_path),
        "plan_sha256": ingress["plan_sha256"],
    }
    ingress_payload: Mapping[str, Any] = ingress
    plan = plan_spx_native_engine(
        machine_ir=machine_ir,
        machine_ir_manifest=machine_ir_manifest,
        recovered_executable_data=recovered_executable_data,
        native_ingress_plan=ingress_payload,
        import_slots=import_slots,
        import_iat_vas=import_iat_vas,
        termination_import=termination_import,
        base_relocation_evidence=base_relocation_evidence,
        canonical_external_sites=canonical_external_sites,
        callback_authority=callback_authority,
        root_closure=root_closure,
        target_certificates=target_certificates,
        parametric_summaries=parametric_summaries,
        fixed_image_base=fixed_image_base,
        preferred_image_base=preferred_image_base,
        initial_zero_ranges=initial_zero_ranges,
        selected_portable_components=selected_portable_components,
    )
    if plan.status != "ready":
        categories = sorted(
            {
                str(row.get("category"))
                for row in plan.blockers
                if row.get("category") is not None
            }
        )
        raise ToolkitInputError(
            "native engine plan is incomplete; no sources were written"
            + (f" ({', '.join(categories)})" if categories else "")
        )
    out.mkdir(parents=True, exist_ok=True)
    write_json(out / "native-ingress-plan.json", ingress_payload)
    plan_path = out / "native-engine-plan.json"
    write_json(plan_path, plan.payload(state_machine_sha256=sha256_file(input_path)))
    header = out / "native-engine-wrapper.h"
    source = out / "native-engine-wrapper.c"
    assembly = out / "native-engine-bridges.S"
    layout_source = out / "native-engine-layout.c"
    header.write_text(_wrapper_header(), encoding="ascii")
    source.write_text(
        _wrapper_source(
            plan, dict(ingress_payload)
        ),
        encoding="ascii",
    )
    assembly.write_text(
        _bridge_assembly(plan),
        encoding="ascii",
    )
    layout_source.write_text(
        render_spx_engine_layout_c(
            flag_storage="split-and-packed",
            include_fs_base=True,
            include_original_rva=True,
        ),
        encoding="ascii",
    )
    ingress_header = out / "native-ingress-runtime.h"
    ingress_source = out / "native-ingress-runtime.c"
    ingress_assembly = out / "native-ingress-bridges.S"
    ingress_header.write_text(
        render_native_ingress_header(ingress_payload), encoding="ascii"
    )
    ingress_source.write_text(
        render_native_ingress_source(ingress_payload), encoding="ascii"
    )
    ingress_assembly.write_text(
        render_native_ingress_assembly(ingress_payload), encoding="ascii"
    )
    ingress_sources = (ingress_header, ingress_source, ingress_assembly)
    result = {
        "format": NATIVE_ENGINE_PACKAGE_FORMAT,
        "status": plan.status,
        "machine_ir": {"path": input_path.name, "sha256": sha256_file(input_path)},
        "machine_ir_manifest": {
            "path": Path(machine_ir_manifest).name,
            "sha256": sha256_file(machine_ir_manifest),
        },
        "recovered_executable_data": (
            None
            if recovered_executable_data is None
            else {
                "path": Path(recovered_executable_data).name,
                "sha256": sha256_file(recovered_executable_data),
                "ranges": len(plan.recovered_executable_data_ranges),
            }
        ),
        "input_mode": plan.input_mode,
        "plan": {"path": plan_path.name, "sha256": sha256_file(plan_path)},
        "native_ingress_plan": ingress_binding,
        "canonical_external_sites": {
            "path": Path(canonical_external_sites).name,
            "manifest_sha256": sha256_file(
                Path(canonical_external_sites) / "manifest.json"
            ),
            "authority": "canonical-external-sites-v3",
        },
        "callback_authority": {
            "path": Path(callback_authority).name,
            "manifest_sha256": sha256_file(Path(callback_authority) / "manifest.json"),
            "authority": "callback-authority-v4",
        },
        "execution_authority": {
            "root_closure_manifest_sha256": sha256_file(
                Path(root_closure) / "manifest.json"
            ),
            "target_certificates_manifest_sha256": sha256_file(
                Path(target_certificates) / "manifest.json"
            ),
            "parametric_summaries_manifest_sha256": sha256_file(
                Path(parametric_summaries) / "manifest.json"
            ),
        },
        "sources": [
            {"path": path.name, "sha256": sha256_file(path)}
            for path in (header, source, assembly, layout_source, *ingress_sources)
        ],
        "counts": plan.payload(state_machine_sha256="")["counts"],
        "code_capability_registrations": plan.payload(
            state_machine_sha256=""
        )["code_capability_registrations"],
        "implementation_dispatch_receipt": (
            plan.implementation_dispatch_receipt.payload()
        ),
        "semantic_coverage": plan.payload(state_machine_sha256="")["semantic_coverage"],
        "execution_policy": plan.payload(state_machine_sha256="")["execution_policy"],
        "image_base_policy": plan.payload(state_machine_sha256="")["image_base_policy"],
        "blockers": list(plan.blockers),
        "policy": {
            "execution_scope": "structural-executable-v1",
            "dynamic_base": plan.fixed_image_base is None,
            "base_relocations": "complete-pe32-highlow-inventory-required",
            "raw_x87_instruction_payloads": "forbidden",
            "typed_x87_operations": TYPED_NATIVE_X87_OPERATION_FORMAT,
            "structural_execution_receipt_required": True,
            "root_callback_engine_buffers": (
                "pe-tls-engine-thread-state"
                if ingress_payload is not None else "fixed-launch-buffers"
            ),
            "nested_callback_engine_buffers": (
                "pe-tls-frame-chain"
                if ingress_payload is not None
                else "stack-local-requires-checked-runtime-frame"
            ),
            "terminal_control": (
                "modeled-environment-refined-import"
                if plan.termination_import is not None
                else "unsupported-native-halt"
            ),
        },
        "authority": "candidate generation only; static and behavioral qualification required",
    }
    write_json(out / "native-engine-package.json", result)
    return result
