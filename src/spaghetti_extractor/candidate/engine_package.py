"""Deterministic source-package emission for a planned candidate engine."""

from __future__ import annotations

from pathlib import Path
from typing import Any, Iterable, Mapping

from ..artifacts.formats import NATIVE_ENGINE_PACKAGE_FORMAT
from ..pe32.stage_binary import StageAInputError
from ..util import sha256_file, write_json
from .engine_layout import render_stage_b_engine_layout_c
from .engine_render import _bridge_assembly, _wrapper_header, _wrapper_source
from .modes import STATIC_CLOSED_CANDIDATE_MODE
from .x87 import TYPED_NATIVE_X87_OPERATION_FORMAT


def write_stage_b_native_engine_package(
    *,
    state_machine: Path | None = None,
    machine_ir: Path | None = None,
    machine_ir_manifest: Path | None = None,
    recovered_executable_data: Path | str | None = None,
    entry_rva: int,
    out: Path,
    callback_targets: Iterable[int | Mapping[str, Any]] = (),
    import_iat_vas: Mapping[tuple[str, str | int], int] | None = None,
    termination_import: Mapping[str, Any] | None = None,
    base_relocation_evidence: Mapping[str, Any] | None = None,
    canonical_external_sites: Path | str | None = None,
    machine_import_profiles: Iterable[Path | str] = (),
    candidate_mode: str = STATIC_CLOSED_CANDIDATE_MODE,
    allow_deferred_potential_transfers: bool = False,
    fixed_image_base: int | None = None,
    preferred_image_base: int | None = None,
    initial_zero_ranges: Iterable[tuple[int, int]] = (),
    selected_portable_components: Iterable[Mapping[str, Any]] = (),
) -> dict[str, Any]:
    """Write deterministic wrapper sources and a fail-closed build plan."""

    from .engine import plan_stage_b_native_engine

    if (state_machine is None) == (machine_ir is None):
        raise StageAInputError("provide exactly one of state_machine or machine_ir")
    input_path = Path(state_machine if state_machine is not None else machine_ir)
    input_kind = "state_machine" if state_machine is not None else "machine_ir"
    out = Path(out)
    out.mkdir(parents=True, exist_ok=True)
    plan = plan_stage_b_native_engine(
        state_machine=state_machine,
        machine_ir=machine_ir,
        machine_ir_manifest=machine_ir_manifest,
        recovered_executable_data=recovered_executable_data,
        entry_rva=entry_rva,
        callback_targets=callback_targets,
        import_iat_vas=import_iat_vas,
        termination_import=termination_import,
        base_relocation_evidence=base_relocation_evidence,
        canonical_external_sites=canonical_external_sites,
        machine_import_profiles=machine_import_profiles,
        candidate_mode=candidate_mode,
        allow_deferred_potential_transfers=allow_deferred_potential_transfers,
        fixed_image_base=fixed_image_base,
        preferred_image_base=preferred_image_base,
        initial_zero_ranges=initial_zero_ranges,
        selected_portable_components=selected_portable_components,
    )
    plan_path = out / "native-engine-plan.json"
    write_json(plan_path, plan.payload(state_machine_sha256=sha256_file(input_path)))
    header = out / "native-engine-wrapper.h"
    source = out / "native-engine-wrapper.c"
    assembly = out / "native-engine-bridges.S"
    layout_source = out / "native-engine-layout.c"
    header.write_text(_wrapper_header(), encoding="ascii")
    source.write_text(_wrapper_source(plan), encoding="ascii")
    assembly.write_text(_bridge_assembly(plan), encoding="ascii")
    layout_source.write_text(
        render_stage_b_engine_layout_c(
            flag_storage="split-and-packed",
            include_fs_base=True,
            include_original_rva=True,
        ),
        encoding="ascii",
    )
    result = {
        "format": NATIVE_ENGINE_PACKAGE_FORMAT,
        "status": plan.status,
        input_kind: {"path": input_path.name, "sha256": sha256_file(input_path)},
        "machine_ir_manifest": (
            None
            if machine_ir_manifest is None
            else {
                "path": Path(machine_ir_manifest).name,
                "sha256": sha256_file(machine_ir_manifest),
            }
        ),
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
        "canonical_external_sites": (
            None
            if canonical_external_sites is None
            else {
                "path": Path(canonical_external_sites).name,
                "manifest_sha256": sha256_file(
                    Path(canonical_external_sites) / "manifest.json"
                ),
                "authority": "canonical-external-sites-v3",
            }
        ),
        "sources": [
            {"path": path.name, "sha256": sha256_file(path)}
            for path in (header, source, assembly, layout_source)
        ],
        "counts": plan.payload(state_machine_sha256="")["counts"],
        "callback_abis": [target.payload() for target in plan.callback_targets],
        "callback_adapter_receipts": [
            receipt.payload() for receipt in plan.callback_adapter_receipts
        ],
        "implementation_dispatch_receipt": (
            plan.implementation_dispatch_receipt.payload()
        ),
        "semantic_coverage": plan.payload(state_machine_sha256="")["semantic_coverage"],
        "execution_policy": plan.payload(state_machine_sha256="")["execution_policy"],
        "deferred_transfers": list(plan.deferred_transfers),
        "image_base_policy": plan.payload(state_machine_sha256="")["image_base_policy"],
        "diagnostic_frontiers": list(plan.diagnostic_frontiers),
        "blockers": list(plan.blockers),
        "policy": {
            "candidate_mode": plan.candidate_mode,
            "dynamic_base": plan.fixed_image_base is None,
            "base_relocations": "complete-pe32-highlow-inventory-required",
            "raw_x87_instruction_payloads": "forbidden",
            "typed_x87_operations": TYPED_NATIVE_X87_OPERATION_FORMAT,
            "static_hybrid_closure_receipt_required": (
                plan.candidate_mode == STATIC_CLOSED_CANDIDATE_MODE
            ),
            "root_callback_engine_buffers": "fixed-launch-buffers",
            "nested_callback_engine_buffers": "stack-local-requires-checked-runtime-frame",
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
