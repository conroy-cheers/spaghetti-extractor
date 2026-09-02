"""Render the canonical module runtime sources without an intermediate package."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Mapping

from ..artifacts.artifact_set import canonical_sha256_v3
from ..errors import ToolkitInputError
from ..transfer.plan import load_executable_transfer_plan
from ..util import write_json
from .formats import NATIVE_INGRESS_PLAN_FORMAT
from .native_ingress_runtime import (
    render_native_ingress_assembly,
    render_native_ingress_header,
    render_native_ingress_source,
)
from .runtime_canonical import plan_module_runtime_from_canonical
from .module_runtime_layout import render_spx_runtime_state_layout_c
from .module_runtime_render import _bridge_assembly, _wrapper_header, _wrapper_source


def render_canonical_runtime_sources(
    *,
    transfer_plan: Path,
    execution_closure: Path | Mapping[str, Any],
    resolved_external_environment: Path,
    native_ingress_plan: Path,
    out: Path,
    recovered_executable_data: Path | None = None,
) -> tuple[Any, dict[str, Any], dict[str, Any], tuple[tuple[str, Path], ...]]:
    """Render the one canonical runtime and ingress source set.

    This is deliberately not an artifact boundary: the shared-runtime package
    owns and inventories every returned source directly.
    """

    transfer_path = Path(transfer_plan)
    closure_input = (
        dict(execution_closure)
        if isinstance(execution_closure, Mapping)
        else Path(execution_closure)
    )
    environment_path = Path(resolved_external_environment)
    ingress_path = Path(native_ingress_plan)
    try:
        ingress = json.loads(ingress_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ToolkitInputError(f"cannot read native ingress plan: {exc}") from exc
    if (
        not isinstance(ingress, dict)
        or ingress.get("format") != NATIVE_INGRESS_PLAN_FORMAT
    ):
        raise ToolkitInputError("native ingress plan has unsupported format")
    ingress_core = {
        key: value for key, value in ingress.items() if key != "plan_sha256"
    }
    if (
        ingress.get("plan_sha256") != canonical_sha256_v3(ingress_core)
        or ingress.get("status") != "complete"
    ):
        raise ToolkitInputError("native ingress plan is stale or incomplete")
    plan = plan_module_runtime_from_canonical(
        transfer_plan=transfer_path,
        execution_closure=closure_input,
        resolved_external_environment=environment_path,
        native_ingress_plan=ingress_path,
        recovered_executable_data=recovered_executable_data,
    )
    transfer_payload, _ = load_executable_transfer_plan(
        transfer_path, require_complete=True
    )
    machine_ir_sha256 = str(transfer_payload["bindings"]["machine_ir_sha256"])
    output = Path(out)
    output.mkdir(parents=True, exist_ok=True)
    write_json(output / "native-ingress-plan.json", ingress)
    write_json(
        output / "module-runtime-plan.json",
        plan.payload(state_machine_sha256=machine_ir_sha256),
    )
    if plan.status != "ready":
        # An incomplete checked plan is a valid diagnostic artifact, but must
        # never produce compilable sources.  Its caller packages these exact
        # blockers for the non-authorizing qualified-runtime provider.
        return plan, ingress, transfer_payload, ()
    header = output / "module-runtime.h"
    source = output / "module-runtime.c"
    assembly = output / "module-ingress-bridges.S"
    layout_source = output / "module-runtime-layout.c"
    header.write_text(_wrapper_header(), encoding="ascii")
    source.write_text(_wrapper_source(plan, ingress), encoding="ascii")
    assembly.write_text(_bridge_assembly(plan), encoding="ascii")
    layout_source.write_text(
        render_spx_runtime_state_layout_c(
            flag_storage="split-and-packed",
            include_fs_base=True,
            include_original_rva=True,
        ),
        encoding="ascii",
    )
    ingress_header = output / "native-ingress-runtime.h"
    ingress_source = output / "native-ingress-runtime.c"
    ingress_assembly = output / "native-ingress-bridges.S"
    ingress_header.write_text(
        render_native_ingress_header(ingress), encoding="ascii"
    )
    ingress_source.write_text(
        render_native_ingress_source(ingress), encoding="ascii"
    )
    ingress_assembly.write_text(
        render_native_ingress_assembly(ingress), encoding="ascii"
    )
    sources = (
        ("module_runtime_header", header),
        ("module_runtime_source", source),
        ("module_runtime_bridge_assembly", assembly),
        ("module_runtime_layout_source", layout_source),
        ("native_ingress_header", ingress_header),
        ("native_ingress_source", ingress_source),
        ("native_ingress_bridge_assembly", ingress_assembly),
    )
    return plan, ingress, transfer_payload, sources


__all__ = ["render_canonical_runtime_sources"]
