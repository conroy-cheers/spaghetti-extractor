"""Select auxiliary source theorems using the enclosing paired proof's scope."""

from pathlib import Path

from ..components.bisimulation_readonly_contracts import check_optional_memory_source_contracts
from ..components.bisimulation_source_dependencies import qualified_dependency_inputs
from ..components.bisimulation_summary_contracts import (
    check_scalar_summary_contracts,
    scalar_summary_operations,
)
from ..components.component_c_v5 import render_component_c_headers_v5
from .portable_c_common import fail


def check_provider_source_contracts(
    *, bundle, symbols, source, source_root, output, cbmc, timeout_seconds,
    workspace, connected_components, proof_models,
):
    if scalar_summary_operations(bundle) is not None:
        package_root = source_root if source_root.is_dir() else source_root.parent
        return check_scalar_summary_contracts(
            bundle=bundle, operation_symbols=symbols,
            source_files=[package_root / "sources" / str(row["path"])
                          for row in source["files"] if str(row["path"]).endswith(".c")],
            headers=render_component_c_headers_v5(bundle, symbols), output=output,
            goto_cc=Path(cbmc).with_name("goto-cc"),
            goto_instrument=Path(cbmc).with_name("goto-instrument"),
            cbmc=Path(cbmc), timeout_seconds=timeout_seconds, workspace=workspace,
        )
    try:
        dependencies = ()
        if all(row["summary_strategy"] in {
            "image-readable-body-free-v1", "image-mutable-body-free-v1",
        } for row in proof_models["connected_components"]):
            dependencies = qualified_dependency_inputs(connected_components)
        return check_optional_memory_source_contracts(
            bundle=bundle, package=source_root, output=output, cbmc=Path(cbmc),
            timeout_seconds=timeout_seconds, workspace=workspace,
            summary_dependencies=dependencies,
        )
    except ValueError as error:
        fail(str(error))
