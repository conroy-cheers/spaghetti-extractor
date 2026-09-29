"""Read source handoffs and render explicitly reviewed candidate backend bindings."""
from __future__ import annotations

import json
from pathlib import Path

from ..components.comparison_package import package_file
from ..components.interface_package_v5 import ComponentInterfaceIntentV1
from ..components.service_c import materialize_service_bridge
from ..components.source_handoff import (
    load_source_export as load_source_export,
    source_export_workspace as source_export_workspace,
    services_from_source_export as services_from_source_export,
    source_private_headers as source_private_headers,
    source_export_draft as source_export_draft,
)


def render_source_service_bridges(root: Path, *, bindings: dict[str, dict],
                                  trace_services: bool = True) -> dict[str, tuple[str, dict]]:
    """Use the existing bridge generator with an explicit new backend selection.

The caller reviews all transports, adapter symbols and outcomes. Original binding
references are examples only. Native fixture resource hooks are intentionally not
inherited by a new backend; object contents/lifetimes need integration evidence.
Normal program assemblies may explicitly set trace_services=False. This removes
generated protocol logging, retaining transport, outcome predicates and their
diagnostics. Such an execution does not supply comparison service observations;
comparison preparation always generates traced bindings.
"""
    report = load_source_export(root)
    if (not isinstance(bindings, dict) or not bindings
            or any(not isinstance(identity, str) or spec is None for identity, spec in bindings.items())):
        raise ValueError('source binding requires explicit reviewed service bridges')
    if bindings.keys() - report['components'].keys():
        raise ValueError('source export has no component: '+', '.join(sorted(bindings.keys() - report['components'].keys())))
    rendered = {}
    for component_id, service_bridge in bindings.items():
        unit = report['components'][component_id]
        interface = ComponentInterfaceIntentV1.parse(json.loads(package_file(root, unit['interface']).read_text()))
        rendered[component_id] = materialize_service_bridge(dict(operation_symbols=unit['operation_symbols'],
            service_catalog=unit['contract'].get('service_catalog'), service_bridge=service_bridge), interface,
            trace_services=trace_services)
    return rendered
