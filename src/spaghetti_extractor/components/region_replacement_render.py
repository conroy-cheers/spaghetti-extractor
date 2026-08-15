"""C override-table rendering for regional replacements."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Mapping, Sequence

from ..errors import ToolkitInputError
from .region_replacement_model import (
    RegionReplacementManifest,
    _json_copy,
)
from .region_replacement_schema import _relative_path, _require_unique


def _validate_override_inventory(contracts: Sequence[RegionReplacementManifest]) -> None:
    for contract in contracts:
        nonqualified = [item["id"] for item in contract.evidence if item["status"] != "qualified"]
        if nonqualified:
            raise ToolkitInputError(
                f"replacement {contract.id} has non-qualified evidence {nonqualified}"
            )
    for name, values in (
        ("replacement ids", [item.id for item in contracts]),
        ("cluster ids", [str(item.cluster["id"]) for item in contracts]),
        ("entry unit ids", [str(item.cluster["entry_unit_id"]) for item in contracts]),
        ("entry RVAs", [int(item.cluster["entry_rva"]) for item in contracts]),
        ("C symbols", [str(item.source["symbol"]) for item in contracts]),
    ):
        _require_unique(values, f"override {name}")
    unit_ids = [unit for item in contracts for unit in item.cluster["unit_ids"]]
    _require_unique(unit_ids, "override unit ids")
    bindings = {
        (
            item.bindings["machine_ir_sha256"],
            item.bindings["baseline_program_sha256"],
        )
        for item in contracts
    }
    if len(bindings) != 1:
        raise ToolkitInputError("override manifests do not bind the same machine IR and baseline")
    spans = [
        {**span, "replacement_id": item.id}
        for item in contracts
        for span in item.cluster["rva_spans"]
    ]
    spans.sort(key=lambda span: (span["start"], span["end"], span["replacement_id"]))
    for left, right in zip(spans, spans[1:]):
        if right["start"] < left["end"]:
            raise ToolkitInputError(
                "override RVA spans overlap between "
                f"{left['replacement_id']} and {right['replacement_id']}"
            )


def _render_override_header(
    contracts: Sequence[RegionReplacementManifest], runtime_header: str
) -> str:
    prototypes = "\n".join(
        f"spx_step_result {item.source['symbol']}(spx_runtime *, spx_machine_state *);"
        for item in contracts
    )
    return f"""#ifndef SPX_REGION_OVERRIDES_H
#define SPX_REGION_OVERRIDES_H

#include <stdint.h>
#include \"{runtime_header}\"

typedef spx_step_result (*spx_region_override_fn)(
    spx_runtime *, spx_machine_state *);

typedef struct spx_region_override {{
  uint32_t entry_rva;
  spx_region_override_fn function;
  uint32_t fallback_on_unimplemented;
  const char *replacement_id;
  const char *cluster_id;
}} spx_region_override;

{prototypes}

extern const spx_region_override spx_region_overrides[];
extern const uint32_t spx_region_override_count;
const spx_region_override *spx_region_override_lookup(uint32_t entry_rva);

#endif
"""


def _render_override_source(
    contracts: Sequence[RegionReplacementManifest], fallback_ids: set[str]
) -> str:
    entries = "\n".join(
        "  { UINT32_C(%d), %s, UINT32_C(%d), %s, %s },"
        % (
            int(item.cluster["entry_rva"]),
            item.source["symbol"],
            1 if item.id in fallback_ids else 0,
            _c_string(item.id),
            _c_string(str(item.cluster["id"])),
        )
        for item in contracts
    )
    return f"""#include <stdint.h>
#include \"region-overrides.h\"

const spx_region_override spx_region_overrides[] = {{
{entries}
}};

const uint32_t spx_region_override_count =
    (uint32_t)(sizeof(spx_region_overrides) / sizeof(spx_region_overrides[0]));

const spx_region_override *spx_region_override_lookup(uint32_t entry_rva) {{
  uint32_t low = 0U, high = spx_region_override_count;
  while (low < high) {{
    uint32_t middle = low + (high - low) / 2U;
    uint32_t observed = spx_region_overrides[middle].entry_rva;
    if (observed < entry_rva) low = middle + 1U;
    else if (observed > entry_rva) high = middle;
    else return &spx_region_overrides[middle];
  }}
  return (const spx_region_override *)0;
}}
"""


def _override_entry(
    contract: RegionReplacementManifest, *, fallback_on_unimplemented: bool
) -> dict[str, Any]:
    return {
        "replacement_id": contract.id,
        "manifest_sha256": contract.manifest_sha256,
        "cluster_id": contract.cluster["id"],
        "entry_unit_id": contract.cluster["entry_unit_id"],
        "entry_rva": contract.cluster["entry_rva"],
        "fallback_on_unimplemented": fallback_on_unimplemented,
        "unit_ids": list(contract.cluster["unit_ids"]),
        "rva_spans": _json_copy(contract.cluster["rva_spans"]),
        "symbol": contract.source["symbol"],
        "source": _json_copy(contract.source),
        "support_sources": _json_copy(contract.support_sources),
    }


def _c_string(value: str) -> str:
    return json.dumps(value, ensure_ascii=True)
