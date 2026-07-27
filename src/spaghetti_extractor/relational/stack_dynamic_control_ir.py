"""Compact typed input for stack/dynamic indirect-control proof phases."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping

from ..errors import StageAInputError


STACK_DYNAMIC_CONTROL_IR_FORMAT = "stage-a-stack-dynamic-control-ir-v1"
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_U32_LIMIT = 1 << 32


class StackDynamicControlIRError(StageAInputError):
    """The cached mixed-original stack/dynamic input is malformed."""


def _u32(value: Any, field: str) -> int:
    if (
        isinstance(value, bool)
        or not isinstance(value, int)
        or not 0 <= value < _U32_LIMIT
    ):
        raise StackDynamicControlIRError(
            f"{field} must be an unsigned PE32 word"
        )
    return value


def _sha256(value: Any, field: str) -> str:
    if not isinstance(value, str) or _SHA256.fullmatch(value) is None:
        raise StackDynamicControlIRError(
            f"{field} must be a lowercase SHA-256 digest"
        )
    return value


@dataclass(frozen=True)
class StackDynamicControlRegion:
    target_id: int
    rva: int


@dataclass(frozen=True)
class StackDynamicControlSite:
    source_rva: int
    instruction_rva: int
    category: str
    is_call: bool
    continuation_rva: int | None
    target_expression: Mapping[str, Any]


@dataclass(frozen=True)
class StackDynamicControlInput:
    original_pe_sha256: str
    state_machine_sha256: str
    regions: tuple[StackDynamicControlRegion, ...]
    indirect_sites: tuple[StackDynamicControlSite, ...]
    remaining_source_rvas: tuple[int, ...]

    def to_json(self) -> dict[str, Any]:
        return {
            "format": STACK_DYNAMIC_CONTROL_IR_FORMAT,
            "inputs": {
                "original_pe_sha256": self.original_pe_sha256,
                "state_machine_sha256": self.state_machine_sha256,
            },
            "regions": [
                {"rva": region.rva, "target_id": region.target_id}
                for region in self.regions
            ],
            "indirect_sites": [
                {
                    "category": site.category,
                    "continuation_rva": site.continuation_rva,
                    "instruction_rva": site.instruction_rva,
                    "is_call": site.is_call,
                    "source_rva": site.source_rva,
                    "target_expression": dict(site.target_expression),
                }
                for site in self.indirect_sites
            ],
            "remaining_source_rvas": list(self.remaining_source_rvas),
        }


def stack_dynamic_control_input_from_plan(
    plan: Any,
    *,
    original_pe_sha256: str,
) -> StackDynamicControlInput:
    """Project the expensive mixed-original plan onto the next proof phase."""

    original_hash = _sha256(original_pe_sha256, "original PE SHA-256")
    state_hash = _sha256(
        getattr(plan, "state_machine_sha256", None),
        "state-machine SHA-256",
    )
    regions = tuple(
        StackDynamicControlRegion(
            target_id=_u32(region.target_id, "region target ID"),
            rva=_u32(region.rva, "region RVA"),
        )
        for region in plan.regions
    )
    if len({region.rva for region in regions}) != len(regions):
        raise StackDynamicControlIRError("region RVAs are not unique")
    if len({region.target_id for region in regions}) != len(regions):
        raise StackDynamicControlIRError("region target IDs are not unique")

    remaining = tuple(sorted({
        _u32(blocker.rva, "stack/dynamic blocker RVA")
        for blocker in plan.blockers
        if blocker.reason_code == "unresolved_indirect_control"
        and "stack_or_dynamic_pointer" in blocker.detail
        and blocker.rva is not None
    }))
    sites: list[StackDynamicControlSite] = []
    for site in plan.indirect_sites:
        if (
            site.category != "stack_or_dynamic_pointer"
            or site.source_rva not in remaining
        ):
            continue
        expression = site.target_expression
        if not isinstance(expression, Mapping):
            raise StackDynamicControlIRError(
                f"site 0x{site.instruction_rva:x} has no target expression"
            )
        sites.append(StackDynamicControlSite(
            source_rva=_u32(site.source_rva, "site source RVA"),
            instruction_rva=_u32(
                site.instruction_rva, "site instruction RVA"
            ),
            category=site.category,
            is_call=bool(site.is_call),
            continuation_rva=(
                None
                if site.continuation_rva is None
                else _u32(site.continuation_rva, "site continuation RVA")
            ),
            target_expression=dict(expression),
        ))
    sites.sort(key=lambda site: (site.source_rva, site.instruction_rva))
    if remaining != tuple(sorted({site.source_rva for site in sites})):
        raise StackDynamicControlIRError(
            "stack/dynamic blocker and indirect-site inventories differ"
        )
    return StackDynamicControlInput(
        original_pe_sha256=original_hash,
        state_machine_sha256=state_hash,
        regions=regions,
        indirect_sites=tuple(sites),
        remaining_source_rvas=remaining,
    )


def load_stack_dynamic_control_input(
    path: Path | str,
    *,
    original_pe_sha256: str,
    state_machine_sha256: str,
) -> StackDynamicControlInput:
    source = Path(path)
    try:
        payload = json.loads(source.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise StackDynamicControlIRError(
            f"cannot read stack/dynamic proof input: {error}"
        ) from error
    if not isinstance(payload, Mapping):
        raise StackDynamicControlIRError(
            "stack/dynamic proof input must be an object"
        )
    if payload.get("format") != STACK_DYNAMIC_CONTROL_IR_FORMAT:
        raise StackDynamicControlIRError(
            "stack/dynamic proof input has the wrong format"
        )
    inputs = payload.get("inputs")
    if not isinstance(inputs, Mapping):
        raise StackDynamicControlIRError(
            "stack/dynamic proof input has no input identities"
        )
    original_hash = _sha256(
        inputs.get("original_pe_sha256"), "original PE SHA-256"
    )
    state_hash = _sha256(
        inputs.get("state_machine_sha256"), "state-machine SHA-256"
    )
    if original_hash != _sha256(
        original_pe_sha256, "expected original PE SHA-256"
    ):
        raise StackDynamicControlIRError(
            "stack/dynamic proof input does not match the original PE"
        )
    if state_hash != _sha256(
        state_machine_sha256, "expected state-machine SHA-256"
    ):
        raise StackDynamicControlIRError(
            "stack/dynamic proof input does not match the state machine"
        )

    region_rows = payload.get("regions")
    site_rows = payload.get("indirect_sites")
    remaining_rows = payload.get("remaining_source_rvas")
    if (
        not isinstance(region_rows, list)
        or not isinstance(site_rows, list)
        or not isinstance(remaining_rows, list)
    ):
        raise StackDynamicControlIRError(
            "stack/dynamic proof inventories must be lists"
        )
    regions: list[StackDynamicControlRegion] = []
    for index, row in enumerate(region_rows):
        if not isinstance(row, Mapping):
            raise StackDynamicControlIRError(f"region {index} is not an object")
        regions.append(StackDynamicControlRegion(
            target_id=_u32(row.get("target_id"), f"region {index} target ID"),
            rva=_u32(row.get("rva"), f"region {index} RVA"),
        ))
    if len({region.rva for region in regions}) != len(regions):
        raise StackDynamicControlIRError("region RVAs are not unique")
    if len({region.target_id for region in regions}) != len(regions):
        raise StackDynamicControlIRError("region target IDs are not unique")

    sites: list[StackDynamicControlSite] = []
    for index, row in enumerate(site_rows):
        if not isinstance(row, Mapping):
            raise StackDynamicControlIRError(f"site {index} is not an object")
        expression = row.get("target_expression")
        if not isinstance(expression, Mapping):
            raise StackDynamicControlIRError(
                f"site {index} target expression is not an object"
            )
        category = row.get("category")
        is_call = row.get("is_call")
        continuation = row.get("continuation_rva")
        if category != "stack_or_dynamic_pointer" or not isinstance(
            is_call, bool
        ):
            raise StackDynamicControlIRError(
                f"site {index} has an invalid category or transfer"
            )
        sites.append(StackDynamicControlSite(
            source_rva=_u32(
                row.get("source_rva"), f"site {index} source RVA"
            ),
            instruction_rva=_u32(
                row.get("instruction_rva"),
                f"site {index} instruction RVA",
            ),
            category=category,
            is_call=is_call,
            continuation_rva=(
                None
                if continuation is None
                else _u32(continuation, f"site {index} continuation RVA")
            ),
            target_expression=dict(expression),
        ))
    sites.sort(key=lambda site: (site.source_rva, site.instruction_rva))
    remaining = tuple(sorted({
        _u32(value, f"remaining source RVA {index}")
        for index, value in enumerate(remaining_rows)
    }))
    if remaining != tuple(sorted({site.source_rva for site in sites})):
        raise StackDynamicControlIRError(
            "stack/dynamic source and site inventories differ"
        )
    return StackDynamicControlInput(
        original_pe_sha256=original_hash,
        state_machine_sha256=state_hash,
        regions=tuple(regions),
        indirect_sites=tuple(sites),
        remaining_source_rvas=remaining,
    )


__all__ = [
    "STACK_DYNAMIC_CONTROL_IR_FORMAT",
    "StackDynamicControlInput",
    "StackDynamicControlIRError",
    "StackDynamicControlRegion",
    "StackDynamicControlSite",
    "load_stack_dynamic_control_input",
    "stack_dynamic_control_input_from_plan",
]
