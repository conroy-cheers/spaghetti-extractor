"""Checked synthetic transfer-plan fixtures shared by tests and Nix gates."""

from __future__ import annotations

import json
from pathlib import Path

from spaghetti_extractor.artifacts.formats import MACHINE_IR_FORMAT
from spaghetti_extractor.machine_ir.memory_actions import build_memory_action_graph
from spaghetti_extractor.transfer.plan import write_executable_transfer_plan
from spaghetti_extractor.util import sha256_file


_SHA_A = "a" * 64
_SHA_B = "b" * 64


def transfer_row(
    *, expression: dict[str, object] | None = None
) -> dict[str, object]:
    value = expression or {
        "op": "add32",
        "args": [
            {"op": "reg", "name": "eax", "width": 32},
            {"op": "const", "value": 1, "width": 32},
        ],
    }
    return {
        "id": "semantic-transfer:fixture",
        "contract_sha256": _SHA_A,
        "instruction_bytes_sha256": _SHA_B,
        "original": {"rva_start": 0x1000, "rva_end": 0x1003, "size": 3},
        "ordered_events": [],
        "register_writes": [{"register": "eax", "value": value}],
        "flag_writes": [],
        "fpu_state": None,
        "outcome": {"kind": "fallthrough", "target_rva": 0x1003},
    }


def set_eax_return_semantics(
    row: dict[str, object], value: dict[str, object]
) -> None:
    """Give a compact function fixture an explicit EAX effect and return."""

    writes = row.setdefault("register_writes", [])
    if not isinstance(writes, list):
        raise ValueError("fixture register writes are malformed")
    writes.append({"register": "eax", "value": value})
    row["outcome"] = {"kind": "return", "value": value}


def as_machine_ir_unit(row: dict[str, object]) -> dict[str, object]:
    if row.get("format") == "spaghetti-extractor-machine-ir-v3":
        unit = json.loads(json.dumps(row))
    else:
        original = dict(row.get("original", {}))
        semantics = {
            name: row.get(name)
            for name in (
                "pre_state",
                "register_writes",
                "flag_writes",
                "memory_events",
                "external_events",
                "faults",
                "ordered_events",
                "edge_conditions",
                "outcome",
                "stack_delta",
                "counts",
                "fpu_state",
                "memory_actions",
                "instruction_effect_schedule",
            )
        }
        unit = {
            "format": "spaghetti-extractor-machine-ir-v3",
            "record_kind": "unit",
            "id": row["id"],
            "status": (
                "incomplete" if row.get("status") == "incomplete" else "qualified"
            ),
            "reachable": row.get("reachable", True),
            "source": {
                "original": original,
                "contract_sha256": row.get("contract_sha256", _SHA_A),
                "instruction_bytes_sha256": row.get(
                    "instruction_bytes_sha256", _SHA_B
                ),
                "semantic_export": None,
            },
            "instructions": _without_raw_instruction_material(
                row.get("instructions", [])
            ),
            "x87_micro_ops": row.get("x87_micro_ops", []),
            "semantics": semantics,
        }
    unit_semantics = unit["semantics"]
    if not isinstance(unit_semantics.get("memory_actions"), dict):
        unit_semantics["memory_actions"] = build_memory_action_graph(
            instructions=unit.get("instructions", []),
            memory_events=unit_semantics.get("memory_events") or [],
            ordered_events=unit_semantics.get("ordered_events") or [],
        )
    return unit


def write_fixture_transfer_plan(
    machine_ir: Path, *, pe_sha256: str = "f" * 64,
) -> Path:
    units = [
        json.loads(line)
        for line in Path(machine_ir).read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    source_map = [
        {
            "unit_id": unit["id"],
            "rva_start": unit["source"]["original"]["rva_start"],
            "contract_sha256": unit["source"]["contract_sha256"],
        }
        for unit in units
    ]
    manifest = Path(machine_ir).with_name(
        f"{Path(machine_ir).stem}-transfer-manifest.json"
    )
    manifest.write_text(
        json.dumps(
            {
                "format": MACHINE_IR_FORMAT,
                "record_kind": "manifest",
                "binary": {"sha256": pe_sha256},
                "authority_bindings": {
                    "binary": {"pe_sha256": pe_sha256},
                },
                "artifacts": {"machine_ir": {"sha256": sha256_file(machine_ir)}},
                "counts": {"units": len(units)},
                "source_map": source_map,
            },
            sort_keys=True,
        ),
        encoding="utf-8",
    )
    plan_root = Path(machine_ir).with_name(
        f"{Path(machine_ir).stem}-transfer"
    )
    write_executable_transfer_plan(
        machine_ir=machine_ir,
        machine_ir_manifest=manifest,
        out=plan_root,
    )
    return plan_root / "executable-transfer-plan.json"


def _without_raw_instruction_material(value):
    forbidden = {
        "bytes",
        "instruction_bytes",
        "opcode_bytes",
        "raw_bytes",
        "encoded_instruction",
    }
    if isinstance(value, dict):
        return {
            key: _without_raw_instruction_material(item)
            for key, item in value.items()
            if key not in forbidden
        }
    if isinstance(value, list):
        return [_without_raw_instruction_material(item) for item in value]
    return value
