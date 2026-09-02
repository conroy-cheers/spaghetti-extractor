"""Small canonical fixtures shared by native-ingress unit tests."""

from __future__ import annotations

from spaghetti_extractor.artifacts.artifact_set import canonical_sha256_v3
from spaghetti_extractor.artifacts.formats import MACHINE_IR_FORMAT
from spaghetti_extractor.calls.frame import PhysicalCallFrameV2
from spaghetti_extractor.candidate.native_ingress_runtime import exact_tls_regions
from spaghetti_extractor.machine_ir.memory_actions import build_memory_action_graph
from spaghetti_extractor.util import sha256_bytes


def native_ingress_plan(
    entry_rva: int,
    *,
    tls_callbacks: tuple[int, ...] = (),
    callbacks: tuple[tuple[int, int], ...] = (),
) -> dict[str, object]:
    specifications = [("process_entry", entry_rva, 0, None)]
    specifications.extend(
        ("tls_callback", rva, 12, None) for rva in tls_callbacks
    )
    specifications.extend(
        ("callback", rva, cleanup, f"fixture-capability-{rva:08x}")
        for rva, cleanup in callbacks
    )
    ingresses = []
    bridges = []
    for index, (role, rva, cleanup, capability) in enumerate(specifications):
        transport = PhysicalCallFrameV2.create(
            subject={
                "kind": "callback" if role == "callback" else "function",
                "id": f"fixture-ingress-{rva:08x}",
                "image_selector": "fixture",
            },
            transfer_kind="callback" if role == "callback" else "direct",
            target="i686-pc-windows-gnu",
            abi_dialect="pe32-i386-gnu-v1",
            calling_convention="stdcall" if cleanup else "cdecl",
            arguments=[],
            results=[],
            stack={
                "coordinate": "callee-entry-esp",
                "alignment_bytes": 4,
                "cleanup": "callee" if cleanup else "caller",
                "cleanup_bytes": cleanup,
                "reserved_bytes": 0,
            },
            preserved_state=["ebx", "ebp", "esi", "edi"],
            clobbered_state=["eax", "ecx", "edx", "eflags"],
            outcomes=["normal"],
        )
        symbol = f"spx_ingress_{index:04d}"
        ingresses.append({
            "role": role,
            "target_rva": rva,
            "target_unit_id": f"unit:{rva:08x}",
            "bridge_symbol": symbol,
            "physical_frame_id": transport.frame_id,
            "physical_frame": {"transport": transport.to_payload()},
            "outcome_protocol_id": "fixture-normal-outcome",
            "capability_id": capability,
            "lifecycle_receipt": {"status": "complete"},
        })
        bridges.append({"symbol": symbol})
    core: dict[str, object] = {
        "format": "spaghetti-extractor-native-ingress-plan-v2",
        "status": "complete",
        "ingresses": ingresses,
        "bridges": bridges,
        "outcome_protocols": [{
            "id": "fixture-normal-outcome", "outcomes": ["normal"]
        }],
        "seh_protocols": [],
        "tls_layout": {
            "runtime_offset": 0,
            "runtime_control_bytes": 0x80000,
            "private_stack_bytes": 0x100000,
            "runtime_regions": exact_tls_regions(
                control_bytes=0x80000, stack_bytes=0x100000
            ),
        },
        "runtime_requirements": {"features": [
            "code_capability_registry_v1",
            "host_thread_concurrency_v1",
            "loader_lock_safe_bootstrap_v1",
            "outgoing_bridge_pe_tls_state_v1",
            "per_thread_ingress_frame_chain_v1",
            "same_thread_reentrancy_v1",
            "tls_private_stack_v1",
            "transactional_boundary_writeback_v1",
        ]},
    }
    return {**core, "plan_sha256": canonical_sha256_v3(core)}


def machine_ir_transfer(
    *,
    event: dict | None = None,
    rva: int = 0x142A,
    size: int = 6,
    mnemonic: str = "call",
    instruction_sha256: str | None = None,
) -> dict:
    instruction_digest = instruction_sha256 or sha256_bytes(b"typed-call")
    registers = {
        name: {"op": "reg", "name": name, "width": 32}
        for name in ("eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp")
    }
    flags = {
        name: {"op": "flag", "name": name}
        for name in ("cf", "zf", "sf", "of", "pf", "df")
    }
    ordered: list[dict] = []
    external: list[dict] = []
    if event is not None:
        ordered = [{
            "family": "external",
            "arguments": [],
            "register_inputs": registers,
            "flag_inputs": flags,
            "stack_inputs": [],
            **event,
        }]
        external = [{
            key: value for key, value in ordered[0].items() if key != "family"
        }]
    end = rva + size
    unit = {
        "format": MACHINE_IR_FORMAT,
        "record_kind": "unit",
        "id": f"semantic-transfer:typed-{rva:08x}",
        "status": "qualified",
        "source": {
            "original": {"rva_start": rva, "rva_end": end, "size": size},
            "contract_sha256": "a" * 64,
            "instruction_bytes_sha256": sha256_bytes(
                f"unit:{rva:08x}:{size}".encode("ascii")
            ),
            "semantic_export": None,
        },
        "instructions": [{
            "rva_start": rva,
            "rva_end": end,
            "size": size,
            "instruction_sha256": instruction_digest,
            "mnemonic": mnemonic,
            "operands": [],
            "registers_read": [],
            "registers_written": [],
            "groups": ["call"] if mnemonic == "call" else [],
        }],
        "x87_micro_ops": [],
        "control": {
            "kind": "return" if mnemonic == "ret" else "fallthrough",
            "direct_targets": [] if mnemonic == "ret" else [end],
            "has_indirect_target": False,
        },
        "semantics": {
            "pre_state": {},
            "register_writes": [],
            "flag_writes": [],
            "memory_events": [],
            "external_events": external,
            "faults": [],
            "ordered_events": ordered,
            "edge_conditions": [],
            "outcome": {"kind": "fallthrough", "target_rva": end},
            "stack_delta": 0,
            "counts": {},
            "fpu_state": None,
            "instruction_effect_schedule": None,
        },
    }
    unit["semantics"]["memory_actions"] = build_memory_action_graph(
        instructions=unit["instructions"], memory_events=[], ordered_events=ordered
    )
    return unit


__all__ = ["machine_ir_transfer", "native_ingress_plan"]
