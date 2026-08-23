from __future__ import annotations

import sys
from pathlib import Path

from spaghetti_extractor.calls.frame import PhysicalCallFrameV2
from spaghetti_extractor.candidate.c_backend import _runtime_header
from spaghetti_extractor.candidate.native_ingress_runtime import (
    exact_tls_regions,
    render_native_ingress_assembly,
    render_native_ingress_header,
    render_native_ingress_source,
)
from spaghetti_extractor.candidate.runtime_render import _native_runtime_header


def add_ingress(
    plan: dict[str, object], *, rva: int, symbol: str,
    role: str = "export", capability: str | None = None,
    capability_lifetime: str | None = None,
) -> None:
    transport = PhysicalCallFrameV2.create(
        subject={
            "kind": "callback" if role == "callback" else "function",
            "id": f"acceptance-{rva:08x}",
            "image_selector": "native-ingress-acceptance",
        },
        transfer_kind="callback" if role == "callback" else "direct",
        target="i686-pc-windows-gnu",
        abi_dialect="pe32-i386-gnu-v1",
        calling_convention="cdecl",
        arguments=[], results=[],
        stack={
            "coordinate": "callee-entry-esp", "alignment_bytes": 4,
            "cleanup": "caller", "cleanup_bytes": 0, "reserved_bytes": 0,
        },
        preserved_state=["ebx", "ebp", "esi", "edi"],
        clobbered_state=["eax", "ecx", "edx", "eflags"],
        outcomes=["normal", "exceptional"],
    )
    descriptor = {
        "role": role,
        "target_rva": rva,
        "target_unit_id": f"unit:{rva:08x}",
        "bridge_symbol": symbol,
        "physical_frame_id": transport.frame_id,
        "physical_frame": {"transport": transport.to_payload()},
        "outcome_protocol_id": "acceptance-outcome",
        "capability_id": capability,
        "capability_lifetime": capability_lifetime,
        "lifecycle_receipt": {"status": "complete"},
    }
    plan["ingresses"].append(descriptor)
    plan["bridges"].append({"symbol": symbol})


def protocol(
    *, source: int, portal: str, handler: int | None, resumption: int | None
) -> dict[str, object]:
    return {
        "exception": {
            "code": 0xC0000094,
            "flags_mask": 0,
            "flags_value": 0,
            "parameter_count": 0,
            "continuable": True,
            "access_violation": None,
        },
        "projections": {
            "registers": ["edi"] if handler is None else [],
            "flags": [],
            "stack": [],
            "exception_record": ["ExceptionCode", "ExceptionAddress"],
            "context": [],
            "x87": [],
        },
        "escape_disposition": (
            "escape_callable_root" if handler is None else "continue_search"
        ),
        "handler_rva": handler,
        "resumption_rva": resumption,
        "gateway_handler_symbol": "spx_seh_gateway_checked",
        "portals": [{"source_rva": source, "candidate_symbol": portal}],
    }


def main() -> None:
    out = Path(sys.argv[1])
    out.mkdir(parents=True, exist_ok=True)
    plan: dict[str, object] = {
        "format": "spaghetti-extractor-native-ingress-plan-v1",
        "status": "complete",
        "ingresses": [],
        "bridges": [],
        "outcome_protocols": [{
            "id": "acceptance-outcome", "outcomes": ["normal", "exceptional"]
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
    }
    add_ingress(plan, rva=0x1010, symbol="spx_ingress_0000")
    add_ingress(
        plan, rva=0x1040, symbol="spx_ingress_0001", role="callback",
        capability="acceptance-callback",
        capability_lifetime="until_replaced_or_process_exit",
    )
    add_ingress(
        plan, rva=0x10a0, symbol="spx_ingress_0007", role="callback",
        capability="acceptance-one-shot",
        capability_lifetime="one_shot_or_process_exit",
    )
    add_ingress(
        plan, rva=0x10b0, symbol="spx_ingress_0008", role="callback",
        capability="acceptance-resource",
        capability_lifetime=(
            "until_resource_event_or_process_exit:resource_closed"
        ),
    )
    add_ingress(
        plan, rva=0x10c0, symbol="spx_ingress_0009", role="callback",
        capability="acceptance-replacement",
        capability_lifetime="until_replaced_or_process_exit",
    )
    for rva, symbol in (
        (0x1020, "spx_ingress_0002"),
        (0x1030, "spx_ingress_0003"),
        (0x1050, "spx_ingress_0004"),
        (0x1060, "spx_ingress_0005"),
        (0x1070, "spx_ingress_0006"),
    ):
        add_ingress(plan, rva=rva, symbol=symbol)
    plan["seh_protocols"] = [
        protocol(
            source=0x1050,
            portal="spx_exception_hardware_divide",
            handler=0x2050,
            resumption=0x2060,
        ),
        protocol(
            source=0x1060,
            portal="spx_exception_host_divide",
            handler=0x2070,
            resumption=0x2080,
        ),
        protocol(
            source=0x1070,
            portal="spx_exception_escape_divide",
            handler=None,
            resumption=0x2090,
        ),
    ]
    (out / "state-machine-interpreter.h").write_text(
        _runtime_header(), encoding="ascii"
    )
    (out / "native-runtime.h").write_text(
        _native_runtime_header(), encoding="ascii"
    )
    (out / "native-ingress-runtime.h").write_text(
        render_native_ingress_header(plan), encoding="ascii"
    )
    (out / "native-ingress-runtime.c").write_text(
        render_native_ingress_source(plan), encoding="ascii"
    )
    (out / "native-ingress-runtime.s").write_text(
        render_native_ingress_assembly(plan), encoding="ascii"
    )


if __name__ == "__main__":
    main()
