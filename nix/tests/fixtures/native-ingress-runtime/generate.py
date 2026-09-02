from __future__ import annotations

import sys
from pathlib import Path

from spaghetti_extractor.calls.frame import PhysicalCallFrameV2
from spaghetti_extractor.transfer.runtime_abi import exact_runtime_header
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
    cleanup_bytes: int = 0,
    loader_lifecycle: bool = False,
    outcome_protocol_id: str = "acceptance-outcome",
    add_bridge: bool = True,
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
        calling_convention="stdcall" if cleanup_bytes else "cdecl",
        arguments=[], results=[],
        stack={
            "coordinate": "callee-entry-esp", "alignment_bytes": 4,
            "cleanup": "callee" if cleanup_bytes else "caller",
            "cleanup_bytes": cleanup_bytes, "reserved_bytes": 0,
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
        "outcome_protocol_id": outcome_protocol_id,
        "capability_id": capability,
        "capability_lifetime": capability_lifetime,
        "lifecycle_receipt": {"status": "complete"},
        "lifecycle_protocol": ({
            "kind": "reviewed_pe32_loader_lifecycle_v1",
            "role": role,
            "image_id": "native-ingress-acceptance",
            "event_source": "pe32-loader-reason-argument",
            "attach_effects": ["activate-image-generation", "activate-thread-generation"],
            "detach_effects": ["expire-thread-capabilities", "expire-image-capabilities"],
        } if loader_lifecycle else None),
    }
    plan["ingresses"].append(descriptor)
    if add_bridge:
        plan["bridges"].append({"symbol": symbol})


def protocol(
    *, source: int, portal: str, handler: int | None, resumption: int | None,
    unwind_effect_ids: tuple[str, ...] = (),
    escape_disposition: str | None = None,
    project_eip: bool = False,
    nested_record: bool = False,
) -> dict[str, object]:
    return {
        "id": f"acceptance-seh-{source:08x}",
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
            "exception_record": (
                ["ExceptionCode", "ExceptionRecord[1].ExceptionCode"]
                if nested_record else
                ["ExceptionCode", "ExceptionRecord"]
                if source == 0x1050 else
                ["ExceptionCode"] if handler is None else []
            ),
            "context": ["Eip"] if project_eip else ["eax"] if source == 0x1050 else [],
            "x87": ["all"] if source == 0x1050 else [],
        },
        "escape_disposition": (
            escape_disposition
            if escape_disposition is not None
            else "escape_callable_root" if handler is None else "continue_search"
        ),
        "handler_rva": handler,
        "resumption_rva": resumption,
        "unwind_effect_ids": list(unwind_effect_ids),
        "gateway_handler_symbol": "spx_seh_gateway_checked",
        "portals": [{"source_rva": source, "candidate_symbol": portal}],
        **({
            "address_policy": "pinned_original_layout",
            "pinned_layout_authority_id": "veto-only-wine-layout-fixture",
        } if project_eip else {}),
    }


def main() -> None:
    out = Path(sys.argv[1])
    out.mkdir(parents=True, exist_ok=True)
    plan: dict[str, object] = {
        "format": "spaghetti-extractor-native-ingress-plan-v2",
        "status": "complete",
        "ingresses": [],
        "bridges": [],
        "outcome_protocols": [{
            "id": "acceptance-outcome",
            "outcomes": ["normal", "exceptional"],
            "seh_protocol_ids": [
                "acceptance-seh-00001050",
                "acceptance-seh-00001060",
                "acceptance-seh-00001070",
                "acceptance-seh-00001160",
                "acceptance-seh-00001170",
            ],
        }, {
            "id": "acceptance-no-return", "outcomes": ["no_return"],
            "seh_protocol_ids": [],
        }, {
            "id": "acceptance-normal", "outcomes": ["normal"],
            "seh_protocol_ids": [],
        }, {
            "id": "acceptance-nested-outer",
            "outcomes": ["normal", "exceptional"],
            "seh_protocol_ids": ["acceptance-seh-00001140"],
        }, {
            "id": "acceptance-process-termination",
            "outcomes": ["exceptional"],
            "seh_protocol_ids": ["acceptance-seh-00001150"],
        }],
        "seh_protocols": [],
        "unwind_effects": [
            {"id": "semantic-transfer:effect-a", "rva": 0x2180},
            {"id": "semantic-transfer:effect-b", "rva": 0x2170},
        ],
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
        plan, rva=0x1040, symbol="spx_ingress_0001", role="callback",
        capability="zz-acceptance-during-call",
        capability_lifetime="during_call", add_bridge=False,
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
    add_ingress(
        plan, rva=0x10d0, symbol="spx_ingress_0010", role="dll_entry",
        cleanup_bytes=12, loader_lifecycle=True,
    )
    add_ingress(
        plan, rva=0x10e0, symbol="spx_ingress_0011",
        outcome_protocol_id="acceptance-no-return",
    )
    add_ingress(
        plan, rva=0x10f0, symbol="spx_ingress_0012",
        outcome_protocol_id="acceptance-normal",
    )
    add_ingress(plan, rva=0x1100, symbol="spx_ingress_0013")
    add_ingress(plan, rva=0x1110, symbol="spx_ingress_0014")
    add_ingress(plan, rva=0x1120, symbol="spx_ingress_0015")
    add_ingress(
        plan, rva=0x1130, symbol="spx_ingress_0016",
        outcome_protocol_id="acceptance-nested-outer",
    )
    add_ingress(
        plan, rva=0x1140, symbol="spx_ingress_0017",
        outcome_protocol_id="acceptance-normal",
    )
    add_ingress(
        plan, rva=0x1150, symbol="spx_ingress_0018",
        role="process_entry",
        outcome_protocol_id="acceptance-process-termination",
    )
    add_ingress(plan, rva=0x1160, symbol="spx_ingress_0019")
    add_ingress(plan, rva=0x1170, symbol="spx_ingress_0020")
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
        protocol(
            source=0x10f0,
            portal="spx_exception_disallowed_divide",
            handler=0x20a0,
            resumption=0x20b0,
        ),
        protocol(
            source=0x1140,
            portal="spx_exception_nested_divide",
            handler=0x2150,
            resumption=0x2160,
            unwind_effect_ids=(
                "semantic-transfer:effect-b",
                "semantic-transfer:effect-a",
            ),
        ),
        protocol(
            source=0x1150,
            portal="spx_exception_process_root_divide",
            handler=None,
            resumption=None,
            escape_disposition="terminate_process_root",
        ),
        protocol(
            source=0x1160,
            portal="spx_exception_pinned_retry",
            handler=0x2190,
            resumption=0x21a0,
            project_eip=True,
        ),
        protocol(
            source=0x1170,
            portal="spx_exception_nested_record",
            handler=0x21b0,
            resumption=0x21c0,
            nested_record=True,
        ),
    ]
    (out / "behavioral-c.h").write_text(
        exact_runtime_header(), encoding="ascii"
    )
    (out / "shared-module-runtime.h").write_text(
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
