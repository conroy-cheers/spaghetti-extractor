from __future__ import annotations

import unittest
from typing import Any
from unittest.mock import patch

import spaghetti_extractor.interprocedural_analysis as interprocedural_analysis

from spaghetti_extractor.call_frame_hypotheses import (
    PreservedRegisterHypothesis,
    hypothesis_id as call_frame_hypothesis_id,
)
from spaghetti_extractor.call_site_effects import (
    CallSiteEffect,
    CallSiteId,
    CallWriteSpan,
)
from spaghetti_extractor.authority_dependencies_v2 import (
    call_frame_dependency_id,
    call_frame_family_dependency_id,
    call_summary_family_node_id,
)
from spaghetti_extractor.interprocedural_analysis import (
    InterproceduralAnalysisWorkspace,
    _Influence,
    _MutableCallTarget,
    _MutableCell,
    _MutableSCCCache,
    _MutableState,
    _analyze_mutable_slot_influence,
    _call_summary_inputs,
    _call_summary_memory_frames,
    _call_summary_memory_preservation,
    _call_site_memory_frames,
    _derive_dependency_edges,
    _merge_bootstrap_callback_arguments,
    _merge_inductive_operation_provenance,
    _requires_inductive_replay,
    _summary_register_state,
    _transfer_mutable_state,
    analyze_interprocedural_control,
)
from spaghetti_extractor.indirect_target_dependency_v2 import (
    build_bounded_selector_dependency_v2,
)
from spaghetti_extractor.checked_memory_access_v2 import (
    MEMORY_ACCESS_PROPOSAL_V2_FORMAT,
)
from spaghetti_extractor.checked_memory_address_domain_v2 import (
    CONTEXTUAL_MEMORY_COVERAGE_V1_FORMAT,
    MEMORY_ADDRESS_DOMAIN_PROPOSAL_V2_FORMAT,
)
from spaghetti_extractor.machine_ir_authority_v2 import machine_ir_sha256
from spaghetti_extractor.machine_abi import (
    NormalCallABIPremise,
    build_pe32_normal_call_abi_premise,
    resolve_machine_call_abi,
)
from spaghetti_extractor.provenance_domain import ValueOrigin
from spaghetti_extractor.hybrid_authority_v2 import (
    BinaryBinding,
    EvidenceIssue,
    EvidenceIssueKind,
    FiniteAlternatives,
    GlobalSlotInvariant,
    EventBinding,
    UnitBinding,
)


IMAGE_BASE = 0x400000
SLOT = 0x430000
REGISTERS = ("eax", "ebp", "ebx", "ecx", "edi", "edx", "esi", "esp")


def reg(name: str) -> dict[str, object]:
    return {"op": "reg", "name": name, "width": 32}


def const(value: int) -> dict[str, object]:
    return {"op": "const", "value": value, "width": 32}


def load(address: object) -> dict[str, object]:
    return {"op": "load", "width": 4, "address": address}


def slot_write(value: object) -> dict[str, object]:
    return {"kind": "write", "width": 4, "address": const(SLOT), "value": value}


def slot_read() -> dict[str, object]:
    return {"kind": "read", "width": 4, "address": const(SLOT)}


def stack_write(offset: int, value: object) -> dict[str, object]:
    return {
        "kind": "write",
        "width": 4,
        "address": {"op": "add32", "args": [reg("esp"), const(offset)]},
        "value": value,
    }


def unit(
    identifier: str,
    rva: int,
    *,
    calls: tuple[int, ...] = (),
    writes: tuple[dict[str, object], ...] = (),
    memory: tuple[dict[str, object], ...] = (),
) -> dict[str, object]:
    events = [
        {
            "kind": "internal_call",
            "target_rva": target,
            "register_inputs": {register: reg(register) for register in REGISTERS},
        }
        for target in calls
    ]
    return {
        "id": identifier,
        "source": {"original": {"rva_start": rva, "rva_end": rva + 1}},
        "instructions": [],
        "semantics": {
            "outcome": {"kind": "fallthrough", "target_rva": rva + 1},
            "register_writes": list(writes),
            "memory_events": list(memory),
            "external_events": events,
            "ordered_events": [*memory, *events],
        },
    }


def edge(source: str, target: str) -> dict[str, object]:
    return {"source_unit_id": source, "target_unit_id": target}


def call_edge(source: str, target: str, event_index: int = 0) -> dict[str, object]:
    return {
        "source_unit_id": source,
        "source_event_index": event_index,
        "target_unit_id": target,
    }


def preserved_register_hypothesis(
    unit_id: str, register: str
) -> dict[str, object]:
    return PreservedRegisterHypothesis(
        id=call_frame_hypothesis_id(unit_id, 0, register),
        unit_id=unit_id,
        event_index=0,
        transfer_kind="internal_call",
        register=register,
        proposal_source="fixture-v1",
        proof_authority=False,
    ).as_json()


def call_effect(
    unit_id: str,
    *,
    preserved: frozenset[str] | None,
    dependencies: tuple[str, ...] = (),
    transfer_kind: str = "internal_call",
) -> dict[str, object]:
    complete = preserved is not None
    return CallSiteEffect(
        site=CallSiteId(unit_id, 0),
        transfer_kind=transfer_kind,
        status="complete" if complete else "incomplete",
        register_frame_status="complete" if complete else "incomplete",
        preserved_registers=frozenset() if preserved is None else preserved,
        stack_frame_status="not_applicable",
        stack_cleanup_bytes=None,
        result_status="not_applicable",
        outputs=(),
        memory_frame_status="not_applicable",
        memory_preserved=False,
        memory_writes=(),
        dependencies=dependencies,
        failure_codes=() if complete else ("call_register_frame_incomplete",),
    ).as_json()


def indirect_exit(
    identity: str,
    source: str,
    *,
    event_index: int = 0,
    kind: str = "indirect_call",
) -> dict[str, object]:
    return {
        "id": identity,
        "source_unit_id": source,
        "source_event_index": event_index,
        "source_rva": 0x1000,
        "kind": kind,
        "target_expression": reg("eax"),
    }


def incomplete_recovery(exit_row: dict[str, object]) -> dict[str, object]:
    return {
        **exit_row,
        "status": "incomplete",
        "closure": "unresolved",
        "target_rvas": [],
        "target_unit_ids": [],
        "external_targets": [],
        "failure": {"code": "unsupported_target_expression"},
    }


def recovered(
    exit_row: dict[str, object],
    *targets: str,
) -> dict[str, object]:
    return {
        **exit_row,
        "status": "recovered",
        "closure": "checked_finite_fixture",
        "target_rvas": [],
        "target_unit_ids": list(targets),
        "external_targets": [],
        "failure": None,
    }


def bounded_table_recovery(
    exit_row: dict[str, object], *targets: tuple[str, int]
) -> dict[str, object]:
    values = list(range(len(targets)))
    result: dict[str, object] = {
        **exit_row,
        "status": "recovered",
        "closure": "checked_finite_target_inventory",
        "recovery_kind": "pe32_indexed_absolute_jump_table",
        "failure": None,
        "index": {
            "expression": reg("eax"),
            "lower_inclusive": 0,
            "upper_exclusive": len(targets),
            "values": values,
            "value_count": len(targets),
            "dataflow_evidence": None,
            "remap": None,
            "bound_evidence": [{
                "source_unit_id": "bound",
                "upper_exclusive": len(targets),
                "sources": ["guard"],
            }],
        },
        "table": {
            "entry_width": 4,
            "entry_count": len(targets),
            "index_values": values,
            "contiguous": True,
            "bytes_sha256": "a" * 64,
            "inventory_sha256": "b" * 64,
        },
        "entries": [
            {"index": index, "entry_rva": 0x3000 + index * 4, "target_rva": rva}
            for index, (_unit_id, rva) in enumerate(targets)
        ],
        "target_rvas": sorted({rva for _unit_id, rva in targets}),
        "target_unit_ids": [unit_id for unit_id, _rva in targets],
        "external_targets": [],
        "unit_binding": {
            "status": "complete",
            "resolved_target_rvas": sorted({rva for _unit_id, rva in targets}),
            "unmaterialized_target_rvas": [],
        },
    }
    result["target_set_dependency"] = build_bounded_selector_dependency_v2(result)
    return result


def summary_row(identifier: str, rva: int) -> dict[str, object]:
    return {
        "target_unit_id": identifier,
        "target_rva": rva,
        "status": "complete",
        "preserved_registers": ["ebp", "ebx", "edi", "esi"],
        "stack_cleanup": {
            "status": "complete",
            "stack_delta": 0,
            "return_stack_offset": 4,
        },
        "result_register_origins": {"status": "complete", "registers": {}},
        "return_behavior": {
            "status": "complete",
            "may_return": True,
            "may_not_return": False,
        },
        "blocker_codes": [],
    }


def slot_invariant(
    initializer: str,
    initializer_rva: int,
    *values: int,
    tainted: bool = False,
    slot_address: int = SLOT,
    event_index: int | None = None,
) -> GlobalSlotInvariant:
    binary = BinaryBinding("a" * 64, "b" * 64)
    binding = UnitBinding(
        binary=binary,
        unit_id=initializer,
        rva_start=initializer_rva,
        rva_end=initializer_rva + 1,
        unit_sha256="c" * 64,
        instruction_bytes_sha256="d" * 64,
    )
    exact_binding = (
        binding
        if event_index is None
        else EventBinding(
            unit=binding,
            event_index=event_index,
            event_kind="read",
            instruction_rva=initializer_rva,
            event_sha256="e" * 64,
        )
    )
    return GlobalSlotInvariant(
        binding=exact_binding,
        slot_rva=slot_address - IMAGE_BASE,
        width_bytes=4,
        invariant_kind=(
            "finite_set" if event_index is None else "finite_set_at_read"
        ),
        alternatives=FiniteAlternatives.of(
            [
                {"kind": "exact_bits", "value": value, "width_bits": 32}
                for value in values
            ],
            maximum=max(1, len(values)),
        ),
        issues=(
            EvidenceIssue(
                EvidenceIssueKind.MISSING,
                "global_slot_unknown_write_taint",
                "a reachable overwrite has unknown value",
            ),
        )
        if tainted
        else (),
    )


def summary_adapter(**kwargs: Any) -> dict[str, object]:
    units = kwargs["units"]
    roots = set(kwargs["roots"])
    internal_edges = kwargs["internal_call_edges"]
    recoveries = kwargs["recovered_indirect_targets"]
    assert isinstance(units, list)
    assert isinstance(internal_edges, list)
    assert isinstance(recoveries, list)
    by_id = {str(row["id"]): row for row in units}
    by_rva = {
        int(row["source"]["original"]["rva_start"]): str(row["id"])
        for row in units
    }
    roots.update(
        str(raw["target_unit_id"])
        for raw in internal_edges
        if isinstance(raw.get("target_unit_id"), str)
        and raw["target_unit_id"] in by_id
    )
    roots.update(
        target
        for raw in recoveries
        if raw.get("status") == "recovered"
        for target in raw.get("target_unit_ids", [])
        if isinstance(target, str) and target in by_id
    )
    for row in units:
        semantics = row.get("semantics")
        events = (
            semantics.get("external_events")
            if isinstance(semantics, dict)
            else None
        )
        for event in events if isinstance(events, list) else ():
            if event.get("kind") != "internal_call":
                continue
            target = by_rva.get(event.get("target_rva"))
            if target is not None:
                roots.add(target)
    pending = list(roots)
    while pending:
        source = pending.pop()
        for raw in internal_edges:
            if raw.get("source_unit_id") != source:
                continue
            target = raw.get("target_unit_id")
            if isinstance(target, str) and target not in roots:
                roots.add(target)
                pending.append(target)
        for raw in recoveries:
            if raw.get("source_unit_id") != source or raw.get("status") != "recovered":
                continue
            for target in raw.get("target_unit_ids", []):
                if isinstance(target, str) and target not in roots:
                    roots.add(target)
                    pending.append(target)
    rows = [
        summary_row(
            identifier,
            int(by_id[identifier]["source"]["original"]["rva_start"]),
        )
        for identifier in sorted(roots)
    ]
    return {
        "status": "complete",
        "fixed_point_complete": True,
        "fixed_point_rounds": 1,
        "recursive_summary_roots": [],
        "summaries": rows,
    }


def legacy_adapter(operation: dict[str, object], **_kwargs: Any) -> dict[str, object]:
    resolutions = operation.get("resolutions")
    return {
        "resolutions": list(resolutions) if isinstance(resolutions, list) else []
    }


class InterproceduralAnalysisTests(unittest.TestCase):
    def test_normal_call_premise_closes_only_register_summary_family(self) -> None:
        premise = build_pe32_normal_call_abi_premise()
        exit_row = indirect_exit("exit:a:0", "a")
        summaries = {
            "summaries": [summary_row("a", 0x1000)],
        }
        effect = call_effect(
            "a",
            preserved=frozenset(premise.preserved_registers),
            dependencies=(premise.dependency_id,),
            transfer_kind="indirect_call",
        )

        dependencies = _derive_dependency_edges(
            units=[unit("a", 0x1000)],
            roots=["a"],
            direct_edges=[],
            internal_call_edges=[],
            indirect_exits=[exit_row],
            summaries=summaries,
            recoveries=[incomplete_recovery(exit_row)],
            call_site_effects=[effect],
            normal_call_abi_premise=premise,
            finite_value_budget=8,
        )

        register_node = call_summary_family_node_id("a", "register", "edi")
        aggregate_node = "call-summary:a"
        self.assertIn((premise.dependency_id, register_node), dependencies)
        self.assertNotIn(("exit:a:0", register_node), dependencies)
        self.assertIn(("exit:a:0", aggregate_node), dependencies)

    def _mutable_replay(
        self,
        *,
        units: list[dict[str, object]],
        roots: list[str],
        cache: _MutableSCCCache,
        direct: list[dict[str, object]] | None = None,
        calls: list[dict[str, object]] | None = None,
        preserved: dict[int, frozenset[str]] | None = None,
    ):
        return _analyze_mutable_slot_influence(
            units=units,
            roots=roots,
            direct_edges=direct or [],
            internal_call_edges=calls or [],
            recovered_indirect_edges=[],
            indirect_exits=[],
            image_base=IMAGE_BASE,
            image_size=0x100000,
            finite_value_budget=8,
            checked_nonimage_stack_units=frozenset(),
            call_preserved_registers=preserved or {},
            call_stack_cleanup={},
            call_result_relations={},
            call_memory_result_relations={},
            call_memory_frames={},
            global_slot_invariants=[],
            writable_image_ranges=(),
            scc_cache=cache,
        )

    def test_complete_callback_registration_seeds_callback_root_arguments(self) -> None:
        observed: list[tuple[tuple[str, ...], object]] = []
        interface_origin = ValueOrigin(
            "interface_object", ("f" * 64, "IThing")
        )

        def resolver(**kwargs: Any) -> dict[str, object]:
            observed.append((
                tuple(sorted(kwargs["roots"])),
                kwargs.get("initial_root_argument_origins"),
            ))
            return {
                "resolutions": [],
                "call_site_effects": [],
                "callback_registrations": [{
                    "status": "complete",
                    "target_unit_ids": ["callback"],
                    "callback_entry_arguments": [{
                        "argument_index": 0,
                        "origins": [interface_origin.as_json()],
                    }],
                }],
            }

        result = self._run(
            units=[unit("root", 0x1000), unit("callback", 0x2000)],
            roots=["root"],
            resolver=resolver,
        )

        self.assertEqual(result.fixed_point["status"], "complete")
        self.assertTrue(any(
            roots == ("callback", "root")
            and isinstance(arguments, dict)
            and arguments.get("callback", {}).get(0)
            == frozenset({interface_origin})
            for roots, arguments in observed
        ))

        observed.clear()
        self._run(
            units=[unit("callback", 0x2000)],
            roots=["callback"],
            resolver=resolver,
        )
        self.assertFalse(any(
            isinstance(arguments, dict) and arguments.get("callback")
            for _roots, arguments in observed
        ))

    def test_callback_root_growth_adds_entry_without_defining_callees(self) -> None:
        summary_entries: list[tuple[str, ...]] = []

        def summaries(**kwargs: Any) -> dict[str, object]:
            summary_entries.append(tuple(sorted(kwargs["roots"])))
            return summary_adapter(**kwargs)

        def resolver(**_kwargs: Any) -> dict[str, object]:
            return {
                "resolutions": [],
                "call_site_effects": [],
                "callback_registrations": [{
                    "status": "complete",
                    "target_unit_ids": ["callback"],
                    "callback_entry_arguments": [],
                }],
            }

        result = self._run(
            units=[unit("entry", 0x1000), unit("callback", 0x2000)],
            roots=["entry"],
            resolver=resolver,
            summary_resolver=summaries,
        )

        self.assertEqual(result.fixed_point["status"], "complete")
        self.assertTrue(summary_entries)
        self.assertIn(("entry",), summary_entries)
        self.assertIn(("callback", "entry"), summary_entries)

    def test_unreachable_incomplete_structural_summary_is_not_required(self) -> None:
        def summaries(**kwargs: Any) -> dict[str, object]:
            result = summary_adapter(**kwargs)
            rows = result["summaries"]
            assert isinstance(rows, list)
            for row in rows:
                if row.get("target_unit_id") == "dead-callee":
                    row["status"] = "incomplete"
                    row["blocker_codes"] = ["dead_fixture_frontier"]
            result["status"] = "incomplete"
            return result

        result = self._run(
            units=[
                unit("entry", 0x1000),
                unit("dead-caller", 0x2000, calls=(0x3000,)),
                unit("dead-callee", 0x3000),
            ],
            roots=["entry"],
            resolver=lambda **_kwargs: {"resolutions": []},
            summary_resolver=summaries,
        )

        self.assertTrue(result.complete, result.fixed_point)
        dead = next(
            row
            for row in result.call_summaries["summaries"]
            if row["target_unit_id"] == "dead-callee"
        )
        self.assertEqual(dead["status"], "incomplete")

    def test_call_site_memory_frames_use_independent_family_status(self) -> None:
        abi = resolve_machine_call_abi("pe32-cdecl-v1")
        assert abi is not None

        def effect(
            unit_id: str,
            *,
            memory_status: str,
            writes: tuple[CallWriteSpan, ...] = (),
        ) -> dict[str, object]:
            complete = memory_status == "complete"
            return CallSiteEffect(
                site=CallSiteId(unit_id, 0),
                transfer_kind="internal_call",
                status="incomplete",
                register_frame_status="incomplete",
                preserved_registers=frozenset(),
                stack_frame_status="complete",
                stack_cleanup_bytes=0,
                result_status="complete",
                outputs=(),
                memory_frame_status=memory_status,
                memory_preserved=complete and not writes,
                memory_writes=writes if complete else (),
                abi=abi,
                argument_words=0,
                failure_codes=("register_frame_unknown",),
            ).as_json()

        frames = _call_site_memory_frames(
            [
                effect("preserved", memory_status="complete"),
                effect(
                    "writer",
                    memory_status="complete",
                    writes=(CallWriteSpan(ValueOrigin("exact", (SLOT,)), 4),),
                ),
                effect("unknown", memory_status="incomplete"),
            ],
            finite_value_budget=4,
        )

        self.assertEqual(frames, {
            CallSiteId("preserved", 0): (),
            CallSiteId("writer", 0): (
                CallWriteSpan(ValueOrigin("exact", (SLOT,)), 4),
            ),
        })

    def test_memory_preservation_requires_framed_effect_closure(self) -> None:
        def summary(
            unit_id: str,
            rva: int,
            *,
            writes: bool = False,
            external: bool = False,
            dependencies: list[str] | None = None,
        ) -> dict[str, object]:
            return {
                "target_unit_id": unit_id,
                "target_rva": rva,
                "status": "complete",
                "memory_effects": {
                    "status": "complete",
                    "local_sites": (
                        [{"kind": "write"}] if writes else [{"kind": "read"}]
                    ),
                },
                "world_effects": {
                    "status": "complete",
                    "external_sites": ([{"kind": "external_call"}] if external else []),
                },
                "target_dependencies": dependencies or [],
            }

        result = _call_summary_memory_preservation(
            {
                "summaries": [
                    summary("leaf", 0x2000),
                    summary(
                        "wrapper",
                        0x2100,
                        dependencies=["call-summary:leaf"],
                    ),
                    summary("writer", 0x2200, writes=True),
                    summary("external", 0x2300, external=True),
                    summary(
                        "unknown",
                        0x2400,
                        dependencies=["indirect-exit:missing"],
                    ),
                    {
                        **summary("private-writer", 0x2500, writes=True),
                        "caller_memory_frame": {
                            "status": "complete",
                            "preserved": True,
                            "writes": [],
                        },
                    },
                ]
            },
            image_base=IMAGE_BASE,
        )

        self.assertEqual(
            set(result),
            {
                IMAGE_BASE + 0x2000,
                IMAGE_BASE + 0x2100,
                IMAGE_BASE + 0x2500,
            },
        )

    def test_complete_caller_memory_frames_are_parsed_fail_closed(self) -> None:
        exact = {"kind": "exact", "key": [SLOT]}
        frame = {
            "status": "complete",
            "preserved": False,
            "writes": [{"base": exact, "size": 4}],
        }
        result = _call_summary_memory_frames(
            {
                "summaries": [
                    {
                        "target_rva": 0x2000,
                        "status": "complete",
                        "caller_memory_frame": frame,
                    },
                    {
                        "target_rva": 0x2100,
                        "status": "complete",
                        "caller_memory_frame": {
                            "status": "complete",
                            "preserved": True,
                            "writes": [],
                        },
                    },
                    {
                        "target_rva": 0x2200,
                        "status": "complete",
                        "caller_memory_frame": {
                            **frame,
                            "writes": [
                                {"base": exact, "size": 4},
                                {"base": exact, "size": 4},
                            ],
                        },
                    },
                    {
                        "target_rva": 0x2300,
                        "status": "incomplete",
                        "caller_memory_frame": frame,
                    },
                ]
            },
            image_base=IMAGE_BASE,
            finite_value_budget=4,
        )

        self.assertEqual(result, {
            IMAGE_BASE + 0x2000: (
                CallWriteSpan(ValueOrigin("exact", (SLOT,)), 4),
            ),
            IMAGE_BASE + 0x2100: (),
            IMAGE_BASE + 0x2300: (
                CallWriteSpan(ValueOrigin("exact", (SLOT,)), 4),
            ),
        })

    def test_partial_summary_families_remain_independently_usable(self) -> None:
        (
            preserved,
            _clobbered,
            _register_frame_completeness,
            cleanup,
            results,
            memory_results,
        ) = _call_summary_inputs(
            {
                "summaries": [{
                    "target_rva": 0x2000,
                    "status": "incomplete",
                    "preserved_registers": ["ebx", "esi"],
                    "register_preservation": {"status": "complete"},
                    "stack_cleanup": {"status": "incomplete"},
                    "result_register_origins": {
                        "status": "complete",
                        "registers": {
                            "eax": {"kind": "input_register", "register": "ecx"},
                        },
                    },
                    "result_memory_origins": {
                        "status": "complete",
                        "locations": [{
                            "location": {
                                "kind": "exact",
                                "key": [SLOT],
                            },
                            "value": {
                                "kind": "typed_origins",
                                "origins": [{
                                    "kind": "resource",
                                    "key": ["fixture-resource"],
                                }],
                            },
                        }],
                    },
                }],
            },
            image_base=IMAGE_BASE,
        )

        address = IMAGE_BASE + 0x2000
        self.assertEqual(preserved[address], frozenset({"ebx", "esi"}))
        self.assertNotIn(address, cleanup)
        self.assertEqual(
            results[address]["eax"],
            [{"kind": "input_register", "register": "ecx"}],
        )
        self.assertEqual(
            memory_results[address],
            ({
                "location": {"kind": "exact", "key": [SLOT]},
                "value": {
                    "kind": "typed_origins",
                    "origins": [{
                        "kind": "resource",
                        "key": ["fixture-resource"],
                    }],
                },
            },),
        )

    def test_checked_partial_register_atoms_remain_usable(self) -> None:
        (
            preserved,
            _clobbered,
            _register_frame_completeness,
            cleanup,
            results,
            memory_results,
        ) = _call_summary_inputs(
            {
                "summaries": [{
                    "target_rva": 0x2000,
                    "status": "incomplete",
                    "preserved_registers": ["esi"],
                    "register_preservation": {
                        "status": "incomplete",
                        "checked_preserved_registers": ["esi"],
                    },
                    "stack_cleanup": {"status": "incomplete"},
                    "result_register_origins": {"status": "incomplete"},
                    "result_memory_origins": {"status": "incomplete"},
                }],
            },
            image_base=IMAGE_BASE,
        )

        self.assertEqual(
            preserved,
            {IMAGE_BASE + 0x2000: frozenset({"esi"})},
        )
        self.assertEqual(cleanup, {})
        self.assertEqual(results, {})
        self.assertEqual(memory_results, {})

    def test_mixed_internal_external_call_keeps_opaque_memory_alternative(self) -> None:
        source_rva = SLOT + 4 - IMAGE_BASE
        destination_rva = SLOT - IMAGE_BASE
        state = _MutableState(
            registers=tuple((register, _Influence()) for register in REGISTERS),
            memory=((
                destination_rva,
                _MutableCell(_Influence(slot_rvas=frozenset({destination_rva}))),
            ),),
            stack=((
                0,
                _MutableCell(_Influence(slot_rvas=frozenset({source_rva}))),
            ),),
            esp_offset=0,
        )
        helper_address = IMAGE_BASE + 0x2000
        output = _transfer_mutable_state(
            unit("call", 0x1000, calls=(0x2000,)),
            state,
            unit_id="call",
            image_base=IMAGE_BASE,
            image_size=0x100000,
            maximum=8,
            checked_nonimage_stack=True,
            call_targets=(
                _MutableCallTarget(0, "helper", helper_address),
                _MutableCallTarget(0, "", None),
            ),
            call_preserved_registers={},
            call_stack_cleanup={helper_address: 0},
            call_result_relations={},
            call_memory_result_relations={
                helper_address: ({
                    "location": {"kind": "exact", "key": [SLOT]},
                    "value": {"kind": "input_stack_word", "offset": 4},
                },),
            },
            call_memory_frames={},
            writable_image_ranges=((SLOT, SLOT + 8),),
        )

        destination = dict(output.memory)[destination_rva]
        self.assertTrue(destination.tainted)
        self.assertEqual(
            destination.value.slot_rvas,
            frozenset({destination_rva, source_rva}),
        )

    def test_mutable_call_frame_taints_only_overlapping_image_slots(self) -> None:
        destination_rva = SLOT - IMAGE_BASE
        child_rva = destination_rva + 4
        state = _MutableState(
            registers=tuple((register, _Influence()) for register in REGISTERS),
            memory=(
                (destination_rva, _MutableCell(_Influence())),
                (child_rva, _MutableCell(_Influence())),
            ),
            esp_offset=0,
        )
        helper_address = IMAGE_BASE + 0x2000
        common = {
            "unit": unit("call", 0x1000, calls=(0x2000,)),
            "state": state,
            "unit_id": "call",
            "image_base": IMAGE_BASE,
            "image_size": 0x100000,
            "maximum": 8,
            "checked_nonimage_stack": True,
            "call_targets": (
                _MutableCallTarget(0, "helper", helper_address),
            ),
            "call_preserved_registers": {},
            "call_stack_cleanup": {helper_address: 0},
            "call_result_relations": {},
            "call_memory_result_relations": {},
            "writable_image_ranges": ((SLOT, SLOT + 8),),
        }

        disjoint = _transfer_mutable_state(
            call_memory_frames={
                0: (
                    CallWriteSpan(ValueOrigin("exact", (SLOT + 4,)), 4),
                ),
            },
            **common,
        )
        overlapping = _transfer_mutable_state(
            call_memory_frames={
                0: (
                    CallWriteSpan(ValueOrigin("exact", (SLOT,)), 4),
                ),
            },
            **common,
        )
        unknown = _transfer_mutable_state(
            call_memory_frames={},
            **common,
        )
        parametric = _transfer_mutable_state(
            call_memory_frames={
                0: (
                    CallWriteSpan(
                        ValueOrigin(
                            "parametric_location",
                            (0, (("input_stack_word", 4, 1),)),
                        ),
                        4,
                    ),
                ),
            },
            **common,
        )

        disjoint_memory = dict(disjoint.memory)
        overlapping_memory = dict(overlapping.memory)
        self.assertFalse(disjoint_memory[destination_rva].tainted)
        self.assertTrue(disjoint_memory[child_rva].tainted)
        self.assertTrue(overlapping_memory[destination_rva].tainted)
        self.assertFalse(overlapping_memory[child_rva].tainted)
        self.assertTrue(all(cell.tainted for _, cell in unknown.memory))
        self.assertTrue(unknown.unknown_write)
        self.assertTrue(all(cell.tainted for _, cell in parametric.memory))
        self.assertTrue(parametric.unknown_write)

    def test_partial_stack_overwrite_taints_overlapping_argument_word(self) -> None:
        source_rva = SLOT - IMAGE_BASE
        state = _MutableState(
            registers=tuple((register, _Influence()) for register in REGISTERS),
            stack=((
                0,
                _MutableCell(_Influence(slot_rvas=frozenset({source_rva}))),
            ),),
            esp_offset=0,
        )
        overwrite = unit(
            "overwrite",
            0x1000,
            memory=({
                "kind": "write",
                "width": 1,
                "address": {
                    "op": "add32",
                    "args": [reg("esp"), const(1)],
                },
                "value": const(0),
            },),
        )
        output = _transfer_mutable_state(
            overwrite,
            state,
            unit_id="overwrite",
            image_base=IMAGE_BASE,
            image_size=0x100000,
            maximum=8,
            checked_nonimage_stack=True,
            call_targets=(),
            call_preserved_registers={},
            call_stack_cleanup={},
            call_result_relations={},
            call_memory_result_relations={},
            call_memory_frames={},
            writable_image_ranges=(),
        )

        self.assertTrue(dict(output.stack)[0].tainted)

    def _run(
        self,
        *,
        units: list[dict[str, object]],
        roots: list[str],
        direct: list[dict[str, object]] | None = None,
        calls: list[dict[str, object]] | None = None,
        exits: list[dict[str, object]] | None = None,
        proposal: list[dict[str, object]] | None = None,
        inductive: list[dict[str, object]] | None = None,
        inductive_frames: list[dict[str, object]] | None = None,
        globals: list[GlobalSlotInvariant] | None = None,
        checked_stack_units: list[str] | None = None,
        resolver,
        budget: int = 8,
        proposal_only: bool = False,
        authority_only: bool = False,
        internal_contracts: dict[str, dict[str, object]] | None = None,
        summary_resolver=summary_adapter,
        static_data_reader=None,
        proposal_static_data_reader=None,
        writable_image_ranges: list[tuple[int, int]] | None = None,
        bind_memory_accesses: bool = False,
        progress=None,
        normal_call_abi_premise: NormalCallABIPremise | None = None,
        workspace: InterproceduralAnalysisWorkspace | None = None,
    ):
        exit_rows = exits or []
        static = [incomplete_recovery(row) for row in exit_rows]
        with (
            patch(
                "spaghetti_extractor.interprocedural_analysis."
                "derive_internal_call_preservation_summaries",
                side_effect=summary_resolver,
            ),
            patch(
                "spaghetti_extractor.interprocedural_analysis."
                "recover_external_interface_targets",
                side_effect=resolver,
            ),
            patch(
                "spaghetti_extractor.interprocedural_analysis."
                "legacy_value_provenance_view",
                side_effect=legacy_adapter,
            ),
        ):
            return analyze_interprocedural_control(
                units=units,
                roots=roots,
                direct_edges=direct or [],
                internal_call_edges=calls or [],
                indirect_exits=exit_rows,
                static_recoveries=static,
                import_abis={},
                imports=[],
                image_base=IMAGE_BASE,
                pe_sha256=("a" * 64 if bind_memory_accesses else None),
                machine_ir_sha256=(
                    machine_ir_sha256(units) if bind_memory_accesses else None
                ),
                static_data_reader=static_data_reader,
                proposal_static_data_reader=proposal_static_data_reader,
                writable_image_ranges=writable_image_ranges or [],
                proposal_recoveries=proposal or [],
                inductive_hypothesis_recoveries=inductive or [],
                inductive_hypothesis_call_frames=inductive_frames or [],
                global_slot_invariants=globals or [],
                checked_nonimage_stack_units=checked_stack_units or [],
                normal_call_abi_premise=normal_call_abi_premise,
                finite_value_budget=budget,
                proposal_only=proposal_only,
                authority_only=authority_only,
                internal_function_contracts=internal_contracts,
                progress=progress,
                workspace=workspace,
            )

    def test_progress_reports_each_pass_and_evaluation(self) -> None:
        observed: list[tuple[str, dict[str, object]]] = []

        result = self._run(
            units=[unit("root", 0x1000)],
            roots=["root"],
            resolver=lambda **_kwargs: {"resolutions": []},
            progress=lambda phase, details: observed.append(
                (phase, dict(details))
            ),
        )

        self.assertTrue(result.complete)
        self.assertEqual(
            [
                details["pass_kind"]
                for phase, details in observed
                if phase == "pass_started"
            ],
            ["discovery", "cold"],
        )
        self.assertEqual(
            [
                details["pass_kind"]
                for phase, details in observed
                if phase == "pass_finished"
            ],
            ["discovery", "cold"],
        )
        self.assertTrue(
            all(
                details["stable"]
                for phase, details in observed
                if phase == "evaluation_finished"
            )
        )

    def test_workspace_reuses_exact_results_across_invocations(self) -> None:
        workspace = InterproceduralAnalysisWorkspace()
        observed: list[tuple[str, dict[str, object]]] = []
        summary_calls = 0

        def summaries(**kwargs: object) -> dict[str, object]:
            nonlocal summary_calls
            summary_calls += 1
            return summary_adapter(**kwargs)

        arguments = {
            "units": [unit("root", 0x1000)],
            "roots": ["root"],
            "resolver": lambda **_kwargs: {"resolutions": []},
            "summary_resolver": summaries,
            "workspace": workspace,
        }
        first = self._run(**arguments)
        first_summary_calls = summary_calls
        second = self._run(
            **arguments,
            progress=lambda phase, details: observed.append(
                (phase, dict(details))
            ),
        )

        self.assertEqual(
            first.fixed_point["authority_artifact_sha256"],
            second.fixed_point["authority_artifact_sha256"],
        )
        self.assertEqual(first.recovered_targets, second.recovered_targets)
        self.assertEqual(summary_calls, first_summary_calls)
        self.assertTrue([
            details
            for phase, details in observed
            if phase == "call_summaries_derived"
        ])
        self.assertTrue(all(
            details["cache_hit"] is True
            for phase, details in observed
            if phase == "call_summaries_derived"
        ))
        self.assertTrue(all(
            details["cache_hit"] is True
            for phase, details in observed
            if phase == "mutable_influence_derived"
        ))

    def test_workspace_invalidates_changed_slot_authority(self) -> None:
        workspace = InterproceduralAnalysisWorkspace()
        arguments = {
            "units": [unit("root", 0x1000)],
            "roots": ["root"],
            "resolver": lambda **_kwargs: {"resolutions": []},
            "workspace": workspace,
        }
        original = interprocedural_analysis._analyze_mutable_slot_influence
        with patch(
            "spaghetti_extractor.interprocedural_analysis."
            "_analyze_mutable_slot_influence",
            side_effect=lambda **kwargs: original(**kwargs),
        ) as replay:
            self._run(**arguments)
            first_calls = replay.call_count
            self._run(
                **arguments,
                globals=[slot_invariant("root", 0x1000, IMAGE_BASE + 0x2000)],
            )

        self.assertGreater(replay.call_count, first_calls)

    def test_workspace_rejects_another_immutable_context(self) -> None:
        workspace = InterproceduralAnalysisWorkspace()
        self._run(
            units=[unit("root", 0x1000)],
            roots=["root"],
            resolver=lambda **_kwargs: {"resolutions": []},
            workspace=workspace,
        )

        with self.assertRaisesRegex(ValueError, "different immutable"):
            self._run(
                units=[unit("root", 0x1004)],
                roots=["root"],
                resolver=lambda **_kwargs: {"resolutions": []},
                workspace=workspace,
            )

    def test_contextual_recovery_runs_only_after_ordinary_stability(self) -> None:
        requests: list[bool] = []

        def resolver(**kwargs: object) -> dict[str, object]:
            requested = kwargs.get("run_contextual_recovery") is True
            requests.append(requested)
            return {
                "resolutions": [],
                "contextual_recovery": {
                    "required": True,
                    "executed": requested,
                },
            }

        result = self._run(
            units=[unit("root", 0x1000)],
            roots=["root"],
            resolver=resolver,
            proposal_only=True,
        )

        self.assertEqual(requests, [False, True])
        self.assertEqual(result.fixed_point["discovery_rounds"], 1)
        self.assertEqual(result.fixed_point["contextual_probe_requests"], 1)
        self.assertEqual(result.fixed_point["contextual_probes"], 1)
        self.assertEqual(result.fixed_point["discovery_contextual_probes"], 1)

    def test_fixed_point_reuses_one_transfer_cache_per_pass(self) -> None:
        caches: list[object] = []

        def resolver(**kwargs: object) -> dict[str, object]:
            caches.append(kwargs["transfer_cache"])
            requested = kwargs.get("run_contextual_recovery") is True
            return {
                "resolutions": [],
                "contextual_recovery": {
                    "required": True,
                    "executed": requested,
                },
            }

        self._run(
            units=[unit("root", 0x1000)],
            roots=["root"],
            resolver=resolver,
            proposal_only=True,
        )

        self.assertEqual(len(caches), 2)
        self.assertIs(caches[0], caches[1])

    def test_pass_without_contextual_frontier_performs_no_probe(self) -> None:
        requests: list[bool] = []

        def resolver(**kwargs: object) -> dict[str, object]:
            requests.append(kwargs.get("run_contextual_recovery") is True)
            return {
                "resolutions": [],
                "contextual_recovery": {
                    "required": False,
                    "executed": False,
                },
            }

        result = self._run(
            units=[unit("root", 0x1000)],
            roots=["root"],
            resolver=resolver,
            proposal_only=True,
        )

        self.assertEqual(requests, [False])
        self.assertEqual(result.fixed_point["contextual_probe_requests"], 0)
        self.assertEqual(result.fixed_point["contextual_probes"], 0)

    def test_contextual_discovery_resumes_ordinary_propagation(self) -> None:
        exit_row = indirect_exit("exit:root:0", "root")
        seed = recovered(exit_row, "target")
        seed.update({
            "analysis_dependencies": [exit_row["id"]],
            "origin_count": 1,
            "origin_kinds": ["internal"],
            "target_origin_witnesses": [{
                "kind": "static_code",
                "key": [IMAGE_BASE + 0x2000, 0],
            }],
            "proposal_source": "bounded_call_context_v1",
            "proof_authority": False,
            "context_coverage": {
                "format": "bounded-call-context-coverage-v1",
                "status": "complete",
                "context_count": 1,
                "complete_contexts": 1,
                "incomplete_contexts": 0,
                "impacted_by_budget": False,
                "contexts": [{
                    "id": "bounded-call-context-v1:fixture",
                    "status": "recovered",
                }],
            },
        })
        requests: list[bool] = []

        def resolver(**kwargs: object) -> dict[str, object]:
            requested = kwargs.get("run_contextual_recovery") is True
            requests.append(requested)
            selected = kwargs.get("recovered_indirect_edges")
            assert isinstance(selected, list)
            current = next(
                row for row in selected if row.get("id") == exit_row["id"]
            )
            if requested:
                return {
                    "resolutions": [incomplete_recovery(exit_row)],
                    "path_recovery_proposals": [seed],
                    "contextual_recovery": {
                        "required": True,
                        "executed": True,
                    },
                }
            if current.get("status") == "recovered":
                witnessed = dict(seed)
                witnessed.pop("proposal_source")
                witnessed.pop("proof_authority")
                return {
                    "resolutions": [witnessed],
                    "contextual_recovery": {
                        "required": False,
                        "executed": False,
                    },
                }
            return {
                "resolutions": [incomplete_recovery(exit_row)],
                "contextual_recovery": {
                    "required": True,
                    "executed": False,
                },
            }

        with patch(
            "spaghetti_extractor.interprocedural_analysis."
            "_materialize_typed_authority_graph",
            wraps=interprocedural_analysis._materialize_typed_authority_graph,
        ) as materialize:
            result = self._run(
                units=[unit("root", 0x1000), unit("target", 0x2000)],
                roots=["root"],
                exits=[exit_row],
                resolver=resolver,
                proposal_only=True,
            )

        self.assertEqual(requests, [False, True, False])
        self.assertEqual(result.fixed_point["discovery_rounds"], 2)
        self.assertEqual(materialize.call_count, 1)
        self.assertEqual(result.fixed_point["contextual_probe_requests"], 1)
        self.assertEqual(result.fixed_point["contextual_probes"], 1)
        self.assertEqual(result.recovered_targets[0]["status"], "recovered")

    def test_proposal_pass_retains_contextual_hint_until_checkpoint_stable(
        self,
    ) -> None:
        exit_row = indirect_exit("exit:root:0", "root")
        hint = recovered(exit_row, "target")
        hint.update({
            "proposal_source": "path_sensitive_pre_widening_v1",
            "proof_authority": False,
            "target_origin_witnesses": [{
                "kind": "static_code",
                "key": [IMAGE_BASE + 0x2000, [SLOT]],
            }],
        })
        requests: list[bool] = []

        def resolver(**kwargs: object) -> dict[str, object]:
            requested = kwargs.get("run_contextual_recovery") is True
            requests.append(requested)
            return {
                "resolutions": [incomplete_recovery(exit_row)],
                "path_recovery_proposals": [hint] if requested else [],
                "contextual_recovery": {
                    "required": True,
                    "executed": requested,
                },
            }

        result = self._run(
            units=[unit("root", 0x1000), unit("target", 0x2000)],
            roots=["root"],
            exits=[exit_row],
            resolver=resolver,
            proposal_only=True,
            writable_image_ranges=[(SLOT, SLOT + 4)],
        )

        self.assertEqual(requests, [False, True, False, True])
        self.assertEqual(result.fixed_point["discovery_rounds"], 2)
        self.assertEqual(result.fixed_point["contextual_probe_requests"], 2)
        self.assertEqual(result.fixed_point["contextual_probes"], 2)
        self.assertEqual(result.recovered_targets[0]["status"], "recovered")
        self.assertFalse(result.recovered_targets[0]["proof_authority"])
        self.assertEqual(
            result.recovered_targets[0]["proposal_source"],
            "path_sensitive_pre_widening_v1",
        )
        self.assertEqual(
            result.recovered_targets[0]["hypothesis_validation"],
            "pending_authority_replay_v2",
        )
        self.assertEqual(
            result.recovered_targets[0]["proposal_failure"]["code"],
            "mutable_slot_invariant_missing",
        )

    def test_contextual_checkpoints_accumulate_bounded_proposals(self) -> None:
        first_exit = indirect_exit("exit:root:0", "root", event_index=0)
        second_exit = indirect_exit("exit:root:1", "root", event_index=1)
        first_hint = recovered(first_exit, "first")
        second_hint = recovered(second_exit, "second")
        for hint in (first_hint, second_hint):
            hint.update({
                "proposal_source": "bounded_call_context_v1",
                "proof_authority": False,
                "target_origin_witnesses": [{
                    "kind": "static_code",
                    "key": [IMAGE_BASE + 0x2000, 0],
                }],
            })
        probes = 0

        def resolver(**kwargs: object) -> dict[str, object]:
            nonlocal probes
            requested = kwargs.get("run_contextual_recovery") is True
            proposals: list[dict[str, object]] = []
            if requested:
                probes += 1
                proposals = [first_hint if probes == 1 else second_hint]
            return {
                "resolutions": [
                    incomplete_recovery(first_exit),
                    incomplete_recovery(second_exit),
                ],
                "path_recovery_proposals": proposals,
                "contextual_recovery": {
                    "required": True,
                    "executed": requested,
                },
            }

        result = self._run(
            units=[
                unit("root", 0x1000),
                unit("first", 0x2000),
                unit("second", 0x3000),
            ],
            roots=["root"],
            exits=[first_exit, second_exit],
            resolver=resolver,
            proposal_only=True,
        )

        self.assertEqual(probes, 3)
        self.assertEqual(
            {
                row["id"]
                for row in result.recovered_targets
                if row["status"] == "recovered"
            },
            {first_exit["id"], second_exit["id"]},
        )
        self.assertLessEqual(result.fixed_point["discovery_rounds"], 3)

    def test_bootstrap_callback_arguments_join_or_fail_closed(self) -> None:
        first = ValueOrigin("exact", (1,))
        second = ValueOrigin("exact", (2,))

        merged = _merge_bootstrap_callback_arguments(
            {"callback": {0: frozenset({first}), 1: frozenset({first})}},
            {
                "callback": {0: frozenset({second})},
                "new": {0: frozenset({first})},
            },
            finite_value_budget=1,
        )

        self.assertNotIn(0, merged["callback"])
        self.assertEqual(merged["callback"][1], frozenset({first}))
        self.assertEqual(merged["new"][0], frozenset({first}))

    def test_transient_proposal_failure_is_not_final_authority(self) -> None:
        exit_row = indirect_exit("exit:root:0", "root")
        effect = call_effect("root", preserved=frozenset({"ebx"}))
        evaluations = 0

        def resolver(**_kwargs: object) -> dict[str, object]:
            nonlocal evaluations
            evaluations += 1
            return {
                "resolutions": [
                    incomplete_recovery(exit_row)
                    if evaluations == 1
                    else recovered(exit_row, "target")
                ],
                "call_site_effects": [effect],
            }

        result = self._run(
            units=[unit("root", 0x1000), unit("target", 0x2000)],
            roots=["root"],
            exits=[exit_row],
            resolver=resolver,
            proposal_only=True,
        )

        inventory = {
            row["id"]: row for row in result.fixed_point["dependencies"]
        }
        self.assertGreaterEqual(result.fixed_point["discovery_rounds"], 2)
        self.assertEqual(inventory[exit_row["id"]]["status"], "complete")
        self.assertEqual(inventory[exit_row["id"]]["failure_reasons"], [])

    def test_mutable_influence_schedules_acyclic_diamond_once(self) -> None:
        observed: list[dict[str, object]] = []

        result = self._run(
            units=[
                unit("root", 0x1000),
                unit("left", 0x1010),
                unit("right", 0x1020),
                unit("join", 0x1030),
            ],
            roots=["root"],
            direct=[
                edge("root", "left"),
                edge("root", "right"),
                edge("left", "join"),
                edge("right", "join"),
            ],
            resolver=lambda **_kwargs: {"resolutions": []},
            progress=lambda phase, details: (
                observed.append(dict(details))
                if phase == "mutable_influence_derived"
                else None
            ),
        )

        self.assertTrue(result.complete)
        self.assertEqual(len(observed), 2)
        self.assertTrue(
            all(details["reached_units"] == 4 for details in observed)
        )
        self.assertTrue(
            all(details["transfer_evaluations"] == 4 for details in observed)
        )
        self.assertTrue(
            all(details["join_evaluations"] == 1 for details in observed)
        )
        self.assertFalse(any(details["budget_exhausted"] for details in observed))

    def test_mutable_scc_cache_replays_exact_graph_without_transfers(self) -> None:
        units = [
            unit("root", 0x1000),
            unit("left", 0x1010),
            unit("right", 0x1020),
            unit("join", 0x1030),
        ]
        direct = [
            edge("root", "left"),
            edge("root", "right"),
            edge("left", "join"),
            edge("right", "join"),
        ]
        cache = _MutableSCCCache(16)

        cold = self._mutable_replay(
            units=units,
            roots=["root"],
            direct=direct,
            cache=cache,
        )
        warm = self._mutable_replay(
            units=units,
            roots=["root"],
            direct=direct,
            cache=cache,
        )

        self.assertEqual(cold.exits, warm.exits)
        self.assertEqual(cold.reached_units, warm.reached_units)
        self.assertEqual(cold.exhausted, warm.exhausted)
        self.assertEqual(cold.transfer_evaluations, 4)
        self.assertEqual(warm.transfer_evaluations, 0)
        self.assertEqual(warm.scc_cache_requests, 4)
        self.assertEqual(warm.scc_cache_hits, 4)

    def test_mutable_scc_cache_projects_call_facts_to_consumers(self) -> None:
        units = [
            unit("root", 0x1000),
            unit("stable", 0x1010),
            unit("caller", 0x1020, calls=(0x2000,)),
            unit("callee", 0x2000),
        ]
        direct = [edge("root", "stable"), edge("stable", "caller")]
        calls = [call_edge("caller", "callee")]
        cache = _MutableSCCCache(16)

        cold = self._mutable_replay(
            units=units,
            roots=["root"],
            direct=direct,
            calls=calls,
            cache=cache,
        )
        refined = self._mutable_replay(
            units=units,
            roots=["root"],
            direct=direct,
            calls=calls,
            preserved={IMAGE_BASE + 0x2000: frozenset({"ebx"})},
            cache=cache,
        )

        self.assertEqual(cold.reached_units, refined.reached_units)
        self.assertEqual(refined.scc_cache_requests, 4)
        self.assertGreaterEqual(refined.scc_cache_hits, 3)
        self.assertLessEqual(refined.transfer_evaluations, 1)

    def test_mutable_scc_cache_invalidates_changed_control_edges(self) -> None:
        units = [
            unit("root", 0x1000),
            unit("left", 0x1010),
            unit("right", 0x1020),
        ]
        cache = _MutableSCCCache(16)

        left = self._mutable_replay(
            units=units,
            roots=["root"],
            direct=[edge("root", "left")],
            cache=cache,
        )
        right = self._mutable_replay(
            units=units,
            roots=["root"],
            direct=[edge("root", "right")],
            cache=cache,
        )

        self.assertEqual(left.reached_units, 2)
        self.assertEqual(right.reached_units, 2)
        self.assertEqual(right.scc_cache_requests, 2)
        self.assertEqual(right.scc_cache_hits, 0)
        self.assertEqual(right.transfer_evaluations, 2)

    def test_mutable_scc_cache_is_bounded(self) -> None:
        cache = _MutableSCCCache(1)
        result = self._mutable_replay(
            units=[unit("root", 0x1000), unit("next", 0x1010)],
            roots=["root"],
            direct=[edge("root", "next")],
            cache=cache,
        )

        self.assertEqual(cache.entry_count, 1)
        self.assertEqual(result.scc_cache_evictions, 1)

    def test_mutable_replay_reuses_unchanged_dependency_projection(self) -> None:
        effect = call_effect("root", preserved=frozenset({"ebx"}))

        result = self._run(
            units=[unit("root", 0x1000)],
            roots=["root"],
            resolver=lambda **_kwargs: {
                "resolutions": [],
                "call_site_effects": [effect],
            },
            proposal_only=True,
        )

        self.assertEqual(result.fixed_point["discovery_rounds"], 2)
        self.assertEqual(result.fixed_point["mutable_replay_requests"], 2)
        self.assertEqual(result.fixed_point["mutable_replay_cache_hits"], 1)

    def test_cold_replay_seals_event_bound_memory_access_facts(self) -> None:
        root = unit(
            "root",
            0x1000,
            memory=(stack_write(12, const(1)),),
        )
        root["source"]["instruction_bytes_sha256"] = "e" * 64

        def resolver(**_kwargs: Any) -> dict[str, object]:
            event = root["semantics"]["memory_events"][0]
            return {
                "resolutions": [],
                "memory_access_proposals": [{
                    "format": MEMORY_ACCESS_PROPOSAL_V2_FORMAT,
                    "status": "complete",
                    "unit_id": "root",
                    "event_index": 0,
                    "memory_kind": "write",
                    "width_bytes": 4,
                    "address_expression": event["address"],
                    "address_origins": [{
                        "kind": "stack_location",
                        "key": [12],
                    }],
                    "authority_dependencies": [],
                }],
            }

        result = self._run(
            units=[root],
            roots=["root"],
            resolver=resolver,
            bind_memory_accesses=True,
        )

        facts = result.operation_provenance["checked_memory_access_facts"]
        self.assertEqual(len(facts), 1)
        self.assertEqual(
            facts[0]["interprocedural_authority_sha256"],
            result.fixed_point["authority_artifact_sha256"],
        )
        self.assertNotIn("memory_access_proposals", result.operation_provenance)
        self.assertEqual(result.fixed_point["checked_memory_access_fact_count"], 1)

    def test_memory_access_validation_reuses_exact_stable_inventory(self) -> None:
        root = unit(
            "root",
            0x1000,
            calls=(0x2000,),
            memory=(stack_write(12, const(1)),),
        )
        root["source"]["instruction_bytes_sha256"] = "e" * 64
        callee = unit("callee", 0x2000)
        callee["source"]["instruction_bytes_sha256"] = "e" * 64
        resolver_calls = 0

        def resolver(**_kwargs: Any) -> dict[str, object]:
            nonlocal resolver_calls
            resolver_calls += 1
            event = root["semantics"]["memory_events"][0]
            return {
                "resolutions": [],
                "call_site_effects": [call_effect(
                    "root",
                    preserved=(
                        frozenset({"ebx"})
                        if resolver_calls == 1
                        else frozenset({"ebx", "esi"})
                    ),
                )],
                "memory_access_proposals": [{
                    "format": MEMORY_ACCESS_PROPOSAL_V2_FORMAT,
                    "status": "complete",
                    "unit_id": "root",
                    "event_index": 0,
                    "memory_kind": "write",
                    "width_bytes": 4,
                    "address_expression": event["address"],
                    "address_origins": [{
                        "kind": "stack_location",
                        "key": [12],
                    }],
                    "authority_dependencies": [],
                }],
            }

        observed: list[bool] = []
        self._run(
            units=[root, callee],
            roots=["root"],
            calls=[call_edge("root", "callee")],
            resolver=resolver,
            bind_memory_accesses=True,
            proposal_only=True,
            progress=lambda phase, details: (
                observed.append(bool(details["memory_validation_cache_hit"]))
                if phase == "call_summaries_derived"
                else None
            ),
        )

        self.assertIn(False, observed)
        self.assertIn(True, observed)

    def test_call_summary_consumes_memory_fact_through_scc_dependency(
        self,
    ) -> None:
        root = unit(
            "root",
            0x1000,
            memory=(stack_write(12, const(1)),),
        )
        root["source"]["instruction_bytes_sha256"] = "e" * 64

        def resolver(**_kwargs: Any) -> dict[str, object]:
            event = root["semantics"]["memory_events"][0]
            return {
                "resolutions": [],
                "memory_access_proposals": [{
                    "format": MEMORY_ACCESS_PROPOSAL_V2_FORMAT,
                    "status": "complete",
                    "unit_id": "root",
                    "event_index": 0,
                    "memory_kind": "write",
                    "width_bytes": 4,
                    "address_expression": event["address"],
                    "address_origins": [{
                        "kind": "stack_location",
                        "key": [12],
                    }],
                    "authority_dependencies": [],
                }],
            }

        def summaries(**kwargs: Any) -> dict[str, object]:
            result = summary_adapter(**kwargs)
            fact_ids = sorted(
                str(row["id"])
                for row in kwargs.get("prepared_memory_access_facts", ())
            )
            for row in result["summaries"]:
                row["target_dependencies"] = fact_ids
            return result

        result = self._run(
            units=[root],
            roots=["root"],
            resolver=resolver,
            summary_resolver=summaries,
            bind_memory_accesses=True,
        )

        facts = result.operation_provenance["checked_memory_access_facts"]
        self.assertEqual(len(facts), 1)
        self.assertEqual(
            result.call_summaries["summaries"][0]["target_dependencies"],
            [facts[0]["id"]],
        )
        self.assertGreaterEqual(result.fixed_point["cold_replay_rounds"], 2)

    def test_contextual_memory_fact_is_retained_until_dependents_stabilize(
        self,
    ) -> None:
        root = unit(
            "root",
            0x1000,
            memory=(stack_write(12, const(1)),),
        )
        root["source"]["instruction_bytes_sha256"] = "e" * 64

        def resolver(**kwargs: Any) -> dict[str, object]:
            contextual = kwargs.get("run_contextual_recovery") is True
            event = root["semantics"]["memory_events"][0]
            return {
                "resolutions": [],
                "contextual_recovery": {
                    "required": True,
                    "executed": contextual,
                },
                "memory_access_proposals": ([] if not contextual else [{
                    "format": MEMORY_ACCESS_PROPOSAL_V2_FORMAT,
                    "status": "complete",
                    "unit_id": "root",
                    "event_index": 0,
                    "memory_kind": "write",
                    "width_bytes": 4,
                    "address_expression": event["address"],
                    "address_origins": [{
                        "kind": "stack_location",
                        "key": [12],
                    }],
                    "authority_dependencies": [],
                }]),
            }

        result = self._run(
            units=[root],
            roots=["root"],
            resolver=resolver,
            bind_memory_accesses=True,
        )

        self.assertEqual(
            len(result.operation_provenance["checked_memory_access_facts"]),
            1,
        )
        self.assertLessEqual(result.fixed_point["cold_replay_rounds"], 3)
        self.assertTrue(result.fixed_point["cold_replay_validated"])

    def test_inductive_memory_fact_requires_all_accepted_dependencies(self) -> None:
        proposal = {
            "format": MEMORY_ACCESS_PROPOSAL_V2_FORMAT,
            "status": "complete",
            "unit_id": "read:cursor",
            "event_index": 0,
            "memory_kind": "read",
            "width_bytes": 4,
            "address_expression": reg("esi"),
            "address_origins": [
                {"kind": "exact", "key": [SLOT]},
                {"kind": "exact", "key": [SLOT + 4]},
            ],
            "authority_dependencies": ["exit:bounded-table"],
        }

        rejected = _merge_inductive_operation_provenance(
            {},
            {"memory_access_proposals": [proposal]},
            available_dependencies=set(),
        )
        accepted = _merge_inductive_operation_provenance(
            {},
            {"memory_access_proposals": [proposal]},
            available_dependencies={"exit:bounded-table"},
        )

        self.assertEqual(rejected["memory_access_proposals"], [])
        self.assertEqual(accepted["memory_access_proposals"], [proposal])

    def test_inductive_memory_fact_resolves_call_frame_to_callee_summary(
        self,
    ) -> None:
        proposal = {
            "format": MEMORY_ACCESS_PROPOSAL_V2_FORMAT,
            "status": "complete",
            "unit_id": "read:cursor",
            "event_index": 0,
            "memory_kind": "read",
            "width_bytes": 4,
            "address_expression": reg("esi"),
            "address_origins": [{"kind": "exact", "key": [SLOT]}],
            "authority_dependencies": [
                call_frame_dependency_id("caller", 0, "callee")
            ],
        }

        rejected = _merge_inductive_operation_provenance(
            {},
            {"memory_access_proposals": [proposal]},
            available_dependencies={"call-summary:other"},
        )
        accepted = _merge_inductive_operation_provenance(
            {},
            {"memory_access_proposals": [proposal]},
            available_dependencies={"call-summary:callee"},
        )

        self.assertEqual(rejected["memory_access_proposals"], [])
        self.assertEqual(accepted["memory_access_proposals"], [proposal])

    def test_cold_replay_seals_exhaustive_memory_address_domain(self) -> None:
        root = unit(
            "root",
            0x1000,
            memory=({
                "kind": "read",
                "width": 4,
                "address": reg("esi"),
            },),
        )
        root["source"]["instruction_bytes_sha256"] = "e" * 64

        def resolver(**kwargs: Any) -> dict[str, object]:
            requested = kwargs.get("run_contextual_recovery") is True
            event = root["semantics"]["memory_events"][0]
            return {
                "resolutions": [],
                "contextual_recovery": {
                    "required": True,
                    "executed": requested,
                },
                "memory_address_domain_proposals": ([] if not requested else [{
                    "format": MEMORY_ADDRESS_DOMAIN_PROPOSAL_V2_FORMAT,
                    "status": "complete",
                    "unit_id": "root",
                    "event_index": 0,
                    "memory_kind": "read",
                    "width_bytes": 4,
                    "address_expression": event["address"],
                    "addresses": [SLOT, SLOT + 4],
                    "authority_dependencies": [],
                    "context_coverage": {
                        "format": CONTEXTUAL_MEMORY_COVERAGE_V1_FORMAT,
                        "status": "complete",
                        "root_unit_ids": ["root"],
                        "relevant_unit_ids": ["root"],
                        "context_states": 1,
                        "context_depth": 1,
                        "contexts_per_unit": 32,
                        "truncated_calls": 0,
                        "dropped_contexts": 0,
                        "work_budget_exceeded": False,
                    },
                }]),
            }

        result = self._run(
            units=[root],
            roots=["root"],
            resolver=resolver,
            bind_memory_accesses=True,
        )

        domains = result.operation_provenance[
            "checked_memory_address_domains"
        ]
        self.assertEqual(len(domains), 1)
        self.assertEqual(domains[0]["addresses"], [SLOT, SLOT + 4])
        self.assertEqual(
            domains[0]["interprocedural_authority_sha256"],
            result.fixed_point["authority_artifact_sha256"],
        )
        self.assertNotIn(
            "memory_address_domain_proposals", result.operation_provenance
        )
        self.assertEqual(
            result.fixed_point["checked_memory_address_domain_count"], 1
        )

    def test_unscheduled_contextual_domain_fails_closed(self) -> None:
        root = unit(
            "root",
            0x1000,
            memory=({
                "kind": "read",
                "width": 4,
                "address": reg("esi"),
            },),
        )

        def resolver(**_kwargs: Any) -> dict[str, object]:
            return {
                "resolutions": [],
                "contextual_recovery": {
                    "required": True,
                    "executed": False,
                },
                "memory_address_domain_proposals": [{
                    "unit_id": "root",
                    "event_index": 0,
                }],
            }

        with self.assertRaisesRegex(
            ValueError,
            "contextual memory address domains require an executed scheduled recovery",
        ):
            self._run(
                units=[root],
                roots=["root"],
                resolver=resolver,
                proposal_only=True,
            )

    def test_operator_internal_contracts_are_proposal_only(self) -> None:
        observed: list[dict[str, dict[str, object]]] = []

        def summaries(**kwargs: Any) -> dict[str, object]:
            observed.append(dict(kwargs["declared_summaries"]))
            return summary_adapter(**kwargs)

        contract = {
            "root": {
                "status": "complete",
                "declared_internal_contract": {
                    "authority": "operator_reviewed_static_analysis_assumption",
                    "replacement_authority": False,
                },
            }
        }
        result = self._run(
            units=[unit("root", 0x1000)],
            roots=["root"],
            resolver=lambda **_kwargs: {"resolutions": []},
            internal_contracts=contract,
            summary_resolver=summaries,
        )

        self.assertTrue(result.complete, result.fixed_point)
        self.assertEqual(observed, [contract, {}])

    def test_call_site_effects_participate_in_each_typed_fixed_point(self) -> None:
        observed: list[tuple[object, ...]] = []
        abi = resolve_machine_call_abi("pe32-cdecl-v1")
        assert abi is not None
        effect = CallSiteEffect(
            site=CallSiteId("root", 0),
            transfer_kind="external_call",
            status="incomplete",
            register_frame_status="complete",
            preserved_registers=frozenset(abi.preserved_registers),
            stack_frame_status="complete",
            stack_cleanup_bytes=0,
            result_status="complete",
            outputs=(),
            memory_frame_status="incomplete",
            memory_preserved=False,
            memory_writes=(),
            abi=abi,
            argument_words=0,
            failure_codes=("memory_frame_unknown",),
        ).as_json()

        def summaries(**kwargs: Any) -> dict[str, object]:
            observed.append(tuple(kwargs["call_site_effects"]))
            return summary_adapter(**kwargs)

        def resolver(**_kwargs: Any) -> dict[str, object]:
            return {"resolutions": [], "call_site_effects": [effect]}

        result = self._run(
            units=[unit("root", 0x1000)],
            roots=["root"],
            resolver=resolver,
            summary_resolver=summaries,
        )

        self.assertTrue(result.complete, result.fixed_point)
        self.assertEqual(observed, [(), (effect,), (), (effect,)])

    def test_writable_image_reader_is_proposal_only(self) -> None:
        observed: list[bytes | None] = []

        def resolver(**kwargs: Any) -> dict[str, object]:
            reader = kwargs["static_data_reader"]
            observed.append(None if reader is None else reader(SLOT, 4))
            return {"resolutions": []}

        result = self._run(
            units=[unit("root", 0x1000)],
            roots=["root"],
            resolver=resolver,
            static_data_reader=lambda _address, _size: None,
            proposal_static_data_reader=lambda _address, _size: b"\x00\x20\x40\x00",
        )

        self.assertTrue(result.complete, result.fixed_point)
        self.assertIn(b"\x00\x20\x40\x00", observed)
        self.assertIn(None, observed)

    def test_static_origin_witness_discovers_writable_slot_dependency(self) -> None:
        exit_row = indirect_exit("exit:dispatch:0", "dispatch")

        def resolver(**_kwargs: Any) -> dict[str, object]:
            resolution = recovered(exit_row, "target")
            resolution["target_origin_witnesses"] = [{
                "kind": "static_code",
                "key": [IMAGE_BASE + 0x2000, [SLOT]],
            }]
            return {"resolutions": [resolution]}

        result = self._run(
            units=[unit("dispatch", 0x1010), unit("target", 0x2000)],
            roots=["dispatch"],
            exits=[exit_row],
            resolver=resolver,
            writable_image_ranges=[(SLOT, SLOT + 0x1000)],
        )

        recovery = result.recovered_targets[0]
        self.assertEqual(
            recovery["failure"]["code"], "mutable_slot_invariant_missing"
        )
        self.assertEqual(recovery["mutable_slot_dependencies"], [{
            "slot_rva": SLOT - IMAGE_BASE,
            "width_bytes": 4,
            "read_sites": [],
            "origin_witnessed": True,
        }])

    def test_proposal_bootstrap_retains_bounded_writable_slot_target(self) -> None:
        exit_row = indirect_exit("exit:dispatch:0", "dispatch")

        def resolver(**_kwargs: Any) -> dict[str, object]:
            resolution = recovered(exit_row, "target")
            resolution.update({
                "target_origin_witnesses": [{
                    "kind": "static_code",
                    "key": (IMAGE_BASE + 0x2000, (SLOT,)),
                }],
            })
            return {"resolutions": [resolution]}

        result = self._run(
            units=[unit("dispatch", 0x1010), unit("target", 0x2000)],
            roots=["dispatch"],
            exits=[exit_row],
            resolver=resolver,
            writable_image_ranges=[(SLOT, SLOT + 4)],
            proposal_only=True,
        )

        self.assertFalse(result.complete)
        recovery = result.recovered_targets[0]
        self.assertEqual(recovery["status"], "recovered")
        self.assertFalse(recovery["proof_authority"])
        self.assertEqual(
            recovery["proposal_source"],
            "mutable_slot_inductive_bootstrap_v2",
        )
        self.assertEqual(
            recovery["hypothesis_validation"],
            "pending_global_slot_replay_v2",
        )
        self.assertEqual(
            recovery["proposal_failure"]["code"],
            "mutable_slot_invariant_missing",
        )

    def test_late_target_discovery_schedules_new_summary_dependency(self) -> None:
        exit_row = indirect_exit("exit:a:0", "a")

        def resolver(**_kwargs: object) -> dict[str, object]:
            return {"resolutions": [recovered(exit_row, "b")]}

        result = self._run(
            units=[unit("a", 0x1000), unit("a-return", 0x1001), unit("b", 0x2000)],
            roots=["a"],
            direct=[edge("a", "a-return")],
            exits=[exit_row],
            resolver=resolver,
        )

        self.assertTrue(result.complete, result.fixed_point)
        self.assertEqual(
            result.fixed_point["discovery_signature"],
            result.fixed_point["cold_replay_signature"],
        )
        self.assertEqual(len(result.fixed_point["cold_replay_signature"]), 64)
        self.assertGreaterEqual(result.fixed_point["cold_replay_rounds"], 2)
        inventory = {row["id"]: row for row in result.fixed_point["dependencies"]}
        self.assertIn("call-summary:b", inventory)
        self.assertEqual(
            inventory["call-summary:a"]["dependencies"],
            ["call-summary:b", "exit:a:0"],
        )
        self.assertNotIn(
            "exit:a:0", inventory["call-summary:b"]["dependencies"]
        )

    def test_recursive_summaries_are_one_dependency_scc(self) -> None:
        result = self._run(
            units=[
                unit("a", 0x1000, calls=(0x2000,)),
                unit("a-return", 0x1001),
                unit("b", 0x2000, calls=(0x1000,)),
                unit("b-return", 0x2001),
            ],
            roots=["a"],
            direct=[edge("a", "a-return"), edge("b", "b-return")],
            calls=[call_edge("a", "b"), call_edge("b", "a")],
            resolver=lambda **_kwargs: {"resolutions": []},
        )

        self.assertTrue(result.complete, result.fixed_point)
        self.assertIn(
            ["call-summary:a", "call-summary:b"],
            result.fixed_point["recursive_sccs"],
        )

    def test_proposal_cannot_authorize_an_unseeded_incomplete_fact(self) -> None:
        exit_row = indirect_exit("exit:a:0", "a")
        seed = recovered(exit_row, "b")

        def resolver(**kwargs: object) -> dict[str, object]:
            selected = kwargs["recovered_indirect_edges"]
            assert isinstance(selected, list)
            row = next(item for item in selected if item.get("id") == exit_row["id"])
            return {
                "resolutions": [
                    seed if row.get("status") == "recovered" else incomplete_recovery(exit_row)
                ]
            }

        result = self._run(
            units=[unit("a", 0x1000), unit("b", 0x2000)],
            roots=["a"],
            exits=[exit_row],
            proposal=[seed],
            resolver=resolver,
        )

        self.assertFalse(result.complete)
        self.assertTrue(result.fixed_point["cold_replay_validated"])
        self.assertIn(
            "reachable_indirect_targets_incomplete",
            result.fixed_point["failure_reasons"],
        )
        self.assertFalse(
            result.fixed_point["proposal_diagnostics"]["same_authorizing_facts"]
        )

    def test_acyclic_hypothesis_does_not_trigger_inductive_replay(self) -> None:
        exit_row = indirect_exit("exit:a:0", "a")
        seed = recovered(exit_row, "b")

        def resolver(**kwargs: object) -> dict[str, object]:
            selected = kwargs["recovered_indirect_edges"]
            assert isinstance(selected, list)
            row = next(item for item in selected if item.get("id") == exit_row["id"])
            return {
                "resolutions": [
                    seed if row.get("status") == "recovered" else incomplete_recovery(exit_row)
                ]
            }

        result = self._run(
            units=[unit("a", 0x1000), unit("b", 0x2000)],
            roots=["a"],
            exits=[exit_row],
            inductive=[seed],
            resolver=resolver,
            authority_only=True,
        )

        self.assertFalse(result.complete)
        replay = result.fixed_point["inductive_replay"]
        self.assertEqual(replay["status"], "not_applicable")
        self.assertFalse(replay["required"])
        self.assertFalse(replay["executed"])
        self.assertFalse(replay["proof_authority"])
        self.assertEqual(replay["missing_ids"], [])

    def test_recovery_certificate_dependency_triggers_inductive_replay(self) -> None:
        exit_row = indirect_exit("exit:a:0", "a")
        seed = recovered(exit_row, "b")
        seed["analysis_dependencies"] = [exit_row["id"]]

        self.assertTrue(
            _requires_inductive_replay(
                units=[unit("a", 0x1000), unit("b", 0x2000)],
                roots=["a"],
                direct_edges=[],
                internal_call_edges=[],
                indirect_exits=[exit_row],
                summaries={"summaries": [{"target_unit_id": "a"}]},
                hypotheses=[seed],
            )
        )

    def test_cyclic_path_recovery_triggers_inductive_replay(self) -> None:
        exit_row = indirect_exit("exit:a:0", "a")
        seed = recovered(exit_row, "b")
        seed.update({
            "proposal_source": "bounded_call_context_v1",
            "proof_authority": False,
            "context_coverage": {
                "format": "bounded-call-context-coverage-v1",
                "status": "complete",
                "context_count": 1,
                "complete_contexts": 1,
                "incomplete_contexts": 0,
                "impacted_by_budget": False,
                "contexts": [{
                    "id": "bounded-call-context-v1:fixture",
                    "status": "recovered",
                }],
            },
        })

        self.assertTrue(
            _requires_inductive_replay(
                units=[
                    unit("a", 0x1000),
                    unit("loop", 0x1001),
                    unit("b", 0x2000),
                ],
                roots=["a"],
                direct_edges=[edge("a", "loop"), edge("loop", "a")],
                internal_call_edges=[],
                indirect_exits=[exit_row],
                summaries={"summaries": [{"target_unit_id": "a"}]},
                hypotheses=[seed],
            )
        )

    def test_acyclic_path_recovery_remains_non_authorizing(self) -> None:
        exit_row = indirect_exit("exit:a:0", "a")
        seed = recovered(exit_row, "b")
        seed.update({
            "proposal_source": "path_sensitive_pre_widening_v1",
            "proof_authority": False,
        })

        self.assertFalse(
            _requires_inductive_replay(
                units=[unit("a", 0x1000), unit("b", 0x2000)],
                roots=["a"],
                direct_edges=[],
                internal_call_edges=[],
                indirect_exits=[exit_row],
                summaries={"summaries": [{"target_unit_id": "a"}]},
                hypotheses=[seed],
            )
        )

    def test_call_frame_hypothesis_requires_a_control_cycle(self) -> None:
        hypothesis = PreservedRegisterHypothesis.parse(
            preserved_register_hypothesis("a", "edi")
        )
        units = [unit("a", 0x1000, calls=(0x2000,)), unit("b", 0x2000)]

        self.assertFalse(
            _requires_inductive_replay(
                units=units,
                roots=["a"],
                direct_edges=[],
                internal_call_edges=[call_edge("a", "b")],
                indirect_exits=[],
                summaries={"summaries": [summary_row("a", 0x1000)]},
                hypotheses=[],
                call_frame_hypotheses=[hypothesis],
            )
        )
        self.assertTrue(
            _requires_inductive_replay(
                units=[*units, unit("loop", 0x1001)],
                roots=["a"],
                direct_edges=[edge("a", "loop"), edge("loop", "a")],
                internal_call_edges=[call_edge("a", "b")],
                indirect_exits=[],
                summaries={"summaries": [summary_row("a", 0x1000)]},
                hypotheses=[],
                call_frame_hypotheses=[hypothesis],
            )
        )

    def test_discovery_exports_cyclic_register_frame_atoms(self) -> None:
        identity = call_frame_hypothesis_id("a", 0, "edi")

        def resolver(**_kwargs: object) -> dict[str, object]:
            return {
                "resolutions": [],
                "call_site_effects": [call_effect(
                    "a",
                    preserved=frozenset({"edi"}),
                    dependencies=(identity,),
                )],
            }

        result = self._run(
            units=[
                unit("a", 0x1000, calls=(0x2000,)),
                unit("loop", 0x1001),
                unit("b", 0x2000),
            ],
            roots=["a"],
            direct=[edge("a", "loop"), edge("loop", "a")],
            calls=[call_edge("a", "b")],
            resolver=resolver,
        )

        self.assertEqual(
            result.proposal_artifacts["call_frame_hypotheses"],
            [{
                **preserved_register_hypothesis("a", "edi"),
                "proposal_source": "unresolved-call-bootstrap-v1",
            }],
        )

    def test_call_frame_hypothesis_closes_only_after_exact_reproduction(self) -> None:
        hypothesis = preserved_register_hypothesis("a", "edi")
        identity = str(hypothesis["id"])

        def resolver(**kwargs: object) -> dict[str, object]:
            proposed = kwargs.get("preserved_register_hypotheses")
            return {
                "resolutions": [],
                "call_site_effects": [call_effect(
                    "a",
                    preserved=(
                        frozenset({"edi"}) if proposed else None
                    ),
                )],
            }

        result = self._run(
            units=[
                unit("a", 0x1000, calls=(0x2000,)),
                unit("loop", 0x1001),
                unit("b", 0x2000),
            ],
            roots=["a"],
            direct=[edge("a", "loop"), edge("loop", "a")],
            calls=[call_edge("a", "b")],
            inductive_frames=[hypothesis],
            resolver=resolver,
            authority_only=True,
        )

        self.assertTrue(result.complete, result.fixed_point)
        replay = result.fixed_point["inductive_replay"]
        self.assertTrue(replay["required"])
        self.assertTrue(replay["proof_authority"])
        self.assertEqual(replay["call_frame_reproduced_ids"], [identity])
        self.assertIn(identity, replay["accepted_nodes"])

    def test_self_dependent_call_frame_hypothesis_remains_non_authorizing(self) -> None:
        hypothesis = preserved_register_hypothesis("a", "edi")
        identity = str(hypothesis["id"])

        def resolver(**kwargs: object) -> dict[str, object]:
            proposed = kwargs.get("preserved_register_hypotheses")
            return {
                "resolutions": [],
                "call_site_effects": [call_effect(
                    "a",
                    preserved=(
                        frozenset({"edi"}) if proposed else None
                    ),
                    dependencies=(identity,) if proposed else (),
                )],
            }

        result = self._run(
            units=[
                unit("a", 0x1000, calls=(0x2000,)),
                unit("loop", 0x1001),
                unit("b", 0x2000),
            ],
            roots=["a"],
            direct=[edge("a", "loop"), edge("loop", "a")],
            calls=[call_edge("a", "b")],
            inductive_frames=[hypothesis],
            resolver=resolver,
            authority_only=True,
        )

        replay = result.fixed_point["inductive_replay"]
        self.assertFalse(replay["proof_authority"])
        self.assertEqual(replay["call_frame_missing_ids"], [identity])
        self.assertNotIn(identity, replay["accepted_nodes"])

    def test_path_recovery_is_exported_without_authorizing_cold_replay(self) -> None:
        exit_row = indirect_exit("exit:a:0", "a")
        seed = recovered(exit_row, "b")
        seed.update({
            "analysis_dependencies": [exit_row["id"]],
            "origin_count": 1,
            "origin_kinds": ["internal"],
            "target_origin_witnesses": [
                {"kind": "static_code", "key": [IMAGE_BASE + 0x2000, 0]}
            ],
            "proposal_source": "path_sensitive_pre_widening_v1",
            "proof_authority": False,
        })

        def resolver(**kwargs: object) -> dict[str, object]:
            return {
                "resolutions": [incomplete_recovery(exit_row)],
                "path_recovery_proposals": (
                    [seed]
                    if kwargs.get("collect_path_recovery_proposals") is True
                    else []
                ),
            }

        result = self._run(
            units=[unit("a", 0x1000), unit("b", 0x2000)],
            roots=["a"],
            exits=[exit_row],
            resolver=resolver,
        )

        self.assertFalse(result.complete)
        self.assertEqual(result.recovered_targets[0]["status"], "incomplete")
        proposal = result.proposal_artifacts["recoveries"][0]
        self.assertEqual(proposal["status"], "recovered")
        self.assertFalse(proposal["proof_authority"])
        self.assertEqual(
            proposal["proposal_source"],
            "path_sensitive_pre_widening_v1",
        )
        self.assertEqual(
            result.proposal_artifacts["path_recovery_diagnostics"], [seed]
        )
        self.assertEqual(
            result.fixed_point["inductive_replay"]["status"],
            "not_applicable",
        )

    def test_cyclic_path_recovery_can_close_only_after_witnessed_replay(self) -> None:
        exit_row = indirect_exit("exit:a:0", "a")
        seed = recovered(exit_row, "b")
        seed.update({
            "proposal_source": "bounded_call_context_v1",
            "proof_authority": False,
            "context_coverage": {
                "format": "bounded-call-context-coverage-v1",
                "status": "complete",
                "context_count": 1,
                "complete_contexts": 1,
                "incomplete_contexts": 0,
                "impacted_by_budget": False,
                "contexts": [{
                    "id": "bounded-call-context-v1:fixture",
                    "status": "recovered",
                }],
            },
        })

        def resolver(**kwargs: object) -> dict[str, object]:
            selected = kwargs["recovered_indirect_edges"]
            assert isinstance(selected, list)
            row = next(item for item in selected if item.get("id") == exit_row["id"])
            if row.get("status") != "recovered":
                return {"resolutions": [incomplete_recovery(exit_row)]}
            witnessed = recovered(exit_row, "b")
            witnessed.update({
                "analysis_dependencies": [exit_row["id"]],
                "origin_count": 1,
                "origin_kinds": ["internal"],
                "target_origin_witnesses": [
                    {"kind": "static_code", "key": [IMAGE_BASE + 0x2000, 0]}
                ],
            })
            return {"resolutions": [witnessed]}

        result = self._run(
            units=[
                unit("a", 0x1000),
                unit("loop", 0x1001),
                unit("b", 0x2000),
            ],
            roots=["a"],
            direct=[edge("a", "loop"), edge("loop", "a")],
            exits=[exit_row],
            inductive=[seed],
            resolver=resolver,
            authority_only=True,
        )

        self.assertTrue(result.complete, result.fixed_point)
        replay = result.fixed_point["inductive_replay"]
        self.assertTrue(replay["required"])
        self.assertTrue(replay["executed"])
        self.assertTrue(replay["proof_authority"])
        self.assertEqual(replay["reproduced_ids"], [exit_row["id"]])

    def test_scheduled_contextual_replay_can_reproduce_cyclic_target(self) -> None:
        exit_row = indirect_exit("exit:a:0", "a")
        seed = recovered(exit_row, "b")
        seed.update({
            "proposal_source": "bounded_call_context_v1",
            "proof_authority": False,
            "context_coverage": {
                "format": "bounded-call-context-coverage-v1",
                "status": "complete",
                "context_count": 1,
                "complete_contexts": 1,
                "incomplete_contexts": 0,
                "impacted_by_budget": False,
                "contexts": [{
                    "id": "bounded-call-context-v1:fixture",
                    "status": "recovered",
                }],
            },
        })

        def resolver(**kwargs: object) -> dict[str, object]:
            selected = kwargs["recovered_indirect_edges"]
            assert isinstance(selected, list)
            row = next(item for item in selected if item.get("id") == exit_row["id"])
            if row.get("status") != "recovered":
                return {"resolutions": [incomplete_recovery(exit_row)]}
            if kwargs.get("run_contextual_recovery") is not True:
                return {
                    "resolutions": [incomplete_recovery(exit_row)],
                    "contextual_recovery": {
                        "required": True,
                        "executed": False,
                    },
                }
            witnessed = recovered(exit_row, "b")
            witnessed.update({
                "proposal_source": "bounded_call_context_v1",
                "proof_authority": False,
                "context_coverage": seed["context_coverage"],
                "analysis_dependencies": [exit_row["id"]],
                "origin_count": 1,
                "origin_kinds": ["internal"],
                "target_origin_witnesses": [
                    {"kind": "static_code", "key": [IMAGE_BASE + 0x2000, 0]}
                ],
            })
            return {
                "resolutions": [incomplete_recovery(exit_row)],
                "path_recovery_proposals": [witnessed],
                "contextual_recovery": {
                    "required": True,
                    "executed": True,
                },
            }

        result = self._run(
            units=[
                unit("a", 0x1000),
                unit("loop", 0x1001),
                unit("b", 0x2000),
            ],
            roots=["a"],
            direct=[edge("a", "loop"), edge("loop", "a")],
            exits=[exit_row],
            inductive=[seed],
            resolver=resolver,
            authority_only=True,
        )

        self.assertTrue(result.complete, result.fixed_point)
        replay = result.fixed_point["inductive_replay"]
        self.assertTrue(replay["required"])
        self.assertTrue(replay["executed"])
        self.assertTrue(replay["proof_authority"])
        self.assertEqual(replay["reproduced_ids"], [exit_row["id"]])

    def test_unexecuted_contextual_checkpoint_remains_incomplete(self) -> None:
        exit_row = indirect_exit("exit:a:0", "a")
        seed = recovered(exit_row, "b")
        seed.update({
            "proposal_source": "bounded_call_context_v1",
            "proof_authority": False,
            "context_coverage": {
                "format": "bounded-call-context-coverage-v1",
                "status": "complete",
                "context_count": 1,
                "complete_contexts": 1,
                "incomplete_contexts": 0,
                "impacted_by_budget": False,
                "contexts": [{
                    "id": "bounded-call-context-v1:fixture",
                    "status": "recovered",
                }],
            },
        })

        def resolver(**_kwargs: object) -> dict[str, object]:
            return {
                "resolutions": [incomplete_recovery(exit_row)],
                "contextual_recovery": {
                    "required": True,
                    "executed": False,
                },
            }

        result = self._run(
            units=[
                unit("a", 0x1000),
                unit("loop", 0x1001),
                unit("b", 0x2000),
            ],
            roots=["a"],
            direct=[edge("a", "loop"), edge("loop", "a")],
            exits=[exit_row],
            inductive=[seed],
            resolver=resolver,
            authority_only=True,
        )

        self.assertFalse(result.complete)
        replay = result.fixed_point["inductive_replay"]
        self.assertFalse(replay["proof_authority"])
        self.assertEqual(replay["missing_ids"], [exit_row["id"]])

    def test_witnessed_inductive_replay_can_close_a_checked_cycle(self) -> None:
        exit_row = indirect_exit("exit:a:0", "a")
        seed = recovered(exit_row, "b")
        seed["analysis_dependencies"] = ['call-frame:["a",0,"b"]']

        def resolver(**kwargs: object) -> dict[str, object]:
            selected = kwargs["recovered_indirect_edges"]
            assert isinstance(selected, list)
            row = next(item for item in selected if item.get("id") == exit_row["id"])
            if row.get("status") != "recovered":
                return {"resolutions": [incomplete_recovery(exit_row)]}
            witnessed = recovered(exit_row, "b")
            witnessed.update({
                "analysis_dependencies": ['call-frame:["a",0,"b"]'],
                "origin_count": 1,
                "origin_kinds": ["internal"],
                "target_origin_witnesses": [
                    {"kind": "static_code", "key": [IMAGE_BASE + 0x2000, 0]}
                ],
            })
            return {"resolutions": [witnessed]}

        result = self._run(
            units=[unit("a", 0x1000), unit("b", 0x2000)],
            roots=["a"],
            exits=[exit_row],
            inductive=[seed],
            resolver=resolver,
            authority_only=True,
        )

        self.assertTrue(result.complete, result.fixed_point)
        replay = result.fixed_point["inductive_replay"]
        self.assertEqual(replay["status"], "complete")
        self.assertTrue(replay["proof_authority"])
        self.assertEqual(replay["reproduced_ids"], [exit_row["id"]])

    def test_register_fact_can_authorize_target_without_complete_call_summary(
        self,
    ) -> None:
        exit_row = indirect_exit("exit:a:0", "a")
        seed = recovered(exit_row, "callee")
        dependency = call_frame_family_dependency_id(
            "a", 0, "callee", "register", "edi"
        )
        seed["analysis_dependencies"] = [dependency]

        def summaries(**kwargs: Any) -> dict[str, object]:
            result = summary_adapter(**kwargs)
            rows = result["summaries"]
            assert isinstance(rows, list)
            for row in rows:
                if row.get("target_unit_id") != "callee":
                    continue
                row.update({
                    "status": "incomplete",
                    "preserved_registers": ["edi"],
                    "register_preservation": {
                        "status": "incomplete",
                        "checked_preserved_registers": ["edi"],
                    },
                    "blocker_codes": ["caller_memory_frame_incomplete"],
                })
            result["status"] = "incomplete"
            return result

        def resolver(**kwargs: object) -> dict[str, object]:
            selected = kwargs["recovered_indirect_edges"]
            assert isinstance(selected, list)
            current = next(
                (row for row in selected if row.get("id") == exit_row["id"]),
                None,
            )
            if current is None or current.get("status") != "recovered":
                return {"resolutions": [incomplete_recovery(exit_row)]}
            replayed = dict(seed)
            replayed.update({
                "origin_count": 1,
                "origin_kinds": ["internal"],
                "target_origin_witnesses": [{
                    "kind": "static_code",
                    "key": [IMAGE_BASE + 0x2000, 0],
                }],
            })
            return {"resolutions": [replayed]}

        result = self._run(
            units=[unit("a", 0x1000), unit("callee", 0x2000)],
            roots=["a"],
            exits=[exit_row],
            inductive=[seed],
            resolver=resolver,
            summary_resolver=summaries,
            authority_only=True,
        )

        recoveries = {str(row["id"]): row for row in result.recovered_targets}
        self.assertEqual(recoveries[exit_row["id"]]["status"], "recovered")
        replay = result.fixed_point["inductive_replay"]
        family_node = call_summary_family_node_id(
            "callee", "register", "edi"
        )
        self.assertIn(exit_row["id"], replay["accepted_nodes"])
        self.assertIn(family_node, replay["accepted_nodes"])
        self.assertNotIn("call-summary:callee", replay["accepted_nodes"])
        callee_summary = next(
            row
            for row in result.call_summaries["summaries"]
            if row["target_unit_id"] == "callee"
        )
        self.assertEqual(callee_summary["status"], "incomplete")
        self.assertEqual(callee_summary["preserved_registers"], ["edi"])
        self.assertEqual(
            callee_summary["register_preservation"],
            {
                "status": "incomplete",
                "checked_preserved_registers": ["edi"],
            },
        )
        self.assertEqual(callee_summary["stack_cleanup"]["status"], "complete")

    def test_missing_register_fact_cannot_authorize_family_dependency(
        self,
    ) -> None:
        exit_row = indirect_exit("exit:a:0", "a")
        seed = recovered(exit_row, "callee")
        seed["analysis_dependencies"] = [call_frame_family_dependency_id(
            "a", 0, "callee", "register", "edi"
        )]

        def incomplete_summaries(**kwargs: Any) -> dict[str, object]:
            result = summary_adapter(**kwargs)
            rows = result["summaries"]
            assert isinstance(rows, list)
            for row in rows:
                if row.get("target_unit_id") == "callee":
                    row.update({
                        "status": "incomplete",
                        "preserved_registers": [],
                        "register_preservation": {
                            "status": "incomplete",
                            "checked_preserved_registers": [],
                        },
                        "blocker_codes": ["register_frame_incomplete"],
                    })
            result["status"] = "incomplete"
            return result

        def resolver(**kwargs: object) -> dict[str, object]:
            selected = kwargs["recovered_indirect_edges"]
            assert isinstance(selected, list)
            if any(row.get("status") == "recovered" for row in selected):
                replayed = dict(seed)
                replayed.update({
                    "origin_count": 1,
                    "origin_kinds": ["internal"],
                    "target_origin_witnesses": [{
                        "kind": "static_code",
                        "key": [IMAGE_BASE + 0x2000, 0],
                    }],
                })
                return {"resolutions": [replayed]}
            return {"resolutions": [incomplete_recovery(exit_row)]}

        result = self._run(
            units=[unit("a", 0x1000), unit("callee", 0x2000)],
            roots=["a"],
            exits=[exit_row],
            inductive=[seed],
            resolver=resolver,
            summary_resolver=incomplete_summaries,
            authority_only=True,
        )

        self.assertEqual(result.recovered_targets[0]["status"], "incomplete")
        self.assertNotIn(
            exit_row["id"],
            result.fixed_point["inductive_replay"]["accepted_nodes"],
        )

    def test_propagated_family_dependency_does_not_rebind_to_later_exit(
        self,
    ) -> None:
        first_exit = indirect_exit("exit:a:0", "a")
        later_exit = indirect_exit("exit:later:0", "later")
        dependency = call_frame_family_dependency_id(
            "a", 0, "callee", "register", "edi"
        )
        first_seed = recovered(first_exit, "callee")
        later_seed = recovered(later_exit, "other")
        first_seed["analysis_dependencies"] = [dependency]
        later_seed["analysis_dependencies"] = [dependency]

        def resolver(**kwargs: object) -> dict[str, object]:
            selected = kwargs["recovered_indirect_edges"]
            assert isinstance(selected, list)
            current = {
                str(row.get("id")): row
                for row in selected
                if isinstance(row, dict)
            }
            resolutions: list[dict[str, object]] = []
            for exit_row, seed in (
                (first_exit, first_seed),
                (later_exit, later_seed),
            ):
                if current.get(str(exit_row["id"]), {}).get("status") != "recovered":
                    resolutions.append(incomplete_recovery(exit_row))
                    continue
                replayed = dict(seed)
                replayed.update({
                    "origin_count": 1,
                    "origin_kinds": ["internal"],
                    "target_origin_witnesses": [{
                        "kind": "static_code",
                        "key": [IMAGE_BASE + 0x2000, 0],
                    }],
                })
                resolutions.append(replayed)
            return {"resolutions": resolutions}

        result = self._run(
            units=[
                unit("a", 0x1000),
                unit("callee", 0x2000),
                unit("later", 0x3000),
                unit("other", 0x4000),
            ],
            roots=["a", "later"],
            exits=[first_exit, later_exit],
            inductive=[first_seed, later_seed],
            resolver=resolver,
            authority_only=True,
        )

        recoveries = {str(row["id"]): row for row in result.recovered_targets}
        self.assertEqual(recoveries[first_exit["id"]]["status"], "recovered")
        self.assertEqual(recoveries[later_exit["id"]]["status"], "recovered")
        projections = [
            row
            for row in result.fixed_point["dependencies"]
            if row["kind"] == "call_frame_family_projection"
        ]
        self.assertEqual(len(projections), 1)

    def test_memory_family_can_authorize_without_complete_call_summary(
        self,
    ) -> None:
        exit_row = indirect_exit("exit:a:0", "a")
        seed = recovered(exit_row, "callee")
        dependency = call_frame_family_dependency_id(
            "a", 0, "callee", "memory"
        )
        seed["analysis_dependencies"] = [dependency]

        def summaries(**kwargs: Any) -> dict[str, object]:
            result = summary_adapter(**kwargs)
            rows = result["summaries"]
            assert isinstance(rows, list)
            for row in rows:
                if row.get("target_unit_id") != "callee":
                    continue
                row.update({
                    "status": "incomplete",
                    "caller_memory_frame": {
                        "status": "complete",
                        "preserved": True,
                        "writes": [],
                    },
                    "blocker_codes": ["result_frame_incomplete"],
                })
            result["status"] = "incomplete"
            return result

        def resolver(**kwargs: object) -> dict[str, object]:
            selected = kwargs["recovered_indirect_edges"]
            assert isinstance(selected, list)
            if not any(row.get("status") == "recovered" for row in selected):
                return {"resolutions": [incomplete_recovery(exit_row)]}
            replayed = dict(seed)
            replayed.update({
                "origin_count": 1,
                "origin_kinds": ["internal"],
                "target_origin_witnesses": [{
                    "kind": "static_code",
                    "key": [IMAGE_BASE + 0x2000, 0],
                }],
            })
            return {"resolutions": [replayed]}

        result = self._run(
            units=[unit("a", 0x1000), unit("callee", 0x2000)],
            roots=["a"],
            exits=[exit_row],
            inductive=[seed],
            resolver=resolver,
            summary_resolver=summaries,
            authority_only=True,
        )

        self.assertTrue(result.complete, result.fixed_point)
        replay = result.fixed_point["inductive_replay"]
        family_node = call_summary_family_node_id("callee", "memory")
        self.assertIn(exit_row["id"], replay["accepted_nodes"])
        self.assertIn(family_node, replay["accepted_nodes"])
        self.assertNotIn("call-summary:callee", replay["accepted_nodes"])
        summary = next(
            row
            for row in result.call_summaries["summaries"]
            if row["target_unit_id"] == "callee"
        )
        self.assertEqual(summary["status"], "incomplete")
        self.assertEqual(summary["caller_memory_frame"]["status"], "complete")

    def test_missing_memory_family_cannot_authorize_family_dependency(
        self,
    ) -> None:
        exit_row = indirect_exit("exit:a:0", "a")
        seed = recovered(exit_row, "callee")
        seed["analysis_dependencies"] = [call_frame_family_dependency_id(
            "a", 0, "callee", "memory"
        )]

        def summaries(**kwargs: Any) -> dict[str, object]:
            result = summary_adapter(**kwargs)
            rows = result["summaries"]
            assert isinstance(rows, list)
            for row in rows:
                if row.get("target_unit_id") == "callee":
                    row.update({
                        "status": "incomplete",
                        "caller_memory_frame": {
                            "status": "incomplete",
                            "preserved": False,
                            "writes": [],
                        },
                        "blocker_codes": ["caller_memory_frame_incomplete"],
                    })
            result["status"] = "incomplete"
            return result

        def resolver(**kwargs: object) -> dict[str, object]:
            selected = kwargs["recovered_indirect_edges"]
            assert isinstance(selected, list)
            if not any(row.get("status") == "recovered" for row in selected):
                return {"resolutions": [incomplete_recovery(exit_row)]}
            replayed = dict(seed)
            replayed.update({
                "origin_count": 1,
                "origin_kinds": ["internal"],
                "target_origin_witnesses": [{
                    "kind": "static_code",
                    "key": [IMAGE_BASE + 0x2000, 0],
                }],
            })
            return {"resolutions": [replayed]}

        result = self._run(
            units=[unit("a", 0x1000), unit("callee", 0x2000)],
            roots=["a"],
            exits=[exit_row],
            inductive=[seed],
            resolver=resolver,
            summary_resolver=summaries,
            authority_only=True,
        )

        self.assertFalse(result.complete)
        self.assertEqual(result.recovered_targets[0]["status"], "incomplete")
        self.assertNotIn(
            exit_row["id"],
            result.fixed_point["inductive_replay"]["accepted_nodes"],
        )

    def test_unused_unknown_scalar_families_are_not_global_obligations(
        self,
    ) -> None:
        result = self._run(
            units=[unit("root", 0x1000)],
            roots=["root"],
            resolver=lambda **_kwargs: {"resolutions": []},
        )

        self.assertTrue(result.complete, result.fixed_point)
        dependencies = {
            row["id"]: row for row in result.fixed_point["dependencies"]
        }
        self.assertEqual(
            dependencies[call_summary_family_node_id("root", "memory")][
                "status"
            ],
            "incomplete",
        )
        self.assertEqual(
            dependencies[call_summary_family_node_id("root", "result")][
                "status"
            ],
            "incomplete",
        )

    def test_closed_register_family_records_checked_non_preservation(self) -> None:
        checked_false = _summary_register_state({
            "status": "complete",
            "preserved_registers": [],
            "register_preservation": {
                "status": "complete",
                "checked_preserved_registers": [],
                "checked_clobbered_registers": ["ebp", "ebx", "edi", "esi"],
            },
        }, "edi")
        unknown = _summary_register_state({
            "status": "incomplete",
            "preserved_registers": [],
            "register_preservation": {
                "status": "incomplete",
                "checked_preserved_registers": [],
                "checked_clobbered_registers": [],
            },
        }, "edi")

        self.assertEqual(checked_false.status, "complete")
        self.assertEqual(
            checked_false.fact.preserved_registers.registers, frozenset()
        )
        self.assertEqual(unknown.status, "incomplete")

    def test_inductive_replay_accepts_only_dependency_closed_sccs(self) -> None:
        accepted_exit = indirect_exit("exit:a:0", "a")
        rejected_exit = indirect_exit("exit:c:0", "c")
        accepted_seed = recovered(accepted_exit, "b")
        rejected_seed = recovered(rejected_exit, "d")
        accepted_seed["analysis_dependencies"] = [
            'call-frame:["a",0,"b"]'
        ]
        rejected_seed["analysis_dependencies"] = [
            'call-frame:["c",0,"d"]'
        ]

        def resolver(**kwargs: object) -> dict[str, object]:
            selected = kwargs["recovered_indirect_edges"]
            assert isinstance(selected, list)
            by_id = {str(row.get("id")): row for row in selected}
            resolutions: list[dict[str, object]] = []
            for exit_row, seed in (
                (accepted_exit, accepted_seed),
                (rejected_exit, rejected_seed),
            ):
                current = by_id.get(str(exit_row["id"]))
                if current is None or current.get("status") != "recovered":
                    resolutions.append(incomplete_recovery(exit_row))
                    continue
                replayed = dict(seed)
                if exit_row is accepted_exit:
                    replayed.update({
                        "origin_count": 1,
                        "origin_kinds": ["internal"],
                        "target_origin_witnesses": [{
                            "kind": "static_code",
                            "key": [IMAGE_BASE + 0x2000, 0],
                        }],
                    })
                resolutions.append(replayed)
            return {"resolutions": resolutions}

        result = self._run(
            units=[
                unit("a", 0x1000),
                unit("b", 0x2000),
                unit("c", 0x3000),
                unit("d", 0x4000),
            ],
            roots=["a", "c"],
            exits=[accepted_exit, rejected_exit],
            inductive=[accepted_seed, rejected_seed],
            resolver=resolver,
            authority_only=True,
        )

        self.assertFalse(result.complete)
        recoveries = {str(row["id"]): row for row in result.recovered_targets}
        self.assertEqual(recoveries["exit:a:0"]["status"], "recovered")
        self.assertEqual(recoveries["exit:c:0"]["status"], "incomplete")
        replay = result.fixed_point["inductive_replay"]
        self.assertTrue(replay["proof_authority"])
        self.assertFalse(replay["all_hypotheses_reproduced"])
        self.assertIn("exit:a:0", replay["accepted_nodes"])
        self.assertNotIn("exit:c:0", replay["accepted_nodes"])
        self.assertIn("call-summary:b", replay["accepted_nodes"])
        # Structural callee summaries are valid independently of whether a
        # particular rooted caller can recover that callee.  The failed
        # caller's site projection and exit certificate remain unaccepted.
        self.assertIn("call-summary:d", replay["accepted_nodes"])
        self.assertNotIn(
            'call-frame:["c",0,"d"]', replay["accepted_nodes"]
        )

    def test_incomplete_analysis_retains_actionable_failure(self) -> None:
        exit_row = indirect_exit("exit:a:0", "a")

        def resolver(**_kwargs: object) -> dict[str, object]:
            row = incomplete_recovery(exit_row)
            row["failure"] = {
                "code": "register_target_origin_missing",
                "register": "eax",
            }
            return {"resolutions": [row]}

        result = self._run(
            units=[unit("a", 0x1000)],
            roots=["a"],
            exits=[exit_row],
            resolver=resolver,
        )

        self.assertFalse(result.complete)
        self.assertEqual(
            result.recovered_targets[0]["failure"],
            {"code": "register_target_origin_missing", "register": "eax"},
        )

    def test_explicit_proposal_only_mode_skips_cold_authority_pass(self) -> None:
        result = self._run(
            units=[unit("a", 0x1000)],
            roots=["a"],
            resolver=lambda **_kwargs: {"resolutions": []},
            proposal_only=True,
        )

        self.assertFalse(result.complete)
        self.assertEqual(result.fixed_point["cold_replay_rounds"], 0)
        self.assertFalse(result.fixed_point["cold_initial_recoveries_empty"])
        self.assertTrue(result.fixed_point["proposal_only"])
        self.assertEqual(
            result.fixed_point["failure_reasons"],
            ["proposal_only_non_authorizing"],
        )

    def test_authority_only_mode_skips_proposal_discovery(self) -> None:
        result = self._run(
            units=[unit("a", 0x1000)],
            roots=["a"],
            resolver=lambda **_kwargs: {"resolutions": []},
            authority_only=True,
        )

        self.assertTrue(result.complete, result.fixed_point)
        self.assertEqual(result.fixed_point["discovery_rounds"], 0)
        self.assertGreater(result.fixed_point["cold_replay_rounds"], 0)
        self.assertTrue(result.fixed_point["authority_only"])
        self.assertFalse(
            result.fixed_point["proposal_diagnostics"]["discovery_executed"]
        )

    def test_finite_target_overflow_is_explicitly_incomplete(self) -> None:
        exit_row = indirect_exit("exit:a:0", "a")

        def resolver(**_kwargs: object) -> dict[str, object]:
            return {"resolutions": [recovered(exit_row, "b", "c", "d")]}

        result = self._run(
            units=[
                unit("a", 0x1000),
                unit("b", 0x2000),
                unit("c", 0x3000),
                unit("d", 0x4000),
            ],
            roots=["a"],
            exits=[exit_row],
            resolver=resolver,
            budget=2,
        )

        self.assertFalse(result.complete)
        self.assertIn(
            "interprocedural_lattice_overflow_or_conflict",
            result.fixed_point["failure_reasons"],
        )
        self.assertEqual(result.recovered_targets[0]["status"], "incomplete")
        self.assertEqual(
            result.recovered_targets[0]["failure"]["code"],
            "finite_value_budget_exceeded",
        )

    def test_exit_dependencies_follow_exact_origin_witness(self) -> None:
        exit_row = indirect_exit("exit:after:0", "after")

        def resolver(**_kwargs: object) -> dict[str, object]:
            resolution = recovered(exit_row)
            resolution["external_targets"] = [
                {"dll": "fixture.dll", "symbol": "fixture_target"}
            ]
            resolution["analysis_dependencies"] = [
                'call-frame:["root",0,"helper"]'
            ]
            return {"resolutions": [resolution]}

        result = self._run(
            units=[
                unit("root", 0x1000, calls=(0x2000,)),
                unit("after", 0x1001),
                unit("helper", 0x2000),
            ],
            roots=["root"],
            direct=[edge("root", "after")],
            calls=[call_edge("root", "helper")],
            exits=[exit_row],
            resolver=resolver,
        )

        self.assertTrue(result.complete, result.fixed_point)
        inventory = {row["id"]: row for row in result.fixed_point["dependencies"]}
        self.assertEqual(
            inventory["exit:after:0"]["dependencies"],
            ["call-summary:helper"],
        )

    def test_dominating_known_write_binds_exact_global_invariant(self) -> None:
        exit_row = indirect_exit("exit:dispatch:0", "dispatch")
        invariant = slot_invariant("init", 0x1000, IMAGE_BASE + 0x2000)

        result = self._run(
            units=[
                unit("init", 0x1000, memory=(slot_write(const(IMAGE_BASE + 0x2000)),)),
                unit(
                    "load",
                    0x1010,
                    writes=({"register": "eax", "value": load(const(SLOT))},),
                    memory=(slot_read(),),
                ),
                unit("dispatch", 0x1020),
                unit("target", 0x2000),
            ],
            roots=["init"],
            direct=[edge("init", "load"), edge("load", "dispatch")],
            exits=[exit_row],
            globals=[invariant],
            resolver=lambda **_kwargs: {
                "resolutions": [recovered(exit_row, "target")]
            },
        )

        self.assertTrue(result.complete, result.fixed_point)
        recovery = result.recovered_targets[0]
        self.assertEqual(recovery["authority_dependencies"], [{
            "role": "mutable_slot_invariant",
            "content_id": invariant.content_id,
        }])
        self.assertEqual(
            recovery["mutable_slot_dependencies"][0]["read_sites"],
            [{"unit_id": "load", "event_index": 0}],
        )
        dependencies = {
            row["id"]: row["dependencies"]
            for row in result.fixed_point["dependencies"]
        }
        self.assertEqual(dependencies["exit:dispatch:0"], [invariant.content_id])

    def test_checked_launch_slot_seeds_cold_provenance_without_machine_write(self) -> None:
        exit_row = indirect_exit("exit:dispatch:0", "dispatch")
        invariant = slot_invariant("launch-binding", 0x1000, IMAGE_BASE + 0x2000)
        observed = []

        def resolver(**kwargs: Any) -> dict[str, object]:
            observed.append(kwargs["initial_known_slots"])
            return {"resolutions": [recovered(exit_row, "target")]}

        result = self._run(
            units=[
                unit(
                    "load",
                    0x1010,
                    writes=({"register": "eax", "value": load(const(SLOT))},),
                    memory=(slot_read(),),
                ),
                unit("dispatch", 0x1020),
                unit("target", 0x2000),
            ],
            roots=["load"],
            direct=[edge("load", "dispatch")],
            exits=[exit_row],
            globals=[invariant],
            resolver=resolver,
        )

        self.assertTrue(result.complete, result.fixed_point)
        self.assertTrue(observed)
        seeded = observed[-1][SLOT]
        self.assertEqual({origin.key for origin in seeded}, {(IMAGE_BASE + 0x2000,)})
        self.assertEqual(
            {origin.dependencies for origin in seeded},
            {(invariant.content_id,)},
        )
        self.assertEqual(
            result.recovered_targets[0]["mutable_slot_dependencies"][0]["content_id"],
            invariant.content_id,
        )

    def test_event_slot_invariant_is_not_seeded_at_roots(self) -> None:
        exit_row = indirect_exit("exit:dispatch:0", "dispatch")
        invariant = slot_invariant(
            "load",
            0x1010,
            IMAGE_BASE + 0x2000,
            event_index=0,
        )
        observed: list[tuple[dict[object, object], dict[object, object]]] = []

        def resolver(**kwargs: Any) -> dict[str, object]:
            observed.append((
                kwargs["initial_known_slots"],
                kwargs["initial_event_known_slots"],
            ))
            resolution = recovered(exit_row, "target")
            resolution["analysis_dependencies"] = [invariant.content_id]
            resolution["target_origin_witnesses"] = [{
                "kind": "exact",
                "key": [IMAGE_BASE + 0x2000],
                "authority_dependencies": [invariant.content_id],
            }]
            return {"resolutions": [resolution]}

        result = self._run(
            units=[
                unit(
                    "load",
                    0x1010,
                    writes=({"register": "eax", "value": load(const(SLOT))},),
                    memory=(slot_read(),),
                ),
                unit("dispatch", 0x1020),
                unit("target", 0x2000),
            ],
            roots=["load"],
            direct=[edge("load", "dispatch")],
            exits=[exit_row],
            globals=[invariant],
            resolver=resolver,
        )

        self.assertTrue(result.complete, result.fixed_point)
        self.assertTrue(observed)
        root_slots, event_slots = observed[-1]
        self.assertEqual(root_slots, {})
        self.assertIn(CallSiteId("load", 0), event_slots)
        self.assertEqual(
            result.recovered_targets[0]["mutable_slot_dependencies"],
            [{
                "slot_rva": SLOT - IMAGE_BASE,
                "width_bytes": 4,
                "content_id": invariant.content_id,
                "read_sites": [{"unit_id": "load", "event_index": 0}],
                "origin_witnessed": False,
            }],
        )

    def test_control_only_slot_dependency_is_bound_to_checked_invariant(self) -> None:
        exit_row = indirect_exit("exit:dispatch:0", "dispatch")
        target_invariant = slot_invariant(
            "target-slot",
            0x1010,
            IMAGE_BASE + 0x2000,
        )
        control_invariant = slot_invariant(
            "control-slot",
            0x1020,
            0,
            slot_address=SLOT + 4,
        )

        def resolver(**_kwargs: Any) -> dict[str, object]:
            resolution = recovered(exit_row, "target")
            resolution["analysis_dependencies"] = [
                control_invariant.content_id,
                target_invariant.content_id,
            ]
            resolution["target_origin_witnesses"] = [{
                "kind": "exact",
                "key": [IMAGE_BASE + 0x2000],
                "authority_dependencies": [target_invariant.content_id],
            }]
            return {"resolutions": [resolution]}

        result = self._run(
            units=[unit("dispatch", 0x1030), unit("target", 0x2000)],
            roots=["dispatch"],
            direct=[],
            exits=[exit_row],
            globals=[target_invariant, control_invariant],
            resolver=resolver,
        )

        self.assertTrue(result.complete, result.fixed_point)
        dependencies = result.recovered_targets[0][
            "mutable_slot_dependencies"
        ]
        self.assertEqual(
            {row["slot_rva"] for row in dependencies},
            {SLOT - IMAGE_BASE, SLOT + 4 - IMAGE_BASE},
        )
        self.assertEqual(
            {row["content_id"] for row in dependencies},
            {target_invariant.content_id, control_invariant.content_id},
        )

    def test_cold_origin_witness_binds_symbolic_slot_address(self) -> None:
        exit_row = indirect_exit("exit:dispatch:0", "dispatch")
        invariant = slot_invariant("launch-binding", 0x1000, IMAGE_BASE + 0x2000)

        def resolver(**_kwargs: Any) -> dict[str, object]:
            resolution = recovered(exit_row, "target")
            resolution["analysis_dependencies"] = [invariant.content_id]
            resolution["target_origin_witnesses"] = [{
                "kind": "exact",
                "key": [IMAGE_BASE + 0x2000],
                "authority_dependencies": [invariant.content_id],
            }]
            return {"resolutions": [resolution]}

        result = self._run(
            units=[
                unit(
                    "load",
                    0x1010,
                    writes=({"register": "eax", "value": load(reg("esi"))},),
                ),
                unit("dispatch", 0x1020),
                unit("target", 0x2000),
            ],
            roots=["load"],
            direct=[edge("load", "dispatch")],
            exits=[exit_row],
            globals=[invariant],
            resolver=resolver,
        )

        self.assertTrue(result.complete, result.fixed_point)
        self.assertEqual(
            result.recovered_targets[0]["authority_dependencies"],
            [{
                "role": "mutable_slot_invariant",
                "content_id": invariant.content_id,
            }],
        )

    def test_uncontracted_call_taints_checked_launch_slot(self) -> None:
        exit_row = indirect_exit("exit:dispatch:0", "dispatch")
        invariant = slot_invariant("launch-binding", 0x1000, IMAGE_BASE + 0x2000)
        caller = unit("call", 0x1000)
        call_event = {"kind": "external_call", "dll": "unknown.dll", "symbol": "Mutate"}
        caller["semantics"]["external_events"] = [call_event]
        caller["semantics"]["ordered_events"] = [call_event]

        result = self._run(
            units=[
                caller,
                unit(
                    "load",
                    0x1010,
                    writes=({"register": "eax", "value": load(const(SLOT))},),
                    memory=(slot_read(),),
                ),
                unit("dispatch", 0x1020),
                unit("target", 0x2000),
            ],
            roots=["call"],
            direct=[edge("call", "load"), edge("load", "dispatch")],
            exits=[exit_row],
            globals=[invariant],
            resolver=lambda **_kwargs: {
                "resolutions": [recovered(exit_row, "target")]
            },
        )

        self.assertFalse(result.complete)
        self.assertEqual(
            result.recovered_targets[0]["failure"]["code"],
            "mutable_slot_tainted",
        )

    def test_unknown_overwrite_taints_recovered_slot_target(self) -> None:
        exit_row = indirect_exit("exit:dispatch:0", "dispatch")
        invariant = slot_invariant("init", 0x1000, IMAGE_BASE + 0x2000)
        result = self._run(
            units=[
                unit(
                    "init",
                    0x1000,
                    memory=(
                        slot_write(const(IMAGE_BASE + 0x2000)),
                        slot_write(reg("ecx")),
                    ),
                ),
                unit("load", 0x1010, writes=({"register": "eax", "value": load(const(SLOT))},)),
                unit("dispatch", 0x1020),
                unit("target", 0x2000),
            ],
            roots=["init"],
            direct=[edge("init", "load"), edge("load", "dispatch")],
            exits=[exit_row],
            globals=[invariant],
            resolver=lambda **_kwargs: {
                "resolutions": [recovered(exit_row, "target")]
            },
        )

        self.assertFalse(result.complete)
        self.assertEqual(
            result.recovered_targets[0]["failure"]["code"],
            "mutable_slot_tainted",
        )

    def test_bounded_selector_does_not_require_mutable_value_invariant(self) -> None:
        exit_row = indirect_exit(
            "exit:dispatch:0", "dispatch", kind="indirect_jump"
        )
        exit_row["target_expression"] = load({
            "op": "add32",
            "args": [const(IMAGE_BASE + 0x3000), {
                "op": "mul32",
                "args": [reg("eax"), const(4)],
            }],
        })
        resolution = bounded_table_recovery(
            exit_row,
            ("target-a", 0x2000),
            ("target-b", 0x2100),
        )

        result = self._run(
            units=[
                unit(
                    "load-selector",
                    0x1000,
                    writes=({"register": "eax", "value": load(const(SLOT))},),
                    memory=(slot_read(),),
                ),
                unit("dispatch", 0x1010),
                unit("target-a", 0x2000),
                unit("target-b", 0x2100),
            ],
            roots=["load-selector"],
            direct=[edge("load-selector", "dispatch")],
            exits=[exit_row],
            resolver=lambda **_kwargs: {"resolutions": [resolution]},
        )

        self.assertTrue(result.complete, result.fixed_point)
        recovered_target = result.recovered_targets[0]
        self.assertEqual(recovered_target["status"], "recovered")
        self.assertNotIn("mutable_slot_dependencies", recovered_target)
        self.assertEqual(
            recovered_target["target_set_dependency"],
            resolution["target_set_dependency"],
        )

    def test_exact_static_target_hypothesis_closes_only_after_cycle_replay(self) -> None:
        exit_row = indirect_exit(
            "exit:dispatch:0", "dispatch", kind="indirect_jump"
        )
        exit_row["target_expression"] = load({
            "op": "add32",
            "args": [
                const(IMAGE_BASE + 0x3000),
                {"op": "mul32", "args": [reg("eax"), const(4)]},
            ],
        })
        hypothesis = bounded_table_recovery(exit_row, ("target", 0x2000))
        hypothesis.update({
            "proof_authority": False,
            "proposal_source": "inductive_static_target_inventory_v2",
            "hypothesis_validation": "exact_pe_target_inventory_v2",
        })
        dynamic = recovered(exit_row, "target")
        dynamic.update({
            "target_rvas": [0x2000],
            "origin_count": 1,
            "origin_kinds": ["internal"],
            "target_origin_witnesses": [{
                "kind": "static_code",
                "key": [IMAGE_BASE + 0x2000, [IMAGE_BASE + 0x3000]],
            }],
            "analysis_dependencies": [],
        })

        def resolver(**kwargs):
            selected = kwargs["recovered_indirect_edges"]
            return {
                "resolutions": [
                    dynamic
                    if any(
                        row.get("id") == exit_row["id"]
                        and row.get("status") == "recovered"
                        for row in selected
                    )
                    else incomplete_recovery(exit_row)
                ]
            }

        result = self._run(
            units=[unit("dispatch", 0x1000), unit("target", 0x2000)],
            roots=["dispatch"],
            direct=[edge("target", "dispatch")],
            exits=[exit_row],
            inductive=[hypothesis],
            resolver=resolver,
            authority_only=True,
        )

        self.assertTrue(result.complete, result.fixed_point)
        recovery = result.recovered_targets[0]
        self.assertEqual(recovery["status"], "recovered")
        self.assertEqual(
            recovery["target_set_dependency"],
            hypothesis["target_set_dependency"],
        )
        self.assertIn(
            exit_row["id"],
            result.fixed_point["inductive_replay"]["accepted_nodes"],
        )

    def test_checked_stack_write_does_not_taint_image_slot(self) -> None:
        exit_row = indirect_exit("exit:dispatch:0", "dispatch")
        invariant = slot_invariant("init", 0x1000, IMAGE_BASE + 0x2000)
        units = [
            unit(
                "init",
                0x1000,
                memory=(slot_write(const(IMAGE_BASE + 0x2000)),),
            ),
            unit("spill", 0x1010, memory=(stack_write(-4, reg("ecx")),)),
            unit(
                "load",
                0x1020,
                writes=({"register": "eax", "value": load(const(SLOT))},),
                memory=(slot_read(),),
            ),
            unit("dispatch", 0x1030),
            unit("target", 0x2000),
        ]
        direct = [
            edge("init", "spill"),
            edge("spill", "load"),
            edge("load", "dispatch"),
        ]
        resolver = lambda **_kwargs: {
            "resolutions": [recovered(exit_row, "target")]
        }

        unchecked = self._run(
            units=units,
            roots=["init"],
            direct=direct,
            exits=[exit_row],
            globals=[invariant],
            resolver=resolver,
        )
        checked = self._run(
            units=units,
            roots=["init"],
            direct=direct,
            exits=[exit_row],
            globals=[invariant],
            checked_stack_units=["spill"],
            resolver=resolver,
        )

        self.assertEqual(
            unchecked.recovered_targets[0]["failure"]["code"],
            "mutable_slot_tainted",
        )
        self.assertTrue(checked.complete, checked.fixed_point)
        self.assertEqual(
            checked.recovered_targets[0]["authority_dependencies"],
            [{
                "role": "mutable_slot_invariant",
                "content_id": invariant.content_id,
            }],
        )

    def test_call_summary_carries_writable_stack_argument_to_continuation(self) -> None:
        source_slot = SLOT + 4
        continuation_exit = indirect_exit("exit:continuation:0", "continuation")
        callee_exit = indirect_exit("exit:helper:0", "helper")

        call = unit(
            "call",
            0x1000,
            calls=(0x2000,),
            memory=(
                {"kind": "read", "width": 4, "address": const(source_slot)},
                stack_write(-4, load(const(source_slot))),
            ),
        )
        call["semantics"]["external_events"][0]["register_inputs"]["esp"] = {
            "op": "add32",
            "args": [reg("esp"), const(-4)],
        }
        call["semantics"]["ordered_events"][-1]["register_inputs"]["esp"] = {
            "op": "add32",
            "args": [reg("esp"), const(-4)],
        }
        helper = unit(
            "helper",
            0x2000,
            writes=({"register": "eax", "value": load(const(SLOT))},),
            memory=(slot_read(),),
        )

        def summaries(**kwargs: Any) -> dict[str, object]:
            result = summary_adapter(**kwargs)
            if not any(
                row["target_rva"] == 0x2000 for row in result["summaries"]
            ):
                result["summaries"].append(summary_row("helper", 0x2000))
            for row in result["summaries"]:
                if row["target_rva"] != 0x2000:
                    continue
                row["memory_effects"] = {
                    "status": "complete",
                    "local_sites": [{"kind": "write"}],
                    "delegated_dependencies": [],
                }
                row["result_memory_origins"] = {
                    "status": "complete",
                    "locations": [{
                        "location": {"kind": "exact", "key": [SLOT]},
                        "value": {"kind": "input_stack_word", "offset": 4},
                    }],
                }
            return result

        result = self._run(
            units=[
                call,
                unit(
                    "continuation",
                    0x1020,
                    writes=({"register": "eax", "value": load(const(SLOT))},),
                    memory=(slot_read(),),
                ),
                helper,
                unit("target", 0x3000),
            ],
            roots=["call"],
            direct=[edge("call", "continuation")],
            calls=[call_edge("call", "helper")],
            exits=[continuation_exit, callee_exit],
            checked_stack_units=["call"],
            writable_image_ranges=[(SLOT, source_slot + 4)],
            summary_resolver=summaries,
            resolver=lambda **_kwargs: {
                "resolutions": [
                    recovered(continuation_exit, "target"),
                    recovered(callee_exit, "target"),
                ]
            },
        )
        unchecked = self._run(
            units=[
                call,
                unit(
                    "continuation",
                    0x1020,
                    writes=({"register": "eax", "value": load(const(SLOT))},),
                    memory=(slot_read(),),
                ),
                helper,
                unit("target", 0x3000),
            ],
            roots=["call"],
            direct=[edge("call", "continuation")],
            calls=[call_edge("call", "helper")],
            exits=[continuation_exit, callee_exit],
            writable_image_ranges=[(SLOT, source_slot + 4)],
            summary_resolver=summaries,
            resolver=lambda **_kwargs: {
                "resolutions": [
                    recovered(continuation_exit, "target"),
                    recovered(callee_exit, "target"),
                ]
            },
        )

        by_id = {row["id"]: row for row in result.recovered_targets}
        self.assertEqual(
            {
                row["slot_rva"]
                for row in by_id[continuation_exit["id"]][
                    "mutable_slot_dependencies"
                ]
            },
            {SLOT - IMAGE_BASE, source_slot - IMAGE_BASE},
        )
        self.assertEqual(
            {
                row["slot_rva"]
                for row in by_id[callee_exit["id"]]["mutable_slot_dependencies"]
            },
            {SLOT - IMAGE_BASE},
        )
        unchecked_by_id = {
            row["id"]: row for row in unchecked.recovered_targets
        }
        self.assertEqual(
            {
                row["slot_rva"]
                for row in unchecked_by_id[continuation_exit["id"]][
                    "mutable_slot_dependencies"
                ]
            },
            {SLOT - IMAGE_BASE},
        )
        self.assertEqual(
            unchecked_by_id[continuation_exit["id"]]["failure"]["code"],
            "mutable_slot_tainted",
        )

    def test_checked_call_summary_stack_copy_closes_both_slot_dependencies(self) -> None:
        source_slot = SLOT + 4
        exit_row = indirect_exit("exit:continuation:0", "continuation")
        call = unit(
            "call",
            0x1000,
            calls=(0x2000,),
            memory=(
                {"kind": "read", "width": 4, "address": const(source_slot)},
                stack_write(-4, load(const(source_slot))),
            ),
        )
        call["semantics"]["external_events"][0]["register_inputs"]["esp"] = {
            "op": "add32",
            "args": [reg("esp"), const(-4)],
        }
        call["semantics"]["ordered_events"][-1]["register_inputs"]["esp"] = {
            "op": "add32",
            "args": [reg("esp"), const(-4)],
        }

        def summaries(**kwargs: Any) -> dict[str, object]:
            result = summary_adapter(**kwargs)
            if not any(
                row["target_rva"] == 0x2000 for row in result["summaries"]
            ):
                result["summaries"].append(summary_row("helper", 0x2000))
            for row in result["summaries"]:
                if row["target_rva"] == 0x2000:
                    row["memory_effects"] = {
                        "status": "complete",
                        "local_sites": [{"kind": "write"}],
                        "delegated_dependencies": [],
                    }
                    row["result_memory_origins"] = {
                        "status": "complete",
                        "locations": [{
                            "location": {"kind": "exact", "key": [SLOT]},
                            "value": {
                                "kind": "input_stack_word",
                                "offset": 4,
                            },
                        }],
                    }
            return result

        result = self._run(
            units=[
                call,
                unit(
                    "continuation",
                    0x1020,
                    writes=({"register": "eax", "value": load(const(SLOT))},),
                    memory=(slot_read(),),
                ),
                unit("helper", 0x2000),
                unit("target", 0x3000),
            ],
            roots=["call"],
            direct=[edge("call", "continuation")],
            calls=[call_edge("call", "helper")],
            exits=[exit_row],
            checked_stack_units=["call"],
            writable_image_ranges=[(SLOT, source_slot + 4)],
            globals=[
                slot_invariant(
                    "call",
                    0x1000,
                    IMAGE_BASE + 0x3000,
                    slot_address=SLOT,
                ),
                slot_invariant(
                    "call",
                    0x1000,
                    IMAGE_BASE + 0x3000,
                    slot_address=source_slot,
                ),
            ],
            summary_resolver=summaries,
            resolver=lambda **_kwargs: {
                "resolutions": [recovered(exit_row, "target")]
            },
        )

        self.assertTrue(result.complete, result.fixed_point)
        self.assertEqual(
            {
                row["slot_rva"]
                for row in result.recovered_targets[0]["mutable_slot_dependencies"]
            },
            {SLOT - IMAGE_BASE, source_slot - IMAGE_BASE},
        )

    def test_finite_branch_join_preserves_mutable_slot_dependency(self) -> None:
        exit_row = indirect_exit("exit:dispatch:0", "dispatch")
        invariant = slot_invariant(
            "init", 0x1000, IMAGE_BASE + 0x2000, IMAGE_BASE + 0x3000
        )
        result = self._run(
            units=[
                unit("init", 0x1000, memory=(slot_write(const(IMAGE_BASE + 0x2000)),)),
                unit("branch", 0x1010),
                unit("left", 0x1020, memory=(slot_write(const(IMAGE_BASE + 0x2000)),)),
                unit("right", 0x1030, memory=(slot_write(const(IMAGE_BASE + 0x3000)),)),
                unit("load", 0x1040, writes=({"register": "eax", "value": load(const(SLOT))},)),
                unit("dispatch", 0x1050),
                unit("left-target", 0x2000),
                unit("right-target", 0x3000),
            ],
            roots=["init"],
            direct=[
                edge("init", "branch"),
                edge("branch", "left"),
                edge("branch", "right"),
                edge("left", "load"),
                edge("right", "load"),
                edge("load", "dispatch"),
            ],
            exits=[exit_row],
            globals=[invariant],
            resolver=lambda **_kwargs: {
                "resolutions": [
                    recovered(exit_row, "left-target", "right-target")
                ]
            },
        )

        self.assertTrue(result.complete, result.fixed_point)
        self.assertEqual(
            result.recovered_targets[0]["mutable_slot_dependencies"][0]["content_id"],
            invariant.content_id,
        )

    def test_direct_slot_target_requires_invariant_without_root_seed(self) -> None:
        exit_row = indirect_exit("exit:dispatch:0", "dispatch")
        exit_row["target_expression"] = load(const(SLOT))
        result = self._run(
            units=[
                unit("init", 0x1000, memory=(slot_write(const(IMAGE_BASE + 0x2000)),)),
                unit("dispatch", 0x1010),
                unit("target", 0x2000),
            ],
            roots=["init"],
            direct=[edge("init", "dispatch")],
            exits=[exit_row],
            resolver=lambda **_kwargs: {
                "resolutions": [recovered(exit_row, "target")]
            },
        )

        self.assertFalse(result.complete)
        self.assertEqual(
            result.recovered_targets[0]["failure"]["code"],
            "mutable_slot_invariant_missing",
        )
        self.assertEqual(result.fixed_point["proposal_seed_count"], 0)

    def test_readonly_image_target_never_requires_mutable_slot_authority(self) -> None:
        readonly_slot = IMAGE_BASE + 0x1500
        exit_row = indirect_exit("exit:dispatch:0", "dispatch")
        exit_row["target_expression"] = load(const(readonly_slot))
        result = self._run(
            units=[
                unit(
                    "unknown-write",
                    0x1000,
                    memory=({
                        "kind": "write",
                        "width": 4,
                        "address": reg("ecx"),
                        "value": reg("eax"),
                    },),
                ),
                unit("dispatch", 0x1010),
                unit("target", 0x2000),
            ],
            roots=["unknown-write"],
            direct=[edge("unknown-write", "dispatch")],
            exits=[exit_row],
            resolver=lambda **_kwargs: {
                "resolutions": [recovered(exit_row, "target")]
            },
            writable_image_ranges=[(SLOT, SLOT + 0x1000)],
        )

        self.assertTrue(result.complete, result.fixed_point)
        recovery = result.recovered_targets[0]
        self.assertEqual(recovery["status"], "recovered")
        self.assertNotIn("mutable_slot_dependencies", recovery)

    def test_unknown_memory_target_is_one_primary_frontier(self) -> None:
        exit_row = indirect_exit("exit:dispatch:0", "dispatch")
        exit_row["target_expression"] = load(reg("eax"))

        result = self._run(
            units=[unit("dispatch", 0x1010), unit("target", 0x2000)],
            roots=["dispatch"],
            exits=[exit_row],
            resolver=lambda **_kwargs: {
                "resolutions": [recovered(exit_row, "target")]
            },
        )

        self.assertFalse(result.complete)
        recovery = result.recovered_targets[0]
        self.assertEqual(
            recovery["failure"]["code"],
            "target_memory_address_unresolved",
        )
        self.assertNotIn("mutable_slot_dependencies", recovery)
        dependency = next(
            row
            for row in result.fixed_point["dependencies"]
            if row["id"] == exit_row["id"]
        )
        self.assertEqual(dependency["dependencies"], [])

    def test_unknown_memory_target_preserves_precise_provenance_failure(self) -> None:
        exit_row = indirect_exit("exit:dispatch:0", "dispatch")
        exit_row["target_expression"] = load(reg("eax"))
        unresolved = incomplete_recovery(exit_row)
        unresolved["failure"] = {"code": "operation_view_origin_missing"}

        result = self._run(
            units=[unit("dispatch", 0x1010), unit("target", 0x2000)],
            roots=["dispatch"],
            exits=[exit_row],
            resolver=lambda **_kwargs: {"resolutions": [unresolved]},
        )

        self.assertFalse(result.complete)
        recovery = result.recovered_targets[0]
        self.assertEqual(
            recovery["failure"]["code"],
            "operation_view_origin_missing",
        )
        self.assertNotIn("mutable_slot_dependencies", recovery)

    def test_indirect_call_target_uses_pre_call_register_state(self) -> None:
        exit_row = indirect_exit("exit:dispatch:0", "dispatch")
        exit_row["target_expression"] = load({
            "op": "add32",
            "args": [const(28), reg("edx")],
        })
        dispatch = unit("dispatch", 0x1030)
        call_event = {
            "kind": "indirect_call",
            "register_inputs": {
                register: reg(register) for register in REGISTERS
            },
            "target": exit_row["target_expression"],
        }
        dispatch["semantics"].update({
            "external_events": [call_event],
            "ordered_events": [call_event],
            "register_writes": [{
                "register": register,
                "value": {
                    "op": "call_response",
                    "call_index": 0,
                    "register": register,
                    "width": 32,
                },
            } for register in REGISTERS],
        })

        result = self._run(
            units=[
                unit(
                    "load-slot",
                    0x1010,
                    writes=({"register": "eax", "value": load(const(SLOT))},),
                    memory=(slot_read(),),
                ),
                unit(
                    "load-object-table",
                    0x1020,
                    writes=({"register": "edx", "value": load(reg("eax"))},),
                    memory=({
                        "kind": "read",
                        "width": 4,
                        "address": reg("eax"),
                    },),
                ),
                dispatch,
                unit("target", 0x2000),
            ],
            roots=["load-slot"],
            direct=[
                edge("load-slot", "load-object-table"),
                edge("load-object-table", "dispatch"),
            ],
            exits=[exit_row],
            writable_image_ranges=[(SLOT, SLOT + 4)],
            resolver=lambda **_kwargs: {
                "resolutions": [recovered(exit_row, "target")]
            },
        )

        recovery = result.recovered_targets[0]
        self.assertEqual(
            recovery["failure"]["code"],
            "mutable_slot_tainted",
        )
        self.assertEqual(
            [row["slot_rva"] for row in recovery["mutable_slot_dependencies"]],
            [SLOT - IMAGE_BASE],
        )

    def test_indirect_call_event_binding_mismatch_fails_closed(self) -> None:
        exit_row = indirect_exit("exit:dispatch:0", "dispatch")
        exit_row["target_expression"] = load(const(SLOT))
        dispatch = unit("dispatch", 0x1010)
        wrong_event = {
            "kind": "external_call",
            "register_inputs": {
                register: reg(register) for register in REGISTERS
            },
        }
        dispatch["semantics"].update({
            "external_events": [wrong_event],
            "ordered_events": [wrong_event],
        })
        invariant = slot_invariant(
            "dispatch", 0x1010, IMAGE_BASE + 0x2000
        )

        result = self._run(
            units=[dispatch, unit("target", 0x2000)],
            roots=["dispatch"],
            exits=[exit_row],
            globals=[invariant],
            writable_image_ranges=[(SLOT, SLOT + 4)],
            resolver=lambda **_kwargs: {
                "resolutions": [recovered(exit_row, "target")]
            },
        )

        recovery = result.recovered_targets[0]
        self.assertEqual(recovery["status"], "incomplete")
        self.assertEqual(recovery["failure"]["code"], "mutable_slot_tainted")
        self.assertEqual(
            recovery["authority_dependencies"],
            [{
                "role": "mutable_slot_invariant",
                "content_id": invariant.content_id,
            }],
        )

    def test_tainted_global_invariant_cannot_authorize_recovery(self) -> None:
        exit_row = indirect_exit("exit:dispatch:0", "dispatch")
        invariant = slot_invariant(
            "init", 0x1000, IMAGE_BASE + 0x2000, tainted=True
        )
        result = self._run(
            units=[
                unit("init", 0x1000, memory=(slot_write(const(IMAGE_BASE + 0x2000)),)),
                unit("load", 0x1010, writes=({"register": "eax", "value": load(const(SLOT))},)),
                unit("dispatch", 0x1020),
                unit("target", 0x2000),
            ],
            roots=["init"],
            direct=[edge("init", "load"), edge("load", "dispatch")],
            exits=[exit_row],
            globals=[invariant],
            resolver=lambda **_kwargs: {
                "resolutions": [recovered(exit_row, "target")]
            },
        )

        self.assertFalse(result.complete)
        self.assertEqual(
            result.recovered_targets[0]["failure"]["code"],
            "mutable_slot_invariant_incomplete",
        )


if __name__ == "__main__":
    unittest.main()
