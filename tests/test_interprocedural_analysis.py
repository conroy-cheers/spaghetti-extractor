from __future__ import annotations

import unittest
from typing import Any
from unittest.mock import patch

from spaghetti_extractor.call_frame_hypotheses import (
    PreservedRegisterHypothesis,
    hypothesis_id as call_frame_hypothesis_id,
)
from spaghetti_extractor.call_site_effects import (
    CallSiteEffect,
    CallSiteId,
)
from spaghetti_extractor.interprocedural_analysis import (
    _call_summary_inputs,
    _call_summary_memory_preservation,
    _call_site_memory_preservation,
    _requires_inductive_replay,
    analyze_interprocedural_control,
)
from spaghetti_extractor.indirect_target_dependency_v2 import (
    build_bounded_selector_dependency_v2,
)
from spaghetti_extractor.checked_memory_access_v2 import (
    MEMORY_ACCESS_PROPOSAL_V2_FORMAT,
)
from spaghetti_extractor.machine_ir_authority_v2 import machine_ir_sha256
from spaghetti_extractor.machine_abi import resolve_machine_call_abi
from spaghetti_extractor.provenance_domain import ValueOrigin
from spaghetti_extractor.hybrid_authority_v2 import (
    BinaryBinding,
    EvidenceIssue,
    EvidenceIssueKind,
    FiniteAlternatives,
    GlobalSlotInvariant,
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
) -> dict[str, object]:
    complete = preserved is not None
    return CallSiteEffect(
        site=CallSiteId(unit_id, 0),
        transfer_kind="internal_call",
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
    return GlobalSlotInvariant(
        binding=binding,
        slot_rva=SLOT - IMAGE_BASE,
        width_bytes=4,
        invariant_kind="finite_set",
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
    def test_mutable_facts_cross_only_memory_preserving_call_sites(self) -> None:
        units = [unit("caller", 0x1000, calls=(0x2000,)), unit("callee", 0x2000)]
        call_edges = [call_edge("caller", "callee")]
        common = {
            "units": units,
            "internal_call_edges": call_edges,
            "recoveries": [],
            "import_abis": {},
            "image_base": IMAGE_BASE,
        }

        unsafe = _call_site_memory_preservation(
            internal_memory_preservation={}, **common
        )
        framed = _call_site_memory_preservation(
            internal_memory_preservation={IMAGE_BASE + 0x2000: True},
            **common,
        )

        self.assertFalse(unsafe["caller"])
        self.assertTrue(framed["caller"])
        self.assertTrue(unsafe["callee"])

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
                ]
            },
            image_base=IMAGE_BASE,
        )

        self.assertEqual(
            set(result),
            {IMAGE_BASE + 0x2000, IMAGE_BASE + 0x2100},
        )

    def test_partial_summary_families_remain_independently_usable(self) -> None:
        preserved, cleanup, results, memory_results = _call_summary_inputs(
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
            {
                ValueOrigin("exact", (SLOT,)): frozenset({
                    ValueOrigin("resource", ("fixture-resource",))
                })
            },
        )

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
                finite_value_budget=budget,
                proposal_only=proposal_only,
                authority_only=authority_only,
                internal_function_contracts=internal_contracts,
            )

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
        self.assertEqual(proposal["status"], "incomplete")
        self.assertIsNot(proposal.get("proof_authority"), True)
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
        self.assertNotIn("call-summary:d", replay["accepted_nodes"])

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
