from __future__ import annotations

import hashlib
import json

import pytest

from spaghetti_extractor.relational.definedness import (
    DEFINEDNESS_EVIDENCE_FORMAT,
    DefinednessAnalysisError,
    analyze_definedness_jsonl,
    analyze_definedness_rows,
)


def _reg(name: str) -> dict[str, object]:
    return {"op": "reg", "name": name, "width": 32}


def _flag(name: str) -> dict[str, object]:
    return {"op": "flag", "name": name}


def _undefined(undefined_id: str = "1000:cf", op: str = "undefined_flag") -> dict[str, str]:
    return {"op": op, "id": undefined_id, "reason": "architecturally undefined"}


def _row(
    transfer_id: str,
    rva: int,
    target: int | None,
    *,
    register_writes: list[dict[str, object]] | None = None,
    flag_writes: list[dict[str, object]] | None = None,
    outcome: dict[str, object] | None = None,
    edge_conditions: list[dict[str, object]] | None = None,
    memory_events: list[dict[str, object]] | None = None,
    external_events: list[dict[str, object]] | None = None,
    faults: list[dict[str, object]] | None = None,
    reachable: bool = True,
) -> dict[str, object]:
    if outcome is None:
        outcome = (
            {"kind": "fallthrough", "target_rva": target}
            if target is not None
            else {"kind": "return", "value": _reg("eax")}
        )
    if edge_conditions is None:
        edge_conditions = (
            [{"condition": {"op": "true"}, "target_rva": target}]
            if target is not None
            else []
        )
    memory_events = memory_events or []
    external_events = external_events or []
    return {
        "format": "stage-a-semantic-transfer-contract-v1",
        "stage_b_format": "stage-b-state-machine-transfer-v1",
        "expression_model": "stage-a-semantic-ir-v1",
        "id": transfer_id,
        "reachable": reachable,
        "status": "reimplementable",
        "blocker": None,
        "original": {"rva_start": rva, "rva_end": rva + 1, "size": 1},
        "register_writes": register_writes or [],
        "flag_writes": flag_writes or [],
        "memory_events": memory_events,
        "external_events": external_events,
        "ordered_events": [
            {"family": "memory", **event} for event in memory_events
        ] + [{"family": "external", **event} for event in external_events],
        "faults": faults or [],
        "edge_conditions": edge_conditions,
        "outcome": outcome,
    }


def _source(target: int = 0x1010) -> dict[str, object]:
    return _row(
        "source",
        0x1000,
        target,
        flag_writes=[{"flag": "cf", "value": _undefined()}],
    )


def _slot(result: dict[str, object]) -> dict[str, object]:
    slots = result["slots"]
    assert isinstance(slots, list) and len(slots) == 1
    assert isinstance(slots[0], dict)
    return slots[0]


def _reason(result: dict[str, object]) -> str:
    slot = _slot(result)
    blockers = slot["blocking_paths"]
    assert isinstance(blockers, list) and blockers
    return blockers[0]["reason_code"]


def test_linear_dependency_graph_is_deterministic_and_hash_bound() -> None:
    rows = [
        _source(),
        _row(
            "carry",
            0x1010,
            0x1020,
            register_writes=[{"register": "eax", "value": _flag("cf")}],
        ),
        _row(
            "overwrite",
            0x1020,
            0x1030,
            register_writes=[{"register": "eax", "value": {"op": "const", "value": 7, "width": 32}}],
            flag_writes=[{"flag": "cf", "value": {"op": "false"}}],
        ),
        _row("after", 0x1030, None),
    ]
    first = analyze_definedness_rows(rows)
    assert first == analyze_definedness_rows(rows)
    assert first["format"] == DEFINEDNESS_EVIDENCE_FORMAT
    assert first["proof_authority"] is False
    body = dict(first)
    digest = body.pop("evidence_sha256")
    assert digest == hashlib.sha256(
        json.dumps(body, sort_keys=True, separators=(",", ":")).encode("ascii")
    ).hexdigest()
    slot = _slot(first)
    assert slot["classification"] == "unconstrained_noninterfering"
    assert slot["choice_source"] == {
        "format": "stage-a-definedness-choice-source-v1",
        "kind": "noninterfering_zero",
        "slot": slot["slot"],
        "undefined_id": slot["undefined_id"],
        "requires_semantic_obligations": False,
    }
    graph = slot["proof"]["graphs"][0]
    assert graph["fixed_point"] == {"states": 3, "scc_back_edges": 0, "complete": True}
    assert {node["transfer_id"] for node in graph["nodes"]} == {"source", "carry", "overwrite"}


def test_independent_branch_guards_are_exhaustively_traversed() -> None:
    branch = _row(
        "branch",
        0x1010,
        None,
        outcome={
            "kind": "branch",
            "condition": _flag("zf"),
            "true_target_rva": 0x1020,
            "false_target_rva": 0x1030,
        },
        edge_conditions=[
            {"condition": _flag("zf"), "target_rva": 0x1020},
            {"condition": {"op": "not", "args": [_flag("zf")]}, "target_rva": 0x1030},
        ],
    )
    overwrite_cf = [{"flag": "cf", "value": {"op": "false"}}]
    result = analyze_definedness_rows(
        [_source(), branch, _row("true", 0x1020, 0x1040, flag_writes=overwrite_cf), _row("false", 0x1030, 0x1040, flag_writes=overwrite_cf), _row("join", 0x1040, None)]
    )
    assert _slot(result)["classification"] == "unconstrained_noninterfering"
    branch_node = next(node for node in _slot(result)["proof"]["graphs"][0]["nodes"] if node["transfer_id"] == "branch")
    assert len(branch_node["edges"]) == 2

    branch["outcome"]["condition"] = _flag("cf")
    branch["edge_conditions"] = [
        {"condition": _flag("cf"), "target_rva": 0x1020},
        {"condition": {"op": "not", "args": [_flag("cf")]}, "target_rva": 0x1030},
    ]
    dependent = _slot(analyze_definedness_rows([_source(), branch, _row("true", 0x1020, 0x1040, flag_writes=overwrite_cf), _row("false", 0x1030, 0x1040, flag_writes=overwrite_cf), _row("join", 0x1040, None)]))
    assert dependent["classification"] == "unknown"
    assert dependent["witness_policy"] is None
    assert dependent["choice_source"] is None
    assert "unsupported_synchronized_choice" in {
        item["reason_code"] for item in dependent["blocking_paths"]
    }
    assert {site["category"] for site in dependent["behavior_relevant_sites"]} == {"guard_dependency"}


@pytest.mark.parametrize(
    ("field", "independent", "dependent", "reason"),
    [
        (
            "memory_events",
            [{"kind": "write", "address": _reg("esp"), "value": {"op": "const", "value": 1, "width": 32}, "width": 4}],
            [{"kind": "write", "address": _reg("esp"), "value": _flag("cf"), "width": 4}],
            "memory_expression_dependency",
        ),
        (
            "external_events",
            [{"kind": "external_call", "arguments": [{"value": _reg("eax")}], "read_footprints": [{"address": _reg("esp"), "width": 4}]}],
            [{"kind": "external_call", "arguments": [{"value": _flag("cf")}], "read_footprints": [{"address": _reg("esp"), "width": 4}]}],
            "call_argument_dependency",
        ),
        (
            "faults",
            [{"kind": "divide_error", "condition": _flag("zf")}],
            [{"kind": "divide_error", "condition": _flag("cf")}],
            "fault_dependency",
        ),
    ],
)
def test_memory_call_and_fault_expressions_are_checked(field, independent, dependent, reason) -> None:
    overwrite = [{"flag": "cf", "value": {"op": "false"}}]
    kwargs = {field: independent, "flag_writes": overwrite}
    allowed = analyze_definedness_rows([_source(), _row("boundary", 0x1010, 0x1020, **kwargs), _row("after", 0x1020, None)])
    assert _slot(allowed)["classification"] == "unconstrained_noninterfering"
    kwargs[field] = dependent
    blocked = analyze_definedness_rows([_source(), _row("boundary", 0x1010, 0x1020, **kwargs), _row("after", 0x1020, None)])
    slot = _slot(blocked)
    assert slot["classification"] == "unknown"
    assert reason in {site["category"] for site in slot["behavior_relevant_sites"]}


def test_return_requires_empty_live_set_but_termination_discards_dead_machine_state() -> None:
    returning = _row("return", 0x1010, None, outcome={"kind": "return", "value": _reg("eax")})
    returned = _slot(analyze_definedness_rows([_source(), returning]))
    assert returned["classification"] == "unconstrained_conditionally_noninterfering"
    assert returned["witness_policy"] == "zero"
    assert {item["kind"] for item in returned["proof_obligations"]} == {"return_continuation_noninterference"}
    returning["flag_writes"] = [{"flag": "cf", "value": {"op": "false"}}]
    assert _slot(analyze_definedness_rows([_source(), returning]))["classification"] == "unconstrained_noninterfering"

    terminating = _row("terminate", 0x1010, None, outcome={"kind": "terminate", "exit_code": _reg("eax")})
    assert _slot(analyze_definedness_rows([_source(), terminating]))["classification"] == "unconstrained_noninterfering"
    terminating["outcome"] = {"kind": "terminate", "exit_code": _flag("cf")}
    terminated = _slot(analyze_definedness_rows([_source(), terminating]))
    assert terminated["classification"] == "unknown"
    assert terminated["behavior_relevant_sites"][0]["json_pointer"] == "/outcome"


def test_finite_scc_fixed_point_is_certified_and_dependent_exit_is_rejected() -> None:
    rows = [_source(), _row("loop-a", 0x1010, 0x1020), _row("loop-b", 0x1020, 0x1010)]
    result = analyze_definedness_rows(rows)
    slot = _slot(result)
    assert slot["classification"] == "unconstrained_noninterfering"
    fixed = slot["proof"]["graphs"][0]["fixed_point"]
    assert fixed["states"] == 3
    assert fixed["scc_back_edges"] == 1

    rows[2] = _row(
        "loop-b",
        0x1020,
        None,
        outcome={"kind": "branch", "condition": _flag("cf"), "true_target_rva": 0x1010, "false_target_rva": 0x1030},
        edge_conditions=[{"condition": _flag("cf"), "target_rva": 0x1010}, {"condition": {"op": "not", "args": [_flag("cf")]}, "target_rva": 0x1030}],
    )
    rows.append(_row("exit", 0x1030, None))
    dependent = _slot(analyze_definedness_rows(rows))
    assert dependent["classification"] == "unknown"
    assert "guard_dependency" in {item["category"] for item in dependent["behavior_relevant_sites"]}


def test_bsr_zero_choice_is_derived_from_exact_destination_input() -> None:
    undefined = {
        "op": "undefined_bv",
        "id": "1000:eax",
        "reason": "bsr-zero-source",
        "width": 32,
        "defined_value": _reg("eax"),
    }
    source = _row(
        "source",
        0x1000,
        0x1010,
        register_writes=[{
            "register": "eax",
            "value": {
                "op": "ite",
                "args": [
                    {"op": "eq", "args": [_reg("ecx"), {"op": "const", "value": 0, "width": 32}]},
                    undefined,
                    {"op": "bsr_index", "args": [32, _reg("ecx")]},
                ],
            },
        }],
    )
    source["instructions"] = [{
        "rva": 0x1000,
        "size": 3,
        "bytes": "0fbdc1",
        "mnemonic": "bsr",
        "op_str": "eax, ecx",
    }]
    observe = _row(
        "observe",
        0x1010,
        None,
        outcome={"kind": "terminate", "exit_code": _reg("eax")},
    )
    slot = _slot(analyze_definedness_rows([source, observe]))
    assert slot["classification"] == "synchronized_behavior_relevant"
    input_expression = _reg("eax")
    assert slot["choice_source"] == {
        "format": "stage-a-definedness-choice-source-v3",
        "kind": "related_machine_input",
        "slot": slot["slot"],
        "undefined_id": "1000:eax",
        "profile": "ia32-bsr-zero-preserves-destination-v1",
        "instruction_rva": 0x1000,
        "instruction_bytes": "0fbdc1",
        "location": {"family": "register", "name": "eax"},
        "input_expression": input_expression,
        "input_expression_sha256": hashlib.sha256(
            json.dumps(
                input_expression,
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=True,
            ).encode("ascii")
        ).hexdigest(),
    }

    missing_value = json.loads(json.dumps(source))
    missing_value["register_writes"][0]["value"]["args"][1].pop("defined_value")
    missing_slot = _slot(analyze_definedness_rows([missing_value, observe]))
    assert missing_slot["classification"] == "unknown"
    assert missing_slot["blocking_paths"][0]["reason_code"] == (
        "unsupported_synchronized_choice"
    )

    recursive_value = json.loads(json.dumps(source))
    recursive_value["register_writes"][0]["value"]["args"][1][
        "defined_value"
    ] = _undefined("1000:recursive", "undefined_bv")
    recursive_result = analyze_definedness_rows([recursive_value, observe])
    recursive_slot = next(
        item
        for item in recursive_result["slots"]
        if item["undefined_id"] == "1000:eax"
    )
    assert recursive_slot["classification"] == "unknown"
    assert recursive_slot["blocking_paths"][0]["reason_code"] == (
        "unsupported_synchronized_choice"
    )


def test_behavior_relevant_non_bsr_choice_fails_closed() -> None:
    source = _source()
    observe = _row(
        "observe",
        0x1010,
        None,
        outcome={"kind": "terminate", "exit_code": _flag("cf")},
    )
    slot = _slot(analyze_definedness_rows([source, observe]))
    assert slot["classification"] == "unknown"
    assert slot["choice_source"] is None
    assert slot["blocking_paths"][0]["reason_code"] == "unsupported_synchronized_choice"


def test_constant_ite_prunes_unreachable_undefined_observation() -> None:
    dead = {
        "op": "ite",
        "args": [
            {"op": "eq_bool", "args": [{"op": "const", "value": 0, "width": 32}, {"op": "const", "value": 1, "width": 32}]},
            _undefined("1000:cf"),
            {"op": "false"},
        ],
    }
    row = _row("source", 0x1000, None, outcome={"kind": "terminate", "exit_code": dead})
    slot = _slot(analyze_definedness_rows([row]))
    assert slot["classification"] == "unconstrained_noninterfering"
    node = slot["proof"]["graphs"][0]["nodes"][0]
    assert node["observations"][0]["dependency"]["slot"] is False


def test_call_state_metadata_is_not_an_abi_observation() -> None:
    row = _row(
        "source",
        0x1000,
        0x1010,
        external_events=[
            {
                "kind": "internal_call",
                "target_rva": 0x2000,
                "return_rva": 0x1010,
                "arguments": [],
                "stack_inputs": [],
                "register_inputs": {"eax": _reg("eax")},
                "flag_inputs": {"of": _undefined("1000:of")},
            }
        ],
    )
    callee = _row(
        "callee",
        0x2000,
        None,
        flag_writes=[{"flag": "of", "value": {"op": "false"}}],
        outcome={"kind": "return", "value": _reg("eax")},
    )
    result = _slot(
        analyze_definedness_rows([row, _row("after", 0x1010, None), callee])
    )
    assert result["classification"] == "unconstrained_noninterfering"
    assert result["behavior_relevant_sites"] == []
    assert result["proof_obligations"] == []


def test_external_call_snapshot_requires_exact_call_frame_noninterference() -> None:
    source = _source()
    call = _row(
        "call",
        0x1010,
        0x1020,
        external_events=[
            {
                "kind": "external_call",
                "arguments": [],
                "stack_inputs": [],
                "register_inputs": {},
                "flag_inputs": {"cf": _flag("cf")},
            }
        ],
        flag_writes=[{"flag": "cf", "value": {"op": "false"}}],
    )
    result = _slot(
        analyze_definedness_rows([source, call, _row("after", 0x1020, None)])
    )
    assert result["classification"] == "unconstrained_conditionally_noninterfering"
    assert result["choice_source"]["requires_semantic_obligations"] is True
    assert {item["kind"] for item in result["proof_obligations"]} == {
        "call_frame_noninterference"
    }


def test_internal_return_resumes_caller_before_becoming_observable() -> None:
    undefined_eax = _undefined("1000:eax", "undefined_bv") | {"width": 32}
    call = _row(
        "source",
        0x1000,
        0x1010,
        external_events=[
            {
                "kind": "internal_call",
                "target_rva": 0x2000,
                "return_rva": 0x1010,
                "arguments": [],
                "stack_inputs": [],
                "register_inputs": {"eax": undefined_eax},
                "flag_inputs": {},
            }
        ],
    )
    callee_return = _row(
        "callee-return",
        0x2000,
        None,
        outcome={"kind": "return", "value": _reg("eax")},
    )
    caller_overwrite = _row(
        "caller-overwrite",
        0x1010,
        0x1020,
        register_writes=[
            {
                "register": "eax",
                "value": {"op": "const", "value": 7, "width": 32},
            }
        ],
    )
    result = _slot(
        analyze_definedness_rows(
            [
                call,
                caller_overwrite,
                _row("caller-return", 0x1020, None),
                callee_return,
            ]
        )
    )
    assert result["classification"] == "unconstrained_noninterfering"
    graph = result["proof"]["graphs"][0]
    callee = next(
        node for node in graph["nodes"] if node["transfer_id"] == "callee-return"
    )
    assert callee["terminal"] == "none"
    assert callee["observations"] == []
    assert callee["edges"][0]["target_rva"] == 0x1010


def test_fault_placeholder_requires_dominance_proof_but_does_not_flow_normally() -> None:
    valid = _flag("zf")
    value = {
        "op": "ite",
        "args": [
            valid,
            {"op": "const", "value": 7, "width": 32},
            _undefined("1000:eax", "undefined_bv") | {"reason": "idiv_fault", "width": 32},
        ],
    }
    row = _row(
        "source",
        0x1000,
        0x1010,
        register_writes=[{"register": "eax", "value": value}],
        faults=[{"kind": "divide_error", "condition": {"op": "not", "args": [valid]}}],
    )
    result = _slot(analyze_definedness_rows([row, _row("after", 0x1010, None)]))
    assert result["classification"] == "unconstrained_conditionally_noninterfering"
    assert result["behavior_relevant_sites"] == []
    assert result["proof_obligations"][0]["kind"] == "fault_dominance"
    assert result["proof_obligations"][0]["json_pointer"] == "/register_writes/0/value"


def test_legacy_x87_incomplete_is_retained_as_exact_replay_obligation() -> None:
    source = _source()
    source["status"] = "incomplete"
    source["blocker_category"] = "x87_physical_state_requires_native_exact_command_replay"
    source["blocker"] = "physical x87 state requires replay"
    result = _slot(
        analyze_definedness_rows(
            [
                source,
                _row(
                    "overwrite",
                    0x1010,
                    0x1020,
                    flag_writes=[{"flag": "cf", "value": {"op": "false"}}],
                ),
                _row("after", 0x1020, None),
            ]
        )
    )
    assert result["classification"] == "unconstrained_conditionally_noninterfering"
    assert result["proof_obligations"][0]["kind"] == "exact_replay_transfer"


def test_malformed_identity_edges_and_budget_fail_closed() -> None:
    missing_id = _source()
    missing_id["flag_writes"][0]["value"].pop("id")
    assert _reason(analyze_definedness_rows([missing_id, _row("next", 0x1010, None)])) == "missing_stable_id"

    conflicting = _row("conflicting", 0x1010, 0x1020, edge_conditions=[{"condition": {"op": "true"}, "target_rva": 0x1030}])
    assert _reason(analyze_definedness_rows([_source(), conflicting, _row("next", 0x1020, None)])) == "ambiguous_direct_edges"

    budget = analyze_definedness_rows([_source(), _row("a", 0x1010, 0x1020), _row("b", 0x1020, 0x1010)], max_states_per_slot=1)
    assert _reason(budget) == "state_budget_exceeded"


def test_jsonl_binding_and_parse_failure(tmp_path) -> None:
    rows = [_source(), _row("overwrite", 0x1010, 0x1020, flag_writes=[{"flag": "cf", "value": {"op": "false"}}]), _row("after", 0x1020, None)]
    path = tmp_path / "state-machine.jsonl"
    raw = b"\n".join(json.dumps(row, sort_keys=True, separators=(",", ":")).encode("ascii") for row in rows) + b"\n"
    path.write_bytes(raw)
    assert analyze_definedness_jsonl(path)["source_sha256"] == hashlib.sha256(raw).hexdigest()
    path.write_text("{not-json}\n", encoding="ascii")
    with pytest.raises(DefinednessAnalysisError, match="invalid semantic-transfer JSON"):
        analyze_definedness_jsonl(path)
