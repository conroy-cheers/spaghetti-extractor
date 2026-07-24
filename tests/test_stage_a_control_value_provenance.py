from __future__ import annotations

import copy
import unittest
from typing import Any

from spaghetti_extractor.relational.lean.control_value_provenance import (
    CONTROL_VALUE_PROVENANCE_FORMAT,
    ControlValueProvenanceGenerationError,
    control_value_provenance_source,
)


FIXTURE_MODULE = "StageA.ControlValueProvenanceFixture"
FIXTURE_CONTEXT = FIXTURE_MODULE + ".exactContext"


def _u32(value: int) -> list[int]:
    return [(value >> shift) & 0xFF for shift in (0, 8, 16, 24)]


def _zero() -> dict[str, Any]:
    return {"kind": "zero"}


def _code(target_id: int) -> dict[str, Any]:
    return {"kind": "code_target", "target_id": target_id}


def _import(dll: str, symbol: str) -> dict[str, Any]:
    return {
        "kind": "import",
        "identity": {"dll": dll, "symbol": symbol},
    }


def _value(
    *atoms: dict[str, Any], blockers: tuple[str, ...] = ()
) -> dict[str, Any]:
    return {"atoms": list(atoms), "blockers": list(blockers)}


def _state(*rows: tuple[int, dict[str, Any]]) -> list[dict[str, Any]]:
    return [
        {"location_id": location_id, "value": value}
        for location_id, value in rows
    ]


def _register(register: str) -> dict[str, Any]:
    return {"kind": "register", "register": register}


def _frame_subtract(amount: int) -> dict[str, Any]:
    return {
        "kind": "frame_word",
        "base": "ebp",
        "adjustment": {"kind": "subtract", "amount": amount},
    }


def _static(address: int) -> dict[str, Any]:
    return {"kind": "static_word", "address": address}


def _location_pair(
    location_id: int,
    original: dict[str, Any],
    candidate: dict[str, Any] | None = None,
) -> dict[str, Any]:
    return {
        "id": location_id,
        "original": original,
        "candidate": original if candidate is None else candidate,
    }


def _region(
    region_id: int,
    start: int,
    code: list[int],
    *,
    entry: bool = False,
    target_id: int | None = None,
    actions: list[dict[str, Any]] | None = None,
    input_state: list[dict[str, Any]] | None = None,
    output_state: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    return {
        "id": region_id,
        "entry": entry,
        "target_id": region_id if target_id is None else target_id,
        "original_span": {"start": start, "size": len(code)},
        "candidate_span": {"start": start, "size": len(code)},
        "original_bytes": code,
        "candidate_bytes": code,
        "actions": [] if actions is None else actions,
        "input": input_state,
        "output": output_state,
    }


def _edge(
    edge_id: int,
    source: int,
    target: int,
    kind: str = "direct",
    call_reference_id: int | None = None,
) -> dict[str, Any]:
    return {
        "id": edge_id,
        "source_region": source,
        "target_region": target,
        "kind": kind,
        "call_reference_id": call_reference_id,
    }


def _scc(
    component_id: int,
    region_ids: list[int],
    *,
    edge_ids: list[int] | None = None,
    predecessors: list[int] | None = None,
    successors: list[int] | None = None,
    cyclic: bool = False,
) -> dict[str, Any]:
    return {
        "id": component_id,
        "region_ids": region_ids,
        "edge_ids": [] if edge_ids is None else edge_ids,
        "predecessor_ids": [] if predecessors is None else predecessors,
        "successor_ids": [] if successors is None else successors,
        "cyclic": cyclic,
    }


def _certificate(**overrides: Any) -> dict[str, Any]:
    result: dict[str, Any] = {
        "format": CONTROL_VALUE_PROVENANCE_FORMAT,
        "context": {
            "module": FIXTURE_MODULE,
            "value": FIXTURE_CONTEXT,
            "call_semantic_dependency": None,
        },
        "finite_disjunction_budget": 4,
        "locations": [],
        "static_seeds": [],
        "regions": [],
        "edges": [],
        "call_references": [],
        "branch_guards": [],
        "sccs": [],
        "component_order": [],
    }
    result.update(overrides)
    return result


def spill_reload_certificate() -> dict[str, Any]:
    atom = _code(2)
    known = _value(atom)
    carried = _state((0, known), (1, known))
    region0 = [0xB8, *_u32(0x401020), 0x89, 0x45, 0xFC, 0xEB, 0x06]
    region1 = [0x8B, 0x45, 0xFC, 0xEB, 0xFB]
    return _certificate(
        locations=[
            _location_pair(0, _register("eax")),
            _location_pair(1, _frame_subtract(4)),
        ],
        regions=[
            _region(
                0,
                0x1000,
                region0,
                entry=True,
                actions=[
                    {"kind": "seed", "output_id": 0, "atom": atom},
                    {"kind": "assign", "output_id": 1, "input_id": 0},
                ],
                input_state=[],
                output_state=carried,
            ),
            _region(
                1,
                0x1010,
                region1,
                actions=[{"kind": "assign", "output_id": 0, "input_id": 1}],
                input_state=carried,
                output_state=carried,
            ),
        ],
        edges=[_edge(0, 0, 1), _edge(1, 1, 1)],
        sccs=[
            _scc(0, [0], successors=[1]),
            _scc(1, [1], edge_ids=[1], predecessors=[0], cyclic=True),
        ],
        component_order=[0, 1],
    )


def zero_static_word_certificate() -> dict[str, Any]:
    zero = _value(_zero())
    initial = _state((1, zero))
    loaded = _state((0, zero), (1, zero))
    return _certificate(
        locations=[
            _location_pair(0, _register("eax")),
            _location_pair(1, _static(0x403000)),
        ],
        static_seeds=[{"id": 0, "location_id": 1, "atom": _zero()}],
        regions=[
            _region(
                0,
                0x1000,
                [0xA1, *_u32(0x403000), 0xEB, 0x00],
                entry=True,
                actions=[{"kind": "assign", "output_id": 0, "input_id": 1}],
                input_state=initial,
                output_state=loaded,
            ),
            _region(
                1,
                0x1007,
                [0x83, 0xF8, 0x07, 0x74, 0x02],
                input_state=loaded,
                output_state=loaded,
            ),
            _region(
                2,
                0x100C,
                [0xEB, 0xFE],
                input_state=loaded,
                output_state=loaded,
            ),
            _region(
                3,
                0x100E,
                [0xEB, 0xFE],
                input_state=loaded,
                output_state=loaded,
            ),
        ],
        edges=[
            _edge(0, 0, 1),
            _edge(1, 1, 3, "branch_taken"),
            _edge(2, 1, 2, "branch_fallthrough"),
            _edge(3, 2, 2),
            _edge(4, 3, 3),
        ],
        branch_guards=[{
            "id": 0,
            "region_id": 1,
            "location_id": 0,
            "original_condition": {
                "op": "equal",
                "left": {
                    "op": "sub",
                    "left": {"op": "input_reg", "reg": "eax"},
                    "right": {"op": "constant", "value": 7},
                },
                "right": {"op": "constant", "value": 0},
            },
            "candidate_condition": {
                "op": "equal",
                "left": {
                    "op": "sub",
                    "left": {"op": "input_reg", "reg": "eax"},
                    "right": {"op": "constant", "value": 7},
                },
                "right": {"op": "constant", "value": 0},
            },
            "observed": zero,
        }],
        sccs=[
            _scc(0, [0], successors=[1]),
            _scc(1, [1], predecessors=[0], successors=[2, 3]),
            _scc(2, [2], edge_ids=[3], predecessors=[1], cyclic=True),
            _scc(3, [3], edge_ids=[4], predecessors=[1], cyclic=True),
        ],
        component_order=[0, 1, 2, 3],
    )


def context_only_certificate() -> dict[str, Any]:
    return _certificate(locations=[_location_pair(0, _register("eax"))])


def budget_overflow_certificate() -> dict[str, Any]:
    result = copy.deepcopy(spill_reload_certificate())
    result["finite_disjunction_budget"] = 1
    overflow = _value(_zero(), _code(2))
    result["regions"][0]["output"] = _state((0, overflow), (1, overflow))
    return result


class StageAControlValueProvenanceTests(unittest.TestCase):
    def test_source_names_canonical_context_and_marks_non_authority(self) -> None:
        source = control_value_provenance_source(spill_reload_certificate())
        self.assertIn(f"import {FIXTURE_MODULE}", source)
        self.assertIn("StaticProofContext", source)
        self.assertIn(".localChecked", source)
        self.assertIn("ExactContextBinding", source)
        self.assertIn("LocalReplayFacts", source)
        self.assertIn("generatedControlValueProvenanceProofAuthority : Bool := false", source)
        self.assertIn("RequiresIntegrationPremise : Bool := true", source)
        self.assertNotIn("SemanticallyValid", source)
        self.assertNotIn("CallPreservationClaim", source)
        self.assertNotIn("native_decide", source)

    def test_exact_spans_adjustments_and_guards_are_serialized(self) -> None:
        spill = control_value_provenance_source(spill_reload_certificate())
        self.assertIn(".frameWord .ebp (.subtract 4)", spill)
        self.assertIn("originalSpan := { start := 4096, size := 10 }", spill)
        guarded = control_value_provenance_source(zero_static_word_certificate())
        self.assertIn("StageA.Formal.BoolExpr.equal", guarded)
        self.assertIn("originalCondition", guarded)
        self.assertIn("staticSeeds := [{ id := 0", guarded)

    def test_rejected_source_proves_only_local_checker_failure(self) -> None:
        source = control_value_provenance_source(
            budget_overflow_certificate(), expectation="rejected"
        )
        self.assertIn("generatedControlValueProvenanceRejected", source)
        self.assertNotIn("generatedControlValueProvenanceExactContext", source)
        self.assertNotIn("generatedControlValueProvenanceLocalReplayFacts", source)

    def test_old_self_asserted_inventories_are_rejected(self) -> None:
        payload = spill_reload_certificate()
        payload["imports"] = []
        with self.assertRaisesRegex(
            ControlValueProvenanceGenerationError, "unexpected fields: imports"
        ):
            control_value_provenance_source(payload)

    def test_context_names_are_injection_safe_and_qualified(self) -> None:
        for value in ("exactContext", "StageA.Bad; #eval 1"):
            payload = spill_reload_certificate()
            payload["context"]["value"] = value
            with self.subTest(value=value), self.assertRaises(
                ControlValueProvenanceGenerationError
            ):
                control_value_provenance_source(payload)

    def test_call_dependency_is_typed_external_input(self) -> None:
        payload = spill_reload_certificate()
        payload["context"]["call_semantic_dependency"] = (
            "StageA.ControlValueProvenanceFixture.callSemantics"
        )
        source = control_value_provenance_source(payload)
        self.assertIn("Option (CallSemanticDependency", source)
        self.assertIn("some (StageA.ControlValueProvenanceFixture.callSemantics)", source)


if __name__ == "__main__":
    unittest.main()
