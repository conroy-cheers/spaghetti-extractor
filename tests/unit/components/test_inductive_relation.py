from __future__ import annotations

import copy
import unittest

from spaghetti_extractor.components.inductive_receipts import (
    build_inductive_machine_receipt,
)
from spaghetti_extractor.components.inductive_relation import (
    InductiveCutpointRelationV1,
    InductiveRelationError,
)
from spaghetti_extractor.components.inductive_source import InductiveSourcePlanV1
from spaghetti_extractor.components.interface_ir import ProofKernelComponentInterface
from spaghetti_extractor.components.semantic_paths import (
    _read_projection,
    _write_projection,
    build_inductive_segment_models,
)
from spaghetti_extractor.components.machine_binding import MachineProjectionV1


def _register(name: str, at: str) -> dict[str, object]:
    return {"kind": "register", "register": name, "width": 32, "at": at}


def _unit(
    identity: str,
    rva: int,
    edges: list[tuple[int, dict[str, object]]],
    writes: list[dict[str, object]],
) -> dict[str, object]:
    return {
        "id": identity,
        "source": {"original": {"rva_start": rva, "rva_end": rva + 1}},
        "semantics": {
            "edge_conditions": [
                {"target_rva": target, "condition": condition}
                for target, condition in edges
            ],
            "outcome": (
                {"kind": "return"}
                if not edges
                else {"kind": "jump", "target_rva": edges[0][0]}
            ),
            "register_writes": writes,
            "flag_writes": [],
            "memory_events": [],
            "external_events": [],
            "faults": [],
        },
    }


def _operation() -> dict[str, object]:
    n = {"op": "reg", "name": "edx", "width": 32}
    mirror = {"op": "reg", "name": "eax", "width": 32}
    zero = {"op": "const", "value": 0, "width": 32}
    return {
        "operation_id": "run",
        "entry_unit_ids": ["entry"],
        "exit_unit_ids": ["exit"],
        "parameters": [{"id": "count", "projection": _register("ecx", "entry")}],
        "results": [{"id": "result", "projection": _register("eax", "exit")}],
        "state": [],
        "preserved_state_ids": [],
        "effects": [],
        "callback_operation_ids": [],
        "units": [
            _unit(
                "entry",
                0x1000,
                [
                    (0x1030, {"op": "eq", "args": [
                        {"op": "reg", "name": "ecx", "width": 32}, zero,
                    ]}),
                    (0x1010, {"op": "not", "args": [{"op": "eq", "args": [
                        {"op": "reg", "name": "ecx", "width": 32}, zero,
                    ]}]}),
                ],
                [
                    {"register": "eax", "value": {"op": "reg", "name": "ecx", "width": 32}},
                    {"register": "edx", "value": {"op": "reg", "name": "ecx", "width": 32}},
                ],
            ),
            _unit(
                "head",
                0x1010,
                [
                    (0x1030, {"op": "eq", "args": [mirror, zero]}),
                    (0x1020, {"op": "not", "args": [{"op": "eq", "args": [mirror, zero]}]}),
                ],
                [],
            ),
            _unit(
                "body",
                0x1020,
                [(0x1010, {"op": "true"})],
                [
                    {
                        "register": "eax",
                        "value": {
                            "op": "sub32",
                            "args": [n, {"op": "const", "value": 1, "width": 32}],
                        },
                    },
                    {
                        "register": "edx",
                        "value": {
                            "op": "sub32",
                            "args": [n, {"op": "const", "value": 1, "width": 32}],
                        },
                    },
                ],
            ),
            _unit(
                "exit",
                0x1030,
                [],
                [{"register": "eax", "value": n}],
            ),
        ],
    }


def _interface() -> ProofKernelComponentInterface:
    return ProofKernelComponentInterface.parse(
        {
            "id": "countdown",
            "types": [{"id": "u32", "kind": "scalar", "c_type": "uint32_t"}],
            "state": [],
            "operations": [{
                "id": "run",
                "kind": "operation",
                "parameters": [{"id": "count", "type_id": "u32"}],
                "results": [{"id": "result", "type_id": "u32"}],
                "effect_ids": [],
                "allowed_service_ids": [],
                "pre_states": ["ready"],
                "post_states": ["ready"],
            }],
            "effects": [],
            "services": [],
            "protocol": {"states": ["ready"], "initial_state": "ready"},
        }
    )


def _artifacts() -> tuple[
    ProofKernelComponentInterface,
    InductiveSourcePlanV1,
    object,
    InductiveCutpointRelationV1,
]:
    interface = _interface()
    plan = InductiveSourcePlanV1.create(
        interface=interface,
        operation_id="run",
        state=[{"id": "n", "type_id": "u32"}],
        phase_ids=["loop"],
        completion_ids=["return"],
        symbols={
            "wrapper": "countdown_run",
            "initialize": "countdown_initialize",
            "step": "countdown_step",
            "finish": "countdown_finish",
        },
    )
    machine = build_inductive_machine_receipt(
        operation=_operation(),
        semantic_contract_sha256="a" * 64,
        cutpoint_unit_ids=["head"],
    )
    inventory = machine.segment_inventory.to_value()
    completion_segments = [
        row["segment_id"]
        for row in inventory["segments"]
        if row["target"]["kind"] == "operation_exit"
    ]
    relation = InductiveCutpointRelationV1.create(
        interface=interface,
        source_plan=plan,
        machine_receipt=machine,
        cutpoints=[{
            "unit_id": "head",
            "phase_id": "loop",
            "values": [
                {
                    "kind": "parameter",
                    "id": "count",
                    "mode": "machine_codec",
                    "projection": _register("ecx", "entry"),
                    "encoding": {"op": "parameter", "name": "count"},
                    "decoding": None,
                },
                {
                    "kind": "source_state",
                    "id": "n",
                    "mode": "machine_codec",
                    "projection": _register("edx", "entry"),
                    "encoding": {"op": "state_input", "name": "n"},
                    "decoding": {"op": "projected_value"},
                },
            ],
            "derived": [{
                "id": "mirror",
                "projection": _register("eax", "entry"),
                "expression": {"op": "state_input", "name": "n"},
            }],
        }],
        completion_segments=[
            {"segment_id": segment_id, "completion_id": "return"}
            for segment_id in completion_segments
        ],
    )
    return interface, plan, machine, relation


class InductiveRelationTests(unittest.TestCase):
    def test_narrow_register_projection_preserves_high_bits_and_reads_low_bits(self) -> None:
        projection = MachineProjectionV1.parse({
            "kind": "register",
            "register": "eax",
            "width": 8,
            "at": "entry",
        })
        original = {"op": "symbol", "name": "machine_eax", "width": 32}
        logical = {"op": "state_input", "name": "byte_value"}
        env = {"eax": original}
        _write_projection(projection, logical, env, {})

        self.assertEqual(env["eax"]["args"][0]["args"][0], original)
        self.assertEqual(
            _read_projection(projection, env, {}),
            {
                "op": "and32",
                "args": [
                    logical,
                    {"op": "const", "value": 0xFF, "width": 32},
                ],
            },
        )

    def test_exact_segments_reduce_to_logical_init_step_and_completion(self) -> None:
        interface, plan, machine, relation = _artifacts()
        model = build_inductive_segment_models(
            _operation(), interface, plan, machine, relation, []
        )

        segments = model["segments"]
        self.assertEqual(len(segments), 4)
        initialization = next(
            row
            for row in segments
            if row["source"]["kind"] == "operation_entry"
            and row["target"]["kind"] == "cutpoint"
        )
        self.assertEqual(
            initialization["target_values"]["source_state:n"],
            {"op": "parameter", "name": "count"},
        )
        preservation = next(
            row
            for row in segments
            if row["target"]["kind"] == "cutpoint"
            and row["source"]["kind"] == "cutpoint"
        )
        self.assertEqual(preservation["target"]["phase_id"], "loop")
        self.assertEqual(len(preservation["relation_checks"]), 3)
        for relation_check in preservation["relation_checks"]:
            self.assertEqual(relation_check["op"], "eq")
            self.assertEqual(relation_check["args"][0], relation_check["args"][1])
        updated_n = preservation["target_values"]["source_state:n"]
        self.assertEqual(updated_n["op"], "add32")
        self.assertIn({"op": "state_input", "name": "n"}, updated_n["args"])
        self.assertIn(
            {"op": "const", "value": 0xFFFFFFFF, "width": 32},
            updated_n["args"],
        )
        completion = next(
            row
            for row in segments
            if row["target"]["kind"] == "operation_exit"
            and row["source"]["kind"] == "cutpoint"
        )
        self.assertEqual(completion["target"]["completion_id"], "return")
        self.assertEqual(
            completion["results"]["result"],
            {"op": "state_input", "name": "n"},
        )

    def test_relation_rejects_missing_logical_value(self) -> None:
        interface, plan, machine, relation = _artifacts()
        payload = copy.deepcopy(relation.to_payload())
        payload["cutpoints"][0]["values"] = payload["cutpoints"][0]["values"][:1]
        from spaghetti_extractor.artifacts.artifact_set import canonical_sha256_v3

        core = dict(payload)
        core.pop("relation_sha256")
        payload["relation_sha256"] = canonical_sha256_v3(core)
        parsed = InductiveCutpointRelationV1.parse(payload)
        with self.assertRaisesRegex(InductiveRelationError, "every logical value"):
            parsed.validate_for(interface, plan, machine)

    def test_relation_rejects_uncovered_completion_segment(self) -> None:
        interface, plan, machine, relation = _artifacts()
        payload = copy.deepcopy(relation.to_payload())
        payload["completion_segments"] = []
        from spaghetti_extractor.artifacts.artifact_set import canonical_sha256_v3

        core = dict(payload)
        core.pop("relation_sha256")
        payload["relation_sha256"] = canonical_sha256_v3(core)
        parsed = InductiveCutpointRelationV1.parse(payload)
        with self.assertRaisesRegex(InductiveRelationError, "every exact exit"):
            parsed.validate_for(interface, plan, machine)

    def test_entry_reachable_cutpoint_rejects_uninitialized_logical_carry(self) -> None:
        interface, plan, machine, relation = _artifacts()
        payload = copy.deepcopy(relation.to_payload())
        state = next(
            item
            for item in payload["cutpoints"][0]["values"]
            if item["kind"] == "source_state"
        )
        state.update({
            "mode": "logical_carry",
            "projection": None,
            "encoding": None,
            "decoding": None,
        })
        from spaghetti_extractor.artifacts.artifact_set import canonical_sha256_v3

        core = dict(payload)
        core.pop("relation_sha256")
        payload["relation_sha256"] = canonical_sha256_v3(core)
        parsed = InductiveCutpointRelationV1.parse(payload)
        with self.assertRaisesRegex(
            InductiveRelationError, "carries uninitialized logical state"
        ):
            parsed.validate_for(interface, plan, machine)

    def test_logical_definition_establishes_machine_free_cutpoint_state(self) -> None:
        interface, plan, machine, relation = _artifacts()
        payload = copy.deepcopy(relation.to_payload())
        state = next(
            item
            for item in payload["cutpoints"][0]["values"]
            if item["kind"] == "source_state"
        )
        state.update({
            "mode": "logical_definition",
            "projection": None,
            "encoding": {"op": "const", "value": 0, "width": 32},
            "decoding": None,
        })
        from spaghetti_extractor.artifacts.artifact_set import canonical_sha256_v3

        core = dict(payload)
        core.pop("relation_sha256")
        payload["relation_sha256"] = canonical_sha256_v3(core)
        parsed = InductiveCutpointRelationV1.parse(payload)
        parsed.validate_for(interface, plan, machine)
        parsed_state = next(
            item
            for item in parsed.cutpoints[0].values
            if item.kind == "source_state"
        )
        self.assertEqual(parsed_state.mode, "logical_definition")
        self.assertEqual(
            parsed_state.encoding,
            {"op": "const", "value": 0, "width": 32},
        )

    def test_private_stack_write_is_classified_without_becoming_logical_state(self) -> None:
        operation = _operation()
        operation["units"][0]["semantics"]["memory_events"] = [{
            "kind": "write",
            "width": 4,
            "address": {
                "op": "sub32",
                "args": [
                    {"op": "reg", "name": "esp", "width": 32},
                    {"op": "const", "value": 4, "width": 32},
                ],
            },
            "value": {"op": "reg", "name": "ebx", "width": 32},
        }]
        interface, plan, _, _ = _artifacts()
        machine = build_inductive_machine_receipt(
            operation=operation,
            semantic_contract_sha256="a" * 64,
            cutpoint_unit_ids=["head"],
        )
        inventory = machine.segment_inventory.to_value()
        completion_segments = [
            row["segment_id"]
            for row in inventory["segments"]
            if row["target"]["kind"] == "operation_exit"
        ]
        relation = InductiveCutpointRelationV1.create(
            interface=interface,
            source_plan=plan,
            machine_receipt=machine,
            cutpoints=[{
                "unit_id": "head",
                "phase_id": "loop",
                "values": [
                    {
                        "kind": "parameter",
                        "id": "count",
                        "mode": "machine_codec",
                        "projection": _register("ecx", "entry"),
                        "encoding": {"op": "parameter", "name": "count"},
                        "decoding": None,
                    },
                    {
                        "kind": "source_state",
                        "id": "n",
                        "mode": "machine_codec",
                        "projection": _register("edx", "entry"),
                        "encoding": {"op": "state_input", "name": "n"},
                        "decoding": {"op": "projected_value"},
                    },
                ],
                "derived": [{
                    "id": "mirror",
                    "projection": _register("eax", "entry"),
                    "expression": {"op": "state_input", "name": "n"},
                }],
            }],
            completion_segments=[
                {"segment_id": segment_id, "completion_id": "return"}
                for segment_id in completion_segments
            ],
        )
        model = build_inductive_segment_models(
            operation, interface, plan, machine, relation, []
        )
        initialization = next(
            row
            for row in model["segments"]
            if row["source"]["kind"] == "operation_entry"
        )
        self.assertEqual(
            initialization["private_stack_writes"],
            [{"offset": -4, "width": 4}],
        )

if __name__ == "__main__":
    unittest.main()
