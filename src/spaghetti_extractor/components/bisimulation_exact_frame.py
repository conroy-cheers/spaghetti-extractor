"""Supplementary physical-memory frame checks in the existing paired model.

A failed frame probe does not invalidate ordinary exact/source equivalence.
Consumers must establish the callee entry domain and bind every covered segment
before using a satisfied probe as a guarantee.
"""

from __future__ import annotations

import hashlib
import re
import shutil
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path

from ..artifacts.artifact_set import canonical_sha256_v3
from .bisimulation_support import BisimulationRefinementError, PROOF_PRIVATE_STACK_BELOW
from .bisimulation_diagnostics import timed_query
from .cbmc_backend import run_cbmc_properties, _output_sha256, _parse_json, _property_statuses

POLICY = "original-physical-empty-write-frame-v1"
GUARD = "__CPROVER_spx_exact_empty_memory_frame"
PROPERTY = GUARD + ".assertion.1"
DESCRIPTION = "spx-bisimulation-exact-empty-memory-frame"
ACTIVE = "__CPROVER_spx_exact_frame_active"
MUTABLE_ACTIVE = "__CPROVER_spx_mutable_frame_active"
MACHINE_STATE_GUARD = "__CPROVER_spx_readable_machine_state"
MACHINE_STATE_PROPERTY = MACHINE_STATE_GUARD + ".assertion.1"
MACHINE_STATE_DESCRIPTION = "spx-bisimulation-readable-machine-state"
CUT_MACHINE_STATE_GUARD = "__CPROVER_spx_readable_cut_machine_state"
CUT_MACHINE_STATE_PROPERTY = CUT_MACHINE_STATE_GUARD + ".assertion.1"
CUT_MACHINE_STATE_DESCRIPTION = "spx-bisimulation-readable-cut-machine-state"


@dataclass(frozen=True)
class PhysicalFrameSpec:
    field: str
    policy: str
    guard: str
    description: str
    entry_prefix: str
    artifact_stem: str

    @property
    def property_id(self):
        return self.guard + ".assertion.1"

    def entry(self, proof_function):
        frame_entry(proof_function)  # Validate the identifier for every policy.
        return self.entry_prefix + proof_function


EMPTY_FRAME = PhysicalFrameSpec("exact_memory_frame", POLICY, GUARD, DESCRIPTION,
                               "__CPROVER_spx_exact_frame_", "exact-frame")


def frame_candidate(interface, operation_id, connected_summaries):
    operation = interface.operation_index()[operation_id]
    types = interface.type_index()
    return (not connected_summaries and not interface.state and not operation.effect_ids
            and not operation.allowed_service_ids and any(
                types[value.type_id].kind == "view" and types[value.type_id].access == "read"
                and types[value.type_id].extent_kind == "fixed" for value in operation.parameters))


def frame_declarations(enabled):
    if not enabled:
        return ""
    return f"""
static uint32_t {ACTIVE};
void {GUARD}(uint32_t permitted) {{
  __CPROVER_assert({ACTIVE} == UINT32_C(0) || permitted, "{DESCRIPTION}");
}}
void {MACHINE_STATE_GUARD}(uint32_t equal) {{
  __CPROVER_assert({ACTIVE} != UINT32_C(2) || equal, "{MACHINE_STATE_DESCRIPTION}");
}}
"""


def frame_write_check(enabled):
    return f"  {GUARD}(world != &spx_exact_world);\n" if enabled else ""


def frame_entry(proof_function):
    if not isinstance(proof_function, str) or re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", proof_function) is None:
        raise ValueError("exact frame proof function is malformed")
    return "__CPROVER_spx_exact_frame_" + proof_function


def readable_entry(proof_function):
    frame_entry(proof_function)  # Same identifier validation.
    return "__CPROVER_spx_readable_entry_" + proof_function


def wide_entry_condition(readable=False, mutable=False):
    terms = ([f"{ACTIVE} == UINT32_C(2)"] if readable else []) + ([f"({MUTABLE_ACTIVE} == UINT32_C(3) || {MUTABLE_ACTIVE} == UINT32_C(4))"] if mutable else [])
    return terms[0] if len(terms) == 1 else "(" + " || ".join(terms) + ")" if terms else "0"


def frame_private_low(enabled, mutable=False):
    original = f"entry_esp - UINT32_C({PROOF_PRIVATE_STACK_BELOW})"
    return (f"({wide_entry_condition(enabled, mutable)} && entry_esp < UINT32_C({PROOF_PRIVATE_STACK_BELOW}) ? UINT32_C(0) : {original})"
            if enabled or mutable else original)


def frame_probe_source(proof_function):
    return f"""
void {frame_entry(proof_function)}(void) {{
  {ACTIVE} = UINT32_C(1);
  {proof_function}();
}}
void {readable_entry(proof_function)}(void) {{
  {ACTIVE} = UINT32_C(2);
  {proof_function}();
}}
"""


def frame_arguments(property_command, proof_function):
    return _physical_frame_arguments(property_command, proof_function, EMPTY_FRAME)


def _physical_frame_arguments(property_command, proof_function, spec):
    return [spec.property_id if value == "$PROPERTY_ID" else spec.entry(proof_function)
            if value == "$PROPERTY_FUNCTION" else value
            for value in property_command["assertion_arguments"]]


def run_exact_frame_probe(**kwargs):
    return run_physical_frame_probe(**kwargs, spec=EMPTY_FRAME)


def run_physical_frame_probe(*, task, ordinary_result, goto_sha256, timeout_seconds, spec, timings=None):
    if ordinary_result.get("status") != "satisfied":
        return {}
    assertions = ordinary_result.get("partitioned_evidence", {}).get("assertions", [])
    guards = [row for row in assertions if row.get("description") == spec.description]
    if not guards:
        return {}
    if len(guards) != 1 or guards[0]["property_id"] != spec.property_id or guards[0]["source_function"] != spec.guard:
        raise BisimulationRefinementError("exact frame guard inventory is malformed")
    model = task["goto_model"]
    arguments = _physical_frame_arguments(task["property_checker_command"], task["proof_function"], spec)
    retained = task.get("diagnostic_timings") is True
    if retained:
        shutil.copyfile(model, model.with_name(spec.artifact_stem + ".goto"))
    result = timed_query(timings, spec.field, run_cbmc_properties,
        command=[str(task["cbmc"]), str(model), *arguments],
        timeout_seconds=timeout_seconds, output_prefix=model.with_name(spec.artifact_stem) if retained else None)
    core = {"policy": spec.policy, "authorizing": False, "proof_function": task["proof_function"],
        "bindings": {"proof_model_sha256": task["proof_model_sha256"], "goto_model_sha256": goto_sha256,
                     "property_checker_command_sha256": task["property_checker_command_sha256"]},
        "tools": {"cbmc_sha256": hashlib.sha256(task["cbmc"].read_bytes()).hexdigest(),
                  "goto_cc_sha256": hashlib.sha256(Path(task["compile_command"][0]).read_bytes()).hexdigest()},
        "command": ["$CBMC", "$GOTO_MODEL", *arguments], "result": result}
    return {spec.field: {**core, "receipt_sha256": canonical_sha256_v3(core)}}


def validate_exact_frame(value, **kwargs):
    return validate_physical_frame(value, **kwargs, spec=EMPTY_FRAME)


def validate_physical_frame(value, *, model, shard, spec, artifacts=None, checker=None, runtime_assurance=None):
    """Validate an auxiliary claim; retained bytes are required for consumption."""
    def require(condition, detail):
        if not condition:
            raise ValueError("exact memory frame: " + detail)

    from .bisimulation_assurance import validate_runtime_assurance_binding
    for record in (value, model, shard):
        validate_runtime_assurance_binding(record, runtime_assurance)

    fields = {"policy", "authorizing", "proof_function", "bindings", "tools", "command", "result", "receipt_sha256"}
    if runtime_assurance is not None:
        fields.add("assurance")
    require(isinstance(value, Mapping) and set(value) == fields, "certificate fields differ")
    require(value["receipt_sha256"] == canonical_sha256_v3({k: v for k, v in value.items() if k != "receipt_sha256"}),
            "certificate digest is stale")
    require(value["policy"] == spec.policy and value["authorizing"] is False, "unsupported policy")
    require(shard.get("status") == "satisfied" and shard.get("nonvacuity", {}).get("status") == "satisfied",
            "ordinary paired proof is incomplete")
    require(value["proof_function"] == model["proof_function"] and value["bindings"] == {
        "proof_model_sha256": model["proof_model_sha256"], "goto_model_sha256": model["goto_model_sha256"],
        "property_checker_command_sha256": model["property_checker_command_sha256"]}, "paired model binding is stale")
    require(value["command"] == ["$CBMC", "$GOTO_MODEL", *_physical_frame_arguments(
        model["property_checker_command"], model["proof_function"], spec)], "checker command is weakened")
    require(isinstance(value["tools"], Mapping) and set(value["tools"]) == {"cbmc_sha256", "goto_cc_sha256"}
            and all(isinstance(v, str) and re.fullmatch(r"[0-9a-f]{64}", v) for v in value["tools"].values()),
            "checker identities are malformed")
    guards = [row for row in shard.get("partitioned_evidence", {}).get("assertions", [])
              if row.get("description") == spec.description]
    require(len(guards) == 1 and guards[0]["property_id"] == spec.property_id and guards[0]["source_function"] == spec.guard,
            "ordinary model omits the frame guard")
    result = value["result"]
    require(isinstance(result, Mapping) and result.get("status") in {"satisfied", "violated", "incomplete"}
            and isinstance(result.get("output_sha256"), str)
            and re.fullmatch(r"[0-9a-f]{64}", result["output_sha256"]), "result is malformed")
    if result["status"] == "satisfied":
        require(isinstance(result.get("properties"), int) and not isinstance(result["properties"], bool),
                "frame property count is not an integer")
        require(result == {"status": "satisfied", "code": "cbmc_properties_satisfied", "properties": 1,
                           "property_ids": [spec.property_id], "output_sha256": result["output_sha256"]},
                "required frame property was not checked")
    if checker is not None:
        require(all(value["tools"][key] == checker.get(key) for key in value["tools"]), "ordinary checker differs")
    if artifacts is not None:
        require(result["status"] == "satisfied", "no satisfied frame to consume")
        root = Path(artifacts).resolve()
        def content(name):
            path = root / name
            require(path.is_file() and path.resolve().is_relative_to(root), "missing or escaped " + name)
            return path.read_bytes()
        require(hashlib.sha256(content(spec.artifact_stem + ".goto")).hexdigest() == value["bindings"]["goto_model_sha256"],
                "retained GOTO differs")
        stdout, stderr = content(spec.artifact_stem + ".stdout"), content(spec.artifact_stem + ".stderr")
        require(_output_sha256(stdout, stderr) == result["output_sha256"], "retained solver output differs")
        payload = _parse_json(stdout.decode())
        require(payload is not None and _property_statuses(payload) == {spec.property_id: "SUCCESS"},
                "retained solver output does not prove the frame")


def checked_empty_frame_operations(proof, *, artifacts, runtime_assurance=None):
    """Bind retained positive facts and require every segment for an operation.

    The supplier loader must already have validated the ordinary proof and its
    qualification. Partial or failed frame facts supply no operation guarantee.
    This function does not establish entry compatibility or authorize a call.
    """
    from .bisimulation_assurance import validate_runtime_assurance_binding
    validate_runtime_assurance_binding(proof, runtime_assurance)
    shards = {(row["operation_id"], row["obligation_id"]): row for row in proof["shards"]}
    complete = []
    for operation_index, operation in enumerate(proof["models"]["operation_models"]):
        all_segments = bool(operation["obligation_models"])
        for index, model in enumerate(operation["obligation_models"]):
            shard = shards[(operation["operation_id"], model["obligation_id"])]
            frame = shard.get("exact_memory_frame")
            if frame is None or frame["result"]["status"] != "satisfied":
                all_segments = False
                continue
            validate_exact_frame(frame, model=model, shard=shard, checker=proof["checker"], runtime_assurance=runtime_assurance,
                artifacts=Path(artifacts) / f"operation-{operation_index:04d}-obligation-{index:04d}")
        if all_segments:
            complete.append(operation["operation_id"])
    return tuple(complete)

