"""Supplementary exact/source proofs over a more composable stack domain.

All paired properties and the original physical write frame must hold. The
ordinary entry remains unchanged. Its domain is included in this larger domain,
so its nonvacuity witness also establishes inhabitation here. This does not
establish a reached caller's reference, allocation, or lifetime premises.
"""

import hashlib
import re
from collections.abc import Mapping
from pathlib import Path
from dataclasses import dataclass

from ..artifacts.artifact_set import canonical_sha256_v3
from .bisimulation_diagnostics import timed_query
from .bisimulation_exact_frame import (EMPTY_FRAME, readable_entry, checked_empty_frame_operations,
    MACHINE_STATE_GUARD, MACHINE_STATE_PROPERTY, MACHINE_STATE_DESCRIPTION,
    CUT_MACHINE_STATE_GUARD, CUT_MACHINE_STATE_PROPERTY, CUT_MACHINE_STATE_DESCRIPTION)
from .bisimulation_mutable_frame import FRAME, CUT_FRAME, ENTRY_PREFIX, checked_fixed_writable_frame_operations
from . import bisimulation_private_frame as private_frame
from .cbmc_backend import run_cbmc_properties, _output_sha256, _parse_json, _property_statuses

POLICY = "paired-readable-entry-empty-frame-v1"
DOMAIN = {"minimum_esp": 4, "image_exclusion_below_esp": 0,
          "image_exclusion_above_esp": "original-private-high-offset",
          "private_low": "saturating-original-window",
          "nonvacuity": "ordinary-domain-inclusion-v1"}


@dataclass(frozen=True)
class EntrySpec:
    policy: str
    field: str
    entry_prefix: str
    frames: tuple
    artifact_stem: str
    domain: Mapping | None = None

    def entry(self, proof_function):
        readable_entry(proof_function)  # Keep the existing identifier validator.
        return self.entry_prefix + proof_function


READABLE = EntrySpec(POLICY, "readable_entry_contract", "__CPROVER_spx_readable_entry_", (EMPTY_FRAME,), "readable-entry")
MUTABLE = EntrySpec("paired-mutable-entry-fixed-write-frame-v1", "mutable_entry_contract", ENTRY_PREFIX,
                    (FRAME, CUT_FRAME), "mutable-entry")


def mutable_entry_spec(model):
    ranges = private_frame.parse_stack_writes(model.get("private_stack_writes", []))
    if not ranges:
        return MUTABLE
    write, cut = private_frame.specs(ranges)
    return EntrySpec("paired-mutable-entry-private-write-frame-v1", MUTABLE.field,
        private_frame.entry_prefix(ranges), (write, CUT_FRAME, cut), MUTABLE.artifact_stem,
        private_frame.entry_domain(ranges))


def readable_entry_arguments(command, proof_function, *, spec=READABLE):
    args = command["assertion_arguments"]
    if args[-2:] != ["--property", "$PROPERTY_ID"] or args.count("--no-standard-checks") != 1:
        raise ValueError("readable entry: unsupported ordinary property command")
    return [spec.entry(proof_function) if arg == "$PROPERTY_FUNCTION" else arg
            for arg in args[:-2] if arg != "--no-standard-checks"] + ["--no-self-loops-to-assumptions"]


def run_readable_entry_probe(*, task, frame, timeout_seconds, timings=None):
    return _run_entry_probe(task=task, frames={EMPTY_FRAME.field: frame}, timeout_seconds=timeout_seconds,
                            timings=timings, spec=READABLE)


def run_mutable_entry_probe(*, task, frames, timeout_seconds, timings=None):
    return _run_entry_probe(task=task, frames=frames, timeout_seconds=timeout_seconds, timings=timings, spec=mutable_entry_spec(task))


def _run_entry_probe(*, task, frames, timeout_seconds, timings, spec):
    if any(frames.get(frame.field) is None or frames[frame.field]["result"]["status"] != "satisfied"
           for frame in spec.frames):
        return {}
    frame = frames[spec.frames[0].field]
    args = readable_entry_arguments(task["property_checker_command"], task["proof_function"], spec=spec)
    model = task["goto_model"]
    result = timed_query(timings, spec.field.removesuffix("_contract"), run_cbmc_properties,
        command=[str(task["cbmc"]), str(model), *args], timeout_seconds=timeout_seconds,
        output_prefix=model.with_name(spec.artifact_stem) if task.get("diagnostic_timings") is True else None)
    core = {"policy": spec.policy, "authorizing": False, "domain": dict(spec.domain or DOMAIN),
        "proof_function": task["proof_function"], "bindings": frame["bindings"], "tools": frame["tools"],
        "command": ["$CBMC", "$GOTO_MODEL", *args], "result": result}
    return {spec.field: {**core, "receipt_sha256": canonical_sha256_v3(core)}}


def validate_readable_entry(value, **kwargs):
    return _validate_entry(value, **kwargs, spec=READABLE)


def validate_mutable_entry(value, **kwargs):
    return _validate_entry(value, **kwargs, spec=mutable_entry_spec(kwargs["model"]))


def _validate_entry(value, *, model, shard, checker, artifacts=None, spec, runtime_assurance=None):
    def require(condition, message):
        if not condition:
            raise ValueError(spec.artifact_stem + ": " + message)

    from .bisimulation_assurance import validate_runtime_assurance_binding
    for record in (value, model, shard):
        validate_runtime_assurance_binding(record, runtime_assurance)

    fields = {"policy", "authorizing", "domain", "proof_function", "bindings", "tools", "command", "result", "receipt_sha256"}
    if runtime_assurance is not None:
        fields.add("assurance")
    require(isinstance(value, Mapping) and set(value) == fields, "certificate fields differ")
    require(value["receipt_sha256"] == canonical_sha256_v3({k: v for k, v in value.items() if k != "receipt_sha256"}),
            "certificate digest is stale")
    require(value["policy"] == spec.policy and value["domain"] == (spec.domain or DOMAIN) and value["authorizing"] is False,
            "unsupported domain policy")
    require(shard.get("status") == "satisfied" and shard.get("nonvacuity", {}).get("status") == "satisfied",
            "ordinary paired proof or domain witness is incomplete")
    require(all(isinstance(shard.get(frame.field), Mapping) and shard[frame.field]["result"]["status"] == "satisfied"
                for frame in spec.frames), "ordinary physical frame is incomplete")
    require(value["proof_function"] == model["proof_function"] and value["bindings"] == {
        "proof_model_sha256": model["proof_model_sha256"], "goto_model_sha256": model["goto_model_sha256"],
        "property_checker_command_sha256": model["property_checker_command_sha256"]}, "paired model binding is stale")
    require(value["tools"] == {key: checker.get(key) for key in ("cbmc_sha256", "goto_cc_sha256")},
            "ordinary checker differs")
    require(value["command"] == ["$CBMC", "$GOTO_MODEL", *readable_entry_arguments(
        model["property_checker_command"], model["proof_function"], spec=spec)], "checker command is weakened")
    result = value["result"]
    require(isinstance(result, Mapping) and result.get("status") in {"satisfied", "violated", "incomplete"}
            and isinstance(result.get("output_sha256"), str)
            and re.fullmatch(r"[0-9a-f]{64}", result["output_sha256"]), "result is malformed")
    if result["status"] == "satisfied":
        ids = result.get("property_ids")
        require(isinstance(ids, list) and all(isinstance(item, str) for item in ids)
                and ids == sorted(set(ids)) and all(frame.property_id in ids for frame in spec.frames), "property inventory is malformed")
        require(result == {"status": "satisfied", "code": "cbmc_properties_satisfied", "properties": len(ids),
                           "property_ids": ids, "output_sha256": result["output_sha256"]}, "property result is malformed")
        require({row["property_id"] for row in shard["partitioned_evidence"]["assertions"]} <= set(ids),
                "ordinary paired assertions are missing")
    if artifacts is not None:
        require(result["status"] == "satisfied", "no satisfied entry theorem to consume")
        root = Path(artifacts).resolve()
        def content(name):
            path = root / name
            require(path.is_file() and path.resolve().is_relative_to(root), "missing or escaped " + name)
            return path.read_bytes()
        require(hashlib.sha256(content(spec.frames[0].artifact_stem + ".goto")).hexdigest() == value["bindings"]["goto_model_sha256"],
                "retained GOTO differs")
        stdout, stderr = content(spec.artifact_stem + ".stdout"), content(spec.artifact_stem + ".stderr")
        require(_output_sha256(stdout, stderr) == result["output_sha256"], "retained solver output differs")
        payload = _parse_json(stdout.decode())
        require(payload is not None and _property_statuses(payload) == {key: "SUCCESS" for key in result["property_ids"]},
                "retained solver output does not prove the entry theorem")


def checked_memory_summary_facts(proof, *, artifacts, runtime_assurance=None):
    """The caller must first validate ordinary supplier qualification."""
    from .bisimulation_assurance import validate_runtime_assurance_binding
    validate_runtime_assurance_binding(proof, runtime_assurance)
    empty = checked_empty_frame_operations(proof, artifacts=artifacts, runtime_assurance=runtime_assurance)
    shards = {(row["operation_id"], row["obligation_id"]): row for row in proof["shards"]}
    wide, machine_state = [], []
    for operation_index, operation in enumerate(proof["models"]["operation_models"]):
        complete = operation["operation_id"] in empty
        for index, model in enumerate(operation["obligation_models"]):
            shard = shards[(operation["operation_id"], model["obligation_id"])]
            value = shard.get("readable_entry_contract")
            if value is None or value["result"]["status"] != "satisfied":
                complete = False
                continue
            validate_readable_entry(value, model=model, shard=shard, checker=proof["checker"], runtime_assurance=runtime_assurance,
                artifacts=Path(artifacts) / f"operation-{operation_index:04d}-obligation-{index:04d}")
        if complete:
            wide.append(operation["operation_id"])
            if readable_machine_state_guarantee(proof, operation):
                machine_state.append(operation["operation_id"])
    return {"empty_exact_frame_operations": empty, "readable_entry_operations": tuple(wide),
            "readable_machine_state_operations": tuple(machine_state)}



def readable_machine_state_guarantee(proof, operation):
    """Derive the cut and exit frame from fixed inventoried assertion identities.

    Metadata readers use this after supplier validation. Retained-byte loading
    separately checks every positive wider theorem before exporting the fact.
    """
    guards = ((MACHINE_STATE_GUARD, MACHINE_STATE_PROPERTY, MACHINE_STATE_DESCRIPTION),
              (CUT_MACHINE_STATE_GUARD, CUT_MACHINE_STATE_PROPERTY, CUT_MACHINE_STATE_DESCRIPTION))
    certificate = proof["models"].get("source_summary_contracts", {}).get("certificate", {})
    shards = {(row["operation_id"], row["obligation_id"]): row for row in proof["shards"]}
    from .bisimulation_source_dependencies import READONLY_POLICIES
    return (certificate.get("policy") in READONLY_POLICIES
            and certificate.get("status") == "satisfied" and bool(operation["obligation_models"]) and all(
        description in model["required_assertion_descriptions"] and
        property_id in shards[(operation["operation_id"], model["obligation_id"])].get(
            "readable_entry_contract", {}).get("result", {}).get("property_ids", []) and
        any(row["property_id"] == property_id and row["description"] == description and row["source_function"] == guard
            for row in shards[(operation["operation_id"], model["obligation_id"])]["partitioned_evidence"]["assertions"])
        for model in operation["obligation_models"] for guard, property_id, description in guards))


def checked_mutable_entry_operations(proof, *, artifacts, runtime_assurance=None):
    """Ordinary qualification and both physical facts precede wider admission.

    This entry theorem does not supply a machine-state clobber contract or
    authorize body omission. The caller still checks its actual entry state.
    """
    from .bisimulation_assurance import validate_runtime_assurance_binding
    validate_runtime_assurance_binding(proof, runtime_assurance)
    confined = (*checked_fixed_writable_frame_operations(proof, artifacts=artifacts, runtime_assurance=runtime_assurance),
                *private_frame.checked_private_frame_operations(proof, artifacts=artifacts, runtime_assurance=runtime_assurance))
    shards = {(row["operation_id"], row["obligation_id"]): row for row in proof["shards"]}
    wide = []
    for operation_index, operation in enumerate(proof["models"]["operation_models"]):
        complete = operation["operation_id"] in confined
        for index, model in enumerate(operation["obligation_models"]):
            shard = shards[(operation["operation_id"], model["obligation_id"])]
            value = shard.get(MUTABLE.field)
            if value is None or value["result"]["status"] != "satisfied":
                complete = False
                continue
            validate_mutable_entry(value, model=model, shard=shard, checker=proof["checker"], runtime_assurance=runtime_assurance,
                artifacts=Path(artifacts) / f"operation-{operation_index:04d}-obligation-{index:04d}")
        if complete:
            wide.append(operation["operation_id"])
    return tuple(wide)

