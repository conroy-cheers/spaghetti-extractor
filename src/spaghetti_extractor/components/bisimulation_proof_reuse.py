"""Retain a checked scalar-contract proof across unchanged local proof inputs.

This is an engine optimization, not a new qualification or activation path.
Current suppliers are validated by prepare_connected_models before this module
is called. The ordinary contextual readers and provider gates remain mandatory.
"""

import copy
import hashlib
import json
import shutil
import time
from pathlib import Path, PurePosixPath

from ..artifacts.artifact_set import canonical_sha256_v3
from ..util import sha256_file
from .bisimulation_summary_contracts import consumed_scalar_summary_contract

POLICY = "unchanged-local-inputs-scalar-contract-proof-reuse-v1"
CALLER_FIELDS = (
    "interface_sha256", "semantic_contract_sha256", "source_profile_sha256",
    "implementation_sha256", "bisimulation_intent_sha256", "exact_c_slice_sha256",
    "machine_overlay_sha256", "proof_overlay_sha256", "trusted_adapter_lowering",
    "reference_authority",
)


def connected_binding(row):
    return {
        "component_id": row["component_id"],
        **({"assurance": row["assurance"], "authorizing": False} if "assurance" in row else {}),
        "binding_intent_sha256": row["binding_intent_sha256"],
        "implementation_sha256": row["source"]["implementation_sha256"],
        **{key: row[key] for key in ("source_profile_sha256", "qualification_sha256",
            "contextual_refinement_sha256", "proof_receipt_sha256", "summary_strategy",
            "source_summary_certificate", "entry_contract", "readable_transport_policy")},
        **({"mutable_transport_policy": row["mutable_transport_policy"]} if "mutable_transport_policy" in row else {}),
        "machine_overlay_sha256": hashlib.sha256(row["production_overlay_source"].encode("ascii")).hexdigest(),
        "proof_overlay_sha256": hashlib.sha256(row["proof_overlay_source"].encode("ascii")).hexdigest(),
        "trusted_adapter_lowering_receipt_sha256": None if row["trusted_adapter_lowering"] is None
            else row["trusted_adapter_lowering"]["receipt_sha256"],
        "machine_overlay_entries_sha256": canonical_sha256_v3(row["overlay_entries"]),
    }


def consumed_dependency(row):
    if (row.get("summary_strategy") != "scalar-body-free-v1" or row.get("entry_contract") is not None
            or row.get("readable_transport_policy") is not None or "assurance" in row
            or "mutable_transport_policy" in row):
        raise ValueError("local proof reuse requires unconditional scalar body-free suppliers")
    return {**{key: row[key] for key in ("component_id", "binding_intent_sha256", "summary_strategy",
        "machine_overlay_sha256", "proof_overlay_sha256", "trusted_adapter_lowering_receipt_sha256",
        "machine_overlay_entries_sha256")},
        "source_contract": consumed_scalar_summary_contract(row["source_summary_certificate"])}


def generator_identity():
    # Deliberately conservative initially: an engine/parser/runtime change
    # invalidates reuse. Do not guess which transitive renderer inputs matter.
    root = Path(__file__).resolve().parents[1]
    return canonical_sha256_v3({p.relative_to(root).as_posix(): sha256_file(p)
                               for p in sorted(root.rglob("*.py"))})


def input_record(*, caller, connected, extra):
    inputs = {"caller": caller, "dependencies": [consumed_dependency(row) for row in connected],
              "extra": extra, "generator_sha256": generator_identity()}
    return {"policy": POLICY, "inputs": inputs, "input_sha256": canonical_sha256_v3(inputs)}


def artifact_inventory(root):
    root = Path(root)
    files = sorted(root.rglob("*"))
    if any(p.is_symlink() for p in files):
        raise ValueError("reusable proof artifacts must not contain symlinks")
    return {p.relative_to(root).as_posix(): sha256_file(p) for p in files if p.is_file()}


def validate_record(models, checker=None):
    record = models.get("reusable_inputs")
    if record is None:
        return
    if (not isinstance(record, dict) or set(record) != {"policy", "inputs", "input_sha256", "artifacts"}
            or record["policy"] != POLICY or record["input_sha256"] != canonical_sha256_v3(record["inputs"])):
        raise ValueError("reusable proof input record is malformed or stale")
    inputs = record["inputs"]
    if (not isinstance(inputs, dict) or set(inputs) != {"caller", "dependencies", "extra", "generator_sha256"}
            or not isinstance(inputs["generator_sha256"], str) or len(inputs["generator_sha256"]) != 64
            or any(c not in "0123456789abcdef" for c in inputs["generator_sha256"])
            or not isinstance(inputs["extra"], dict)
            or inputs["caller"] != {key: models[key] for key in CALLER_FIELDS}
            or inputs["dependencies"] != [consumed_dependency(row) for row in models["connected_components"]]):
        raise ValueError("reusable proof contract differs from its enclosing proof")
    if checker is not None and any(inputs["extra"].get(key) != checker.get(key)
                                   for key in ("cbmc_sha256", "goto_cc_sha256", "smt_solver")):
        raise ValueError("reusable proof tool binding differs from its checker")
    artifacts = record["artifacts"]
    if (not isinstance(artifacts, dict) or not artifacts
            or artifacts.get("proof-reuse-inputs.json") != record["input_sha256"]
            or any(not isinstance(name, str) or not name or PurePosixPath(name).is_absolute()
                   or ".." in PurePosixPath(name).parts or PurePosixPath(name).as_posix() != name
                   or not isinstance(digest, str) or len(digest) != 64
                   or any(c not in "0123456789abcdef" for c in digest)
                   for name, digest in artifacts.items())):
        raise ValueError("reusable proof artifact inventory is malformed")


def reuse_proof(*, previous, record, connected, diagnostic_root):
    if previous is None or record is None or diagnostic_root is None:
        return None
    from .contextual_bisimulation import validate_contextual_refinement_v2

    started = time.monotonic()
    previous = Path(previous)
    packet = json.loads((previous / "contextual-refinement-result.json").read_text())
    proof = packet["proof"]
    validate_contextual_refinement_v2(proof, proof_plan=packet["proof_plan"], exact_c_slice=packet["exact_c_slice"])
    old = proof["models"].get("reusable_inputs")
    if (old is None or proof["status"] != "satisfied" or proof["activation_authorized"] is not True
            or {key: old[key] for key in record} != record):
        return None
    source = previous / ("proof-diagnostics" if "qualification_input" in packet else "diagnostics")
    if artifact_inventory(source) != old["artifacts"]:
        raise ValueError("retained reusable proof artifacts differ from the bound inventory")
    bindings = copy.deepcopy(proof["models"])
    bindings.pop("source_summary_contracts", None)  # Provider owns auxiliary source evidence.
    bindings["connected_components"] = connected
    validate_record(bindings, proof["checker"])
    destination = Path(diagnostic_root)
    if destination.exists():
        raise ValueError("reused proof destination already exists")
    shutil.copytree(source, destination)
    core = {"status": "satisfied", "activation_authorized": True, "component_id": proof["component_id"],
            "bindings": bindings, "checker": copy.deepcopy(proof["checker"]),
            "checks": copy.deepcopy(proof["shards"]), "issues": []}
    (destination.parent / "proof-reuse.json").write_text(json.dumps({
        "authorizing": False, "policy": POLICY, "previous_proof_receipt_sha256": proof["receipt_sha256"],
        "model_generation": 0, "compiler_runs": 0, "solver_runs": 0,
        "seconds": time.monotonic() - started}, indent=2) + "\n")
    return {**core, "receipt_sha256": canonical_sha256_v3(core)}
