"""Assumption identities for non-authorizing runtime-contract checks.

This validates dependency identities, not contract semantics or runtime
validation. Selecting a contract still needs an implemented lowering and an
independently validated runtime binding. A declaration is not a checked summary.
"""

from collections.abc import Mapping
import re

from .bisimulation_support import BisimulationRefinementError


def checked_runtime_assurance(value):
    """Copy a canonical trust selection; absence keeps ordinary evidence keys.

Contract hashes identify semantics, including relevant ABI and frame rules.
They are not C signature hashes or hashes of changing test reports. Runtime
validation receipts must be bound separately by the consuming result.
"""
    if value is None:
        return None
    if (not isinstance(value, Mapping) or set(value) != {"kind", "contracts"}
            or value["kind"] != "conditional-runtime-contracts"
            or not isinstance(value["contracts"], list) or not value["contracts"]):
        raise BisimulationRefinementError("runtime assurance requires explicit conditional contracts")
    contracts = []
    for row in value["contracts"]:
        if (not isinstance(row, Mapping) or set(row) != {"id", "revision", "contract_sha256"}
                or not isinstance(row["id"], str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}", row["id"])
                or type(row["revision"]) is not int or row["revision"] < 1
                or not isinstance(row["contract_sha256"], str)
                or not re.fullmatch(r"[0-9a-f]{64}", row["contract_sha256"])):
            raise BisimulationRefinementError("runtime assurance contract identity is malformed")
        contracts.append(dict(row))
    names = [row["id"] for row in contracts]
    if names != sorted(set(names)):
        raise BisimulationRefinementError("runtime assurance contracts must be unique and ordered")
    return {"kind": value["kind"], "contracts": contracts}


def runtime_assurance_defines(value):
    """Compilation markers bind guarded conditional lowerings to task assurance."""
    checked = checked_runtime_assurance(value)
    return ([] if checked is None else [
        "-DSPX_CONDITIONAL_RUNTIME_CONTRACT_" + row["contract_sha256"]
        for row in checked["contracts"]])


def _implemented_runtime_contracts():
    from ..artifacts.artifact_set import canonical_sha256_v3
    from .bisimulation_issued_access import issued_access_contract
    from .bisimulation_world_memory import allocation_byte_projection_contract

    from .bisimulation_world_namespace import world_reference_contract
    from .bisimulation_runtime_dispatch import runtime_dispatch_contract
    from .bisimulation_native_admission import native_admission_contract

    contracts = [issued_access_contract(), allocation_byte_projection_contract(), world_reference_contract(),
                 runtime_dispatch_contract(), native_admission_contract()]
    return {row["id"]: {"id": row["id"], "revision": row["revision"],
                         "contract_sha256": canonical_sha256_v3(row)} for row in contracts}


def checked_implemented_runtime_assurance(value):
    """Require exact implemented semantics before generating conditional C."""
    known = _implemented_runtime_contracts()
    checked = checked_runtime_assurance(value)
    if checked is None:
        return None
    if any(known.get(row["id"]) != row for row in checked["contracts"]):
        raise BisimulationRefinementError("runtime generation requires exact implemented contracts")
    return checked


def validate_runtime_assurance_binding(record, expected):
    """Check an evidence layer against a caller-selected trust boundary.

    Never infer permission to consume conditional evidence from the evidence
    itself. Ordinary callers pass None and continue to reject that evidence.
    Auxiliary ordinary certificates may already have authorizing=False.
    """
    expected = checked_implemented_runtime_assurance(expected)
    if not isinstance(record, Mapping):
        raise BisimulationRefinementError("runtime assurance evidence is malformed")
    if expected is None:
        if "assurance" in record:
            raise BisimulationRefinementError(
                "conditional runtime-contract evidence cannot authorize contextual qualification")
    elif record.get("assurance") != expected or record.get("authorizing") is not False:
        raise BisimulationRefinementError("conditional runtime assurance binding differs")


def admitted_supplier_assurance(proof, parent_assurance):
    """A caller may use only assumptions it explicitly selected itself.

    Subset inclusion is logical assumption weakening, not compatibility inferred
    from signatures or contract names. Revisions and semantic hashes must match.
    Ordinary supplier proofs continue through the ordinary proof validator.
    """
    parent = checked_implemented_runtime_assurance(parent_assurance)
    if "assurance" not in proof:
        return None
    supplier = checked_implemented_runtime_assurance(proof["assurance"])
    if parent is None or supplier is None or any(row not in parent["contracts"] for row in supplier["contracts"]):
        raise BisimulationRefinementError("conditional supplier assumptions are not selected by the caller")
    validate_runtime_assurance_binding(proof, supplier)
    return supplier


def runtime_contract_selected(value, identity):
    checked = checked_implemented_runtime_assurance(value)
    # The requested selector itself must name implemented semantics, even when
    # no conditional selection was supplied by the caller.
    if identity not in _implemented_runtime_contracts():
        raise BisimulationRefinementError("unknown generated runtime contract")
    return checked is not None and any(row["id"] == identity for row in checked["contracts"])
