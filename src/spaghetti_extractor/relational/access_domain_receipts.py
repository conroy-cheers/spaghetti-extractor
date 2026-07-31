"""Typed access/fault qualification artifacts and legacy diagnostic receipts.

Receipt proposals are untrusted scheduling data.  Checked receipts bind one
exact binary occurrence to one Lean declaration from a trust-zero compiled
module.  Neither artifact carries state-transition or relational authority.

The GNU round-trip lane no longer uses those theorem-name receipts as proof
evidence.  ``generate_typed_access_fault_qualification`` emits concrete
``TypedAccessFaultQualification`` terms whose types bind the exact decoded
instruction anchor, checked semantic transfer, memory footprint, fault classes,
canonical region lookup, and the remaining runtime-state admissibility premise.
"""

from __future__ import annotations

from collections import Counter
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any
import hashlib
import json
import re

from ..errors import StageAInputError
from ..util import sha256_bytes


ACCESS_DOMAIN_DIMENSION = "access_fault_domain"
ACCESS_DOMAIN_RECEIPT_PROPOSALS_FORMAT = (
    "stage-a-access-domain-receipt-proposals-v1"
)
ACCESS_DOMAIN_RECEIPTS_FORMAT = "stage-a-access-domain-receipts-v1"
ACCESS_DOMAIN_RECEIPT_RESOLUTION_FORMAT = (
    "stage-a-access-domain-receipt-resolution-v1"
)
TYPED_ACCESS_FAULT_QUALIFICATION_FORMAT = (
    "stage-a-typed-access-fault-qualification-v1"
)
TYPED_ACCESS_FAULT_QUALIFICATION_MANIFEST_FORMAT = (
    "stage-a-typed-access-fault-qualification-manifest-v1"
)
LEAN_KERNEL_CHECK_REQUESTS_FORMAT = "stage-a-lean-kernel-check-requests-v1"
APPROVED_ACCESS_DOMAIN_AXIOMS = (
    "Classical.choice",
    "Quot.sound",
    "propext",
)

_SHA256_RE = re.compile(r"[0-9a-f]{64}")
_HEX_RE = re.compile(r"[0-9a-f]+")
_SIDES = ("original", "candidate")
_SIDE_RANK = {side: index for index, side in enumerate(_SIDES)}
_TERM_FIELDS = {"module", "namespace", "symbol"}
_KEY_FIELDS = {
    "side",
    "binary_sha256",
    "rva",
    "size",
    "bytes",
    "semantic_form",
}
_KERNEL_FIELDS = {
    "status",
    "lean_trust",
    "target_bundle_sha256",
    "source_sha256",
    "olean_sha256",
    "module",
    "axiom_audit_complete",
    "approved_axioms",
    "observed_axioms",
    "unexpected_axioms",
}
_RECEIPT_FIELDS = (
    _KEY_FIELDS
    | {
        "id",
        "dimension",
        "theorem",
        "kernel_check",
        "receipt_sha256",
    }
)
_PROPOSAL_FIELDS = _KEY_FIELDS | {"dimension", "theorem"}
_RECEIPT_ARTIFACT_FIELDS = {
    "format",
    "dimension",
    "approved_axioms",
    "receipts",
    "receipts_sha256",
    "trust",
}
_PROPOSAL_ARTIFACT_FIELDS = {
    "format",
    "dimension",
    "proposals",
    "proposals_sha256",
    "trust",
}
_RESOLUTION_FIELDS = {
    "format",
    "dimension",
    "input_sha256",
    "status",
    "accepted_receipts",
    "diagnostics",
    "counts",
    "trust",
}
_DIAGNOSTIC_FIELDS = {
    "code",
    "receipt_index",
    "receipt_id",
    "side",
    "binary_sha256",
    "rva",
    "size",
    "bytes",
    "semantic_form",
}
_RESOLUTION_COUNT_FIELDS = {"provided", "accepted", "rejected", "by_code"}
_PROPOSAL_TRUST = {
    "role": "untrusted_access_domain_kernel_check_scheduling",
    "proof_authority": False,
    "changes_semantic_coverage": False,
}
_RECEIPT_TRUST = {
    "role": "lean_checked_exact_occurrence_access_domain_binding",
    "proof_authority": False,
    "claim_scope": "modeled_domain_only",
    "affects_dimensions": [ACCESS_DOMAIN_DIMENSION],
    "requires_exact_source_and_olean_identity": True,
    "requires_approved_axiom_audit": True,
}
_RESOLUTION_TRUST = {
    "role": "derived_access_domain_receipt_application",
    "proof_authority": False,
    "fail_closed": True,
    "affects_dimensions": [ACCESS_DOMAIN_DIMENSION],
}
_TYPED_QUALIFICATION_TRUST = {
    "role": "lean_typed_access_fault_qualification_source",
    "proof_authority": False,
    "closes_stage_a_proof": False,
    "executes_original_binary": False,
    "executes_candidate_binary": False,
    "exact_pe_decode_required": True,
    "checked_semantic_transfer_required": True,
    "runtime_state_admissibility_required": True,
    "fail_closed": True,
}


def _canonical_json(value: Any, context: str) -> bytes:
    try:
        return json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")
    except (RecursionError, TypeError, ValueError) as exc:
        raise StageAInputError(
            f"{context} is not canonical JSON: {exc}"
        ) from exc


def _canonical_sha256(value: Any, context: str) -> str:
    return sha256_bytes(_canonical_json(value, context))


def _object(value: Any, context: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise StageAInputError(f"{context} must be an object")
    return value


def _exact_fields(
    value: Mapping[str, Any], expected: set[str], context: str
) -> None:
    if set(value) != expected:
        raise StageAInputError(f"{context} fields are malformed")


def _string(value: Any, context: str) -> str:
    if (
        not isinstance(value, str)
        or not value
        or value.strip() != value
        or any(ord(character) < 0x20 for character in value)
    ):
        raise StageAInputError(
            f"{context} must be a nonempty printable string"
        )
    return value


def _sha256(value: Any, context: str) -> str:
    if not isinstance(value, str) or _SHA256_RE.fullmatch(value) is None:
        raise StageAInputError(
            f"{context} must be 64 lowercase hex characters"
        )
    return value


def _integer(
    value: Any,
    context: str,
    *,
    minimum: int = 0,
    maximum: int | None = None,
) -> int:
    if (
        isinstance(value, bool)
        or not isinstance(value, int)
        or value < minimum
        or (maximum is not None and value > maximum)
    ):
        raise StageAInputError(f"{context} is outside its integer range")
    return value


def _ordered_strings(value: Any, context: str) -> list[str]:
    if not isinstance(value, list):
        raise StageAInputError(f"{context} must be a list")
    result = [_string(item, f"{context}[{index}]") for index, item in enumerate(value)]
    if result != sorted(set(result)):
        raise StageAInputError(
            f"{context} must be unique and canonically ordered"
        )
    return result


def _semantic_form(value: Any, context: str) -> str:
    if (
        not isinstance(value, str)
        or not value
        or value.strip() != value
        or len(value) > 65536
        or "\r" in value
        or "\t" in value
        or any(
            ord(character) < 0x20 and character != "\n"
            for character in value
        )
    ):
        raise StageAInputError(f"{context} is not a canonical semantic form")
    return value


def _term(value: Any, context: str) -> dict[str, str]:
    payload = _object(value, context)
    _exact_fields(payload, _TERM_FIELDS, context)
    result = {
        field: _string(payload[field], f"{context}.{field}")
        for field in ("module", "namespace", "symbol")
    }
    if not result["module"].startswith("StageA."):
        raise StageAInputError(f"{context}.module is outside StageA")
    return result


def _key_payload(value: Mapping[str, Any], context: str) -> dict[str, Any]:
    side = value.get("side")
    if side not in _SIDES:
        raise StageAInputError(f"{context}.side is invalid")
    size = _integer(
        value.get("size"), f"{context}.size", minimum=1, maximum=15
    )
    encoded = value.get("bytes")
    if (
        not isinstance(encoded, str)
        or len(encoded) != size * 2
        or _HEX_RE.fullmatch(encoded) is None
    ):
        raise StageAInputError(f"{context}.bytes is invalid")
    return {
        "side": side,
        "binary_sha256": _sha256(
            value.get("binary_sha256"), f"{context}.binary_sha256"
        ),
        "rva": _integer(
            value.get("rva"),
            f"{context}.rva",
            maximum=2**32 - 1,
        ),
        "size": size,
        "bytes": encoded,
        "semantic_form": _semantic_form(
            value.get("semantic_form"), f"{context}.semantic_form"
        ),
    }


def access_domain_occurrence_key(
    value: Mapping[str, Any],
) -> tuple[str, str, int, int, str, str]:
    """Return the canonical receipt identity tuple."""

    return (
        str(value["side"]),
        str(value["binary_sha256"]),
        int(value["rva"]),
        int(value["size"]),
        str(value["bytes"]),
        str(value["semantic_form"]),
    )


def _receipt_sort_key(
    value: Mapping[str, Any],
) -> tuple[int, str, int, int, str, str, str]:
    key = access_domain_occurrence_key(value)
    return (
        _SIDE_RANK[key[0]],
        key[1],
        key[2],
        key[3],
        key[4],
        key[5],
        str(value.get("id", "")),
    )


def _parse_kernel_check(
    value: Any,
    *,
    theorem: Mapping[str, str],
    context: str,
) -> dict[str, Any]:
    payload = _object(value, context)
    _exact_fields(payload, _KERNEL_FIELDS, context)
    approved = _ordered_strings(
        payload["approved_axioms"], f"{context}.approved_axioms"
    )
    observed = _ordered_strings(
        payload["observed_axioms"], f"{context}.observed_axioms"
    )
    unexpected = _ordered_strings(
        payload["unexpected_axioms"], f"{context}.unexpected_axioms"
    )
    expected_approved = list(APPROVED_ACCESS_DOMAIN_AXIOMS)
    expected_unexpected = sorted(set(observed) - set(approved))
    if (
        payload["status"] != "checked"
        or payload["lean_trust"] != 0
        or payload["axiom_audit_complete"] is not True
        or approved != expected_approved
        or unexpected != expected_unexpected
        or unexpected
    ):
        raise StageAInputError(
            f"{context} is not a trust-zero approved-axiom check"
        )
    module = _string(payload["module"], f"{context}.module")
    if module != theorem["module"]:
        raise StageAInputError(
            f"{context}.module does not match the theorem module"
        )
    return {
        "status": "checked",
        "lean_trust": 0,
        "target_bundle_sha256": _sha256(
            payload["target_bundle_sha256"],
            f"{context}.target_bundle_sha256",
        ),
        "source_sha256": _sha256(
            payload["source_sha256"], f"{context}.source_sha256"
        ),
        "olean_sha256": _sha256(
            payload["olean_sha256"], f"{context}.olean_sha256"
        ),
        "module": module,
        "axiom_audit_complete": True,
        "approved_axioms": approved,
        "observed_axioms": observed,
        "unexpected_axioms": [],
    }


def parse_access_domain_receipt(
    value: Any, *, context: str = "access-domain receipt"
) -> dict[str, Any]:
    """Strictly parse one checked exact-occurrence receipt."""

    payload = _object(value, context)
    _exact_fields(payload, _RECEIPT_FIELDS, context)
    key = _key_payload(payload, context)
    if payload["dimension"] != ACCESS_DOMAIN_DIMENSION:
        raise StageAInputError(f"{context}.dimension is invalid")
    theorem = _term(payload["theorem"], f"{context}.theorem")
    kernel = _parse_kernel_check(
        payload["kernel_check"],
        theorem=theorem,
        context=f"{context}.kernel_check",
    )
    body = {
        **key,
        "dimension": ACCESS_DOMAIN_DIMENSION,
        "theorem": theorem,
        "kernel_check": kernel,
    }
    expected_sha256 = _canonical_sha256(body, context)
    expected_id = f"access-domain-receipt-{expected_sha256[:24]}"
    if payload["receipt_sha256"] != expected_sha256:
        raise StageAInputError(f"{context}.receipt_sha256 mismatch")
    if payload["id"] != expected_id:
        raise StageAInputError(f"{context}.id mismatch")
    return {
        "id": expected_id,
        **body,
        "receipt_sha256": expected_sha256,
    }


def _checked_access_domain_receipt(
    *,
    side: str,
    binary_sha256: str,
    rva: int,
    size: int,
    encoded: str,
    semantic_form: str,
    theorem: Mapping[str, str],
    target_bundle_sha256: str,
    source_sha256: str,
    olean_sha256: str,
    observed_axioms: Sequence[str] = (),
) -> dict[str, Any]:
    """Package already checked Lean evidence; this performs no Lean proof."""

    body = {
        **_key_payload(
            {
                "side": side,
                "binary_sha256": binary_sha256,
                "rva": rva,
                "size": size,
                "bytes": encoded,
                "semantic_form": semantic_form,
            },
            "access-domain receipt",
        ),
        "dimension": ACCESS_DOMAIN_DIMENSION,
        "theorem": _term(theorem, "access-domain receipt theorem"),
    }
    observed = sorted(set(observed_axioms))
    body["kernel_check"] = {
        "status": "checked",
        "lean_trust": 0,
        "target_bundle_sha256": target_bundle_sha256,
        "source_sha256": source_sha256,
        "olean_sha256": olean_sha256,
        "module": body["theorem"]["module"],
        "axiom_audit_complete": True,
        "approved_axioms": list(APPROVED_ACCESS_DOMAIN_AXIOMS),
        "observed_axioms": observed,
        "unexpected_axioms": sorted(
            set(observed) - set(APPROVED_ACCESS_DOMAIN_AXIOMS)
        ),
    }
    digest = _canonical_sha256(body, "access-domain receipt")
    return parse_access_domain_receipt(
        {
            "id": f"access-domain-receipt-{digest[:24]}",
            **body,
            "receipt_sha256": digest,
        }
    )


def create_access_domain_receipts(
    *,
    proposals_payload: Any,
    target_bundle: Any,
    source_root: Path,
) -> dict[str, Any]:
    """Bind proposals to actual compiled modules and Lean axiom inventories."""

    requests = build_access_domain_kernel_check_requests(proposals_payload)
    del requests
    proposal_artifact = _object(
        proposals_payload, "access-domain receipt proposal artifact"
    )
    raw_proposals = proposal_artifact["proposals"]
    proposals = [
        _parse_proposal(row, index)
        for index, row in enumerate(raw_proposals)
    ]

    bundle = _object(target_bundle, "Lean target bundle")
    if (
        bundle.get("format") != "stage-a-lean-target-bundle-v2"
        or bundle.get("lean_trust") != 0
    ):
        raise StageAInputError(
            "Lean target bundle is not a trust-zero v2 bundle"
        )
    nodes = bundle.get("nodes")
    if not isinstance(nodes, list):
        raise StageAInputError("Lean target bundle has no node inventory")
    outputs: dict[
        str, list[tuple[Mapping[str, Any], Mapping[str, Any]]]
    ] = {}
    for node_index, raw_node in enumerate(nodes):
        node = _object(
            raw_node, f"Lean target bundle node {node_index}"
        )
        raw_outputs = node.get("outputs")
        if not isinstance(raw_outputs, list):
            raise StageAInputError(
                f"Lean target bundle node {node_index} has no outputs"
            )
        for output_index, raw_output in enumerate(raw_outputs):
            output = _object(
                raw_output,
                f"Lean target bundle node {node_index} output {output_index}",
            )
            module = output.get("module")
            if not isinstance(module, str) or not module:
                raise StageAInputError(
                    "Lean target bundle output has no module"
                )
            outputs.setdefault(module, []).append((node, output))

    bundle_sha256 = _canonical_sha256(
        target_bundle, "Lean target bundle"
    )
    receipts: list[dict[str, Any]] = []
    for index, proposal in enumerate(proposals):
        theorem = proposal["theorem"]
        short_module = theorem["module"].removeprefix("StageA.")
        matching_pairs = [
            *outputs.get(theorem["module"], []),
            *outputs.get(short_module, []),
        ]
        unique_matching = {
            (id(node), id(output)): (node, output)
            for node, output in matching_pairs
        }
        matching_pairs = list(unique_matching.values())
        if len(matching_pairs) != 1:
            raise StageAInputError(
                f"compiled output for {theorem['module']} is absent "
                "or ambiguous"
            )
        node, output = matching_pairs[0]
        olean_sha256 = _sha256(
            output.get("olean_sha256"),
            f"compiled output for {theorem['module']} olean SHA-256",
        )
        audit = output.get("axiom_audit")
        inventories = (
            audit.get("inventories")
            if isinstance(audit, Mapping)
            else None
        )
        if (
            not isinstance(audit, Mapping)
            or audit.get("complete") is not True
            or not isinstance(inventories, Mapping)
        ):
            raise StageAInputError(
                f"compiled output for {theorem['module']} has no complete "
                "axiom audit"
            )
        qualified = f"{theorem['namespace']}.{theorem['symbol']}"
        audited = [
            value
            for declaration, value in inventories.items()
            if (
                declaration == theorem["symbol"]
                or declaration == qualified
                or qualified.endswith(f".{declaration}")
            )
        ]
        if len(audited) != 1 or not isinstance(audited[0], list):
            raise StageAInputError(
                f"compiled output did not audit {qualified}"
            )
        source = (
            source_root
            / "StageA"
            / Path(*short_module.split(".")).with_suffix(".lean")
        )
        if not source.is_file():
            raise StageAInputError(
                f"kernel-check source is missing for {theorem['module']}"
            )
        node_modules = node.get("modules")
        node_source_sha256 = node.get("source_sha256")
        if (
            not isinstance(node_modules, list)
            or short_module not in node_modules
            or not all(
                isinstance(module, str) and module
                for module in node_modules
            )
        ):
            raise StageAInputError(
                f"compiled node does not bind {theorem['module']}"
            )
        module_source_hashes: list[str] = []
        for node_module in node_modules:
            node_source = (
                source_root
                / "StageA"
                / Path(*node_module.split(".")).with_suffix(".lean")
            )
            if not node_source.is_file():
                raise StageAInputError(
                    f"compiled node source is missing for StageA.{node_module}"
                )
            module_source_hashes.append(
                hashlib.sha256(node_source.read_bytes()).hexdigest()
            )
        direct_source_sha256 = (
            module_source_hashes[0] if len(module_source_hashes) == 1 else None
        )
        packed_source_sha256 = hashlib.sha256(
            ":".join(module_source_hashes).encode("ascii")
        ).hexdigest()
        if node_source_sha256 not in {
            direct_source_sha256,
            packed_source_sha256,
        }:
            raise StageAInputError(
                f"compiled node source identity for {theorem['module']} "
                "does not match the exact source files"
            )
        observed = _ordered_strings(
            audited[0],
            f"compiled output axiom inventory for {qualified}",
        )
        unexpected = sorted(
            set(observed) - set(APPROVED_ACCESS_DOMAIN_AXIOMS)
        )
        if unexpected:
            raise StageAInputError(
                f"compiled output for {qualified} uses unapproved axioms"
            )
        receipts.append(
            _checked_access_domain_receipt(
                side=proposal["side"],
                binary_sha256=proposal["binary_sha256"],
                rva=proposal["rva"],
                size=proposal["size"],
                encoded=proposal["bytes"],
                semantic_form=proposal["semantic_form"],
                theorem=theorem,
                target_bundle_sha256=bundle_sha256,
                source_sha256=hashlib.sha256(source.read_bytes()).hexdigest(),
                olean_sha256=olean_sha256,
                observed_axioms=observed,
            )
        )
    return access_domain_receipts_payload(receipts)


def access_domain_receipts_payload(
    receipts: Sequence[Mapping[str, Any]],
) -> dict[str, Any]:
    """Package checked receipts without creating or strengthening evidence."""

    parsed = [
        parse_access_domain_receipt(
            receipt, context=f"access-domain receipt {index}"
        )
        for index, receipt in enumerate(receipts)
    ]
    parsed.sort(key=_receipt_sort_key)
    keys = [access_domain_occurrence_key(row) for row in parsed]
    if len(keys) != len(set(keys)):
        raise StageAInputError(
            "access-domain receipt artifact duplicates an occurrence"
        )
    body = {
        "format": ACCESS_DOMAIN_RECEIPTS_FORMAT,
        "dimension": ACCESS_DOMAIN_DIMENSION,
        "approved_axioms": list(APPROVED_ACCESS_DOMAIN_AXIOMS),
        "receipts": parsed,
        "trust": dict(_RECEIPT_TRUST),
    }
    return {
        **body,
        "receipts_sha256": _canonical_sha256(
            body, "access-domain receipt artifact"
        ),
    }


def _parse_proposal(value: Any, index: int) -> dict[str, Any]:
    context = f"access-domain receipt proposal {index}"
    payload = _object(value, context)
    _exact_fields(payload, _PROPOSAL_FIELDS, context)
    if payload["dimension"] != ACCESS_DOMAIN_DIMENSION:
        raise StageAInputError(f"{context}.dimension is invalid")
    return {
        **_key_payload(payload, context),
        "dimension": ACCESS_DOMAIN_DIMENSION,
        "theorem": _term(payload["theorem"], f"{context}.theorem"),
    }


def access_domain_receipt_proposals_payload(
    proposals: Sequence[Mapping[str, Any]],
) -> dict[str, Any]:
    """Package untrusted occurrence-to-theorem scheduling proposals."""

    parsed = [_parse_proposal(row, index) for index, row in enumerate(proposals)]
    parsed.sort(key=_receipt_sort_key)
    keys = [access_domain_occurrence_key(row) for row in parsed]
    if len(keys) != len(set(keys)):
        raise StageAInputError(
            "access-domain receipt proposals duplicate an occurrence"
        )
    body = {
        "format": ACCESS_DOMAIN_RECEIPT_PROPOSALS_FORMAT,
        "dimension": ACCESS_DOMAIN_DIMENSION,
        "proposals": parsed,
        "trust": dict(_PROPOSAL_TRUST),
    }
    return {
        **body,
        "proposals_sha256": _canonical_sha256(
            body, "access-domain receipt proposal artifact"
        ),
    }


def build_access_domain_kernel_check_requests(
    proposals_payload: Any,
) -> dict[str, Any]:
    """Turn exact receipt proposals into deduplicated Lean check requests."""

    payload = _object(
        proposals_payload, "access-domain receipt proposal artifact"
    )
    _exact_fields(
        payload,
        _PROPOSAL_ARTIFACT_FIELDS,
        "access-domain receipt proposal artifact",
    )
    if (
        payload["format"] != ACCESS_DOMAIN_RECEIPT_PROPOSALS_FORMAT
        or payload["dimension"] != ACCESS_DOMAIN_DIMENSION
        or payload["trust"] != _PROPOSAL_TRUST
    ):
        raise StageAInputError(
            "access-domain receipt proposal artifact identity mismatch"
        )
    raw = payload["proposals"]
    if not isinstance(raw, list):
        raise StageAInputError(
            "access-domain receipt proposals must be a list"
        )
    proposals = [_parse_proposal(row, index) for index, row in enumerate(raw)]
    keys = [access_domain_occurrence_key(row) for row in proposals]
    if keys != sorted(set(keys), key=lambda key: (
        _SIDE_RANK[key[0]], key[1], key[2], key[3], key[4], key[5]
    )):
        raise StageAInputError(
            "access-domain receipt proposals must be unique and ordered"
        )
    body = {
        field: payload[field]
        for field in _PROPOSAL_ARTIFACT_FIELDS - {"proposals_sha256"}
    }
    if payload["proposals_sha256"] != _canonical_sha256(
        body, "access-domain receipt proposal artifact"
    ):
        raise StageAInputError(
            "access-domain receipt proposal artifact SHA-256 mismatch"
        )
    terms = {
        (
            proposal["theorem"]["module"],
            proposal["theorem"]["namespace"],
            proposal["theorem"]["symbol"],
        )
        for proposal in proposals
    }
    return {
        "format": LEAN_KERNEL_CHECK_REQUESTS_FORMAT,
        "requests": [
            {
                "term": {
                    "module": module,
                    "namespace": namespace,
                    "symbol": symbol,
                }
            }
            for module, namespace, symbol in sorted(terms)
        ],
    }


def _diagnostic(
    code: str,
    index: int | None,
    raw: Any,
) -> dict[str, Any]:
    payload = raw if isinstance(raw, Mapping) else {}
    return {
        "code": code,
        "receipt_index": index,
        "receipt_id": (
            payload.get("id") if isinstance(payload.get("id"), str) else None
        ),
        "side": (
            payload.get("side") if payload.get("side") in _SIDES else None
        ),
        "binary_sha256": (
            payload.get("binary_sha256")
            if isinstance(payload.get("binary_sha256"), str)
            and _SHA256_RE.fullmatch(payload["binary_sha256"])
            else None
        ),
        "rva": (
            payload.get("rva")
            if isinstance(payload.get("rva"), int)
            and not isinstance(payload.get("rva"), bool)
            else None
        ),
        "size": (
            payload.get("size")
            if isinstance(payload.get("size"), int)
            and not isinstance(payload.get("size"), bool)
            else None
        ),
        "bytes": (
            payload.get("bytes")
            if isinstance(payload.get("bytes"), str)
            else None
        ),
        "semantic_form": (
            payload.get("semantic_form")
            if isinstance(payload.get("semantic_form"), str)
            else None
        ),
    }


def _diagnostic_sort_key(value: Mapping[str, Any]) -> tuple[Any, ...]:
    side = value["side"]
    return (
        _SIDE_RANK.get(side, len(_SIDES)),
        value["binary_sha256"] or "",
        value["rva"] if value["rva"] is not None else 2**33,
        value["size"] if value["size"] is not None else 16,
        value["bytes"] or "",
        value["semantic_form"] or "",
        value["code"],
        value["receipt_index"]
        if value["receipt_index"] is not None
        else 2**63,
        value["receipt_id"] or "",
    )


def _resolution(
    *,
    input_sha256: str | None,
    status: str,
    accepted: Sequence[Mapping[str, Any]],
    diagnostics: Sequence[Mapping[str, Any]],
    provided: int,
) -> dict[str, Any]:
    accepted_rows = sorted(
        (dict(row) for row in accepted), key=_receipt_sort_key
    )
    diagnostic_rows = sorted(
        (dict(row) for row in diagnostics), key=_diagnostic_sort_key
    )
    by_code = Counter(row["code"] for row in diagnostic_rows)
    return {
        "format": ACCESS_DOMAIN_RECEIPT_RESOLUTION_FORMAT,
        "dimension": ACCESS_DOMAIN_DIMENSION,
        "input_sha256": input_sha256,
        "status": status,
        "accepted_receipts": accepted_rows,
        "diagnostics": diagnostic_rows,
        "counts": {
            "provided": provided,
            "accepted": len(accepted_rows),
            "rejected": max(provided - len(accepted_rows), 0),
            "by_code": {
                code: by_code[code] for code in sorted(by_code)
            },
        },
        "trust": dict(_RESOLUTION_TRUST),
    }


def resolve_access_domain_receipts(
    payload: Any | None,
    *,
    occurrences: Sequence[Mapping[str, Any]],
    binary_sha256_by_side: Mapping[str, str],
) -> dict[str, Any]:
    """Resolve checked receipts against exact current occurrences.

    Malformed, stale, duplicated, or tampered evidence is diagnosed and
    ignored.  The caller therefore retains ``requires-proof`` for those rows.
    """

    if payload is None:
        return _resolution(
            input_sha256=None,
            status="absent",
            accepted=(),
            diagnostics=(),
            provided=0,
        )
    try:
        input_sha256 = _canonical_sha256(
            payload, "access-domain receipt input"
        )
    except StageAInputError:
        return _resolution(
            input_sha256=None,
            status="blocked",
            accepted=(),
            diagnostics=[
                _diagnostic("receipt-artifact-not-canonical", None, payload)
            ],
            provided=0,
        )

    artifact = payload if isinstance(payload, Mapping) else {}
    raw_receipts = artifact.get("receipts")
    provided = len(raw_receipts) if isinstance(raw_receipts, list) else 0
    if (
        not isinstance(payload, Mapping)
        or set(payload) != _RECEIPT_ARTIFACT_FIELDS
        or payload.get("format") != ACCESS_DOMAIN_RECEIPTS_FORMAT
        or payload.get("dimension") != ACCESS_DOMAIN_DIMENSION
        or payload.get("approved_axioms")
        != list(APPROVED_ACCESS_DOMAIN_AXIOMS)
        or payload.get("trust") != _RECEIPT_TRUST
        or not isinstance(raw_receipts, list)
    ):
        return _resolution(
            input_sha256=input_sha256,
            status="blocked",
            accepted=(),
            diagnostics=[
                _diagnostic("receipt-artifact-schema-mismatch", None, payload)
            ],
            provided=provided,
        )
    body = {
        field: payload[field]
        for field in _RECEIPT_ARTIFACT_FIELDS - {"receipts_sha256"}
    }
    if payload["receipts_sha256"] != _canonical_sha256(
        body, "access-domain receipt artifact"
    ):
        return _resolution(
            input_sha256=input_sha256,
            status="blocked",
            accepted=(),
            diagnostics=[
                _diagnostic("receipt-artifact-digest-mismatch", None, payload)
            ],
            provided=provided,
        )

    occurrence_by_key: dict[
        tuple[str, str, int, int, str, str], Mapping[str, Any]
    ] = {}
    loose_occurrences: set[tuple[str, int, int, str, str]] = set()
    location_occurrences: set[tuple[str, str, int]] = set()
    for occurrence in occurrences:
        side = str(occurrence["side"])
        key = (
            side,
            binary_sha256_by_side[side],
            int(occurrence["rva"]),
            int(occurrence["size"]),
            str(occurrence["bytes"]),
            str(occurrence["form"]),
        )
        occurrence_by_key[key] = occurrence
        loose_occurrences.add((key[0], key[2], key[3], key[4], key[5]))
        location_occurrences.add((key[0], key[1], key[2]))

    parsed_rows: list[tuple[int, dict[str, Any]]] = []
    diagnostics: list[dict[str, Any]] = []
    for index, raw in enumerate(raw_receipts):
        try:
            parsed_rows.append(
                (
                    index,
                    parse_access_domain_receipt(
                        raw, context=f"access-domain receipt {index}"
                    ),
                )
            )
        except StageAInputError as exc:
            code = (
                "receipt-digest-mismatch"
                if "receipt_sha256 mismatch" in str(exc)
                or ".id mismatch" in str(exc)
                else (
                    "receipt-kernel-check-invalid"
                    if "kernel_check" in str(exc)
                    or "approved-axiom" in str(exc)
                    else "receipt-schema-mismatch"
                )
            )
            diagnostics.append(_diagnostic(code, index, raw))

    grouped: dict[
        tuple[str, str, int, int, str, str],
        list[tuple[int, dict[str, Any]]],
    ] = {}
    for indexed in parsed_rows:
        grouped.setdefault(
            access_domain_occurrence_key(indexed[1]), []
        ).append(indexed)

    accepted: list[dict[str, Any]] = []
    for key in sorted(
        grouped,
        key=lambda item: (
            _SIDE_RANK[item[0]],
            item[1],
            item[2],
            item[3],
            item[4],
            item[5],
        ),
    ):
        rows = grouped[key]
        if len(rows) != 1:
            diagnostics.extend(
                _diagnostic("receipt-duplicate-key", index, row)
                for index, row in rows
            )
            continue
        index, row = rows[0]
        occurrence = occurrence_by_key.get(key)
        if occurrence is None:
            loose = (key[0], key[2], key[3], key[4], key[5])
            if loose in loose_occurrences:
                code = "receipt-stale-binary"
            elif (key[0], key[1], key[2]) in location_occurrences:
                code = "receipt-stale-occurrence"
            else:
                code = "receipt-unmatched-occurrence"
            diagnostics.append(_diagnostic(code, index, row))
            continue
        if occurrence.get("access_fault_domain") != "requires-proof":
            diagnostics.append(
                _diagnostic("receipt-dimension-not-required", index, row)
            )
            continue
        accepted.append(row)

    return _resolution(
        input_sha256=input_sha256,
        status=(
            "applied"
            if accepted and not diagnostics
            else "partial"
            if accepted
            else "blocked"
        ),
        accepted=accepted,
        diagnostics=diagnostics,
        provided=provided,
    )


def parse_access_domain_receipt_resolution(value: Any) -> dict[str, Any]:
    """Strictly parse the self-contained resolver result."""

    payload = _object(value, "access-domain receipt resolution")
    _exact_fields(
        payload, _RESOLUTION_FIELDS, "access-domain receipt resolution"
    )
    if (
        payload["format"] != ACCESS_DOMAIN_RECEIPT_RESOLUTION_FORMAT
        or payload["dimension"] != ACCESS_DOMAIN_DIMENSION
        or payload["trust"] != _RESOLUTION_TRUST
        or payload["status"]
        not in {"absent", "applied", "partial", "blocked"}
    ):
        raise StageAInputError(
            "access-domain receipt resolution identity mismatch"
        )
    input_sha256 = payload["input_sha256"]
    if input_sha256 is not None:
        input_sha256 = _sha256(
            input_sha256, "access-domain receipt resolution input SHA-256"
        )
    raw_accepted = payload["accepted_receipts"]
    if not isinstance(raw_accepted, list):
        raise StageAInputError(
            "access-domain receipt resolution accepted_receipts is not a list"
        )
    accepted = [
        parse_access_domain_receipt(
            row, context=f"accepted access-domain receipt {index}"
        )
        for index, row in enumerate(raw_accepted)
    ]
    if accepted != sorted(accepted, key=_receipt_sort_key):
        raise StageAInputError(
            "accepted access-domain receipts are not ordered"
        )
    accepted_keys = [access_domain_occurrence_key(row) for row in accepted]
    if len(accepted_keys) != len(set(accepted_keys)):
        raise StageAInputError(
            "accepted access-domain receipts contain duplicate keys"
        )
    raw_diagnostics = payload["diagnostics"]
    if not isinstance(raw_diagnostics, list):
        raise StageAInputError(
            "access-domain receipt resolution diagnostics is not a list"
        )
    diagnostics: list[dict[str, Any]] = []
    for index, raw in enumerate(raw_diagnostics):
        context = f"access-domain receipt diagnostic {index}"
        diagnostic = _object(raw, context)
        _exact_fields(diagnostic, _DIAGNOSTIC_FIELDS, context)
        code = _string(diagnostic["code"], f"{context}.code")
        receipt_index = diagnostic["receipt_index"]
        if receipt_index is not None:
            receipt_index = _integer(
                receipt_index, f"{context}.receipt_index"
            )
        receipt_id = diagnostic["receipt_id"]
        if receipt_id is not None:
            receipt_id = _string(receipt_id, f"{context}.receipt_id")
        side = diagnostic["side"]
        if side is not None and side not in _SIDES:
            raise StageAInputError(f"{context}.side is invalid")
        binary_sha256 = diagnostic["binary_sha256"]
        if binary_sha256 is not None:
            binary_sha256 = _sha256(
                binary_sha256, f"{context}.binary_sha256"
            )
        rva = diagnostic["rva"]
        if rva is not None:
            rva = _integer(
                rva, f"{context}.rva", maximum=2**32 - 1
            )
        size = diagnostic["size"]
        if size is not None:
            size = _integer(
                size, f"{context}.size", minimum=1, maximum=15
            )
        encoded = diagnostic["bytes"]
        if encoded is not None and (
            not isinstance(encoded, str)
            or _HEX_RE.fullmatch(encoded) is None
            or (size is not None and len(encoded) != size * 2)
        ):
            raise StageAInputError(f"{context}.bytes is invalid")
        semantic_form = diagnostic["semantic_form"]
        if semantic_form is not None:
            semantic_form = _semantic_form(
                semantic_form, f"{context}.semantic_form"
            )
        diagnostics.append(
            {
                "code": code,
                "receipt_index": receipt_index,
                "receipt_id": receipt_id,
                "side": side,
                "binary_sha256": binary_sha256,
                "rva": rva,
                "size": size,
                "bytes": encoded,
                "semantic_form": semantic_form,
            }
        )
    if diagnostics != sorted(diagnostics, key=_diagnostic_sort_key):
        raise StageAInputError(
            "access-domain receipt diagnostics are not ordered"
        )
    counts = _object(
        payload["counts"], "access-domain receipt resolution counts"
    )
    _exact_fields(
        counts,
        _RESOLUTION_COUNT_FIELDS,
        "access-domain receipt resolution counts",
    )
    expected_counts = {
        "provided": _integer(
            counts["provided"],
            "access-domain receipt resolution counts.provided",
        ),
        "accepted": len(accepted),
        "rejected": _integer(
            counts["rejected"],
            "access-domain receipt resolution counts.rejected",
        ),
        "by_code": dict(Counter(row["code"] for row in diagnostics)),
    }
    expected_counts["by_code"] = {
        code: expected_counts["by_code"][code]
        for code in sorted(expected_counts["by_code"])
    }
    if dict(counts) != expected_counts:
        raise StageAInputError(
            "access-domain receipt resolution counts mismatch"
        )
    if expected_counts["rejected"] != max(
        expected_counts["provided"] - len(accepted), 0
    ):
        raise StageAInputError(
            "access-domain receipt resolution rejected count mismatch"
        )
    expected_status = (
        "absent"
        if input_sha256 is None
        and expected_counts["provided"] == 0
        and not accepted
        and not diagnostics
        else "applied"
        if accepted and not diagnostics
        else "partial"
        if accepted
        else "blocked"
    )
    if payload["status"] != expected_status:
        raise StageAInputError(
            "access-domain receipt resolution status mismatch"
        )
    return {
        "format": ACCESS_DOMAIN_RECEIPT_RESOLUTION_FORMAT,
        "dimension": ACCESS_DOMAIN_DIMENSION,
        "input_sha256": input_sha256,
        "status": payload["status"],
        "accepted_receipts": accepted,
        "diagnostics": diagnostics,
        "counts": expected_counts,
        "trust": dict(_RESOLUTION_TRUST),
    }


def _load_state_machine_rows(path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for line_number, line in enumerate(
        path.read_text(encoding="utf-8").splitlines(), start=1
    ):
        if not line:
            continue
        try:
            value = json.loads(line)
        except json.JSONDecodeError as exc:
            raise StageAInputError(
                f"state-machine line {line_number} is not JSON"
            ) from exc
        rows.append(
            dict(_object(value, f"state-machine line {line_number}"))
        )
    if not rows:
        raise StageAInputError("state-machine input is empty")
    return rows


def _typed_occurrence_index(
    original_isa: Mapping[str, Any],
) -> dict[int, dict[str, Any]]:
    if (
        original_isa.get("format") != "stage-a-relational-side-isa-v1"
        or original_isa.get("side") != "original"
    ):
        raise StageAInputError(
            "typed access/fault qualification requires original side ISA"
        )
    regions = original_isa.get("regions")
    if not isinstance(regions, list) or not regions:
        raise StageAInputError("original side ISA has no regions")
    by_rva: dict[int, dict[str, Any]] = {}
    for region_index, raw_region in enumerate(regions):
        region = _object(raw_region, f"original ISA region {region_index}")
        occurrences = region.get("occurrences")
        if not isinstance(occurrences, list):
            raise StageAInputError(
                f"original ISA region {region_index} has no occurrences"
            )
        for occurrence_index, raw_occurrence in enumerate(occurrences):
            context = (
                f"original ISA region {region_index} occurrence "
                f"{occurrence_index}"
            )
            occurrence = _object(raw_occurrence, context)
            rva = _integer(
                occurrence.get("rva"),
                f"{context}.rva",
                maximum=2**32 - 1,
            )
            size = _integer(
                occurrence.get("size"),
                f"{context}.size",
                minimum=1,
                maximum=15,
            )
            encoded = occurrence.get("bytes")
            if (
                not isinstance(encoded, str)
                or len(encoded) != size * 2
                or _HEX_RE.fullmatch(encoded) is None
            ):
                raise StageAInputError(f"{context}.bytes is invalid")
            form = _semantic_form(occurrence.get("form"), f"{context}.form")
            parsed = {
                "rva": rva,
                "size": size,
                "bytes": encoded,
                "form": form,
            }
            prior = by_rva.get(rva)
            if prior is not None and prior != parsed:
                raise StageAInputError(
                    f"original side ISA has ambiguous occurrence at RVA {rva}"
                )
            by_rva[rva] = parsed
    return by_rva


def _typed_region_span(row: Mapping[str, Any], region_id: int) -> tuple[int, int]:
    original = _object(
        row.get("original"), f"state-machine region {region_id}.original"
    )
    start = _integer(
        original.get("rva_start"),
        f"state-machine region {region_id}.original.rva_start",
        maximum=2**32 - 1,
    )
    end = _integer(
        original.get("rva_end"),
        f"state-machine region {region_id}.original.rva_end",
        maximum=2**32,
    )
    if end <= start:
        raise StageAInputError(
            f"state-machine region {region_id} has an empty span"
        )
    return start, end - start


def _typed_region_blocker(
    *,
    region_id: int,
    row: Mapping[str, Any],
    record_count: int,
    occurrence: Mapping[str, Any] | None,
) -> str | None:
    instructions = row.get("instructions")
    if not isinstance(instructions, list) or not instructions:
        return "missing_instruction_inventory"
    mnemonics = [
        str(instruction.get("mnemonic", "")).strip().lower()
        for instruction in instructions
        if isinstance(instruction, Mapping)
    ]
    faults = row.get("faults", [])
    if not isinstance(faults, list) or any(
        not isinstance(fault, Mapping)
        or fault.get("kind") != "divide_error"
        for fault in faults
    ):
        return "unsupported_fault_class"
    if occurrence is None:
        return "missing_exact_instruction_occurrence"
    if row.get("fpu_state") is not None:
        return None
    if region_id >= record_count:
        return "missing_checked_program_record"
    return None


def _lean_bytes(encoded: str) -> str:
    return "[" + ", ".join(
        str(value) for value in bytes.fromhex(encoded)
    ) + "]"


def _typed_term_prefix(region_id: int) -> str:
    return f"generatedGnuHelloAccessFaultRegion{region_id:04d}"


def _typed_access_fault_shard_source(
    *,
    authority_index: int,
    rows: Sequence[Mapping[str, Any]],
    certificate_pack_size: int,
) -> str:
    module_suffix = f"{authority_index:04d}"
    imports = [
        "import StageA.RelationalAccessFaultQualification",
        (
            "import "
            "StageA.GeneratedRelationalInterpreterMixedOriginalBaseContextData"
        ),
    ]
    if any(row["qualification_kind"] == "ordinary" for row in rows):
        imports.append(
            "import "
            f"StageA.GeneratedInterpreterKernelDataAuthorityPack{module_suffix}"
        )
    lines = imports + [
        "",
        (
            "namespace "
            "StageA.GeneratedRelational.GnuHelloAccessFaultQualification"
            f".Shard{module_suffix}"
        ),
        "",
        "open StageA.Formal StageA.Relational",
        "open StageA.Relational.Interpreter",
        "open StageA.Relational.InterpreterKernelData",
        "open StageA.Relational.InterpreterTransfer",
        "open StageA.Relational.InterpreterX87",
        "open StageA.Relational.AccessFaultQualification",
        (
            "open "
            "StageA.GeneratedRelational.InterpreterKernelData"
        ),
        (
            "open "
            "StageA.GeneratedRelational.InterpreterMixedOriginalBase"
        ),
        "",
        "set_option maxRecDepth 1000000",
        "set_option maxHeartbeats 0",
        "set_option compiler.extract_closed false",
        "set_option Elab.async false",
        "",
    ]
    for row in rows:
        region_id = int(row["region_id"])
        start = int(row["rva"])
        size = int(row["region_size"])
        occurrence = row["occurrence"]
        prefix = _typed_term_prefix(region_id)
        certificate_pack = region_id // certificate_pack_size
        entry = region_id % certificate_pack_size
        data = (
            "generatedInterpreterKernelDataCertificatePack"
            f"{certificate_pack:04d}Entry{entry:04d}Data"
        )
        fallback = (
            "{ id := "
            f"{region_id}, original := {{ start := {start}, size := {size} }}, "
            f"candidate := {{ start := {start}, size := {size} }}, "
            "root := false, inputs := [], outputs := [], "
            "inputRelations := [], bounds := [], addressSeparations := [], "
            "targets := [] }"
        )
        lines.extend([
            f"def {prefix}Region : RegionRelation :=",
            (
                "  (generatedOriginalCarrierRegionIndex.get? "
                f"{region_id}).getD {fallback}"
            ),
            "",
            f"theorem {prefix}RegionLookupExact :",
            (
                "    generatedOriginalCarrierRegionIndex.get? "
                f"{region_id} = some {prefix}Region := by"
            ),
            "  decide +kernel",
            "",
        ])
        if row["qualification_kind"] == "x87":
            lines.extend(
                [
                    (
                        f"noncomputable def {prefix}Certificate : "
                        "X87AccessFaultFormCertificate := {"
                    ),
                    "  occurrence := {",
                    f"    offset := {occurrence['rva']}",
                    f"    size := {occurrence['size']}",
                    f"    bytes := {_lean_bytes(str(occurrence['bytes']))}",
                    f"    form := {occurrence['form']}",
                    "  }",
                    "}",
                    "",
                    f"theorem {prefix}CertificateChecked :",
                    (
                        f"    {prefix}Certificate.checked .original "
                        "generatedOriginalCarrierContext "
                        f"{prefix}Region = true := by"
                    ),
                    "  decide +kernel",
                    "",
                    f"def {prefix}StateAdmissible",
                    (
                        "    (world : RelationalWorld) "
                        "(state : MachineState) : Prop :="
                    ),
                    "  forall result,",
                    (
                        "    executeX87Singleton "
                        "generatedOriginalCarrierContext.originalPe "
                        f"{prefix}Certificate.record state = some result ->"
                    ),
                    (
                        "      x87TransitionAccessFaultChecked "
                        f"{prefix}Certificate .original "
                        "generatedOriginalCarrierContext world result = true"
                    ),
                    "",
                    f"noncomputable def {prefix}Qualification",
                    (
                        "    (world : RelationalWorld) : "
                        "TypedX87AccessFaultQualification"
                    ),
                    f"      ({prefix}StateAdmissible world)",
                    (
                        f"      {prefix}Certificate .original "
                        "generatedOriginalCarrierContext world "
                        f"{prefix}Region := {{"
                    ),
                    f"  decodedChecked := {prefix}CertificateChecked",
                    "  transitionsChecked := by",
                    "    intro state result admissible executed",
                    "    exact admissible result executed",
                    "}",
                    "",
                ]
            )
        else:
            lines.extend(
                [
                f"noncomputable def {prefix}Record : ProgramRecord :=",
                f"  {data}.compiled.record",
                "",
                f"noncomputable def {prefix}Transfer : SemanticTransfer :=",
                f"  checkedSemanticTransfer {prefix}Record",
                "",
                (
                    f"noncomputable def {prefix}Certificate : "
                    "AccessFaultFormCertificate := {"
                ),
                "  occurrence := {",
                f"    offset := {occurrence['rva']}",
                f"    size := {occurrence['size']}",
                f"    bytes := {_lean_bytes(str(occurrence['bytes']))}",
                f"    form := {occurrence['form']}",
                "  }",
                (
                    "  footprint := orderedFlatMemoryFootprint "
                    f"{prefix}Transfer"
                ),
                (
                    "  permittedFaults := permittedFaultClasses "
                    f"{prefix}Transfer"
                ),
                "}",
                "",
                f"theorem {prefix}CertificateChecked :",
                (
                    f"    {prefix}Certificate.checked .original "
                    "generatedOriginalCarrierContext "
                    f"{prefix}Region {prefix}Record {prefix}Transfer = true := by"
                ),
                "  decide +kernel",
                "",
                f"def {prefix}StateAdmissible",
                (
                    "    (world : RelationalWorld) "
                    "(environment : Environment)"
                ),
                "    (state : InterpreterMachine) : Prop :=",
                "  forall result,",
                (
                    f"    {prefix}Transfer.execute environment state = "
                    "some result ->"
                ),
                (
                    "      transitionAccessFaultChecked "
                    f"{prefix}Certificate .original "
                    "generatedOriginalCarrierContext world result = true"
                ),
                "",
                f"noncomputable def {prefix}Qualification",
                (
                    "    (world : RelationalWorld) : "
                    "TypedAccessFaultQualification"
                ),
                f"      ({prefix}StateAdmissible world)",
                (
                    f"      {prefix}Certificate .original "
                    "generatedOriginalCarrierContext world"
                ),
                (
                    f"      {prefix}Region {prefix}Record "
                    f"{prefix}Transfer := {{"
                ),
                f"  decodedChecked := {prefix}CertificateChecked",
                "  transitionsChecked := by",
                "    intro environment state result admissible executed",
                "    exact admissible result executed",
                "}",
                "",
                ]
            )
    lines.extend(
        [
            (
                "end "
                "StageA.GeneratedRelational.GnuHelloAccessFaultQualification"
                f".Shard{module_suffix}"
            ),
            "",
        ]
    )
    return "\n".join(lines)


def generate_typed_access_fault_qualification(
    *,
    original_isa: Mapping[str, Any],
    state_machine_rows: Sequence[Mapping[str, Any]],
    reachability_plan: Mapping[str, Any],
    kernel_data_inventory: Mapping[str, Any],
    out: Path,
    certificate_pack_size: int = 8,
) -> dict[str, Any]:
    """Emit deterministic GNU typed access/fault qualification shards.

    Each emitted qualification is canonical at the static boundary and leaves
    one explicit dynamic premise: states admitted at that reachable region
    must make every concrete access belong to the modeled PE/runtime world and
    must produce only the certificate's checked fault classes.
    """

    if certificate_pack_size <= 0:
        raise StageAInputError("certificate pack size must be positive")
    occurrences = _typed_occurrence_index(original_isa)
    rows = [dict(_object(row, f"state-machine region {index}"))
            for index, row in enumerate(state_machine_rows)]
    if reachability_plan.get("format") not in {
        "stage-a-relational-interpreter-mixed-original-base-plan-v1",
        "stage-a-interpreter-mixed-original-base-plan-v1",
        "stage-a-interpreter-mixed-original-v1",
    }:
        raise StageAInputError(
            "typed access/fault qualification reachability plan is invalid"
        )
    raw_reachable = reachability_plan.get("reachable_target_ids")
    if not isinstance(raw_reachable, list):
        raise StageAInputError("reachability plan has no reachable target IDs")
    reachable = [
        _integer(
            value,
            f"reachable target ID {index}",
            maximum=2**32 - 1,
        )
        for index, value in enumerate(raw_reachable)
    ]
    if reachable != sorted(set(reachable)):
        raise StageAInputError(
            "reachable target IDs must be unique and ordered"
        )
    if kernel_data_inventory.get("format") != (
        "stage-a-interpreter-kernel-data-inventory-v7"
    ):
        raise StageAInputError("kernel-data inventory format is invalid")
    counts = _object(
        kernel_data_inventory.get("counts"), "kernel-data inventory counts"
    )
    record_count = _integer(
        counts.get("records"), "kernel-data inventory record count", minimum=1
    )
    certificate_pack_count = _integer(
        counts.get("certificate_packs"),
        "kernel-data inventory certificate-pack count",
        minimum=1,
    )
    if (
        record_count + certificate_pack_size - 1
    ) // certificate_pack_size != certificate_pack_count:
        raise StageAInputError(
            "kernel-data certificate-pack geometry is incompatible"
        )
    authority_transfer_limit = _integer(
        kernel_data_inventory.get("authority_transfer_limit"),
        "kernel-data authority transfer limit",
        minimum=certificate_pack_size,
    )
    if authority_transfer_limit % certificate_pack_size != 0:
        raise StageAInputError(
            "kernel-data authority geometry is incompatible"
        )
    binary_sha256 = _sha256(
        original_isa.get("binary_sha256"), "original ISA binary SHA-256"
    )

    qualified: list[dict[str, Any]] = []
    blockers: list[dict[str, Any]] = []
    by_reason: Counter[str] = Counter()
    for region_id in reachable:
        if region_id >= len(rows):
            reason = "missing_state_machine_region"
            blockers.append(
                {
                    "region_id": region_id,
                    "rva": None,
                    "reason": reason,
                }
            )
            by_reason[reason] += 1
            continue
        row = rows[region_id]
        rva, region_size = _typed_region_span(row, region_id)
        occurrence = occurrences.get(rva)
        reason = _typed_region_blocker(
            region_id=region_id,
            row=row,
            record_count=record_count,
            occurrence=occurrence,
        )
        if reason is not None:
            blockers.append(
                {
                    "region_id": region_id,
                    "rva": rva,
                    "reason": reason,
                }
            )
            by_reason[reason] += 1
            continue
        assert occurrence is not None
        authority_index = region_id // authority_transfer_limit
        prefix = _typed_term_prefix(region_id)
        qualification_kind = (
            "x87" if row.get("fpu_state") is not None else "ordinary"
        )
        qualified.append(
            {
                "region_id": region_id,
                "rva": rva,
                "region_size": region_size,
                "authority_index": authority_index,
                "qualification_kind": qualification_kind,
                "occurrence": occurrence,
                "certificate_symbol": f"{prefix}Certificate",
                "qualification_symbol": f"{prefix}Qualification",
                "region_lookup_symbol": f"{prefix}RegionLookupExact",
                "state_admissible_symbol": f"{prefix}StateAdmissible",
                "remaining_premise": (
                    "prove the canonical reachable-state invariant implies "
                    f"{prefix}StateAdmissible for every relational world "
                    f"under the {qualification_kind} checked executor"
                ),
            }
        )

    grouped: dict[int, list[dict[str, Any]]] = {}
    for row in qualified:
        grouped.setdefault(int(row["authority_index"]), []).append(row)
    stage_a = out / "StageA"
    stage_a.mkdir(parents=True, exist_ok=True)
    shards: list[dict[str, Any]] = []
    resources: dict[str, dict[str, Any]] = {}
    targets: list[str] = []
    for authority_index, shard_rows in sorted(grouped.items()):
        module = (
            "GeneratedGnuHelloAccessFaultQualificationShard"
            f"{authority_index:04d}"
        )
        source = _typed_access_fault_shard_source(
            authority_index=authority_index,
            rows=shard_rows,
            certificate_pack_size=certificate_pack_size,
        )
        source_path = stage_a / f"{module}.lean"
        source_path.write_text(source, encoding="utf-8")
        targets.append(module)
        resources[module] = {
            "resource_class": "medium",
            "estimated_memory_mb": 3072,
        }
        shards.append(
            {
                "authority_index": authority_index,
                "module": module,
                "region_ids": [
                    int(row["region_id"]) for row in shard_rows
                ],
                "source_sha256": hashlib.sha256(
                    source.encode("utf-8")
                ).hexdigest(),
            }
        )

    artifact_body = {
        "format": TYPED_ACCESS_FAULT_QUALIFICATION_FORMAT,
        "status": (
            "source-ready-with-frontiers" if qualified else "blocked"
        ),
        "side": "original",
        "binary_sha256": binary_sha256,
        "certificate_pack_size": certificate_pack_size,
        "authority_transfer_limit": authority_transfer_limit,
        "qualified_regions": qualified,
        "blockers": blockers,
        "shards": shards,
        "counts": {
            "reachable_regions": len(reachable),
            "typed_qualification_regions": len(qualified),
            "remaining_state_admissibility_premises": len(qualified),
            "blocked_regions": len(blockers),
            "shards": len(shards),
            "by_qualification_kind": dict(
                sorted(
                    Counter(
                        str(row["qualification_kind"]) for row in qualified
                    ).items()
                )
            ),
            "by_blocker_reason": dict(sorted(by_reason.items())),
        },
        "trust": dict(_TYPED_QUALIFICATION_TRUST),
    }
    artifact = {
        **artifact_body,
        "artifact_sha256": _canonical_sha256(
            artifact_body, "typed access/fault qualification artifact"
        ),
    }
    manifest = {
        "format": TYPED_ACCESS_FAULT_QUALIFICATION_MANIFEST_FORMAT,
        "phase": "typed-access-fault-qualification",
        "status": artifact["status"],
        "proof_authority": False,
        "executes_original_binary": False,
        "executes_candidate_binary": False,
        "targets": targets,
        "counts": artifact["counts"],
        "remaining_premises": [
            {
                "region_id": row["region_id"],
                "rva": row["rva"],
                "state_admissible_symbol": row["state_admissible_symbol"],
                "requirement": row["remaining_premise"],
            }
            for row in qualified
        ],
        "blockers": blockers,
        "public_outputs": {
            "artifact": "typed-access-fault-qualification.json",
            "lean_sources": "StageA/",
            "module_resources": "module-resources.json",
        },
        "trust": dict(_TYPED_QUALIFICATION_TRUST),
    }
    (out / "typed-access-fault-qualification.json").write_text(
        json.dumps(artifact, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    (out / "phase-manifest.json").write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    (out / "module-resources.json").write_text(
        json.dumps(resources, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    (out / "proof-targets.json").write_text(
        json.dumps(targets, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return artifact


__all__ = [
    "ACCESS_DOMAIN_DIMENSION",
    "ACCESS_DOMAIN_RECEIPTS_FORMAT",
    "ACCESS_DOMAIN_RECEIPT_PROPOSALS_FORMAT",
    "ACCESS_DOMAIN_RECEIPT_RESOLUTION_FORMAT",
    "APPROVED_ACCESS_DOMAIN_AXIOMS",
    "TYPED_ACCESS_FAULT_QUALIFICATION_FORMAT",
    "TYPED_ACCESS_FAULT_QUALIFICATION_MANIFEST_FORMAT",
    "access_domain_occurrence_key",
    "access_domain_receipt_proposals_payload",
    "access_domain_receipts_payload",
    "build_access_domain_kernel_check_requests",
    "create_access_domain_receipts",
    "generate_typed_access_fault_qualification",
    "_load_state_machine_rows",
    "parse_access_domain_receipt",
    "parse_access_domain_receipt_resolution",
    "resolve_access_domain_receipts",
]
