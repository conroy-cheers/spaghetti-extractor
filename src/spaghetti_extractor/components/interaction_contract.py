"""Reusable, target-neutral contracts for checked boundary interactions.

Interaction contracts describe only portable ports and provider assumptions.
They never name machine places or provide executable evaluator code.  A target
selects one reviewed contract; specialization then rewrites abstract ``port``
references to one exact interaction site in Relation IR.
"""

from __future__ import annotations

import copy
import re
from dataclasses import dataclass
from typing import Mapping, Sequence

from ..artifacts.artifact_set import canonical_sha256_v3
from .formats import (
    INTERACTION_CONTRACT_CATALOG_V1_FORMAT,
    INTERACTION_CONTRACT_RECEIPT_V1_FORMAT,
    INTERACTION_CONTRACT_V1_FORMAT,
)
from .interface_ir import ProofKernelLogicalType


_ID = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9_.:-]*[A-Za-z0-9])?\Z")
_DIGEST = re.compile(r"[0-9a-f]{64}\Z")
_DIRECTIONS = frozenset({"input", "output"})
_TYPE_KINDS = frozenset(
    {"scalar", "enum", "record", "reference", "view", "resource", "callback"}
)
_EXPRESSION_OPS = frozenset(
    {
        "port",
        "true",
        "false",
        "const",
        "not",
        "and",
        "or",
        "eq",
        "ult",
        "ule",
        "ref_is_null",
        "same_origin",
        "borrowed_interior",
        "ref_offset",
        "ref_remaining",
        "view_extent",
    }
)


class InteractionContractError(ValueError):
    """A reusable interaction contract is malformed or cannot specialize."""


def _object(value: object, context: str) -> Mapping[str, object]:
    if not isinstance(value, Mapping):
        raise InteractionContractError(f"{context} must be an object")
    return value


def _array(value: object, context: str) -> Sequence[object]:
    if not isinstance(value, list):
        raise InteractionContractError(f"{context} must be an array")
    return value


def _exact(value: Mapping[str, object], fields: set[str], context: str) -> None:
    if set(value) != fields:
        raise InteractionContractError(
            f"{context} fields differ: missing={sorted(fields-set(value))!r}, "
            f"extra={sorted(set(value)-fields)!r}"
        )


def _text(value: object, context: str) -> str:
    if not isinstance(value, str) or not value:
        raise InteractionContractError(f"{context} must be a nonempty string")
    return value


def _identifier(value: object, context: str) -> str:
    result = _text(value, context)
    if _ID.fullmatch(result) is None:
        raise InteractionContractError(f"{context} is not canonical")
    return result


def _uint(value: object, context: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise InteractionContractError(f"{context} must be an unsigned integer")
    return value


@dataclass(frozen=True)
class InteractionTypeParameterV1:
    identity: str
    kind: str
    width: int | None
    element_width: int | None
    access: str | None
    nullable: bool | None
    nul_terminated: bool | None

    @classmethod
    def parse(cls, value: object, context: str) -> "InteractionTypeParameterV1":
        row = _object(value, context)
        _exact(
            row,
            {"id", "kind", "width", "element_width", "access", "nullable", "nul_terminated"},
            context,
        )
        kind = _text(row["kind"], f"{context} kind")
        if kind not in _TYPE_KINDS:
            raise InteractionContractError(f"{context} kind is unsupported")
        width = None if row["width"] is None else _uint(row["width"], f"{context} width")
        element_width = (
            None
            if row["element_width"] is None
            else _uint(row["element_width"], f"{context} element width")
        )
        access = None if row["access"] is None else _text(row["access"], f"{context} access")
        nullable = row["nullable"]
        nul_terminated = row["nul_terminated"]
        if nullable is not None and not isinstance(nullable, bool):
            raise InteractionContractError(f"{context} nullable must be Boolean or null")
        if nul_terminated is not None and not isinstance(nul_terminated, bool):
            raise InteractionContractError(f"{context} nul_terminated must be Boolean or null")
        if kind in {"scalar", "enum"} and width not in {8, 16, 32, 64}:
            raise InteractionContractError(f"{context} scalar width is unsupported")
        if kind not in {"scalar", "enum"} and width is not None:
            raise InteractionContractError(f"{context} non-scalar cannot declare width")
        if kind not in {"reference", "view"} and element_width is not None:
            raise InteractionContractError(f"{context} element width is inapplicable")
        if kind != "reference" and nullable is not None:
            raise InteractionContractError(f"{context} nullability is inapplicable")
        if kind != "view" and nul_terminated is not None:
            raise InteractionContractError(f"{context} termination is inapplicable")
        return cls(
            _identifier(row["id"], f"{context} id"),
            kind,
            width,
            element_width,
            access,
            nullable,
            nul_terminated,
        )

    def to_payload(self) -> dict[str, object]:
        return {
            "id": self.identity,
            "kind": self.kind,
            "width": self.width,
            "element_width": self.element_width,
            "access": self.access,
            "nullable": self.nullable,
            "nul_terminated": self.nul_terminated,
        }


@dataclass(frozen=True)
class InteractionContractPortV1:
    identity: str
    direction: str
    type_parameter: str

    @classmethod
    def parse(cls, value: object, context: str) -> "InteractionContractPortV1":
        row = _object(value, context)
        _exact(row, {"id", "direction", "type_parameter"}, context)
        direction = _text(row["direction"], f"{context} direction")
        if direction not in _DIRECTIONS:
            raise InteractionContractError(f"{context} direction is unsupported")
        return cls(
            _identifier(row["id"], f"{context} id"),
            direction,
            _identifier(row["type_parameter"], f"{context} type parameter"),
        )

    @property
    def key(self) -> tuple[str, str]:
        return self.direction, self.identity

    def to_payload(self) -> dict[str, object]:
        return {
            "id": self.identity,
            "direction": self.direction,
            "type_parameter": self.type_parameter,
        }


def _validate_contract_expression(
    value: object,
    *,
    ports: set[tuple[str, str]],
    context: str,
) -> Mapping[str, object]:
    row = _object(value, context)
    op = _text(row.get("op"), f"{context} operation")
    if op not in _EXPRESSION_OPS:
        raise InteractionContractError(f"{context} operation {op!r} is unsupported")
    if op == "port":
        _exact(row, {"op", "direction", "id"}, context)
        direction = _text(row["direction"], f"{context} direction")
        identity = _identifier(row["id"], f"{context} port id")
        if (direction, identity) not in ports:
            raise InteractionContractError(f"{context} references an unknown port")
        return copy.deepcopy(dict(row))
    if op in {"true", "false"}:
        _exact(row, {"op"}, context)
        return {"op": op}
    if op == "const":
        _exact(row, {"op", "value", "width"}, context)
        width = _uint(row["width"], f"{context} width")
        constant = _uint(row["value"], f"{context} value")
        if width not in {8, 16, 32, 64} or constant >= 1 << width:
            raise InteractionContractError(f"{context} constant is outside its width")
        return {"op": op, "value": constant, "width": width}
    _exact(row, {"op", "args"}, context)
    arguments = [
        _validate_contract_expression(
            item, ports=ports, context=f"{context} argument {index}"
        )
        for index, item in enumerate(_array(row["args"], f"{context} arguments"))
    ]
    arity = {
        "not": 1,
        "ref_is_null": 1,
        "ref_offset": 1,
        "ref_remaining": 1,
        "view_extent": 1,
        "and": 2,
        "or": 2,
        "eq": 2,
        "ult": 2,
        "ule": 2,
        "same_origin": 2,
        "borrowed_interior": 2,
    }[op]
    if len(arguments) != arity:
        raise InteractionContractError(f"{context} has the wrong arity")
    return {"op": op, "args": arguments}


@dataclass(frozen=True)
class InteractionContractV1:
    identity: str
    subject: Mapping[str, object]
    primitive_id: str
    type_parameters: tuple[InteractionTypeParameterV1, ...]
    ports: tuple[InteractionContractPortV1, ...]
    requires: tuple[Mapping[str, object], ...]
    ensures: tuple[Mapping[str, object], ...]
    effects: tuple[Mapping[str, object], ...]
    provenance: Mapping[str, object]
    contract_sha256: str

    @classmethod
    def parse(cls, value: object) -> "InteractionContractV1":
        row = _object(value, "interaction contract")
        _exact(
            row,
            {
                "format",
                "id",
                "subject",
                "primitive_id",
                "type_parameters",
                "ports",
                "requires",
                "ensures",
                "effects",
                "provenance",
                "contract_sha256",
            },
            "interaction contract",
        )
        if row["format"] != INTERACTION_CONTRACT_V1_FORMAT:
            raise InteractionContractError("unsupported interaction contract format")
        subject = copy.deepcopy(dict(_object(row["subject"], "interaction subject")))
        if not subject:
            raise InteractionContractError("interaction subject must be nonempty")
        type_parameters = tuple(
            InteractionTypeParameterV1.parse(item, f"interaction type parameter {index}")
            for index, item in enumerate(
                _array(row["type_parameters"], "interaction type parameters")
            )
        )
        type_ids = [item.identity for item in type_parameters]
        # A void(void) interaction can still have effects and outcomes. Its
        # empty value boundary needs no invented argument or result type.
        if type_ids != sorted(set(type_ids)):
            raise InteractionContractError(
                "interaction type parameters must be unique and ordered"
            )
        ports = tuple(
            InteractionContractPortV1.parse(item, f"interaction port {index}")
            for index, item in enumerate(_array(row["ports"], "interaction ports"))
        )
        port_keys = [item.key for item in ports]
        if port_keys != sorted(set(port_keys)):
            raise InteractionContractError(
                "interaction ports must be unique and ordered"
            )
        if any(item.type_parameter not in set(type_ids) for item in ports):
            raise InteractionContractError("interaction port has an unknown type parameter")
        port_set = set(port_keys)
        requires = tuple(
            _validate_contract_expression(
                item, ports=port_set, context=f"interaction requirement {index}"
            )
            for index, item in enumerate(_array(row["requires"], "interaction requirements"))
        )
        ensures = tuple(
            _validate_contract_expression(
                item, ports=port_set, context=f"interaction guarantee {index}"
            )
            for index, item in enumerate(_array(row["ensures"], "interaction guarantees"))
        )
        effects = tuple(
            copy.deepcopy(dict(_object(item, f"interaction effect {index}")))
            for index, item in enumerate(_array(row["effects"], "interaction effects"))
        )
        for index, effect in enumerate(effects):
            _exact(effect, {"primitive", "arguments", "result"}, f"interaction effect {index}")
            _identifier(effect["primitive"], f"interaction effect {index} primitive")
            _array(effect["arguments"], f"interaction effect {index} arguments")
        provenance = copy.deepcopy(
            dict(_object(row["provenance"], "interaction contract provenance"))
        )
        _exact(provenance, {"kind", "source", "reviewed"}, "interaction contract provenance")
        _text(provenance["kind"], "interaction provenance kind")
        _text(provenance["source"], "interaction provenance source")
        if not isinstance(provenance["reviewed"], bool):
            raise InteractionContractError("interaction provenance reviewed flag is invalid")
        core = {key: copy.deepcopy(item) for key, item in row.items() if key != "contract_sha256"}
        digest = _text(row["contract_sha256"], "interaction contract digest")
        if _DIGEST.fullmatch(digest) is None or canonical_sha256_v3(core) != digest:
            raise InteractionContractError("interaction contract digest is stale")
        return cls(
            _identifier(row["id"], "interaction contract id"),
            subject,
            _identifier(row["primitive_id"], "interaction primitive id"),
            type_parameters,
            ports,
            requires,
            ensures,
            effects,
            provenance,
            digest,
        )

    @classmethod
    def create(
        cls,
        *,
        identity: str,
        subject: Mapping[str, object],
        primitive_id: str,
        type_parameters: Sequence[Mapping[str, object]],
        ports: Sequence[Mapping[str, object]],
        requires: Sequence[Mapping[str, object]] = (),
        ensures: Sequence[Mapping[str, object]] = (),
        effects: Sequence[Mapping[str, object]] = (),
        provenance: Mapping[str, object],
    ) -> "InteractionContractV1":
        core = {
            "format": INTERACTION_CONTRACT_V1_FORMAT,
            "id": identity,
            "subject": copy.deepcopy(dict(subject)),
            "primitive_id": primitive_id,
            "type_parameters": [copy.deepcopy(dict(item)) for item in type_parameters],
            "ports": [copy.deepcopy(dict(item)) for item in ports],
            "requires": [copy.deepcopy(dict(item)) for item in requires],
            "ensures": [copy.deepcopy(dict(item)) for item in ensures],
            "effects": [copy.deepcopy(dict(item)) for item in effects],
            "provenance": copy.deepcopy(dict(provenance)),
        }
        return cls.parse({**core, "contract_sha256": canonical_sha256_v3(core)})

    def to_payload(self) -> dict[str, object]:
        return {
            "format": INTERACTION_CONTRACT_V1_FORMAT,
            "id": self.identity,
            "subject": copy.deepcopy(dict(self.subject)),
            "primitive_id": self.primitive_id,
            "type_parameters": [item.to_payload() for item in self.type_parameters],
            "ports": [item.to_payload() for item in self.ports],
            "requires": [copy.deepcopy(dict(item)) for item in self.requires],
            "ensures": [copy.deepcopy(dict(item)) for item in self.ensures],
            "effects": [copy.deepcopy(dict(item)) for item in self.effects],
            "provenance": copy.deepcopy(dict(self.provenance)),
            "contract_sha256": self.contract_sha256,
        }


@dataclass(frozen=True)
class InteractionContractCatalogV1:
    contracts: tuple[InteractionContractV1, ...]
    catalog_sha256: str

    @classmethod
    def parse(cls, value: object) -> "InteractionContractCatalogV1":
        row = _object(value, "interaction contract catalog")
        _exact(row, {"format", "contracts", "catalog_sha256"}, "interaction contract catalog")
        if row["format"] != INTERACTION_CONTRACT_CATALOG_V1_FORMAT:
            raise InteractionContractError("unsupported interaction contract catalog format")
        contracts = tuple(
            InteractionContractV1.parse(item)
            for item in _array(row["contracts"], "interaction contracts")
        )
        identities = [item.identity for item in contracts]
        if not contracts or identities != sorted(set(identities)):
            raise InteractionContractError(
                "interaction contracts must be nonempty, unique, and ordered"
            )
        core = {"format": INTERACTION_CONTRACT_CATALOG_V1_FORMAT, "contracts": [item.to_payload() for item in contracts]}
        digest = _text(row["catalog_sha256"], "interaction catalog digest")
        if _DIGEST.fullmatch(digest) is None or canonical_sha256_v3(core) != digest:
            raise InteractionContractError("interaction contract catalog digest is stale")
        return cls(contracts, digest)

    @classmethod
    def create(cls, contracts: Sequence[InteractionContractV1]) -> "InteractionContractCatalogV1":
        ordered = sorted(contracts, key=lambda item: item.identity)
        core = {
            "format": INTERACTION_CONTRACT_CATALOG_V1_FORMAT,
            "contracts": [item.to_payload() for item in ordered],
        }
        return cls.parse({**core, "catalog_sha256": canonical_sha256_v3(core)})

    def to_payload(self) -> dict[str, object]:
        return {
            "format": INTERACTION_CONTRACT_CATALOG_V1_FORMAT,
            "contracts": [item.to_payload() for item in self.contracts],
            "catalog_sha256": self.catalog_sha256,
        }

    def contract(self, identity: str) -> InteractionContractV1:
        matches = [item for item in self.contracts if item.identity == identity]
        if len(matches) != 1:
            raise InteractionContractError(f"interaction contract {identity!r} is unavailable")
        return matches[0]


@dataclass(frozen=True)
class InteractionContractReceiptV1:
    contract_id: str
    contract_sha256: str
    status: str
    receipt_sha256: str

    @classmethod
    def create(cls, contract: InteractionContractV1) -> "InteractionContractReceiptV1":
        status = "checked" if contract.provenance.get("reviewed") is True else "incomplete"
        core = {
            "format": INTERACTION_CONTRACT_RECEIPT_V1_FORMAT,
            "contract_id": contract.identity,
            "contract_sha256": contract.contract_sha256,
            "status": status,
            "code": "reviewed_reusable_contract" if status == "checked" else "contract_review_missing",
        }
        return cls(
            contract.identity,
            contract.contract_sha256,
            status,
            canonical_sha256_v3(core),
        )

    @property
    def authorizing(self) -> bool:
        return self.status == "checked"

    def to_payload(self) -> dict[str, object]:
        core = {
            "format": INTERACTION_CONTRACT_RECEIPT_V1_FORMAT,
            "contract_id": self.contract_id,
            "contract_sha256": self.contract_sha256,
            "status": self.status,
            "code": "reviewed_reusable_contract" if self.authorizing else "contract_review_missing",
        }
        return {**core, "receipt_sha256": self.receipt_sha256}


def logical_type_width(
    logical_type: ProofKernelLogicalType,
    types: Mapping[str, ProofKernelLogicalType],
) -> int | None:
    if logical_type.kind not in {"scalar", "enum"} or logical_type.c_type is None:
        return None
    return int(
        logical_type.c_type.removeprefix("uint")
        .removeprefix("int")
        .removesuffix("_t")
    )


def contract_type_matches(
    pattern: InteractionTypeParameterV1,
    logical_type: ProofKernelLogicalType,
    types: Mapping[str, ProofKernelLogicalType],
) -> bool:
    if pattern.kind != logical_type.kind:
        return False
    if pattern.width is not None and logical_type_width(logical_type, types) != pattern.width:
        return False
    if pattern.element_width is not None:
        element = types.get(str(logical_type.element_type_id))
        if element is None or logical_type_width(element, types) != pattern.element_width:
            return False
    if pattern.access is not None and logical_type.access != pattern.access:
        return False
    if pattern.nullable is not None and logical_type.nullable != pattern.nullable:
        return False
    if pattern.nul_terminated is not None and logical_type.nul_terminated != pattern.nul_terminated:
        return False
    return True


__all__ = [
    "InteractionContractCatalogV1",
    "InteractionContractError",
    "InteractionContractPortV1",
    "InteractionContractReceiptV1",
    "InteractionContractV1",
    "InteractionTypeParameterV1",
    "contract_type_matches",
    "logical_type_width",
]
