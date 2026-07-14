from __future__ import annotations

from dataclasses import dataclass
from types import MappingProxyType
from typing import Any, Mapping

from .schema import RELATIONAL_PROOF_IR_FORMAT, SchemaError, integer


def _object(value: Any, field: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise SchemaError(f"{field} must be an object")
    return value


def _objects(value: Any, field: str) -> tuple[Mapping[str, Any], ...]:
    if not isinstance(value, list) or any(not isinstance(item, Mapping) for item in value):
        raise SchemaError(f"{field} must be a list of objects")
    return tuple(value)


def _string(value: Any, field: str) -> str:
    if not isinstance(value, str) or not value:
        raise SchemaError(f"{field} must be a non-empty string")
    return value


@dataclass(frozen=True)
class ProofFamily:
    family: str
    status: str

    @classmethod
    def parse(cls, payload: Mapping[str, Any]) -> "ProofFamily":
        return cls(
            family=_string(payload.get("family"), "families[].family"),
            status=_string(payload.get("status"), "families[].status"),
        )


@dataclass(frozen=True)
class ProofObligation:
    id: str
    kind: str
    status: str

    @classmethod
    def parse(cls, payload: Mapping[str, Any]) -> "ProofObligation":
        return cls(
            id=_string(payload.get("id"), "obligations[].id"),
            kind=_string(payload.get("kind"), "obligations[].kind"),
            status=_string(payload.get("status"), "obligations[].status"),
        )


@dataclass(frozen=True)
class RelationalProofIR:
    format: str
    model: str
    profile: str
    status: str
    families: tuple[ProofFamily, ...]
    obligations: tuple[ProofObligation, ...]
    raw: Mapping[str, Any]

    @classmethod
    def parse(cls, payload: Mapping[str, Any]) -> "RelationalProofIR":
        format_id = _string(payload.get("format"), "format")
        if format_id != RELATIONAL_PROOF_IR_FORMAT:
            raise SchemaError(f"unexpected relational proof IR format: {format_id}")
        families = tuple(
            ProofFamily.parse(item) for item in _objects(payload.get("families"), "families")
        )
        obligations = tuple(
            ProofObligation.parse(item)
            for item in _objects(payload.get("obligations"), "obligations")
        )
        family_names = [family.family for family in families]
        obligation_ids = [obligation.id for obligation in obligations]
        if len(family_names) != len(set(family_names)):
            raise SchemaError("proof family names must be unique")
        if len(obligation_ids) != len(set(obligation_ids)):
            raise SchemaError("proof obligation ids must be unique")
        return cls(
            format=format_id,
            model=_string(payload.get("model"), "model"),
            profile=_string(payload.get("profile"), "profile"),
            status=_string(payload.get("status"), "status"),
            families=families,
            obligations=obligations,
            raw=MappingProxyType(dict(payload)),
        )


@dataclass(frozen=True)
class ProductGraphIR:
    format: str
    model: str
    status: str
    node_ids: tuple[int, ...]
    edge_ids: tuple[int, ...]
    root_node_ids: tuple[int, ...]
    raw: Mapping[str, Any]

    @classmethod
    def parse(cls, payload: Mapping[str, Any]) -> "ProductGraphIR":
        nodes = _objects(payload.get("nodes"), "nodes")
        edges = _objects(payload.get("edges"), "edges")

        def ids(rows: tuple[Mapping[str, Any], ...], field: str) -> tuple[int, ...]:
            parsed = tuple(integer(row.get("id")) for row in rows)
            if any(item is None or item < 0 for item in parsed):
                raise SchemaError(f"{field}[].id must be a non-negative integer")
            result = tuple(int(item) for item in parsed)
            if len(result) != len(set(result)):
                raise SchemaError(f"{field} ids must be unique")
            return result

        roots_value = payload.get("root_node_ids")
        if not isinstance(roots_value, list):
            raise SchemaError("root_node_ids must be a list")
        roots = tuple(integer(item) for item in roots_value)
        if any(item is None or item < 0 for item in roots):
            raise SchemaError("root_node_ids must contain non-negative integers")
        node_ids = ids(nodes, "nodes")
        root_ids = tuple(int(item) for item in roots)
        if not set(root_ids).issubset(node_ids):
            raise SchemaError("root_node_ids must refer to declared nodes")
        _object(payload.get("counts"), "counts")
        _object(payload.get("evidence"), "evidence")
        return cls(
            format=_string(payload.get("format"), "format"),
            model=_string(payload.get("model"), "model"),
            status=_string(payload.get("status"), "status"),
            node_ids=node_ids,
            edge_ids=ids(edges, "edges"),
            root_node_ids=root_ids,
            raw=MappingProxyType(dict(payload)),
        )


@dataclass(frozen=True)
class WholeProgramAcceptanceIR:
    format: str
    status: str
    profile: str
    required_theorem: str
    blockers: tuple[Mapping[str, Any], ...]
    raw: Mapping[str, Any]

    @classmethod
    def parse(cls, payload: Mapping[str, Any]) -> "WholeProgramAcceptanceIR":
        blockers = _objects(payload.get("blockers"), "blockers")
        return cls(
            format=_string(payload.get("format"), "format"),
            status=_string(payload.get("status"), "status"),
            profile=_string(payload.get("profile"), "profile"),
            required_theorem=_string(payload.get("required_theorem"), "required_theorem"),
            blockers=blockers,
            raw=MappingProxyType(dict(payload)),
        )


@dataclass(frozen=True)
class CompositionProgressIR:
    format: str
    status: str
    counts: Mapping[str, Any]
    raw: Mapping[str, Any]

    @classmethod
    def parse(cls, payload: Mapping[str, Any]) -> "CompositionProgressIR":
        counts = _object(payload.get("counts"), "counts")
        _object(payload.get("frontiers"), "frontiers")
        _object(payload.get("acceptance"), "acceptance")
        return cls(
            format=_string(payload.get("format"), "format"),
            status=_string(payload.get("status"), "status"),
            counts=MappingProxyType(dict(counts)),
            raw=MappingProxyType(dict(payload)),
        )
