"""Stable operator intent for typed call protocols.

Intent records semantic choices only.  Generated hashes, evidence identifiers,
statuses, and physical frame fragments are rejected so a nonsemantic rebuild
cannot silently become an operator decision.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Mapping

from ..artifacts.formats import CALL_PROTOCOL_INTENT_V1_FORMAT
from ._canonical import CallProtocolError, array, exact, identifier, object_, text
from .frame import CallSubjectV1
from .types import PortableTypeGraphV1, PortableTypeNodeV1


_FORBIDDEN_KEYS = frozenset(
    {
        "status",
        "authority",
        "evidence",
        "evidence_ids",
        "proposal_id",
        "frame",
        "fragments",
        "argument_words",
        "stack_cleanup_bytes",
        "result_register",
    }
)


@dataclass(frozen=True)
class CallProtocolIntentV1:
    intent_id: str
    subject: CallSubjectV1
    abi_dialect: str
    faithful_function_type_id: str
    types: tuple[PortableTypeNodeV1, ...]
    source_names: Mapping[str, object]
    lifecycle: tuple[Mapping[str, object], ...]
    idiomatic_projections: tuple[Mapping[str, object], ...]
    rationale: str

    @classmethod
    def parse(cls, value: object) -> "CallProtocolIntentV1":
        row = object_(value, "call protocol intent")
        _reject_generated_fields(row, "call protocol intent")
        exact(row, {"format", "id", "subject", "abi_dialect", "faithful_function_type_id", "types", "source_names", "lifecycle", "idiomatic_projections", "rationale"}, "call protocol intent")
        if row["format"] != CALL_PROTOCOL_INTENT_V1_FORMAT:
            raise CallProtocolError("unsupported call protocol intent format")
        types = tuple(PortableTypeNodeV1.parse(item, f"call intent type {index}") for index, item in enumerate(array(row["types"], "call intent types")))
        graph = PortableTypeGraphV1.create(types)
        function_type_id = identifier(row["faithful_function_type_id"], "call intent faithful function type")
        function = graph.index.get(function_type_id)
        if function is None or function.kind != "function":
            raise CallProtocolError("call intent faithful type is not a declared function")
        source_names = dict(object_(row["source_names"], "call intent source names"))
        lifecycle = tuple(dict(object_(item, f"call intent lifecycle {index}")) for index, item in enumerate(array(row["lifecycle"], "call intent lifecycle")))
        projections = tuple(dict(object_(item, f"call intent projection {index}")) for index, item in enumerate(array(row["idiomatic_projections"], "call intent projections")))
        _reject_generated_fields(source_names, "call intent source names")
        for index, item in enumerate((*lifecycle, *projections)):
            _reject_generated_fields(item, f"call intent semantic entry {index}")
        rationale = text(row["rationale"], "call intent rationale")
        return cls(identifier(row["id"], "call intent id"), CallSubjectV1.parse(row["subject"]), identifier(row["abi_dialect"], "call intent ABI dialect"), function_type_id, graph.nodes, source_names, lifecycle, projections, rationale)

    @property
    def type_graph(self) -> PortableTypeGraphV1:
        return PortableTypeGraphV1.create(self.types)

    def to_payload(self) -> dict[str, object]:
        return {
            "format": CALL_PROTOCOL_INTENT_V1_FORMAT,
            "id": self.intent_id,
            "subject": self.subject.to_payload(),
            "abi_dialect": self.abi_dialect,
            "faithful_function_type_id": self.faithful_function_type_id,
            "types": [item.to_payload() for item in self.types],
            "source_names": dict(self.source_names),
            "lifecycle": [dict(item) for item in self.lifecycle],
            "idiomatic_projections": [dict(item) for item in self.idiomatic_projections],
            "rationale": self.rationale,
        }


def _reject_generated_fields(value: object, context: str) -> None:
    if isinstance(value, Mapping):
        for key, item in value.items():
            if not isinstance(key, str):
                raise CallProtocolError(f"{context} has a non-string key")
            if key in _FORBIDDEN_KEYS or key.endswith("_sha256"):
                raise CallProtocolError(f"{context} contains generated authority field {key!r}")
            _reject_generated_fields(item, context)
    elif isinstance(value, list):
        for item in value:
            _reject_generated_fields(item, context)


__all__ = ["CallProtocolIntentV1"]
