"""Bind exact continuation premises to selected generated objects and symbols."""

import copy
import re
from typing import Mapping, Sequence

from ..semantic_providers.exact_context import exact_context_blockers
from ..semantic_providers.slices_v2 import SemanticSliceV2


class ExactContextLinkError(ValueError):
    pass


def selected_context(*, qualification, selection, qualifications: Sequence) -> dict | None:
    context = qualification.payload.get("exact_context")
    if context is None:
        return None
    blockers = exact_context_blockers(
        qualifications=qualifications,
        definition_selections=selection.payload["definition_selections"],
        obligation_selections=selection.payload["obligation_selections"],
    )
    if blockers or selection.payload["status"] != "complete":
        raise ExactContextLinkError(f"exact continuation selection is incomplete: {blockers}")
    choices = {row["definition_id"]: row for row in selection.payload["definition_selections"]}
    providers = {item.identity: item for item in qualifications}
    definitions = []
    for definition in context["definitions"]:
        choice = choices[definition["definition_id"]]
        provider = providers[choice["qualification_sha256"]]
        materialization = next(row for row in provider.payload["definition_materializations"]
                               if row["definition_id"] == definition["definition_id"])
        definitions.append({
            **{key: choice[key] for key in ("definition_id", "symbol_id", "provider_id", "qualification_sha256", "native_symbol")},
            "object_sha256s": list(materialization["object_sha256s"]),
        })
    return {"semantic_slice_sha256": context["semantic_slice_sha256"],
            "implementation_selection_sha256": selection.identity, "definitions": definitions}


def bind_context_objects(context: Mapping, *, object_rows: Sequence[Mapping], symbol_owners: Mapping) -> dict:
    result = copy.deepcopy(dict(context))
    objects = {row["object_sha256"]: row for row in object_rows}
    for definition in result["definitions"]:
        for digest in definition["object_sha256s"]:
            row = objects.get(digest, {})
            selected = row.get("selected_provider", {})
            if any(definition[key] not in selected.get(inventory, []) for key, inventory in (
                ("provider_id", "provider_ids"), ("qualification_sha256", "qualification_sha256s"),
                ("definition_id", "definition_ids"),
            )):
                raise ExactContextLinkError("exact continuation object is absent or not selected for its definition")
        owners = symbol_owners.get(definition["native_symbol"], [])
        if len(owners) != 1 or owners[0][0] != "strong" or owners[0][2]["object_sha256"] not in definition["object_sha256s"]:
            raise ExactContextLinkError("exact continuation symbol is missing, weak, duplicated or in another object")
        definition["implementation_object_sha256"] = owners[0][2]["object_sha256"]
    return result


def finish_context(context: Mapping, *, linked_symbols: Mapping, selection_sha256: str) -> dict:
    if context.get("implementation_selection_sha256") != selection_sha256:
        raise ExactContextLinkError("exact continuation selection changed during linking")
    result = copy.deepcopy(dict(context))
    for definition in result["definitions"]:
        rva = linked_symbols.get(definition["native_symbol"])
        if type(rva) is not int or rva <= 0:
            raise ExactContextLinkError("exact continuation symbol is absent from the linker map")
        definition["linked_rva"] = rva
    return result


def validate_context_receipt(context: object) -> None:
    def digest(value):
        return isinstance(value, str) and re.fullmatch("[0-9a-f]{64}", value) is not None

    if (not isinstance(context, Mapping) or set(context) != {"semantic_slice_sha256", "implementation_selection_sha256", "definitions"}
            or not digest(context["semantic_slice_sha256"]) or not digest(context["implementation_selection_sha256"])):
        raise ExactContextLinkError("exact continuation receipt is malformed")
    definitions = context["definitions"]
    if not isinstance(definitions, list) or not definitions:
        raise ExactContextLinkError("exact continuation receipt has no definitions")
    identities = []
    for row in definitions:
        if not isinstance(row, Mapping) or set(row) != {
            "definition_id", "symbol_id", "provider_id", "qualification_sha256", "native_symbol",
            "object_sha256s", "implementation_object_sha256", "linked_rva",
        }:
            raise ExactContextLinkError("exact continuation definition receipt is malformed")
        if any(not isinstance(row[key], str) or not row[key] for key in ("definition_id", "symbol_id", "provider_id", "native_symbol")):
            raise ExactContextLinkError("exact continuation definition identity is malformed")
        objects = row["object_sha256s"]
        if (not isinstance(objects, list) or not objects or any(not digest(value) for value in objects)
                or objects != sorted(set(objects)) or not digest(row["qualification_sha256"])
                or row["implementation_object_sha256"] not in objects
                or type(row["linked_rva"]) is not int or not 0 < row["linked_rva"] <= 0xffffffff
                or not row["symbol_id"].startswith("original:function:")):
            raise ExactContextLinkError("exact continuation definition binding is malformed")
        identities.append(row["definition_id"])
    if identities != sorted(set(identities)):
        raise ExactContextLinkError("exact continuation definitions are noncanonical")


def validate_realized_contexts(*, entries: Sequence[Mapping], providers: Sequence[Mapping],
                               definitions: Sequence[Mapping], objects: Sequence[Mapping], selection_sha256: str) -> None:
    provider_index = {row["provider_id"]: row for row in providers}
    definition_index = {row["definition_id"]: row for row in definitions}
    object_index = {row["object_sha256"]: row for row in objects}
    owned = {unit for entry in entries for unit in entry["owned_unit_ids"]}
    for entry in entries:
        expected = provider_index.get(entry["provider_id"], {}).get("exact_context")
        context = entry.get("exact_context")
        if expected is None and context is None:
            continue
        if expected is None or context is None:
            raise ExactContextLinkError("portable dispatch omits or invents its exact continuation premise")
        validate_context_receipt(context)
        if context["implementation_selection_sha256"] != selection_sha256:
            raise ExactContextLinkError("linked exact continuation binds another implementation selection")
        semantic_slice = SemanticSliceV2.parse(expected)
        required = {row["definition_id"]: row for row in semantic_slice.payload["definitions"]}
        if context["semantic_slice_sha256"] != semantic_slice.identity or set(required) != {row["definition_id"] for row in context["definitions"]}:
            raise ExactContextLinkError("linked exact continuation inventory differs from its provider premise")
        for row in context["definitions"]:
            definition = definition_index.get(row["definition_id"], {})
            if (row["symbol_id"] != required[row["definition_id"]]["symbol_id"]
                    or row["symbol_id"].removeprefix("original:function:") in owned
                    or definition.get("provider_kind") != "generated_behavioral_c"
                    or definition.get("implementation_rva") != row["linked_rva"]
                    or any(definition.get(key) != row[key] for key in ("provider_id", "qualification_sha256", "native_symbol", "symbol_id"))):
                raise ExactContextLinkError("linked exact continuation was replaced or its selected symbol changed")
            for digest in row["object_sha256s"]:
                obj = object_index.get(digest, {})
                if row["provider_id"] not in obj.get("provider_ids", []) or row["definition_id"] not in obj.get("definition_ids", []):
                    raise ExactContextLinkError("linked exact continuation object membership is incomplete")
