"""Compact native reference-fact validation for semantic linking."""

from __future__ import annotations

from typing import Any, Iterable, Mapping, Sequence

from ..artifacts.artifact_set import canonical_sha256_v3
from ..semantic_objects.semantic_object import SemanticObjectV1
from ..transfer.reference_facts import decode_reference_index_set_v1
from .errors import LinkedSemanticModuleError


def _fail(message: str) -> None:
    raise LinkedSemanticModuleError(message)


def _mapping(value: object, context: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        _fail(f"{context} must be an object")
    return value


def _rows(value: object, context: str) -> list[Any]:
    if not isinstance(value, list) or len(value) > 2_000_000:
        _fail(f"{context} must be a bounded array")
    return value


def _canonical_rows(rows: Sequence[Mapping[str, Any]]) -> list[dict[str, Any]]:
    return sorted((dict(row) for row in rows), key=canonical_sha256_v3)
_REFERENCE_CATALOG_FIELDS = {
    "reference_atoms", "bindings", "memory_keys", "memory_ranges",
    "allocation_identities",
}
NATIVE_REFERENCE_FACT_FIELDS = {
    "unit_id", "rva", "root_rva", "state_contexts",
    "reference_atom_indices", "callback_binding_indices",
    "relational_object_binding_indices", "written_memory_key_indices",
    "invalidated_memory_range_indices", "all_memory_invalidated",
    "effect_invalidated_memory_range_indices",
    "effect_all_memory_invalidated",
    "possible_allocation_identity_indices",
    "all_preserve_inherited_memory", "any_preserve_inherited_memory",
}



def empty_reference_facts_v1() -> dict[str, Any]:
    return {
        "catalog": {field: [] for field in sorted(_REFERENCE_CATALOG_FIELDS)},
        "facts": [],
    }

def validated_reference_catalog_v1(value: object) -> dict[str, list[Any]]:
    catalog = dict(_mapping(value, "semantic reference catalog"))
    if set(catalog) != _REFERENCE_CATALOG_FIELDS:
        _fail("semantic reference catalog fields are incomplete")
    atoms = [
        dict(_mapping(row, "semantic reference atom"))
        for row in _rows(catalog["reference_atoms"], "semantic reference atoms")
    ]
    atom_keys: list[tuple[str, str, int]] = []
    for atom in atoms:
        if (
            set(atom) != {"kind", "identity", "offset"}
            or atom.get("kind") not in {
                "object", "object_view", "guest_code",
                "external_function", "loader_module",
            }
            or not isinstance(atom.get("identity"), str)
            or not atom["identity"]
            or not isinstance(atom.get("offset"), int)
            or isinstance(atom.get("offset"), bool)
        ):
            _fail("semantic reference atom is malformed")
        atom_keys.append((atom["kind"], atom["identity"], atom["offset"]))
    if atom_keys != sorted(set(atom_keys)):
        _fail("semantic reference atoms are noncanonical")
    bindings = [
        dict(_mapping(row, "semantic reference binding"))
        for row in _rows(catalog["bindings"], "semantic reference bindings")
    ]
    for binding in bindings:
        values = _rows(
            binding.get("values"), "semantic reference binding values"
        )
        if (
            set(binding) != {"identity", "values"}
            or not isinstance(binding.get("identity"), str)
            or not binding["identity"] or not values
            or any(not isinstance(item, Mapping) for item in values)
            or values != sorted(values, key=canonical_sha256_v3)
            or len({canonical_sha256_v3(item) for item in values}) != len(values)
        ):
            _fail("semantic reference binding is malformed")
    binding_digests = [canonical_sha256_v3(row) for row in bindings]
    if binding_digests != sorted(set(binding_digests)):
        _fail("semantic reference bindings are noncanonical")
    memory_keys = [
        dict(_mapping(row, "semantic reference memory key"))
        for row in _rows(catalog["memory_keys"], "semantic reference memory keys")
    ]
    key_keys: list[tuple[str, str, int, int]] = []
    for row in memory_keys:
        if (
            set(row) != {"kind", "identity", "offset", "width"}
            or not isinstance(row.get("kind"), str)
            or not isinstance(row.get("identity"), str)
            or not isinstance(row.get("offset"), int)
            or isinstance(row.get("offset"), bool)
            or not isinstance(row.get("width"), int)
            or isinstance(row.get("width"), bool)
            or row["width"] <= 0
        ):
            _fail("semantic reference memory key is malformed")
        key_keys.append((
            row["kind"], row["identity"], row["offset"], row["width"],
        ))
    if key_keys != sorted(set(key_keys)):
        _fail("semantic reference memory keys are noncanonical")
    memory_ranges = [
        dict(_mapping(row, "semantic reference memory range"))
        for row in _rows(
            catalog["memory_ranges"], "semantic reference memory ranges"
        )
    ]
    range_keys: list[tuple[str, str, int, int]] = []
    for row in memory_ranges:
        if (
            set(row) != {"kind", "identity", "start", "end"}
            or not isinstance(row.get("kind"), str)
            or not isinstance(row.get("identity"), str)
            or not isinstance(row.get("start"), int)
            or isinstance(row.get("start"), bool)
            or not isinstance(row.get("end"), int)
            or isinstance(row.get("end"), bool)
            or row["end"] < row["start"]
        ):
            _fail("semantic reference memory range is malformed")
        range_keys.append((
            row["kind"], row["identity"], row["start"], row["end"],
        ))
    if range_keys != sorted(set(range_keys)):
        _fail("semantic reference memory ranges are noncanonical")
    allocations = _rows(
        catalog["allocation_identities"],
        "semantic reference allocation identities",
    )
    if (
        allocations != sorted(set(allocations))
        or any(
            not isinstance(item, str) or not item.startswith("allocation:")
            for item in allocations
        )
    ):
        _fail("semantic reference allocation identities are noncanonical")
    return {
        "reference_atoms": atoms,
        "bindings": bindings,
        "memory_keys": memory_keys,
        "memory_ranges": memory_ranges,
        "allocation_identities": list(allocations),
    }

def linked_native_reference_facts_v1(
    value: object,
    *, semantic: SemanticObjectV1,
    symbols: Sequence[Mapping[str, Any]],
    root_ids_by_rva: Mapping[int, Sequence[str]],
) -> dict[str, Any]:
    """Validate compact same-pass facts and replace root RVAs by root IDs."""

    source = _mapping(value, "native semantic reference facts")
    if set(source) != {"catalog", "facts"}:
        _fail("native semantic reference facts are incomplete")
    catalog = validated_reference_catalog_v1(source["catalog"])
    rows = _rows(source["facts"], "native semantic reference facts")
    unit_by_rva = {
        transfer.rva_start: transfer.identity for transfer in semantic.transfers
    }
    symbol_by_unit = {
        transfer.identity: next(
            row for row in symbols
            if row["symbol_id"] == f"original:function:{transfer.identity}"
        )
        for transfer in semantic.transfers
    }
    result: list[dict[str, Any]] = []
    previous: tuple[int, int] | None = None
    limits = {
        "reference_atom_indices": len(catalog["reference_atoms"]),
        "callback_binding_indices": len(catalog["bindings"]),
        "relational_object_binding_indices": len(catalog["bindings"]),
        "written_memory_key_indices": len(catalog["memory_keys"]),
        "invalidated_memory_range_indices": len(catalog["memory_ranges"]),
        "effect_invalidated_memory_range_indices": len(
            catalog["memory_ranges"]
        ),
        "possible_allocation_identity_indices": len(
            catalog["allocation_identities"]
        ),
    }
    for raw in rows:
        row = dict(_mapping(raw, "native semantic reference fact"))
        if set(row) != NATIVE_REFERENCE_FACT_FIELDS:
            _fail("native semantic reference fact fields are incomplete")
        unit_id, rva, root_rva, contexts = (
            row["unit_id"], row["rva"], row["root_rva"],
            row["state_contexts"],
        )
        if (
            not isinstance(unit_id, str) or not unit_id
            or not isinstance(rva, int) or isinstance(rva, bool)
            or not isinstance(root_rva, int) or isinstance(root_rva, bool)
            or rva < 0 or root_rva < 0
            or unit_by_rva.get(rva) != unit_id
            or root_rva not in root_ids_by_rva
            or not isinstance(contexts, int) or isinstance(contexts, bool)
            or contexts <= 0
            or any(
                not isinstance(row[field], bool)
                for field in (
                    "all_memory_invalidated",
                    "effect_all_memory_invalidated",
                    "all_preserve_inherited_memory",
                    "any_preserve_inherited_memory",
                )
            )
            or (
                row["all_preserve_inherited_memory"]
                and not row["any_preserve_inherited_memory"]
            )
        ):
            _fail("native semantic reference identity is malformed")
        identity = (rva, root_rva)
        if previous is not None and identity <= previous:
            _fail("native semantic reference facts are noncanonical")
        previous = identity
        root_ids = root_ids_by_rva[root_rva]
        if not set(root_ids) <= set(symbol_by_unit[unit_id].get("root_ids", ())):
            _fail("native semantic reference fact is disconnected from its unit")
        for field, limit in limits.items():
            try:
                decode_reference_index_set_v1(row[field], limit=limit)
            except ValueError:
                _fail(f"semantic reference {field} is malformed")
        body = {
            key: item for key, item in row.items() if key != "root_rva"
        }
        result.extend({**body, "root_id": root_id} for root_id in root_ids)
    result.sort(key=lambda row: (int(row["rva"]), str(row["root_id"])))
    return {"catalog": catalog, "facts": result}

def check_native_link_facts_v1(
    native: Mapping[str, Any],
    *, semantic: SemanticObjectV1,
    symbols: Sequence[dict[str, Any]],
    relocations: Sequence[dict[str, Any]],
    objects: Sequence[dict[str, Any]],
    effects: dict[str, list[dict[str, Any]]],
    root_ids_by_rva: Mapping[int, Sequence[str]],
    expected_blockers: Sequence[Mapping[str, Any]],
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """Require whole-result parity for native link and effect provenance."""

    if set(native) != {
        "symbols", "relocations", "objects", "effects", "references",
        "blockers",
    }:
        _fail("native semantic-link facts are incomplete")
    native_symbol_rows = _rows(native.get("symbols"), "native linked symbols")
    native_relocation_rows = _rows(
        native.get("relocations"), "native linked relocations"
    )
    native_object_rows = _rows(native.get("objects"), "native linked objects")
    native_references = _mapping(
        native.get("references"), "native semantic reference facts"
    )
    native_blocker_rows = _rows(
        native.get("blockers"), "native linked blockers"
    )
    native_effect_groups = _mapping(
        native.get("effects"), "native linked effects"
    )
    if set(native_effect_groups) != set(effects):
        _fail("native semantic-link effect groups are incomplete")
    expected_symbols = [
        {
            "symbol_id": row["symbol_id"],
            "resolution": dict(_mapping(
                row.get("resolution"), "linked symbol resolution"
            )),
            "reachable": row.get("reachable"),
            "root_rvas": _root_rvas_for_ids(
                root_ids_by_rva, row.get("root_ids", ())
            ),
        }
        for row in symbols
    ]
    expected_relocations = [
        {
            "relocation_id": row["relocation_id"],
            "status": row.get("status"),
            "target_symbols": list(row.get("target_symbols", ())),
            "reachable": row.get("reachable"),
        }
        for row in relocations
    ]
    expected_objects = [
        {
            "object_id": row["id"],
            "semantic_symbol_id": row.get("semantic_symbol_id"),
            "reachable": row.get("reachable"),
            "root_rvas": _root_rvas_for_ids(
                root_ids_by_rva, row.get("root_ids", ())
            ),
        }
        for row in objects
    ]
    observed_symbols = [dict(_mapping(row, "native linked symbol"))
                        for row in native_symbol_rows]
    observed_relocations = [
        dict(_mapping(row, "native linked relocation"))
        for row in native_relocation_rows
    ]
    observed_objects = [
        dict(_mapping(row, "native linked object")) for row in native_object_rows
    ]
    if observed_symbols != expected_symbols:
        _fail("native and Python semantic symbol links disagree")
    if observed_relocations != expected_relocations:
        _fail("native and Python semantic relocation links disagree")
    if observed_objects != expected_objects:
        _fail("native and Python semantic object links disagree")
    root_rva_by_id = _root_rva_by_id(root_ids_by_rva)
    expected_effects = {
        group: [
            {
                "effect": {
                    key: item for key, item in row.items()
                    if key != "root_ids"
                },
                "root_rvas": sorted({
                    root_rva_by_id[root_id]
                    for root_id in row.get("root_ids", ())
                }),
            }
            for row in rows
        ]
        for group, rows in effects.items()
    }
    observed_effects = {
        group: [
            dict(_mapping(row, f"native linked {group} effect"))
            for row in _rows(
                native_effect_groups.get(group), f"native linked {group}"
            )
        ]
        for group in effects
    }
    if observed_effects != expected_effects:
        _fail("native and Python semantic effect provenance disagree")
    observed_blockers = _canonical_rows([
        dict(_mapping(row, "native linked blocker"))
        for row in native_blocker_rows
    ])
    if observed_blockers != _canonical_rows(expected_blockers):
        _fail("native and Python semantic-link blockers disagree")
    native_symbols = {
        str(row["symbol_id"]): row for row in observed_symbols
    }
    for linked_symbol in symbols:
        native_symbol = native_symbols[str(linked_symbol["symbol_id"])]
        linked_symbol["resolution"] = dict(native_symbol["resolution"])
        linked_symbol["reachable"] = native_symbol["reachable"]
        linked_symbol["root_ids"] = _root_ids_for_rvas(
            root_ids_by_rva, native_symbol["root_rvas"]
        )
    native_relocations = {
        str(row["relocation_id"]): row for row in observed_relocations
    }
    for linked_relocation in relocations:
        native_relocation = native_relocations[
            str(linked_relocation["relocation_id"])
        ]
        linked_relocation["status"] = native_relocation["status"]
        linked_relocation["target_symbols"] = list(
            native_relocation["target_symbols"]
        )
        linked_relocation["reachable"] = native_relocation["reachable"]
    native_objects = {
        str(row["object_id"]): row for row in observed_objects
    }
    for linked_object in objects:
        native_object = native_objects[str(linked_object["id"])]
        linked_object["semantic_symbol_id"] = native_object[
            "semantic_symbol_id"
        ]
        linked_object["reachable"] = native_object["reachable"]
        linked_object["root_ids"] = _root_ids_for_rvas(
            root_ids_by_rva, native_object["root_rvas"]
        )
    for group in effects:
        effects[group] = [
            {
                **dict(_mapping(row["effect"], f"native {group} effect body")),
                "root_ids": _root_ids_for_rvas(
                    root_ids_by_rva, row["root_rvas"]
                ),
            }
            for row in observed_effects[group]
        ]
    references = linked_native_reference_facts_v1(
        native_references,
        semantic=semantic,
        symbols=symbols,
        root_ids_by_rva=root_ids_by_rva,
    )
    return observed_blockers, references

def _root_ids_for_rvas(
    root_ids_by_rva: Mapping[int, Sequence[str]],
    rvas: Iterable[int],
) -> list[str]:
    return sorted({
        root_id
        for rva in rvas
        for root_id in root_ids_by_rva[rva]
    })

def _root_rvas_for_ids(
    root_ids_by_rva: Mapping[int, Sequence[str]],
    root_ids: Iterable[str],
) -> list[int]:
    selected = set(root_ids)
    return sorted(
        rva for rva, candidates in root_ids_by_rva.items()
        if selected.intersection(candidates)
    )

def _root_rva_by_id(
    root_ids_by_rva: Mapping[int, Sequence[str]],
) -> dict[str, int]:
    return {
        root_id: rva
        for rva, root_ids in root_ids_by_rva.items()
        for root_id in root_ids
    }
