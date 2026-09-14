"""Project supplied native producer selectors into a component's authority table.

This checks correspondence within the supplied complete ordered inventories. It
cannot establish their origin/completeness or a caller's live instance inventory;
the normal runtime-locator and allocation-service admission guards remain closed.
"""

import re
from collections.abc import Mapping

from ..external.range_bindings import (
    RangeBindingError, range_object_selectors, range_ownership_fields,
)
from .bisimulation_support import BisimulationRefinementError
from .bisimulation_allocation_classes import (
    ALLOCATION_EFFECT_FIELDS, allocation_class_requirement,
)


def allocation_producer_correspondence(authority, inventory):
    result = [None for _ in authority.rules]
    if inventory is None:
        return result
    try:
        if not isinstance(inventory, Mapping) or set(inventory) != {"object_rules", "external_range_rules"}:
            raise ValueError("native allocation inventory fields are malformed")
        objects, ranges = inventory["object_rules"], inventory["external_range_rules"]
        if any(not isinstance(rows, list) or any(not isinstance(row, Mapping) for row in rows)
               for rows in (objects, ranges)):
            raise ValueError("native allocation inventory rows are malformed")
        by_id = {row["id"]: (index, row) for index, row in enumerate(objects, 1)}
        if len(by_id) != len(objects):
            raise ValueError("native allocation authority identities are duplicated")
        object_selectors, producer_selectors = range_object_selectors(objects, ranges)
        ownership_rows, _families = range_ownership_fields(ranges)
        for local_index, rule in enumerate(authority.rules):
            if (rule.locator.kind != "external_allocation" or rule.kind != "external" or
                    rule.lifetime != "allocation"):
                continue
            selected = by_id.get(rule.identity)
            if selected is None:
                raise ValueError(f"native allocation authority {rule.identity!r} is missing")
            native_index, native_rule = selected
            expected = {"id": rule.identity, "domain": rule.domain, "object": rule.object_id,
                "generation": rule.generation, "extent": rule.extent, "permissions": rule.permissions,
                "lifetime": rule.lifetime, "interior_pointers": rule.interior_pointers,
                "extent_mode": rule.extent_mode}
            if any(type(native_rule.get(key, "fixed" if key == "extent_mode" else None)) is not type(value) or
                   native_rule.get(key, "fixed" if key == "extent_mode" else None) != value
                   for key, value in expected.items()):
                raise ValueError(f"native allocation authority {rule.identity!r} disagrees with the proof authority")
            locator = native_rule["locator"]
            if any(locator.get(key) != value for key, value in {
                "kind": rule.locator.kind, "identity": rule.locator.identity, "offset": rule.locator.offset}.items()):
                raise ValueError("native allocation locator disagrees with the proof authority")
            members = [index for index, target in object_selectors.items() if target == native_index]
            if not members:
                raise ValueError("native allocation authority has no bound producer")
            first = members[0]
            producer = ranges[first - 1]
            digest = producer.get("contract_identity_sha256")
            if not isinstance(digest, str) or re.fullmatch(r"[0-9a-f]{64}", digest) is None:
                raise ValueError("native allocation producer lacks its exact checked contract identity")
            if producer["action"] != "add_result_range" or producer.get("ownership") is None:
                raise ValueError("proof allocation correspondence requires an owned result producer")
            result[local_index] = {
                "native_object_selector": native_index,
                "native_producer_selector": producer_selectors[first],
                "native_family_selector": ownership_rows[first - 1][0],
                "owner_argument": producer["ownership"]["owner_argument"],
                "family": producer["ownership"]["family"],
                "contract_identity_sha256": digest,
                "native_site_selectors": members,
                "class_requirement": allocation_class_requirement(rule,
                    contract_identity_sha256=digest, argument_words=producer['argument_count'],
                    effect={key: producer.get(key) for key in ALLOCATION_EFFECT_FIELDS}),
            }
        families = {name: index for index, name in enumerate(sorted({
            row["family"] for row in result if row is not None}), 1)}
        for row in result:
            if row is not None:
                row["proof_family_selector"] = families[row["family"]]
    except (KeyError, TypeError, ValueError, RangeBindingError) as exc:
        raise BisimulationRefinementError(f"proof allocation producer correspondence: {exc}") from exc
    return result
