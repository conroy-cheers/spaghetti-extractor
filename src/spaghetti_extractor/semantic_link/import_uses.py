"""Exact importer-side IAT-use projection from transfer-v2."""

from __future__ import annotations

from typing import Any, Mapping, Sequence

from ..artifacts.artifact_set import canonical_sha256_v3
from ..semantic_objects.semantic_object import SemanticObjectV1
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


def _identity_key(declaration: Mapping[str, Any]) -> tuple[str, str] | None:
    dll = declaration.get("dll")
    symbol = declaration.get("symbol")
    ordinal = declaration.get("ordinal")
    if not isinstance(dll, str) or not dll:
        return None
    if isinstance(symbol, str) and symbol:
        return dll.lower(), symbol
    if isinstance(ordinal, int) and not isinstance(ordinal, bool) and ordinal >= 0:
        return dll.lower(), f"ordinal:{ordinal}"
    return None

def _module_import_slots_v1(
    module_interface: Mapping[str, Any],
) -> list[dict[str, Any]]:
    rows = [
        {**dict(_mapping(raw, "module import slot")), "import_kind": "ordinary"}
        for raw in _rows(module_interface.get("imports"), "module imports")
    ]
    for raw_descriptor in _rows(
        module_interface.get("delay_imports"), "module delay imports"
    ):
        descriptor = _mapping(raw_descriptor, "module delay-import descriptor")
        rows.extend(
            {
                **dict(_mapping(raw, "module delay-import slot")),
                "import_kind": "delay",
            }
            for raw in _rows(
                descriptor.get("cells"), "module delay-import cells"
            )
        )
    return sorted(rows, key=lambda row: str(row["slot_id"]))

def semantic_import_uses_v1(
    *, semantic: SemanticObjectV1,
    resolved_environment: Mapping[str, Any],
    roots_by_unit: Mapping[str, set[str]],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Project exact reachable IAT code/data uses from transfer-v2.

    This is a link projection over the one canonical behavioral language.  It
    deliberately recognizes only exact direct pointer flow.  Anything that
    would require a second abstract interpreter remains an honest blocker.
    """

    interface = semantic.module_interface
    image_id = str(interface["image_id"])
    image_base = int(_mapping(
        interface.get("loader"), "module loader contract"
    )["preferred_base"])
    slots = _module_import_slots_v1(interface)
    slots_by_id = {str(row["slot_id"]): row for row in slots}
    slots_by_va = {
        (image_base + int(row["iat_rva"])) & 0xFFFFFFFF: row
        for row in slots
    }
    slots_by_identity: dict[tuple[str, str], list[dict[str, Any]]] = {}
    for row in slots:
        key = _identity_key(row)
        if key is None:
            _fail("module import slot has no exact identity")
        slots_by_identity.setdefault(key, []).append(row)

    contracts_by_slot: dict[str, Mapping[str, Any]] = {}
    for raw in _rows(
        resolved_environment.get("machine_import_contracts"),
        "resolved machine-import contracts",
    ):
        contract = _mapping(raw, "resolved machine-import contract")
        iat_rva = contract.get("iat_rva")
        identity = _mapping(
            contract.get("identity"), "machine-import identity"
        )
        candidates = [
            row for row in slots
            if row["import_kind"] == contract.get("import_kind", "ordinary")
            and row["iat_rva"] == iat_rva
            and _identity_key(row) == _identity_key(identity)
        ]
        if len(candidates) != 1:
            continue
        contracts_by_slot[str(candidates[0]["slot_id"])] = contract

    uses: dict[str, dict[str, Any]] = {}
    blockers: list[dict[str, Any]] = []

    def state_for(slot: Mapping[str, Any]) -> dict[str, Any]:
        slot_id = str(slot["slot_id"])
        return uses.setdefault(slot_id, {
            "slot": slot,
            "code_sites": [],
            "data_sites": [],
            "permissions": 0,
            "minimum_extent": 0,
        })

    def code_site(
        slot: Mapping[str, Any], *, transfer_id: str, source_rva: int,
        call_id: int, instruction_rva: int, root_ids: list[str],
    ) -> None:
        state_for(slot)["code_sites"].append({
            "kind": "code_call",
            "transfer_id": transfer_id,
            "source_rva": source_rva,
            "call_id": call_id,
            "instruction_rva": instruction_rva,
            "root_ids": root_ids,
        })

    def data_site(
        slot: Mapping[str, Any], *, kind: str, transfer_id: str,
        source_rva: int, expression_id: int | None,
        effect_id: int | None, byte_offset: int, width: int,
        permissions: int, root_ids: list[str],
    ) -> None:
        state = state_for(slot)
        state["permissions"] |= permissions
        state["minimum_extent"] = max(
            int(state["minimum_extent"]), byte_offset + width
        )
        state["data_sites"].append({
            "kind": kind,
            "transfer_id": transfer_id,
            "source_rva": source_rva,
            "expression_id": expression_id,
            "effect_id": effect_id,
            "byte_offset": byte_offset,
            "width": width,
            "root_ids": root_ids,
        })

    for raw_transfer in semantic.transfer_plan["transfers"]:
        transfer = _mapping(raw_transfer, "transfer-v2 body")
        transfer_id = str(transfer["identity"])
        roots = sorted(roots_by_unit.get(transfer_id, ()))
        if not roots:
            continue
        source = _mapping(transfer.get("source"), "transfer-v2 source")
        source_rva = int(source["rva_start"])
        raw_calls = _rows(transfer.get("calls"), "transfer-v2 calls")
        raw_expressions = _rows(
            transfer.get("expressions"), "transfer-v2 expressions"
        )
        has_iat_pointer_source = any(
            isinstance(raw, Mapping)
            and raw.get("op") == "const"
            and isinstance(raw.get("parameters"), Mapping)
            and raw["parameters"].get("immediate") in slots_by_va
            for raw in raw_expressions
        )
        if not raw_calls and not has_iat_pointer_source:
            continue
        expressions = [
            _mapping(raw, "transfer-v2 expression")
            for raw in raw_expressions
        ]
        memo: dict[
            int, tuple[int | None, frozenset[tuple[str, int]], frozenset[str]]
        ] = {}

        def expression_value(
            node_id: int,
        ) -> tuple[int | None, frozenset[tuple[str, int]], frozenset[str]]:
            cached = memo.get(node_id)
            if cached is not None:
                return cached
            node = expressions[node_id]
            op = str(node["op"])
            operands = [int(item) for item in node["operands"]]
            parameters = _mapping(
                node.get("parameters"), "transfer-v2 expression parameters"
            )
            values = [expression_value(item) for item in operands]
            taint = frozenset().union(*(item[2] for item in values))
            constant: int | None = None
            references: frozenset[tuple[str, int]] = frozenset()
            if op == "const":
                constant = int(parameters["immediate"]) & 0xFFFFFFFF
            elif op == "load":
                address = values[0]
                slot = (
                    None
                    if address[0] is None else slots_by_va.get(address[0])
                )
                if slot is not None:
                    slot_id = str(slot["slot_id"])
                    references = frozenset({(slot_id, 0)})
                    taint = frozenset({slot_id})
                else:
                    # A value loaded through an imported data pointer is no
                    # longer itself an exact interior of that anchor.
                    references = frozenset()
            elif op == "add32":
                referenced = [item for item in values if item[1]]
                plain = [item for item in values if not item[1]]
                if (
                    len(referenced) == 1
                    and len(referenced[0][1]) == 1
                    and all(item[0] is not None and not item[2] for item in plain)
                ):
                    slot_id, offset = next(iter(referenced[0][1]))
                    delta = sum(int(item[0]) for item in plain)
                    references = frozenset({(
                        slot_id, (offset + delta) & 0xFFFFFFFF
                    )})
                elif all(item[0] is not None for item in values):
                    constant = sum(int(item[0]) for item in values) & 0xFFFFFFFF
            elif op == "sub32" and len(values) == 2:
                left, right = values
                if len(left[1]) == 1 and right[0] is not None and not right[2]:
                    slot_id, offset = next(iter(left[1]))
                    references = frozenset({(
                        slot_id, (offset - int(right[0])) & 0xFFFFFFFF
                    )})
                elif left[0] is not None and right[0] is not None:
                    constant = (left[0] - right[0]) & 0xFFFFFFFF
            elif op == "ite" and len(values) == 3:
                left, right = values[1], values[2]
                if left[:2] == right[:2] and left[2] == right[2]:
                    constant, references = left[:2]
                    taint = frozenset((*values[0][2], *left[2]))
            result = (constant, references, taint)
            memo[node_id] = result
            return result

        def access(
            node_id: int, *, width: int, permissions: int, kind: str,
            expression_id: int | None, effect_id: int | None,
        ) -> None:
            _constant, references, taint = expression_value(node_id)
            if len(references) == 1:
                slot_id, offset = next(iter(references))
                if (
                    taint == frozenset({slot_id})
                    and 0 <= offset <= 0xFFFFFFFF
                    and 0 < width <= 0xFFFFFFFF - offset
                ):
                    data_site(
                        slots_by_id[slot_id], kind=kind,
                        transfer_id=transfer_id, source_rva=source_rva,
                        expression_id=expression_id, effect_id=effect_id,
                        byte_offset=offset, width=width,
                        permissions=permissions, root_ids=roots,
                    )
                    return
            if taint:
                blockers.append({
                    "code": "linked_import_data_pointer_use_inexact",
                    "transfer_id": transfer_id,
                    "source_rva": source_rva,
                    "slot_ids": sorted(taint),
                    "expression_id": expression_id,
                    "effect_id": effect_id,
                })

        if has_iat_pointer_source:
            for expression_id, expression in enumerate(expressions):
                if expression.get("op") != "load":
                    continue
                operands = expression.get("operands")
                parameters = _mapping(
                    expression.get("parameters"),
                    "load expression parameters",
                )
                access(
                    int(operands[0]), width=int(parameters["aux"]),
                    permissions=1, kind="data_read",
                    expression_id=expression_id, effect_id=None,
                )

            for effect_id, raw_effect in enumerate(
                _rows(transfer.get("effects"), "transfer-v2 effects")
            ):
                effect = _mapping(raw_effect, "transfer-v2 effect")
                op = str(effect["op"])
                operands = [int(item) for item in effect["operands"]]
                parameters = _mapping(
                    effect.get("parameters"),
                    "transfer-v2 effect parameters",
                )
                if op == "memory_write":
                    access(
                        operands[0], width=int(parameters["aux"]),
                        permissions=2, kind="data_write",
                        expression_id=None, effect_id=effect_id,
                    )
                elif op in {"atomic_compare_exchange", "atomic_exchange"}:
                    access(
                        operands[0], width=int(parameters["aux"]),
                        permissions=3, kind="data_atomic",
                        expression_id=None, effect_id=effect_id,
                    )
                elif op in {
                    "rep_movsd", "rep_movs", "rep_stosd", "rep_stos",
                    "rep_scas",
                }:
                    address_operands = (
                        operands[:2] if op in {"rep_movsd", "rep_movs"}
                        else operands[:1]
                    )
                    tainted = sorted({
                        slot_id
                        for node_id in address_operands
                        for slot_id in expression_value(node_id)[2]
                    })
                    if tainted:
                        blockers.append({
                            "code": "linked_import_data_extent_dynamic",
                            "transfer_id": transfer_id,
                            "source_rva": source_rva,
                            "slot_ids": tainted,
                            "effect_id": effect_id,
                        })

        for raw_call in raw_calls:
            call = _mapping(raw_call, "transfer-v2 call")
            call_id = int(call["id"])
            slot: Mapping[str, Any] | None = None
            if call.get("kind") == "external_call":
                key = _identity_key(call)
                candidates = [] if key is None else slots_by_identity.get(key, [])
                if len(candidates) == 1:
                    slot = candidates[0]
                elif candidates:
                    blockers.append({
                        "code": "linked_import_code_slot_ambiguous",
                        "transfer_id": transfer_id,
                        "source_rva": source_rva,
                        "call_id": call_id,
                        "slot_ids": sorted(str(row["slot_id"]) for row in candidates),
                    })
            elif (
                call.get("kind") == "indirect_call"
                and has_iat_pointer_source
            ):
                target_node = call.get("target_node")
                if isinstance(target_node, int) and not isinstance(target_node, bool):
                    _constant, references, taint = expression_value(target_node)
                    if len(references) == 1:
                        slot_id, offset = next(iter(references))
                        if offset == 0 and taint == frozenset({slot_id}):
                            slot = slots_by_id[slot_id]
                    if slot is None and taint:
                        blockers.append({
                            "code": "linked_import_code_pointer_use_inexact",
                            "transfer_id": transfer_id,
                            "source_rva": source_rva,
                            "call_id": call_id,
                            "slot_ids": sorted(taint),
                        })
            if slot is not None:
                code_site(
                    slot, transfer_id=transfer_id, source_rva=source_rva,
                    call_id=call_id,
                    instruction_rva=int(call["instruction_rva"]),
                    root_ids=roots,
                )

    result: list[dict[str, Any]] = []
    for slot_id, state in sorted(uses.items()):
        slot = _mapping(state["slot"], "linked import-use slot")
        code_sites = sorted(state["code_sites"], key=canonical_sha256_v3)
        data_sites = sorted(state["data_sites"], key=canonical_sha256_v3)
        use_kind = (
            "ambiguous" if code_sites and data_sites
            else "code" if code_sites else "data"
        )
        contract = contracts_by_slot.get(slot_id)
        boundary = (
            None if contract is None else contract.get("boundary")
        )
        frame = (
            None if not isinstance(boundary, Mapping)
            else boundary.get("physical_call_frame_v3")
        )
        if code_sites and not isinstance(frame, Mapping):
            blockers.append({
                "code": "linked_import_code_protocol_missing",
                "slot_id": slot_id,
            })
        if use_kind == "ambiguous":
            blockers.append({
                "code": "linked_import_code_data_use_ambiguous",
                "slot_id": slot_id,
            })
        root_ids = sorted({
            root_id
            for site in (*code_sites, *data_sites)
            for root_id in site["root_ids"]
        })
        core = {
            "logical_image_id": image_id,
            "slot_id": slot_id,
            "import_kind": slot["import_kind"],
            "iat_rva": int(slot["iat_rva"]),
            "identity": {
                "dll": slot["dll"],
                "symbol": slot["symbol"],
                "ordinal": slot["ordinal"],
            },
            "use_kind": use_kind,
            "importer_physical_frame_id": (
                frame.get("id") if isinstance(frame, Mapping) else None
            ),
            "importer_physical_frame": (
                dict(frame) if isinstance(frame, Mapping) else None
            ),
            "required_permissions": (
                int(state["permissions"]) if data_sites else None
            ),
            "minimum_extent": (
                int(state["minimum_extent"]) if data_sites else None
            ),
            "sites": [*code_sites, *data_sites],
            "root_ids": root_ids,
        }
        result.append({
            "import_use_id": "import-use-v1:" + canonical_sha256_v3(core),
            **core,
        })
    return sorted(result, key=lambda row: str(row["import_use_id"])), blockers

def bind_semantic_import_use_roots_v1(
    provisional_rows: Sequence[Mapping[str, Any]],
    provisional_blockers: Sequence[Mapping[str, Any]],
    roots_by_unit: Mapping[str, set[str]],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Bind a pre-kernel IAT-use syntax view to final root provenance."""

    result: list[dict[str, Any]] = []
    blockers = [
        dict(row) for row in provisional_blockers
        if isinstance(row.get("transfer_id"), str)
        and roots_by_unit.get(str(row["transfer_id"]))
    ]
    for raw in provisional_rows:
        provisional = _mapping(raw, "provisional semantic import use")
        sites = []
        for raw_site in _rows(
            provisional.get("sites"), "provisional import-use sites"
        ):
            site = dict(_mapping(raw_site, "provisional import-use site"))
            roots = sorted(roots_by_unit.get(str(site["transfer_id"]), ()))
            if not roots:
                continue
            site["root_ids"] = roots
            sites.append(site)
        if not sites:
            continue
        sites.sort(key=canonical_sha256_v3)
        code_sites = [row for row in sites if row["kind"] == "code_call"]
        data_sites = [row for row in sites if row["kind"] != "code_call"]
        use_kind = (
            "ambiguous" if code_sites and data_sites
            else "code" if code_sites else "data"
        )
        permissions = 0
        minimum_extent = 0
        for site in data_sites:
            permissions |= {
                "data_read": 1, "data_write": 2, "data_atomic": 3,
            }[str(site["kind"])]
            minimum_extent = max(
                minimum_extent,
                int(site["byte_offset"]) + int(site["width"]),
            )
        core = {
            key: item for key, item in provisional.items()
            if key not in {
                "import_use_id", "use_kind", "required_permissions",
                "minimum_extent", "sites", "root_ids",
            }
        }
        core.update({
            "use_kind": use_kind,
            "required_permissions": permissions if data_sites else None,
            "minimum_extent": minimum_extent if data_sites else None,
            "sites": sites,
            "root_ids": sorted({
                root_id for site in sites for root_id in site["root_ids"]
            }),
        })
        row = {
            "import_use_id": "import-use-v1:" + canonical_sha256_v3(core),
            **core,
        }
        result.append(row)
        if code_sites and row["importer_physical_frame"] is None:
            blockers.append({
                "code": "linked_import_code_protocol_missing",
                "slot_id": row["slot_id"],
            })
        if use_kind == "ambiguous":
            blockers.append({
                "code": "linked_import_code_data_use_ambiguous",
                "slot_id": row["slot_id"],
            })
    return (
        sorted(result, key=lambda row: str(row["import_use_id"])),
        blockers,
    )
