from __future__ import annotations

import json
from typing import Any

from ..schema import integer as _integer
from ..model import _semantic_constant_word, _stack_window_transfer_claims

def _semantic_external_target_identity(
    imported: Any,
) -> tuple[str, str, str | int] | None:
    if not isinstance(imported, dict):
        return None
    dll = imported.get("dll")
    if isinstance(dll, list) and all(isinstance(byte, int) for byte in dll):
        try:
            dll = bytes(dll).decode("utf-8")
        except (ValueError, UnicodeDecodeError):
            return None
    name = imported.get("name")
    if not isinstance(dll, str) or not isinstance(name, dict):
        return None
    operation = name.get("op")
    if operation == "symbol":
        value = name.get("bytes")
        if not isinstance(value, list) or not all(isinstance(byte, int) for byte in value):
            return None
        try:
            symbol = bytes(value).decode("utf-8")
        except (ValueError, UnicodeDecodeError):
            return None
        return (dll.lower(), "symbol", symbol)
    if operation == "ordinal":
        ordinal = _integer(name.get("value", name.get("ordinal")))
        return None if ordinal is None else (dll.lower(), "ordinal", ordinal)
    return None

def _semantic_add_word_offset(
    expression: dict[str, Any], offset: int,
) -> dict[str, Any]:
    offset %= 2**32
    if offset == 0:
        return expression
    if (
        expression.get("op") == "add"
        and isinstance(expression.get("right"), dict)
        and expression["right"].get("op") == "constant"
    ):
        combined = (int(expression["right"]["value"]) + offset) % 2**32
        if combined == 0:
            return expression["left"]
        return {
            "op": "add", "left": expression["left"],
            "right": {"op": "constant", "value": combined},
        }
    if (
        expression.get("op") == "sub"
        and isinstance(expression.get("right"), dict)
        and expression["right"].get("op") == "constant"
    ):
        combined = (2**32 - int(expression["right"]["value"]) + offset) % 2**32
        if combined == 0:
            return expression["left"]
        return {
            "op": "add", "left": expression["left"],
            "right": {"op": "constant", "value": combined},
        }
    return {
        "op": "add", "left": expression,
        "right": {"op": "constant", "value": offset},
    }

def _semantic_call_push_base(expression: Any) -> dict[str, Any] | None:
    if not isinstance(expression, dict) or expression.get("op") not in {"add", "sub"}:
        return None
    right = expression.get("right")
    left = expression.get("left")
    if (
        not isinstance(left, dict)
        or not isinstance(right, dict)
        or right.get("op") != "constant"
    ):
        return None
    value = _integer(right.get("value"))
    if value is None or not 0 <= value < 2**32:
        return None
    restored = (
        value + 4 if expression["op"] == "add" else 2**32 - value + 4
    ) % 2**32
    return _semantic_add_word_offset(left, restored)

def _semantic_word_writes_disjoint(left: Any, right: Any) -> bool:
    left_affine = _semantic_affine_base_offset(left)
    right_affine = _semantic_affine_base_offset(right)
    if left_affine is None or right_affine is None or left_affine[0] != right_affine[0]:
        return False
    return all(
        (left_affine[1] + left_offset) % 2**32
        != (right_affine[1] + right_offset) % 2**32
        for left_offset in range(4) for right_offset in range(4)
    )

def _semantic_exact_stack_argument(
    stack: dict[str, Any], writes: list[dict[str, Any]], offset: int,
) -> dict[str, Any] | None:
    address = _semantic_add_word_offset(stack, offset)
    for index in range(len(writes) - 1, -1, -1):
        write = writes[index]
        if write.get("address") != address:
            continue
        if not all(
            _semantic_word_writes_disjoint(address, later.get("address"))
            for later in writes[index + 1:]
        ):
            return None
        value = write.get("value")
        return value if isinstance(value, dict) else None
    return None

def _semantic_externalize_register_import_call(
    behavior: dict[str, Any], machine_contract: dict[str, Any],
    dispatch_register: str, imported: dict[str, Any],
) -> dict[str, Any] | None:
    outcome = behavior.get("outcome") or {}
    target = outcome.get("target") or {}
    registers = behavior.get("registers") or {}
    writes = behavior.get("writes") or []
    if (
        outcome.get("op") != "indirect_call"
        or target != {"op": "input_reg", "reg": dispatch_register}
        or not isinstance(writes, list) or not writes
        or not isinstance(registers.get("esp"), dict)
    ):
        return None
    final_write = writes[-1]
    if (
        final_write.get("address") != registers["esp"]
        or not isinstance(final_write.get("value"), dict)
        or final_write["value"].get("op") != "constant"
    ):
        return None
    restored_stack = _semantic_call_push_base(registers["esp"])
    if restored_stack is None:
        return None
    prior_writes = writes[:-1]
    arguments: list[dict[str, Any]] = []
    for offset in machine_contract.get("stack_argument_offsets", []):
        argument_address = _semantic_add_word_offset(restored_stack, int(offset))
        argument = _semantic_exact_stack_argument(
            restored_stack, prior_writes, int(offset)
        )
        if argument is None:
            if not all(
                _semantic_word_writes_disjoint(
                    argument_address, write.get("address")
                )
                for write in prior_writes
            ):
                return None
            argument = {
                "op": "read32",
                "address": argument_address,
            }
        arguments.append(argument)
    externalized = json.loads(json.dumps(behavior))
    externalized["registers"]["esp"] = restored_stack
    externalized["writes"] = prior_writes
    externalized["outcome"] = {
        "op": "external_call",
        "import": imported,
        "arguments": arguments,
        "continuation": int(outcome["continuation"]),
    }
    return externalized

def _semantic_input_register_offset(
    expression: Any,
) -> tuple[str, int] | None:
    for register in ("eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp"):
        witness = _register_offset_witness(expression, register)
        if witness is not None:
            word_offset = int(witness[1])
            signed_offset = (
                word_offset if word_offset < 2**31 else word_offset - 2**32
            )
            return register, signed_offset
    return None

def _semantic_affine_word_read(
    register: str, offset: int,
) -> dict[str, Any]:
    def byte_address(byte_offset: int) -> dict[str, Any]:
        absolute_offset = offset + byte_offset
        if absolute_offset == 0:
            return {"op": "input_reg", "reg": register}
        return {
            "op": "add",
            "left": {"op": "input_reg", "reg": register},
            "right": {"op": "constant", "value": absolute_offset},
        }

    byte_reads = [
        {"op": "read8", "address": byte_address(byte_offset)}
        for byte_offset in range(4)
    ]
    return {
        "op": "bit_or",
        "left": {
            "op": "bit_or",
            "left": byte_reads[0],
            "right": {"op": "shift_left", "value": byte_reads[1], "amount": 8},
        },
        "right": {
            "op": "bit_or",
            "left": {"op": "shift_left", "value": byte_reads[2], "amount": 16},
            "right": {"op": "shift_left", "value": byte_reads[3], "amount": 24},
        },
    }

def _semantic_word_read(expression: dict[str, Any]) -> tuple[dict[str, Any], bool] | None:
    if expression.get("op") == "read32" and isinstance(expression.get("address"), dict):
        return expression["address"], False
    left = expression.get("left")
    first_byte = left.get("left") if isinstance(left, dict) else None
    first_address = first_byte.get("address") if isinstance(first_byte, dict) else None
    if not isinstance(first_address, dict):
        return None
    affine = _semantic_input_register_offset(first_address)
    if affine is None or affine[1] + 4 > 2**32:
        return None
    register, offset = affine
    if expression != _semantic_affine_word_read(register, offset):
        return None
    return first_address, True

def _external_argument_relation_claims(
    source: dict[str, Any], original_arguments: Any, candidate_arguments: Any,
) -> tuple[list[dict[str, Any]] | None, str | None]:
    if not isinstance(original_arguments, list) or not isinstance(candidate_arguments, list):
        return None, "external call arguments were not recovered as expression lists"
    if len(original_arguments) != len(candidate_arguments):
        return None, "original and candidate external argument counts differ"
    claims: list[dict[str, Any]] = []
    for argument_index, (original, candidate) in enumerate(zip(
        original_arguments, candidate_arguments, strict=True
    )):
        if not isinstance(original, dict) or not isinstance(candidate, dict):
            return None, f"external argument {argument_index} is not a symbolic expression"
        original_constant = _semantic_constant_word(original)
        candidate_constant = _semantic_constant_word(candidate)
        if original_constant is not None and original_constant == candidate_constant:
            claims.append({
                "kind": "self",
                "original_expression": original,
                "candidate_expression": candidate,
            })
            continue
        original_register = _semantic_input_register_offset(original)
        candidate_register = _semantic_input_register_offset(candidate)
        if original_register is not None and candidate_register is not None:
            matches = [
                relation for relation in source.get("input_relations", [])
                if str(relation["original"]) == original_register[0]
                and str(relation["candidate"]) == candidate_register[0]
            ]
            if len(matches) != 1:
                return None, (
                    f"external argument {argument_index} lacks one unambiguous source "
                    "register relation"
                )
            relation = matches[0]
            if original_register[1] != candidate_register[1]:
                return None, (
                    f"external argument {argument_index} has differing affine register "
                    "offsets"
                )
            if relation["relation"] == "exact" or (
                relation["relation"] == "related_word" and original_register[1] == 0
            ):
                claims.append({
                    "kind": "register_word",
                    "relation": relation,
                    "offset": original_register[1],
                    "original_expression": original,
                    "candidate_expression": candidate,
                })
                continue
            return None, (
                f"external argument {argument_index} uses affine offset "
                f"{original_register[1]} from a {relation['relation']} register; "
                "establish an exact relation or a checked mapped-range witness"
            )
        original_read = _semantic_word_read(original)
        candidate_read = _semantic_word_read(candidate)
        if original_read is None or candidate_read is None:
            return None, (
                f"external argument {argument_index} is neither a paired constant, "
                "a checked register word, nor a checked memory word read"
            )
        original_read_address, original_assembled = original_read
        candidate_read_address, candidate_assembled = candidate_read
        original_address = _semantic_input_register_offset(original_read_address)
        candidate_address = _semantic_input_register_offset(candidate_read_address)
        if original_address is None or candidate_address is None:
            return None, (
                f"external argument {argument_index} memory read address is not an "
                "affine input-register expression"
            )
        stack_matches = [
            window for window in source.get("stack_windows", [])
            if str(window["original_register"]) == original_address[0]
            and str(window["candidate_register"]) == candidate_address[0]
            and original_address[1] == candidate_address[1]
            and original_address[1] >= -int(window.get("bytes_below", 0))
            and original_address[1] + 4 <= int(window.get("bytes_above", 0))
        ]
        if len(stack_matches) == 1:
            claims.append({
                "kind": "stack_word_read",
                "window": stack_matches[0],
                "offset": original_address[1],
                "original_assembled_read": original_assembled,
                "candidate_assembled_read": candidate_assembled,
                "original_expression": original,
                "candidate_expression": candidate,
            })
            continue
        if len(stack_matches) > 1:
            return None, (
                f"external argument {argument_index} matches multiple source stack windows"
            )
        if original_assembled or candidate_assembled:
            return None, (
                f"external argument {argument_index} assembled memory read lacks one "
                "checked source stack-window relation"
            )
        matches = [
            relation for relation in source.get("input_dynamic_range_relations", [])
            if str(relation["original"]) == original_address[0]
            and str(relation["candidate"]) == candidate_address[0]
        ]
        if len(matches) != 1:
            return None, (
                f"external argument {argument_index} lacks one unambiguous source "
                "dynamic-range relation"
            )
        relation = matches[0]
        original_offset = int(relation.get("original_offset", 0)) + original_address[1]
        candidate_offset = int(relation.get("candidate_offset", 0)) + candidate_address[1]
        if (
            original_offset >= 2**32
            or candidate_offset >= 2**32
            or original_offset != candidate_offset
        ):
            return None, (
                f"external argument {argument_index} resolves to differing or wrapped "
                "dynamic-range offsets"
            )
        word = {"offset": original_offset, "kind": "relatedWord"}
        if word not in relation.get("required_words", []):
            return None, (
                f"external argument {argument_index} requires relatedWord at dynamic "
                f"range offset {original_offset}; add it to the source relation and "
                "prove it on every incoming edge"
            )
        claims.append({
            "kind": "dynamic_related_word_read",
            "range_relation": relation,
            "word_relation": word,
            "original_read_offset": original_address[1],
            "candidate_read_offset": candidate_address[1],
            "original_expression": original,
            "candidate_expression": candidate,
        })
    return claims, None

def _external_call_site_candidates(
    contract: dict[str, Any],
    behaviors: list[dict[str, Any]],
    register_relations: dict[str, Any],
    import_call_candidates: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    contracts_by_target = {
        (
            str(item["import"]["dll"]).lower(),
            "symbol" if "symbol" in item["import"] else "ordinal",
            item["import"].get("symbol", item["import"].get("ordinal")),
        ): item
        for item in contract.get("machine_import_call_contracts", [])
    }
    indirect_calls_by_edge: dict[tuple[int, int], list[dict[str, Any]]] = {}
    for call in import_call_candidates or []:
        key = (
            int(call["source_region_index"]),
            int(call["continuation_region_index"]),
        )
        indirect_calls_by_edge.setdefault(key, []).append(call)
    candidates: list[dict[str, Any]] = []
    gaps: list[dict[str, Any]] = []
    for edge_index, edge in enumerate(register_relations.get("edges", [])):
        if not edge.get("environment_barrier"):
            continue
        source_index = int(edge["source_region_index"])
        target_index = int(edge["target_region_index"])
        source = contract["regions"][source_index]
        decoded_original = behaviors[source_index]["original_ir"]
        decoded_candidate = behaviors[source_index]["candidate_ir"]
        original = decoded_original
        candidate = decoded_candidate
        original_outcome = decoded_original.get("outcome") or {}
        candidate_outcome = decoded_candidate.get("outcome") or {}
        original_target = _semantic_external_target_identity(
            original_outcome.get("import")
        )
        candidate_target = _semantic_external_target_identity(
            candidate_outcome.get("import")
        )
        machine_contract = contracts_by_target.get(original_target)
        dispatch_profile = "decoded_external_call"
        dispatch_registers = None
        argument_claims = None
        blocker = None
        paired_direct = (
            original_outcome.get("op") == "external_call"
            and candidate_outcome.get("op") == "external_call"
        )
        paired_indirect = (
            original_outcome.get("op") == "indirect_call"
            and candidate_outcome.get("op") == "indirect_call"
        )
        if paired_indirect:
            indirect_matches = indirect_calls_by_edge.get(
                (source_index, target_index), []
            )
            if len(indirect_matches) != 1:
                blocker = (
                    "register-held import call lacks one unambiguous checked "
                    "import-register target"
                )
            else:
                indirect = indirect_matches[0]
                imported = indirect["import"]
                original_target = (
                    str(imported["dll"]).lower(),
                    "symbol" if "symbol" in imported else "ordinal",
                    imported.get("symbol", imported.get("ordinal")),
                )
                candidate_target = original_target
                machine_contract = contracts_by_target.get(original_target)
                if machine_contract is None:
                    blocker = "no unique machine import call contract matches the call"
                else:
                    original = _semantic_externalize_register_import_call(
                        decoded_original, machine_contract,
                        str(indirect["original_register"]), imported,
                    )
                    candidate = _semantic_externalize_register_import_call(
                        decoded_candidate, machine_contract,
                        str(indirect["candidate_register"]), imported,
                    )
                    if original is None or candidate is None:
                        blocker = (
                            "register-held import call does not have the checked "
                            "decoder call-push and stack-argument shape"
                        )
                    else:
                        original_outcome = original["outcome"]
                        candidate_outcome = candidate["outcome"]
                        dispatch_profile = "checked_import_register"
                        dispatch_registers = {
                            "original": str(indirect["original_register"]),
                            "candidate": str(indirect["candidate_register"]),
                        }
        elif not paired_direct:
            blocker = "external edge is not a paired returning import call"
        if blocker is None:
            if original_target is None or original_target != candidate_target:
                blocker = "original and candidate import identities do not match"
            elif machine_contract is None:
                blocker = "no unique machine import call contract matches the call"
            elif edge.get("original_guard") != {"op": "bool_constant", "value": True} or (
                edge.get("candidate_guard") != {"op": "bool_constant", "value": True}
            ):
                blocker = "external call guard is not unconditionally paired"
            elif original_outcome.get("arguments") != candidate_outcome.get("arguments"):
                blocker = "original and candidate external arguments differ"
            elif original.get("x87") != candidate.get("x87"):
                blocker = "external call setup has differing x87 transformations"
            else:
                argument_claims, argument_blocker = _external_argument_relation_claims(
                    source,
                    original_outcome.get("arguments", []),
                    candidate_outcome.get("arguments", []),
                )
                if argument_blocker is not None:
                    blocker = argument_blocker

        boundary_windows: list[dict[str, Any]] = []
        if blocker is None:
            for window in contract["regions"][source_index].get(
                "stack_windows", []
            ):
                original_register = str(window["original_register"])
                candidate_register = str(window["candidate_register"])
                original_offset = _register_offset_witness(
                    (original.get("registers") or {}).get(original_register),
                    original_register,
                )
                candidate_offset = _register_offset_witness(
                    (candidate.get("registers") or {}).get(candidate_register),
                    candidate_register,
                )
                if original_offset is None or candidate_offset is None:
                    blocker = "call boundary stack register is not affine"
                    break
                original_delta = int(original_offset[1])
                candidate_delta = int(candidate_offset[1])
                if original_delta >= 2**31:
                    original_delta -= 2**32
                if candidate_delta >= 2**31:
                    candidate_delta -= 2**32
                if original_delta != candidate_delta:
                    blocker = "paired call boundary stack deltas differ"
                    break
                boundary_windows.append({
                    "range_id": int(window["range_id"]),
                    "original_register": original_register,
                    "candidate_register": candidate_register,
                    "bytes_below": max(
                        int(window.get("bytes_below", 0)) + original_delta, 0
                    ),
                    "bytes_above": max(
                        int(window.get("bytes_above", 0)) - original_delta, 0
                    ),
                    "source": "external_call_boundary_affine_transfer",
                })
        boundary_invariant = {
            "register_relations": [],
            "import_register_relations": source.get(
                "output_import_relations", []
            ),
            "dynamic_register_range_relations": source.get(
                "output_dynamic_range_relations", []
            ),
            "bounds": [],
            "flag_bits": source.get("flag_outputs", []),
            "address_separations": [],
            "stack_windows": boundary_windows,
        }
        import_transfer_claims: list[dict[str, Any]] = []
        dynamic_transfer_claims: list[dict[str, Any]] = []
        if blocker is None and dispatch_profile == "checked_import_register":
            boundary_invariant["register_relations"] = []
            boundary_invariant["import_register_relations"] = []
            boundary_invariant["dynamic_register_range_relations"] = []
            original_registers = original.get("registers") or {}
            candidate_registers = candidate.get("registers") or {}
            for register in machine_contract.get("preserved_registers", []):
                original_expression = original_registers.get(register) or {}
                candidate_expression = candidate_registers.get(register) or {}
                if (
                    original_expression.get("op") != "input_reg"
                    or candidate_expression.get("op") != "input_reg"
                ):
                    blocker = (
                        f"preserved register {register} is not an identity transfer at "
                        "the register-held import boundary"
                    )
                    break
                source_original = str(original_expression["reg"])
                source_candidate = str(candidate_expression["reg"])
                imports = [
                    relation for relation in source.get("input_import_relations", [])
                    if str(relation["original"]) == source_original
                    and str(relation["candidate"]) == source_candidate
                ]
                dynamics = [
                    relation for relation in source.get(
                        "input_dynamic_range_relations", []
                    )
                    if str(relation["original"]) == source_original
                    and str(relation["candidate"]) == source_candidate
                ]
                ordinary = [
                    relation for relation in source.get("input_relations", [])
                    if str(relation["original"]) == source_original
                    and str(relation["candidate"]) == source_candidate
                ]
                if len(imports) == 1:
                    target_relation = {
                        "original": str(register), "candidate": str(register),
                        "import": imports[0]["import"],
                    }
                    boundary_invariant["import_register_relations"].append(
                        target_relation
                    )
                    import_transfer_claims.append({
                        "import": imports[0]["import"],
                        "source_original_register": source_original,
                        "source_candidate_register": source_candidate,
                        "target_original_register": str(register),
                        "target_candidate_register": str(register),
                    })
                elif len(dynamics) == 1:
                    target_relation = json.loads(json.dumps(dynamics[0]))
                    target_relation["original"] = str(register)
                    target_relation["candidate"] = str(register)
                    boundary_invariant["dynamic_register_range_relations"].append(
                        target_relation
                    )
                    dynamic_transfer_claims.append({
                        "source_relation": dynamics[0],
                        "target_relation": target_relation,
                    })
                elif len(ordinary) == 1:
                    target_relation = {
                        "original": str(register), "candidate": str(register),
                        "relation": ordinary[0]["relation"],
                    }
                    boundary_invariant["register_relations"].append(target_relation)
                else:
                    blocker = (
                        f"preserved register {register} lacks one source relation at "
                        "the register-held import boundary"
                    )
                    break
        if blocker is None and boundary_invariant["flag_bits"] not in ([], [10]):
            blocker = "external boundary flag transfer is not limited to preserved DF"
        if (
            blocker is None
            and boundary_invariant["flag_bits"] == [10]
            and 10 not in source.get("flag_inputs", [])
        ):
            blocker = "external boundary requires DF without a source DF relation"

        covered_registers = {
            (window["original_register"], window["candidate_register"])
            for window in boundary_windows
        }
        if dispatch_profile != "checked_import_register":
            boundary_invariant["register_relations"] = [
                relation for relation in source.get("output_relations", [])
                if (relation["original"], relation["candidate"])
                not in covered_registers
            ]
        selected_output_claims: list[dict[str, Any]] = []
        if blocker is None:
            output_claims = register_relations["regions"][source_index].get(
                "output_claims", []
            )
            for relation in boundary_invariant["register_relations"]:
                matches = [
                    claim for claim in output_claims
                    if claim.get("output") == relation
                    and claim.get("kind") != "exact_memory"
                ]
                if len(matches) != 1:
                    blocker = (
                        "boundary register relation lacks one non-memory output claim"
                    )
                    break
                selected_output_claims.append(matches[0])
        if (
            blocker is None
            and boundary_invariant["import_register_relations"]
            and dispatch_profile != "checked_import_register"
        ):
            blocker = "external boundary import-register transfer is not implemented"
        if (
            blocker is None
            and boundary_invariant["dynamic_register_range_relations"]
            and dispatch_profile != "checked_import_register"
        ):
            blocker = "external boundary dynamic-register transfer is not implemented"

        stack_transfer_claims = None
        if blocker is None:
            stack_transfer_claims = _stack_window_transfer_claims(
                source,
                {"stack_windows": boundary_windows},
                {"original_ir": original, "candidate_ir": candidate},
            )
            if stack_transfer_claims is None:
                blocker = "external boundary stack window transfer is not affine"
        if blocker is not None:
            def import_value(
                identity: tuple[str, str, str | int] | None,
            ) -> dict[str, Any] | None:
                if identity is None:
                    return None
                imported: dict[str, Any] = {"dll": identity[0]}
                imported[identity[1]] = identity[2]
                return imported

            gaps.append({
                "edge_index": edge_index,
                "source_region_index": source_index,
                "target_region_index": target_index,
                "reason": blocker,
                "original_import": import_value(original_target),
                "candidate_import": import_value(candidate_target),
                "dispatch_profile": dispatch_profile,
            })
            continue

        candidates.append({
            "id": edge_index,
            "edge_index": edge_index,
            "source_region_index": source_index,
            "target_region_index": target_index,
            "source_target_id": int(source["numeric_id"]),
            "continuation_target_id": int(
                contract["regions"][target_index]["numeric_id"]
            ),
            "machine_contract_id": int(machine_contract["id"]),
            "dispatch_profile": dispatch_profile,
            "dispatch_registers": dispatch_registers,
            "argument_relation_claims": argument_claims,
            "import_transfer_claims": import_transfer_claims,
            "dynamic_transfer_claims": dynamic_transfer_claims,
            "boundary_invariant": boundary_invariant,
            "register_output_claims": selected_output_claims,
            "stack_transfer_claims": stack_transfer_claims,
            "argument_values": [
                _semantic_constant_word(argument)
                for argument in original_outcome.get("arguments", [])
            ],
            "argument_expressions": original_outcome.get("arguments", []),
            "proof_profile": (
                "paired_constant_arguments_external_call_v1"
                if all(claim["kind"] == "self" for claim in argument_claims or [])
                else "paired_relational_arguments_external_call_v1"
            ),
            "status": "candidate_requires_lean_replay",
        })
    return {
        "format": "stage-a-relational-external-call-sites-v1",
        "status": "incomplete" if gaps else "candidate_requires_lean_replay",
        "candidates": candidates,
        "gaps": gaps,
        "counts": {
            "candidates": len(candidates),
            "gaps": len(gaps),
        },
    }

def _register_offset_witness(
    expression: Any,
    register: str = "esp",
) -> tuple[dict[str, Any], int] | None:
    if not isinstance(expression, dict):
        return None
    operation = expression.get("op")
    if operation == "input_reg":
        if expression.get("reg") != register:
            return None
        return {"kind": "input"}, 0
    if operation not in {"add", "sub"}:
        return None
    left = expression.get("left")
    right = expression.get("right")
    witness_kind = "add_right" if operation == "add" else "sub_right"
    if (
        operation == "add"
        and isinstance(left, dict)
        and left.get("op") == "constant"
    ):
        left, right = right, left
        witness_kind = "add_left"
    if not isinstance(right, dict) or right.get("op") != "constant":
        return None
    value = int(right.get("value", -1))
    if not 0 <= value < 2**32:
        return None
    prior = _register_offset_witness(left, register)
    if prior is None:
        return None
    prior_witness, prior_offset = prior
    offset = (
        prior_offset + value
        if operation == "add"
        else prior_offset - value
    ) % 2**32
    return {
        "kind": witness_kind,
        "prior": prior_witness,
        "value": value,
    }, offset


def _machine_import_call_contract_analysis(
    contract: dict[str, Any],
    behaviors: list[dict[str, Any]],
) -> dict[str, Any]:
    contracts_by_target = {
        (
            str(item["import"]["dll"]).lower(),
            "symbol" if "symbol" in item["import"] else "ordinal",
            item["import"].get("symbol", item["import"].get("ordinal")),
        ): item
        for item in contract.get("machine_import_call_contracts", [])
    }
    calls: list[dict[str, Any]] = []
    for region_index, behavior_pair in enumerate(behaviors):
        original_outcome = behavior_pair["original_ir"].get("outcome") or {}
        candidate_outcome = behavior_pair["candidate_ir"].get("outcome") or {}
        original_operation = original_outcome.get("op")
        candidate_operation = candidate_outcome.get("op")
        if original_operation not in {"external_call", "external_jump"} and \
                candidate_operation not in {"external_call", "external_jump"}:
            continue
        original_target = _semantic_external_target_identity(
            original_outcome.get("import")
        )
        candidate_target = _semantic_external_target_identity(
            candidate_outcome.get("import")
        )
        matched_contract = (
            contracts_by_target.get(original_target)
            if original_target is not None and original_target == candidate_target
            else None
        )
        original_arguments = original_outcome.get("arguments")
        candidate_arguments = candidate_outcome.get("arguments")
        expected_arguments = (
            len(matched_contract["stack_argument_offsets"])
            if matched_contract is not None else None
        )
        arguments_recovered = (
            expected_arguments is not None
            and isinstance(original_arguments, list)
            and isinstance(candidate_arguments, list)
            and len(original_arguments) == expected_arguments
            and len(candidate_arguments) == expected_arguments
        )
        calls.append({
            "region_index": region_index,
            "region_id": contract["regions"][region_index]["id"],
            "original_operation": original_operation,
            "candidate_operation": candidate_operation,
            "original_import": (
                list(original_target) if original_target is not None else None
            ),
            "candidate_import": (
                list(candidate_target) if candidate_target is not None else None
            ),
            "contract_id": (
                int(matched_contract["id"]) if matched_contract is not None else None
            ),
            "expected_argument_words": expected_arguments,
            "original_arguments": original_arguments,
            "candidate_arguments": candidate_arguments,
            "arguments_recovered": arguments_recovered,
            "status": (
                "candidate_requires_lean_replay"
                if original_operation == candidate_operation
                and original_target == candidate_target
                and arguments_recovered
                else "incomplete"
            ),
        })
    return {
        "format": "stage-a-relational-machine-import-calls-v1",
        "status": "incomplete",
        "contracts": contract.get("machine_import_call_contracts", []),
        "calls": calls,
        "counts": {
            "contracts": len(contract.get("machine_import_call_contracts", [])),
            "call_sites": len(calls),
            "contracted_call_sites": sum(call["contract_id"] is not None for call in calls),
            "argument_recovery_candidates": sum(
                call["status"] == "candidate_requires_lean_replay" for call in calls
            ),
            "incomplete_call_sites": sum(
                call["status"] == "incomplete" for call in calls
            ),
        },
    }

def _semantic_affine_base_offset(expression: Any) -> tuple[Any, int] | None:
    if not isinstance(expression, dict):
        return None
    operation = expression.get("op")
    right = expression.get("right")
    if operation in {"add", "sub"} and isinstance(right, dict) \
            and right.get("op") == "constant":
        value = _integer(right.get("value"))
        if value is None or not 0 <= value < 2**32:
            return None
        return (
            expression.get("left"),
            (value if operation == "add" else 2**32 - value) % 2**32,
        )
    return expression, 0

def _attach_machine_import_call_contract_analysis(
    proof_ir: dict[str, Any], analysis: dict[str, Any]
) -> dict[str, Any]:
    obligations: list[dict[str, Any]] = []
    for call in analysis["calls"]:
        replay = call["status"] == "candidate_requires_lean_replay"
        obligations.append({
            "id": f"machine-import-call:{call['region_index']}",
            "kind": "machine_import_call_boundary",
            "status": call["status"],
            "region_id": call["region_id"],
            "region_index": call["region_index"],
            "contract_id": call["contract_id"],
            "repair_class": (
                "checked_stack_argument_recovery"
                if replay else "missing_machine_import_call_contract"
            ),
            "blocker": None if replay else (
                "the paired external exit lacks one unique machine-level call contract, "
                "matching import identity, or the declared number of recovered arguments"
            ),
            "next_action": (
                "replay the exact decoded outcome and stack-after-local-writes argument "
                "expressions in Lean, then instantiate paired environment refinement"
                if replay else
                "declare stack argument offsets, stack result delta, preserved/clobbered "
                "registers, and memory/world effects for this imported target"
            ),
            "analysis": call,
        })
    attached = dict(proof_ir)
    attached["machine_import_call_summary"] = analysis["counts"]
    attached["obligations"] = [*proof_ir["obligations"], *obligations]
    attached["families"] = [
        *proof_ir["families"],
        {
            "family": "machine_import_call_boundaries",
            "status": "not_applicable" if not obligations else "incomplete",
        },
    ]
    attached["status"] = "incomplete"
    return attached

def _attach_external_call_site_analysis(
    proof_ir: dict[str, Any], analysis: dict[str, Any]
) -> dict[str, Any]:
    obligations = [
        {
            "id": f"external-call-edge:{site['edge_index']}",
            "kind": "external_call_product_edge_refinement",
            "status": "pending_lean",
            "edge_id": int(site["edge_index"]),
            "source_region_index": int(site["source_region_index"]),
            "target_region_index": int(site["target_region_index"]),
            "machine_contract_id": int(site["machine_contract_id"]),
            "repair_class": "paired_external_call_refinement",
            "blocker": (
                "the generated local call-boundary and paired-environment refinement "
                "theorems have not yet been replayed by Lean"
            ),
            "next_action": (
                "build the generated external-call edge theorem, then include its "
                "product-edge refinement in the checked external-call certificate"
            ),
            "analysis": site,
        }
        for site in analysis["candidates"]
    ]
    gap_actions = {
        "no unique machine import call contract matches the call": (
            "declare one machine-level contract for the matched import, including "
            "argument words, stack cleanup, register policy, memory effect, and world effect"
        ),
        "external edge is not a paired returning import call": (
            "recover a paired returning import-call outcome or classify the external "
            "transition under a separately checked event profile"
        ),
        "external arguments are not yet checked constant expressions": (
            "prove the original and candidate argument expressions related at the call "
            "boundary and emit their explicit relation witnesses"
        ),
        "boundary register relation lacks one non-memory output claim": (
            "establish one unambiguous checked output claim for every boundary register"
        ),
    }

    def gap_next_action(gap: dict[str, Any]) -> str:
        reason = str(gap["reason"])
        if reason == "no unique machine import call contract matches the call":
            imported = gap.get("original_import")
            identity = None
            if isinstance(imported, dict):
                name = imported.get("symbol", imported.get("ordinal"))
                if imported.get("dll") is not None and name is not None:
                    identity = f"{imported['dll']}!{name}"
            prefix = f"declare one machine-level contract for {identity}; " if identity else ""
            return (
                prefix
                + "select a reviewed pe32-cdecl-v1 or pe32-stdcall-v1 ABI template, "
                "provide argument_words, and explicitly declare memory and world effects"
            )
        if reason in gap_actions:
            return gap_actions[reason]
        if "external argument" in reason or "dynamic range offset" in reason:
            return (
                "prove the original and candidate argument expressions related at the "
                "call boundary and emit their explicit relation witnesses"
            )
        if "import-register target" in reason:
            return (
                "close the decoded indirect target through one checked ImportAddressPair "
                "and source import-register invariant"
            )
        return "supply the missing machine-level external-call evidence and regenerate"

    obligations.extend(
        {
            "id": f"external-call-edge:{gap['edge_index']}",
            "kind": "external_call_product_edge_refinement",
            "status": "incomplete",
            "edge_id": int(gap["edge_index"]),
            "source_region_index": int(gap["source_region_index"]),
            "target_region_index": int(gap["target_region_index"]),
            "repair_class": "external_call_contract_gap",
            "blocker": str(gap["reason"]),
            "next_action": gap_next_action(gap),
            "analysis": gap,
        }
        for gap in analysis["gaps"]
    )
    attached = dict(proof_ir)
    attached["external_call_sites"] = analysis
    attached["external_call_summary"] = analysis["counts"]
    attached["obligations"] = [*proof_ir["obligations"], *obligations]
    attached["families"] = [
        *proof_ir["families"],
        {
            "family": "paired_external_environment_refinement",
            "status": "not_applicable" if not obligations else "incomplete",
        },
    ]
    attached["status"] = "incomplete"
    return attached
