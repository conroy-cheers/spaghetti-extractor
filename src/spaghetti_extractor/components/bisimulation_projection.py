"""Canonical machine-projection expressions shared by proof construction."""
from typing import Mapping
from .bisimulation_support import BisimulationRefinementError, mapping as _mapping
from .machine_storage import register_relative_address, scalar_storage_address


def exact_stack_address_expression(offset: int, *, state: str) -> str:
    operator = "+" if offset >= 0 else "-"
    return f"(({state}.esp) {operator} UINT32_C({abs(offset)}))"


MACHINE_FACT_POLICY = "checked-current-machine-cut-facts-v1"
STACK_FACT_POLICY = "checked-current-stack-machine-cut-facts-v2"


def machine_fact_stack(relation):
    return relation.expression.get('op') == 'exact_projection' and any(
        projection['kind'] == 'stack' for projection in
        (relation.projection.payload, relation.expression['projection']))


def machine_fact_expression(projection, *, state, direction):
    """Read a current stack word only after checking its non-wrapping address."""
    projection = getattr(projection, 'payload', projection)
    if projection['kind'] == 'stack':
        return (f"spx_proof_exact_{direction}_stack_read({state}.esp, "
                f"INT64_C({projection['offset']}), UINT32_C({projection['width'] // 8}))")
    return _projection_expression(projection, state=state, read=f'spx_proof_exact_{direction}_read')


def machine_fact_read_descriptions(sync, direction):
    facts = [relation for relation in sync.derived if relation.expression.get('op') == 'exact_projection']
    reads = any(projection['kind'] in {'static_slot', 'stack'} for relation in facts
                for projection in (relation.projection.payload, relation.expression['projection']))
    return ([f'spx-bisimulation-exact-{direction}-read'] if reads else []) + (
        [f'spx-bisimulation-exact-{direction}-stack-range'] if any(map(machine_fact_stack, facts)) else [])


def machine_fact_metadata(operation):
    policy = STACK_FACT_POLICY if any(machine_fact_stack(relation)
        for sync in operation.syncs for relation in sync.derived) else MACHINE_FACT_POLICY
    return ({"machine_fact_policy": policy} if any(
        relation.expression.get("op") == "exact_projection"
        for sync in operation.syncs for relation in sync.derived) else {})


def validate_machine_fact_model(planned, model):
    from .inductive_relation import CutpointDerivedRelationV1
    facts = [CutpointDerivedRelationV1.parse(row, "planned machine fact")
             for sync in planned["source"]["syncs"] for row in sync["derived"]
             if row["expression"].get("op") == "exact_projection"]
    if "machine_image" in model:
        for fact in facts:
            for projection in (fact.projection.payload, fact.expression["projection"]):
                if (projection["kind"] == "static_slot" and
                        projection["rva"] + projection["width"] // 8 > model["machine_image"]["image_size"]):
                    raise ValueError("machine fact image scalar is outside the proof image")
    policy = STACK_FACT_POLICY if any(map(machine_fact_stack, facts)) else MACHINE_FACT_POLICY
    expected = {"machine_fact_policy": policy} if facts else {}
    actual = {key: model[key] for key in ("machine_fact_policy",) if key in model}
    if actual != expected:
        raise ValueError("current machine fact transport differs from the proof plan")
    if 'obligation_id' in model and policy == STACK_FACT_POLICY:
        targets = {edge['target_unit_id'] for edge in planned['exact']['control_edges']
                   if edge['source_unit_id'] in model['selected_unit_ids']}
        for sync in planned['source']['syncs']:
            for raw in sync['derived']:
                if raw['expression'].get('op') != 'exact_projection':
                    continue
                fact = CutpointDerivedRelationV1.parse(raw, 'planned stack machine fact')
                reads = any(p['kind'] in {'stack', 'static_slot'}
                            for p in (fact.projection.payload, fact.expression['projection']))
                required = set()
                for direction, active in (('input', model['obligation_id'] == 'sync:' + sync['id']),
                                          ('output', sync['exact_unit_id'] in targets)):
                    if active:
                        if reads:
                            required.add(f'spx-bisimulation-exact-{direction}-read')
                        if machine_fact_stack(fact):
                            required.add(f'spx-bisimulation-exact-{direction}-stack-range')
                        if direction == 'output':
                            required.add(f"spx-bisimulation-derived:{sync['id']}:{fact.identity}")
                if not required <= set(model['required_assertion_descriptions']):
                    raise ValueError('stack machine fact omits its checked read, range or predecessor assertion')
    return expected


def incoming_machine_relations(sync, *, state: str) -> list[str]:
    """Admit checked current machine facts before either region executes.

    These are existing derived cut relations, asserted at every predecessor.
    Keep the source-header assumption and assertion too. Image scalar reads use
    the checked input reader, and their image bounds are validated by the
    harness. Source-dependent relations still wait for source reconstruction.
    """
    lines = []
    for relation in sync.derived:
        projection = relation.projection.payload
        op = relation.expression.get("op")
        if op == "exact_stack_address" and projection.get("kind") == "register":
            right = exact_stack_address_expression(relation.expression["offset"], state=state)
        elif (op == 'const' and relation.expression.get('width') == 32
              and projection.get('kind') == 'register' and projection.get('width') == 32):
            # A checked register literal is source-independent too. Delaying it
            # until the portable barrier leaves earlier exact service prefixes
            # with an unconstrained register (for example a known zero store).
            right = f"UINT32_C({relation.expression['value']})"
        elif op == "exact_projection":
            right = machine_fact_expression(relation.expression["projection"], state=state, direction='input')
        else:
            continue
        left = (machine_fact_expression(projection, state=state, direction='input') if op == 'exact_projection'
                else _projection_expression(projection, state=state, read="spx_proof_exact_input_read"))
        lines.append(f"  __CPROVER_assume(({left}) == ({right}));")
    return lines


def _captured_parameter_view(capture) -> Mapping[str, object] | None:
    raw = getattr(capture.projection, "payload", capture.projection)
    if (capture.kind != "parameter" or capture.mode != "machine_codec"
            or not isinstance(raw, Mapping) or raw.get("kind") not in {"view", "bytes_view"}):
        return None
    return raw


def _projection_expression(value: object, *, state: str, read: str) -> str | None:
    if value is None:
        return None
    payload = getattr(value, "payload", value)
    row = _mapping(payload, "machine projection")
    kind = row.get("kind")
    width = int(row.get("width", 32))
    if not 1 <= width <= 32 or width % 8 != 0:
        raise BisimulationRefinementError("machine projection width is unsupported")
    mask = "" if width == 32 else f" & UINT32_C({(1 << width) - 1})"
    if kind == "offset":
        return register_relative_address(row, state=state)
    if kind == 'flag':
        from .machine_binding import MachineProjectionV1
        flag = MachineProjectionV1.parse(row).payload['flag']
        # Runtime flags occupy uint32 slots. Read the complete slot: masking
        # would hide noncanonical values from the outgoing transport check.
        return f'({state}.{flag})'
    if kind == "register":
        register = str(row.get("register"))
        if register not in {
            "eax",
            "ebx",
            "ecx",
            "edx",
            "esi",
            "edi",
            "ebp",
            "esp",
        }:
            raise BisimulationRefinementError(
                "machine projection register is unsupported"
            )
        return f"(({state}.{register}){mask})"
    if kind == "stack":
        return (
            f"{read}({state}.esp + UINT32_C({int(row.get('offset', 0))}), "
            f"UINT32_C({width // 8}))"
        )
    if kind == "service_output":
        if read == "spx_proof_exact_output_read":
            return (
                "spx_proof_exact_call_output("
                f"UINT32_C({int(row.get('call_index', -1))}), "
                f"UINT32_C({int(row.get('output_index', -1))}))"
            )
        return _projection_expression(row.get("fallback"), state=state, read=read)
    if kind == "static_slot":
        return (
            f"{read}(SPX_PROOF_IMAGE_BASE + UINT32_C({int(row.get('rva', 0))}), "
            f"UINT32_C({width // 8}))"
        )
    if kind == "memory":
        address, storage_width = scalar_storage_address(row, state=state,
                                                       image_base="SPX_PROOF_IMAGE_BASE")
        return f"{read}({address}, UINT32_C({storage_width // 8}))"
    if kind == "constant":
        return f"UINT32_C({int(row.get('value', 0)) & 0xFFFFFFFF})"
    if kind in {"view", "bytes_view"}:
        return _projection_expression(row.get("base"), state=state, read=read)
    if kind in {"reference", "resource", "callback_handle"}:
        return _projection_expression(row.get("source"), state=state, read=read)
    raise BisimulationRefinementError(
        f"machine projection kind {kind!r} is unsupported"
    )
