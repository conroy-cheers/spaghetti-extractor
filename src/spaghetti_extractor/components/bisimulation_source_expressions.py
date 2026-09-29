"""Render source expressions, cut-invariant projections and memory readers."""
from __future__ import annotations

from typing import Mapping, Sequence
from .bisimulation_support import BisimulationRefinementError, mapping as _mapping
from .bisimulation_projection import _projection_expression, exact_stack_address_expression
from .bisimulation_reference_transport import view_address_expression

def _incoming_scalar_invariant(sync, *, unsigned_words: Sequence[str]) -> list[str]:
    """Admit a type-preserving projection of an existing cut invariant early.

    Source restoration, its invariant assumption, and all predecessor capture,
    roundtrip and invariant assertions remain. Only compiler-confirmed unsigned
    words with identity codecs can be substituted. Unsupported expressions keep
    the existing source-side admission; no partial Boolean rewrite is permitted.
    """
    if sync is None or sync.source_bindings:
        return []
    projections = {}
    for capture in sync.captures:
        # Avoid restoration through aliased lvalues or logical definitions.
        if capture.mode != 'machine_codec':
            return []
        if capture.kind == 'source_state' and (
                capture.encoding not in [{"op": op, "name": capture.identity}
                                         for op in ('state_input', 'loop_variable')]
                or capture.decoding != {"op": "projected_value"}):
            return []
        projection = getattr(capture.projection, 'payload', capture.projection)
        if (capture.identity in unsigned_words and isinstance(projection, Mapping)
                and projection.get('kind') in {'register', 'stack', 'static_slot'}
                and projection.get('width') == 32 and projection.get('at') == 'entry'
                and capture.encoding in [{"op": op, "name": capture.identity}
                                         for op in ('parameter', 'state_input', 'loop_variable')]):
            projections[capture.identity] = {'op': 'exact_projection', 'projection': projection}

    class Unsupported(Exception):
        pass

    def project(row):
        op = row['op']
        if op in {'parameter', 'state_input', 'loop_variable'}:
            if row['name'] not in projections:
                raise Unsupported
            return projections[row['name']]
        if op == 'const' and row['width'] <= 32:
            return row
        if op in {'true', 'false'}:
            return row
        if op in {'add32', 'sub32', 'mul32', 'and32', 'or32', 'xor32',
                  'eq', 'ult32', 'ule32', 'and', 'or', 'and_bool', 'or_bool', 'not', 'ite'}:
            return {'op': op, 'args': [project(child) for child in row['args']]}
        raise Unsupported

    try:
        projected = project(sync.invariant)
    except Unsupported:
        return []
    if projected['op'] in {'true', 'false'}:
        return []
    expression = _render_source_expression(projected, memory='input')
    return [f'  /* Existing unsigned scalar cut invariant: {sync.identity}. */',
            f'  __CPROVER_assume({expression});']


def _render_decoding(value: object, projected: str, *, memory: str, renderer=None) -> str:
    if value is None:
        return projected
    row = _mapping(value, "sync decoding")
    if row.get("op") == "projected_value":
        return projected
    render = _render_source_expression if renderer is None else renderer
    return render(
        _replace_projected_value(row, projected), memory=memory
    )


def _replace_projected_value(value: object, projected: str) -> object:
    if isinstance(value, Mapping):
        if value.get("op") == "projected_value":
            return {"op": "raw_c", "value": projected}
        return {
            str(key): _replace_projected_value(item, projected)
            for key, item in value.items()
        }
    if isinstance(value, list):
        return [_replace_projected_value(item, projected) for item in value]
    return value


def _render_source_expression(value: object, *, memory: str) -> str:
    row = _mapping(value, "bisimulation expression")
    op = row.get("op")
    if op == "exact_projection":
        state = "spx_proof_exact_input" if memory == "input" else "spx_proof_exact_output"
        read = "spx_proof_exact_input_read" if memory == "input" else "spx_proof_exact_output_read"
        return _projection_expression(row["projection"], state=state, read=read)
    if op == "exact_stack_address":
        state = (
            "spx_proof_exact_input" if memory == "input" else "spx_proof_exact_output"
        )
        return exact_stack_address_expression(int(row.get("offset", 0)), state=state)
    if op == "raw_c":
        return str(row.get("value"))
    if op in {"parameter", "state_input", "loop_variable"}:
        return str(row.get("name"))
    if op == "bytes_address":
        return view_address_expression(str(row.get("name")))
    if op == "nul_extent":
        address = view_address_expression(str(row.get("name")))
        return f"__CPROVER_uninterpreted_spx_nul_extent((uint32_t)({address}))"
    if op == "byte_extent":
        return f"((uint32_t)({row.get('name')}->extent))"
    if op == "resource_identity":
        return f"((uint32_t)({row.get('name')}.identity))"
    if op == "byte_read":
        index = _render_source_expression(row.get("index"), memory=memory)
        reader = (
            "spx_proof_exact_input_read"
            if memory == "input"
            else "spx_proof_exact_output_read"
        )
        address = view_address_expression(str(row.get("name")), index=index)
        return f"({reader}({address}, UINT32_C(1)))"
    if op == "const":
        return f"UINT32_C({int(row.get('value', 0)) & 0xFFFFFFFF})"
    if op in {"true", "false"}:
        return "UINT32_C(1)" if op == "true" else "UINT32_C(0)"
    args = row.get("args")
    if not isinstance(args, list):
        raise BisimulationRefinementError(
            f"bisimulation expression {op!r} has no arguments"
        )
    rendered = [_render_source_expression(item, memory=memory) for item in args]
    binary = {
        "add32": "+",
        "sub32": "-",
        "mul32": "*",
        "and32": "&",
        "or32": "|",
        "xor32": "^",
        "eq": "==",
        "ult32": "<",
        "ule32": "<=",
        "and_bool": "&&",
        "or_bool": "||",
    }
    if op in binary and len(rendered) == 2:
        return f"(({rendered[0]}) {binary[op]} ({rendered[1]}))"
    if op in {"and", "or"} and rendered:
        operator = " && " if op == "and" else " || "
        return "(" + operator.join(f"({item})" for item in rendered) + ")"
    if op == "not" and len(rendered) == 1:
        return f"(!({rendered[0]}))"
    if op == "ite" and len(rendered) == 3:
        return f"(({rendered[0]}) ? ({rendered[1]}) : ({rendered[2]}))"
    raise BisimulationRefinementError(f"bisimulation expression {op!r} is unsupported")


def memory_projection_readers(*, stack_facts=False):
    """Use checked incoming and current bytes for generated cut projections."""
    lines = [
        "uint32_t spx_proof_exact_input_read(uint32_t address, uint32_t width) {",
        "  uint32_t fault = UINT32_C(0);",
        "  uint32_t value = spx_proof_initial_read(address, width, &fault);",
        "  __CPROVER_assert(fault == UINT32_C(0),",
        '      "spx-bisimulation-exact-input-read");',
        "  __CPROVER_assume(fault == UINT32_C(0));",
        "  return value;",
        "}",
        "uint32_t spx_proof_exact_output_read(uint32_t address, uint32_t width) {",
        "  uint32_t fault = UINT32_C(0);",
        "  uint32_t value = spx_proof_exact_read(0, address, width, &fault);",
        "  __CPROVER_assert(fault == UINT32_C(0),",
        '      "spx-bisimulation-exact-output-read");',
        "  __CPROVER_assume(fault == UINT32_C(0));",
        "  return value;",
        "}",
        "uint32_t spx_proof_source_output_read(uint32_t address, uint32_t width) {",
        "  uint32_t fault = UINT32_C(0);",
        "  uint32_t value = spx_proof_source_read(0, address, width, &fault);",
        "  __CPROVER_assert(fault == UINT32_C(0),",
        '      "spx-bisimulation-source-output-read");',
        "  __CPROVER_assume(fault == UINT32_C(0));",
        "  return value;",
        "}",
    ]
    if stack_facts:
        for direction in ('input', 'output'):
            lines += [
                f"uint32_t spx_proof_exact_{direction}_stack_read(uint32_t stack, int64_t offset, uint32_t width) {{",
                "  int64_t address = (int64_t)stack + offset;",
                "  uint32_t valid = address >= INT64_C(0) && address <= INT64_C(4294967295) &&",
                "      (width == 1U || width == 2U || width == 4U) && address + width <= INT64_C(4294967296);",
                f'  __CPROVER_assert(valid, "spx-bisimulation-exact-{direction}-stack-range");',
                "  __CPROVER_assume(valid);",
                f"  return spx_proof_exact_{direction}_read((uint32_t)address, width);",
                "}",
            ]
    return lines
