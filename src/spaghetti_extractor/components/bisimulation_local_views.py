"""Local and borrowed parameter views cross cuts through their native accessor codec."""

from collections.abc import Mapping

from .bisimulation_projection import _projection_expression
from .bisimulation_support import BisimulationRefinementError
from .bisimulation_view_context import RUNTIME_FIELDS
from .component_c_v5 import _c
from .machine_overlay_boundaries_v5 import authority_selector_expression

POLICY = "canonical-service-view-cut-v2"
LEGACY_POLICY = "canonical-service-view-cut-v1"
BYTE_ACCESS = "spx-bisimulation-native-view-byte-access"


def input_owner_description(sync_id, capture_id):
    return f"spx-bisimulation-native-view-input-owner:{sync_id}:{capture_id}"


def byte_read_checks(sync):
    payload = sync.to_payload() if hasattr(sync, "to_payload") else sync
    native = {capture["id"] for capture in payload["captures"] if capture["mode"] == "native_view"}

    def reads(value):
        if isinstance(value, Mapping):
            return (value.get("op") == "byte_read" and value.get("name") in native
                    or any(reads(child) for child in value.values()))
        return isinstance(value, list) and any(reads(child) for child in value)

    return {BYTE_ACCESS} if reads(payload) else set()


def has_local_views(operation):
    return any(capture.mode == "native_view" for sync in operation.syncs for capture in sync.captures)


def local_view_metadata(operation):
    return {"local_view_cut_policy": POLICY} if has_local_views(operation) else {}


def validate_local_view_model(planned, model):
    from .inductive_relation import CutpointValueRelationV1
    for sync in planned["source"]["syncs"]:
        for capture in sync["captures"]:
            if capture["mode"] == "native_view":
                CutpointValueRelationV1.parse(capture, "local view capture")
    present = any(capture["mode"] == "native_view" for sync in planned["source"]["syncs"]
                  for capture in sync["captures"])
    if (("local_view_cut_policy" in model) != present or
            present and model["local_view_cut_policy"] not in {LEGACY_POLICY, POLICY}):
        raise ValueError("local view cut transport differs from the proof plan")
    parameters = [capture for sync in planned['source']['syncs'] for capture in sync['captures']
                  if capture['mode'] == 'native_view' and capture['kind'] == 'parameter']
    if parameters and model.get('local_view_cut_policy') != POLICY:
        raise ValueError('native parameter cuts require checked owner transport')
    if "obligation_id" in model:
        selected = model.get("selected_unit_ids", [])
        targets = {edge["target_unit_id"] for edge in planned["exact"]["control_edges"]
                   if edge["source_unit_id"] in selected}
        for sync in planned["source"]["syncs"]:
            if model["obligation_id"] == "sync:" + sync["id"] and model.get("local_view_cut_policy") == POLICY:
                owners = {input_owner_description(sync["id"], capture["id"])
                          for capture in sync["captures"] if capture["mode"] == "native_view"}
                if not owners <= set(model.get("required_assertion_descriptions", [])):
                    raise ValueError("local view owner substitution lacks its checked input assertion")
            if model["obligation_id"] == "sync:" + sync["id"] or sync["exact_unit_id"] in targets:
                if not byte_read_checks(sync) <= set(model.get("required_assertion_descriptions", [])):
                    raise ValueError("local view content read lacks its checked access assertion")
            if sync['exact_unit_id'] in targets:
                for capture in sync['captures']:
                    if capture['mode'] == 'native_view' and capture['kind'] == 'parameter' and (
                            f"spx-bisimulation-capture-reference-memory:{sync['id']}:{capture['id']}"
                            not in model.get('required_assertion_descriptions', [])):
                        raise ValueError('native parameter cut omits current origin contents')
    return {"local_view_cut_policy": model["local_view_cut_policy"]} if present else {}


def local_view_specs(operation, *, component_id, overlay_entry, authority, parameter_specs=None):
    if not has_local_views(operation):
        return None
    selectors = overlay_entry.get("object_authority_selectors")
    if not isinstance(authority, Mapping) or not isinstance(selectors, Mapping):
        raise BisimulationRefinementError("local view cut requires bound native authority selectors")
    rules = {rule["id"]: rule for rule in authority["rules"]}
    result = {"symbol": f"__CPROVER_spx_{_c(component_id)}_local_view_codec", "captures": {},
              "byte_reads": any(byte_read_checks(sync) for sync in operation.syncs)}
    for sync in operation.syncs:
        for capture in sync.captures:
            if capture.mode != "native_view":
                continue
            raw = capture.projection.payload
            identity = raw.get("authority", {}).get("id")
            rule = rules.get(selectors.get(identity))
            if rule is None or rule["lifetime"] not in {"image", "allocation"}:
                raise BisimulationRefinementError("local view cut requires image or checked allocation authority")
            if rule["lifetime"] == "allocation" and (sync.allocation_history is None or
                    rule["id"] not in sync.allocation_history.classes):
                raise BisimulationRefinementError("local view cut omits its allocation-history class")
            result["captures"][(sync.identity, capture.identity)] = {
                "selector": authority_selector_expression(raw, selectors),
                "permissions": {"read": 1, "write": 2, "read_write": 3}[capture.encoding["access"]],
                "nullable": int(capture.encoding["nullable"])}
            if capture.kind == "parameter":
                bound = (parameter_specs or {}).get(capture.identity)
                current = result["captures"][(sync.identity, capture.identity)]
                if (bound is None or bound.get("nullable_input") is not True or
                        bound["selector"] != current["selector"] or
                        bound["permissions"] != current["permissions"]):
                    raise BisimulationRefinementError("native parameter cut lacks its bound input decoder")
                result["parameter_views"] = True
    return result


def runtime_source():
    equal = " &&\n      ".join(f"current->{field} == spx_local_view_runtime_snapshot.{field}" for field in RUNTIME_FIELDS)
    return f'''
static spx_runtime *spx_local_view_runtime_identity;
static spx_runtime spx_local_view_runtime_snapshot;
static void spx_proof_bind_local_view_runtime(spx_runtime *runtime) {{
  spx_local_view_runtime_identity = runtime;
  spx_local_view_runtime_snapshot = *runtime;
}}
spx_runtime *spx_proof_local_view_runtime(void) {{
  spx_runtime *current = spx_local_view_runtime_identity;
  return current != 0 && ({equal}) ? current : 0;
}}
'''


def runtime_binding(operation):
    return ["  spx_proof_bind_local_view_runtime(&source_runtime);"] if has_local_views(operation) else []


def header_source(specs):
    if specs is None:
        return []
    return ['#include "portable-component.h"',
        "spx_runtime *spx_proof_local_view_runtime(void);",
        f"uint32_t {specs['symbol']}(spx_runtime *, spx_view_v5 *, uint32_t, uint32_t,",
        "    uint64_t, uint32_t, const char *, uint32_t, uint32_t);",
        *(_parameter_observer_source(specs['symbol']).splitlines() if specs.get('parameter_views') else []),
        *(_byte_reader_source().splitlines() if specs.get("byte_reads") else [])]


def _parameter_observer_source(symbol):
    return f'''
static inline uint32_t {symbol}_observe(spx_runtime *runtime, const spx_view_v5 *view,
    uint32_t address, uint32_t requested, uint64_t visible, uint32_t permissions,
    const char *selector, uint32_t nullable) {{
  if (view == 0) return 0U;
  spx_view_v5 observed = *view;
  return {symbol}(runtime, &observed, address, requested, visible, permissions,
      selector, nullable, 0U);
}}
'''


def _byte_reader_source():
    return f'''
uint32_t spx_proof_exact_input_read(uint32_t, uint32_t);
uint32_t spx_proof_exact_output_read(uint32_t, uint32_t);
static inline uint32_t spx_proof_local_view_byte(
    const spx_view_v5 *view, uint32_t base, uint32_t index, uint32_t incoming) {{
  uint32_t admitted = view->element_width == 1U && (view->base.permissions & 1U) != 0U &&
      index < view->extent && base != 0U && (uint64_t)base + index <= UINT32_MAX;
  __CPROVER_assert(admitted, "{BYTE_ACCESS}");
  __CPROVER_assume(admitted);
  return incoming ? spx_proof_exact_input_read(base + index, 1U) :
                    spx_proof_exact_output_read(base + index, 1U);
}}
'''


def cut_fragments(sync, capture, specs):
    if specs is None or (sync.identity, capture.identity) not in specs["captures"]:
        raise BisimulationRefinementError("local view cut lacks its checked native codec")
    spec = specs["captures"][(sync.identity, capture.identity)]
    raw, name = capture.projection.payload, capture.identity
    parameter = capture.kind == 'parameter'

    def call(memory, construct):
        state = f"spx_proof_exact_{memory}"
        read = f"spx_proof_exact_{memory}_read"
        address = _projection_expression(raw, state=state, read=read)
        requested = _projection_expression(raw["requested_extent"], state=state, read=read)
        visible = ("UINT64_MAX" if raw["extent"]["kind"] == "origin_remainder" else
                   _projection_expression(raw["extent"], state=state, read=read))
        if any(value is None for value in (address, requested, visible)):
            raise BisimulationRefinementError("local view cut has an unsupported address or extent")
        symbol = specs['symbol'] + ('_observe' if parameter else '')
        value = f'({name})' if parameter else f'&({name})'
        mode = '' if parameter else f', UINT32_C({construct})'
        return (f"{symbol}(spx_proof_local_view_runtime(), {value}, "
                f"(uint32_t)({address}), (uint32_t)({requested}), (uint64_t)({visible}), "
                f"UINT32_C({spec['permissions']}), {spec['selector']}, UINT32_C({spec['nullable']}){mode})")

    # Every restoration finishes before these checks run. Retain the complete
    # descriptor check, then establish pointer equality before substituting its
    # owner. This makes the restored pointer explicit to CBMC without trusting
    # lifetime, repairing unchecked aliases or changing native accessor code.
    owner = "__CPROVER_spx_cut_owner"
    if parameter:
        # The production decoder has constructed this borrowed descriptor.
        # Do not overwrite it or assume away a discrepancy. Checks run after
        # every local restoration, since another capture may alias its fields.
        address = _projection_expression(raw, state='spx_proof_exact_output', read='spx_proof_exact_output_read')
        if address is None:
            raise BisimulationRefinementError('native parameter cut lacks its current address')
        return (["    /* Observe the borrowed input descriptor after local restoration. */",
            f'    __CPROVER_assert({call("input", 0)}, "spx-bisimulation-native-view-input:{sync.identity}:{name}");',
            f'    __CPROVER_assert(({name})->access_context == (({name})->base.object == 0U ? 0 : spx_proof_local_view_runtime()), "{input_owner_description(sync.identity, name)}");'],
            [f'    __CPROVER_assert({call("output", 0)}, "spx-bisimulation-capture:{sync.identity}:{name}");',
             f'    __CPROVER_assert(({name})->base.object == 0U || spx_proof_world_memory_range_equal('
             f'(uint32_t)((uint64_t)({address}) - ({name})->base.offset), ({name})->base.extent), '
             f'"spx-bisimulation-capture-reference-memory:{sync.identity}:{name}");'])
    return ([f"    __CPROVER_assume({call('input', 2)});",
             f'    __CPROVER_assert({call("input", 0)}, "spx-bisimulation-native-view-input:{sync.identity}:{name}");',
             "    do {",
             f"      {owner} = ({name}).base.object == UINT64_C(0) ? 0 : spx_proof_local_view_runtime();",
             f'      __CPROVER_assert(({name}).access_context == {owner}, "{input_owner_description(sync.identity, name)}");',
             f"      __CPROVER_assume(({name}).access_context == {owner});",
             f"      ({name}).access_context = {owner};",
             "    } while (0);"],
            [f'    __CPROVER_assert({call("output", 0)}, "spx-bisimulation-capture:{sync.identity}:{name}");'])


def render_expression(sync, value, *, memory, checked_view_addresses=None):
    from .bisimulation_harness import _render_source_expression
    native = {capture.identity: capture for capture in sync.captures if capture.mode == "native_view"}

    def adapt(row):
        if isinstance(row, Mapping):
            if row.get("name") in native:
                capture = native[row['name']]
                descriptor = f"*({row['name']})" if capture.kind == 'parameter' else row['name']
                if row.get("op") == "byte_extent":
                    return {"op": "raw_c", "value": f"((uint32_t)({descriptor}).extent)"}
                if row.get("op") == "bytes_address":
                    address = _projection_expression(native[row["name"]].projection,
                        state=f"spx_proof_exact_{memory}", read=f"spx_proof_exact_{memory}_read")
                    if address is None:
                        raise BisimulationRefinementError("local view address lacks checked transport")
                    # The mandatory input/output codec binds this machine
                    # coordinate to the current descriptor. The coordinate
                    # alone grants neither validity nor separation from peers.
                    return {"op": "raw_c", "value": f"((uint32_t)({address}))"}
                if row.get("op") == "byte_read":
                    index = _render_source_expression(adapt(row["index"]), memory=memory)
                    address = _projection_expression(native[row["name"]].projection,
                        state=f"spx_proof_exact_{memory}", read=f"spx_proof_exact_{memory}_read")
                    if address is None:
                        raise BisimulationRefinementError("local byte read lacks a checked address")
                    return {"op": "raw_c", "value": f"spx_proof_local_view_byte(&({descriptor}), "
                        f"(uint32_t)({address}), (uint32_t)({index}), UINT32_C({int(memory == 'input')}))"}
                raise BisimulationRefinementError("local view expressions support bytes_address, byte_extent and byte_read")
            name = row.get("name")
            if name in (checked_view_addresses or {}):
                address = checked_view_addresses[name]
                if row.get("op") == "bytes_address":
                    return {"op": "raw_c", "value": address}
                if row.get("op") == "byte_read":
                    index = _render_source_expression(adapt(row["index"]), memory=memory)
                    return {"op": "raw_c", "value":
                        f"spx_proof_exact_{memory}_read(__CPROVER_spx_checked_view_byte_address("
                        f"{address}, ({name})->extent, (uint64_t)({index})), UINT32_C(1))"}
            return {key: adapt(child) for key, child in row.items()}
        if isinstance(row, list):
            return [adapt(child) for child in row]
        return row

    return _render_source_expression(adapt(value), memory=memory)
