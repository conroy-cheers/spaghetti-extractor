"""Proof consumers recover physical spans through the canonical runtime ABI."""

import re
from collections.abc import Sequence


CONNECTED_READABLE_TRANSPORT_POLICY = "canonical-readable-callee-transport-v1"
CONNECTED_MUTABLE_TRANSPORT_POLICY = "canonical-mutable-callee-transport-v1"


def connected_readable_transport_assertions(connected):
    policy = connected.get("readable_transport_policy")
    if policy is None:
        return []
    if policy != CONNECTED_READABLE_TRANSPORT_POLICY or connected.get("entry_contract") is None:
        raise ValueError("readable transport lacks a checked supplier entry contract")
    return ["spx-bisimulation-connected-summary-readable-runtime",
        *(["spx-bisimulation-connected-summary-readable-empty-allocation-world"]
          if connected.get("summary_strategy") == "image-readable-body-free-v1" else []), *(
        f"spx-bisimulation-connected-summary-readable-{kind}:{connected['component_id']}:{operation['operation_id']}"
        for operation in connected["entry_contract"]["operations"]
        for kind in ("view", "domain", "transport"))]


def connected_mutable_transport_assertions(connected):
    policy = connected.get("mutable_transport_policy")
    entry = connected.get("entry_contract")
    mutable = entry is not None and entry.get("policy") == "checked-mutable-callee-stack-entry-v1"
    if not mutable and policy is None:
        return []
    if not mutable or policy != CONNECTED_MUTABLE_TRANSPORT_POLICY or connected.get("readable_transport_policy") is not None:
        raise ValueError("mutable entry requires its checked canonical transport")
    return ["spx-bisimulation-connected-summary-framed-runtime" if connected.get('summary_strategy') == 'image-shared-framed-body-free-v1'
            else "spx-bisimulation-connected-summary-mutable-runtime",
        *(["spx-bisimulation-connected-summary-mutable-empty-allocation-world"]
          if connected.get('summary_strategy') == 'image-shared-body-free-v1' else []),
        *(["spx-bisimulation-connected-summary-mutable-empty-allocation-world", *(
            f"spx-bisimulation-connected-summary-mutable-post-memory:{connected['component_id']}:{op['operation_id']}"
            for op in entry["operations"])] if connected.get("summary_strategy") == "image-mutable-body-free-v1" else []), *(
        f"spx-bisimulation-connected-summary-mutable-{kind}:{connected['component_id']}:{operation['operation_id']}"
        for operation in entry["operations"] for kind in ("view", "domain", "transport"))]


def machine_reference_expression(reference: str) -> str:
    fields = ", ".join(f"({reference}).{field}" for field in
                       ("domain", "object", "generation", "offset", "extent", "permissions"))
    return f"((spx_machine_reference_v1){{{fields}}})"


def reference_transport_source() -> str:
    # No origin discovery or new authority: realize an already-issued reference.
    return """
#ifndef SPX_PROOF_REFERENCE_TRANSPORT_H
#define SPX_PROOF_REFERENCE_TRANSPORT_H
static uint32_t __CPROVER_spx_reference_span(
    spx_runtime *runtime, spx_machine_reference_v1 reference,
    uint32_t permissions, uint32_t nullable, uint32_t one_past,
    uint64_t extent, uint32_t *address) {
  if (runtime == 0 || runtime->realize_reference == 0 || address == 0 ||
      reference.offset > reference.extent || extent > reference.extent - reference.offset)
    return 0U;
  if (runtime->realize_reference(runtime->context, &reference, permissions,
          nullable, one_past, address) != SPX_BOUNDARY_OK)
    return 0U;
  return reference.offset <= (uint64_t)*address &&
      reference.extent <= UINT64_C(4294967296) - ((uint64_t)*address - reference.offset);
}
#endif
"""


CONNECTED_REFERENCE_DECLARATION = """uint32_t spx_proof_connected_reference_address(
    void *opaque, spx_machine_reference_v1 reference, uint64_t extent,
    uint32_t permissions, uint32_t nullable, uint32_t one_past)"""


def connected_reference_transport_source() -> str:
    return reference_transport_source() + CONNECTED_REFERENCE_DECLARATION + """ {
  struct runtime_prefix { spx_runtime *runtime; };
  struct runtime_prefix *service = (struct runtime_prefix *)opaque;
  uint32_t address = 0U;
  uint32_t valid = service != 0 && __CPROVER_spx_reference_span(
      service->runtime, reference, permissions, nullable, one_past, extent, &address);
  __CPROVER_assert(valid, "spx-bisimulation-connected-summary-reference-address");
  __CPROVER_assume(valid);
  return address;
}
"""


def readonly_overlay_transport_source(symbol: str) -> str:
    """Append to a trusted overlay TU, after its canonical read accessors.

    Static C function identities belong to that TU. A consumer must explicitly
    enumerate trusted overlay inspectors; a declaration or a matching function
    signature cannot register an authored accessor as a canonical transport.
    This is a proof helper, not a new production callback or component API.
    """
    return _overlay_transport_source(symbol, mutable=False)


def mutable_overlay_transport_source(symbol: str) -> str:
    return _overlay_transport_source(symbol, mutable=True)


def shared_state_overlay_transport_source(symbol: str) -> str:
    """Inspect fixed shared-state accessors in their trusted overlay TU.

    These views carry the runtime directly, unlike bounded parameter views.
    The enclosing transport check realizes the live reference and full span;
    this inspector establishes the identity of the actual access path.
    """
    _overlay_transport_source(symbol, mutable=True)  # Reserved symbol validation.
    return f"""
uint32_t {symbol}(const spx_view_v5 *view, const spx_runtime *runtime,
    uint32_t address, uint32_t permissions) {{
  (void)address;
  if (view == 0 || runtime == 0 || view->access_context == 0 ||
      view->context != 0 || view->read_u8 != 0 || view->write_u8 != 0 ||
      view->read != spx_component_result_view_read ||
      !((permissions == 1U && view->write == 0) ||
        (permissions == 3U && view->write == spx_component_result_view_write)))
    return 0U;
  const spx_runtime *transport = (const spx_runtime *)view->access_context;
  return transport->context == runtime->context &&
      transport->read == runtime->read && transport->write == runtime->write &&
      transport->realize_reference == runtime->realize_reference;
}}
"""


def _overlay_transport_source(symbol: str, *, mutable: bool) -> str:
    flavor = "mutable" if mutable else "readonly"
    if re.fullmatch(r"__CPROVER_spx_" + flavor + r"_overlay_[a-zA-Z0-9_]+", symbol) is None:
        raise ValueError("read-only overlay inspector must use the reserved proof namespace")
    parameter = ", uint32_t permissions" if mutable else ""
    writes = ("!((permissions == 1U && view->write_u8 == 0 && view->write == 0) ||\n"
              "        (permissions == 3U && view->write_u8 == spx_component_view_write && view->write == spx_component_view_write_span))"
              if mutable else "view->write_u8 != 0 || view->write != 0")
    write_runtime = "transport->runtime->write == runtime->write &&\n      " if mutable else ""
    return f"""
uint32_t {symbol}(const spx_view_v5 *view, const spx_runtime *runtime, uint32_t address{parameter}) {{
  if (view == 0 || runtime == 0 || view->context == 0 ||
      view->context != view->access_context ||
      view->read_u8 != spx_component_view_read ||
      view->read != spx_component_view_read_span ||
      {writes})
    return 0U;
  const spx_component_view_context *transport =
      (const spx_component_view_context *)view->context;
  return transport->runtime != 0 && transport->runtime->read == runtime->read &&
      transport->runtime->context == runtime->context &&
      {write_runtime}transport->address == address && transport->extent == view->extent &&
      transport->permissions == {"permissions" if mutable else "1U"};
}}
"""


def readonly_connected_transport_source(inspectors: Sequence[str]) -> str:
    """Check view transport against the caller's actual world and live reference.

    Only inspectors emitted beside trusted lowering helpers may be supplied.
    Unknown callbacks are rejected without invoking them. The world supplies a
    checked canonical read runtime; realization validates the current logical
    reference before an inspector compares the view's physical span.
    """
    return _connected_transport_source(inspectors, mutable=False)


def mutable_connected_transport_source(inspectors: Sequence[str], *, symbol: str, framed=False) -> str:
    if re.fullmatch(r"__CPROVER_spx_connected_mutable_transport_[a-zA-Z0-9_]+", symbol) is None:
        raise ValueError("mutable transport wrapper must use the reserved proof namespace")
    return _connected_transport_source(inspectors, mutable=True, symbol=symbol, framed=framed)


def _connected_transport_source(inspectors: Sequence[str], *, mutable: bool, symbol=None, framed=False) -> str:
    if not inspectors or len(set(inspectors)) != len(inspectors):
        raise ValueError("read-only transport needs distinct trusted overlay inspectors")
    for inspector in inspectors:
        _overlay_transport_source(inspector, mutable=mutable)
    argument, parameter = (", permissions", ", uint32_t permissions") if mutable else ("", "")
    runtime_function = "__CPROVER_spx_connected_mutable_runtime" if mutable else "__CPROVER_spx_connected_read_runtime"
    if framed:
        if not mutable:
            raise ValueError('allocation framing requires checked mutable transport')
        runtime_function = '__CPROVER_spx_connected_framed_runtime'
    transport_function = symbol if mutable else "__CPROVER_spx_connected_readable_transport"
    permission = "permissions" if mutable else "1U"
    # The reference retains the permissions of its issued origin. A read-only
    # view can borrow a writable origin; its callbacks and transport grant still
    # have to match the requested access exactly in the trusted inspector.
    admitted = "(permissions == 1U || permissions == 3U) && (view->base.permissions & permissions) == permissions" if mutable else "(view->base.permissions & 1U) != 0U"
    declarations = "\n".join(
        f"extern uint32_t {symbol}(const spx_view_v5 *, const spx_runtime *, uint32_t{', uint32_t' if mutable else ''});"
        for symbol in inspectors)
    matches = " || ".join(f"{symbol}(view, runtime, address{argument})" for symbol in inspectors)
    reference = machine_reference_expression("view->base")
    return reference_transport_source() + declarations + f"""
extern spx_runtime *{runtime_function}(void *);
uint32_t {transport_function}(void *opaque, const spx_view_v5 *view{parameter}) {{
  spx_runtime *runtime = {runtime_function}(opaque);
  uint32_t address = 0U;
  return view != 0 && view->element_width == 1U && {admitted} &&
      __CPROVER_spx_reference_span(runtime, {reference}, {permission}, 0U, 0U,
          view->extent, &address) && ({matches});
}}
"""


def view_address_expression(name: str, *, index: str | None = None, object_start=False) -> str:
    function = ("object_address" if object_start else "byte_address" if index is not None else "address")
    arguments = f"({name})->context, {machine_reference_expression(f'({name})->base')}, ({name})->extent"
    if index is not None:
        arguments += f", (uint64_t)({index})"
    return f"__CPROVER_spx_view_{function}({arguments})"


def view_address_check_source(symbol: str) -> str:
    """Give a checked address call its own property identity, preserving its body."""
    return """static uint32_t __CPROVER_spx_view_address(
    void *opaque, spx_machine_reference_v1 reference, uint64_t extent) {
  const spx_component_view_context *view = (const spx_component_view_context *)opaque;
  uint32_t valid = view != 0 && __CPROVER_spx_view_reference_matches(
      opaque, reference, extent, view->address);
  __CPROVER_assert(valid, "spx-bisimulation-view-reference-address");
  __CPROVER_assume(valid);
  return view->address;
}
""".replace("__CPROVER_spx_view_address(", symbol + "(", 1)


def specialize_view_address_checks(header: str) -> str:
    """Separate cut-macro call sites without changing their checks or assumptions.

    CBMC otherwise merges every call into one property. Keep runtime helpers
    unchanged and emit one identical assertion-bearing function for each direct
    cut expression. The normal property inventory must still check every site.
    """
    prefix, marker, macros = header.partition("#define SPX_PROOF_BEGIN")
    if not marker:
        raise ValueError("cut header lacks its proof entry macro")
    definitions = []

    def specialize(match):
        symbol = "__CPROVER_spx_view_address_site_" + str(len(definitions))
        definitions.append(view_address_check_source(symbol))
        return symbol + "("

    macros = re.sub(r"\b__CPROVER_spx_view_address\(", specialize, macros)
    return prefix + "\n".join(definitions) + "\n" + marker + macros if definitions else header


def view_reference_transport_source() -> str:
    return reference_transport_source() + """
static uint32_t __CPROVER_spx_view_reference_matches(
    void *opaque, spx_machine_reference_v1 reference, uint64_t extent, uint32_t expected) {
  const spx_component_view_context *view = (const spx_component_view_context *)opaque;
  uint32_t address = 0U;
  return view != 0 && view->extent == extent &&
      __CPROVER_spx_reference_span(view->runtime, reference, view->permissions,
          0U, 0U, extent, &address) && address == expected && view->address == address;
}

""" + view_address_check_source("__CPROVER_spx_view_address") + """
static uint32_t __CPROVER_spx_view_object_address(
    void *opaque, spx_machine_reference_v1 reference, uint64_t extent) {
  uint32_t address = __CPROVER_spx_view_address(opaque, reference, extent);
  return (uint32_t)((uint64_t)address - reference.offset);
}

static uint32_t __CPROVER_spx_checked_view_byte_address(
    uint32_t address, uint64_t extent, uint64_t index) {
  uint32_t valid = index < extent && index <= UINT32_MAX - address;
  __CPROVER_assert(valid, "spx-bisimulation-view-reference-byte-index");
  __CPROVER_assume(valid);
  return address + (uint32_t)index;
}

static uint32_t __CPROVER_spx_view_byte_address(
    void *opaque, spx_machine_reference_v1 reference, uint64_t extent, uint64_t index) {
  return __CPROVER_spx_checked_view_byte_address(
      __CPROVER_spx_view_address(opaque, reference, extent), extent, index);
}
"""
