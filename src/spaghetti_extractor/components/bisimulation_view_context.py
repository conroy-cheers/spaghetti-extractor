"""Checked reconstruction of the canonical view callback context and runtime."""

from .machine_overlay_logical_views_v5 import VIEW_CONTEXT_DECLARATION
from .bisimulation_reference_transport import view_reference_transport_source


# Keep this field inventory total over the canonical runtime ABI. The ABI
# regression compares it with every member, including currently unused hooks.
RUNTIME_FIELDS = (
    "context", "image_base", "read", "write", "atomic_compare_exchange",
    "atomic_exchange", "resolve_reference", "realize_reference",
    "resolve_interface_resource", "realize_interface_resource", "undefined_value",
    "external_call_fallback", "resolve_code_target", "execute_typed_x87_operation", "route_nonlocal",
    "invoke_callable_external_jump", "record_access_violation",
)


def view_context_proof_source() -> str:
    """Inspect the actual overlay context type without changing the native ABI.

    These helpers appear only in the generated proof header. Snapshot names and
    functions use the namespace excluded from authored source by its profile.
    Runtime context identity is preserved; pointed-to world memory still has
    its independent state/effect relation.
    """
    runtime_equal = " &&\n      ".join(
        f"current->runtime->{field} == snapshot->runtime.{field}"
        for field in RUNTIME_FIELDS
    )
    return VIEW_CONTEXT_DECLARATION + view_reference_transport_source() + """
typedef struct {
  void *identity;
  spx_component_view_context context;
  spx_runtime runtime;
} __CPROVER_spx_view_context_snapshot;

static __CPROVER_spx_view_context_snapshot __CPROVER_spx_snapshot_view_context(void *opaque) {
  __CPROVER_spx_view_context_snapshot snapshot = {0};
  snapshot.identity = opaque;
  if (opaque != 0) {
    snapshot.context = *(spx_component_view_context *)opaque;
    if (snapshot.context.runtime != 0)
      snapshot.runtime = *snapshot.context.runtime;
  }
  return snapshot;
}

static uint32_t __CPROVER_spx_view_context_matches(
    const __CPROVER_spx_view_context_snapshot *snapshot,
    void *opaque, uint32_t address, uint64_t extent) {
  const spx_component_view_context *current = (const spx_component_view_context *)opaque;
  return opaque != 0 && opaque == snapshot->identity &&
      snapshot->context.runtime != 0 && current->runtime == snapshot->context.runtime &&
      current->address == address && current->extent == extent &&
      current->permissions == snapshot->context.permissions &&
      """ + runtime_equal + ";\n}\n"
