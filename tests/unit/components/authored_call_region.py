"""Use a public, compiler-bound caller region in the paired Metapad experiment.

The result remains conditional on the named supplier/runtime domain. Only the
0x5646 caller region has authored-source correspondence here; 0x570e is excluded.
"""

from spaghetti_extractor.components.bisimulation_source_call_check import checked_source_call_regions
from .shared_call_region import render_call_regions


def render_authored_call(transition, source_result, *, source_artifacts):
    projection, = checked_source_call_regions(source_result, artifacts=source_artifacts)
    if (projection['service_id'] != 'resource_text' or len(projection['arguments']) != 1
            or projection['context_type'] != 'spx_text_cleanup_context_v5'):
        raise ValueError('caller service adapter does not admit this source projection')
    # The source projector admits precisely this five-instruction form, and
    # preserves the complete view value copied into its fresh automatic result.
    # Pointer/table validity and binding to the checked child remain explicit
    # premises of this constructed incoming context, not inferred reachability.
    body = '''static spx_view_v5 authored_region(spx_text_cleanup_context_v5 *context) {
  spx_view_v5 message = context->services->resource_text(context->services->context, %dU);
  return message;
}
static spx_view_v5 portable_region(void *opaque,uint32_t which) {
  (void)which;
  spx_text_cleanup_services_v5 services = {.context=opaque,.resource_text=shared_transition};
  spx_text_cleanup_context_v5 context = {.services=&services};
  return authored_region(&context);
}
''' % projection['arguments'][0]
    source = render_call_regions(transition)
    a = source.index('static spx_view_v5 portable_region(')
    b = source.index('void check_call_regions(', a)
    source = source[:a]+body+source[b:]
    source = source.replace('which<2U;', 'which<1U;').replace(
        'child_trace.count[0]==2U && child_trace.count[1]==2U',
        'child_trace.count[0]==1U && child_trace.count[1]==1U')
    return source
