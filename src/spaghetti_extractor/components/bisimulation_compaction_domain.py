"""Shared public-memory premises for entry admission and local compaction steps.

Expressions are supplied by the checked model renderers. Sharing these predicates
prevents a producer's outgoing checks from silently omitting a consumer premise;
it does not by itself compose their evidence, private frames or object lifetimes.
"""


def compaction_public_domain(*, text_nul_byte, scratch_probe_byte,
                             input_value='input', output_value='output', removed_value='removed',
                             pending_bytes=None):
    result = {
        'text-span': 'text_address>0U && text_extent>0U && (uint64_t)text_address+text_extent<=UINT64_C(4294967296)',
        'scratch-span': '(uint64_t)scratch_address+scratch_extent<=UINT64_C(4294967296)',
        'nullable-scratch': '(scratch_extent==0U && scratch_address==0U) || (scratch_extent>0U && scratch_address>0U)',
        'disjoint-public-spans': '(uint64_t)text_address+text_extent<=scratch_address || (uint64_t)scratch_address+scratch_extent<=text_address',
        'cursor-domain': f'{input_value}<text_extent && {output_value}<={input_value} && {removed_value}=={input_value}-{output_value}',
        'allocation-domain': f'(scratch_extent==0U && {output_value}==0U) || (scratch_extent>0U && {input_value}<scratch_extent && scratch_extent<=text_extent && ({text_nul_byte})==0U)',
        'zero-suffix': f'!(scratch_extent && probe>=scratch_address+{output_value} && (uint64_t)probe<(uint64_t)scratch_address+scratch_extent) || ({scratch_probe_byte})==0U',
    }
    if pending_bytes is not None:
        first, second = pending_bytes
        result['null-scratch-pending-crlf'] = (
            f'scratch_extent || {input_value}==0U || '
            f'((uint64_t){input_value}+1U<text_extent && ({first})==13U && ({second})==10U)')
    return result
