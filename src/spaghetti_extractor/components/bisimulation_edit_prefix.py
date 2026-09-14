"""Factor identical effects before a single changed, finite source-edit suffix.

This is a compiled correspondence, not a callee summary. The caller must first
check complete symbol/helper/context identity. Unknown branches are followed on
both arms; matching early returns keep their result assignments and epilogues.
Only the suffix may change, and its behavior needs a separate universal proof.
"""

from ..artifacts.artifact_set import canonical_sha256_v3
from .bisimulation_cut_state import _symbol
from .bisimulation_entry_conformance import _payload, _truth

POLICY = 'identical-effect-prefix-single-frontier-v1'


def _require(condition, detail):
    if not condition:
        raise ValueError('source edit prefix: ' + detail)


def common_effect_prefix(*, bodies, regions):
    """Return a checked common prefix and remaining regions, or no factoring.

    No heap projection, call precondition, or normal-return assumption is added.
    An identical call may fail, diverge or change memory; both versions retain
    that behavior. At the single continuing frontier the suffix checker must
    quantify over all incoming scalar values and preserve preexisting storage.
    """
    rows = [body['instructions'] for body in bodies]
    maps = [{r['locationNumber']: i for i, r in enumerate(side)} for side in rows]
    ports = [{index: port for port, index in region[2].items()} for region in regions]

    def advance(side, index):
        while index not in ports[side] and rows[side][index]['instructionId'] in {'SKIP', 'LOCATION'}:
            index += 1
        return index

    def successors(side, index):
        row = rows[side][index]
        if row['instructionId'] == 'GOTO':
            targets = row.get('targets', [])
            _require(len(targets) == 1, 'ambiguous branch')
            truth = _truth(row['guard'], {})
            return ([maps[side][targets[0]]] if truth is not False else []) + ([index + 1] if truth is not True else [])
        _require(not row.get('targets'), 'target on non-branch')
        return [index + 1]

    pending = [tuple(region[0] + 1 for region in regions)]
    matched, frontier, completed, calls = set(), set(), set(), []
    while pending:
        a, b = pending.pop()
        a, b = advance(0, a), advance(1, b)
        pair = (a, b)
        if pair in matched or pair in frontier:
            continue
        exits = [ports[side].get(index) for side, index in enumerate(pair)]
        if any(v is not None for v in exits):
            if exits[0] == exits[1]:
                completed.add(exits[0])
                continue
            frontier.add(pair)
            continue
        left, right = rows[0][a], rows[1][b]
        if _payload(left) != _payload(right):
            frontier.add(pair)
            continue
        kind = left['instructionId']
        _require(kind in {'DECL', 'DEAD', 'ASSIGN', 'FUNCTION_CALL', 'GOTO', 'SET_RETURN_VALUE', 'ASSERT'},
                 'unsupported common effect: ' + kind)
        if kind == 'FUNCTION_CALL':
            args = left.get('code', {}).get('sub', [])
            _require(len(args) == 3 and _symbol(args[1]), 'indirect call needs separate target correspondence')
            calls.append({'indices': list(pair), 'callee': _symbol(args[1]), 'payload_sha256': canonical_sha256_v3(_payload(left))})
        matched.add(pair)
        aa, bb = successors(0, a), successors(1, b)
        _require(len(aa) == len(bb), 'branch coverage differs')
        pending.extend(zip(aa, bb))
    if not calls:
        return None
    _require(len(frontier) == 1, 'effects do not meet at one unchanged-state frontier')
    starts = next(iter(frontier))
    suffixes = []
    for side, start in enumerate(starts):
        visited, reached, todo = set(), {}, [start]
        prefix_indices = {pair[side] for pair in matched}
        while todo:
            index = advance(side, todo.pop())
            if index in visited:
                continue
            if index in ports[side]:
                reached[ports[side][index]] = index
                continue
            _require(index not in prefix_indices, 'suffix reenters the matched prefix')
            _require(index in regions[side][1], 'suffix escapes the original region')
            visited.add(index)
            todo.extend(successors(side, index))
        _require('@return' not in reached, 'changed return requires result-state transport')
        _require(visited and reached, 'missing changed suffix or exit')
        suffixes.append((start - 1, visited, reached))
    _require(set(suffixes[0][2]) == set(suffixes[1][2]), 'suffix exit coverage differs')
    binding = {'policy': POLICY, 'status': 'matched-identical-effect-prefix',
               'frontier_indices': list(starts), 'pairs': [list(v) for v in sorted(matched)],
               'completed_ports': sorted(completed), 'calls': sorted(calls, key=lambda v: v['indices']),
               'prefix_payloads_sha256': canonical_sha256_v3([_payload(rows[0][a]) for a, _ in sorted(matched)]),
               'callee_summary_claimed': False, 'incoming_domain_assumed': False}
    return binding, suffixes


def comparison_effects_preserved(comparison):
    """Validate the frame claim's scope; a common write is not an empty frame."""
    binding = comparison.get('binding', {})
    if binding.get('policy') == 'pure-scalar-region-comparison-v1':
        return 'common_prefix' not in binding and comparison.get('preexisting_storage_unchanged') is True
    prefix = binding.get('common_prefix', {})
    return bool(binding.get('policy') == 'common-prefix-pure-suffix-comparison-v1'
                and prefix.get('policy') == POLICY and prefix.get('status') == 'matched-identical-effect-prefix'
                and prefix.get('calls') and prefix.get('pairs')
                and prefix.get('callee_summary_claimed') is False and prefix.get('incoming_domain_assumed') is False
                and comparison.get('preexisting_storage_unchanged') is False
                and comparison.get('common_prefix_effects_preserved') is True
                and comparison.get('suffix_preexisting_storage_unchanged') is True)
