"""Bind value algorithms to retained PE32 inputs; no pilot rebuild required."""
from pathlib import Path
import argparse
import json
import random
import runpy

from spaghetti_extractor.components.comparison_environment import native_environment, native_adapter_headers
from spaghetti_extractor.components.comparison_original import native_entry_header
from spaghetti_extractor.components.comparison_package import prepare_comparison_package


def cases():
    rows = []

    def add(name, operation, first, second=None):
        rows.append(dict(id=name, arguments=[operation, json.dumps(first), json.dumps(second)]))

    for name, value in [('empty-object', {}), ('empty-array', []), ('array', [1, None, 'x']),
                        ('object', {'z': 1, 'a': 2, 'é': 3, 'a\x00z': 4})]:
        for operation in ('keys', 'keys_unsorted'):
            add(operation + '-' + name, operation, value)
    for name, first, second in [
        ('kinds', None, False), ('number', -2, 10), ('nan', float('nan'), float('nan')),
        ('nan-number', float('nan'), 5), ('infinity', float('inf'), 1),
        ('bytes', 'az', 'ba'), ('utf8', 'é', '🙂'), ('nul', 'a\x00z', 'a\x00a'),
        ('prefix', 'abcd', 'a'), ('array-prefix', [1, 2], [1]),
        ('nested', [{'x': [1, 2]}], [{'x': [1, 3]}]),
        ('object-keys', {'z': 1}, {'a': 10}), ('equal', {'a': 1, 'b': 2}, {'b': 2, 'a': 1}),
    ]:
        add('compare-' + name, 'compare', first, second)
    # Keep decimal literal tokens intact instead of rounding them in Python.
    rows.append(dict(id='compare-decimal', arguments=['compare', '9007199254740993', '9007199254740992']))
    for name, first, second in [
        ('array', [1, 2, 3], 1), ('negative', [1, 2, 3], -1),
        ('fractional', [1, 2, 3], 1.5), ('nan', [1, 2, 3], float('nan')),
        ('null', None, 'x'), ('object', {'a': None}, 'a'), ('absent', {'a': 1}, 'b'),
        ('type-error', 'abc', 1),
    ]:
        add('has-' + name, 'has', first, second)
    for name, value, paths in [
        ('nested', {'a': [{'b': 1, 'c': 2}, 3], 'z': 0}, [['a', 0, 'b'], ['z']]),
        ('overlap', {'a': {'b': 1}, 'c': 2}, [['a', 'b'], ['a'], ['a']]),
        ('array', [0, 1, 2, 3, 4], [[1], [-1], [1], [99]]),
        ('slice', [0, 1, 2, 3, 4, 5], [[{'start': 1, 'end': 3}], [-1]]),
        ('fractional-slice', [0, 1, 2, 3, 4], [[{'start': 1.2, 'end': 2.2}]]),
        ('whole', {'x': [1]}, [[]]), ('empty', [1, 2], []),
        ('null', None, [['x']]), ('missing', {'a': 1}, [['b', 'c']]),
        ('bad-paths', {'x': 1}, {}), ('bad-path', {'x': 1}, [1]),
        ('bad-key', {'x': 1}, [[1]]), ('bad-array-key', [1, 2], [['x']]),
    ]:
        add('delete-' + name, 'delete', value, paths)
    for name, keys in [('empty', []), ('stable', [2, 1, 2, 1]),
                       ('mixed', [None, False, True, 0, '', [], {}]),
                       ('nested', [{'b': 1}, {'a': 2}, {'b': 1}]),
                       ('nan', [float('nan'), 1, float('nan'), -1]),
                       ('nul', ['a\x00z', 'a\x00a', 'a'])]:
        for operation in ('sort', 'group', 'unique'):
            add(operation + '-' + name, operation, list(range(len(keys))), keys)
    rng = random.Random(1847)
    for index in range(8):
        keys = [rng.randrange(-4, 5) for _ in range(rng.randrange(4, 45))]
        for operation in ('sort', 'group', 'unique'):
            add(operation + '-generated-' + str(index), operation, list(range(len(keys))), keys)
    return rows


def prepare(workspace, retained, output):
    here = Path(__file__).resolve().parent
    bindings = output.parent / 'native-inputs'
    bindings.mkdir(exist_ok=True)
    rows = json.loads((here / 'native-entries.json').read_text())
    header = ''
    for _, name, _, _, rva, end in rows:
        # parse_slice is shared with native get/set; leave that helper intact.
        extra = {'delpaths': ((0x2d7a3, 0x2d816), (0x2df11, 0x2f2c6), (0x313b6, 0x31ed2)),
                 'sort': ((0x2f2c6, 0x2f6f5), (0x344e5, 0x34598)),
                 'cmp': ((0x2f6f5, 0x2f806),)}.get(name, ())
        header += native_entry_header(
            original=retained / 'runtime/libjq-1.dll',
            expected_sha256='50d05ffd1f3cdbb5257f2cda429d9b920d95c091bb88a9d8bcdcb08ae9bacb1d',
            module='libjq-1.dll', entry_rva=rva, end_rva=end,
            installer='install_' + name, additional_ranges=extra)
    header += 'static int install_entries(void) { return ' + ' && '.join(
        f'install_{row[1]}((void (*)(void))spx_entry_{row[1]})' for row in rows) + '; }\n'
    header += 'static int entries_intact(void) { return ' + ' && '.join(
        f'install_{row[1]}_intact()' for row in rows) + '; }\n'
    (bindings / 'native-entry.h').write_text(header)
    prepare_comparison_package(
        **runpy.run_path(str(workspace / 'prepare.py'))['source_inputs'](),
        **native_environment(retained),
        adapter_files={name: here / name for name in ('driver.c', 'entries.c', 'native-runtime.c')} | {
            'allocation-observer.c': here.parent / 'jq-array-storage/allocation-observer.c'},
        include_files={**{p.name: p for p in (workspace / 'headers').iterdir()},
                       **{name: here / name for name in ('entries.h', 'entry-observations.h')},
                       'native-entry.h': bindings / 'native-entry.h',
                       'allocation-observer.h': here.parent / 'jq-array-storage/allocation-observer.h',
                       **native_adapter_headers()},
        original_files=['runtime/libjq-1.dll'], oracle_kind='native-original', cases=cases(),
        observation_fields=['result', 'retained_first', 'retained_second', 'allocation_lifetime'],
        assumptions=json.loads((workspace / 'assumptions.json').read_text()),
        scope='jq value algorithms: ordering, stable sorting, grouping, uniqueness, keys, membership and recursive deletion with retained aliases.',
        output=output)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('workspace', 'retained', 'output'):
        parser.add_argument(name, type=Path)
    args = parser.parse_args()
    prepare(args.workspace.resolve(), args.retained.resolve(), args.output.resolve())
