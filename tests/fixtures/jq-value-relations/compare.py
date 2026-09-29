"""Bind value relations to retained PE32 inputs; no pilot rebuild required."""
from pathlib import Path
import argparse
import json
import runpy

from spaghetti_extractor.components.comparison_environment import native_environment, native_adapter_headers
from spaghetti_extractor.components.comparison_original import native_entry_header
from spaghetti_extractor.components.comparison_package import prepare_comparison_package


def cases():
    rows = []
    def add(name, op, first, second):
        rows.append(dict(id=name, arguments=[op, json.dumps(first), json.dumps(second)]))
    for name, a, b in [
        ('kinds', None, False), ('numbers', 1, 1), ('unequal', 1, 2),
        ('nan', float('nan'), float('nan')), ('string', 'a\x00b', 'a\x00b'),
        ('substring', 'abc\x00def', '\x00d'), ('empty-string', 'x', ''),
        ('longer-string', 'a', 'aa'), ('arrays', [1, [2, 3]], [[3]]),
        ('nested-equal', [{'a': [1, 2]}], [{'a': [1, 2]}]),
        ('multiplicity', [1], [1, 1]), ('empty-array', [1], []),
        ('objects', {'a': {'x': 1, 'y': 2}, 'b': 3}, {'a': {'x': 1}}),
        ('object-missing', {'a': 1}, {'b': 1}),
    ]:
        for op in ('equal', 'contains'):
            add(op + '-' + name, op, a, b)
    for op in ('equal', 'identical', 'contains'):
        for name, a, b in [('views', '@views', ''), ('alias', '@alias', '[1,2]'),
                          ('zeros', '@zeros', ''), ('invalids', '@invalids', ''),
                          ('invalid-slot', '@invalid-slot', 'present'),
                          ('missing-slot', '@invalid-slot', 'missing')]:
            rows.append(dict(id=op+'-'+name, arguments=[op, a, b]))
    for op in ('merge', 'merge_recursive'):
        for name, a, b in [('empty', {}, {}), ('replace', {'a': 1}, {'a': 2, 'b': 3}),
                          ('nested', {'a': {'x': 1}, 'z': 0}, {'a': {'y': 2}}),
                          ('replace-object', {'a': {'x': 1}}, {'a': [1, 2]}),
                          ('binary-key', {'a\x00b': 1}, {'a\x00b': 2})]:
            add(op+'-'+name, op, a, b)
        rows.append(dict(id=op+'-alias', arguments=[op, '@alias', '{"a":{"x":1},"b":2}']))
    rows.append(dict(id='equal-decimal', arguments=['equal', '9007199254740993', '9007199254740992']))
    return rows


def prepare(workspace, retained, output):
    here = Path(__file__).resolve().parent
    bindings = output.parent / 'native-inputs'
    bindings.mkdir(exist_ok=True)
    rows = json.loads((here / 'native-entries.json').read_text())
    header = ''
    for _, name, _, _, rva, end in rows:
        # Shared string equality still serves original object lookup.
        extra = {'equal': ((0x277b5, 0x27808), (0x2c5e3, 0x2ca7d)),
                 'contains': ((0x2ce99, 0x2d440),)}.get(name, ())
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
        observation_fields=['result', 'retained_first', 'retained_second', 'shared_backing', 'reference_counts', 'allocation_lifetime'],
        assumptions=json.loads((workspace / 'assumptions.json').read_text()),
        scope='jq value relations: recursive equality/containment, representation identity and object merging with retained aliases.',
        output=output)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('workspace', 'retained', 'output'):
        parser.add_argument(name, type=Path)
    args = parser.parse_args()
    prepare(args.workspace.resolve(), args.retained.resolve(), args.output.resolve())
