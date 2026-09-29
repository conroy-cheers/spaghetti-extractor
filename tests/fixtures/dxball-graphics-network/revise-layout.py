"""Apply a reviewed portable graphics layout to existing local and caller workspaces.

The C adapter maps named fields to the unchanged PE state. This recipe preserves
selected C and uses the ordinary revision API for the coupled representation
group. It prepares drafts; local and consumer comparisons remain necessary.
"""
import argparse
from pathlib import Path
import time

from spaghetti_extractor.components.comparison_composition import contract_identity
from spaghetti_extractor.components.comparison_package import (
    comparison_preparation, load_comparison_package, revise_comparison_package,
)
from spaghetti_extractor.util import sha256_file, write_json

def prepare(packages, layout, revision, output, *, consumer=None):
    started = time.monotonic()
    consumer = consumer or packages/'graphics-initialize'
    caller, _ = load_comparison_package(consumer)
    if (caller['target_id'], caller['component_id']) != ('dxball', 'graphics-initialize'):
        raise ValueError('requires the reviewed graphics initializer consumer')
    group = caller['representation']['group']
    selected = {unit['id']: unit for unit in caller.get('dependencies', [])}
    if group['id'] != 'dxball-graphics' or set(group['members']) != set(selected) | {caller['component_id']}:
        raise ValueError('review the changed graphics selection before revising its shared layout')
    if not layout.is_file() or not revision or revision == caller['representation']['revision']:
        raise ValueError('supply a reviewed layout file and a new explicit representation revision')
    preparations = {}
    with comparison_preparation(output) as staged:
        for identity in group['members']:
            main = identity == caller['component_id']
            package = consumer if main else packages/identity
            plan, _ = load_comparison_package(package)
            if (plan['target_id'], plan['component_id']) != ('dxball', identity):
                raise ValueError('local package has another target or component: '+identity)
            representation = plan.get('representation') or {}
            if (representation.get('group') != caller['representation']['group']
                    or representation.get('inputs') != {
                        'layout': 'headers/graphics-state.h', 'source-layout': 'source/graphics-state.h',
                        'runtime-contract': 'headers/runtime.h'}):
                raise ValueError('review the changed graphics representation declarations: '+identity)
            source_root = consumer
            unit = caller if main else selected[identity]
            prefix = '' if main else 'dependencies/'+identity+'/'
            if (contract_identity(package, plan) != contract_identity(source_root, unit)
                    or {path.removeprefix(prefix) for path in unit['sources']} != set(plan['sources'])):
                raise ValueError('local boundary differs from the selected consumer: '+identity)
            # Carry the consumer's actual chosen C, including in-progress edits,
            # while each local package retains its own oracle and case driver.
            sources = {path.removeprefix(prefix+'source/'): source_root/path for path in unit['sources']}
            adapters = {path.removeprefix('adapters/'): package/path for path in plan['adapters']}
            if not main:
                exports = {Path(path).name: path for path in plan.get('export_adapters', [])}
                chosen = {Path(path).name: source_root/path for path in unit['adapters']}
                if exports.keys() != chosen.keys():
                    raise ValueError('review changed dependency adapter ownership: '+identity)
                for key, path in exports.items():
                    adapters[path.removeprefix('adapters/')] = chosen[key]
            before = time.monotonic()
            # This reviewed same-field layout recipe covers the selected callers'
            # named-field accesses and adapters. Other boundary changes need their
            # own review; the API does not infer compatibility from these names.
            reviews = [node.get('id', node.get('component_id'))+'/'+req['id']
                       for node in [plan, *plan.get('dependencies', [])]
                       for req in node.get('requirements', []) if req['supplier'] in group['members']]
            revise_comparison_package(package=package, output=staged/identity,
                source_files=sources, adapter_files=adapters,
                representation_updates={group['id']: dict(revision=revision,
                    inputs={'layout': layout, 'source-layout': layout}, reviewed_requirements=reviews)})
            preparations[identity] = dict(seconds=time.monotonic()-before,
                local_package=str(package), selected_sources=list(unit['sources']),
                local_boundary_sha256=contract_identity(package, plan))
        write_json(staged/'layout-revision.json', dict(status='prepared', authority=False,
            layout=str(layout), layout_sha256=sha256_file(layout), revision=revision,
            consumer=str(consumer), packages=preparations, seconds=time.monotonic()-started,
            original_machine_layout_unchanged=True, selected_c_preserved=True,
            comparisons_required=True,
            scope='Reviewed DX-Ball graphics state with unchanged fields, native transport and lifetime conventions.'))
    print(output/'graphics-initialize')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('packages', type=Path, help='existing local graphics workspaces')
    parser.add_argument('layout', type=Path, help='reviewed replacement graphics-state.h')
    parser.add_argument('revision', help='explicit new representation revision')
    parser.add_argument('output', type=Path)
    parser.add_argument('--consumer', type=Path, help='edited or native initializer workspace to retain')
    args = parser.parse_args()
    prepare(args.packages.resolve(), args.layout.resolve(), args.revision, args.output.resolve(),
            consumer=args.consumer.resolve() if args.consumer else None)
