"""Export compared authored C through existing V3 source packages.

The portable build is a component library. Application entry and platform/service
bindings remain explicit requirements; exporting does not grant qualification.
"""
from __future__ import annotations

import json
from pathlib import Path
import tempfile

from ..components.comparison_dependencies import comparison_units, comparison_includes
from ..components.comparison_composition import contract_binding, contract_identity
from ..components.comparison_package import load_comparison_package, package_file
from ..components.comparison_run import load_comparison_result
from ..components.interface_package_v5 import ComponentInterfaceIntentV1
from ..components.source import build_component_source_package, load_component_source_package
from ..components.source import _build_path, checked_source_build as checked_source_build
from ..util import sha256_file, write_json




def _unit_inputs(root, unit, entries, input_hashes):
    selected = [row for row in entries if row['unit'] == unit['id'] and row['source'] in unit['sources']]
    if {row['source'] for row in selected} != {p for p in unit['sources'] if p.endswith('.c')}:
        raise ValueError('source export requires compiled authored units for '+unit['id'])
    names = set(unit['sources']); system = {}
    for row in selected:
        for name, digest in row['inputs'].items():
            if name.startswith('@/'):
                relative = name[2:]
                if sha256_file(package_file(root, relative)) != digest:
                    raise ValueError('compiled source input changed: '+relative)
                names.add(relative)
            else:
                system.setdefault(Path(name).name, set()).add(digest)
    names.update((unit.get('representation') or {}).get('inputs', {}).values())
    # Retain licenses and the reviewed operator narrative without copying native
    # fixture headers, comparison drivers, objects or original runtime binaries.
    for directory in unit['include_directories']:
        for path in (root/directory).rglob('*'):
            if path.is_file() and (path.name.startswith(('COPYING', 'LICENSE')) or path.suffix == '.md'):
                names.add(path.relative_to(root).as_posix())
    prefix = '' if not unit['interface'].startswith('dependencies/') else 'dependencies/'+unit['id']+'/'
    if any(not name.startswith(prefix) for name in names):
        prefix = ''  # Preserve a genuine cross-directory include relationship.
    digests = {_build_path(name.removeprefix(prefix)):input_hashes[name] for name in sorted(names)}
    names = {_build_path(name.removeprefix(prefix)):package_file(root, name) for name in sorted(names)}
    if any(sha256_file(path) != digests[name] for name,path in names.items()):
        raise ValueError('source export inputs changed while reading the comparison')
    return names, prefix, digests, {name:sorted(values) for name,values in sorted(system.items())}


def source_makefile(units: dict) -> str:
    """Render one conventional library from explicit per-component build inputs."""
    objects=[];rules=[]
    for identity,unit in sorted(units.items()):
        base=(Path(unit['source_package']).parent/'sources').as_posix()+'/'
        build=unit['build'];includes=['-I'+base+p for p in build['includes']]
        dependencies=' '.join(base+name for name in build['inputs'])
        for index,name in enumerate(build['sources']):
            obj=f'build/{identity}-{index}.o';objects.append(obj)
            rules.append(f'{obj}: {dependencies}\n\t@mkdir -p build\n'
                f'\t$(CC) $(CPPFLAGS) $(CFLAGS) {" ".join(includes)} -MMD -MP -c {base+name} -o $@\n')
    make=['# Conventional source build; CC/AR may select another architecture.',
        'CC ?= cc','AR ?= ar','CFLAGS ?= -O2 -std=c11 -Wall -Wextra -Werror',
        'OBJECTS := '+' '.join(objects),'.PHONY: all clean','all: liblifted.a',
        'liblifted.a: $(OBJECTS)\n\trm -f $@\n\t$(AR) rcs $@ $(OBJECTS)',*rules,
        '-include $(OBJECTS:.o=.d)','clean:\n\trm -rf build liblifted.a','']
    return '\n\n'.join(make)




def export_comparison_sources(*, comparisons: list[Path], target_id: str, output: Path, update: bool = False,
                              update_components: bool = False,
                              accept_boundary_changes: list[str] | None = None,
                              component_ids: list[str] | None = None,
                              remove_component_ids: list[str] | None = None) -> dict:
    """Emit a buildable source closure; no original runtime or toolkit is copied."""
    if update and update_components:raise ValueError('choose --update or --update-components')
    if component_ids is not None and not update_components:
        raise ValueError('named source updates require --update-components')
    if remove_component_ids is not None and not update_components:
        raise ValueError('component removal requires --update-components')
    if update or update_components:
        from .source_export_update import update_comparison_sources
        return update_comparison_sources(comparisons=comparisons, target_id=target_id, output=output,
                                         accept_boundary_changes=accept_boundary_changes,partial=update_components,
                                         component_ids=component_ids,remove_component_ids=remove_component_ids)
    if accept_boundary_changes:
        raise ValueError('accepting boundary changes requires --update or --update-components')
    output = Path(output).resolve()
    if not comparisons:
        raise ValueError('source export requires at least one matching comparison')
    if output.exists() and (not output.is_dir() or any(output.iterdir())):
        raise ValueError('source export output must be a new or empty directory')
    prepared = {}; symbols = {}; receipts = []
    for comparison in comparisons:
        comparison = Path(comparison).resolve()
        if output.is_relative_to(comparison) or comparison.is_relative_to(output):
            raise ValueError('source export output must be separate from comparison inputs')
        result = load_comparison_result(comparison)
        if result['target_id'] != target_id or result['status'] != 'match':
            raise ValueError('source export requires a matching comparison for the requested target')
        root = comparison/'inputs'
        plan, _ = load_comparison_package(root)
        compilation = json.loads((comparison/'build/compilation.json').read_text())
        receipts.append(dict(receipt_sha256=result['receipt_sha256'], scope=plan['scope'],
            component_id=plan['component_id'],
            cases=[row['id'] for row in result['cases']], formal_check=result['formal_check'],
            original=plan['original'], observation_fields=plan['observation_fields']))
        for unit in comparison_units(plan):
            if unit['id'] == plan['component_id']:
                unit = {**plan, **unit}
            identity = _build_path(unit['id'])
            if '/' in identity or identity in ('.', '..'):
                raise ValueError('source export component identity must be a basename')
            names, prefix, digests, system = _unit_inputs(root, unit, compilation['units'], result['input_sha256s'])
            interface = ComponentInterfaceIntentV1.parse(json.loads(package_file(root, unit['interface']).read_text()))
            authored = [name.removeprefix(prefix) for name in unit['sources']]
            includes = [_build_path(p.removeprefix(prefix)) for p in comparison_includes(plan, unit)]
            assumptions = unit.get('assumptions', plan['assumptions'])
            description = dict(operation_symbols=unit['operation_symbols'],
                interface=interface.to_payload(), assumptions=assumptions, includes=includes,
                contract=contract_binding(root, unit), contract_sha256=contract_identity(root, unit),
                requirements=unit.get('requirements', []), recursion_groups=unit.get('recursion_groups', []),
                private_headers=sorted(name.removeprefix(prefix) for name in unit.get('private_headers',[])),
                local_shared_contract=unit.get('local_shared_contract'),
                files=digests)
            reference = dict(comparison_receipt_sha256=result['receipt_sha256'],
                service_bridge=unit.get('service_bridge'))
            if identity in prepared:
                if description != prepared[identity]['description']:
                    raise ValueError('conflicting source or boundary selections for '+identity)
                if reference not in prepared[identity]['binding_references']:
                    prepared[identity]['binding_references'].append(reference)
                continue
            for symbol in unit['operation_symbols'].values():
                if symbol in symbols: raise ValueError('selected components repeat an operation symbol: '+symbol)
                symbols[symbol] = identity
            prepared[identity] = dict(names=names, authored=authored, description=description,
                system=system, binding_references=[reference])

    output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='source-export-', dir=output.parent) as temporary:
        stage = Path(temporary)/'project'; stage.mkdir()
        units = {}
        for identity, unit in sorted(prepared.items()):
            directory = stage/'components'/identity
            description = unit['description']; names = unit['names']
            source = build_component_source_package(lift_unit_id=identity,
                files={name:names[name] for name in unit['authored']},
                shared_inputs={name:path for name,path in names.items() if name not in unit['authored']},
                operation_symbols=description['operation_symbols'], out_dir=directory)
            load_component_source_package(directory)
            if any(sha256_file(directory/'sources'/name) != digest for name,digest in description['files'].items()):
                raise ValueError('source export inputs changed while copying '+identity)
            write_json(directory/'interface.json', description['interface'])
            units[identity] = dict(source_package=f'components/{identity}/source-package.json',
                implementation_sha256=source['implementation_sha256'], interface=f'components/{identity}/interface.json',
                interface_sha256=sha256_file(directory/'interface.json'),
                operation_symbols=description['operation_symbols'], assumptions=description['assumptions'],
                contract=description['contract'], contract_sha256=description['contract_sha256'],
                requirements=description['requirements'], recursion_groups=description['recursion_groups'],
                local_shared_contract=description['local_shared_contract'],
                **({'private_headers':description['private_headers']} if description['private_headers'] else {}),
                build=dict(sources=[p for p in unit['authored'] if p.endswith('.c')],
                    includes=description['includes'],inputs=sorted(names)),
                required_services=description['interface']['services'],
                comparison_binding_references=unit['binding_references'],
                comparison_system_headers=unit['system'])
        from ..components.state_ownership import check_state_owner_selection
        check_state_owner_selection({name:unit['contract'].get('state_owners') for name,unit in units.items()})
        (stage/'Makefile').write_text(source_makefile(units))
        (stage/'README.md').write_text(
            '# Exported component source\n\nRun `make` with a C11 compiler and `ar`. '
            'Override `CC` and `AR` for a different toolchain; run `make clean` when '
            'changing toolchains or flags. This build needs neither '
            'the extractor nor Python, Nix or the original executable.\n\n'
            'The result is `liblifted.a`, not a complete program. Supply an application '
            'entry and implementations of the listed services/state/representation '
            'contracts. Each component keeps its existing generated API and reviewed '
            'assumptions. Compile adapters against one component interface per C file; '
            'shared generated support types are not a combined multi-interface header.\n\n'
            'The retained comparisons test their original fixture environments; they '
            'do not validate a new backend, compiler or architecture. Source provenance '
            'and successful compilation do not grant qualification or activation. '
            'Existing license and boundary documents are retained in component sources.\n')
        with (stage/'README.md').open('a') as document:
            document.write('\n`source-export.json` retains original input identities and '
                'comparison binding references alongside the exact service contracts. '
                'These describe the compared environment, not an accepted portable backend. '
                'Review adapter symbols, transports and outcomes before generating a new '
                'bridge; supply its C declarations/implementations and validate the program. '
                'Different comparisons of the same component may have different bindings. '
                'Resource instrumentation and native ABI assumptions do not transfer automatically.\n')
        report = dict(version=1, authority='source-provenance-only', target_id=target_id,
            scope='component-library', whole_program_portable=False, qualification=False,
            comparisons=receipts, components=units,
            omitted_roles=['comparison-drivers', 'native-fixture-adapters', 'original-runtime', 'compiled-objects'],
            required_integration=['application-entry', 'service-and-state-bindings', 'platform-backends', 'program-validation'])
        from ..operator.source_export_guidance import write_source_export_guidance
        write_source_export_guidance(stage, report)
        report['files']={str(p.relative_to(stage)):sha256_file(p) for p in stage.rglob('*') if p.is_file()}
        write_json(stage/'source-export.json', report)
        if output.exists(): output.rmdir()
        stage.rename(output)
    return report
