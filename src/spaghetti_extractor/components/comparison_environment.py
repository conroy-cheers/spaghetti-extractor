"""Installed tools and C adapter helpers for experimental comparison authoring.

Return existing comparison-factory arguments and header paths. No environment
artifact, target boundary, adapter semantics or assurance is inferred here.
"""
from __future__ import annotations

import copy
from contextlib import contextmanager
import json
import os
from pathlib import Path, PurePosixPath
import shutil
import subprocess
import tempfile

from .comparison_package import load_comparison_package, package_file, retained_comparison_environment

PYTHON_RESOURCES = (
    'src/spaghetti_extractor/resources/native/pe32-entry-hook.h',
    'src/spaghetti_extractor/resources/native/pe32-import-hook.h',
    'src/spaghetti_extractor/resources/native/pe32-process-observer.h',
    'src/spaghetti_extractor/resources/comparison/spx-observation.h',
)


def _executable(name: str) -> Path:
    found = shutil.which(name)
    if found is None:
        raise ValueError(f'missing {name}; enter the project Nix development shell')
    return Path(found).absolute()


def native_environment(package: Path | None = None) -> dict:
    """Use an explicit retained package, or the lifting shell's PE32 tools/DLLs."""
    if package is not None:
        return retained_comparison_environment(package)
    compiler = _executable('i686-w64-mingw32-gcc')
    runtime = {}
    gcc_dll = subprocess.run([str(compiler), '-print-file-name=libgcc_s_sjlj-1.dll'],
        check=True, capture_output=True, text=True).stdout.strip()
    thread_dll = os.environ.get('SPAGHETTI_PE32_MCFGTHREAD_DLL')
    if not thread_dll:
        raise ValueError('SPAGHETTI_PE32_MCFGTHREAD_DLL is missing; use the project Nix development shell')
    for name, value in [('libgcc_s_sjlj-1.dll', gcc_dll), ('libmcfgthread-2.dll', thread_dll)]:
        path = Path(value)
        if not path.is_absolute() or not path.is_file():
            raise ValueError(f'compiler runtime {name} is not an existing absolute file: {path}')
        runtime[name] = path
    return dict(compiler=compiler, runner=_executable('wine'), server=_executable('wineserver'),
                link_files={}, runtime_files=runtime)


def host_environment() -> dict:
    """Use the selected host compiler for retained-C comparison consumers."""
    return dict(compiler=_executable('cc'), runner=None, server=None, link_files={}, runtime_files={})


@contextmanager
def retained_component_inputs(package: Path, *, component_id: str, retain_dependencies: bool = False):
    """Reuse one selected unit's boundary and C when preparing a local check.

    Yield existing prepare_comparison_package arguments. Call it inside this
    context so its temporary V3 source package remains available. The interface,
    shared inputs, services, assumptions and file roles are preserved, including
    existing supplier requirements. retain_dependencies=True also selects their
    current implementations from this network through the existing composition
    resolver. Otherwise supply those suppliers explicitly if needed. Selection
    follows declared requirements, not inferred calls or replacement-group names.

    The local driver, oracle, cases, observations, tools and evidence are not
    inherited. The operator must establish the local execution setup; a selected
    network body alone does not supply an independent comparison. This helper
    supports the source/ and headers/ layout emitted by the preparation API.
    """
    from .source import build_component_source_package

    package=package.resolve()
    plan,_=load_comparison_package(package)
    units={plan['component_id']:plan,**{row['id']:row for row in plan.get('dependencies',[])}}
    if component_id not in units:
        raise ValueError('component is absent from the comparison selection: '+component_id)
    unit=units[component_id]
    prefix='' if component_id==plan['component_id'] else 'dependencies/'+component_id+'/'

    def relative(name):
        if not name.startswith(prefix):
            raise ValueError('retained component input is outside its namespace: '+name)
        return name.removeprefix(prefix)

    includes=[relative(name) for name in unit['include_directories']]
    if includes not in (['source'],['source','headers']):
        raise ValueError('retained component inputs require the prepared source/headers include layout; '
                         'use explicit authoring inputs for custom include directories')
    authored={}
    for name in unit['sources']:
        local=relative(name)
        if not local.startswith('source/'):
            raise ValueError('retained authored file is outside source/: '+name)
        authored[local.removeprefix('source/')]=package_file(package,name)
    shared={};headers={}
    for directory in includes:
        for path in sorted((package/prefix/directory).rglob('*')):
            if path.is_symlink():
                raise ValueError('retained component include tree contains symbolic links')
            if not path.is_file():continue
            name=path.relative_to(package/prefix/directory).as_posix()
            checked=package_file(package,path.relative_to(package).as_posix())
            if directory=='headers':headers[name]=checked
            elif name not in authored:shared[name]=checked
    inputs=dict(interface_package=package_file(package,unit['interface']),
        target_id=plan['target_id'],component_id=component_id,include_files=headers,
        **{name:copy.deepcopy(unit[name]) for name in ('assumptions','input_domain','resource_checks',
            'service_catalog','service_bridge','requirements','recursion_groups','local_shared_contract','state_owners') if name in unit})
    if 'representation' in unit:
        inputs['representation']={**copy.deepcopy(unit['representation']),
            'inputs':{name:relative(path) for name,path in unit['representation']['inputs'].items()}}
    if 'private_headers' in unit:
        inputs['private_headers']=[relative(name) for name in unit['private_headers']]
    if retain_dependencies:
        if 'composition' not in plan and plan.get('dependencies'):
            raise ValueError('retaining suppliers requires declared composition; select reviewed dependencies explicitly')
        suppliers=sorted({row['supplier'] for row in unit.get('requirements',[]) if row['supplier']!=component_id})
        inputs['dependencies']=[dict(id=name,package=package) for name in suppliers]
        # Supplier cycle declarations travel with their selected members in the
        # resolver. Do not change this unit's boundary merely because it calls
        # a recursive supplier; that would prevent its C-only return handoff.
    with tempfile.TemporaryDirectory(prefix='spaghetti-retained-component-') as temporary:
        source=Path(temporary)/'source'
        build_component_source_package(lift_unit_id=component_id,files=authored,shared_inputs=shared,
            operation_symbols=unit['operation_symbols'],out_dir=source)
        yield dict(inputs,source_package=source)


def _network_service_selection(package: Path, units: dict, names: dict) -> tuple[dict,dict,dict]:
    """Resolve explicit local-name -> component/service choices within one network."""
    from .service_authoring import services_from_interface, service_types
    from .interface_package_v5 import ComponentInterfaceIntentV1

    if not names or any(not isinstance(name,str) or not name for name in names):
        raise ValueError('retained service selection needs nonempty local names')
    references={};selected={}
    for local,reference in names.items():
        if not isinstance(reference,str) or len(reference.split('/'))!=2 or not all(reference.split('/')):
            raise ValueError('retained service reference must be COMPONENT/SERVICE: '+str(reference))
        owner,name=reference.split('/')
        if owner not in units:
            raise ValueError('component is absent from the comparison selection: '+owner)
        references[local]=(owner,name)
        selected.setdefault(owner,set()).add(name)
    definitions={};bridges={}
    for owner,needed in selected.items():
        unit=units[owner]
        interface=ComponentInterfaceIntentV1.parse(json.loads(package_file(package,unit['interface']).read_text()))
        definitions[owner]=services_from_interface(interface,unit.get('service_catalog'),names=sorted(needed))
        bridges[owner]=unit.get('service_bridge')
        if bridges[owner] is None:
            raise ValueError('retained services need an existing generated service binding: '+owner)
    services={local:definitions[owner][name] for local,(owner,name) in references.items()}
    # Exact layouts must agree before merging their executable transport choices.
    service_types(services)
    transports={};origins={};adapters={}
    for local,(owner,name) in references.items():
        bridge=bridges[owner];origin=owner+'/'+name
        adapters[local]=copy.deepcopy(bridge['adapters'][name])
        for type_id,spec in bridge['transports'].items():
            if type_id not in services[local].schema.type_index:continue
            if type_id in transports and transports[type_id]!=spec:
                raise ValueError('retained service transport differs for type '+type_id+' between '+
                    origins[type_id]+' and '+origin+'; author a reviewed common C binding explicitly')
            transports[type_id]=copy.deepcopy(spec);origins.setdefault(type_id,origin)
    return services,transports,adapters


def retained_service_inputs(package: Path, *, names, native_symbol: str | None,
                            adapters, headers, component_id: str | None = None) -> tuple[dict,dict]:
    """Select reviewed services and executable inputs for a new comparison.

    Return ServiceDefinitions and prepare_comparison_package keyword arguments.
    A names list selects services from component_id (the root by default).
    Alternatively, names maps each new local name to COMPONENT/SERVICE, selecting
    reviewed services from several units without renaming their contracts. In
    this form omit component_id. Exact shared types and C transport choices must
    agree; only transports used by those service schemas are retained. Additional
    entry-only transports and semantic adaptations remain explicit recipe inputs.
    Lists of file names remain relative to the package's adapters/ or headers/;
    mappings select destination names from explicit package-relative paths,
    including shared root inputs and selected neighboring adapters. The new
    wrapper entry is explicit too; None selects operator-owned C entries.
    No operation, source body, driver, cases,
    assumptions, oracle declaration or evidence is inherited automatically.
    Reusing declarations/transport does not establish adapter correctness or
    independence; inspect the selected C before defining the new boundary.
    """
    from .service_authoring import service_catalog, services_from_interface
    from .interface_package_v5 import ComponentInterfaceIntentV1

    package=package.resolve()
    plan,interface=load_comparison_package(package)
    units={plan['component_id']:plan,**{row['id']:row for row in plan.get('dependencies',[])}}
    if isinstance(names,dict):
        if component_id is not None:
            raise ValueError('choose component_id with a service list or explicit COMPONENT/SERVICE references')
        services,transports,bindings=_network_service_selection(package,units,names)
    else:
        identity=plan['component_id'] if component_id is None else component_id
        if identity not in units:
            raise ValueError('component is absent from the comparison selection: '+str(identity))
        unit=units[identity]
        if identity!=plan['component_id']:
            interface=ComponentInterfaceIntentV1.parse(json.loads(package_file(package,unit['interface']).read_text()))
        services=services_from_interface(interface,unit.get('service_catalog'),names=names)
        bridge=unit.get('service_bridge')
        if bridge is None:
            raise ValueError('retained services need an existing generated service binding; author C bindings explicitly for this package')
        transports=copy.deepcopy(bridge['transports'])
        bindings={name:copy.deepcopy(bridge['adapters'][name]) for name in services}
    if native_symbol is not None and (not isinstance(native_symbol,str) or not native_symbol):
        raise ValueError('retained services require an explicit native wrapper symbol or None for manual entries')

    def files(role, selected):
        if isinstance(selected,(list,tuple)):
            if any(not isinstance(name,str) or not name for name in selected) or len(set(selected))!=len(selected):
                raise ValueError('retained '+role+' require unique explicit file names')
            selected={name:role+'/'+name for name in selected}
        if not isinstance(selected,dict):
            raise ValueError('retained '+role+' require file names or an explicit destination-to-package-path mapping')
        available={name for member in units.values() for name in member['adapters']}
        result={}
        for name,relative in selected.items():
            if (not isinstance(name,str) or not name or PurePosixPath(name).is_absolute()
                    or '..' in PurePosixPath(name).parts or PurePosixPath(name).as_posix()!=name or name=='.'):
                raise ValueError('retained '+role+' destination must be a relative file name: '+str(name))
            checked=package_file(package,relative)
            if role=='adapters' and relative not in available:
                raise ValueError('retained adapter is not selected by the source package: '+relative)
            result[name]=checked
        return result

    return services,dict(**retained_comparison_environment(package),
        adapter_files=files('adapters',adapters),include_files=files('headers',headers),
        service_catalog=service_catalog(services).to_payload(),
        service_bridge=dict(native_symbol=native_symbol,transports=transports,adapters=bindings))


def observation_headers() -> dict[str, Path]:
    """Portable JSON output helpers for explicitly chosen C-driver observations."""
    path=Path(__file__).resolve().parents[1]/'resources/comparison/spx-observation.h'
    if not path.is_file():raise ValueError('installed comparison observation header is missing')
    return {path.name:path}


def native_adapter_headers(*names: str) -> dict[str, Path]:
    """Select installed PE32 interception/observation helpers for include_files.

    These helpers are for single-threaded comparison drivers. Native signatures,
    whole-body ranges, image identity, state transport and observations remain
    explicit caller responsibilities. They are not portable program backends.
    With no names, retain the original entry/import selection; process observation
    is explicit so unrelated packages do not gain unused inputs.
    """
    available = {Path(name).name: Path(__file__).resolve().parents[1] / name.removeprefix(
        'src/spaghetti_extractor/') for name in PYTHON_RESOURCES if '/native/' in name}
    if set(names) - available.keys():
        raise ValueError('unknown native adapter headers: '+', '.join(sorted(set(names) - available.keys())))
    selected = {name: available[name] for name in names or ('pe32-entry-hook.h', 'pe32-import-hook.h')}
    if any(not path.is_file() for path in selected.values()):
        raise ValueError('installed native adapter headers are missing')
    return selected
