"""Start ordinary C authoring from an existing interface, before fixture preparation."""
from __future__ import annotations

import json
import os
from pathlib import Path, PurePosixPath
import re
import shlex
import shutil
import tempfile
import time
from urllib.parse import quote

from ..components.component_c_v5 import render_component_c_headers_v5, render_component_c_skeleton_v5
from ..components.interface_package_v5 import ComponentInterfaceIntentV1, compile_component_interface_v5
from ..components.comparison_package import comparison_preparation
from ..util import write_json
from .source_guidance import write_authoring_guidance


def _preparation_recipe(target: str, component: str, sources: list[str],
                        adapters: list[str], includes: list[str]) -> str:
    source_map='{'+', '.join(json.dumps(name.removeprefix('source/'))+': WORKSPACE / '+json.dumps(name)
                            for name in sources)+'}'
    def file_map(names,prefix):
        return '{'+', '.join(json.dumps(name.removeprefix(prefix+'/'))+': WORKSPACE / '+json.dumps(name)
                             for name in names)+'}'
    return f'''"""Edit this recipe to connect authored C to an executable comparison.

Run: python prepare.py --output /path/to/new-comparison
Preparation copies inputs; it does not compile, run Wine, or create assurance.
"""
import argparse
import json
from pathlib import Path
import shlex

from spaghetti_extractor.components.comparison_environment import host_environment, native_environment, observation_headers
from spaghetti_extractor.components.comparison_package import prepare_comparison_package

WORKSPACE = Path(__file__).resolve().parent


def source_inputs():
    # Add helper .c/.h files here explicitly; generated headers are regenerated.
    choices = json.loads((WORKSPACE / "authoring.json").read_text())
    catalog = WORKSPACE / "service-catalog.json"
    bridge = WORKSPACE / "service-bridge.json"
    resources = WORKSPACE / "resource-checks.json"
    state = WORKSPACE / "state-owners.json"
    return dict(
        interface_package=WORKSPACE / "interface.json",
        source_files={source_map},
        operation_symbols=choices["operation_symbols"],
        target_id={target!r}, component_id={component!r},
        private_headers=choices["private_headers"] or None,
        **({{"service_catalog": json.loads(catalog.read_text())}} if catalog.exists() else {{}}),
        **({{"service_bridge": json.loads(bridge.read_text())}} if bridge.exists() else {{}}),
        **({{"resource_checks": json.loads(resources.read_text())}} if resources.exists() else {{}}),
        **({{"state_owners": json.loads(state.read_text())}} if state.exists() else {{}}),
    )


def comparison_inputs():
    # Choose an execution setup in the lifting shell:
    # environment = host_environment()                 # retained portable-C oracle
    # environment = native_environment()               # PE32 tools and Wine
    # environment = native_environment(Path("/path/to/retained-comparison"))
    environment = None
    if environment is None:
        raise ValueError("choose host_environment() or native_environment() in comparison_inputs()")
    return dict(
        **environment,
        adapter_files={file_map(adapters,'adapters')},  # list any additional driver/adapter C here
        include_files={file_map(includes,'headers')},  # observation_headers() supplies optional portable JSON output helpers
                                # other target/runtime headers belong here; authored helpers go in source_inputs()
        original_files=[],      # materialized paths, e.g. ["runtime/original.dll"]
        oracle_kind="native-original",  # use "fixture" for a synthetic oracle
        cases=[],               # e.g. [dict(id="empty", arguments=[""])]
        observation_fields=[],  # JSON fields emitted by both sides of the driver
        assumptions=json.loads((WORKSPACE / "assumptions.json").read_text())
            if (WORKSPACE / "assumptions.json").exists() else [],
                                # review admitted states, service behavior and unobserved effects
        scope="",               # the operation and environment actually exercised
        # Add representation,
        # dependencies or other existing preparation arguments when needed.
        # Runtime DLLs and original link inputs belong in the chosen environment.
    )


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    try:
        prepare_comparison_package(**source_inputs(), **comparison_inputs(), output=args.output)
    except (OSError, ValueError) as exc:
        parser.error("edit " + str(WORKSPACE / "prepare.py") + ": " + str(exc))
    print("Prepared comparison: " + str(args.output.resolve()))
    print("Next: " + shlex.join(["spaghetti-extractor", "component", "start", {target!r}, {component!r},
          "--comparison-package", str(args.output.resolve()), "--output", "/path/to/work"]))


if __name__ == "__main__":
    main()
'''


def _authoring_choices(root):
    """Read editor/entry choices as data; never execute the editable recipe."""
    from ..components.comparison_package import package_file

    if root is None or not (root/'authoring.json').exists():
        return {}
    choices=json.loads(package_file(root,'authoring.json').read_text())
    if not isinstance(choices,dict) or set(choices)!={'compiler','operation_symbols','private_headers'}:
        raise ValueError('authoring.json requires compiler, operation_symbols and private_headers')
    symbols=choices['operation_symbols'];private=choices['private_headers']
    if (not isinstance(symbols,dict) or any(not isinstance(name,str) or not name or
            not isinstance(symbol,str) or not re.fullmatch(r'[A-Za-z_][A-Za-z0-9_]*',symbol)
            for name,symbol in symbols.items())):
        raise ValueError('authoring.json operation_symbols must map operation names to C identifiers')
    if not isinstance(choices['compiler'],str) or not choices['compiler'].strip():
        raise ValueError('authoring.json compiler must be a nonempty executable path or command name')
    if (not isinstance(private,list) or any(not isinstance(name,str) or not name.startswith('source/')
            or not name.endswith('.h') or '..' in PurePosixPath(name).parts for name in private)
            or len(private)!=len(set(private))):
        raise ValueError('authoring.json private_headers must name distinct source/ headers')
    return choices


def _authored_files(args, skeleton: str, choices: dict):
    """Carry ordinary C into a reviewed interface without carrying assurance.

    Interface-only workspaces have no immutable source manifest. Selecting one
    explicitly selects its current source/ C and headers, including local edits.
    Comparison and exported selections retain their own existing import routes.
    """
    from .comparison import dependency_packages
    from ..components.comparison_source_draft import checked_source_file_selection

    files={'source/component.c':skeleton.encode('utf-8')}
    if args.reuse_source is not None:
        previous=args.reuse_source.resolve()
        output=args.output.resolve()
        if output.is_relative_to(previous) or previous.is_relative_to(output):
            raise ValueError('interface authoring source and output must be separate')
        if (previous/'comparison-plan.json').exists() or (previous/'source-export.json').exists():
            raise ValueError('interface --reuse-source requires an interface authoring workspace; '
                             'use the comparison boundary revision workflow for executable selections')
        from ..components.comparison_source_draft import read_interface_authoring_files
        _,files=read_interface_authoring_files(previous,component_id=args.unit)
    replacements=dependency_packages(getattr(args,'source_file',None),option='--source-file',key='NAME')
    removed=getattr(args,'remove_source',None) or []
    if len(set(removed))!=len(removed) or set(removed)&replacements.keys():
        raise ValueError('source removals must be unique and cannot also name replacement files')
    for name in removed:
        if name not in files:raise ValueError('source removal is not an authored file: '+name)
        del files[name]
    files.update({name:path.read_bytes() for name,path in replacements.items()})
    unit=dict(component_id=args.unit,sources=[])
    private=sorted({name for name in choices.get('private_headers',[]) if name in files} |
                   set(getattr(args,'private_header',None) or []))
    return checked_source_file_selection(args.output.resolve(),dict(original=dict(files={})),unit,files,
        private_headers=private)


def _adapter_files(args):
    """Carry selected editable adapter inputs without importing an execution plan."""
    from .comparison import dependency_packages
    from ..components.comparison_package import package_file

    files={}
    for role,option in (('adapters','adapter_file'),('headers','include_file')):
        if args.reuse_source is not None:
            directory=args.reuse_source/role
            if directory.is_symlink() or (directory.exists() and not directory.is_dir()):
                raise ValueError('interface authoring '+role+'/ must be an ordinary directory')
            for path in sorted(directory.rglob('*')):
                if path.is_symlink():raise ValueError('interface authoring '+role+'/ must not contain symbolic links')
                if path.is_file() and (role=='headers' or path.suffix=='.c'):
                    name=path.relative_to(args.reuse_source).as_posix()
                    files[name]=package_file(args.reuse_source,name).read_bytes()
        selected=dependency_packages(getattr(args,option,None),option='--'+option.replace('_','-'),key='NAME')
        for name,path in selected.items():
            relative=PurePosixPath(name)
            if relative.is_absolute() or '..' in relative.parts or str(relative)!=name or name=='.':
                raise ValueError('authoring '+role+' input must have a relative name: '+name)
            if role=='adapters' and relative.suffix!='.c':
                raise ValueError('authoring adapter input must be a C translation unit: '+name)
            files[role+'/'+name]=path.read_bytes()
    return files


def _write_boundary_knowledge(root, args, intent, symbols, sources, adapter_files):
    """Keep existing declarations and premises local before execution is prepared."""
    from ..components.comparison_source_draft import read_interface_authoring_knowledge
    from ..components.comparison_package import package_file
    from .comparison_guidance import render_boundary, _text

    if args.reuse_source is not None:
        for name in ('service-catalog.json','assumptions.json','service-bridge.json','state-owners.json'):
            if name=='service-catalog.json' and not intent.services:continue
            if (args.reuse_source/name).exists():
                (root/name).write_bytes(package_file(args.reuse_source,name).read_bytes())
    if getattr(args,'service_catalog',None) is not None:
        (root/'service-catalog.json').write_bytes(args.service_catalog.read_bytes())
    if getattr(args,'service_bridge',None) is not None:
        (root/'service-bridge.json').write_bytes(args.service_bridge.read_bytes())
    if getattr(args,'assumption_file',None):
        write_json(root/'assumptions.json',[path.read_text() for path in args.assumption_file])
    if getattr(args,'resource_checks',None) is not None:
        (root/'resource-checks.json').write_bytes(args.resource_checks.read_bytes())
    elif args.reuse_source is not None and (args.reuse_source/'resource-checks.json').exists():
        from ..components.resource_authoring import rebind_resource_checks
        previous=ComponentInterfaceIntentV1.parse(json.loads(package_file(args.reuse_source,'interface.json').read_text()))
        checks=json.loads(package_file(args.reuse_source,'resource-checks.json').read_text())
        write_json(root/'resource-checks.json',rebind_resource_checks(checks,previous=previous,interface=intent))
    if getattr(args,'state_owners',None) is not None:
        (root/'state-owners.json').write_bytes(args.state_owners.read_bytes())
    knowledge=read_interface_authoring_knowledge(root,intent)
    from ..components.state_ownership import checked_state_owners
    checked_state_owners(knowledge.get('state_owners'),sources=[name.removeprefix('source/') for name in sources])
    catalog=knowledge.get('service_catalog');assumptions=knowledge.get('assumptions')
    binding=json.loads((root/'service-bridge.json').read_text()) if (root/'service-bridge.json').exists() else None
    plan=dict(component_id=intent.component_id,operation_symbols=symbols,service_bridge=binding,**knowledge)
    from ..components.comparison_resources import materialize_resource_runtime
    from ..components.comparison_service_runtime import materialize_service_runtime
    materialize_resource_runtime(root,plan)
    materialize_service_runtime(root,plan)
    from ..components.service_c import materialize_service_bridge
    bridge=materialize_service_bridge(plan,intent)
    if bridge is not None:
        (root/'generated/comparison-service-bridge.h').write_text(bridge[0])
        write_json(root/'generated/service-coverage.json',bridge[1])
    unit=dict(interface=intent.to_payload(),operation_symbols=symbols,resource_checks=knowledge.get('resource_checks'),
        state_owners=knowledge.get('state_owners'),service_catalog=catalog,service_bridge=binding,source_navigation=dict(operations={},services={}))
    def link(name):return '['+_text(name)+']('+quote(name)+')'
    lines=['# Component boundary: '+intent.component_id, '',
        'This generated guide records the declarations at workspace creation. The JSON files below are '
        'the inputs; reopening regenerates the guide. No executable comparison or assurance is present.', '',
        'Interface: '+link('interface.json')+'. Source: '+', '.join(link(name) for name in sources)+'.', '']
    if catalog is not None:
        lines+=['Full service contracts: '+link('service-catalog.json')+'.', '']
    elif intent.services:
        lines+=['Service definitions have not been supplied. Contract identifiers alone do not describe '
            'their effects or lifetime conventions. Reopen with `--service-catalog FILE` to retain those declarations.', '']
    lines+=render_boundary(unit,link=link,implementation=lambda _:[],contract_path='resource-checks.json',
        adapter_note='not selected; establish executable C adapters during comparison preparation')
    if bridge is not None:
        lines+=['', 'Reviewed binding choices: '+link('service-bridge.json')+'. Generated bridge: '+
            link('generated/comparison-service-bridge.h')+'.',
            'Include the generated bridge once, after the portable implementation header and the native '
            'types/adapter declarations it uses. Declared resource checks generate the same instrumentation '
            'as comparison preparation; generation supplies no checked lifetime or memory behavior.']
    runtime_sources=[name for name in ('generated/comparison-resources.c','generated/comparison-services.c')
                     if (root/name).is_file()]
    if runtime_sources:
        lines+=['', 'Generated runtime support: '+', '.join(link(name) for name in runtime_sources)+'.',
            'Editor commands include these files. The comparison factory regenerates and links them; '
            'keep them out of authored adapter/source lists. Handler scopes and object transport remain adapter C responsibilities.']
    if adapter_files:
        lines+=['', 'Adapter C and support files: '+', '.join(link(name) for name in sorted(adapter_files))+'.',
            'Their editor commands use the selected compiler. Review these files and binding choices against '
            'a revised interface; generated signatures cannot establish their semantics.']
    lines+=['', '## Assumptions', '']
    if assumptions is None:
        lines+=['No assumptions have been supplied. Establish admitted states, object contents/lifetimes, '
            'aliases, service behavior and unobserved effects before comparison.']
    else:
        lines+=['Authoring premises: '+link('assumptions.json')+'.', '']
        for assumption in assumptions:lines += ['> '+line for line in assumption.splitlines()]+['']
        if not assumptions:lines+=['The supplied assumption list is empty; this is not evidence of unrestricted behavior.']
    lines+=['', '## Prepare and refine', '',
        'The editable `prepare.py` reads these catalog, assumption, binding and resource inputs. Choose original/source adapters, '
        'observations, examples and runtime inputs there; these declarations do not supply executable transport.',
        'To revise the interface, use `component start --interface-intent ... --reuse-source ...`. '
        'C, service contracts and assumptions are carried into the new workspace and its guide is regenerated. '
        'Review inherited premises; provide `--service-catalog FILE` or `--assumption-file FILE` to replace them.',
        'When attaching to an existing comparison, supplied contracts, assumptions and resource checks must match that boundary. '
        'C-only import uses that comparison\'s adapters; these adapter drafts and binding choices are not imported. '
        'Use comparison boundary revision to adopt adapter changes. No recipe or comparison is executed during import.', '']
    (root/'BOUNDARY.md').write_text('\n'.join(lines))
    return runtime_sources


def check_authoring_workspace(args) -> int:
    """Run the existing source-only checker on current unregistered authoring C."""
    from ..components.comparison_environment import _executable
    from ..components.comparison_package import comparison_preparation, package_file
    from ..components.comparison_source_draft import read_interface_authoring_files
    from ..components.source import build_component_source_package
    from .source_check import render_component_source_check, write_component_source_check

    if not args.source:
        raise ValueError('--authoring-workspace requires --source; prepare an executable comparison for behavioral checks')
    if any(getattr(args,name,None) for name in ('comparison_package','history','history_baseline','case','case_arguments',
            'reuse_comparison','dependency_package','dependency_source','rerun','conditional','local_contracts',
            'compare_baseline','region','reuse_proof','query_timeout','entry_query_timeout')):
        raise ValueError('authoring source checks cannot select comparison cases, dependencies or proof checks')
    workspace=args.authoring_workspace.resolve()
    if getattr(args,'compiler_view',False) and args.output is None:
        raise ValueError('--compiler-view requires --output to retain its diagnostic files')
    if args.output is not None:
        output=args.output.resolve()
        if output.is_relative_to(workspace) or workspace.is_relative_to(output):
            raise ValueError('source feedback output must be separate from the authoring workspace')
    intent,files=read_interface_authoring_files(workspace,component_id=args.unit)
    from ..components.comparison_source_draft import read_interface_authoring_knowledge
    state=read_interface_authoring_knowledge(workspace,intent).get('state_owners')
    choices=_authoring_choices(workspace)
    if not choices:
        raise ValueError('authoring workspace has no saved entry choices; reopen it with --interface-intent and explicit --operation-symbol choices first')
    compiler=_executable('cc');pe32=_executable('i686-w64-mingw32-gcc')
    headers=workspace/'headers';shared={}
    if headers.is_symlink() or (headers.exists() and not headers.is_dir()):
        raise ValueError('authoring headers/ must be an ordinary directory')
    for path in sorted(headers.rglob('*')):
        if path.is_symlink():raise ValueError('authoring headers/ must not contain symbolic links')
        if path.is_file():
            name=path.relative_to(workspace).as_posix()
            shared[name]=package_file(workspace,name)
    with tempfile.TemporaryDirectory(prefix='spaghetti-authoring-source-') as temporary:
        output=args.output.resolve() if args.output is not None else Path(temporary)/'check'
        with comparison_preparation(output) as staged:
            started=time.monotonic();inputs=staged/'inputs'
            write_json(inputs/'interface/component-interface-intent-v1.json',intent.to_payload())
            build_component_source_package(lift_unit_id=args.unit,
                files={name.removeprefix('source/'):package_file(workspace,name) for name in files},
                shared_inputs=shared,operation_symbols=choices['operation_symbols'],out_dir=inputs/'source')
            timings=[dict(phase='preparation',step='authoring-source-snapshot',seconds=time.monotonic()-started)]
            write_component_source_check(target_id=args.target,component_id=args.unit,
                interface_package=inputs/'interface',source_package=inputs/'source',host_compiler=compiler,pe32_compiler=pe32,
                out=staged,timings=timings,compiler_view=getattr(args,'compiler_view',False),state_owners=state)
            write_json(staged/'timings.json',timings)
        path=output/'source-check.json'
        code=render_component_source_check(path=path,payload=json.loads(path.read_text()),
            target_id=args.target,component_id=args.unit,as_json=args.json)
        if not args.json:
            print('Authored C only; adapter syntax, linking, runtime behavior and original equivalence are separate checks.')
            if args.output is not None:print('retained source feedback: '+str(output))
        return code


def start_interface_component(args) -> int:
    if args.output is None or args.apply:
        raise ValueError('interface authoring requires --output; prepare executable comparisons before source adoption')
    if any(getattr(args,key,None) for key in ('reuse_cases','case_file','dependency_package','dependency_source','refine_requirement')):
        raise ValueError('interface authoring has no comparison selection; prepare adapters and cases before importing or refining suppliers')
    intent=ComponentInterfaceIntentV1.parse(json.loads(args.interface_intent.read_text()))
    if intent.component_id!=args.unit:
        raise ValueError('interface intent belongs to another component: '+intent.component_id)
    bundle=compile_component_interface_v5(intent)
    choices=_authoring_choices(args.reuse_source)
    def fragment(name):return name.replace('-','_').replace('.','_')
    symbols={op.identity:'lifted_'+fragment(intent.component_id)+'_'+fragment(op.identity)
             for op in bundle.interface.operations}
    symbols.update({name:symbol for name,symbol in choices.get('operation_symbols',{}).items() if name in symbols})
    selected=set()
    for entry in args.operation_symbol or []:
        name,separator,symbol=entry.partition('=')
        if not separator or not re.fullmatch(r'[A-Za-z_][A-Za-z0-9_]*',symbol) or name not in symbols or name in selected:
            raise ValueError('--operation-symbol requires unique declared OPERATION=SYMBOL entries')
        symbols[name]=symbol;selected.add(name)
    compiler=choices.get('compiler') or shutil.which('cc') or 'cc'
    if args.compiler is not None:
        compiler=str(args.compiler.resolve())
    if '/' in compiler:
        path=Path(compiler)
        if not path.is_file() or not os.access(path,os.X_OK):
            raise ValueError('authoring compiler is not executable: '+str(path)+'; select the intended ABI with --compiler FILE')
    else:
        compiler=shutil.which(compiler) or compiler
    output=args.output.resolve()
    headers=render_component_c_headers_v5(bundle,symbols)
    skeleton=render_component_c_skeleton_v5(bundle,symbols)
    draft=_authored_files(args,skeleton,choices)
    adapter_files=_adapter_files(args)
    adapters=sorted(name for name in adapter_files if name.startswith('adapters/'))
    includes=sorted(name for name in adapter_files if name.startswith('headers/'))
    sources=sorted(draft.files)
    translation_units=[name for name in sources if name.endswith('.c')]
    directories=['generated','source',*(['headers'] if includes else [])]
    source_check=shlex.join(['spaghetti-extractor','component','check',args.target,args.unit,
        '--source','--authoring-workspace',str(output)])
    with comparison_preparation(output) as staged:
        write_json(staged/'interface.json',intent.to_payload())
        write_json(staged/'authoring.json',dict(compiler=compiler,operation_symbols=symbols,private_headers=draft.private_headers))
        (staged/'generated').mkdir();(staged/'source').mkdir()
        for name,text in headers.items():
            (staged/'generated'/name).write_text(text)
        if '#include "spx-atomics.h"' in headers['portable-component.h']:
            from ..components.atomics import spx_atomics_header
            (staged/'generated/spx-atomics.h').write_text(spx_atomics_header())
        for name,data in {**draft.files,**adapter_files}.items():
            path=staged/name;path.parent.mkdir(parents=True,exist_ok=True);path.write_bytes(data)
        runtime_sources=_write_boundary_knowledge(staged,args,intent,symbols,sources,adapter_files)
        syntax=[compiler,'-std=c11','-Wall','-Wextra',*[part for directory in directories for part in ('-I',str(output/directory))],
                '-fsyntax-only',*[str(output/name) for name in [*translation_units,*adapters,*runtime_sources]]]
        (staged/'generated/component-skeleton.c').write_text(skeleton)
        (staged/'prepare.py').write_text(_preparation_recipe(args.target,args.unit,sources,adapters,includes))
        write_authoring_guidance(staged,workspace=output,sources=translation_units,
            adapter_sources=[*adapters,*runtime_sources],include_directories=directories,compiler=compiler,header='generated/portable-component-implementation.h',
            check_command=shlex.join(syntax),check_label='Syntax check',boundary_guide='BOUNDARY.md',source_check_command=source_check)
        lines=['# Start a component implementation','',
            'This workspace contains your interface, generated C declarations and selected authored C.',
            'It has no original implementation, executable comparison, tested behavior or proof.','',
            'Read [BOUNDARY.md](BOUNDARY.md) for operations, shared types, service contracts and authoring assumptions.','',
            '1. Edit '+', '.join('`'+name+'`' for name in sources)+'; implement every declared operation.',
            '2. Use `compile_commands.json` in your editor, or the syntax command in `AUTHORING.md`.',
            '   In the lifting shell, run `'+source_check+'` for host/PE32 compilation and C-profile feedback before a comparison exists.',
            '3. Establish original/source entry adapters, shared state and services, cases and meaningful observations.',
            '4. Fill in `comparison_inputs()` in `prepare.py`, and list any helper C/headers in `source_inputs()`.',
            '   Run `python prepare.py --output /path/to/new-comparison` in the lifting shell.',
            '5. Open that prepared comparison with `component start --comparison-package`, then check and diagnose it.','',
            'Generated headers describe the declaration. They do not implement services or memory transport.',
            'Keep source changes in ordinary C; revise the interface through its authoring API.',
            'A populated destination is preserved: start a revised interface in another directory.','',
            '## Revise before comparison preparation','',
            'Use `'+shlex.join(['spaghetti-extractor','component','start',args.target,args.unit,
                '--interface-intent','REVISED.json','--reuse-source',str(output),
                '--output','NEW_WORKSPACE'])+'`.',
            'It copies the current `source/` C and headers, then regenerates declarations and editor commands.',
            '`authoring.json` retains C entry names, the editor compiler and private helper-header roles as editable setup data. '
            'Reopening reads that data without executing `prepare.py`. Existing operations keep their names; new entries use the normal defaults. '
            'Use `--operation-symbol` or `--compiler` to override a choice. An unavailable retained compiler needs an explicit replacement.',
            'Use `--source-file source/NAME=FILE` and `--remove-source source/NAME` to change the file selection.',
            'List additional implementation-only headers with `--private-header source/NAME`; retained roles follow surviving files. '
            'Review an intentional role change in `authoring.json` before reopening. Older workspaces without this file need their choices supplied once.',
            '`generated/component-skeleton.c` shows the new operation signatures without overwriting your C.',
            'The new `prepare.py` lists the selected files. Comparison inputs are unconfigured:',
            'review the old recipe and its adapters against the new interface before carrying that setup forward.',
            'Existing service contracts and assumptions are retained. Catalog bindings are checked against the selected interface; '
            'review inherited premises in `BOUNDARY.md`. Use `--service-catalog` and `--assumption-file` for changed premises.',
            'The previous workspace is unchanged. Carrying C does not establish interface compatibility.','',
            '## Prepare adapter C before execution','',
            '`--service-bridge FILE` retains the existing reviewed binding specification: `adapters`, `transports` and `native_symbol`. '
            'The existing generator emits `generated/comparison-service-bridge.h` and its coverage description. '
            'Supply the matching service catalog; adapter symbols, transport functions and outcome predicates remain explicit C choices.',
            '`--adapter-file NAME=FILE` copies adapter C into `adapters/`; `--include-file NAME=FILE` copies support files into `headers/`. '
            'Names are relative to those directories. Use `--compiler` for the intended adapter ABI. '
            'Editor commands and the syntax command include the selected adapter C and headers.',
            'Interface revision carries current `adapters/` C, `headers/` files and the binding specification, then regenerates the bridge. '
            'Review that C against changed declarations. Remove obsolete files in the old draft before reopening; '
            'provide `--service-bridge` when binding choices change.',
            'The generated recipe lists these local files. Add later files to that recipe or reopen the draft. '
            'Original entry setup, runtime/link inputs, cases and observations remain explicit preparation work. '
            'C-only attachment to an existing comparison retains its adapters; use boundary revision to adopt adapter changes.','',
            '`--resource-checks FILE` retains the existing operation resource observation settings and generates their runtime C/headers. '
            'Service catalogs also generate any declared nonlocal-handler support. Editor commands cover those generated C files; '
            'the comparison factory regenerates and links them, so do not list them as authored adapters.',
            'Reopening retains resource settings and rebinds them across unrelated schema changes using the existing revision rules. '
            'Changed operation values/types require explicit reviewed settings. Generation is not execution or lifetime assurance.','',
            '## Prepare an executable comparison','',
            '`prepare.py` is an ordinary editable Python recipe using `prepare_comparison_package`.',
            'It already carries the interface, source files, component identity and operation symbols.',
            'Choose `host_environment()` for a retained C oracle or `native_environment()` for PE32/Wine.',
            'Both use installed tools from the lifting shell; `native_environment(Path(...))` reuses a retained setup.',
            'Fill in the original/source adapters, headers, original files, cases, observations, assumptions and scope.',
            'Declare services, resources and representation transport when the boundary needs them.',
            'Preparation copies current inputs through the existing factory; it does not compile or execute either side.',
            'Run any subsequent Wine comparison inside `spaghetti-headless-wayland`.',
            'The recipe stays editable and uses paths relative to its own directory. Starting again does not overwrite it.','',
            'Do not pass generated headers as authored C. The comparison factory regenerates them from the interface.',
            'For grouped entries, implement every operation in the symbol map; private helpers need no new component.','',
            '## Attach an existing comparison setup','',
            'If a prepared comparison already supplies the matching interface and execution setup, carry this C directly:', '',
            '```sh',shlex.join(['spaghetti-extractor','component','start',args.target,args.unit,
                '--comparison-package','PREPARED','--reuse-source',str(output),'--output','COMPARISON_WORKSPACE']),'```','',
            'Use `--comparison-result CHECK` instead of `--comparison-package PREPARED` to retain its reuse baseline. '
            'The selected comparison supplies the target, operation symbols, header roles, assumptions, adapters and cases. '
            'Only current `source/` C and headers are imported; `prepare.py` is not executed and no evidence is inherited.',
            'The interface and any supplied service catalog/assumptions/resource checks must match exactly, and existing shared headers must be unchanged. '
            'Review a changed boundary with the revision workflow, or reopen this C with the selected interface first. '
            'For a supplier, `--dependency-source COMPONENT=DIR` imports the same draft into an existing consumer check.', '']
        (staged/'README.md').write_text('\n'.join(lines))
    print('wrote interface authoring workspace: '+str(output))
    print('edit: '+', '.join(str(output/name) for name in sources))
    print('boundary: '+str(output/'BOUNDARY.md'))
    if args.reuse_source is not None:
        print(f'carried {len(sources)} authored C/header files; adapt them to the reviewed interface and operation symbols')
        if not choices:
            print('Previous workspace has no authoring.json; supply any custom --operation-symbol, --compiler and --private-header choices once.')
    print('syntax: '+shlex.join(syntax))
    print('source/profile check: '+source_check)
    print('next: edit executable comparison inputs in '+str(output/'prepare.py'))
    print('No comparison or qualification evidence has been created.')
    return 0
