"""Retained real cleanup loop with compiled cut transport and local memory."""
import json
from pathlib import Path
import shutil
import subprocess

from spaghetti_extractor.components.bisimulation_mutable_memory import sparse_mutable_memory_runtime
from spaghetti_extractor.components.machine_overlay_v5 import _view_runtime_helpers
from spaghetti_extractor.components.capabilities import spx_portable_reference_runtime_v5_source
from spaghetti_extractor.components.bisimulation_region_context import check_inert_region_markers, _normalized
from spaghetti_extractor.components.component_c_v5 import render_component_c_headers_v5
from spaghetti_extractor.components.interface_package_v5 import ComponentInterfaceIntentV1, compile_component_interface_v5
from spaghetti_extractor.components.inductive_refinement import _write_cbmc_stdint
from spaghetti_extractor.components.bisimulation_readonly_model import readonly_checker_options
from spaghetti_extractor.components.cbmc_backend import bind_smt_solver, run_cbmc_properties, solver_arguments
from spaghetti_extractor.components.bisimulation_query_evidence import CbmcQueryEvidence
from spaghetti_extractor.util import sha256_file
from .region_context_transport import check_marked_region_observer_transport

FIXTURE = Path(__file__).parents[2] / 'fixtures/metapad-cleanup-iteration'
RESTORES = {'cleanup::1::'+name:name for name in ('input','output','removed','scratch')}


def compile_iteration(root, *, body=None):
    root=Path(root); root.mkdir()
    original=json.loads((FIXTURE/'component-exact-c-slice-v1.json').read_text())
    for row in original['files']:
        source=FIXTURE/row['path']
        if sha256_file(source)!=row['sha256']:
            raise ValueError('retained original iteration input changed')
        shutil.copyfile(source,root/row['path'])
    bundle=compile_component_interface_v5(ComponentInterfaceIntentV1.parse(
        json.loads((FIXTURE/'component-interface-intent-v1.json').read_text())))
    for name,text in render_component_c_headers_v5(bundle,{'cleanup':'cleanup'}).items():
        (root/name).write_text(text)
    _write_cbmc_stdint(root/'stdint.h')
    (root/'stddef.h').write_text('typedef unsigned int size_t;\ntypedef int ptrdiff_t;\n#define NULL ((void *)0)\n')
    (root/'authored.c').write_text((FIXTURE/'authored.c').read_text() if body is None else body)
    replacements={'@MEMORY_RUNTIME@':'\n'.join(sparse_mutable_memory_runtime(1)),
        '@VIEW_RUNTIME@':'\n'.join(_view_runtime_helpers(need_read=True,need_write=True)),
        '@REFERENCE_RUNTIME@':spx_portable_reference_runtime_v5_source()}
    models={}
    for name in ('ordinary','marked','pair'):
        text=(FIXTURE/(name+'.c.in')).read_text()
        for token,value in replacements.items():
            text=text.replace(token,value)
        (root/(name+'.c')).write_text(text)
        files=[name+'.c']+(['behavioral-fn-00005601.c','behavioral-support.c'] if name=='pair' else [])
        command=[shutil.which('goto-cc'),'--i386-win32','-nostdinc','-I','.',*files,
                 '--function','check_iteration' if name=='pair' else 'cleanup','-o',name+'.goto']
        run=subprocess.run(command,cwd=root,capture_output=True,text=True,timeout=30)
        if run.returncode:
            raise ValueError(run.stderr)
        model={}
        for key,flag,field in [('functions','--show-goto-functions','functions'),
                               ('symbols','--show-symbol-table','symbolTable')]:
            run=subprocess.run([shutil.which('goto-instrument'),flag,'--json-ui',name+'.goto'],
                               cwd=root,capture_output=True,text=True,check=True,timeout=30)
            rows=next(r[field] for r in json.loads(run.stdout) if field in r)
            model[key]={r['name']:r for r in rows} if key=='functions' else rows
        models[name]=model
    return models


def checked_transport(models):
    ordinary,marked,local=[models[name] for name in ('ordinary','marked','pair')]
    inert=check_inert_region_markers(original_functions=ordinary['functions'],original_symbols=ordinary['symbols'],
        marked_functions=marked['functions'],marked_symbols=marked['symbols'],function='cleanup',markers=['region_loop','region_tail'])
    relation=check_marked_region_observer_transport(marked_functions=marked['functions'],marked_symbols=marked['symbols'],
        local_functions=local['functions'],local_symbols=local['symbols'],function='cleanup',entry_sync='loop',
        markers={'loop':'region_loop','tail':'region_tail'},restored_locals=RESTORES,
        cut_results={'loop':0x5606,'tail':0x560d},observer='observe_loop',
        observer_arguments=[(key,name=='scratch') for key,name in RESTORES.items()])
    for name in ('spx_view_read_u8','spx_view_write_u8'):
        if _normalized(marked['functions'][name])!=_normalized(local['functions'][name]):
            raise ValueError('view helper body differs')
    return {'inert':inert,'transport':relation}


def check_properties(root):
    root=Path(root)
    solver=bind_smt_solver(Path(shutil.which('z3')))
    evidence=CbmcQueryEvidence(model=root/'pair.goto',checker=Path(shutil.which('cbmc')),
        compiler=Path(shutil.which('goto-cc')),output=root/'query-evidence',smt_solver=solver)
    options=readonly_checker_options(16)
    position=options.index('--sat-solver')
    options[position:position+2]=solver_arguments(solver)
    options += ['--object-bits','12','--reachability-slice-fb','--slice-formula',
                '--verbosity','8','--timestamp','monotonic']
    return run_cbmc_properties(command=[shutil.which('cbmc'),'pair.goto','--function','check_iteration',
        *options],cwd=root,timeout_seconds=60,query_evidence=evidence,output_prefix=root/'query')
