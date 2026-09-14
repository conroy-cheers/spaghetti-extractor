"""Run or reuse a source-bound conditional byte-compaction region theorem."""
from pathlib import Path
import shlex
import shutil
import subprocess
import time

from ..artifacts.artifact_set import canonical_sha256_v3
from ..util import sha256_file, write_json
from .bisimulation_call_evidence import read_json
from .bisimulation_compaction_contract import require, compaction_runtime_contract
from .bisimulation_compaction_inputs import load_compaction_inputs
from .bisimulation_compaction_model import render_compaction_source, render_compaction_model
from .bisimulation_fresh_buffer_model import render_fresh_buffer_source, render_fresh_buffer_model
from .bisimulation_cleanup_model import render_cleanup_source, render_cleanup_model
from .bisimulation_compaction_evidence import (
    POLICY, ENTRY, compaction_producers, compiled_sources, source_transport, check_compaction_evidence, region_checker_options,
)
from .bisimulation_compilation import workspace_compile_command
from .bisimulation_query_evidence import CbmcQueryEvidence
from .bisimulation_support import BisimulationRefinementError
from .cbmc_backend import bind_smt_solver, run_cbmc_properties, validate_smt_solver_binding, CbmcBackendError


def check_source_compaction(*, preparation, exact, contract, output, goto_cc, goto_instrument,
                            cbmc, smt_solver, previous=None, unwind=16, timeout_seconds=60, timings=None,
                            dependencies=None, host_cc=None):
    root=Path(output).resolve(); root.mkdir(parents=True,exist_ok=False)
    result={'policy':POLICY,'status':'incomplete','authorizing':False,'activation_authorized':False,
        'runtime_compatibility':'unverified','whole_component_complete':False,
        'inputs':{'preparation':str(preparation),'exact':str(exact),'contract':contract},
        'reuse':{'status':'not-requested','model_generation':0,'compiler_runs':0,'inventory_runs':0,'solver_runs':0},'checks':[]}
    def measured(phase,step,function):
        tick=time.monotonic()
        try:
            return function()
        finally:
            if timings is not None:
                timings.append({'phase':phase,'step':step,'seconds':time.monotonic()-tick})
    try:
        if dependencies is not None:
            require(isinstance(dependencies, dict), 'dependencies must be a mapping of checked products')
            result['inputs']['dependencies'] = {name: str(path) for name, path in dependencies.items()}
        data=measured('preparation','region-inputs',lambda:load_compaction_inputs(preparation,exact,contract,dependencies))
        host_cc = Path(host_cc or shutil.which('cc'))
        if data.get('dependency_evidence'):
            result['dependency_evidence'] = data['dependency_evidence']
        old=read_json(Path(previous)/'result.json') if previous is not None else None
        solver=old.get('solver') if old and smt_solver is not None else None
        if solver is not None:
            validate_smt_solver_binding(solver)
        if smt_solver is not None and (solver is None or Path(solver['executable']).resolve()!=Path(smt_solver).resolve() or solver['sha256']!=sha256_file(Path(smt_solver))):
            solver=measured('preparation','solver-identity',lambda:bind_smt_solver(Path(smt_solver)))
        options=region_checker_options(unwind,solver)
        bindings=compaction_bindings(data)
        key={'bindings':bindings,'options':options,
            'tools':{name:sha256_file(Path(path)) for name,path in [('goto_cc',goto_cc),('goto_instrument',goto_instrument),('cbmc',cbmc),('smt_solver',smt_solver),('host_cc',host_cc)] if path is not None},
            'producers':measured('evidence','region-producers',compaction_producers)}
        result.update(proof_key=key,proof_key_sha256=canonical_sha256_v3(key),solver=solver)
        if old is not None:
            require(old.get('policy')==POLICY and old.get('receipt_sha256')==canonical_sha256_v3(
                {k:v for k,v in old.items() if k!='receipt_sha256'}), 'stale previous region result')
        if old is not None and old['status']=='satisfied' and old['proof_key']==key:
            measured('evidence-reuse','region-proof-import',lambda:check_compaction_evidence(old,previous))
            transport=measured('evidence-reuse','current-source-transport',lambda:source_transport(data,Path(previous)/'proof'))
            shutil.copytree(Path(previous)/'proof',root/'proof')
            result.update(status='satisfied',query=old['query'],proof_files=old['proof_files'],source_transport=transport)
            result['reuse'].update(status='reused',previous_receipt_sha256=old['receipt_sha256'])
        else:
            if old is not None:
                result['reuse'].update(status='requires-recheck',changed_bindings=[name for name,value in bindings.items()
                    if old.get('proof_key',{}).get('bindings',{}).get(name)!=value])
            proof=root/'proof'; proof.mkdir()
            def model():
                for name in bindings['headers']:
                    shutil.copyfile(data['include']/name,proof/name)
                for name in bindings['original_files']:
                    shutil.copyfile(Path(exact)/name,proof/name)
                if contract['profile'] == 'local-text-cleanup-entry-v1':
                    (proof/'authored.c').write_text(render_fresh_buffer_source(data))
                    (proof/'pair.c').write_text(render_fresh_buffer_model(data))
                elif data.get('dependency_evidence'):
                    (proof/'authored.c').write_text(render_cleanup_source(data))
                    (proof/'pair.c').write_text(render_cleanup_model(data))
                else:
                    (proof/'authored.c').write_text(render_compaction_source(data['text'],data['boundary'],contract))
                    (proof/'pair.c').write_text(render_compaction_model(contract,source_function=data['source_function'],
                        original_function=data['original_function'],parameters=data['parameters']))
            measured('model','region-model',model); result['reuse']['model_generation']=1
            allowed={f.name for f in proof.iterdir() if f.is_file()}
            prefix=[str(goto_cc),'--i386-win32','-nostdinc','-I','.']
            def run(command,name,phase='compiler'):
                result['reuse']['inventory_runs' if phase=='inventory' else 'compiler_runs']+=1
                # Syntax checking emits no object/path-sensitive proof artifact;
                # GCC needs its ordinary writable /dev/null for this veto.
                invocation = command if name == 'host-typecheck' else workspace_compile_command(command,proof)
                process=measured(phase,name,lambda:subprocess.run(invocation,cwd=proof,
                    capture_output=True,text=True,timeout=timeout_seconds))
                (proof/(name+'.stdout')).write_text(process.stdout); (proof/(name+'.stderr')).write_text(process.stderr)
                require(process.returncode==0,name+': '+process.stderr[-2000:])
                return process
            command=[str(host_cc),'-m32','-fsyntax-only','-nostdinc','-I','.',
                     '-Werror=incompatible-pointer-types','-Wno-implicit-function-declaration','pair.c']
            host=run(command,'host-typecheck')
            write_json(proof/'host-typecheck.json',{'command':command,'returncode':host.returncode,
                'inputs':{name:sha256_file(proof/name) for name in sorted(allowed)}})
            for index,file in enumerate(compiled_sources(bindings)):
                raw=run([*prefix,'-M','-MT','spx_region_inputs',file],f'dependencies-{index}').stdout.replace('\\\n',' ').strip()
                require(raw.startswith('spx_region_inputs:'),'malformed include inventory')
                names={str(Path(name)) for name in shlex.split(raw.removeprefix('spx_region_inputs:'))}
                require(file in names and names<=allowed,'unbound region compiler input')
            command=[*prefix,*compiled_sources(bindings),'--function',ENTRY,'-o','model.goto']
            compiled=run(command,'compiler')
            write_json(proof/'compiler-command.json',{'command':command,'returncode':compiled.returncode,
                'inputs':{name:sha256_file(proof/name) for name in sorted(allowed)}})
            inventories={}
            for name,flag in [('functions','--show-goto-functions'),('symbols','--show-symbol-table')]:
                command=[str(goto_instrument),flag,'--json-ui','model.goto']; process=run(command,name,'inventory')
                inventories[name]={'command':command,'returncode':process.returncode,'model_sha256':sha256_file(proof/'model.goto'),
                    'stdout_sha256':sha256_file(proof/(name+'.stdout')),'stderr_sha256':sha256_file(proof/(name+'.stderr'))}
            write_json(proof/'inventory-commands.json',inventories)
            result['source_transport']=measured('evidence','source-region-transport',lambda:source_transport(data,proof))
            evidence=CbmcQueryEvidence(model=proof/'model.goto',checker=Path(cbmc),compiler=Path(goto_cc),
                output=proof/'query-evidence',smt_solver=solver)
            query=measured('solver','region-correctness',lambda:run_cbmc_properties(
                command=[str(cbmc),'model.goto','--function',ENTRY,*options],cwd=proof,timeout_seconds=timeout_seconds,
                query_evidence=evidence,output_prefix=proof/'query'))
            result['reuse']['solver_runs']=1
            result.update(status=query['status'],query=query,
                proof_files={str(f.relative_to(proof)):sha256_file(f) for f in sorted(proof.rglob('*')) if f.is_file()})
        result['checks']=[{'status':result['status'],'code':result['query']['code'],'detail':result['query'].get('detail')}]
    except (ValueError,KeyError,TypeError,IndexError,StopIteration,OSError,subprocess.TimeoutExpired,CbmcBackendError,BisimulationRefinementError) as error:
        result['status']='incomplete'; result['reuse']['status']='requires-recheck' if previous is not None else 'incomplete'
        result['checks'].append({'status':'incomplete','code':'source_compaction_incomplete','detail':str(error)})
    result['receipt_sha256']=canonical_sha256_v3(result); write_json(root/'result.json',result)
    return result


def compaction_bindings(data):
    return {**data['binding'],'runtime_contract':compaction_runtime_contract(data['contract']),
        'original_files':{name:digest for name,digest in data['original_files'].items() if name!='behavioral-dispatch.c'},
        'headers':{p.name:sha256_file(p) for p in sorted(data['include'].iterdir()) if p.is_file()}}
