"""Execute or rebind a conditional source-bound caller-region proof."""

from pathlib import Path
import shlex
import shutil
import subprocess
import time

from ..artifacts.artifact_set import canonical_sha256_v3
from ..util import sha256_file, write_json
from .bisimulation_call_domain import require
from .bisimulation_call_evidence import (
    POLICY, read_json, load_call_inputs, producer_binding, checker_options, check_call_evidence,
)
from .bisimulation_call_model import ENTRY, render_call_model
from .bisimulation_compilation import workspace_compile_command
from .bisimulation_query_evidence import CbmcQueryEvidence
from .cbmc_backend import bind_smt_solver, run_cbmc_properties, validate_smt_solver_binding, CbmcBackendError


def check_source_bound_call(*, preparation, exact, supplier, contract, output, goto_cc, cbmc,
                            smt_solver, previous=None, unwind=16, timeout_seconds=30, timings=None):
    """A successful region remains conditional; it never completes the whole caller."""
    root = Path(output).resolve()
    root.mkdir(parents=True, exist_ok=False)
    result = {'policy':POLICY, 'status':'incomplete', 'authorizing':False, 'activation_authorized':False,
        'runtime_compatibility':'unverified', 'whole_component_complete':False,
        'inputs':{'preparation':str(preparation),'exact':str(exact),'supplier':str(supplier),'contract':contract},
        'region':{'entry_rva':contract.get('entry_rva'),'service_id':contract.get('service_id')},
        'reuse':{'status':'not-requested','model_generation':0,'compiler_runs':0,'solver_runs':0}, 'checks':[]}

    def measured(phase, step, function):
        tick=time.monotonic()
        try:
            return function()
        finally:
            if timings is not None:
                timings.append({'phase':phase,'step':step,'seconds':time.monotonic()-tick})

    try:
        domain, transition, bindings = measured('preparation','caller-inputs',lambda:load_call_inputs(
            preparation=preparation,exact=exact,supplier=supplier,contract=contract))
        solver = read_json(Path(supplier)/'original-comparison/result.json')['tools']['smt_solver']
        validate_smt_solver_binding(solver)
        if (Path(solver['executable']).resolve()!=Path(smt_solver).resolve()
                or solver['sha256']!=sha256_file(Path(smt_solver))):
            solver = measured('preparation','caller-solver-identity',lambda:bind_smt_solver(Path(smt_solver)))
        options = checker_options(unwind, solver)
        tools = {name:sha256_file(Path(path)) for name,path in [('goto_cc',goto_cc),('cbmc',cbmc),('smt_solver',smt_solver)]}
        key = {'bindings':bindings,'options':options,'tools':tools,
               'producers':measured('evidence','caller-producer-binding',producer_binding)}
        result.update(proof_key=key,proof_key_sha256=canonical_sha256_v3(key),supplier_transition=transition)
        old = read_json(Path(previous)/'result.json') if previous is not None else None
        reused = False
        if old is not None:
            require(old.get('policy') == POLICY and old.get('receipt_sha256') == canonical_sha256_v3(
                {k:v for k,v in old.items() if k!='receipt_sha256'}), 'stale previous caller result')
            if old['status']=='satisfied' and old['proof_key']==key:
                measured('evidence-reuse','caller-proof-import',lambda:check_call_evidence(old,previous))
                shutil.copytree(Path(previous)/'proof',root/'proof')
                result.update(status='satisfied',query=old['query'],proof_files=old['proof_files'])
                result['reuse'].update(status='reused',previous_receipt_sha256=old['receipt_sha256'])
                reused=True
            else:
                result['reuse']['status']='requires-recheck'
                if old.get('proof_key'):
                    result['reuse']['changed_inputs']=[k for k,v in key.items() if old['proof_key'].get(k)!=v]
                    result['reuse']['changed_bindings']=[k for k,v in bindings.items()
                        if old['proof_key']['bindings'].get(k)!=v]
        if not reused:
            proof=root/'proof'; proof.mkdir()
            model = measured('model','caller-model',lambda:render_call_model(domain))
            result['reuse']['model_generation']=1
            (proof/'pair.c').write_text(model)
            for name in bindings['original_files']:
                shutil.copyfile(Path(exact)/name,proof/name)
            include=Path(preparation)/f'source-call-region-models/{contract["region_index"]:04d}-ordinary/include'
            for name in ('stdint.h','stddef.h','portable-component.h','portable-component-implementation.h'):
                shutil.copyfile(include/name,proof/name)
            files=['pair.c',f'behavioral-fn-{domain["entry"]:08x}.c','behavioral-support.c']
            prefix=[str(goto_cc),'--i386-win32','-nostdinc','-I','.']
            allowed={f.name for f in proof.iterdir() if f.is_file()}
            def run(command, name):
                result['reuse']['compiler_runs']+=1
                process=measured('compiler',name,lambda:subprocess.run(workspace_compile_command(command,proof),
                    capture_output=True,text=True,timeout=timeout_seconds))
                (proof/(name+'.stdout')).write_text(process.stdout)
                (proof/(name+'.stderr')).write_text(process.stderr)
                require(process.returncode==0,name+': '+process.stderr[-2000:])
                return process
            for i,file in enumerate(files):
                raw=run([*prefix,'-M','-MT','spx_call_inputs',file],f'dependencies-{i}').stdout.replace('\\\n',' ').strip()
                require(raw.startswith('spx_call_inputs:'),'malformed caller include inventory')
                names={str(Path(name)) for name in shlex.split(raw.removeprefix('spx_call_inputs:'))}
                require(file in names and names<=allowed,'unbound caller compiler input')
            command=[*prefix,*files,'--function',ENTRY,'-o','model.goto']
            compiled=run(command,'compiler')
            write_json(proof/'compiler-command.json',{'command':command,'returncode':compiled.returncode,
                'inputs':{name:sha256_file(proof/name) for name in sorted(allowed)}})
            evidence=CbmcQueryEvidence(model=proof/'model.goto',checker=Path(cbmc),compiler=Path(goto_cc),
                output=proof/'query-evidence',smt_solver=solver)
            query=measured('solver','caller-region',lambda:run_cbmc_properties(
                command=[str(cbmc),'model.goto','--function',ENTRY,*options],cwd=proof,timeout_seconds=timeout_seconds,
                query_evidence=evidence,output_prefix=proof/'query'))
            result['reuse']['solver_runs']=1
            result.update(status=query['status'],query=query,
                proof_files={str(f.relative_to(proof)):sha256_file(f) for f in sorted(proof.rglob('*')) if f.is_file()})
        result['checks']=[{'status':result['status'],'code':result['query']['code'],
                          'detail':result['query'].get('detail')}]
    except (ValueError, KeyError, TypeError, IndexError, StopIteration, OSError, subprocess.TimeoutExpired, CbmcBackendError) as error:
        result['status']='incomplete'
        result['reuse']['status']='requires-recheck' if previous is not None else 'incomplete'
        result['checks'].append({'status':'incomplete','code':'source_bound_call_incomplete','detail':str(error)})
    result['receipt_sha256']=canonical_sha256_v3(result)
    write_json(root/'result.json',result)
    return result
