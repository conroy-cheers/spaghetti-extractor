"""Conditional complete source operations using checked paired dependency contracts."""
from copy import deepcopy
import json
from pathlib import Path
import re
import shlex
import shutil
import subprocess
import time

from ..artifacts.artifact_set import canonical_sha256_v3
from ..components.bisimulation_call_evidence import checker_options, producer_binding, read_json
from ..components.bisimulation_cleanup_save import ENTRY, PROFILE, render_cleanup_save_model
from ..components.bisimulation_cleanup_replace import (
    PROFILE as REPLACE_PROFILE, ENTRY as REPLACE_ENTRY, INTERFACE_SHA256 as REPLACE_INTERFACE,
    render_cleanup_replace_model,
)
from ..components.bisimulation_cleanup_summary import _manifest
from ..components.bisimulation_compilation import workspace_compile_command
from ..components.bisimulation_query_evidence import CbmcQueryEvidence
from ..components.cbmc_backend import _output_sha256, _property_statuses, run_cbmc_properties
from ..components.component_c_v5 import render_component_c_headers_v5
from ..components.inductive_refinement import _write_cbmc_stdint
from ..components.interface_package_v5 import ComponentInterfaceIntentV1, compile_component_interface_v5
from ..components.source import load_component_source_package, component_operation_symbols
from ..components.source_profile import check_component_source_profile, _strip_comments_and_literals
from ..util import sha256_file, write_json
from .source_composition_check import checked_component_operation_summary

POLICY = 'conditional-source-operation-call-v1'
# All contract terms except the separately checked normal-frame conjunction.
CONTRACT_CORE_SHA256 = '3fa795e73de3270198fe4c6cdd1fe2dce97fb2417e0c80dda554ce029839b5eb'


def require(value, message):
    if not value:
        raise ValueError('operation caller: '+message)


def selected_profile(contract):
    profiles = {
        PROFILE: {'component':'cleanup-save','entry':0x5c2a,'units':[0x5c2a,0x5c34],
            'operation':'prepare','instruction':0x5c2f,'call_source':0x5c2a,'return':0x5c34,
            'interface':'e54d8406a762ed4641449ce67024cd00e782c1515cf23ebb187aaa2aa12a28ba',
            'proof_entry':ENTRY,'render':render_cleanup_save_model,'required_frame':['ebp','ebx','esi']},
        REPLACE_PROFILE: {'component':'cleanup-replace','entry':0xb18e,'units':[0xb18e,0xb195,0xb19c,0xb1a1,0xb1af],
            'operation':'replace','instruction':0xb19c,'call_source':0xb19c,'return':0xb1a1,
            'interface':REPLACE_INTERFACE,'proof_entry':REPLACE_ENTRY,'render':render_cleanup_replace_model,
            'required_frame':['ebp','ebx','edi','esi']},
    }
    require(isinstance(contract,dict) and contract.get('profile') in profiles, 'unsupported caller profile')
    profile=profiles[contract['profile']]
    require(contract=={'profile':contract['profile'],'entry_rva':profile['entry'],'service_id':'cleanup'}, 'unsupported caller profile')
    return profile


def consumed_dependency_contract(summary, required_frame):
    """Use only declared frame facts; everything else keeps its full identity.

    The rendered native transition leaves every unselected register arbitrary.
    A passing complete caller query therefore establishes that these requirements
    suffice. Availability and exact supplier evidence are rebound separately.
    """
    c = deepcopy(summary['contract'])
    require(summary['contract_sha256'] == canonical_sha256_v3(c), 'dependency contract binding differs')
    available = c['normal_return'].pop('preserved_equalities')
    require(canonical_sha256_v3(c) == CONTRACT_CORE_SHA256,
            'dependency contract requires a reviewed composition rule')
    require(isinstance(available, list) and all(isinstance(v, str) for v in available)
            and available == sorted(set(available)), 'dependency frame is not canonical')
    required = ['state.'+field+'==initial.'+field for field in required_frame]
    used = sorted(set(required) & set(available))
    c['normal_return']['preserved_equalities'] = used
    digest = canonical_sha256_v3(c)
    missing = sorted(set(required) - set(available))
    return c, {'rule':'normal-frame-conjunction-v1', 'status':'requires-recheck' if missing else 'compatible',
        'required_normal_frame':required, 'available_normal_frame':available, 'missing_guarantees':missing,
        'provided_contract_sha256':summary['contract_sha256'], 'consumed_contract_sha256':digest,
        'unchanged_contract_core_sha256':CONTRACT_CORE_SHA256}


def load_inputs(*, preparation, exact, supplier, contract, source_package, interface_package):
    preparation, exact, supplier, source_package, interface_package = map(Path,
        (preparation, exact, supplier, source_package, interface_package))
    selected=selected_profile(contract); component=selected['component']
    summary = deepcopy(checked_component_operation_summary(supplier))
    c, requirements = consumed_dependency_contract(summary, selected['required_frame'])
    summary['consumer_requirements'] = requirements
    source = load_component_source_package(source_package)
    intent_file = interface_package/'component-interface-intent-v1.json'
    intent = ComponentInterfaceIntentV1.parse(read_json(intent_file))
    profile = check_component_source_profile(package=source_package)
    feedback = read_json(preparation/'compiler-checks.json')
    status = read_json(preparation/'source-check.json')
    require(status['status']=='complete' and profile['status']=='satisfied'
        and feedback['source_profile']==profile, 'source preparation is incomplete or stale')
    subject, = status['subjects']
    require(subject['subject']=='component:'+component and source['lift_unit_id']==intent.component_id==component
        and {r['role']:r['sha256'] for r in subject['sources']} == {
            'component-interface':sha256_file(intent_file),
            'component-source-package':sha256_file(source_package/'source-package.json')}, 'prepared interface/source binding differs')
    # The full interface, not its C signature alone, selects this first supported
    # multi-view caller rule. Source statements and function size remain editable.
    require(intent.intent_sha256 == selected['interface'], 'unsupported caller interface semantics')
    require(not source['shared_inputs'] and len(source['files'])==1, 'one complete ordinary translation unit is required')
    file = source['files'][0]['path']
    require(Path(file).name==file and file.endswith('.c') and file not in {'pair.c','behavioral-support.c'}, 'unsupported source path')
    text = (source_package/'sources'/file).read_text()
    require(not re.search(r'\b__(?:FILE|LINE|BASE_FILE|FILE_NAME|INCLUDE_LEVEL|DATE|TIME|TIMESTAMP|COUNTER)__\b',
                         _strip_comments_and_literals(text)), 'source location macro needs correspondence')
    symbols = component_operation_symbols(source)
    require(set(symbols)=={selected['operation']}, 'source operation coverage differs')
    original = _manifest(exact, component)
    require(original['bindings']['executable_transfer_plan_sha256']==c['original_transfer_plan_sha256']
        and original['root_entry_rvas']==[selected['entry']] and original['root_unit_ids']==original['root_context_unit_ids']
        and not original['forced_label_rvas'] and not original['dependency_components'], 'original operation scope differs')
    mapping = {r['unit_id']:r['rva'] for r in original['source_map']}
    require({mapping[u] for u in original['root_unit_ids']}==set(selected['units']), 'original caller ownership has a hole or extra unit')
    function, = [f for f in original['functions'] if f['entries']==[selected['entry']]]
    require(function['unit_rvas']==selected['units'], 'original caller includes unselected transfers')
    edges = [e for e in original['internal_direct_call_closure']['call_edges'] if e['source_rva'] in selected['units']]
    require(len(edges)==1 and all(edges[0][k]==v for k,v in {'source_rva':selected['call_source'],'instruction_rva':selected['instruction'],
        'return_rva':selected['return'],'target_rva':0x55b7,'call_index':0}.items()), 'original dependency edge differs')
    files = {r['path']:r['sha256'] for r in original['files']}
    copied = [f'behavioral-fn-{selected["entry"]:08x}.c','behavioral-support.c','behavioral-c.h','state-machine-runtime.h']
    bindings = {'contract':contract,'source':source,'interface_intent':intent.to_payload(),
        'source_profile':profile,'original_slice_sha256':original['slice_sha256'],
        'original_files':{n:files[n] for n in copied},'supplier_domain_sha256':requirements['consumed_contract_sha256'],
        'dependency_requirements':{'rule':requirements['rule'], 'normal_frame':requirements['required_normal_frame'],
            'contract_core_sha256':CONTRACT_CORE_SHA256},
        'runtime_contract':{'id':contract['profile'],'revision':1,'supplier':c,
            'caller_entry':'Live nonwrapping EBP slots outside the callee private frame and image; input pointer word corresponds to the text view; length service target corresponds to the current IAT word.',
            'memory':'Current public byte correspondence includes aliases. The caller loads the length after cleanup. Only the callee private frame is excluded from public post-memory.',
            'views':'Persistent generated view contexts and access hooks remain valid across the dependency invocation under the supplier runtime premises.',
            'outcomes':'Normal removed count and uint32 length subtraction; cleanup memory faults stop before length writes and continuation pushes.',
            'scope':'Conditional selected operation only; actual caller reachability, physical adapters and service/runtime applicability are unverified.'}}
    if contract['profile']==REPLACE_PROFILE:
        bindings['runtime_contract'].update(
            caller_entry='The mode word at incoming ESP+48 corresponds to the source mode. UI argument words are disjoint from text and image. Cleanup-specific premises apply only when mode is neither 2 nor 3.',
            memory='Corresponding current public bytes before cleanup and before SendMessage; no NUL postcondition is inferred from the cleanup summary.',
            outcomes='Cleanup faults stop before message delivery. Modes 2 and 3 bypass cleanup. The separately tagged normal result admits every uint32 message result.',
            message_service={'id':'paired-returning-sendmessage-v1','revision':1,
                'requires':'Corresponding handle, message, wparam, live text view and current public memory; invocation returns normally under the selected runtime.',
                'ensures':'Same arbitrary uint32 result and public post-memory; stdcall restores the 16 argument bytes and preserves EBX, EBP, ESI and EDI.',
                'unverified':['Concrete Win32 applicability and text termination after cleanup.','Invocation faults, reentrancy and nonreturning calls.']})
    return bindings, summary


def _producer():
    return producer_binding({__name__})


def validate_evidence(result, root):
    root = Path(root); key=result['proof_key']; proof=root/'proof'
    selected=selected_profile(key['bindings']['contract']); entry=selected['proof_entry']; original=f'behavioral-fn-{selected["entry"]:08x}.c'
    require(result['policy']==POLICY and result['status']=='satisfied' and result['authorizing'] is False
        and result['activation_authorized'] is False and result['whole_component_complete'] is False
        and result['runtime_compatibility']=='unverified'
        and result['receipt_sha256']==canonical_sha256_v3({k:v for k,v in result.items() if k!='receipt_sha256'})
        and result['proof_key_sha256']==canonical_sha256_v3(key), 'invalid successful caller receipt')
    require(key['options']==checker_options(key['unwind'],None), 'caller safety/unwinding policy differs')
    require(set(result['proof_files'])=={str(f.relative_to(proof)) for f in proof.rglob('*') if f.is_file()}, 'proof inventory differs')
    for name,digest in result['proof_files'].items():
        path=proof/name
        require(path.resolve().is_relative_to(proof.resolve()) and sha256_file(path)==digest, 'caller proof bytes changed')
    records=list((proof/'query-evidence').glob('*/query.json'))
    require(len(records)==1, 'one complete caller query is required')
    record=read_json(records[0]); d=records[0].parent; binding=record['binding']
    require(record['returncode']==0 and d.name==canonical_sha256_v3(binding)
        and binding['goto_model_sha256']==result['proof_files']['model.goto']
        and binding['arguments']==['$GOTO_MODEL','--function',entry,*key['options']], 'caller query binding differs')
    for actual,expected in [('compiler','goto_cc'),('checker','cbmc')]:
        require(sha256_file(Path(binding['tools'][actual]))==binding['tools'][actual+'_sha256']==key['tools'][expected], 'caller tool changed')
    compiler=read_json(proof/'compiler-command.json');source_file=key['bindings']['source']['files'][0]['path']
    require(compiler['returncode']==0 and compiler['command']==[binding['tools']['compiler'],'--i386-win32','-nostdinc','-I','.',
        'pair.c',source_file,original,'behavioral-support.c','--function',entry,'-o','model.goto'], 'caller compilation differs')
    expected={'pair.c',source_file,'portable-component.h','portable-component-implementation.h','stdint.h','stddef.h',*key['bindings']['original_files']}
    require(set(compiler['inputs'])==expected and all(result['proof_files'][n]==v for n,v in compiler['inputs'].items()), 'compiled inventory differs')
    require(all(compiler['inputs'][n]==v for n,v in key['bindings']['original_files'].items())
        and compiler['inputs'][source_file]==key['bindings']['source']['files'][0]['sha256'], 'compiled original/source binding differs')
    stdout,stderr=(d/'stdout').read_text(),(d/'stderr').read_text();statuses=_property_statuses(json.loads(stdout))
    require(sha256_file(d/'stdout')==record['stdout_sha256'] and sha256_file(d/'stderr')==record['stderr_sha256']
        and statuses and set(statuses.values())=={'SUCCESS'} and sorted(statuses)==result['query']['property_ids']
        and len(statuses)==result['query']['properties'] and _output_sha256(stdout,stderr)==result['query']['output_sha256'], 'caller properties incomplete')


def check_operation_call(*, preparation, exact, supplier, contract, source_package, interface_package,
                         output, goto_cc, cbmc, previous=None, unwind=16, timeout_seconds=30, timings=None):
    root=Path(output).resolve();root.mkdir(parents=True,exist_ok=False)
    result={'policy':POLICY,'status':'incomplete','authorizing':False,'activation_authorized':False,
        'whole_component_complete':False,'runtime_compatibility':'unverified',
        'inputs':{k:str(v) for k,v in {'preparation':preparation,'exact':exact,'supplier':supplier,
            'source_package':source_package,'interface_package':interface_package}.items()},
        'region':{'entry_rva':contract.get('entry_rva'),'service_id':'cleanup'},'reuse':{'status':'not-requested','model_generation':0,'compiler_runs':0,'solver_runs':0},'checks':[]}
    result['inputs']['contract']=contract
    def measured(phase,step,fn):
        t=time.monotonic()
        try:return fn()
        finally:
            if timings is not None:timings.append({'phase':phase,'step':step,'seconds':time.monotonic()-t})
    try:
        bindings,summary=measured('preparation','operation-caller-inputs',lambda:load_inputs(**result['inputs']))
        selected=selected_profile(contract);entry=selected['proof_entry'];original=f'behavioral-fn-{selected["entry"]:08x}.c'
        key={'bindings':bindings,'unwind':unwind,'options':checker_options(unwind,None),
            'tools':{n:sha256_file(Path(p)) for n,p in [('goto_cc',goto_cc),('cbmc',cbmc)]},'producers':_producer()}
        result.update(proof_key=key,proof_key_sha256=canonical_sha256_v3(key),supplier_transition={
            'domain_sha256':summary['contract_sha256'],'supplier_receipt_sha256':canonical_sha256_v3(summary['evidence']),
            'evidence':summary['evidence'],'authorizing':False})
        result['dependency_contract'] = summary['consumer_requirements']
        if result['dependency_contract']['missing_guarantees']:
            result['reuse'].update(status='requires-recheck', changed_bindings=['dependency_requirements'])
            raise ValueError('dependency contract no longer supplies required guarantees: ' +
                             ', '.join(result['dependency_contract']['missing_guarantees']))
        old=read_json(Path(previous)/'result.json') if previous is not None else None
        if old is not None:
            require(old.get('receipt_sha256')==canonical_sha256_v3({k:v for k,v in old.items() if k!='receipt_sha256'}), 'previous receipt changed')
        if old is not None and old.get('status')=='satisfied' and old.get('proof_key')==key:
            measured('evidence-reuse','operation-caller-import',lambda:validate_evidence(old,previous))
            shutil.copytree(Path(previous)/'proof',root/'proof')
            result.update(status='satisfied',query=old['query'],proof_files=old['proof_files'])
            result['reuse']['status']='reused'
        else:
            if old is not None:
                result['reuse']['status']='requires-recheck'
                result['reuse']['changed_bindings']=[k for k,v in bindings.items() if old.get('proof_key',{}).get('bindings',{}).get(k)!=v]
            proof=root/'proof';proof.mkdir()
            source=bindings['source'];symbols=component_operation_symbols(source);file=source['files'][0]['path']
            (proof/'pair.c').write_text(measured('model','operation-caller-model',lambda:selected['render'](bindings['runtime_contract']['supplier'],symbols[selected['operation']])))
            result['reuse']['model_generation']=1
            shutil.copyfile(Path(source_package)/'sources'/file,proof/file)
            for n in bindings['original_files']:shutil.copyfile(Path(exact)/n,proof/n)
            bundle=compile_component_interface_v5(ComponentInterfaceIntentV1.parse(bindings['interface_intent']))
            headers=render_component_c_headers_v5(bundle,symbols)
            for n in ('portable-component.h','portable-component-implementation.h'):
                (proof/n).write_text(headers[n])
            _write_cbmc_stdint(proof/'stdint.h')
            (proof/'stddef.h').write_text('typedef unsigned int size_t;\ntypedef int ptrdiff_t;\n#define NULL ((void *)0)\n')
            allowed={f.name for f in proof.iterdir()};files=['pair.c',file,original,'behavioral-support.c']
            prefix=[str(goto_cc),'--i386-win32','-nostdinc','-I','.']
            def run(command,name):
                result['reuse']['compiler_runs']+=1
                p=measured('compiler',name,lambda:subprocess.run(workspace_compile_command(command,proof),capture_output=True,text=True,timeout=timeout_seconds))
                (proof/(name+'.stdout')).write_text(p.stdout);(proof/(name+'.stderr')).write_text(p.stderr)
                require(p.returncode==0,name+': '+p.stderr[-2000:]);return p
            for i,file in enumerate(files):
                raw=run([*prefix,'-M','-MT','spx_inputs',file],'dependencies-'+str(i)).stdout.replace('\\\n',' ').strip()
                require(raw.startswith('spx_inputs:') and set(shlex.split(raw.removeprefix('spx_inputs:')))<=allowed, 'unbound compiler include')
            command=[*prefix,*files,'--function',entry,'-o','model.goto'];compiled=run(command,'compiler')
            write_json(proof/'compiler-command.json',{'command':command,'returncode':compiled.returncode,'inputs':{n:sha256_file(proof/n) for n in sorted(allowed)}})
            evidence=CbmcQueryEvidence(model=proof/'model.goto',checker=Path(cbmc),compiler=Path(goto_cc),output=proof/'query-evidence')
            query=measured('solver','operation-caller',lambda:run_cbmc_properties(command=[str(cbmc),'model.goto','--function',entry,*key['options']],cwd=proof,
                timeout_seconds=timeout_seconds,query_evidence=evidence,output_prefix=proof/'query'))
            result['reuse']['solver_runs']=1
            result.update(status=query['status'],query=query,proof_files={str(f.relative_to(proof)):sha256_file(f) for f in sorted(proof.rglob('*')) if f.is_file()})
        result['checks']=[{'status':result['status'],'code':result['query']['code'],'detail':result['query'].get('detail')}]
    except (ValueError,KeyError,TypeError,IndexError,OSError,subprocess.TimeoutExpired) as error:
        result['status']='incomplete';result['checks'].append({'status':'incomplete','code':'operation_call_incomplete','detail':str(error)})
    result['receipt_sha256']=canonical_sha256_v3(result);write_json(root/'result.json',result);return result


def validate_operation_call_result(result, root):
    bindings,summary=load_inputs(**result['inputs'])
    require(bindings==result['proof_key']['bindings'] and result['proof_key']['producers']==_producer(), 'caller inputs or engine changed')
    require(result['dependency_contract'] == summary['consumer_requirements']
            and result['dependency_contract']['status'] == 'compatible', 'caller dependency requirements differ or are unfulfilled')
    require(result['supplier_transition']=={'domain_sha256':summary['contract_sha256'],
        'supplier_receipt_sha256':canonical_sha256_v3(summary['evidence']),'evidence':summary['evidence'],'authorizing':False}, 'supplier evidence changed')
    validate_evidence(result,root)
