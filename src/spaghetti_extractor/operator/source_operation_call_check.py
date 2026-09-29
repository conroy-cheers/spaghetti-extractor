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
from ..components.bisimulation_caller_definition import (
    selected_definition, instantiate_definition, checked_caller_scope,
)
from ..components.bisimulation_caller_boundary import ADMISSION_ENTRY, ADMISSION_WITNESS, render_caller_boundary
from ..components.bisimulation_cleanup_summary import _manifest
from ..components.bisimulation_supplier_facts import checked_supplier_facts
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


def require(value, message):
    if not value:
        raise ValueError('operation caller: '+message)


def _authored_files(source):
    """Bind one translation unit and its headers without shadowing the checker.

    The generated model and authored unit are separate translation units. Every
    authored header remains an exact input, including currently unread headers;
    dependency output can never import an unbound host or proof header.
    """
    require(not source['shared_inputs'], 'shared source inputs need a checked caller binding')
    files = {row['path']: row['sha256'] for row in source['files']}
    require(len(files) == len(source['files']) and
            sum(name.endswith('.c') for name in files) == 1,
            'one complete ordinary translation unit and its headers are required')
    reserved = {'pair.c', 'record-types.c', 'stdint.h', 'stddef.h', 'state-machine-runtime.h'}
    for name in files:
        path = Path(name)
        require(not path.is_absolute() and '..' not in path.parts and str(path) == name
                and not name.startswith('-')
                and path.suffix in {'.c', '.h'} and path.name not in reserved
                and not path.name.startswith(('behavioral-', 'portable-component')),
                'unsupported or reserved source path: '+name)
    return files, next(name for name in files if name.endswith('.c'))


def checked_caller_supplier(supplier, required_frame):
    """Select a validated supplier family, with no fallback after bad evidence."""
    caller=supplier/'caller-comparison/result.json'
    if caller.is_file():
        require(not (supplier/'original-comparison/result.json').exists()
                and not (supplier/'region-composition/result.json').exists(), 'ambiguous supplier evidence families')
        from ..components.bisimulation_caller_summary import checked_finite_caller_supplier
        return checked_finite_caller_supplier(supplier, required_frame)
    original=supplier/'original-comparison/result.json'
    if original.is_file():
        from ..components.bisimulation_shared_original_check import OBJECT_POLICY, checked_shared_original_transition
        from ..components.bisimulation_supplier_facts import checked_borrowed_supplier_facts
        require(not (supplier/'region-composition/result.json').exists(),'ambiguous supplier evidence families')
        comparison=read_json(original)
        if comparison.get('policy') == OBJECT_POLICY:
            from ..components.bisimulation_object_call import checked_object_supplier_facts
            return checked_object_supplier_facts(supplier, required_frame)
        transition=checked_shared_original_transition(comparison,artifacts=original.parent,
            certificate=read_json(supplier/'local-contract.json'),source_artifacts=supplier/'local-contract-models')
        facts,requirements=checked_borrowed_supplier_facts(transition,
            original=comparison['bindings']['exact_c_slice'],required_frame=required_frame)
        return facts,{'contract_sha256':transition['domain_sha256'],'consumer_requirements':requirements,
            'evidence':{k:transition[k] for k in ('supplier_receipt_sha256','source_certificate_sha256')}}
    summary=deepcopy(checked_component_operation_summary(supplier))
    facts,requirements=checked_supplier_facts(summary,required_frame)
    summary['consumer_requirements']=requirements
    return facts,summary


def checked_caller_suppliers(supplier, contract, selected):
    if 'suppliers' not in contract:
        return checked_caller_supplier(Path(supplier), selected['required_frame'])
    require(isinstance(supplier, dict) and set(supplier)==set(contract['suppliers']),
            'checked supplier evidence coverage differs')
    facts, summaries = {}, {}
    for service, requested in sorted(contract['suppliers'].items()):
        facts[service], summaries[service] = checked_caller_supplier(Path(supplier[service]), requested['required_frame'])
        if requested.get('bindings'):
            from ..components.bisimulation_caller_summary import CALLER_CALL_RULE
            require(facts[service]['rule']==CALLER_CALL_RULE, 'contract parameter bindings require a finite supplier rule')
    requirements = {service: summary['consumer_requirements'] for service, summary in summaries.items()}
    missing = [service+':'+claim for service, row in requirements.items() for claim in row['missing_guarantees']]
    consumed = {service: row['consumed_contract_sha256'] for service, row in requirements.items()}
    return facts, {'contract_sha256':canonical_sha256_v3({service:row['contract_sha256'] for service,row in summaries.items()}),
        'evidence':{service:row['evidence'] for service,row in summaries.items()},
        'consumer_requirements':{'rule':('checked-finite-caller-network-v1' if any(
            row['rule']=='checked-finite-caller-paired-call-v1' for row in facts.values()) else 'checked-live-object-network-v1'),
            'status':'requires-recheck' if missing else 'compatible', 'missing_guarantees':missing,
            'required_normal_frame':{service:row['required_normal_frame'] for service,row in requirements.items()},
            'consumed_contract_sha256':canonical_sha256_v3(consumed), 'suppliers':requirements}}


def load_inputs(*, preparation, exact, supplier, contract, source_package, interface_package):
    preparation, exact, source_package, interface_package = map(Path,
        (preparation, exact, source_package, interface_package))
    selected=selected_definition(contract); component=selected['component']
    c,summary=checked_caller_suppliers(supplier,contract,selected)
    suppliers=c if 'suppliers' in contract else {contract['service_id']:c}
    requirements=summary['consumer_requirements']
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
    authored, _ = _authored_files(source)
    for name in authored:
        text = (source_package/'sources'/name).read_text()
        require(not re.search(r'\b__(?:FILE|LINE|BASE_FILE|FILE_NAME|INCLUDE_LEVEL|DATE|TIME|TIMESTAMP|COUNTER)__\b',
                             _strip_comments_and_literals(text)), 'source location macro needs correspondence: '+name)
        if name.endswith('.h'):
            # Record headers also appear in the checker translation unit. Their
            # declarations may not change checker constants or preprocessor state.
            directives=_strip_comments_and_literals(text)
            require(not re.search(r'(?m)^\s*#\s*(?:undef|pragma)\b',directives)
                    and not re.search(r'(?m)^\s*#\s*define\s+(?:spx_|SPX_|__|U?INT[0-9]*_|SIZE_|PTRDIFF_|NULL\b|(?:u?int[0-9]+_t|size_t|ptrdiff_t)\b)',directives),
                    'authored header changes reserved checker/compiler definitions: '+name)
    symbols = component_operation_symbols(source)
    require(set(symbols)=={selected['operation']}, 'source operation coverage differs')
    original = _manifest(exact, component)
    boundary,calls,services,runtime_contract=instantiate_definition(contract,selected,c,intent)
    if 'records' in boundary:
        require(boundary['records']['header'] in authored, 'record layout header is not bound authored input')
    files = {r['path']:r['sha256'] for r in original['files']}
    summaries=original['internal_direct_call_closure'].get('summary_entry_rvas',[])
    # Runtime-only callers still own and check the complete original scope.
    # Supplier plan correspondence is an additional obligation, not its source.
    scope=checked_caller_scope(original,selected,calls,original['bindings']['executable_transfer_plan_sha256'])
    for supplied in suppliers.values():
        scope=checked_caller_scope(original,selected,calls,supplied['original_transfer_plan_sha256'])
        absent_body=f'behavioral-fn-{supplied["original_entry_rva"]:08x}.c'
        require(all(files.get(n)==digest or (n==absent_body and n not in files and supplied['original_entry_rva'] in summaries)
                    for n,digest in supplied.get('original_files',{}).items()),
                'original dependency body differs from checked supplier')
    copied = [f'behavioral-fn-{selected["entry"]:08x}.c','behavioral-support.c','behavioral-c.h','state-machine-runtime.h']
    # Access declaration order and an explicit spelling of the compatibility
    # default do not change the local theorem. Its normalized meaning is bound
    # once below; current input declarations remain in result.inputs for replay.
    bindings = {'contract':{k:v for k,v in contract.items() if k!='native_memory'},
        'source':source,'interface_intent':intent.to_payload(),
        'native_memory':selected['native_memory'],
        'native_calls':calls,
        'source_services':services,
        'boundary':boundary,
        'supplier_entry_relations':({service:row['entry_relations'] for service,row in suppliers.items()}
            if 'suppliers' in contract else c['entry_relations']),
        'source_profile':profile,'original_slice_sha256':original['slice_sha256'],
        'original_files':{n:files[n] for n in copied},'supplier_domain_sha256':requirements['consumed_contract_sha256'],
        'dependency_requirements':{'rule':requirements['rule'], 'normal_frame':requirements['required_normal_frame']},
        'runtime_contract':runtime_contract,'scope':scope}
    return bindings, summary


def _producer():
    return producer_binding({__name__})


def _headers(bindings):
    names=['portable-component.h','portable-component-implementation.h']
    if bindings['boundary'].get('local_views'):names.append('portable-component-local-bytes.h')
    return names


def validate_evidence(result, root):
    root = Path(root); key=result['proof_key']; proof=root/'proof'
    boundary=key['bindings']['boundary'];entry=boundary['proof_entry'];original=f'behavioral-fn-{boundary["entry"]:08x}.c'
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
    seen=set();binding=None
    if 'property_checker_command' in key:
        from .source_caller_partition import validate_partitioned_caller
        binding=validate_partitioned_caller(result,proof)
        records=[p for p in records if read_json(p)['binding']['arguments']==['$GOTO_MODEL','--function',ADMISSION_ENTRY,*key['options']]]
        require(len(records)==1,'caller nonempty admission query is required')
    else:
        require(len(records)==2, 'caller correctness and nonempty admission queries are required')
    for path in records:
        record=read_json(path);directory=path.parent;b=record['binding']
        function=b['arguments'][2]
        require(function in {entry,ADMISSION_ENTRY} and function not in seen, 'caller query coverage differs')
        seen.add(function);admission=function==ADMISSION_ENTRY
        require(record['returncode']==(10 if admission else 0) and directory.name==canonical_sha256_v3(b)
            and b['goto_model_sha256']==result['proof_files']['model.goto']
            and b['arguments']==['$GOTO_MODEL','--function',function,*key['options']], 'caller query binding differs')
        for actual,expected in [('compiler','goto_cc'),('checker','cbmc')]:
            require(sha256_file(Path(b['tools'][actual]))==b['tools'][actual+'_sha256']==key['tools'][expected], 'caller tool changed')
        stdout,stderr=(directory/'stdout').read_text(),(directory/'stderr').read_text()
        blocks=json.loads(stdout);statuses=_property_statuses(blocks)
        query=result['admission_query'] if admission else result['query']
        require(sha256_file(directory/'stdout')==record['stdout_sha256'] and sha256_file(directory/'stderr')==record['stderr_sha256']
            and statuses and sorted(statuses)==query['property_ids'] and len(statuses)==query['properties']
            and _output_sha256(stdout,stderr)==query['output_sha256'], 'caller properties incomplete')
        if admission:
            require(_admitted_entry(query,blocks) and result['admission']=={'status':'satisfied','policy':'nonempty-entry-domain-v1'},
                    'caller entry has no checked nonempty admission witness')
        else:
            require(set(statuses.values())=={'SUCCESS'}, 'caller properties incomplete')
            binding=b
    compiler=read_json(proof/'compiler-command.json')
    authored, source_file = _authored_files(key['bindings']['source'])
    require(compiler['returncode']==0 and compiler['command']==[binding['tools']['compiler'],'--i386-win32','-nostdinc','-I','.',
        'pair.c',source_file,original,'behavioral-support.c','--function',entry,'-o','model.goto'], 'caller compilation differs')
    expected={'pair.c',*authored,*_headers(key['bindings']),'stdint.h','stddef.h',*key['bindings']['original_files']}
    if 'records' in boundary:
        expected.add('record-types.c')
        checked=read_json(proof/'record-type-command.json')
        require(checked['returncode']==0 and checked['command']==[binding['tools']['compiler'],'--i386-linux','-nostdinc','-I','.',
            'record-types.c','--function','spx_check_record_types','-o','record-types.goto']
            and checked['inputs']==compiler['inputs'], 'record type compilation differs')
    require(set(compiler['inputs'])==expected and all(result['proof_files'][n]==v for n,v in compiler['inputs'].items()), 'compiled inventory differs')
    require(all(compiler['inputs'][n]==v for n,v in key['bindings']['original_files'].items())
        and all(compiler['inputs'][n]==v for n,v in authored.items()), 'compiled original/source binding differs')


def _admitted_entry(query,blocks):
    properties=[r for block in blocks for r in block.get('result',[])]
    failures=[r for r in properties if r['status']=='FAILURE']
    return (query['status']=='violated' and len(failures)==1 and failures[0]['description']==ADMISSION_WITNESS
            and all(r['status'] in {'SUCCESS','FAILURE'} for r in properties))


def check_operation_call(*, preparation, exact, supplier, contract, source_package, interface_package,
                         output, goto_cc, cbmc, previous=None, unwind=16, timeout_seconds=30, timings=None):
    root=Path(output).resolve();root.mkdir(parents=True,exist_ok=False)
    result={'policy':POLICY,'status':'incomplete','authorizing':False,'activation_authorized':False,
        'whole_component_complete':False,'runtime_compatibility':'unverified',
        'inputs':{k:str(v) for k,v in {'preparation':preparation,'exact':exact,
            'source_package':source_package,'interface_package':interface_package}.items()},
        'region':{'entry_rva':contract.get('entry_rva'),'service_id':contract.get('service_id')},'reuse':{'status':'not-requested','model_generation':0,'compiler_runs':0,'solver_runs':0},'checks':[]}
    result['inputs'].update(contract=contract, supplier=(
        {service:str(path) for service,path in sorted(supplier.items())} if isinstance(supplier,dict) else str(supplier)))
    def measured(phase,step,fn):
        t=time.monotonic()
        try:return fn()
        finally:
            if timings is not None:timings.append({'phase':phase,'step':step,'seconds':time.monotonic()-t})
    try:
        bindings,summary=measured('preparation','operation-caller-inputs',lambda:load_inputs(**result['inputs']))
        selected=selected_definition(contract);entry=selected['proof_entry'];original=f'behavioral-fn-{selected["entry"]:08x}.c'
        key={'bindings':bindings,'unwind':unwind,'options':checker_options(unwind,None),
            'tools':{n:sha256_file(Path(p)) for n,p in [('goto_cc',goto_cc),('cbmc',cbmc)]},'producers':_producer()}
        if any('objects' in row for row in bindings['boundary']['services']):
            from ..components.bisimulation_execution import property_checker_command
            key['property_checker_command']=property_checker_command([],source_unwind_limit=unwind,smt_solver=None)
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
            result.update(status='satisfied',query=old['query'],admission=old['admission'],admission_query=old['admission_query'],proof_files=old['proof_files'])
            if 'property_model' in old:result['property_model']=old['property_model']
            result['reuse']['status']='reused'
        else:
            if old is not None:
                result['reuse']['status']='requires-recheck'
                result['reuse']['changed_bindings']=[k for k,v in bindings.items() if old.get('proof_key',{}).get('bindings',{}).get(k)!=v]
            proof=root/'proof';proof.mkdir()
            source=bindings['source'];symbols=component_operation_symbols(source)
            authored, file = _authored_files(source)
            bundle=compile_component_interface_v5(ComponentInterfaceIntentV1.parse(bindings['interface_intent']))
            (proof/'pair.c').write_text(measured('model','operation-caller-model',lambda:render_caller_boundary(
                bindings['boundary'],symbols[selected['operation']],
                interface_bundle=bundle,native_memory=bindings['native_memory'],native_calls=bindings['native_calls'],
                source_services=bindings['source_services'])))
            result['reuse']['model_generation']=1
            for name in authored:
                (proof/name).parent.mkdir(parents=True,exist_ok=True)
                shutil.copyfile(Path(source_package)/'sources'/name,proof/name)
            for n in bindings['original_files']:shutil.copyfile(Path(exact)/n,proof/n)
            headers=render_component_c_headers_v5(bundle,symbols)
            for n in _headers(bindings):
                (proof/n).write_text(headers[n])
            _write_cbmc_stdint(proof/'stdint.h')
            (proof/'stddef.h').write_text('typedef unsigned int size_t;\ntypedef int ptrdiff_t;\n#define NULL ((void *)0)\n')
            record_types='records' in bindings['boundary']
            if record_types:
                from ..components.bisimulation_caller_records import record_type_check_source
                (proof/'record-types.c').write_text(record_type_check_source(bindings['boundary'],bundle))
            allowed={str(f.relative_to(proof)) for f in proof.rglob('*') if f.is_file()};files=['pair.c',file,original,'behavioral-support.c']
            prefix=[str(goto_cc),'--i386-win32','-nostdinc','-I','.']
            def run(command,name):
                result['reuse']['compiler_runs']+=1
                p=measured('compiler',name,lambda:subprocess.run(workspace_compile_command(command,proof),capture_output=True,text=True,timeout=timeout_seconds))
                (proof/(name+'.stdout')).write_text(p.stdout);(proof/(name+'.stderr')).write_text(p.stderr)
                require(p.returncode==0,name+': '+p.stderr[-2000:]);return p
            for i,file in enumerate([*files,*(['record-types.c'] if record_types else [])]):
                syntax_prefix=[str(goto_cc),'--i386-linux','-nostdinc','-I','.'] if file=='record-types.c' else prefix
                raw=run([*syntax_prefix,'-M','-MT','spx_inputs',file],'dependencies-'+str(i)).stdout.replace('\\\n',' ').strip()
                require(raw.startswith('spx_inputs:') and set(shlex.split(raw.removeprefix('spx_inputs:')))<=allowed, 'unbound compiler include')
            compiled_inputs={n:sha256_file(proof/n) for n in sorted(allowed)}
            if record_types:
                type_command=[str(goto_cc),'--i386-linux','-nostdinc','-I','.', 'record-types.c',
                              '--function','spx_check_record_types','-o','record-types.goto']
                checked=run(type_command,'record-type-compiler')
                write_json(proof/'record-type-command.json',{'command':type_command,'returncode':checked.returncode,'inputs':compiled_inputs})
            command=[*prefix,*files,'--function',entry,'-o','model.goto'];compiled=run(command,'compiler')
            write_json(proof/'compiler-command.json',{'command':command,'returncode':compiled.returncode,'inputs':compiled_inputs})
            evidence=CbmcQueryEvidence(model=proof/'model.goto',checker=Path(cbmc),compiler=Path(goto_cc),output=proof/'query-evidence')
            admission=measured('solver','boundary-entry-witness',lambda:run_cbmc_properties(
                command=[str(cbmc),'model.goto','--function',ADMISSION_ENTRY,*key['options']],cwd=proof,
                timeout_seconds=timeout_seconds,query_evidence=evidence,output_prefix=proof/'admission-query'))
            result['reuse']['solver_runs']=1;result['admission_query']=admission
            blocks=read_json(proof/'admission-query.stdout')
            require(_admitted_entry(admission,blocks), 'boundary entry admission is empty or its witness query is incomplete')
            result['admission']={'status':'satisfied','policy':'nonempty-entry-domain-v1'}
            if 'property_checker_command' in key:
                from .source_caller_partition import check_partitioned_caller
                query,result['property_model']=measured('solver','operation-caller',lambda:check_partitioned_caller(
                    proof=proof,entry=entry,command=key['property_checker_command'],cbmc=Path(cbmc),evidence=evidence,timeout_seconds=timeout_seconds))
            else:
                query=measured('solver','operation-caller',lambda:run_cbmc_properties(command=[str(cbmc),'model.goto','--function',entry,*key['options']],cwd=proof,
                    timeout_seconds=timeout_seconds,query_evidence=evidence,output_prefix=proof/'query'))
            result['reuse']['solver_runs']=evidence.executed
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
