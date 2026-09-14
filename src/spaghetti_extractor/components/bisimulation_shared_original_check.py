"""Conditional original/source checks consume an already checked source object.

This public diagnostic theorem has no provider or runtime qualification authority.
It binds the complete exact slice, opaque source object, selected service premises
and explicit runtime domain. Composition must establish compatibility separately.
"""

import json
from pathlib import Path
import re
import shlex
import shutil
import subprocess
import time

from ..artifacts.artifact_set import canonical_sha256_v3
from ..util import sha256_file, write_json
from .binding_intent import ComponentMachineBindingIntentV1
from .bisimulation_query_evidence import CbmcQueryEvidence
from .bisimulation_readonly_evidence import validate_shared_source_contracts
from .bisimulation_readonly_model import mutable_checker_options
from .bisimulation_shared_model import SHARED_CONTRACT_POLICY
from .bisimulation_shared_machine_model import render_shared_machine_model, shared_machine_runtime_contract
from .cbmc_backend import bind_smt_solver, run_cbmc_properties, solver_arguments, _output_sha256, _property_statuses
from .formats import COMPONENT_EXACT_C_SLICE_V1_FORMAT
from .interface_package_v5 import ComponentInterfaceIntentV1, compile_component_interface_v5

POLICY = 'borrowed-image-original-source-comparison-v1'


def _require(condition, message):
    if not condition:
        raise ValueError('original comparison: ' + message)


def checked_shared_original_transition(result, *, artifacts, certificate, source_artifacts):
    """Read a conditional functional leaf for a separately checked caller.

    This returns premises, not qualification. A caller still must establish
    argument/current-memory correspondence, machine entry, frame separation and
    runtime compatibility. Implementation identity is bound separately from the
    consumed transition domain; internal source-check storage budgets are not a
    semantic part of that domain. The original behavior identity is retained.
    No compiler or solver is invoked while validating the retained evidence.
    """
    root = Path(artifacts).resolve()
    validate_shared_source_contracts(certificate, artifacts=Path(source_artifacts))
    _require(result.get('policy') == POLICY and result.get('status') == 'satisfied'
             and result.get('authorizing') is False and result.get('activation_authorized') is False
             and result.get('runtime_compatibility') == 'unverified', 'transition requires a complete conditional comparison')
    _require(result['receipt_sha256'] == canonical_sha256_v3(
        {k:v for k,v in result.items() if k != 'receipt_sha256'}), 'transition receipt is stale')
    _require(result['runtime_contract'] == shared_machine_runtime_contract()
             and result['runtime_contract_sha256'] == canonical_sha256_v3(result['runtime_contract']),
             'transition runtime domain differs')
    bound = result['bindings']
    bundle = compile_component_interface_v5(ComponentInterfaceIntentV1.parse(certificate['interface_intent']))
    _require(certificate['policy'] == SHARED_CONTRACT_POLICY and len(certificate['operation_symbols']) == 1,
             'transition requires a checked functional leaf')
    operation, symbol = next(iter(certificate['operation_symbols'].items()))
    _require(bound['source_certificate_sha256'] == certificate['receipt_sha256']
             and bound['source_implementation_sha256'] == certificate['source_package']['implementation_sha256']
             and bound['authored_goto_sha256'] == certificate['authored_goto_sha256']
             and bound['interface_sha256'] == bundle.interface.interface_sha256
             and bound['shared_contract'] == certificate['shared_contract'], 'transition source binding differs')
    exact = bound['exact_c_slice']
    binding = ComponentMachineBindingIntentV1.parse(bound['binding_intent'])
    semantics = binding.operations[0].semantics
    _require(len(binding.operations) == 1 and semantics.operation_id == operation
             and exact['component_id'] == binding.component_id == bundle.interface.identity
             and exact['format'] == COMPONENT_EXACT_C_SLICE_V1_FORMAT
             and exact['slice_sha256'] == canonical_sha256_v3({k:v for k,v in exact.items() if k != 'slice_sha256'})
             and exact['root_entry_rvas'] == list(semantics.entry_rvas)
             and set(exact['root_unit_ids']) == set(semantics.unit_ids)
             and exact['unit_ids'] == exact['root_unit_ids'] == exact['root_context_unit_ids']
             and not exact['dependency_components'] and not exact['forced_label_rvas']
             and exact['internal_direct_call_closure'] == {'call_edges':[], 'entry_rvas':[], 'unit_ids':[]}
             and len(exact['functions']) == 1, 'transition exact leaf differs')
    original = f'behavioral-fn-{semantics.entry_rvas[0]:08x}.c'
    expected = {'behavioral-c.h','state-machine-runtime.h','behavioral-support.c','behavioral-dispatch.c',original}
    _require(len(exact['files']) == len(expected) and {r['path'] for r in exact['files']} == expected,
             'transition original inventory differs')
    def checked_file(name, digest):
        path = root/name
        _require(path.is_file() and path.resolve().is_relative_to(root) and sha256_file(path) == digest,
                 'transition artifact changed: '+name)
    for row in exact['files']:
        if row['path'] != 'behavioral-dispatch.c':
            checked_file(row['path'], row['sha256'])
    for name in ('stdint.h','stddef.h','state-machine-runtime.h','portable-component.h','portable-component-implementation.h'):
        checked_file(name, certificate['support_headers'][name])
    checked_file('authored.goto', certificate['authored_goto_sha256'])
    generated, entry = render_shared_machine_model(bundle=bundle, operation_id=operation, symbol=symbol,
        shared_contract=bound['shared_contract'], binding_intent=bound['binding_intent'],
        service_bindings=bound['service_bindings'], machine_domain=bound['machine_domain'])
    _require((root/'pair.c').read_text() == generated and result['models']['entry'] == entry,
             'transition model meaning differs')
    _require(set(result['models']['compiled_files']) == {'pair.c', original, 'behavioral-support.c','authored.goto'},
             'transition compiled inventory differs')
    for name,digest in result['models']['compiled_files'].items():
        checked_file(name,digest)
    allowed = expected - {'behavioral-dispatch.c'} | {
        'pair.c','stdint.h','stddef.h','portable-component.h','portable-component-implementation.h'}
    dependencies = result['compiler_dependencies']
    _require([row['source'] for row in dependencies] == ['pair.c',original,'behavioral-support.c'],
             'transition compiler dependency sources differ')
    for index,row in enumerate(dependencies):
        names = [item['path'] for item in row['inputs']]
        _require(len(names) == len(set(names)) and row['source'] in names and set(names) <= allowed,
                 'transition compiler reads an unbound input')
        for item in row['inputs']:
            checked_file(item['path'],item['sha256'])
        inventory = (root/f'dependencies-{index}.stdout').read_text().replace('\\\n',' ').strip()
        _require(inventory.startswith('spx_original_inputs:') and {
            (root/name).resolve() for name in shlex.split(inventory.removeprefix('spx_original_inputs:'))}
            == {(root/name).resolve() for name in names}, 'transition include inventory differs')
    checked_file('pair.c',result['models']['source_sha256'])
    checked_file('model.goto',result['models']['goto_sha256'])
    queries = list((root/'query-evidence').glob('*/query.json'))
    _require(len(queries) == 1, 'transition needs one complete raw query')
    query = json.loads(queries[0].read_text()); directory = queries[0].parent
    options = mutable_checker_options(int(certificate['checker_options'][8]))
    solver = result['tools']['smt_solver']
    position = options.index('--sat-solver'); options[position:position+2] = solver_arguments(solver)
    expected_arguments = ['$GOTO_MODEL','--function',entry,*options,'--verbosity','8','--timestamp','monotonic']
    _require(query['binding']['arguments'] == expected_arguments
             and query['binding']['goto_model_sha256'] == result['models']['goto_sha256']
             and directory.name == canonical_sha256_v3(query['binding'])
             and query['returncode'] == 0, 'transition raw query differs or is incomplete')
    tools = query['binding']['tools']
    commands = result['commands']
    _require(query['binding']['policy'] == 'exact-compiled-cbmc-query-evidence-v1'
             and query['binding']['authorizing'] is False and 'assurance' not in query['binding']
             and len(commands) == 2 and commands[0]['exit_code'] == 0
             and Path(commands[0]['command'][0]).resolve() == Path(tools['compiler']).resolve()
             and commands[0]['command'][1:] == ['--i386-win32','-nostdinc','-I','.', 'pair.c',original,
                 'behavioral-support.c','authored.goto','--function',entry,'-o','model.goto']
             and Path(commands[1]['command'][0]).resolve() == Path(tools['checker']).resolve()
             and commands[1]['command'][1:] == ['model.goto',*expected_arguments[1:]],
             'transition compiler or query command differs')
    _require(result['tools']['cbmc_sha256'] == certificate['tools']['cbmc']
             and result['tools']['goto_cc_sha256'] == certificate['tools']['goto_cc'],
             'transition checker differs from the checked source toolchain')
    for name,digest in (('checker',result['tools']['cbmc_sha256']),('compiler',result['tools']['goto_cc_sha256']),
                        ('external_smt2_solver',solver['sha256'])):
        _require(sha256_file(Path(tools[name])) == tools[name+'_sha256'] == digest, 'transition tool differs')
    stdout,stderr = (directory/'stdout').read_text(),(directory/'stderr').read_text()
    _require(sha256_file(directory/'stdout') == query['stdout_sha256']
             and sha256_file(directory/'stderr') == query['stderr_sha256'], 'transition raw output changed')
    statuses = _property_statuses(json.loads(stdout))
    _require(statuses and all(status == 'SUCCESS' for status in statuses.values())
             and len(result['checks']) == 1 and result['checks'][0]['status'] == 'satisfied'
             and sorted(statuses) == result['checks'][0]['property_ids']
             and len(statuses) == result['checks'][0]['properties']
             and commands[1]['output_sha256'] == result['checks'][0]['output_sha256']
             and result['checks'][0]['output_sha256'] == _output_sha256(stdout,stderr),
             'transition lacks complete successful properties')
    domain = {'runtime_contract':result['runtime_contract'], 'interface_intent':certificate['interface_intent'],
        'binding_intent':bound['binding_intent'], 'exact_c_slice_sha256':exact['slice_sha256'],
        'machine_domain':bound['machine_domain'], 'service_bindings':bound['service_bindings'],
        'relation_intent':bound['shared_contract']['relation_intent']}
    return {'authorizing':False, 'activation_authorized':False, 'runtime_compatibility':'unverified',
        'operation_id':operation, 'domain':domain, 'domain_sha256':canonical_sha256_v3(domain),
        'supplier_receipt_sha256':result['receipt_sha256'], 'source_certificate_sha256':certificate['receipt_sha256']}


def check_shared_original_comparison(*, certificate, source_artifacts, exact_c_slice,
        binding_intent, machine_domain, service_bindings, output, goto_cc, cbmc, smt_solver,
        unwind=16, timeout_seconds=60, timings=None):
    """Compare the actual original leaf with the validated authored GOTO object.

    A satisfied result is conditional on the named memory/service domain. It
    cannot be imported by the contextual-qualification or connected-summary
    readers. Unsupported shapes and stale inputs fail before any theorem is
    reported. No neighboring implementation is compiled by this checker.
    """
    start = time.monotonic()
    output = Path(output).resolve()
    output.mkdir(parents=True, exist_ok=False)
    result = {'policy':POLICY, 'status':'incomplete', 'authorizing':False,
        'activation_authorized':False, 'runtime_compatibility':'unverified', 'checks':[],
        'runtime_contract':shared_machine_runtime_contract(), 'bindings':{}, 'models':{}, 'commands':[]}

    def measured(phase, step, function):
        tick = time.monotonic()
        try:
            return function()
        finally:
            if timings is not None:
                timings.append({'phase':phase, 'step':step, 'seconds':time.monotonic()-tick})

    try:
        source_artifacts, exact_c_slice = Path(source_artifacts), Path(exact_c_slice)
        _require(certificate.get('policy') == SHARED_CONTRACT_POLICY,
                 'requires a checked leaf shared-source contract; dependency composition is not implemented')
        validate_shared_source_contracts(certificate, artifacts=source_artifacts)
        bundle = compile_component_interface_v5(ComponentInterfaceIntentV1.parse(certificate['interface_intent']))
        binding = ComponentMachineBindingIntentV1.parse(binding_intent)
        _require(len(bundle.interface.operations) == len(binding.operations) == 1,
                 'requires a single complete operation')
        operation = binding.operations[0].semantics
        _require(operation.operation_id in certificate['operation_symbols'], 'operation identity differs')
        exact = json.loads((exact_c_slice/'component-exact-c-slice-v1.json').read_text())
        _require(exact.get('format') == COMPONENT_EXACT_C_SLICE_V1_FORMAT and exact.get('slice_sha256') ==
                 canonical_sha256_v3({k:v for k,v in exact.items() if k != 'slice_sha256'}), 'exact slice is stale')
        _require(exact['component_id'] == binding.component_id == bundle.interface.identity
                 and exact['root_entry_rvas'] == list(operation.entry_rvas)
                 and set(exact['root_unit_ids']) == set(operation.unit_ids)
                 and exact['unit_ids'] == exact['root_unit_ids'] == exact['root_context_unit_ids']
                 and not exact['dependency_components']
                 and exact['internal_direct_call_closure'] == {'call_edges':[], 'entry_rvas':[], 'unit_ids':[]}
                 and not exact['forced_label_rvas'] and len(exact['functions']) == 1,
                 'exact slice does not describe the complete bound leaf')
        original = 'behavioral-fn-' + format(operation.entry_rvas[0], '08x') + '.c'
        expected = {'behavioral-c.h','state-machine-runtime.h','behavioral-support.c','behavioral-dispatch.c',original}
        _require({row['path'] for row in exact['files']} == expected and len(exact['files']) == len(expected),
                 'unsupported or incomplete original file inventory')
        for row in exact['files']:
            _require(sha256_file(exact_c_slice/row['path']) == row['sha256'], 'original bytes changed: '+row['path'])
            if row['path'] != 'behavioral-dispatch.c':
                shutil.copyfile(exact_c_slice/row['path'], output/row['path'])
        for name in ('stdint.h','stddef.h','state-machine-runtime.h','portable-component.h','portable-component-implementation.h'):
            path = source_artifacts/'include'/name
            _require(sha256_file(path) == certificate['support_headers'][name], 'source support changed')
            if name == 'state-machine-runtime.h':
                _require(path.read_bytes() == (output/name).read_bytes(), 'original and source runtime ABI differ')
            shutil.copyfile(path, output/name)
        authored = source_artifacts/'authored.goto'
        _require(sha256_file(authored) == certificate['authored_goto_sha256'], 'authored object changed')
        shutil.copyfile(authored, output/'authored.goto')
        solver = bind_smt_solver(Path(smt_solver))
        result['bindings'] = {'source_certificate_sha256':certificate['receipt_sha256'],
            'source_implementation_sha256':certificate['source_package']['implementation_sha256'],
            'authored_goto_sha256':certificate['authored_goto_sha256'], 'interface_sha256':bundle.interface.interface_sha256,
            'exact_c_slice':exact, 'binding_intent':binding.to_payload(), 'machine_domain':machine_domain,
            'service_bindings':service_bindings, 'shared_contract':certificate['shared_contract']}
        result['runtime_contract_sha256'] = canonical_sha256_v3(result['runtime_contract'])
        result['tools'] = {'goto_cc_sha256':sha256_file(goto_cc), 'cbmc_sha256':sha256_file(cbmc), 'smt_solver':solver}
        if timings is not None:
            timings.append({'phase':'preparation','step':'original-comparison-inputs','seconds':time.monotonic()-start})
        generated,entry = measured('model','original-comparison-render', lambda: render_shared_machine_model(
            bundle=bundle, operation_id=operation.operation_id, symbol=certificate['operation_symbols'][operation.operation_id],
            shared_contract=certificate['shared_contract'], binding_intent=binding.to_payload(),
            service_bindings=service_bindings, machine_domain=machine_domain))
        (output/'pair.c').write_text(generated)
        allowed = {path.resolve() for path in output.iterdir() if path.suffix in {'.c','.h'}}
        result['compiler_dependencies'] = []
        for index,name in enumerate(('pair.c',original,'behavioral-support.c')):
            dependency_command = [str(goto_cc),'--i386-win32','-nostdinc','-I','.',
                                  '-M','-MT','spx_original_inputs',name]
            dependency = measured('compiler','original-inputs-'+str(index),lambda: subprocess.run(
                dependency_command,cwd=output,capture_output=True,text=True,check=False,timeout=timeout_seconds))
            (output/f'dependencies-{index}.stdout').write_text(dependency.stdout)
            (output/f'dependencies-{index}.stderr').write_text(dependency.stderr)
            dependency_text = dependency.stdout.replace('\\\n',' ').strip()
            _require(dependency.returncode == 0 and dependency_text.startswith('spx_original_inputs:'),
                     'original compiler dependency inventory failed')
            paths = {(output/path).resolve() for path in shlex.split(dependency_text.removeprefix('spx_original_inputs:'))}
            _require((output/name).resolve() in paths and paths <= allowed, 'original compiler reads an unbound input')
            result['compiler_dependencies'].append({'source':name,'inputs':[
                {'path':str(path.relative_to(output)),'sha256':sha256_file(path)} for path in sorted(paths)]})
        command = [str(goto_cc),'--i386-win32','-nostdinc','-I','.', 'pair.c',original,'behavioral-support.c',
                   'authored.goto','--function',entry,'-o','model.goto']
        compiled = measured('compiler','original-comparison-link', lambda: subprocess.run(command,cwd=output,
            capture_output=True,text=True,check=False,timeout=timeout_seconds))
        (output/'compiler.stdout').write_text(compiled.stdout)
        (output/'compiler.stderr').write_text(compiled.stderr)
        result['commands'].append({'command':command,'exit_code':compiled.returncode})
        _require(compiled.returncode == 0, 'original/source model compiler failed: '+compiled.stderr[-2000:])
        result['models'] = {'source_sha256':sha256_file(output/'pair.c'), 'goto_sha256':sha256_file(output/'model.goto'),
            'entry':entry, 'compiled_files':{name:sha256_file(output/name) for name in (
                'pair.c',original,'behavioral-support.c','authored.goto')}}
        options = mutable_checker_options(unwind)
        position = options.index('--sat-solver')
        options[position:position+2] = solver_arguments(solver)
        command = [str(cbmc),'model.goto','--function',entry,*options,'--verbosity','8','--timestamp','monotonic']
        evidence = CbmcQueryEvidence(model=output/'model.goto',checker=cbmc,compiler=goto_cc,
                                    output=output/'query-evidence',smt_solver=solver)
        checked = measured('solver','original-comparison-query',lambda: run_cbmc_properties(command=command,
            cwd=output,timeout_seconds=timeout_seconds,query_evidence=evidence,output_prefix=output/'query'))
        result['checks'].append(checked)
        result['commands'].append({'command':command,'output_sha256':checked['output_sha256']})
        result['status'] = checked['status']
        if timings is not None and checked['status'] != 'incomplete':
            for row in json.loads((output/'query.stdout').read_text()):
                match = re.fullmatch(r'Runtime (Symex|Convert SSA|Solver): ([0-9.e+-]+)s',row.get('messageText',''))
                if match:
                    timings.append({'phase':{'Symex':'symbolic-execution','Convert SSA':'solver-conversion',
                        'Solver':'solver-backend'}[match[1]], 'step':'original-comparison-query','seconds':float(match[2])})
    except (ValueError, KeyError, TypeError, OSError, StopIteration, subprocess.TimeoutExpired) as error:
        result['status'] = 'incomplete'
        result['checks'].append({'status':'incomplete','code':'shared_original_comparison_incomplete','detail':str(error)})
    result['receipt_sha256'] = canonical_sha256_v3(result)
    write_json(output/'result.json',result)
    return result
