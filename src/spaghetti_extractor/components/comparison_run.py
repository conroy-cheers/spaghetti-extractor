"""Concrete original/source comparisons; never a provider qualification receipt."""
from __future__ import annotations

import json
import math
import os
from pathlib import Path
import shutil
import time

from ..util import sha256_file,sha256_text,write_json
from .comparison_package import load_comparison_package,package_file
from .comparison_build import compile_comparison,observed_command
from .comparison_runtime import wine_sessions,prepare_comparison_runtime,check_runtime_inputs
from .comparison_dependencies import check_comparison_sources, finish_comparison_profiles
from .comparison_source_draft import DependencySelection
from .formats import COMPONENT_COMPARISON_RESULT_V1_FORMAT
from .comparison_domain import DOMAIN_EXIT,domain_event,domain_case_status,comparison_status,validate_input_observation


def first_difference(original, source, path='$'):
    if type(original) is not type(source):
        return {'path':path,'kind':'type','original':original,'source':source}
    if isinstance(original,dict):
        for key in sorted(original.keys() | source.keys()):
            if key not in original or key not in source:
                return {'path':path+'.'+key,'kind':'missing-field',
                        'original_present':key in original,'source_present':key in source}
            difference=first_difference(original[key],source[key],path+'.'+key)
            if difference:
                return difference
    elif isinstance(original,list):
        for index,(left,right) in enumerate(zip(original,source)):
            difference=first_difference(left,right,f'{path}[{index}]')
            if difference:
                return difference
        if len(original)!=len(source):
            return {'path':path,'kind':'length','original':len(original),'source':len(source)}
    elif original!=source:
        return {'path':path,'kind':'value','original':original,'source':source}
    return None


def comparison_result_identity(payload: dict) -> str:
    # Concrete JSON observations can contain finite floating-point numbers.
    # The formal artifact canonicalizer deliberately rejects those; this receipt
    # uses an explicit JSON byte identity and never enters a proof reader.
    return sha256_text(json.dumps(payload,sort_keys=True,separators=(',',':'),allow_nan=False))


def retained_storage(output,inputs,artifacts):
    """Bound retained input/build/observation bytes; excludes transient runtimes."""
    return dict(inputs=sum(package_file(output/'inputs',name).stat().st_size for name in inputs),
        build=sum(package_file(output,name).stat().st_size for name in artifacts if name.startswith('build/')),
        observations=sum(package_file(output,name).stat().st_size for name in artifacts if name.startswith('cases/')))


def _observation(path: Path, fields: list[str]):
    if path.stat().st_size > 8*1024*1024:
        raise ValueError('comparison observation exceeds 8 MiB')
    def constant(value):
        raise ValueError(f'nonfinite observation: {value}')
    def pairs(rows):
        result={}
        for key,value in rows:
            if key in result:
                raise ValueError('duplicate observation field')
            result[key]=value
        return result
    def number(text):
        value=float(text)
        if not math.isfinite(value):
            raise ValueError('nonfinite comparison number')
        return value
    value=json.loads(path.read_text(),parse_constant=constant,parse_float=number,object_pairs_hook=pairs)
    if not isinstance(value,dict) or not all(field in value for field in fields):
        raise ValueError('comparison observation omits required fields')
    return value


def run_comparison(*, package: Path, output: Path, target_id: str, component_id: str,
                   case_id: str | None = None, timeout: float = 60, reuse_previous: Path | None = None, rerun: bool = False,
                   case_arguments: list[str] | None = None,
                   dependency_packages: dict[str,DependencySelection] | None = None,
                   local_contracts: bool = False, query_timeout: float | None = None,
                   compiler_view: bool = False) -> dict:
    from .comparison_reuse import comparison_execution_context,comparison_runtime_state,try_reuse_comparison
    package=package.resolve()
    output=output.resolve()
    if not math.isfinite(timeout) or timeout<=0:
        raise ValueError('comparison timeout must be positive')
    if query_timeout is not None and (not math.isfinite(query_timeout) or query_timeout<=0):
        raise ValueError('optional contract query timeout must be finite and positive')
    if output.is_relative_to(package) or package.is_relative_to(output):
        raise ValueError('comparison output must be separate from its input package')
    if output.exists() and (not output.is_dir() or any(output.iterdir())):
        raise ValueError('comparison output must be a new or empty directory')
    timings=[];prior=None;prior_plan=None
    # A reuse request carries the selected checks forward. Omitting the flag on
    # the next edit must not silently erase a known optional-proof failure.
    if reuse_previous is not None:
        started=time.monotonic()
        prior,prior_plan=load_comparison_evidence(reuse_previous)
        timings.append({'phase':'evidence-validation','step':'previous-result','seconds':time.monotonic()-started})
        prior_formal=prior['formal_check']
        if prior_formal['status']!='not-requested':
            local_contracts=True
            if query_timeout is None:
                query_timeout=prior_formal['query_timeout_seconds']
    started=time.monotonic()
    plan,interface=load_comparison_package(package)
    if (plan['target_id'],plan['component_id']) != (target_id,component_id):
        raise ValueError('comparison package has another target/component identity')
    if os.environ.get('SPAGHETTI_ORIGINAL_EXECUTION_FORBIDDEN')=='1' and plan['original']['kind']!='fixture':
        raise ValueError('original execution is forbidden in this test environment')
    added_case=False
    if case_arguments is not None:
        if not isinstance(case_id,str) or not case_id:
            raise ValueError('case arguments require an explicit --case name')
        if not isinstance(case_arguments,list) or any(not isinstance(v,str) or '\0' in v for v in case_arguments):
            raise ValueError('case arguments must be a list of strings without NUL characters')
        existing=next((case for case in plan['cases'] if case['id']==case_id),None)
        if existing is not None and existing['arguments']!=case_arguments:
            raise ValueError('case name already has different arguments; choose a new --case name')
        if existing is None:
            plan['cases']=[*plan['cases'],dict(id=case_id,arguments=list(case_arguments))]
            added_case=True
    cases=[case for case in plan['cases'] if case_id is None or case['id']==case_id]
    if not cases:
        raise ValueError('selected comparison case does not exist')
    output.mkdir(parents=True,exist_ok=True)
    from .comparison_package import prepare_comparison_inputs
    snapshot=output/'inputs'
    plan,interface=prepare_comparison_inputs(package=package,snapshot=snapshot,plan=plan,interface=interface,
        dependency_packages=dependency_packages,rewrite_plan=added_case)
    profile,profiles=check_comparison_sources(snapshot,plan,output)
    timings.append({'phase':'preparation','seconds':time.monotonic()-started})
    input_hashes={str(path.relative_to(snapshot)):sha256_file(path) for path in sorted(snapshot.rglob('*')) if path.is_file()}
    result={'format':COMPONENT_COMPARISON_RESULT_V1_FORMAT,'target_id':target_id,'component_id':component_id,
        'authorizing':False,'scope':plan['scope'],'oracle':plan['original'],
        'assumptions':plan['assumptions'],'status':'source-profile-failed' if profile['status']=='incomplete' else 'pending',
        'source_profile':profile,'source_profiles':profiles,'input_sha256s':input_hashes,'tools':plan['tools'],
        'formal_check':{'status':'not-requested','required_for_comparison':False},
        'case_selection':case_id,
        'execution_context':comparison_execution_context(),
        'runtime_state':comparison_runtime_state(plan),
        'reuse':None,
        'cases':[],'timings':timings,'binary_sha256':None,'compiler_dependencies':{}}
    build=output/'build'
    build.mkdir()
    if reuse_previous is not None:
        from .comparison_refinement import _refinement_report
        started=time.monotonic()
        # No compiler or runtime has run since validating the prior receipt.
        # Reuse its parsed declarations only for these preparation decisions.
        _refinement_report(previous=reuse_previous,output=output,result=result,
            old=prior,old_plan=prior_plan,plan=plan)
        timings.append({'phase':'evidence-validation','step':'input-domain-refinement','seconds':time.monotonic()-started})
    binary=None
    eligible=all(p['status'] in ('satisfied','pending-storage') for p in profiles.values())
    reused=(eligible and reuse_previous is not None
            and try_reuse_comparison(previous=reuse_previous.resolve(),output=output,current=result,
                prior=prior,plan=plan,rerun=rerun))
    if eligible and not reused:
        binary,dependencies=compile_comparison(package=snapshot,plan=plan,output=build,timings=timings,timeout=timeout,previous=reuse_previous)
        result['compiler_dependencies']=dependencies
        result['status']='compile-failed' if binary is None else 'match'
    if binary is not None or reused:
        profile = finish_comparison_profiles(profiles, plan, build)
        result['source_profile'] = profile
        if profile['status'] != 'satisfied':
            binary = None
            result['status'] = 'source-profile-failed'
            result['cases'] = []
    if compiler_view:
        from .comparison_build import write_comparison_compiler_views
        result['compiler_views']=write_comparison_compiler_views(package=snapshot,plan=plan,output=build,
            timings=timings,timeout=timeout)
    if binary is not None and plan.get('program_driver',{}).get('process'):
        from .comparison_program import run_program_cases
        result['binary_sha256']=sha256_file(binary)
        result['cases']=run_program_cases(package=snapshot,plan=plan,output=output,cases=cases,
            timings=timings,timeout=timeout)
        result['status']=comparison_status(result['cases'])
    elif binary is not None:
        result['binary_sha256']=sha256_file(binary)
        for name in plan['runtime_files']:
            shutil.copyfile(package_file(snapshot,name),build/Path(name).name)
        runtime=prepare_comparison_runtime(build=build,output=output,
            names=['comparison.exe',*[Path(name).name for name in plan['runtime_files']],
                   *([plan['program_driver']['library']] if plan.get('program_driver') else [])])
        environments={}
        for side in ('original','source'):
            directory=runtime['directories'][side]
            env={**os.environ,'LC_ALL':'C','WINEDEBUG':'-all','TMPDIR':str(directory/'tmp')}
            if plan['tools']['runner'] is not None:
                env.update(WINEPREFIX=str(output/f'wine-{side}'),WINEPATH=str(directory))
                Path(env['WINEPREFIX']).mkdir(mode=0o700)
            environments[side]=env
        server=plan['tools']['server']
        with wine_sessions(server=server['path'] if server else None,
                environments=environments, cwd=build, logs=build, timeout=timeout,
                timings=timings, persistent=True, dispose_prefixes=True,
                runner=plan['tools']['runner']['path'] if server else None):
            for index,case in enumerate(cases):
                row={'id':case['id'],'arguments':case['arguments'],'status':'match','observations':{},'domain_events':{},'executions':{}}
                for side in ('original','source'):
                    prefix=output/'cases'/f'{index:04d}-{side}'
                    runner=[] if plan['tools']['runner'] is None else [plan['tools']['runner']['path']]
                    directory=runtime['directories'][side]
                    check_runtime_inputs(directory,runtime['bindings'])
                    execution=observed_command([*runner,str(directory/'comparison.exe'),side,*case['arguments']],cwd=directory,
                        env=environments[side],timeout=timeout,output=prefix,phase='execution',timings=timings)
                    check_runtime_inputs(directory,runtime['bindings'])
                    row['executions'][side]={k:execution[k] for k in ('returncode','timed_out')}
                    if not execution['timed_out'] and execution['returncode']==DOMAIN_EXIT:
                        try:
                            value=_observation(prefix.with_suffix('.stdout'),['input_domain_exclusion'])
                            row['domain_events'][side]=domain_event(plan,value)
                        except (ValueError,UnicodeError) as error:
                            row.update(status='invalid-observation',failed_side=side,diagnostic=str(error))
                            break
                        continue
                    if execution['timed_out'] or execution['returncode']:
                        row['status']='timeout' if execution['timed_out'] else 'runtime-failed'
                        row['failed_side']=side
                        break
                    try:
                        row['observations'][side]=_observation(prefix.with_suffix('.stdout'),plan['observation_fields'])
                        validate_input_observation(plan,row['observations'][side])
                    except (ValueError,UnicodeError) as error:
                        row.update(status='invalid-observation',failed_side=side,diagnostic=str(error))
                        break
                if row['status']=='match' and row['domain_events']:
                    row['status']=domain_case_status(plan,row['domain_events'])
                elif row['status']=='match':
                    row['first_difference']=first_difference(row['observations']['original'],row['observations']['source'])
                    if row['first_difference'] is not None:
                        row['status']='mismatch'
                from .comparison_resources import resource_case
                resources=resource_case(plan,output,index,row['executions'])
                if resources is not None:
                    row['resources']=resources
                result['cases'].append(row)
            result['status']=comparison_status(result['cases'])
    if local_contracts and profile['status']=='satisfied':
        from .practical_contracts import check_practical_contracts
        result['formal_check']=check_practical_contracts(output=output,plan=plan,interface=interface,
            query_timeout=30 if query_timeout is None else query_timeout,previous=reuse_previous)
    result['work_counts']={phase:sum(row['phase']==phase for row in timings)
        for phase in ('compiler','link','execution','model','solver')}
    started=time.monotonic()
    result['artifact_sha256s']={str(p.relative_to(output)):sha256_file(p)
        for role in ('cases','build') for p in sorted((output/role).rglob('*'))
        if p.is_file() and not p.is_symlink()}
    timings.append({'phase':'evidence-hashing','seconds':time.monotonic()-started})
    started=time.monotonic()
    result['retained_bytes']=retained_storage(output,result['input_sha256s'],result['artifact_sha256s'])
    timings.append({'phase':'storage-accounting','seconds':time.monotonic()-started})
    from .comparison_refinement import retain_refinement
    refinement=retain_refinement(previous=reuse_previous,output=output,result=result,timings=timings)
    if refinement is not None:
        result['refinement']=refinement
    if 'composition' in plan:
        from .comparison_composition import selection_impact
        result['composition']=plan['composition']
        if result.get('reuse'):
            result['selection_impact']=selection_impact(plan,result['reuse']['changed_inputs'],result['reuse'].get('ignored_unread_headers',()))
    result['receipt_sha256']=comparison_result_identity(result)
    write_json(output/'comparison-result.json',result)
    return result


def load_comparison_result(output: Path) -> dict:
    """Recheck retained concrete evidence before displaying or consuming it."""
    return load_comparison_evidence(output)[0]


def load_comparison_evidence(output: Path) -> tuple[dict,dict]:
    """Validate a receipt and return its already-checked input plan alongside it.

    Callers may share these parsed values during preparation. There is no cache
    across calls; post-execution and independently requested reads validate again.
    """
    result=json.loads(package_file(output,'comparison-result.json').read_text())
    if not isinstance(result,dict) or result.get('format')!=COMPONENT_COMPARISON_RESULT_V1_FORMAT or result.get('authorizing') is not False:
        raise ValueError('comparison result has unsupported format or authority')
    core={k:v for k,v in result.items() if k!='receipt_sha256'}
    if result.get('receipt_sha256')!=comparison_result_identity(core):
        raise ValueError('comparison result identity is stale')
    snapshot=output/'inputs'
    plan,interface=load_comparison_package(snapshot)
    from .comparison_representation import validate_representation_selection
    validate_representation_selection(snapshot,plan)
    if result.get('composition')!=plan.get('composition'):
        raise ValueError('comparison composition graph differs from retained inputs')
    if 'selection_impact' in result:
        from .comparison_composition import selection_impact
        if not result.get('reuse') or result['selection_impact']!=selection_impact(plan,result['reuse']['changed_inputs'],result['reuse'].get('ignored_unread_headers',())):
            raise ValueError('comparison selection impact differs from its input changes')
    for key in ('target_id','component_id','scope','assumptions','tools'):
        if result[key]!=plan[key]:
            raise ValueError(f'comparison result disagrees with its retained {key}')
    if result['oracle']!=plan['original']:
        raise ValueError('comparison oracle binding differs')
    hashes={str(p.relative_to(snapshot)):sha256_file(p) for p in sorted(snapshot.rglob('*')) if p.is_file()}
    if hashes!=result['input_sha256s']:
        raise ValueError('comparison retained input bytes are stale')
    for name,digest in result['artifact_sha256s'].items():
        if sha256_file(package_file(output,name))!=digest:
            raise ValueError(f'comparison retained artifact is stale: {name}')
    if 'retained_bytes' in result and result['retained_bytes']!=retained_storage(output,hashes,result['artifact_sha256s']):
        raise ValueError('comparison retained storage inventory is stale')
    if result['binary_sha256'] is not None and sha256_file(package_file(output,'build/comparison.exe'))!=result['binary_sha256']:
        raise ValueError('comparison binary binding is stale')
    selected=[case for case in plan['cases'] if result['case_selection'] is None or case['id']==result['case_selection']]
    if not selected:
        raise ValueError('comparison selection is absent from retained cases')
    if result['binary_sha256'] is not None:
        if [r['id'] for r in result['cases']]!=[r['id'] for r in selected]:
            raise ValueError('comparison result omits selected cases')
        for index,(row,case) in enumerate(zip(result['cases'],selected,strict=True)):
            if plan.get('program_driver',{}).get('process'):
                from .comparison_program import program_case
                expected=program_case(plan,output,index,case,row['executions'])
                if row!=expected:
                    raise ValueError('program comparison differs from its retained observations')
                continue
            from .comparison_resources import resource_case
            observed_resources=resource_case(plan,output,index,row['executions'])
            # Coverage counts are optional display metadata in older receipts.
            # Their bound events and all applicability findings still recheck.
            if observed_resources is not None and 'contract_coverage' not in row.get('resources',{}):
                observed_resources.pop('contract_coverage',None)
            if row.get('resources')!=observed_resources:
                raise ValueError('resource findings differ from bound instrumentation observations')
            if row['arguments']!=case['arguments']:
                raise ValueError('comparison case arguments differ')
            for side,observation in row['observations'].items():
                if side not in ('original','source'):
                    raise ValueError('comparison result has an unknown side')
                expected=_observation(package_file(output,f'cases/{index:04d}-{side}.stdout'),plan['observation_fields'])
                if first_difference(expected,observation) is not None:
                    raise ValueError('comparison recorded observation differs from process output')
                if row['status']!='invalid-observation':
                    validate_input_observation(plan,observation)
            events=row.get('domain_events',{})
            for side,event in events.items():
                if side not in ('original','source') or side in row['observations']:
                    raise ValueError('comparison domain event has an invalid side')
                observed=_observation(package_file(output,f'cases/{index:04d}-{side}.stdout'),['input_domain_exclusion'])
                if domain_event(plan,observed)!=event or row['executions'][side]!={'returncode':DOMAIN_EXIT,'timed_out':False}:
                    raise ValueError('comparison domain event differs from its execution')
            if row['status'] in {'excluded','domain-mismatch','assumption-violated'} or events:
                if row['status'] not in {'invalid-observation','runtime-failed','timeout'} and (not events or row['status']!=domain_case_status(plan,events)):
                    raise ValueError('comparison domain classification differs')
            if row['status'] in ('match','mismatch'):
                if set(row['observations'])!={'original','source'}:
                    raise ValueError('comparison result lacks both executions')
                difference=first_difference(row['observations']['original'],row['observations']['source'])
                if difference!=row['first_difference'] or row['status']!=('match' if difference is None else 'mismatch'):
                    raise ValueError('comparison mismatch classification differs')
        status=comparison_status(result['cases'])
        if status!=result['status']:
            raise ValueError('comparison overall status differs from its cases')
    elif result['status'] not in ('source-profile-failed','compile-failed') or result['cases']:
        raise ValueError('comparison without a binary cannot report executed cases')
    if 'work_counts' in result and result['work_counts']!={phase:sum(row['phase']==phase for row in result['timings'])
            for phase in ('compiler','link','execution','model','solver')}:
        raise ValueError('comparison work counts differ from retained phase timings')
    from .comparison_reuse import validate_reused_comparison
    validate_reused_comparison(output,result)
    from .practical_contracts import validate_practical_contracts
    validate_practical_contracts(output=output,plan=plan,interface=interface,value=result['formal_check'])
    from .comparison_refinement import validate_refinement
    validate_refinement(output,result)
    return result,plan
