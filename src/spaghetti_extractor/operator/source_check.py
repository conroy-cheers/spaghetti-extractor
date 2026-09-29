"""Compiler and source-profile feedback without machine qualification authority."""
from __future__ import annotations

import json
import re
import shutil
import time
from pathlib import Path

from ..artifacts.artifact_set import canonical_sha256_v3
from ..components.bisimulation_readonly_contracts import (
    check_readonly_source_contracts, check_mutable_source_contracts, check_shared_source_contracts,
    check_object_source_contracts,
)
from ..components.bisimulation_object_model import object_source_shape
from ..components.bisimulation_readonly_model import fixed_mutable_summary_operations
from ..components.interface_package_v5 import ComponentInterfaceIntentV1, compile_component_interface_v5
from ..components.portable_object import compile_portable_component_objects
from ..components.source import component_operation_symbols, load_component_source_package
from ..components.source_profile import check_component_source_profile
from ..components.machine_overlay_services_v5 import _c_identifier
from ..components.bisimulation_source_contract_reuse import consumed_memory_contract
from ..components.bisimulation_source_call_check import (
    prepare_source_call_regions, checked_source_call_regions,
    prepare_source_region_graphs, checked_source_region_graphs,
)
from ..components.bisimulation_shared_original_check import (
    check_shared_original_comparison, checked_shared_original_transition,
    check_object_original_comparison, checked_object_original_transition,
)
from ..util import sha256_file, write_json
from .work_status import build_operator_blocker_detail_v1, build_operator_work_status_v2
from .source_guidance import source_issue_guidance


def write_component_source_check(
    *, target_id: str, component_id: str, interface_package: Path,
    source_package: Path, host_compiler: Path, pe32_compiler: Path, out: Path,
    compiler_view: bool = False,
    state_owners: list | None = None,
    cbmc: Path | None = None,
    contract_workspace: Path | None = None,
    contract_unwind: int = 16,
    contract_timeout_seconds: int = 30,
    local_contract_dependencies=(),
    previous_local_contract: Path | None = None,
    shared_contract=None,
    shared_service_bindings=None,
    terminal_services=(),
    original_comparison=None,
    source_call_regions=(),
    source_region_graphs=(),
    graph_workspace: Path | None = None,
    region_goto_cc: Path | None = None,
    region_workspace: Path | None = None,
    smt_solver: Path | None = None,
    timings: list[dict] | None = None,
) -> dict:
    preparation_started = time.monotonic()
    if (source_call_regions or source_region_graphs) and region_goto_cc is None:
        raise ValueError("source call regions require an explicit inventory compiler")
    if original_comparison is not None and (cbmc is None or local_contract_dependencies
            or set(original_comparison)-{'service_bindings'} != {'exact_c_slice','binding_intent','machine_domain'}):
        raise ValueError("original comparison requires a supported leaf contract, exact inputs and explicit checker")
    if terminal_services and (cbmc is None or local_contract_dependencies or shared_contract is not None):
        raise ValueError('terminal services require an explicit local-object checker')
    interface_path = interface_package / "component-interface-intent-v1.json"
    intent = ComponentInterfaceIntentV1.parse(json.loads(interface_path.read_text()))
    source = load_component_source_package(source_package)
    if intent.component_id != component_id or source["lift_unit_id"] != component_id:
        raise ValueError("source check inputs bind another component")
    profile = check_component_source_profile(package=source_package)
    from ..components.source_dialect import practical_source_profile
    from ..components.state_ownership import checked_state_owners
    state_owners=checked_state_owners(state_owners, sources=[row["path"].removeprefix("source/") for row in source["files"]])
    practical = practical_source_profile(profile, state_owners=state_owners)
    bundle = compile_component_interface_v5(intent)
    object_comparison = original_comparison is not None and shared_contract is None
    if original_comparison is not None and (
            (object_comparison and (object_source_shape(bundle, terminal_services=terminal_services) is None or shared_service_bindings is not None))
            or (not object_comparison and (shared_service_bindings is None or smt_solver is None))):
        raise ValueError("original comparison requires its checked object or shared-service source domain")
    if shared_service_bindings is not None:
        from ..components.bisimulation_shared_services import normalize_shared_service_bindings
        if shared_contract is None:
            raise ValueError("selected shared services require an explicit local contract")
        shared_contract = {**shared_contract,
            "service_contracts": normalize_shared_service_bindings(bundle, shared_service_bindings)}
    if (local_contract_dependencies or previous_local_contract is not None or shared_contract is not None) and cbmc is None:
        raise ValueError("source dependency contracts require local contract checking")
    summary_dependencies = []
    for row in local_contract_dependencies:
        if set(row) != {"package", "operation_id"}:
            raise ValueError("local source dependency needs a package and operation")
        package = Path(row["package"])
        certificate = json.loads((package/"local-contract.json").read_text())
        child = ComponentInterfaceIntentV1.parse(certificate["interface_intent"])
        summary_dependencies.append({"symbol":f"spx_component_logical_{_c_identifier(child.component_id)}_{_c_identifier(row['operation_id'])}",
            "operation_id":row["operation_id"],"certificate":certificate,"artifacts":package/"local-contract-models"})
    summary_dependencies.sort(key=lambda row:row["symbol"])
    if timings is not None:
        timings.append({"phase":"preparation","step":"source-product-inputs","seconds":time.monotonic()-preparation_started})
    compilation_started = time.monotonic()
    checks, _, artifact = compile_portable_component_objects(
        source_package, source, bundle=bundle,
        operation_symbols=component_operation_symbols(source), induction_source_plan=None,
        machine_overlay=None, machine_overlay_error="source review only",
        runtime_header="", host_compiler=host_compiler, pe32_compiler=pe32_compiler,
        output=None, summary_dependencies=summary_dependencies,
        inspect_storage=practical['status'] == 'pending-storage',
        compiler_view_output=out/'compiler-views' if compiler_view else None,
    )
    if timings is not None:
        timings.append({"phase":"compiler","step":"host-and-pe32-source-check","seconds":time.monotonic()-compilation_started})
    if artifact is not None:
        raise ValueError("source review unexpectedly materialized provider objects")
    # The shared compiler retains its missing-overlay result. Only the source
    # facet is projected here; this result never satisfies machine refinement.
    source_checks = [dict(row) for row in checks if row["code"] != "component_machine_overlay_incomplete"]
    practical = practical_source_profile(profile, [dict(row['storage'], source=row['source'],
        **({'authored_source':row['source'].removeprefix('source/')} if state_owners is not None else {}))
        for row in source_checks if 'storage' in row], state_owners=state_owners)
    proof_requested = cbmc is not None or bool(source_call_regions or source_region_graphs)
    selected_issues = profile['issues'] if proof_requested else practical['issues']
    blockers = [dict(row, family="source-profile", diagnostic=row.get('diagnostic') or source_issue_guidance(row["code"]))
                for row in selected_issues]
    for row in source_checks:
        diagnostic = row.get("diagnostic", "")
        diagnostic = str(diagnostic).replace(str(source_package / "sources") + "/", "")
        diagnostic = re.sub(r"/[^\s:'\"]+/generated/", "<generated>/", diagnostic)
        row["diagnostic"] = diagnostic
        if row.get("status") != "checked":
            blockers.append({**row, "family": "source-compile"})
    call_regions = None
    if source_call_regions and not blockers:
        region_output = out / 'source-call-region-models'
        if region_workspace is not None and region_workspace.resolve().is_relative_to(out.resolve()):
            raise ValueError('source call region workspace must be outside its artifact output')
        call_regions = prepare_source_call_regions(package=source_package, source=source, bundle=bundle,
            boundaries=source_call_regions, workspace=region_output if region_workspace is None else region_workspace,
            goto_cc=region_goto_cc, goto_instrument=region_goto_cc.with_name('goto-instrument'),
            timeout_seconds=contract_timeout_seconds, timings=timings)
        if region_workspace is not None:
            shutil.copytree(region_workspace, region_output)
        for row in call_regions['checks']:
            blockers.append({'family': 'source-call-region', 'status': 'incomplete', 'code': row['code'],
                             'diagnostic': row['detail']})
    region_graphs = None
    if source_region_graphs and not blockers:
        graph_output = out / 'source-region-graph-models'
        if graph_workspace is not None and graph_workspace.resolve().is_relative_to(out.resolve()):
            raise ValueError('source region graph workspace must be outside its artifact output')
        region_graphs = prepare_source_region_graphs(package=source_package, source=source, bundle=bundle,
            boundaries=source_region_graphs, workspace=graph_output if graph_workspace is None else graph_workspace,
            goto_cc=region_goto_cc, goto_instrument=region_goto_cc.with_name('goto-instrument'),
            timeout_seconds=contract_timeout_seconds, timings=timings)
        if graph_workspace is not None:
            shutil.copytree(graph_workspace, graph_output)
        for row in region_graphs['checks']:
            blockers.append({'family': 'source-region-graph', 'status': 'incomplete', 'code': row['code'],
                             'diagnostic': row['detail']})
    local_contract = None
    query_reuse = {"executed_queries": 0, "reused_queries": 0}
    if cbmc is not None and not blockers:
        out.mkdir(parents=True, exist_ok=True)
        model_output = out / "local-contract-models"
        if contract_workspace is not None and contract_workspace.resolve().is_relative_to(out.resolve()):
            raise ValueError("local contract workspace must be outside the artifact output")
        checker = (check_object_source_contracts if object_comparison or terminal_services else
                   check_shared_source_contracts if shared_contract is not None else
                   check_mutable_source_contracts if fixed_mutable_summary_operations(bundle) is not None
                   else check_object_source_contracts if object_source_shape(bundle) is not None
                   else check_readonly_source_contracts)
        local_contract = checker(
            bundle=bundle, package=source_package,
            output=model_output if contract_workspace is None else contract_workspace,
            goto_cc=cbmc.with_name("goto-cc"), goto_instrument=cbmc.with_name("goto-instrument"),
            cbmc=cbmc, timeout_seconds=contract_timeout_seconds, unwind=contract_unwind,
            summary_dependencies=summary_dependencies,
            previous_contract=None if previous_local_contract is None else previous_local_contract/'local-contract-models',
            timings=timings,
            **({'smt_solver': smt_solver} if smt_solver is not None else {}),
            **({"shared_contract": shared_contract} if shared_contract is not None else {}),
            **({'terminal_services': terminal_services} if terminal_services else {}),
        )
        if contract_workspace is not None and contract_workspace.is_dir():
            shutil.copytree(contract_workspace, model_output)
        for path in sorted((model_output/'query-evidence').glob('*/reuse.json')):
            record = json.loads(path.read_text())
            for key in query_reuse:
                query_reuse[key] += record[key]
        write_json(out / "local-contract.json", local_contract)
        if local_contract["status"] != "satisfied":
            failures = [row for row in local_contract.get("checks", []) if row.get("status") != "satisfied"]
            for row in failures or [local_contract]:
                detail = row.get("detail") or "; ".join(str(issue.get("detail", "")) for issue in row.get("issues", [])[:5])
                blockers.append({"family": "source-local-contract",
                    "status": "violated" if row.get("status") == "violated" else "incomplete",
                    "code": row.get("code", "readonly_summary_local_contract_incomplete"),
                    "diagnostic": f"{row.get('operation_id', component_id)}/{row.get('kind', 'local contract')}: "
                        f"{detail or 'memory-view contract is unsupported or unproved'}"})
    original_result = None
    original_transition = None
    if original_comparison is not None and not blockers:
        original_workspace = (out/'original-comparison' if contract_workspace is None else
                              contract_workspace.with_name(contract_workspace.name+'-original'))
        original_checker = check_object_original_comparison if object_comparison else check_shared_original_comparison
        original_validator = checked_object_original_transition if object_comparison else checked_shared_original_transition
        original_options = dict(original_comparison)
        service_bindings = original_options.pop('service_bindings', [] if object_comparison else shared_service_bindings)
        original_result = original_checker(certificate=local_contract,
            source_artifacts=model_output, **original_options, service_bindings=service_bindings,
            output=original_workspace, goto_cc=cbmc.with_name('goto-cc'), cbmc=cbmc, smt_solver=smt_solver,
            unwind=contract_unwind, timeout_seconds=contract_timeout_seconds, timings=timings)
        if original_result['status'] == 'satisfied':
            started = time.monotonic()
            try:
                original_transition = original_validator(original_result,
                    artifacts=original_workspace,certificate=local_contract,source_artifacts=model_output)
            except (ValueError, KeyError, TypeError, OSError) as error:
                blockers.append({'family':'source-original-comparison','status':'incomplete',
                    'code':'shared_original_transition_incomplete','diagnostic':str(error)})
            finally:
                if timings is not None:
                    timings.append({'phase':'evidence','step':'original-transition-validation',
                                    'seconds':time.monotonic()-started})
        if contract_workspace is not None:
            shutil.copytree(original_workspace,out/'original-comparison')
        if original_result['status'] != 'satisfied':
            for row in original_result['checks']:
                if row['status'] != 'satisfied':
                    blockers.append({'family':'source-original-comparison','status':row['status'],
                        'code':row.get('code','shared_original_comparison_incomplete'),
                        'diagnostic':row.get('detail','original/source comparison is incomplete')})
    state = ("violated" if any(row.get("status") == "violated" for row in blockers)
             else "incomplete" if blockers else "complete")
    normalized = []
    for row in blockers:
        location = row.get("source")
        if isinstance(location, dict):
            location = f"{location['path']}:{location['line']}"
        normalized.append({"family": row["family"], "code": row["code"], "location": location})
    status = build_operator_work_status_v2(target_id=target_id, scope="component-source", subjects=[{
        "subject": f"component:{component_id}", "kind": "component", "state": state,
        "authority": "not-applicable", "stage": ("source-compile-profile-and-local-contract" if cbmc is not None
                                                    else "source-compile-and-profile"),
        "sources": [
            {"role": "component-interface", "format": intent.to_payload()["format"],
             "sha256": sha256_file(interface_path)},
            {"role": "component-source-package", "format": source["format"],
             "sha256": sha256_file(source_package / "source-package.json")},
        ],
        "blockers": normalized,
        "next_action": ("validate the selected runtime domain and caller composition before qualification"
                        if state == "complete" and original_result is not None else
                        "inspect original-comparison/result.json and repair the source or boundary contract"
                        if any(row['family'] == 'source-original-comparison' for row in blockers) else
                        "prepare an executable original/source comparison; focused proofs can add assurance"
                        if state == "complete" else
                        "inspect local-contract.json, refine the local contract or source, and rerun component check --source --local-contracts"
                        if any(row["family"] == "source-local-contract" for row in blockers) else
                        "repair the reported source errors and rerun this source check"),
    }])
    out.mkdir(parents=True, exist_ok=True)
    write_json(out / "source-check.json", status)
    details = build_operator_blocker_detail_v1(
        target_id=target_id, subject=f"component:{component_id}",
        source_format=status["format"], source_sha256=sha256_file(out / "source-check.json"),
        blockers=blockers, family=None, code=None, limit=None,
    )
    write_json(out / "source-check-details.json", details)
    write_json(out / "compiler-checks.json", {
        "authority": False, "checks": source_checks, "source_profile": profile, "practical_profile": practical,
        **({'source_call_regions': call_regions} if call_regions is not None else {}),
        **({'source_region_graphs': region_graphs} if region_graphs is not None else {}),
        "local_contract": None if local_contract is None else {
            "status": local_contract["status"], "authorizing": False,
            "receipt_sha256": local_contract.get("receipt_sha256"),
            "path": "local-contract.json", "qualified_connected_summary": False,
            "query_reuse": query_reuse,
            **({'original_comparison':{'status':original_result['status'],'authorizing':False,
                'receipt_sha256':original_result['receipt_sha256'],'path':'original-comparison/result.json',
                'runtime_compatibility':original_result['runtime_compatibility'],
                'runtime_contract':original_result['runtime_contract'],
                'transition_domain_sha256':None if original_transition is None else original_transition['domain_sha256'],
                'runtime_contract_sha256':original_result.get('runtime_contract_sha256')}}
               if original_result is not None else {}),
            **({"service_dependencies": [{
                "service_id": row["service_id"],
                "external_contract_identity_sha256": row["external_contract_identity_sha256"],
                "abi_sha256": row["abi_sha256"],
                "effect_contract_sha256": canonical_sha256_v3(row["external_effect_contract"]),
            } for row in local_contract["shared_contract"]["service_contracts"]]}
               if local_contract.get("shared_contract", {}).get("service_contracts") else {}),
            **({"dependencies":[{"symbol":row["symbol"],"operation_id":row["operation_id"],
                  "component_id":row["certificate"]["source_package"]["lift_unit_id"],
                  "consumed_contract_sha256":canonical_sha256_v3(consumed_memory_contract(row)),
                  "source_contract_sha256":row["certificate"]["receipt_sha256"]}
                 for row in summary_dependencies]} if summary_dependencies else {}),
        },
        "compilers": [{"kind": kind, "path": str(path), "sha256": sha256_file(path)}
                      for kind, path in (("host", host_compiler), ("pe32", pe32_compiler))],
    })
    return status


def render_component_source_check(*, path: Path, payload: dict, target_id: str,
                                  component_id: str, as_json: bool) -> int:
    from .formats import OPERATOR_BLOCKER_DETAIL_FORMAT, OPERATOR_WORK_STATUS_FORMAT

    subjects = payload.get("subjects", [])
    if (payload.get("format") != OPERATOR_WORK_STATUS_FORMAT
            or payload.get("target_id") != target_id or payload.get("scope") != "component-source"
            or len(subjects) != 1 or subjects[0].get("subject") != f"component:{component_id}"
            or subjects[0].get("authority") != "not-applicable"
            or payload.get("status") not in {"complete", "incomplete", "violated"}
            or subjects[0].get("state") != payload["status"]):
        raise ValueError("component source feedback has stale identity or authority")
    details = json.loads((path.parent / "source-check-details.json").read_text())
    if (details.get("format") != OPERATOR_BLOCKER_DETAIL_FORMAT
            or details.get("target_id") != target_id or details.get("subject") != subjects[0]["subject"]
            or details.get("source") != {"format": payload["format"], "sha256": sha256_file(path)}):
        raise ValueError("component source details are stale")
    compiler_feedback = json.loads((path.parent/"compiler-checks.json").read_text())
    call_regions = compiler_feedback.get('source_call_regions')
    if call_regions is not None and call_regions.get('status') == 'prepared':
        checked_source_call_regions(call_regions, artifacts=path.parent/'source-call-region-models')
    region_graphs = compiler_feedback.get('source_region_graphs')
    if region_graphs is not None and region_graphs.get('status') == 'prepared':
        checked_source_region_graphs(region_graphs, artifacts=path.parent/'source-region-graph-models')
    local = None
    if subjects[0].get("stage") == "source-compile-profile-and-local-contract":
        local = json.loads((path.parent/"compiler-checks.json").read_text()).get("local_contract")
    if local is not None and 'caller_comparison' in local:
        from .source_call_check import validate_component_source_call_feedback
        validate_component_source_call_feedback(path.parent, local, payload['status'])
    if local is not None and 'region_comparison' in local:
        from .source_region_check import validate_component_source_region_feedback
        validate_component_source_region_feedback(path.parent, local, payload['status'])
    if local is not None and 'region_composition' in local:
        from .source_composition_check import validate_component_source_composition_feedback
        validate_component_source_composition_feedback(path.parent, local, payload['status'])
    if as_json:
        print(json.dumps({"status": payload, "details": details,
                          **({"practical_profile":compiler_feedback['practical_profile'],
                              "proof_profile":compiler_feedback['source_profile']}
                             if 'practical_profile' in compiler_feedback else {}),
                          **({"local_contract":local} if local is not None else {}),
                          **({"source_call_regions": call_regions} if call_regions is not None else {}),
                          **({"source_region_graphs": region_graphs} if region_graphs is not None else {})}, indent=2, sort_keys=True))
    else:
        print(f"{component_id}: source={payload['status']} (host/PE32 compilation and C profile; no qualification authority)")
        if 'practical_profile' in compiler_feedback:
            print('  practical dialect: '+compiler_feedback['practical_profile']['status']+
                  '; formal source eligibility: '+compiler_feedback['source_profile']['status'])
        from ..components.state_ownership import state_owner_guidance
        for line in state_owner_guidance(compiler_feedback.get('practical_profile',{}).get('state_owners')):
            print(line)
        if any('compiler_view' in row for row in compiler_feedback['checks']):
            print('  compiler views: '+str(path.parent/'compiler-views')+' (diagnostic only; keep editing the original C)')
        if region_graphs is not None:
            print(f"  manual region graphs: {region_graphs['status']} (compiled boundaries; behavior, state transport and progress unchecked)")
        if subjects[0].get("stage") == "source-compile-profile-and-local-contract":
            print("  local contract checks requested; success is conditional and does not qualify a connected summary")
            for dependency in (local or {}).get("dependencies",[]):
                print(f"  source contract dependency: {dependency['component_id']}/{dependency['operation_id']}")
            for dependency in (local or {}).get("service_dependencies", []):
                print(f"  selected service contract: {dependency['service_id']} "
                      f"({dependency['external_contract_identity_sha256']})")
            if local is not None and "query_reuse" in local:
                reuse = local["query_reuse"]
                print(f"  local queries: {reuse['executed_queries']} executed, {reuse['reused_queries']} reused")
            caller = (local or {}).get('caller_comparison')
            if caller is not None:
                print(f"  caller region: {caller['status']}; dependency reuse: {caller['reuse']['status']}; "
                      f"runtime compatibility: {caller['runtime_compatibility']}")
                print("  whole component remains incomplete; caller entry and remaining region/progress obligations are separate")
            region = (local or {}).get('region_comparison')
            if region is not None:
                print(f"  selected region: {region['status']}; proof reuse: {region['reuse']['status']}; "
                      f"runtime compatibility: {region['runtime_compatibility']}")
                print("  whole component remains incomplete; entry admission and remaining coverage are separate")
            composition = (local or {}).get('region_composition')
            if composition is not None:
                print(f"  spatial composition admission: {composition['spatial_admission']}")
                print(f"  private byte transport: {composition['private_transport']['status']}")
                print(f"  current memory transport: {composition['public_transport']['status']}")
                print(f"  live descriptor transport: {composition['descriptor_transport']['status']}; "
                      f"scratch grant: {composition['descriptor_transport']['grant_protocol']['status']}")
                runtime_view = composition['runtime_view_transport']
                print(f"  production view accessor relation: {runtime_view['status']}; "
                      f"source use: {runtime_view['source_use']['status']}")
                for requirement in runtime_view['requires']:
                    print(f"  conditional accessor premise: {requirement}")
                operation_summary = composition['conditional_operation_summary']
                print(f"  conditional operation contract: {operation_summary['status']}; paired caller equivalence only")
                observations = composition['observations']
                print(f"  ordered service-prefix composition: {observations['status']}; conditional on regional runtime contracts")
                control = composition['control_transport']
                print(f"  conditional control and return-frame composition: {control['status']}")
                print(f"  loop ranking: {control['contract']['rank']}")
                for requirement in control['contract']['requires']:
                    print(f"  conditional composition premise: {requirement}")
                for name, requirement in composition['descriptor_transport']['runtime_requirements'].items():
                    print(f"  {requirement['status']} {name}: {requirement['requirement']}")
                for name, predicate in composition['additional_requirements'].items():
                    print(f"  unqualified requirement {name}: {predicate}")
                print("  complete state, lifetime and concrete caller/service compatibility remain unchecked")
            original = (local or {}).get('original_comparison')
            if original is not None:
                print(f"  original/source comparison: {original['status']}; runtime compatibility: {original['runtime_compatibility']}")
        if call_regions is not None:
            print(f"  source call regions: {call_regions['status']}; source binding only, functional proof pending")
            for region in call_regions['regions']:
                projection = region.get('projection')
                if projection:
                    print(f"    {projection['function']} -> {projection['service_id']}{tuple(projection['arguments'])}: "
                          f"live result {projection['result_local']}")
        for row in details["blockers"]:
            print(f"  {row['code']}: {row.get('source', '')}")
            if row.get("diagnostic"):
                print(str(row["diagnostic"]).rstrip())
        print(f"next: {subjects[0]['next_action']}")
    return 0 if payload["status"] == "complete" else 2
