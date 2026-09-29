"""Supplementary, source-bound obligations for fixed memory-view summaries.

Providers may attach this local result as auxiliary evidence. It does not prove
exact/source equivalence, transport compatibility, or activation.
"""

from __future__ import annotations

import hashlib
import json
import math
import shlex
import shutil
import subprocess
import time
from pathlib import Path

from ..artifacts.artifact_set import canonical_sha256_v3
from ..transfer.runtime_abi import exact_runtime_header
from .bisimulation_readonly_access import check_memory_source_access
from .bisimulation_readonly_model import (
    READONLY_MODEL_POLICY, fixed_readonly_summary_operations, render_readonly_source_model,
    READONLY_CONTRACT_POLICY, readonly_checker_options,
    MUTABLE_CONTRACT_POLICY, MUTABLE_MODEL_POLICY, fixed_mutable_summary_operations, render_mutable_source_model,
    mutable_checker_options,
)
from .bisimulation_readonly_evidence import validate_readonly_source_contracts, validate_mutable_source_contracts
from .bisimulation_summary_contracts import _cyclic_calls
from .cbmc_backend import run_cbmc_properties, bind_smt_solver, _output_sha256
from .component_c_v5 import render_component_c_headers_v5
from .inductive_refinement import _write_cbmc_stdint
from .interface_package_v5 import CompiledComponentInterfaceV5
from .machine_overlay_services_v5 import _c_identifier
from .source import component_operation_symbols, load_component_source_package
from .source_profile import check_component_source_profile
from . import bisimulation_source_dependencies as source_dependencies
from .bisimulation_query_evidence import CbmcQueryEvidence
from .bisimulation_shared_model import (
    SHARED_CONTRACT_POLICY, SHARED_MODEL_POLICY, shared_source_shape, render_shared_source_model,
    SHARED_DEPENDENCY_POLICY, SHARED_DEPENDENCY_MODEL,
)
from .bisimulation_readonly_evidence import validate_shared_source_contracts
from .bisimulation_source_contract_reuse import reuse_memory_consumer
from .bisimulation_object_model import (
    OBJECT_CONTRACT_POLICY, OBJECT_MODEL_POLICY, object_source_shape, render_object_source_model,
)
from .bisimulation_readonly_evidence import validate_object_source_contracts


def _previous_contract_queries(root):
    """Recheck the prior local theorem before offering its raw query outputs.

    Reuse still requires current compilation, identical GOTO/tool/query bytes
    and current dependency evidence. Contract signatures alone grant no reuse.
    """
    if root is None:
        return {}
    root = Path(root).resolve()
    value = json.loads((root / "local-contract-result.json").read_text())
    mutable = value.get("policy") in {MUTABLE_CONTRACT_POLICY, source_dependencies.MUTABLE_POLICY}
    validator = (validate_object_source_contracts if value.get("policy") == OBJECT_CONTRACT_POLICY else
                 validate_shared_source_contracts if value.get("policy") in {SHARED_CONTRACT_POLICY, SHARED_DEPENDENCY_POLICY} else
                 validate_mutable_source_contracts if mutable else validate_readonly_source_contracts)
    validator(value, artifacts=root)
    checks = {(row['operation_id'], row['kind']): row for row in value['checks'] if 'operation_id' in row}
    return {(model['operation_id'], model['kind']): {
        'directory': root/'query-evidence'/f"{_c_identifier(model['operation_id'])}-{model['kind']}",
        'outputs': ([_output_sha256((p.parent/'stdout').read_bytes(), (p.parent/'stderr').read_bytes())
                     for p in (root/'query-evidence'/f"{_c_identifier(model['operation_id'])}-{model['kind']}").glob('*/query.json')]
                    if 'property_model' in model else [checks[(model['operation_id'], model['kind'])]['output_sha256']]),
        'goto_model_sha256': model['checked_goto_sha256'],
        'checker': {'cbmc_sha256': value['tools']['cbmc'], 'goto_cc_sha256': value['tools']['goto_cc']},
        'proof_receipt_sha256': value['receipt_sha256'],
    } for model in value['models']}


def check_readonly_source_contracts(**kwargs):
    return _check_memory_source_contracts(**kwargs, mutable=False)


def check_mutable_source_contracts(**kwargs):
    """Check local mutable effects without granting connected-summary authority."""
    return _check_memory_source_contracts(**kwargs, mutable=True)


def check_shared_source_contracts(*, shared_contract, **kwargs):
    """Check local shared-state/service premises without admitting a summary."""
    if shared_contract is None:
        raise ValueError("shared source checker requires an explicit boundary contract")
    return _check_memory_source_contracts(**kwargs, mutable=True, shared_contract=shared_contract)


def check_object_source_contracts(**kwargs):
    """Check nullable/shared object views; machine and lifetime admission remain separate."""
    return _check_memory_source_contracts(**kwargs, mutable=True, objects=True)


def _check_memory_source_contracts(
    *, bundle: CompiledComponentInterfaceV5, package: Path, output: Path,
    goto_cc: Path, goto_instrument: Path, cbmc: Path, unwind: int = 16,
    timeout_seconds: int = 60, timings: list[dict[str, object]] | None = None, mutable: bool,
    summary_dependencies=(), previous_contract: Path | None = None, shared_contract=None,
    query_timeout_seconds: float | None = None, objects=False, terminal_services=(), smt_solver=None,
) -> dict[str, object]:
    """Check opacity, related memory/results, the write frame and bounded progress.

    The bound is a solver resource limit, never an input precondition. All loops
    must discharge their unwinding assertions; direct recursion is unsupported.
    Compiler/model/solver timings may be collected separately from deterministic
    evidence, so measurements cannot perturb a Nix content-addressed result.
    """
    flavor = "mutable" if mutable else "readonly"
    shared = shared_contract is not None
    if shared and not mutable:
        raise ValueError("shared source contracts require mutable memory checking")
    if objects and (not mutable or shared or summary_dependencies):
        raise ValueError("object-view source contracts do not yet compose dependencies or services")
    if terminal_services and not objects:
        raise ValueError('terminal source services require the live-object rule')
    shape = fixed_mutable_summary_operations if mutable else fixed_readonly_summary_operations
    renderer = render_mutable_source_model if mutable else render_readonly_source_model
    validator = validate_mutable_source_contracts if mutable else validate_readonly_source_contracts
    preparation_started = time.monotonic()
    output = output.resolve()
    options = mutable_checker_options(unwind) if mutable else readonly_checker_options(unwind)
    partition_command = None
    if smt_solver is not None:
        from .bisimulation_execution import property_checker_command
        partition_command = property_checker_command([], source_unwind_limit=unwind,
                                                     smt_solver=bind_smt_solver(smt_solver))
    if timeout_seconds <= 0:
        raise ValueError("read-only contract timeout must be positive")
    if query_timeout_seconds is not None and (not math.isfinite(query_timeout_seconds) or query_timeout_seconds<=0):
        raise ValueError('read-only contract query timeout must be finite and positive')
    if shared:
        shape = shared_source_shape
        renderer = lambda **args: render_shared_source_model(**args, shared_contract=shared_contract)
        validator = validate_shared_source_contracts
    if objects:
        shape = lambda value: object_source_shape(value, terminal_services=terminal_services)
        renderer = lambda **args: render_object_source_model(**args, terminal_services=terminal_services)
        validator = validate_object_source_contracts
    operation_ids = shape(bundle)
    if operation_ids is None:
        if objects:
            return {"status": "incomplete", "authorizing": False,
                    "code": "object_summary_contract_shape_unsupported",
                    "detail": "requires service-free fixed shared byte views and/or nullable remaining-origin byte parameters, one protocol state and scalar results; object lifetime and caller admission remain unproved"}
        if shared:
            return {"status": "incomplete", "authorizing": False,
                    "code": "shared_summary_contract_shape_unsupported",
                    "detail": "requires fixed nonnullable shared byte views, one protocol state, integer scalar service values and a returned state view; floating scalars, opaque resources and general heap lifetimes are not modeled"}
        return {"status": "incomplete", "authorizing": False,
                "code": f"{flavor}_summary_contract_shape_unsupported",
                "detail": ("requires a stateless, service-free interface with nonnullable fixed readable views and scalar results"
                           + (" in every operation and at least one read_write view; address metadata must fit PE32"
                              if mutable else ""))}
    package = package if package.is_dir() else package.parent
    source = load_component_source_package(package)
    symbols = component_operation_symbols(source)
    if source["lift_unit_id"] != bundle.interface.identity or set(symbols) != set(operation_ids):
        raise ValueError("read-only contract source operation bindings disagree with interface")
    if len({_c_identifier(operation_id) for operation_id in operation_ids}) != len(operation_ids):
        raise ValueError("read-only contract operation artifact names collide")
    profile = check_component_source_profile(package=package)
    if profile["status"] != "satisfied":
        return {"status": "incomplete", "authorizing": False,
                "code": f"{flavor}_summary_source_profile_rejected", "source_profile": profile}
    output.mkdir(parents=True, exist_ok=False)
    summary_rows = source_dependencies.prepare_dependencies(summary_dependencies,
        component_id=bundle.interface.identity, output=output) if summary_dependencies else []
    headers = source_dependencies.dependency_headers(render_component_c_headers_v5(bundle, symbols), summary_rows)
    source_rows = [*source["files"], *source["shared_inputs"]]
    if (any(not str(row["path"]).endswith((".c", ".h")) for row in source_rows)
            or not any(str(row["path"]).endswith(".c") for row in source["files"])):
        raise ValueError("read-only contract source package contains unsupported inputs")
    # Shared declarations may only be the exact generated interface headers.
    for row in source["shared_inputs"]:
        if row["path"] not in headers or row["sha256"] != hashlib.sha256(headers[row["path"]].encode()).hexdigest():
            raise ValueError("read-only contract has an unmodeled shared source input")
    reserved = {*headers, "stdint.h", "stddef.h", "state-machine-runtime.h"}
    if any(Path(row["path"]).name in reserved for row in source["files"]):
        raise ValueError("read-only contract authored source shadows a generated header")
    reuse_preparation_seconds = time.monotonic() - preparation_started
    reuse_timing_index = len(timings) if timings is not None else 0
    reused = reuse_memory_consumer(previous=previous_contract, output=output, bundle=bundle,
        source=source, profile=profile, headers=headers, dependencies=summary_rows,
        options=options, tools={'goto_cc': goto_cc, 'goto_instrument': goto_instrument, 'cbmc': cbmc},
        mutable=mutable, shared_contract=shared_contract, timings=timings, objects=objects,
        terminal_services=terminal_services, property_checker_command=partition_command)
    if reused is not None:
        if timings is not None:
            timings.insert(reuse_timing_index, {'phase': 'preparation', 'step': 'reuse-prepare',
                                              'seconds': reuse_preparation_seconds})
        return reused
    previous_queries = _previous_contract_queries(previous_contract)
    include = output / "include"
    include.mkdir()
    _write_cbmc_stdint(include / "stdint.h")
    (include / "stddef.h").write_text("typedef unsigned int size_t;\ntypedef int ptrdiff_t;\n#define NULL ((void *)0)\n")
    (include / "state-machine-runtime.h").write_text(exact_runtime_header())
    for name, text in headers.items():
        (include / name).write_text(text)
    inputs = output / "inputs"
    inputs.mkdir()
    for row in source_rows:
        content = (package / "sources" / row["path"]).read_bytes()
        if hashlib.sha256(content).hexdigest() != row["sha256"]:
            raise ValueError("read-only contract source changed during preparation")
        target = inputs / row["path"]
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(content)
    commands: list[dict[str, object]] = []
    checks: list[dict[str, object]] = []
    models: list[dict[str, object]] = []
    inventories: list[dict[str, object]] = []
    dependencies: list[dict[str, object]] = []

    def relative_command(command: list[str]) -> list[str]:
        # GOTO binaries retain source paths. Output-store self references would
        # be rewritten by Nix after hashing; compile from stable relative paths.
        prefix = str(output) + "/"
        return [item[len(prefix):] if item.startswith(prefix) else
                "." if item == str(output) else item for item in command]

    def run(command: list[str], step: str, phase: str) -> subprocess.CompletedProcess[str] | None:
        command = relative_command(command)
        start = time.monotonic()
        try:
            result = subprocess.run(command, capture_output=True, text=True,
                                    timeout=timeout_seconds, check=False, cwd=output)
        except (OSError, subprocess.TimeoutExpired) as error:
            checks.append({"status": "incomplete", "step": step,
                           "code": f"{flavor}_contract_tool_failed", "detail": str(error)})
            return None
        finally:
            if timings is not None:
                timings.append({"step": step, "phase": phase, "seconds": time.monotonic() - start})
        (output / f"{step}.stdout").write_text(result.stdout)
        (output / f"{step}.stderr").write_text(result.stderr)
        commands.append({"step": step, "command": command, "cwd": "$MODEL_ROOT", "exit_code": result.returncode,
                         "output_sha256": hashlib.sha256((result.stdout + result.stderr).encode()).hexdigest()})
        if result.returncode:
            checks.append({"status": "incomplete", "step": step, "code": f"{flavor}_contract_tool_failed",
                           "detail": result.stderr[-2000:]})
            return None
        return result

    def inventory(path: Path, step: str, field: str, flag: str) -> list | None:
        result = run([str(goto_instrument), flag, "--json-ui", str(path)], step, "model")
        if result is None:
            return None
        try:
            rows = [row[field] for row in json.loads(result.stdout) if field in row]
            if len(rows) != 1 or not isinstance(rows[0], list):
                raise ValueError("inventory must occur exactly once")
        except (ValueError, TypeError, KeyError) as error:
            checks.append({"status": "incomplete", "step": step,
                           "code": f"{flavor}_contract_inventory_malformed", "detail": str(error)})
            return None
        inventories.append({"step": step, "kind": field, "sha256": canonical_sha256_v3(rows[0]), "rows": rows[0]})
        return rows[0]

    authored = [str(inputs / row["path"]) for row in source["files"] if str(row["path"]).endswith(".c")]
    compile_prefix = [str(goto_cc), "--i386-win32", "-nostdinc", "-I", str(include), "-I", str(inputs)]
    allowed_inputs = {path.resolve() for path in include.iterdir()} | {
        (inputs / row["path"]).resolve() for row in source_rows}
    if timings is not None:
        timings.append({"step": "prepare", "phase": "preparation", "seconds": time.monotonic() - preparation_started})
    for index, authored_path in enumerate(authored):
        step = f"authored-{index:04d}-dependencies"
        dependency_result = run([*compile_prefix, "-M", "-MT", "spx_readonly_dependencies", authored_path], step, "compiler")
        if dependency_result is None:
            continue
        try:
            dependency_text = dependency_result.stdout.replace("\\\n", " ").strip()
            prefix = "spx_readonly_dependencies:"
            if not dependency_text.startswith(prefix):
                raise ValueError("compiler dependency target is malformed")
            paths = {(output / path).resolve() for path in shlex.split(dependency_text[len(prefix):])}
            if not paths or Path(authored_path).resolve() not in paths or not paths <= allowed_inputs:
                raise ValueError("compiler reads a header outside the bound source package and generated headers")
            dependencies.append({"source": str(Path(authored_path).relative_to(output)),
                "inputs": [{"path": str(path.relative_to(output.resolve())),
                            "sha256": hashlib.sha256(path.read_bytes()).hexdigest()} for path in sorted(paths)]})
        except (ValueError, OSError) as error:
            checks.append({"status": "incomplete", "step": step, "code": f"{flavor}_contract_unbound_include",
                           "detail": str(error)})
    raw_source = output / "authored.goto"
    source_compiled = run([*compile_prefix, *authored, "--function", symbols[operation_ids[0]],
                           "-o", str(raw_source)], "authored-compile", "compiler") if not checks else None
    opacity = None
    source_loops = None
    if source_compiled is not None:
        functions = inventory(raw_source, "authored-functions", "functions", "--show-goto-functions")
        source_loops = inventory(raw_source, "authored-loops", "loops", "--show-loops")
        if functions is not None:
            opacity = check_memory_source_access(functions, operation_symbols=list(symbols.values()),
                context_tag=f"tag-spx_{_c_identifier(bundle.interface.identity)}_context_v5", mutable=mutable,
                dependency_symbols=[row['symbol'] for row in summary_rows],
                boundary_bundle=bundle if shared or objects else None)
            checks.append({"kind": "source_opacity", **opacity})
        if opacity is not None and _cyclic_calls([tuple(edge) for edge in opacity["call_edges"]]):
            checks.append({"status": "incomplete", "kind": "progress",
                           "code": f"{flavor}_contract_recursion_unsupported"})
    if (opacity is not None and opacity["status"] == "satisfied" and source_loops is not None
            and all(row["status"] == "satisfied" for row in checks)):
        for operation_id in operation_ids:
            for kind in ("frame", "input_dependence"):
                name = f"{_c_identifier(operation_id)}-{kind}"
                start = time.monotonic()
                generated, entry = renderer(bundle=bundle, operation_id=operation_id,
                    symbol=symbols[operation_id], kind=kind, summary_dependencies=summary_rows)
                if timings is not None:
                    timings.append({"step": name + "-generate", "phase": "model", "seconds": time.monotonic() - start})
                model = output / f"{name}.c"
                model.write_text(generated)
                raw = output / f"{name}.goto"
                if run([*compile_prefix, str(model), *authored, "--function", entry, "-o", str(raw)],
                       name + "-compile", "compiler") is None:
                    continue
                if (inventory(raw, name + "-functions", "functions", "--show-goto-functions") is None
                        or inventory(raw, name + "-loops", "loops", "--show-loops") is None):
                    continue
                checked = raw
                if kind == "frame":
                    checked = output / f"{name}-checked.goto"
                    if run([str(goto_instrument), "--dfcc", entry, "--enforce-contract", symbols[operation_id],
                            str(raw), str(checked)], name + "-instrument", "model") is None:
                        continue
                command = relative_command([str(cbmc), str(checked), "--function", entry, *options])
                partitioned = kind == 'input_dependence' and partition_command is not None
                evidence = CbmcQueryEvidence(model=checked, checker=cbmc, compiler=goto_cc,
                    output=output/'query-evidence'/name,
                    previous=previous_queries.get((operation_id, kind)),
                    smt_solver=partition_command['smt_solver'] if partitioned else None)
                start = time.monotonic()
                deadline = timeout_seconds if query_timeout_seconds is None else query_timeout_seconds
                property_model = None
                if partitioned:
                    from .bisimulation_property_replay import check_partitioned_model
                    result, property_model = check_partitioned_model(model=checked, entry=entry,
                        command=partition_command, cbmc=cbmc, evidence=evidence, timeout_seconds=deadline,
                        subject={'subject': 'local-source-contract', 'operation': operation_id, 'kind': kind})
                else:
                    result = run_cbmc_properties(command=command, timeout_seconds=deadline, cwd=output,
                        query_evidence=evidence, output_prefix=output / (name + "-check"))
                    commands.append({"step": name + "-check", "command": command, "cwd": "$MODEL_ROOT",
                                     "output_sha256": result["output_sha256"]})
                if timings is not None:
                    timings.append({"step": name + "-check", "phase": "solver", "seconds": time.monotonic() - start,
                                    "executed_queries": evidence.executed, "reused_queries": evidence.reused})
                checks.append({"operation_id": operation_id, "kind": kind, **result})
                models.append({"operation_id": operation_id, "kind": kind, "entry": entry,
                               "source_sha256": hashlib.sha256(generated.encode()).hexdigest(),
                               "raw_goto_sha256": hashlib.sha256(raw.read_bytes()).hexdigest(),
                               "checked_goto_sha256": hashlib.sha256(checked.read_bytes()).hexdigest(),
                               **({'property_model': property_model} if property_model is not None else {})})
    expected = {(operation_id, kind) for operation_id in operation_ids for kind in ("frame", "input_dependence")}
    complete = (len(checks) == 1 + len(expected) and len(models) == len(expected)
                and all(row["status"] == "satisfied" for row in checks)
                and {(row.get("operation_id"), row.get("kind")) for row in checks if "operation_id" in row} == expected)
    validation_started = time.monotonic()
    core = {"status": "satisfied" if complete else "incomplete", "authorizing": False,
            "policy": MUTABLE_CONTRACT_POLICY if mutable else READONLY_CONTRACT_POLICY,
            "model_policy": MUTABLE_MODEL_POLICY if mutable else READONLY_MODEL_POLICY,
            "checker_options": options, "interface_sha256": bundle.interface.interface_sha256,
            "interface_intent": bundle.intent.to_payload(),
            "authored_goto_sha256": hashlib.sha256(raw_source.read_bytes()).hexdigest() if raw_source.is_file() else None,
            "source_package": source, "source_profile": profile, "operation_symbols": symbols,
            "source_dependencies": dependencies,
            "headers_sha256": canonical_sha256_v3(headers),
            "support_headers": {path.name: hashlib.sha256(path.read_bytes()).hexdigest()
                                for path in sorted(include.iterdir())},
            "tools": {name: hashlib.sha256(path.read_bytes()).hexdigest()
                      for name, path in (("goto_cc", goto_cc), ("goto_instrument", goto_instrument), ("cbmc", cbmc))},
            "checks": checks, "models": models, "inventories": inventories,
            "commands": [{**row, "command": [item.replace(str(output), "$MODEL_ROOT") for item in row["command"]]}
                         for row in commands]}
    if shared:
        core.update(policy=SHARED_CONTRACT_POLICY, model_policy=SHARED_MODEL_POLICY,
                    shared_contract=shared_contract)
    if partition_command is not None:
        core['property_checker_command'] = partition_command
    if objects:
        core.update(policy=OBJECT_CONTRACT_POLICY, model_policy=OBJECT_MODEL_POLICY)
        if terminal_services:
            core['terminal_services'] = list(terminal_services)
    if summary_rows:
        core.update(policy=SHARED_DEPENDENCY_POLICY if shared else source_dependencies.MUTABLE_POLICY if mutable else source_dependencies.READONLY_POLICY,
            model_policy=SHARED_DEPENDENCY_MODEL if shared else source_dependencies.MUTABLE_MODEL if mutable else source_dependencies.READONLY_MODEL,
            summary_dependencies=summary_rows)
    result = {**core, "receipt_sha256": canonical_sha256_v3(core)}
    if complete:
        validator(result, artifacts=output)
        if timings is not None:
            timings.append({"step": "validate-evidence", "phase": "model", "seconds": time.monotonic() - validation_started})
    (output / "local-contract-result.json").write_text(json.dumps(result, indent=2) + "\n")
    return result


def check_optional_readonly_source_contracts(**kwargs):
    return _check_optional_memory_source_contracts(**kwargs, mutable=False)


def check_optional_memory_source_contracts(**kwargs):
    return _check_optional_memory_source_contracts(**kwargs,
        mutable=fixed_mutable_summary_operations(kwargs["bundle"]) is not None)


def _check_optional_memory_source_contracts(*, bundle, package, output, cbmc,
                                          timeout_seconds, workspace=None, mutable, summary_dependencies=()):
    """Retain auxiliary local evidence without changing ordinary qualification.

    Nix supplies a disjoint compiler workspace so output-path rewriting cannot
    change the model bytes after their hashes have been recorded.
    """
    shape = fixed_mutable_summary_operations if mutable else fixed_readonly_summary_operations
    checker = check_mutable_source_contracts if mutable else check_readonly_source_contracts
    if shape(bundle) is None:
        return None
    if workspace is not None and (
            workspace.resolve().is_relative_to(output.resolve())
            or output.resolve().is_relative_to(workspace.resolve())):
        raise ValueError("read-only summary workspace and artifact output must be disjoint")
    certificate = checker(
        bundle=bundle, package=package, output=output if workspace is None else workspace,
        goto_cc=cbmc.with_name("goto-cc"), goto_instrument=cbmc.with_name("goto-instrument"),
        cbmc=cbmc, timeout_seconds=timeout_seconds,
        summary_dependencies=summary_dependencies,
    )
    if workspace is not None and workspace.is_dir():
        shutil.copytree(workspace, output)
    return certificate if certificate["status"] == "satisfied" else None
