"""Public command surface for the active reconstruction workflow."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any, Callable

from .analysis.binary_inventory import stage_a_inventory_binary
from .analysis.isa_inventory import write_binary_isa_inventory
from .component_discovery import write_component_proposals
from .component_selection import materialize_component_declarations
from .component_workspace import (
    create_component_workspace,
    promote_qualified_components,
    qualify_component,
    rebind_component_workspace,
    run_component_source_check,
)
from .contract_tools import (
    REFERENCE_CONTRACT_MODEL_ID,
    stage_a_diff_obligations,
    stage_a_explain_obligations,
    stage_a_export_reference_contract,
    stage_a_smoke_contract,
)
from .import_abi import expand_import_abi_policy
from .external_operation_profiles import load_external_operation_profile
from .isa_catalog_enrichment import write_enriched_side_isa_catalog
from .isa_conformance import parse_isa_conformance_corpus, serialize_isa_conformance_report
from .isa_conformance_bochs import run_bochs_corpus
from .isa_conformance_lean import run_lean_isa_conformance_with_forms
from .isa_conformance_nix import stage_a_check_isa_conformance_nix
from .isa_conformance_unicorn import run_unicorn_corpus
from .opaque_reconstruction import stage_a_export_opaque_reconstruction
from .reconstruction_ir import export_machine_ir_package
from .roundtrip_fuzz.generator import generate_spike_corpus
from .roundtrip_fuzz.runner import run_roundtrip_corpus
from .semantic_components import write_semantic_component_catalog
from .source_operation_catalog import render_source_operations
from .source_project import bind_source_project
from .stage_b import (
    stage_b_explain_delta,
    stage_b_validate_candidate,
)
from .stage_b_c_backend import stage_b_generate_semantic_c_from_state_machine
from .stage_b_functional import (
    StageBFunctionalInputError,
    stage_b_run_functional_suite,
)
from .stage_b_interpreter_backend import write_stage_b_interpreter_package
from .stage_b_native_engine import write_stage_b_native_engine_package
from .stage_b_native_runtime import write_stage_b_native_runtime_package
from .stage_b_provenance import StageBProvenanceInputError, stage_b_generate_candidate_provenance
from .stage_b_skeleton import stage_b_generate_skeleton
from .stage_binary import StageAInputError


Handler = Callable[[argparse.Namespace], Any]


def _path(command: argparse.ArgumentParser, name: str, **kwargs: Any) -> None:
    command.add_argument(f"--{name.replace('_', '-')}", dest=name, type=Path, **kwargs)


def _many_paths(command: argparse.ArgumentParser, name: str) -> None:
    command.add_argument(
        f"--{name.replace('_', '-')}", dest=name, type=Path, action="append", default=[]
    )


def _command(
    commands: argparse._SubParsersAction[argparse.ArgumentParser],
    name: str,
    help_text: str,
    handler: Handler,
) -> argparse.ArgumentParser:
    parser = commands.add_parser(name, help=help_text)
    parser.set_defaults(handler=handler)
    return parser


def _build_parser(*, prog: str | None = None) -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog=prog or "spaghetti-extractor")
    commands = parser.add_subparsers(dest="command", required=True)

    inventory = _command(
        commands,
        "stage-a-inventory-binary",
        "classify every executable byte and recover static code regions",
        lambda a: stage_a_inventory_binary(
            binary=a.binary, linker_map=a.linker_map, side="original", out=a.out
        ),
    )
    _path(inventory, "binary", required=True)
    _path(inventory, "linker_map")
    _path(inventory, "out", required=True)

    isa_inventory = _command(
        commands,
        "stage-a-inventory-isa",
        "classify the instruction forms required by one static binary inventory",
        lambda a: write_binary_isa_inventory(
            binary=a.binary, inventory=a.inventory, scope=a.scope, out=a.out
        ),
    )
    _path(isa_inventory, "binary", required=True)
    _path(isa_inventory, "inventory", required=True)
    isa_inventory.add_argument("--scope", choices=("base", "superset"), default="superset")
    _path(isa_inventory, "out", required=True)

    opaque = _command(
        commands,
        "stage-a-export-opaque-reconstruction",
        "emit the original-only reference contract and canonical state machine",
        lambda a: stage_a_export_opaque_reconstruction(
            original=a.original, inventory=a.inventory, out=a.out
        ),
    )
    _path(opaque, "original", required=True)
    _path(opaque, "inventory", required=True)
    _path(opaque, "out", required=True)

    reference = _command(
        commands,
        "stage-a-export-reference-contract",
        "emit reusable static constraints and source-mapped transfer contracts",
        lambda a: stage_a_export_reference_contract(
            original=a.original,
            mapping=a.mapping,
            out=a.out,
            sidecar_dir=a.sidecar_dir,
            unit_contract_dir=a.unit_contract_dir,
            model=REFERENCE_CONTRACT_MODEL_ID,
        ),
    )
    _path(reference, "original", required=True)
    _path(reference, "mapping")
    _path(reference, "sidecar_dir")
    _path(reference, "unit_contract_dir")
    _path(reference, "out", required=True)

    smoke = _command(
        commands,
        "stage-a-smoke-contract",
        "run the cheap reference-contract consistency gate",
        lambda a: stage_a_smoke_contract(reference_contract=a.reference_contract, out=a.out),
    )
    _path(smoke, "reference_contract", required=True)
    _path(smoke, "out")

    explain = _command(
        commands,
        "stage-a-explain-contract",
        "explain one static contract region, family, or issue",
        lambda a: stage_a_explain_obligations(
            reference_contract=a.reference_contract, focus=a.focus, out=a.out
        ),
    )
    _path(explain, "reference_contract", required=True)
    explain.add_argument("--focus", required=True)
    _path(explain, "out")

    diff = _command(
        commands,
        "stage-a-diff-contract",
        "diff two static contract iterations",
        lambda a: stage_a_diff_obligations(before=a.before, after=a.after, out=a.out),
    )
    _path(diff, "before", required=True)
    _path(diff, "after", required=True)
    _path(diff, "out")

    import_abi = _command(
        commands,
        "stage-a-expand-import-abi",
        "bind reviewed ABI policy to exact PE imports",
        lambda a: expand_import_abi_policy(
            original_pe=a.original, policy=a.policy, out=a.out
        ),
    )
    _path(import_abi, "original", required=True)
    _path(import_abi, "policy", required=True)
    _path(import_abi, "out", required=True)

    conformance = _command(
        commands,
        "stage-a-check-isa-conformance",
        "run one ISA oracle as a cached Nix derivation",
        _run_isa_conformance_nix,
    )
    _path(conformance, "corpus", required=True)
    conformance.add_argument("--backend", choices=("lean", "unicorn", "bochs"), required=True)
    _path(conformance, "bochs_runner")
    _path(conformance, "forms_out")
    _path(conformance, "flake")
    _path(conformance, "builders_file")
    _path(conformance, "builder_trusted_public_keys_file")
    _path(conformance, "out", required=True)

    worker = _command(
        commands,
        "stage-a-check-isa-conformance-worker",
        "internal Nix worker for one concrete ISA oracle",
        _run_isa_conformance_worker,
    )
    _path(worker, "corpus", required=True)
    worker.add_argument("--backend", choices=("lean", "unicorn", "bochs"), required=True)
    _path(worker, "bochs_runner")
    _path(worker, "forms_out")
    _path(worker, "out", required=True)

    enrich = _command(
        commands,
        "stage-a-enrich-isa-catalog",
        "replay static encodings and derive qualification metadata",
        lambda a: write_enriched_side_isa_catalog(
            proposal=a.proposal, out=a.out, timeout_seconds=a.timeout_seconds
        ),
    )
    _path(enrich, "proposal", required=True)
    enrich.add_argument("--timeout-seconds", type=float, default=300.0)
    _path(enrich, "out", required=True)

    roundtrip_generate = _command(
        commands,
        "roundtrip-generate",
        "generate small PE32 static-analysis regression cases",
        lambda a: generate_spike_corpus(
            out=a.out,
            seed=a.seed,
            count=a.count,
            toolchain=a.toolchain,
            compiler=a.compiler,
            linker=a.linker,
            force=a.force,
        ),
    )
    _path(roundtrip_generate, "out", required=True)
    roundtrip_generate.add_argument("--seed", type=int, default=0)
    roundtrip_generate.add_argument("--count", type=int, default=36)
    roundtrip_generate.add_argument("--toolchain", choices=("gnu", "llvm-msvc"), default="gnu")
    roundtrip_generate.add_argument("--compiler")
    roundtrip_generate.add_argument("--linker")
    roundtrip_generate.add_argument("--force", action="store_true")

    roundtrip_run = _command(
        commands,
        "roundtrip-run",
        "qualify generated PE32 extraction and violation localization",
        lambda a: run_roundtrip_corpus(
            corpus=a.corpus,
            out=a.out,
            case_ids=tuple(a.case),
        ),
    )
    _path(roundtrip_run, "corpus", required=True)
    roundtrip_run.add_argument("--case", action="append", default=[])
    _path(roundtrip_run, "out", required=True)

    machine_ir = _command(
        commands,
        "stage-a-export-machine-ir",
        "export deterministic byte-free executable machine IR",
        _export_machine_ir,
    )
    _path(machine_ir, "state_machine", required=True)
    _path(machine_ir, "original", required=True)
    _path(machine_ir, "reference_contract")
    _path(machine_ir, "indirect_target_profile")
    _many_paths(machine_ir, "machine_import_profile")
    _many_paths(machine_ir, "external_interface_profile")
    _many_paths(machine_ir, "external_operation_profile")
    _path(machine_ir, "out", required=True)

    skeleton = _command(
        commands,
        "stage-b-generate-skeleton",
        "generate a compilable C scaffold or contract-guided baseline",
        lambda a: stage_b_generate_skeleton(
            original=a.original,
            linker_map=a.linker_map,
            reference_contract=a.reference_contract,
            out_dir=a.out,
            target_name=a.target_name,
            implementation_mode=a.mode,
            source_language="c",
        ),
    )
    _path(skeleton, "original", required=True)
    _path(skeleton, "linker_map")
    _path(skeleton, "reference_contract")
    skeleton.add_argument("--target-name", required=True)
    skeleton.add_argument(
        "--mode", choices=("scaffold", "decompiled-c", "contract-guided-c"), default="contract-guided-c"
    )
    _path(skeleton, "out", required=True)

    semantic_c = _command(
        commands,
        "stage-b-generate-semantic-c",
        "lower the canonical state machine into deterministic C",
        lambda a: stage_b_generate_semantic_c_from_state_machine(
            state_machine=a.state_machine,
            machine_call_catalog=a.machine_call_catalog,
            out_dir=a.out,
        ),
    )
    _path(semantic_c, "state_machine", required=True)
    _path(semantic_c, "machine_call_catalog")
    _path(semantic_c, "out", required=True)

    interpreter = _command(
        commands,
        "stage-b-generate-interpreter",
        "emit the portable machine-IR interpreter package",
        lambda a: write_stage_b_interpreter_package(
            state_machine=a.state_machine, machine_ir=a.machine_ir, out=a.out
        ),
    )
    _path(interpreter, "state_machine")
    _path(interpreter, "machine_ir")
    _path(interpreter, "out", required=True)

    native_engine = _command(
        commands,
        "stage-b-generate-native-engine",
        "emit PE32 ABI bridges for the generated interpreter",
        lambda a: write_stage_b_native_engine_package(
            state_machine=a.state_machine,
            machine_ir=a.machine_ir,
            entry_rva=a.entry_rva,
            callable_external_contract=a.callable_external_contract,
            out=a.out,
        ),
    )
    _path(native_engine, "state_machine")
    _path(native_engine, "machine_ir")
    native_engine.add_argument("--entry-rva", type=lambda v: int(v, 0), required=True)
    _path(native_engine, "callable_external_contract")
    _path(native_engine, "out", required=True)

    native_runtime = _command(
        commands,
        "stage-b-generate-native-runtime",
        "emit the candidate-only external runtime package",
        lambda a: write_stage_b_native_runtime_package(
            interpreter_package=a.interpreter_package,
            native_engine_package=a.native_engine_package,
            external_profile=a.external_profile,
            callable_external_contract=a.callable_external_contract,
            out=a.out,
        ),
    )
    _path(native_runtime, "interpreter_package", required=True)
    _path(native_runtime, "native_engine_package", required=True)
    _path(native_runtime, "external_profile")
    _path(native_runtime, "callable_external_contract")
    _path(native_runtime, "out", required=True)

    components = _command(
        commands,
        "stage-b-build-component-catalog",
        "derive semantic component definitions from machine IR",
        lambda a: write_semantic_component_catalog(
            machine_ir=a.machine_ir,
            reconstruction_plan=a.reconstruction_plan,
            declarations=a.declarations,
            out=a.out,
        ),
    )
    _path(components, "machine_ir", required=True)
    _path(components, "reconstruction_plan", required=True)
    _path(components, "declarations", required=True)
    _path(components, "out", required=True)

    discovery = _command(
        commands,
        "stage-b-discover-components",
        "propose component coarsenings without authorizing replacement",
        lambda a: write_component_proposals(
            machine_ir=a.machine_ir,
            reconstruction_plan=a.reconstruction_plan,
            out=a.out,
            max_units=a.max_units,
            max_candidates_per_seed=a.max_candidates_per_seed,
        ),
    )
    _path(discovery, "machine_ir", required=True)
    _path(discovery, "reconstruction_plan", required=True)
    discovery.add_argument("--max-units", type=int, default=512)
    discovery.add_argument("--max-candidates-per-seed", type=int, default=12)
    _path(discovery, "out", required=True)

    selection = _command(
        commands,
        "stage-b-select-components",
        "materialize reviewed component declarations",
        lambda a: materialize_component_declarations(
            proposals=a.proposals, selection=a.selection, out=a.out
        ),
    )
    _path(selection, "proposals", required=True)
    _path(selection, "selection", required=True)
    _path(selection, "out", required=True)

    component_create = _command(
        commands,
        "stage-b-create-component",
        "create an editable portable-C component workspace",
        _create_component,
    )
    _path(component_create, "catalog")
    _path(component_create, "plan")
    _path(component_create, "machine_ir")
    _path(component_create, "component_slice")
    _path(component_create, "interpreter_package", required=True)
    _path(component_create, "interface_refinement", required=True)
    component_create.add_argument("--component-id", required=True)
    component_create.add_argument("--profile", required=True)
    _path(component_create, "out", required=True)

    component_rebind = _command(
        commands,
        "stage-b-rebind-component",
        "refresh hashes after editing portable component source",
        lambda a: rebind_component_workspace(workspace=a.workspace),
    )
    _path(component_rebind, "workspace", required=True)

    component_check = _command(
        commands,
        "stage-b-check-component",
        "run the bounded component contract checker",
        lambda a: run_component_source_check(
            workspace=a.workspace, cbmc=a.cbmc, out=a.out, timeout_seconds=a.timeout_seconds
        ),
    )
    _path(component_check, "workspace", required=True)
    component_check.add_argument("--cbmc", required=True)
    component_check.add_argument("--timeout-seconds", type=int, default=120)
    _path(component_check, "out", required=True)

    component_qualify = _command(
        commands,
        "stage-b-qualify-component",
        "bind source evidence and authorize one component replacement",
        lambda a: qualify_component(
            workspace=a.workspace, source_evidence=a.source_evidence, out=a.out
        ),
    )
    _path(component_qualify, "workspace", required=True)
    _path(component_qualify, "source_evidence", required=True)
    _path(component_qualify, "out", required=True)

    component_promote = _command(
        commands,
        "stage-b-promote-components",
        "compose qualified components into an override registry",
        lambda a: promote_qualified_components(
            workspaces=a.workspace, qualifications=a.qualification, out_dir=a.out
        ),
    )
    _many_paths(component_promote, "workspace")
    _many_paths(component_promote, "qualification")
    _path(component_promote, "out", required=True)

    source_bind = _command(
        commands,
        "stage-b-bind-source-project",
        "bind a portable source project to machine-IR components",
        _bind_source_project,
    )
    _path(source_bind, "spec", required=True)
    _path(source_bind, "source_root", required=True)
    _path(source_bind, "machine_ir", required=True)
    _path(source_bind, "out", required=True)

    render_operations = _command(
        commands,
        "stage-b-render-source-operations",
        "render recovered external operations as non-authoritative C calls",
        _render_source_operations,
    )
    _path(render_operations, "catalog", required=True)
    _path(render_operations, "operation_profile", required=True)
    _path(render_operations, "operations", required=True)
    _path(render_operations, "out", required=True)

    functional = _command(
        commands,
        "stage-b-run-functional-suite",
        "run curated candidate-only expected-output tests under headless Wine",
        lambda a: stage_b_run_functional_suite(
            candidate_command=tuple(a.candidate_command),
            candidate_binary=a.candidate_binary,
            suite=a.suite,
            out=a.out,
        ),
    )
    functional.add_argument("--candidate-command", nargs="+", required=True)
    _path(functional, "candidate_binary")
    _path(functional, "suite", required=True)
    _path(functional, "out", required=True)

    provenance = _command(
        commands,
        "stage-b-record-candidate",
        "record candidate-only source and build provenance",
        lambda a: stage_b_generate_candidate_provenance(
            target_name=a.target_name,
            candidate=a.candidate,
            skeleton_manifest=a.skeleton_manifest,
            build_target=a.build_target,
            build_compiler=a.build_compiler,
            out=a.out,
        ),
    )
    provenance.add_argument("--target-name", required=True)
    provenance.add_argument("--build-target", required=True)
    provenance.add_argument("--build-compiler", required=True)
    _path(provenance, "candidate", required=True)
    _path(provenance, "skeleton_manifest", required=True)
    _path(provenance, "out", required=True)

    validate = _command(
        commands,
        "stage-b-validate-candidate",
        "compare candidate static evidence to the reference contract",
        lambda a: stage_b_validate_candidate(
            reference_contract=a.reference_contract,
            candidate=a.candidate,
            linker_map_candidate=a.linker_map_candidate,
            skeleton_manifest=a.skeleton_manifest,
            candidate_provenance=a.candidate_provenance,
            target_name=a.target_name,
            out=a.out,
        ),
    )
    validate.add_argument("--target-name", required=True)
    _path(validate, "reference_contract", required=True)
    _path(validate, "candidate", required=True)
    _path(validate, "linker_map_candidate", required=True)
    _path(validate, "skeleton_manifest", required=True)
    _path(validate, "candidate_provenance", required=True)
    _path(validate, "out", required=True)

    delta = _command(
        commands,
        "stage-b-explain-delta",
        "rank source-mapped candidate repair items",
        _explain_delta,
    )
    _path(delta, "reference_contract", required=True)
    _path(delta, "candidate", required=True)
    _path(delta, "linker_map_candidate", required=True)
    _path(delta, "skeleton_manifest", required=True)
    _path(delta, "candidate_crash_report")
    _path(delta, "out", required=True)

    return parser


def _run_isa_conformance_nix(args: argparse.Namespace) -> dict[str, Any]:
    return stage_a_check_isa_conformance_nix(
        corpus=args.corpus,
        backend=args.backend,
        out=args.out,
        forms_out=args.forms_out,
        bochs_runner=args.bochs_runner,
        flake=args.flake,
        builders_file=args.builders_file,
        builder_trusted_public_keys_file=args.builder_trusted_public_keys_file,
    )


def _run_isa_conformance_worker(args: argparse.Namespace) -> dict[str, Any]:
    corpus = parse_isa_conformance_corpus(json.loads(args.corpus.read_text(encoding="utf-8")))
    if args.backend == "lean":
        report, forms = run_lean_isa_conformance_with_forms(corpus)
        if args.forms_out is not None:
            args.forms_out.parent.mkdir(parents=True, exist_ok=True)
            args.forms_out.write_text(json.dumps(forms, indent=2, sort_keys=True) + "\n")
    elif args.backend == "unicorn":
        report = run_unicorn_corpus(corpus)
    else:
        if args.bochs_runner is None:
            raise StageAInputError("--bochs-runner is required for the Bochs worker")
        report = run_bochs_corpus(corpus, runner=args.bochs_runner)
    payload = serialize_isa_conformance_report(report)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n")
    return payload


def _export_machine_ir(args: argparse.Namespace) -> dict[str, Any]:
    package = export_machine_ir_package(
        state_machine=args.state_machine,
        original_pe=args.original,
        out=args.out,
        reference_contract=args.reference_contract,
        indirect_target_profile=args.indirect_target_profile,
        machine_import_profiles=args.machine_import_profile,
        external_interface_profiles=args.external_interface_profile,
        external_operation_profiles=args.external_operation_profile,
    )
    return package.manifest


def _create_component(args: argparse.Namespace) -> dict[str, Any]:
    return create_component_workspace(
        catalog=args.catalog,
        plan=args.plan,
        machine_ir=args.machine_ir,
        component_slice=args.component_slice,
        interpreter_package=args.interpreter_package,
        component_id=args.component_id,
        proof_profile=args.profile,
        interface_refinement=args.interface_refinement,
        out_dir=args.out,
    )


def _bind_source_project(args: argparse.Namespace) -> dict[str, Any]:
    spec = json.loads(args.spec.read_text(encoding="utf-8"))
    return bind_source_project(
        specification=spec,
        source_root=args.source_root,
        machine_ir=args.machine_ir,
        out=args.out,
    )


def _render_source_operations(args: argparse.Namespace) -> dict[str, Any]:
    profile = load_external_operation_profile(args.operation_profile)
    operations_payload = json.loads(args.operations.read_text(encoding="utf-8"))
    operations = operations_payload.get("operations") if isinstance(operations_payload, dict) else None
    if not isinstance(operations, list):
        raise StageAInputError("operation evidence must contain an operations array")
    result = render_source_operations(
        catalog=args.catalog,
        operation_profile_sha256=profile.sha256,
        operations=operations,
    )
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return result


def _explain_delta(args: argparse.Namespace) -> dict[str, Any]:
    return stage_b_explain_delta(
        reference_contract=args.reference_contract,
        candidate=args.candidate,
        linker_map_candidate=args.linker_map_candidate,
        skeleton_manifest=args.skeleton_manifest,
        candidate_crash_report=args.candidate_crash_report,
        out=args.out,
    )


def _exit_status(result: dict[str, Any]) -> int:
    status = result.get("status", result.get("verdict"))
    return 0 if status in {
        None,
        "checked",
        "complete",
        "generated",
        "pass",
        "qualified",
        "ready",
        "satisfied",
        "usable-incomplete",
    } else 1


def main(argv: list[str] | None = None, *, prog: str | None = None) -> int:
    parser = _build_parser(prog=prog)
    args = parser.parse_args(argv)
    try:
        result = args.handler(args)
    except (
        OSError,
        StageAInputError,
        StageBFunctionalInputError,
        StageBProvenanceInputError,
        ValueError,
    ) as exc:
        print(f"{parser.prog}: {exc}", file=sys.stderr)
        return 2
    if isinstance(result, int):
        return result
    if isinstance(result, dict):
        print(json.dumps(result, indent=2, sort_keys=True))
        return _exit_status(result)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
