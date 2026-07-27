{ pkgs
, pythonEnv
, spaghettiExtractor
, sourceRoot
, leanSourceRoot
, originalFixture
, mingw32
, mkLeanGraph ? import ./stage-a-lean-graph.nix
}:

let
  lib = pkgs.lib;
  # Each proof phase is independently content-addressed so identical checked
  # semantics can be substituted across local and remote realizations.
  driver = ./gnu-hello-roundtrip-driver.py;
  directCallSemanticsDriver = ./gnu-hello-direct-call-semantics.py;
  directCallFixedPointDriver = ./gnu-hello-direct-call-fixed-point.py;
  stackDynamicAuthorityDriver = ./gnu-hello-stack-dynamic-authority.py;
  stackDynamicHints = ./gnu-hello-stack-dynamic-hints.json;
  proofSourceAggregateDriver = ./stage-a-proof-source-aggregate.py;
  kernelDataDriver = ./gnu-hello-kernel-data-driver.py;
  compiledKernelDriver = ./gnu-hello-compiled-kernel.py;
  proofClosureDriver = ./gnu-hello-proof-closure-driver.py;
  constructiveSourceCoverageDriver =
    ./gnu-hello-constructive-source-coverage.py;
  canonicalRelationCoreDriver = ./gnu-hello-canonical-relation-core.py;
  nativeLaunchGraphDriver = ./gnu-hello-native-launch-graph.py;
  diagnosticDriver = ./gnu-hello-roundtrip-diagnostic.py;
  universalPairedExternalEnvironmentDriver =
    ./gnu-hello-universal-paired-external-environment.py;
  fixtureRoot =
    "${originalFixture}/share/spaghetti-extractor/stage-a-gnu-hello-fixtures/original";
  originalPe = "${fixtureRoot}/hello.exe";
  originalMap = "${fixtureRoot}/hello.map";
  machineRuntimeProfileSource = lib.fileset.toSource {
    root = ../profiles;
    fileset = lib.fileset.unions [
      ../profiles/pe32-msvcrt-machine-runtime-v1.json
      ../profiles/pe32-kernel32-lockstep-v1.json
      ../profiles/pe32-msvcrt-lockstep-v1.json
      ../profiles/pe32-kernel32-callable-resolvers-v1.json
    ];
  };
  machineRuntimeProfile =
    "${machineRuntimeProfileSource}/pe32-msvcrt-machine-runtime-v1.json";
  python = "${pythonEnv}/bin/python3";
  aggregatePython = "${pkgs.python3}/bin/python3";
  compiler = "${mingw32.stdenv.cc}/bin/i686-w64-mingw32-gcc";
  # Candidate production only needs runtime Python.  In particular, neither
  # reviewed Lean nor Python proof emitters participate in its source hash.
  runtimePythonSource = lib.fileset.toSource {
    root = ../.;
    fileset = lib.fileset.unions [
      ../src/spaghetti_extractor/__init__.py
      ../src/spaghetti_extractor/errors.py
      ../src/spaghetti_extractor/util.py
      ../src/spaghetti_extractor/pe.py
      ../src/spaghetti_extractor/stage_binary.py
      ../src/spaghetti_extractor/contract_tools.py
      ../src/spaghetti_extractor/roundtrip_fuzz/image_contract.py
      ../src/spaghetti_extractor/relational/__init__.py
      ../src/spaghetti_extractor/relational/definedness.py
      ../src/spaghetti_extractor/relational/semantic_cutpoints.py
      ../src/spaghetti_extractor/relational/x87_profile.py
      ../src/spaghetti_extractor/stage_b_api_catalog.py
      ../src/spaghetti_extractor/stage_b_c_backend.py
      ../src/spaghetti_extractor/stage_b_engine_layout.py
      ../src/spaghetti_extractor/stage_b_interpreter_backend.py
      ../src/spaghetti_extractor/stage_b_interpreter_native_build.py
      ../src/spaghetti_extractor/stage_b_native_binding.py
      ../src/spaghetti_extractor/stage_b_native_build.py
      ../src/spaghetti_extractor/stage_b_native_engine.py
      ../src/spaghetti_extractor/stage_b_native_runtime.py
      ../src/spaghetti_extractor/stage_b_pe_composer.py
      ../src/spaghetti_extractor/stage_b_state_machine.py
    ];
  };
  stackDynamicProofPythonFiles = lib.fileset.unions [
    ../src/spaghetti_extractor/relational/lean/stack_dynamic_indirect_control.py
    ../src/spaghetti_extractor/relational/lean/original_stack_dynamic_control_closure.py
    ../src/spaghetti_extractor/relational/lean/runtime_value_carry.py
  ];
  directCallProposalProofPythonFiles = lib.fileset.unions [
    ../src/spaghetti_extractor/relational/lean/internal_direct_call_register_summary.py
    ../src/spaghetti_extractor/relational/lean/internal_direct_call_summary_proposal.py
  ];
  proofPythonFiles = lib.fileset.difference
    (lib.fileset.intersection
      (lib.fileset.difference
        ../src
        ../src/spaghetti_extractor/lean/StageA)
      (lib.fileset.fileFilter (file: !file.hasExt "pyc") ../src))
    (lib.fileset.unions [
      stackDynamicProofPythonFiles
      directCallProposalProofPythonFiles
      ../src/spaghetti_extractor/relational/build.py
    ]);
  proofPythonSource = lib.fileset.toSource {
    root = ../.;
    fileset = proofPythonFiles;
  };
  # The stack/dynamic phase consumes a compact typed projection of the
  # mixed-original plan. Keep its emitter closure independent from the
  # monolithic lane driver and unrelated proof tooling.
  stackDynamicAuthorityPythonSource = lib.fileset.toSource {
    root = ../.;
    fileset = lib.fileset.unions [
      ../src/spaghetti_extractor/__init__.py
      ../src/spaghetti_extractor/errors.py
      ../src/spaghetti_extractor/util.py
      ../src/spaghetti_extractor/relational/__init__.py
      ../src/spaghetti_extractor/relational/original_cutpoint_graph_ir.py
      ../src/spaghetti_extractor/relational/runtime_value_carry_ir.py
      ../src/spaghetti_extractor/relational/stack_dynamic_control_ir.py
      ../src/spaghetti_extractor/relational/lean/__init__.py
      ../src/spaghetti_extractor/relational/lean/nullable_code_pointer_table.py
      ../src/spaghetti_extractor/relational/lean/original_indirect_control_authority.py
      ../src/spaghetti_extractor/relational/lean/stack_fixed_code_pointer.py
      stackDynamicProofPythonFiles
    ];
  };
  # Direct-call semantic adapters are a hot proof-iteration boundary.  Keep
  # their emitter independent from the monolithic GNU lane driver and from
  # unrelated extraction/analysis modules.
  directCallSemanticsPythonSource = lib.fileset.toSource {
    root = ../.;
    fileset = lib.fileset.unions [
      ../src/spaghetti_extractor/__init__.py
      ../src/spaghetti_extractor/errors.py
      ../src/spaghetti_extractor/util.py
      ../src/spaghetti_extractor/relational/__init__.py
      ../src/spaghetti_extractor/relational/direct_call_proposal_ir.py
      ../src/spaghetti_extractor/relational/original_cutpoint_graph_ir.py
      ../src/spaghetti_extractor/relational/stack_dynamic_control_ir.py
      ../src/spaghetti_extractor/relational/lean/__init__.py
      ../src/spaghetti_extractor/relational/lean/internal_direct_call_mixed_original_integration.py
      ../src/spaghetti_extractor/relational/lean/internal_direct_call_register_control_authority.py
      ../src/spaghetti_extractor/relational/lean/internal_direct_call_register_summary.py
      ../src/spaghetti_extractor/relational/lean/internal_direct_call_semantics_bundle.py
      ../src/spaghetti_extractor/relational/lean/internal_direct_call_summary_proposal.py
    ];
  };
  directCallProposalPythonSource = lib.fileset.toSource {
    root = ../.;
    fileset = lib.fileset.unions [
      proofPythonFiles
      directCallProposalProofPythonFiles
    ];
  };
  directCallFixedPointPythonSource = lib.fileset.toSource {
    root = ../.;
    fileset = directCallFixedPointDriver;
  };
  # The exact-data phase emits hundreds of immutable Lean certificate packs.
  # Keep its Python closure independent from unrelated proof emitters so a new
  # composition theorem does not regenerate and recompile that entire graph.
  kernelDataPythonSource = lib.fileset.toSource {
    root = ../.;
    fileset = lib.fileset.unions [
      ../src/spaghetti_extractor/__init__.py
      ../src/spaghetti_extractor/errors.py
      ../src/spaghetti_extractor/pe.py
      ../src/spaghetti_extractor/stage_binary.py
      ../src/spaghetti_extractor/util.py
      ../src/spaghetti_extractor/relational/__init__.py
      ../src/spaghetti_extractor/relational/artifacts.py
      ../src/spaghetti_extractor/relational/contract.py
      ../src/spaghetti_extractor/relational/definedness.py
      ../src/spaghetti_extractor/relational/model.py
      ../src/spaghetti_extractor/relational/schema.py
      ../src/spaghetti_extractor/relational/semantic_cutpoints.py
      ../src/spaghetti_extractor/relational/x86_instruction_profile.py
      ../src/spaghetti_extractor/relational/x87_profile.py
      ../src/spaghetti_extractor/relational/lean/__init__.py
      ../src/spaghetti_extractor/relational/lean/artifact_byte_packs.py
      ../src/spaghetti_extractor/relational/lean/common.py
      ../src/spaghetti_extractor/relational/lean/interpreter_kernel.py
      ../src/spaghetti_extractor/relational/lean/interpreter_kernel_data.py
      ../src/spaghetti_extractor/roundtrip_fuzz/image_contract.py
      ../src/spaghetti_extractor/stage_b_api_catalog.py
      ../src/spaghetti_extractor/stage_b_c_backend.py
      ../src/spaghetti_extractor/stage_b_engine_layout.py
      ../src/spaghetti_extractor/stage_b_interpreter_backend.py
      ../src/spaghetti_extractor/stage_b_interpreter_native_build.py
      ../src/spaghetti_extractor/stage_b_native_binding.py
      ../src/spaghetti_extractor/stage_b_native_build.py
      ../src/spaghetti_extractor/stage_b_native_engine.py
      ../src/spaghetti_extractor/stage_b_native_runtime.py
      ../src/spaghetti_extractor/stage_b_pe_composer.py
      ../src/spaghetti_extractor/stage_b_state_machine.py
    ];
  };
  kernelDataLeanSource = lib.fileset.toSource {
    root = ../.;
    fileset = lib.fileset.unions [
      ../src/spaghetti_extractor/lean/StageA/Formal.lean
      ../src/spaghetti_extractor/lean/StageA/RelationalFiniteIndex.lean
      ../src/spaghetti_extractor/lean/StageA/RelationalInterpreter.lean
      ../src/spaghetti_extractor/lean/StageA/RelationalInterpreterKernelData.lean
      ../src/spaghetti_extractor/lean/StageA/RelationalLoader.lean
      ../src/spaghetti_extractor/lean/StageA/RelationalPEBytePacks.lean
      ../src/spaghetti_extractor/lean/StageA/X87.lean
    ];
  };
  constructiveSourceCoveragePythonSource = lib.fileset.toSource {
    root = ../.;
    fileset = lib.fileset.unions [
      ../src/spaghetti_extractor/__init__.py
      ../src/spaghetti_extractor/errors.py
      ../src/spaghetti_extractor/util.py
      ../src/spaghetti_extractor/relational/__init__.py
      ../src/spaghetti_extractor/relational/lean/__init__.py
      ../src/spaghetti_extractor/relational/lean/interpreter_mixed_source_coverage.py
    ];
  };
  canonicalRelationCorePythonSource = lib.fileset.toSource {
    root = ../.;
    fileset = lib.fileset.unions [
      ../src/spaghetti_extractor/__init__.py
      ../src/spaghetti_extractor/errors.py
      ../src/spaghetti_extractor/util.py
      ../src/spaghetti_extractor/relational/__init__.py
      ../src/spaghetti_extractor/relational/lean/__init__.py
      ../src/spaghetti_extractor/relational/lean/interpreter_mixed_relation_core.py
    ];
  };
  # The graph emitter shares PE/relocation literals with the broader proof
  # generators.  Keep it out of the candidate closure; its deterministic
  # output is compiled and cached as an independent proof phase below.
  nativeLaunchGraphPythonSource = proofPythonSource;
  proofClosurePythonSource = lib.fileset.toSource {
    root = ../.;
    fileset = lib.fileset.unions [
      ../src/spaghetti_extractor/__init__.py
      ../src/spaghetti_extractor/errors.py
      ../src/spaghetti_extractor/pe.py
      ../src/spaghetti_extractor/stage_binary.py
      ../src/spaghetti_extractor/util.py
      ../src/spaghetti_extractor/relational/__init__.py
      ../src/spaghetti_extractor/relational/artifacts.py
      ../src/spaghetti_extractor/relational/contract.py
      ../src/spaghetti_extractor/relational/definedness.py
      ../src/spaghetti_extractor/relational/model.py
      ../src/spaghetti_extractor/relational/schema.py
      ../src/spaghetti_extractor/relational/semantic_cutpoints.py
      ../src/spaghetti_extractor/relational/x86_instruction_profile.py
      ../src/spaghetti_extractor/relational/x87_profile.py
      ../src/spaghetti_extractor/relational/lean/__init__.py
      ../src/spaghetti_extractor/relational/lean/artifact_byte_packs.py
      ../src/spaghetti_extractor/relational/lean/common.py
      ../src/spaghetti_extractor/relational/lean/interpreter_kernel.py
      ../src/spaghetti_extractor/relational/lean/interpreter_kernel_abi.py
      ../src/spaghetti_extractor/relational/lean/interpreter_kernel_callback.py
      ../src/spaghetti_extractor/relational/lean/interpreter_kernel_cdecl_epilogue.py
      ../src/spaghetti_extractor/relational/lean/interpreter_kernel_cdecl_epilogue_symbolic_closure.py
      ../src/spaghetti_extractor/relational/lean/interpreter_kernel_cdecl_epilogue_static_preservation.py
      ../src/spaghetti_extractor/relational/lean/interpreter_kernel_cdecl_epilogue_external_payload.py
      ../src/spaghetti_extractor/relational/lean/interpreter_kernel_operation_result_encoding.py
      ../src/spaghetti_extractor/relational/lean/interpreter_kernel_abstract_operation_transition.py
      ../src/spaghetti_extractor/relational/lean/interpreter_kernel_data.py
      ../src/spaghetti_extractor/relational/lean/interpreter_kernel_invoke.py
      ../src/spaghetti_extractor/relational/lean/interpreter_kernel_invoke_native.py
      ../src/spaghetti_extractor/relational/lean/interpreter_kernel_lookup_native.py
      ../src/spaghetti_extractor/relational/lean/interpreter_kernel_program_lookup_operation.py
      ../src/spaghetti_extractor/relational/lean/interpreter_kernel_run.py
      ../src/spaghetti_extractor/relational/lean/interpreter_kernel_run_native.py
      ../src/spaghetti_extractor/relational/lean/interpreter_kernel_run_operation.py
      ../src/spaghetti_extractor/relational/lean/interpreter_kernel_step.py
      ../src/spaghetti_extractor/relational/lean/interpreter_kernel_step_native.py
      ../src/spaghetti_extractor/relational/lean/interpreter_kernel_step_operation.py
      ../src/spaghetti_extractor/relational/lean/interpreter_kernel_step_program_lookup_call.py
      ../src/spaghetti_extractor/relational/lean/interpreter_kernel_step_program_lookup_call_closure.py
      ../src/spaghetti_extractor/relational/lean/interpreter_kernel_step_program_lookup_exact_computation.py
      ../src/spaghetti_extractor/relational/lean/interpreter_kernel_summary.py
      ../src/spaghetti_extractor/relational/lean/interpreter_x87_replay_bridge_target.py
      ../src/spaghetti_extractor/roundtrip_fuzz/image_contract.py
      ../src/spaghetti_extractor/stage_b_api_catalog.py
      ../src/spaghetti_extractor/stage_b_c_backend.py
      ../src/spaghetti_extractor/stage_b_engine_layout.py
      ../src/spaghetti_extractor/stage_b_interpreter_backend.py
      ../src/spaghetti_extractor/stage_b_interpreter_native_build.py
      ../src/spaghetti_extractor/stage_b_native_binding.py
      ../src/spaghetti_extractor/stage_b_native_build.py
      ../src/spaghetti_extractor/stage_b_native_engine.py
      ../src/spaghetti_extractor/stage_b_native_runtime.py
      ../src/spaghetti_extractor/stage_b_pe_composer.py
      ../src/spaghetti_extractor/stage_b_state_machine.py
    ];
  };
  # Compatibility name for downstream source-shape checks and diagnostics.
  roundTripPythonSource = proofPythonSource;
  runtimeDriver = pkgs.writeText "gnu-hello-roundtrip-runtime-driver.py" ''
    import argparse
    import json
    import sys
    import types
    from pathlib import Path

    import spaghetti_extractor

    # The public roundtrip_fuzz facade eagerly imports the proof pipeline.
    # Candidate generation only consumes its exact image-contract submodule.
    roundtrip_fuzz = types.ModuleType("spaghetti_extractor.roundtrip_fuzz")
    roundtrip_fuzz.__path__ = [str(
        Path(spaghetti_extractor.__file__).parent / "roundtrip_fuzz"
    )]
    sys.modules[roundtrip_fuzz.__name__] = roundtrip_fuzz

    from spaghetti_extractor.contract_tools import (
        stage_a_export_reference_contract,
        stage_a_generate_map,
    )
    from spaghetti_extractor.roundtrip_fuzz.image_contract import (
        load_stage_a_load_image_contract,
        write_stage_a_load_image_contract,
    )
    from spaghetti_extractor.stage_b_interpreter_backend import (
        write_stage_b_interpreter_package,
    )
    from spaghetti_extractor.stage_b_interpreter_native_build import (
        build_stage_b_interpreter_native_candidate,
    )
    from spaghetti_extractor.stage_b_native_engine import (
        write_stage_b_native_engine_package,
    )
    from spaghetti_extractor.stage_b_native_runtime import (
        write_stage_b_native_runtime_package,
    )
    from spaghetti_extractor.stage_b_state_machine import (
        write_stage_b_state_machine_from_stage_a_export,
    )
    from spaghetti_extractor.stage_binary import _parse_stage_a_pe
    from spaghetti_extractor.util import sha256_file, write_json


    def jsonl_count(path):
        return sum(1 for line in path.read_text(encoding="utf-8").splitlines() if line.strip())


    def smoke(args):
        original = Path(args.original)
        linker_map = Path(args.linker_map)
        out = Path(args.out)
        out.mkdir(parents=True, exist_ok=True)
        binary = _parse_stage_a_pe(original)
        try:
            if binary.machine != "i386" or binary.bitness != 32:
                raise ValueError("GNU hello smoke input is not an i386 PE32 image")
            if not linker_map.is_file() or not linker_map.read_bytes():
                raise ValueError("GNU hello smoke input has no linker map")
            write_json(out / "smoke.json", {
                "format": "stage-a-gnu-hello-roundtrip-smoke-v1",
                "status": "pass",
                "static_only": True,
                "executes_original_binary": False,
                "executes_candidate_binary": False,
                "original": {
                    "sha256": binary.sha256,
                    "machine": binary.machine,
                    "bitness": binary.bitness,
                    "entry_rva": binary.entrypoint_rva,
                    "sections": len(binary.sections),
                },
                "linker_map_sha256": sha256_file(linker_map),
            })
        finally:
            binary.pe.close()


    def static_export(args):
        original = Path(args.original)
        linker_map = Path(args.linker_map)
        out = Path(args.out)
        out.mkdir(parents=True, exist_ok=True)
        self_map = out / "original-self-map.json"
        result = stage_a_generate_map(
            original=original,
            candidate=original,
            linker_map_original=linker_map,
            linker_map_candidate=linker_map,
            out=self_map,
            original_flags="opaque-static-original",
            candidate_flags="opaque-static-reference",
        )
        if result.get("status") != "pass":
            raise ValueError("Stage A could not map the GNU hello image to itself")
        reference = out / "reference-contract.json"
        stage_a_export_reference_contract(
            original=original,
            out=reference,
            mapping=self_map,
            sidecar_dir=out,
            unit_contract_dir=out,
        )
        semantic = out / "semantic-transfer-contracts.jsonl"
        state_machine = out / "state-machine.jsonl"
        write_stage_b_state_machine_from_stage_a_export(
            reference_contract=reference,
            semantic_transfer_contracts=semantic,
            original_pe=original,
            out=state_machine,
        )
        load_image = out / "load-image-contract.json"
        load_contract = write_stage_a_load_image_contract(original_pe=original, out=load_image)
        write_json(out / "phase-manifest.json", {
            "format": "stage-a-gnu-hello-roundtrip-phase-v1",
            "phase": "static-export",
            "executes_original_binary": False,
            "executes_candidate_binary": False,
            "inputs": {
                "original_linker_map": {
                    "path": linker_map.name,
                    "sha256": sha256_file(linker_map),
                },
                "original_pe": {
                    "path": original.name,
                    "sha256": sha256_file(original),
                },
            },
            "status": "ready",
            "public_outputs": {
                "reference_contract": reference.name,
                "semantic_transfers": semantic.name,
                "state_machine": state_machine.name,
                "load_image_contract": load_image.name,
                "original_self_map": self_map.name,
            },
            "counts": {
                "transfers": jsonl_count(state_machine),
                "imports": sum(len(item.cells) for item in load_contract.imports),
                "tls_callbacks": 0 if load_contract.tls is None else len(load_contract.tls.callbacks),
            },
        })


    def interpreter(args):
        write_stage_b_interpreter_package(
            state_machine=Path(args.state_machine),
            out=Path(args.out),
        )


    def native_engine(args):
        contract_path = Path(args.load_image_contract)
        reference_path = Path(args.reference_contract)
        contract = load_stage_a_load_image_contract(contract_path)
        if args.entry_rva != contract.identity.entry_rva:
            raise ValueError("native-engine entry RVA differs from the load-image contract")
        callback_targets = []
        import_iat_vas = {}
        for descriptor in contract.imports:
            for cell in descriptor.cells:
                identity = cell.symbol if cell.symbol is not None else cell.ordinal
                if identity is None:
                    raise ValueError("load-image import cell has no identity")
                key = (descriptor.dll.lower(), identity)
                value = contract.identity.preferred_base + cell.iat_rva
                previous = import_iat_vas.setdefault(key, value)
                if previous != value:
                    raise ValueError("load-image contract has ambiguous IAT cells")
        termination_profile = json.loads(
            Path(args.termination_profile).read_text(encoding="utf-8")
        )
        termination_contracts = [
            row
            for row in termination_profile.get(
                "machine_import_call_contracts", []
            )
            if row.get("disposition") == "terminates"
            and row.get("import") == {
                "dll": args.termination_dll,
                "symbol": args.termination_symbol,
            }
        ]
        if len(termination_contracts) != 1:
            raise ValueError(
                "termination selection must name one exact modeled terminates contract"
            )
        if contract.tls is not None:
            callback_targets.extend({
                "rva": callback.rva,
                "kind": "tls_callback",
                "stack_cleanup_bytes": 12,
            } for callback in contract.tls.callbacks)
        relocation_rows = []
        for block in contract.relocations:
            for relocation in block.relocations:
                if relocation.target_rva is None or relocation.preferred_value is None or relocation.width == 0:
                    continue
                relocation_rows.append({
                    "source_rva": relocation.target_rva,
                    "type": relocation.type,
                    "kind": relocation.kind,
                    "width": relocation.width,
                    "preferred_value": relocation.preferred_value,
                })
        write_stage_b_native_engine_package(
            state_machine=Path(args.state_machine),
            entry_rva=args.entry_rva,
            callback_targets=callback_targets,
            import_iat_vas=import_iat_vas,
            termination_import={
                "dll": args.termination_dll,
                "symbol": args.termination_symbol,
                "disposition": "terminates",
            },
            base_relocation_evidence={
                "format": "stage-b-pe32-base-relocation-evidence-v1",
                "complete": contract.completeness.complete,
                "pe_sha256": contract.identity.pe_sha256,
                "reference_contract_sha256": sha256_file(reference_path),
                "image_base": contract.identity.preferred_base,
                "relocations": relocation_rows,
            },
            out=Path(args.out),
        )


    def native_runtime(args):
        write_stage_b_native_runtime_package(
            interpreter_package=Path(args.interpreter_package),
            native_engine_package=Path(args.native_engine_package),
            out=Path(args.out),
        )


    def candidate(args):
        build_stage_b_interpreter_native_candidate(
            interpreter_package=Path(args.interpreter_package),
            native_engine_package=Path(args.native_engine_package),
            native_runtime_package=Path(args.native_runtime_package),
            load_image_contract=Path(args.load_image_contract),
            compiler=args.compiler,
            out_dir=Path(args.out),
        )


    parser = argparse.ArgumentParser()
    commands = parser.add_subparsers(required=True)
    for name, function in (("smoke", smoke), ("static-export", static_export)):
        command = commands.add_parser(name)
        command.add_argument("--original", required=True)
        command.add_argument("--linker-map", required=True)
        command.add_argument("--out", required=True)
        command.set_defaults(function=function)
    command = commands.add_parser("interpreter")
    command.add_argument("--state-machine", required=True)
    command.add_argument("--out", required=True)
    command.set_defaults(function=interpreter)
    command = commands.add_parser("native-engine")
    command.add_argument("--state-machine", required=True)
    command.add_argument("--entry-rva", type=lambda value: int(value, 0), required=True)
    command.add_argument("--load-image-contract", required=True)
    command.add_argument("--reference-contract", required=True)
    command.add_argument("--termination-profile", required=True)
    command.add_argument("--termination-dll", required=True)
    command.add_argument("--termination-symbol", required=True)
    command.add_argument("--out", required=True)
    command.set_defaults(function=native_engine)
    command = commands.add_parser("native-runtime")
    command.add_argument("--interpreter-package", required=True)
    command.add_argument("--native-engine-package", required=True)
    command.add_argument("--out", required=True)
    command.set_defaults(function=native_runtime)
    command = commands.add_parser("candidate")
    command.add_argument("--interpreter-package", required=True)
    command.add_argument("--native-engine-package", required=True)
    command.add_argument("--native-runtime-package", required=True)
    command.add_argument("--load-image-contract", required=True)
    command.add_argument("--compiler", required=True)
    command.add_argument("--out", required=True)
    command.set_defaults(function=candidate)
    arguments = parser.parse_args()
    arguments.function(arguments)
  '';
  commonInputs = [ pythonEnv pkgs.jq pkgs.coreutils ];
  commonEnvironment = pythonSource: ''
    export PYTHONPATH=${pythonSource}/src
    export PYTHONHASHSEED=0
    export LC_ALL=C.UTF-8
    export SOURCE_DATE_EPOCH=1
  '';
  mkPhaseWithSource = pythonSource: name: nativeBuildInputs: script:
    pkgs.runCommand name {
      nativeBuildInputs = commonInputs ++ nativeBuildInputs;
      preferLocalBuild = false;
      allowSubstitutes = true;
      __contentAddressed = true;
    } ''
      set -euo pipefail
      ${commonEnvironment pythonSource}
      ${script}
    '';
  runtimePhaseNames = [
    "stage-a-gnu-hello-roundtrip-smoke"
    "stage-a-gnu-hello-roundtrip-static-export"
    "stage-b-gnu-hello-roundtrip-interpreter"
    "stage-b-gnu-hello-roundtrip-native-engine"
    "stage-b-gnu-hello-roundtrip-native-runtime"
    "stage-b-gnu-hello-roundtrip-candidate"
  ];
  mkPhase = name: nativeBuildInputs: script:
    mkPhaseWithSource
      (if builtins.elem name runtimePhaseNames
       then runtimePythonSource
       else roundTripPythonSource)
      name nativeBuildInputs script;

  smoke = mkPhase "stage-a-gnu-hello-roundtrip-smoke" [] ''
    ${python} ${runtimeDriver} smoke \
      --original ${originalPe} \
      --linker-map ${originalMap} \
      --out "$out"
    jq -e '
      .format == "stage-a-gnu-hello-roundtrip-smoke-v1" and
      .status == "pass" and .static_only and
      (.executes_original_binary | not) and
      (.executes_candidate_binary | not) and
      .original.machine == "i386" and .original.bitness == 32
    ' "$out/smoke.json" >/dev/null
  '';

  staticExport = mkPhase "stage-a-gnu-hello-roundtrip-static-export" [] ''
    ${python} ${runtimeDriver} static-export \
      --original ${originalPe} \
      --linker-map ${originalMap} \
      --out "$out"
    jq -e '
      .phase == "static-export" and .status == "ready" and
      (.executes_original_binary | not) and
      (.executes_candidate_binary | not) and
      .counts.transfers > 0
    ' "$out/phase-manifest.json" >/dev/null
  '';

  interpreter = mkPhase "stage-b-gnu-hello-roundtrip-interpreter" [] ''
    ${python} ${runtimeDriver} interpreter \
      --state-machine ${staticExport}/state-machine.jsonl \
      --out "$out"
    jq -e '
      .format == "stage-b-semantic-interpreter-package-v1" and
      .status == "ready" and .counts.blocked_transfers == 0 and
      .counts.input_transfers == .counts.transfers
    ' "$out/state-machine-interpreter-package.json" >/dev/null
  '';

  nativeEngine = mkPhase "stage-b-gnu-hello-roundtrip-native-engine" [] ''
    entry_rva="$(jq -r .identity.entry_rva ${staticExport}/load-image-contract.json)"
    ${python} ${runtimeDriver} native-engine \
      --state-machine ${staticExport}/state-machine.jsonl \
      --entry-rva "$entry_rva" \
      --load-image-contract ${staticExport}/load-image-contract.json \
      --reference-contract ${staticExport}/reference-contract.json \
      --termination-profile \
        ${machineRuntimeProfileSource}/pe32-msvcrt-lockstep-v1.json \
      --termination-dll msvcrt.dll \
      --termination-symbol _amsg_exit \
      --out "$out"
    jq -e '
      .format == "stage-b-native-engine-package-v1" and
      .status == "ready" and .counts.blockers == 0
    ' "$out/native-engine-package.json" >/dev/null
  '';

  nativeRuntime = mkPhase "stage-b-gnu-hello-roundtrip-native-runtime" [] ''
    ${python} ${runtimeDriver} native-runtime \
      --interpreter-package ${interpreter} \
      --native-engine-package ${nativeEngine} \
      --out "$out"
    jq -e '
      .format == "stage-b-native-runtime-package-v1" and .status == "ready"
    ' "$out/native-runtime-package.json" >/dev/null
  '';

  candidate = mkPhase "stage-b-gnu-hello-roundtrip-candidate" [
    mingw32.stdenv.cc
    mingw32.binutils
  ] ''
    ${python} ${runtimeDriver} candidate \
      --interpreter-package ${interpreter} \
      --native-engine-package ${nativeEngine} \
      --native-runtime-package ${nativeRuntime} \
      --load-image-contract ${staticExport}/load-image-contract.json \
      --compiler ${compiler} \
      --out "$out"
    jq -e '
      .format == "stage-b-interpreter-native-build-v1" and
      .status == "candidate-generated"
    ' "$out/interpreter-native-build-manifest.json" >/dev/null
    test -s "$out/candidate.exe"
    test -s "$out/payload.map"
  '';

  # This phase binds the canonical entry/TLS source inventory to the exact
  # candidate bytes.  It remains diagnostic until finite wrapper routes and
  # their named Lean binding to launch_chunk are generated.
  nativeLaunchRequest = mkPhase
    "stage-a-gnu-hello-roundtrip-native-launch-request" [] ''
    ${python} ${driver} native-launch-request \
      --candidate ${candidate}/candidate.exe \
      --out "$out"
    jq -e '
      .format == "stage-a-native-launch-route-request-v1" and
      .status == "incomplete" and
      (.acceptance_authority | not) and
      (.canonical_sources | length) > 0 and
      (.missing_inputs | length) > 0
    ' "$out/native-launch-route-request.json" >/dev/null
    test "$(jq -r .candidate_sha256 \
      "$out/native-launch-route-request.json")" = \
      "$(sha256sum ${candidate}/candidate.exe | cut -d ' ' -f1)"
  '';

  engineSegments = mkPhase "stage-a-gnu-hello-roundtrip-engine-segments" [] ''
    cutpoint_args=()
    while IFS= read -r rva; do
      cutpoint_args+=(--product-cutpoint "$rva")
    done < <(jq -r '
      .identity.entry_rva,
      (.tls.callbacks[]?.rva)
    ' ${staticExport}/load-image-contract.json)
    segment_status=0
    ${python} -m spaghetti_extractor stage-a-generate-engine-segments \
      --semantic-transfers ${staticExport}/state-machine.jsonl \
      --interpreter-program ${interpreter}/state-machine-interpreter-program.json \
      --interpreter-package ${interpreter}/state-machine-interpreter-package.json \
      --candidate ${candidate}/candidate.exe \
      --linker-map ${candidate}/payload.map \
      --engine-layout ${candidate}/engine-layout.bin \
      --kernel-callback-plan \
        ${kernelCallbackLean}/interpreter-kernel-callback-plan.json \
      "''${cutpoint_args[@]}" \
      --out "$out/engine-segments.json" || segment_status=$?
    test "$segment_status" -eq 1
    jq -e '
      .format == "stage-a-engine-segment-evidence-v1" and
      .status == "incomplete" and
      (.acceptance_authority | not) and
      (.transfers | length) > 0 and
      (.proof_obligations | length) > 0
    ' "$out/engine-segments.json" >/dev/null
    ${python} - "$out/phase-manifest.json" <<'PY'
    import json, pathlib, sys
    pathlib.Path(sys.argv[1]).write_text(json.dumps({
      "format": "stage-a-gnu-hello-roundtrip-phase-v1",
      "phase": "engine-segments",
      "status": "evidence-ready",
      "executes_original_binary": False,
      "executes_candidate_binary": False,
    }, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    PY
  '';

  nativeLaunchGraphLean = mkPhaseWithSource nativeLaunchGraphPythonSource
    "stage-a-gnu-hello-roundtrip-native-launch-graph-lean" [] ''
    ${python} ${nativeLaunchGraphDriver} \
      --candidate ${candidate}/candidate.exe \
      --linker-map ${candidate}/payload.map \
      --native-engine-plan ${nativeEngine}/native-engine-plan.json \
      --engine-segments ${engineSegments}/engine-segments.json \
      --out "$out"
    jq -e '
      .format == "stage-a-gnu-hello-native-launch-graph-v1" and
      .phase == "native-launch-graph" and
      .status == "source-ready" and
      (.acceptance_authority | not) and
      (.executes_original_binary | not) and
      (.executes_candidate_binary | not) and
      .counts.canonical_roots == 3 and
      .counts.cutpoints == 6 and
      .counts.routes == 7 and
      .counts.decoded_nodes > 0 and
      .failure_mode == "incomplete"
    ' "$out/phase-manifest.json" >/dev/null
    test -s "$out/native-launch-graph-artifact-binding.json"
    test -s "$out/interpreter-native-launch-graph-plan.json"
    test -s \
      "$out/StageA/GeneratedRelationalInterpreterNativeLaunchGraph.lean"
  '';

  nativeLaunchGraphProofSources = mkPhase
    "stage-a-gnu-hello-roundtrip-native-launch-graph-proof-sources" [] ''
    ${aggregatePython} ${proofSourceAggregateDriver} \
      --source ${leanSourceRoot} \
      --source ${nativeLaunchGraphLean} \
      --target GeneratedRelationalInterpreterNativeLaunchGraph \
      --out "$out"
  '';
  nativeLaunchGraphProofModules = builtins.fromJSON (
    builtins.readFile
      "${nativeLaunchGraphProofSources}/standalone-modules.json"
  );
  nativeLaunchGraphProofResources = builtins.fromJSON (
    builtins.readFile
      "${nativeLaunchGraphProofSources}/module-resources.json"
  );
  nativeLaunchGraphProof = mkLeanGraph {
    inherit pkgs;
    contentAddressed = true;
    standaloneSourceRoot = nativeLaunchGraphProofSources + "/StageA";
    standaloneModules = nativeLaunchGraphProofModules;
    standaloneModuleResources = nativeLaunchGraphProofResources;
    targetNodes = [ "GeneratedRelationalInterpreterNativeLaunchGraph" ];
    targetBundle = true;
    targetAxiomAudit = {
      module = "GeneratedRelationalInterpreterNativeLaunchGraph";
      declaration =
        "StageA.GeneratedRelational.InterpreterNativeLaunchGraph.generatedNativeLaunchGraphStaticChecked";
      approved_axioms = [ "propext" "Classical.choice" "Quot.sound" ];
    };
  };

  originalPeLean = mkPhase "stage-a-gnu-hello-roundtrip-original-pe-lean" [] ''
    ${python} ${driver} original-pe-source \
      --original ${originalPe} --out "$out"
  '';

  staticMachineImportContractsLean = mkPhase
    "stage-a-gnu-hello-roundtrip-static-machine-import-contracts-lean" [] ''
    ${python} ${driver} static-machine-import-contracts \
      --original ${originalPe} \
      --reference-contract ${staticExport}/reference-contract.json \
      --state-machine ${staticExport}/state-machine.jsonl \
      --load-image-contract ${staticExport}/load-image-contract.json \
      --profile ${machineRuntimeProfile} \
      --profile \
        ${machineRuntimeProfileSource}/pe32-kernel32-lockstep-v1.json \
      --profile \
        ${machineRuntimeProfileSource}/pe32-msvcrt-lockstep-v1.json \
      --shard-size 128 \
      --out "$out"
    jq -e '
      .phase == "rooted-static-machine-import-contracts" and
      .status == "source-ready" and
      (.proof_authority | not) and
      .plan_format == "stage-a-static-machine-import-contracts-v1" and
      .public_outputs.report == "machine-import-contract-report.json" and
      .public_outputs.lean_module ==
        "StageA/GeneratedStaticMachineImportContracts.lean" and
      .targets == ["GeneratedStaticMachineImportContracts"] and
      .rooted_counts.reachable_targets > 0 and
      .rooted_counts.required_imports > 0 and
      .rooted_counts.boundaries > 0 and
      .rooted_counts.blockers == 0
    ' "$out/phase-manifest.json" >/dev/null
    test -s "$out/machine-import-contract-report.json"
    test -s "$out/StageA/GeneratedStaticMachineImportContracts.lean"
  '';

  universalPairedExternalEnvironmentLean = mkPhase
    "stage-a-gnu-hello-roundtrip-universal-paired-external-environment-lean" [] ''
    ${python} ${universalPairedExternalEnvironmentDriver} \
      --original ${originalPe} \
      --candidate ${candidate}/candidate.exe \
      --machine-import-report \
        ${staticMachineImportContractsLean}/machine-import-contract-report.json \
      --out "$out"
    jq -e '
      .phase == "universal-paired-external-environment" and
      .status == "source-ready" and
      (.proof_authority | not) and
      (.executes_original_binary | not) and
      (.executes_candidate_binary | not) and
      (.counts.required_imports > 0) and
      (.counts.machine_contracts > 0) and
      (.counts.candidate_pe_byte_packs > 0) and
      (.proved_by_generated_terms | index(
        "normalized_import_inventories_equal") != null) and
      (.remaining_premises | index(
        "each_returning_site_has_a_universally_sound_response_relation") != null) and
      .targets == ["GeneratedGnuHelloUniversalPairedExternalEnvironment"]
    ' "$out/phase-manifest.json" >/dev/null
    test -s "$out/universal-paired-external-environment.json"
    test -s \
      "$out/StageA/GeneratedGnuHelloUniversalPairedExternalEnvironment.lean"
    test -s "$out/StageA/GeneratedGnuHelloExternalCandidatePE.lean"
  '';

  staticMachineImportProofSources = mkPhase
    "stage-a-gnu-hello-roundtrip-static-machine-import-proof-sources" [] ''
    ${aggregatePython} ${proofSourceAggregateDriver} \
      --source ${leanSourceRoot} \
      --source ${originalPeLean} \
      --source ${staticMachineImportContractsLean} \
      --target GeneratedStaticMachineImportContracts \
      --out "$out"
  '';
  staticMachineImportProofModules = builtins.fromJSON (
    builtins.readFile
      "${staticMachineImportProofSources}/standalone-modules.json"
  );
  staticMachineImportProofResources = builtins.fromJSON (
    builtins.readFile
      "${staticMachineImportProofSources}/module-resources.json"
  );
  staticMachineImportProof = mkLeanGraph {
    inherit pkgs;
    contentAddressed = true;
    standaloneSourceRoot = staticMachineImportProofSources + "/StageA";
    standaloneModules = staticMachineImportProofModules;
    standaloneModuleResources = staticMachineImportProofResources;
    targetNodes = [ "GeneratedStaticMachineImportContracts" ];
    targetBundle = true;
  };

  mixedOriginalDiagnostic = mkPhase
    "stage-a-gnu-hello-roundtrip-mixed-original-diagnostic" [] ''
    ${python} ${diagnosticDriver} \
      --driver ${driver} \
      --original ${originalPe} \
      --reference-contract ${staticExport}/reference-contract.json \
      --state-machine ${staticExport}/state-machine.jsonl \
      --load-image-contract ${staticExport}/load-image-contract.json \
      --machine-import-report \
        ${staticMachineImportContractsLean}/machine-import-contract-report.json \
      --callable-resolver-profile \
        ${machineRuntimeProfileSource}/pe32-kernel32-callable-resolvers-v1.json \
      --shard-size 128 \
      --out "$out"
    jq -e '
      .phase == "mixed-original-diagnostic" and
      (.status == "ready" or .status == "incomplete") and
      (.proof_authority | not) and
      .authorizing_term == null and
      .public_outputs.report == "interpreter-mixed-original-plan.json" and
      .counts.regions > 0 and .counts.reachable_targets > 0
    ' "$out/phase-manifest.json" >/dev/null
    test -s "$out/interpreter-mixed-original-plan.json"
  '';

  mixedOriginalBaseLean = mkPhase
    "stage-a-gnu-hello-roundtrip-mixed-original-base-lean" [] ''
    ${python} ${driver} mixed-original-base \
      --original ${originalPe} \
      --reference-contract ${staticExport}/reference-contract.json \
      --state-machine ${staticExport}/state-machine.jsonl \
      --load-image-contract ${staticExport}/load-image-contract.json \
      --machine-import-report \
        ${staticMachineImportContractsLean}/machine-import-contract-report.json \
      --callable-resolver-profile \
        ${machineRuntimeProfileSource}/pe32-kernel32-callable-resolvers-v1.json \
      --shard-size 128 \
      --out "$out"
    jq -e '
      .phase == "mixed-original-base-lean" and
      .status == "base-source-ready" and
      (.proof_authority | not) and
      (.exact_reachability_emitted | not) and
      .targets == ["GeneratedRelationalInterpreterMixedOriginalBase"] and
      .counts.regions > 0 and
      .counts.reachable_targets > 0
    ' "$out/phase-manifest.json" >/dev/null
    test -s \
      "$out/StageA/GeneratedRelationalInterpreterMixedOriginalBase.lean"
    test -s "$out/interpreter-mixed-original-base-plan.json"
    test -s "$out/module-resources.json"
    jq -e '
      .GeneratedRelationalInterpreterMixedOriginalBase.resource_class ==
        "light" and
      .GeneratedRelationalInterpreterMixedOriginalBase.estimated_memory_mb <=
        1024 and
      ([to_entries[]
        | select(.key
          | startswith(
              "GeneratedRelationalInterpreterMixedOriginalBaseCertificateShard"
            ))
        | .value.estimated_memory_mb]
        | length > 0 and all(. <= 8192))
    ' "$out/module-resources.json" >/dev/null
  '';

  mixedOriginalWritableSlotAuthorityLean = mkPhase
    "stage-a-gnu-hello-roundtrip-mixed-original-writable-slot-authority-lean" [] ''
    ${python} ${driver} mixed-original-writable-slot-authority \
      --original ${originalPe} \
      --reference-contract ${staticExport}/reference-contract.json \
      --state-machine ${staticExport}/state-machine.jsonl \
      --load-image-contract ${staticExport}/load-image-contract.json \
      --machine-import-report \
        ${staticMachineImportContractsLean}/machine-import-contract-report.json \
      --callable-resolver-profile \
        ${machineRuntimeProfileSource}/pe32-kernel32-callable-resolvers-v1.json \
      --base-plan \
        ${mixedOriginalBaseLean}/interpreter-mixed-original-base-plan.json \
      --shard-size 128 \
      --out "$out"
    jq -e '
      .phase == "mixed-original-writable-slot-authority-lean" and
      .status == "source-ready" and
      (.proof_authority | not) and
      .failure_mode == "incomplete" and
      .report_format ==
        "stage-a-relocated-writable-static-pointer-slot-authorities-v2" and
      .counts.authority_terms > 0 and
      .counts.authority_proposal_blockers == 0 and
      .counts.decomposed_adapters == .counts.authority_terms and
      .counts.blockers_before ==
        (.counts.blockers_after + .counts.authority_terms) and
      (.authorizing_lean_terms | length) == .counts.authority_terms and
      (.adapter_terms | length) == .counts.authority_terms and
      .public_outputs.authority_report ==
        "relocated-writable-static-pointer-slot-authorities.json" and
      .public_outputs.base_plan ==
        "interpreter-mixed-original-base-plan.json" and
      .targets == ["GeneratedRelationalInterpreterMixedOriginalBase"]
    ' "$out/phase-manifest.json" >/dev/null
    jq -e '
      .format ==
        "stage-a-relocated-writable-static-pointer-slot-authorities-v2" and
      (.artifact_role.acceptance_authority | not) and
      .artifact_role.lean_checker_must_reparse_and_redecode and
      .artifact_role.proposal_only and
      .counts.authority_terms > 0 and
      .counts.mixed_original_blockers_before ==
        (.counts.potential_mixed_original_blockers_after +
          .counts.authority_terms) and
      (.sites | length) == .counts.authority_terms
    ' \
      "$out/relocated-writable-static-pointer-slot-authorities.json" \
      >/dev/null
    test -s \
      "$out/StageA/GeneratedRelationalInterpreterMixedOriginalBase.lean"
    test -s "$out/interpreter-mixed-original-base-plan.json"
    test -s "$out/direct-call-proposal-ir.json"
    test -s "$out/original-cutpoint-graph-ir.json"
    test -s "$out/module-resources.json"
  '';

  mixedOriginalRegisterIndirectAuthorityLean = mkPhase
    "stage-a-gnu-hello-roundtrip-mixed-original-register-indirect-authority-lean" [] ''
    ${python} ${driver} mixed-original-register-indirect-authority \
      --original ${originalPe} \
      --reference-contract ${staticExport}/reference-contract.json \
      --state-machine ${staticExport}/state-machine.jsonl \
      --load-image-contract ${staticExport}/load-image-contract.json \
      --machine-import-report \
        ${staticMachineImportContractsLean}/machine-import-contract-report.json \
      --callable-resolver-profile \
        ${machineRuntimeProfileSource}/pe32-kernel32-callable-resolvers-v1.json \
      --writable-slot-authority-report \
        ${mixedOriginalWritableSlotAuthorityLean}/relocated-writable-static-pointer-slot-authorities.json \
      --base-plan \
        ${mixedOriginalWritableSlotAuthorityLean}/interpreter-mixed-original-base-plan.json \
      --shard-size 128 \
      --out "$out"
    jq -e '
      .phase == "mixed-original-register-indirect-authority-lean" and
      .status == "source-ready" and
      (.proof_authority | not) and
      .runtime_closure_required and
      (.report_status_is_authority | not) and
      .counts.static_authority_terms > 0 and
      .counts.proposal_blockers == 0 and
      .counts.register_frontiers_partitioned ==
        .counts.static_authority_terms and
      .counts.runtime_frontiers_remaining ==
        .counts.register_frontiers_partitioned and
      .counts.nonregister_frontiers > 0 and
      .targets == ["GeneratedRegisterIndirectControlAuthorities"]
    ' "$out/phase-manifest.json" >/dev/null
    jq -e '
      .format == "stage-a-register-indirect-control-authorities-v1" and
      (.artifact_role.acceptance_authority | not) and
      .artifact_role.lean_checker_must_reparse_and_redecode and
      .artifact_role.proposal_only and
      (.sites | length) > 0 and
      .counts.register_sites_unresolved == 0 and
      .counts.untouched_nonregister_blockers > 0
    ' "$out/register-indirect-control-authorities.json" >/dev/null
    test -s \
      "$out/StageA/GeneratedRegisterIndirectControlAuthorities.lean"
    test -s "$out/module-resources.json"
  '';

  mixedOriginalRegisterIndirectAuthorityProofSources = mkPhase
    "stage-a-gnu-hello-roundtrip-mixed-original-register-indirect-authority-proof-sources" [] ''
    ${aggregatePython} ${proofSourceAggregateDriver} \
      --source ${leanSourceRoot} \
      --source ${originalPeLean} \
      --source ${staticMachineImportContractsLean} \
      --source ${mixedOriginalWritableSlotAuthorityLean} \
      --source ${mixedOriginalRegisterIndirectAuthorityLean} \
      --target GeneratedRegisterIndirectControlAuthorities \
      --out "$out"
  '';
  mixedOriginalRegisterIndirectAuthorityProofModules = builtins.fromJSON (
    builtins.readFile
      "${mixedOriginalRegisterIndirectAuthorityProofSources}/standalone-modules.json"
  );
  mixedOriginalRegisterIndirectAuthorityProofResources = builtins.fromJSON (
    builtins.readFile
      "${mixedOriginalRegisterIndirectAuthorityProofSources}/module-resources.json"
  );
  mixedOriginalRegisterIndirectAuthorityProof = mkLeanGraph {
    inherit pkgs;
    contentAddressed = true;
    standaloneSourceRoot =
      mixedOriginalRegisterIndirectAuthorityProofSources + "/StageA";
    standaloneModules = mixedOriginalRegisterIndirectAuthorityProofModules;
    standaloneModuleResources =
      mixedOriginalRegisterIndirectAuthorityProofResources;
    targetNodes = [
      "GeneratedRegisterIndirectControlAuthorities"
      "GeneratedRelationalInterpreterMixedOriginalBase"
    ];
    targetBundle = true;
  };

  mixedOriginalDirectCallProposalsLean = mkPhaseWithSource
    directCallProposalPythonSource
    "stage-a-gnu-hello-roundtrip-mixed-original-direct-call-proposals" [] ''
    ${python} ${driver} mixed-original-direct-call-proposals \
      --original ${originalPe} \
      --reference-contract ${staticExport}/reference-contract.json \
      --state-machine ${staticExport}/state-machine.jsonl \
      --load-image-contract ${staticExport}/load-image-contract.json \
      --machine-import-report \
        ${staticMachineImportContractsLean}/machine-import-contract-report.json \
      --callable-resolver-profile \
        ${machineRuntimeProfileSource}/pe32-kernel32-callable-resolvers-v1.json \
      --register-indirect-authority-report \
        ${mixedOriginalRegisterIndirectAuthorityLean}/register-indirect-control-authorities.json \
      --writable-slot-authority-report \
        ${mixedOriginalWritableSlotAuthorityLean}/relocated-writable-static-pointer-slot-authorities.json \
      --base-plan \
        ${mixedOriginalWritableSlotAuthorityLean}/interpreter-mixed-original-base-plan.json \
      --proposal-ir \
        ${mixedOriginalWritableSlotAuthorityLean}/direct-call-proposal-ir.json \
      --runtime-value-carry-hints \
        ${./gnu-hello-stack-dynamic-hints.json} \
      --shard-size 128 \
      --out "$out"
    jq -e '
      .phase == "mixed-original-direct-call-proposals" and
      .status == "proposal-source-ready" and
      (.proof_authority | not)
    ' "$out/phase-manifest.json" >/dev/null
    jq -e '
      .format == "stage-a-mixed-original-direct-call-proposals-v1" and
      (.authority.standalone_acceptance_authority | not) and
      .authority.authorizing_lean_term == null
    ' "$out/internal-direct-call-summary-proposals.json" >/dev/null
  '';
  mixedOriginalDirectCallProposalTargets =
    (builtins.fromJSON (builtins.readFile
      "${mixedOriginalDirectCallProposalsLean}/phase-manifest.json")).modules;
  mixedOriginalDirectCallProposalTargetArgs = builtins.concatStringsSep " " (
    map (module: "--target ${pkgs.lib.escapeShellArg module}")
      mixedOriginalDirectCallProposalTargets
  );
  mixedOriginalDirectCallProposalProofSources = mkPhase
    "stage-a-gnu-hello-roundtrip-mixed-original-direct-call-proposal-proof-sources" [] ''
    ${aggregatePython} ${proofSourceAggregateDriver} \
      --source ${leanSourceRoot} \
      --source ${originalPeLean} \
      --source ${staticMachineImportContractsLean} \
      --source ${mixedOriginalWritableSlotAuthorityLean} \
      --source ${mixedOriginalDirectCallProposalsLean} \
      ${mixedOriginalDirectCallProposalTargetArgs} \
      --explicit-targets-only \
      --target-closure-only \
      --out "$out"
  '';
  mixedOriginalDirectCallProposalProofModules = builtins.fromJSON (
    builtins.readFile
      "${mixedOriginalDirectCallProposalProofSources}/standalone-modules.json"
  );
  mixedOriginalDirectCallProposalProofResources = builtins.fromJSON (
    builtins.readFile
      "${mixedOriginalDirectCallProposalProofSources}/module-resources.json"
  );
  mixedOriginalDirectCallProposalProof = mkLeanGraph {
    inherit pkgs;
    contentAddressed = true;
    standaloneSourceRoot =
      mixedOriginalDirectCallProposalProofSources + "/StageA";
    standaloneModules = mixedOriginalDirectCallProposalProofModules;
    standaloneModuleResources =
      mixedOriginalDirectCallProposalProofResources;
    targetNodes = mixedOriginalDirectCallProposalTargets;
    targetBundle = true;
  };

  mixedOriginalDirectCallSemanticsLean = mkPhaseWithSource
    directCallSemanticsPythonSource
    "stage-a-gnu-hello-roundtrip-mixed-original-direct-call-semantics" [] ''
    ${python} ${directCallSemanticsDriver} \
      --original ${originalPe} \
      --state-machine ${staticExport}/state-machine.jsonl \
      --proposal-report \
        ${mixedOriginalDirectCallProposalsLean}/internal-direct-call-summary-proposals.json \
      --out "$out"
    jq -e '
      .phase == "mixed-original-direct-call-semantics" and
      (.proof_authority | not) and
      (.status == "semantic-terms-ready" or
        .status == "semantic-premises-pending")
    ' "$out/phase-manifest.json" >/dev/null
    jq -e '
      .format == "stage-a-mixed-original-direct-call-authority-bindings-v2" and
      (.report_authority | not) and
      .authority_source == "named Lean terms only"
    ' "$out/direct-call-authority-bindings.json" >/dev/null
  '';
  mixedOriginalDirectCallSemanticsTargets =
    (builtins.fromJSON (builtins.readFile
      "${mixedOriginalDirectCallSemanticsLean}/phase-manifest.json")).modules;
  mixedOriginalDirectCallSemanticsTargetArgs =
    builtins.concatStringsSep " " (
      map (module: "--target ${pkgs.lib.escapeShellArg module}")
        mixedOriginalDirectCallSemanticsTargets
    );
  mixedOriginalDirectCallSemanticsProofSources = mkPhase
    "stage-a-gnu-hello-roundtrip-mixed-original-direct-call-semantics-proof-sources" [] ''
    ${aggregatePython} ${proofSourceAggregateDriver} \
      --source ${leanSourceRoot} \
      --source ${originalPeLean} \
      --source ${staticMachineImportContractsLean} \
      --source ${mixedOriginalWritableSlotAuthorityLean} \
      --source ${mixedOriginalDirectCallProposalsLean} \
      --source ${mixedOriginalDirectCallSemanticsLean} \
      ${mixedOriginalDirectCallSemanticsTargetArgs} \
      --explicit-targets-only \
      --target-closure-only \
      --out "$out"
  '';
  mixedOriginalDirectCallSemanticsProofModules = builtins.fromJSON (
    builtins.readFile
      "${mixedOriginalDirectCallSemanticsProofSources}/standalone-modules.json"
  );
  mixedOriginalDirectCallSemanticsProofResources = builtins.fromJSON (
    builtins.readFile
      "${mixedOriginalDirectCallSemanticsProofSources}/module-resources.json"
  );
  mixedOriginalDirectCallSemanticsProof = mkLeanGraph {
    inherit pkgs;
    contentAddressed = true;
    standaloneSourceRoot =
      mixedOriginalDirectCallSemanticsProofSources + "/StageA";
    standaloneModules = mixedOriginalDirectCallSemanticsProofModules;
    standaloneModuleResources =
      mixedOriginalDirectCallSemanticsProofResources;
    targetNodes = mixedOriginalDirectCallSemanticsTargets;
    targetBundle = true;
  };

  # A later round may use only already Lean-checked call summaries to recover
  # additional finite-origin call entries.  Keeping the round explicit in the
  # derivation DAG makes every new authority and its invalidation closure
  # independently content-addressable.
  mixedOriginalDirectCallClosureProposalsLean = mkPhaseWithSource
    directCallProposalPythonSource
    "stage-a-gnu-hello-roundtrip-mixed-original-direct-call-closure-proposals" [] ''
    ${python} ${driver} mixed-original-direct-call-proposals \
      --original ${originalPe} \
      --reference-contract ${staticExport}/reference-contract.json \
      --state-machine ${staticExport}/state-machine.jsonl \
      --load-image-contract ${staticExport}/load-image-contract.json \
      --machine-import-report \
        ${staticMachineImportContractsLean}/machine-import-contract-report.json \
      --callable-resolver-profile \
        ${machineRuntimeProfileSource}/pe32-kernel32-callable-resolvers-v1.json \
      --register-indirect-authority-report \
        ${mixedOriginalRegisterIndirectAuthorityLean}/register-indirect-control-authorities.json \
      --writable-slot-authority-report \
        ${mixedOriginalWritableSlotAuthorityLean}/relocated-writable-static-pointer-slot-authorities.json \
      --base-plan \
        ${mixedOriginalWritableSlotAuthorityLean}/interpreter-mixed-original-base-plan.json \
      --proposal-ir \
        ${mixedOriginalWritableSlotAuthorityLean}/direct-call-proposal-ir.json \
      --prior-direct-call-authority-report \
        ${mixedOriginalDirectCallSemanticsLean}/direct-call-authority-bindings.json \
      --runtime-value-carry-hints \
        ${./gnu-hello-stack-dynamic-hints.json} \
      --shard-size 128 \
      --out "$out"
    jq -e '
      .phase == "mixed-original-direct-call-proposals" and
      .status == "proposal-source-ready" and
      (.proof_authority | not) and
      .counts.recovered_finite_origin_entry_authorities > 0
    ' "$out/phase-manifest.json" >/dev/null
  '';
  mixedOriginalDirectCallClosureProposalTargets =
    (builtins.fromJSON (builtins.readFile
      "${mixedOriginalDirectCallClosureProposalsLean}/phase-manifest.json")).modules;
  mixedOriginalDirectCallClosureProposalTargetArgs =
    builtins.concatStringsSep " " (
      map (module: "--target ${pkgs.lib.escapeShellArg module}")
        mixedOriginalDirectCallClosureProposalTargets
    );
  mixedOriginalDirectCallClosureProposalProofSources = mkPhase
    "stage-a-gnu-hello-roundtrip-mixed-original-direct-call-closure-proposal-proof-sources" [] ''
    ${aggregatePython} ${proofSourceAggregateDriver} \
      --source ${leanSourceRoot} \
      --source ${originalPeLean} \
      --source ${staticMachineImportContractsLean} \
      --source ${mixedOriginalWritableSlotAuthorityLean} \
      --source ${mixedOriginalDirectCallProposalsLean} \
      --source ${mixedOriginalDirectCallSemanticsLean} \
      --source ${mixedOriginalDirectCallClosureProposalsLean} \
      ${mixedOriginalDirectCallClosureProposalTargetArgs} \
      --explicit-targets-only \
      --target-closure-only \
      --out "$out"
  '';
  mixedOriginalDirectCallClosureProposalProofModules =
    builtins.fromJSON (builtins.readFile
      "${mixedOriginalDirectCallClosureProposalProofSources}/standalone-modules.json");
  mixedOriginalDirectCallClosureProposalProofResources =
    builtins.fromJSON (builtins.readFile
      "${mixedOriginalDirectCallClosureProposalProofSources}/module-resources.json");
  mixedOriginalDirectCallClosureProposalProof = mkLeanGraph {
    inherit pkgs;
    contentAddressed = true;
    standaloneSourceRoot =
      mixedOriginalDirectCallClosureProposalProofSources + "/StageA";
    standaloneModules = mixedOriginalDirectCallClosureProposalProofModules;
    standaloneModuleResources =
      mixedOriginalDirectCallClosureProposalProofResources;
    targetNodes = mixedOriginalDirectCallClosureProposalTargets;
    targetBundle = true;
  };

  mixedOriginalDirectCallClosureSemanticsLean = mkPhaseWithSource
    directCallSemanticsPythonSource
    "stage-a-gnu-hello-roundtrip-mixed-original-direct-call-closure-semantics" [] ''
    ${python} ${directCallSemanticsDriver} \
      --original ${originalPe} \
      --state-machine ${staticExport}/state-machine.jsonl \
      --proposal-report \
        ${mixedOriginalDirectCallClosureProposalsLean}/internal-direct-call-summary-proposals.json \
      --out "$out"
    jq -e '
      .phase == "mixed-original-direct-call-semantics" and
      .status == "semantic-terms-ready" and
      (.proof_authority | not) and
      .counts.remaining_semantic_frontiers == 0
    ' "$out/phase-manifest.json" >/dev/null
  '';
  mixedOriginalDirectCallClosureSemanticsTargets =
    (builtins.fromJSON (builtins.readFile
      "${mixedOriginalDirectCallClosureSemanticsLean}/phase-manifest.json")).modules;
  mixedOriginalDirectCallClosureSemanticsTargetArgs =
    builtins.concatStringsSep " " (
      map (module: "--target ${pkgs.lib.escapeShellArg module}")
        mixedOriginalDirectCallClosureSemanticsTargets
    );
  mixedOriginalDirectCallClosureSemanticsProofSources = mkPhase
    "stage-a-gnu-hello-roundtrip-mixed-original-direct-call-closure-semantics-proof-sources" [] ''
    ${aggregatePython} ${proofSourceAggregateDriver} \
      --source ${leanSourceRoot} \
      --source ${originalPeLean} \
      --source ${staticMachineImportContractsLean} \
      --source ${mixedOriginalWritableSlotAuthorityLean} \
      --source ${mixedOriginalDirectCallProposalsLean} \
      --source ${mixedOriginalDirectCallSemanticsLean} \
      --source ${mixedOriginalDirectCallClosureProposalsLean} \
      --source ${mixedOriginalDirectCallClosureSemanticsLean} \
      ${mixedOriginalDirectCallClosureSemanticsTargetArgs} \
      --explicit-targets-only \
      --target-closure-only \
      --out "$out"
  '';
  mixedOriginalDirectCallClosureSemanticsProofModules =
    builtins.fromJSON (builtins.readFile
      "${mixedOriginalDirectCallClosureSemanticsProofSources}/standalone-modules.json");
  mixedOriginalDirectCallClosureSemanticsProofResources =
    builtins.fromJSON (builtins.readFile
      "${mixedOriginalDirectCallClosureSemanticsProofSources}/module-resources.json");
  mixedOriginalDirectCallClosureSemanticsProof = mkLeanGraph {
    inherit pkgs;
    contentAddressed = true;
    standaloneSourceRoot =
      mixedOriginalDirectCallClosureSemanticsProofSources + "/StageA";
    standaloneModules = mixedOriginalDirectCallClosureSemanticsProofModules;
    standaloneModuleResources =
      mixedOriginalDirectCallClosureSemanticsProofResources;
    targetNodes = mixedOriginalDirectCallClosureSemanticsTargets;
    targetBundle = true;
  };

  # The register-authority report is already a finite exact inventory of every
  # call boundary that needs a preservation contract. Once the closure round
  # has one complete proposal and one named Lean authority per request, another
  # whole-PE analysis cannot discover an additional request. Preserve the old
  # public aliases while replacing that redundant analysis with a strict
  # hash-bound coverage check.
  mixedOriginalDirectCallFixedPointProposalsLean =
    mixedOriginalDirectCallClosureProposalsLean;
  mixedOriginalDirectCallFixedPointSemanticsLean =
    mixedOriginalDirectCallClosureSemanticsLean;
  mixedOriginalDirectCallFixedPointCheck = mkPhaseWithSource
    directCallFixedPointPythonSource
    "stage-a-gnu-hello-roundtrip-mixed-original-direct-call-fixed-point-check" [] ''
    ${python} ${directCallFixedPointDriver} \
      --proposal-report \
        ${mixedOriginalDirectCallClosureProposalsLean}/internal-direct-call-summary-proposals.json \
      --authority-report \
        ${mixedOriginalDirectCallClosureSemanticsLean}/direct-call-authority-bindings.json \
      --out "$out"
    jq -e '
      .format == "stage-a-direct-call-closure-fixed-point-v2" and
      .status == "satisfied" and
      (.proof_authority | not) and
      (.acceptance_authority | not) and
      .counts.remaining_frontiers == 0 and
      .counts.proposal_modules ==
        (.counts.ordinary_requests + .counts.finite_origin_requests) and
      .counts.semantic_contracts == .counts.proposal_modules
    ' "$out/direct-call-fixed-point.json" >/dev/null
  '';

  mixedOriginalStackDynamicAuthorityLean =
    mkPhaseWithSource stackDynamicAuthorityPythonSource
    "stage-a-gnu-hello-roundtrip-mixed-original-stack-dynamic-authority-lean" [] ''
    test -e ${mixedOriginalDirectCallFixedPointCheck}
    ${python} ${stackDynamicAuthorityDriver} \
      --original ${originalPe} \
      --state-machine ${staticExport}/state-machine.jsonl \
      --proof-input \
        ${mixedOriginalDirectCallFixedPointProposalsLean}/stack-dynamic-control-input.json \
      --cutpoint-graph \
        ${mixedOriginalDirectCallFixedPointProposalsLean}/original-cutpoint-graph-ir.json \
      --direct-call-authority \
        ${mixedOriginalDirectCallClosureSemanticsLean}/direct-call-authority-bindings.json \
      --hints ${stackDynamicHints} \
      --out "$out"
    jq -e '
      .phase == "mixed-original-stack-dynamic-authority-lean" and
      .status == "runtime-premises-required" and
      (.proof_authority | not) and
      (.report_status_is_authority | not) and
      .runtime_closure_required and
      .counts.sites == 3 and
      .counts.static_authorities == .counts.sites and
      .counts.runtime_premises_required == .counts.sites and
      .counts.stack_sites == 1 and
      .counts.indexed_table_sites == 1 and
      .counts.dynamic_callback_sites == 1
      and .counts.runtime_value_carry_routes == 1
      and .counts.runtime_value_carry_required_transfers == 1
    ' "$out/phase-manifest.json" >/dev/null
    jq -e '
      .format == "stage-a-original-stack-dynamic-control-closure-v1" and
      .status == "incomplete" and
      (.artifact_role.acceptance_authority | not) and
      (.artifact_role.report_status_closes_obligations | not) and
      (.sites | length) == 3
    ' "$out/original-stack-dynamic-control-closure.json" >/dev/null
    jq -e '
      .format == "stage-a-runtime-value-carry-ir-v1" and
      (.proof_ready | not) and
      (.routes | length) == 1 and
      ([.routes[].transfers[] |
        select(.authority_status == "required")] | length) == 1
    ' "$out/runtime-value-carry-ir.json" >/dev/null
    jq -e '
      .format == "stage-a-runtime-value-carry-lean-v1" and
      (.proof_authority | not) and
      (.semantic_authority_complete | not) and
      (.routes | length) == 1 and
      .routes[0].semantic_authority == null
    ' "$out/runtime-value-carry-lean.json" >/dev/null
    test -s \
      "$out/StageA/GeneratedRelationalRuntimeValueCarryStructure.lean"
    test -s \
      "$out/StageA/GeneratedRelationalRuntimeValueCarryBinding.lean"
  '';
  mixedOriginalStackDynamicAuthorityTargets =
    (builtins.fromJSON (builtins.readFile
      "${mixedOriginalStackDynamicAuthorityLean}/phase-manifest.json")).targets;
  mixedOriginalStackDynamicAuthorityTargetArgs =
    builtins.concatStringsSep " " (
      map (module: "--target ${pkgs.lib.escapeShellArg module}")
        mixedOriginalStackDynamicAuthorityTargets
    );
  mixedOriginalStackDynamicAuthorityProofSources = mkPhase
    "stage-a-gnu-hello-roundtrip-mixed-original-stack-dynamic-authority-proof-sources" [] ''
    ${aggregatePython} ${proofSourceAggregateDriver} \
      --source ${leanSourceRoot} \
      --source ${originalPeLean} \
      --source ${staticMachineImportContractsLean} \
      --source ${mixedOriginalWritableSlotAuthorityLean} \
      --source ${mixedOriginalStackDynamicAuthorityLean} \
      ${mixedOriginalStackDynamicAuthorityTargetArgs} \
      --explicit-targets-only \
      --target-closure-only \
      --out "$out"
  '';
  mixedOriginalStackDynamicAuthorityProofModules =
    builtins.fromJSON (builtins.readFile
      "${mixedOriginalStackDynamicAuthorityProofSources}/standalone-modules.json");
  mixedOriginalStackDynamicAuthorityProofResources =
    builtins.fromJSON (builtins.readFile
      "${mixedOriginalStackDynamicAuthorityProofSources}/module-resources.json");
  mixedOriginalStackDynamicAuthorityProof = mkLeanGraph {
    inherit pkgs;
    contentAddressed = true;
    standaloneSourceRoot =
      mixedOriginalStackDynamicAuthorityProofSources + "/StageA";
    standaloneModules = mixedOriginalStackDynamicAuthorityProofModules;
    standaloneModuleResources =
      mixedOriginalStackDynamicAuthorityProofResources;
    targetNodes = mixedOriginalStackDynamicAuthorityTargets;
    targetBundle = true;
  };

  mixedOriginalLean = mkPhase
    "stage-a-gnu-hello-roundtrip-mixed-original-lean" [] ''
    test -e ${mixedOriginalDirectCallFixedPointCheck}
    test -e ${mixedOriginalStackDynamicAuthorityProof}
    ${python} ${driver} mixed-original-final \
      --original ${originalPe} \
      --reference-contract ${staticExport}/reference-contract.json \
      --state-machine ${staticExport}/state-machine.jsonl \
      --load-image-contract ${staticExport}/load-image-contract.json \
      --machine-import-report \
        ${staticMachineImportContractsLean}/machine-import-contract-report.json \
      --callable-resolver-profile \
        ${machineRuntimeProfileSource}/pe32-kernel32-callable-resolvers-v1.json \
      --direct-call-authority-report \
        ${mixedOriginalDirectCallClosureSemanticsLean}/direct-call-authority-bindings.json \
      --stack-dynamic-authority-report \
        ${mixedOriginalStackDynamicAuthorityLean}/original-stack-dynamic-control-closure.json \
      --writable-slot-authority-report \
        ${mixedOriginalWritableSlotAuthorityLean}/relocated-writable-static-pointer-slot-authorities.json \
      --base-plan \
        ${mixedOriginalWritableSlotAuthorityLean}/interpreter-mixed-original-base-plan.json \
      --shard-size 128 \
      --out "$out"
    jq -e '
      .phase == "mixed-original-final-lean" and
      (.status == "source-ready" or .status == "incomplete") and
      (.proof_authority | not) and
      .targets == ["GeneratedRelationalInterpreterMixedOriginal"] and
      .counts.regions > 0 and .counts.reachable_targets > 0 and
      .counts.checked_stack_dynamic_static_authorities > 0 and
      .counts.stack_dynamic_runtime_premises ==
        .counts.checked_stack_dynamic_static_authorities and
      (.stack_dynamic_runtime_frontiers | length) ==
        .counts.stack_dynamic_runtime_premises and
      ((.status == "source-ready" and .exact_reachability_emitted) or
       (.status == "incomplete" and
        (.exact_reachability_emitted | not) and .counts.blockers > 0))
    ' "$out/phase-manifest.json" >/dev/null
    test -s "$out/StageA/GeneratedRelationalInterpreterMixedOriginal.lean"
    test -s "$out/interpreter-mixed-original-plan.json"
  '';

  mixedOriginalStaticReachabilityLean = mkPhase
    "stage-a-gnu-hello-roundtrip-mixed-original-static-reachability-lean" [] ''
    ${python} ${driver} mixed-original-static-reachability \
      --mixed-original-plan \
        ${mixedOriginalLean}/interpreter-mixed-original-plan.json \
      --out "$out"
    jq -e '
      .phase == "mixed-original-static-reachability" and
      .status == "typed-interface-ready" and
      (.proof_authority | not) and
      .failure_mode == "incomplete" and
      .runtime_indirect_control.closed_by_this_artifact == false and
      .runtime_indirect_control.required_at ==
        "mixed-component-composition" and
      .counts.reachable_targets > 0 and
      .theorem ==
        "StageA.GeneratedRelational.InterpreterMixedOriginalStaticReachability.generatedExactOriginalDecodedStaticReachability" and
      .targets == [
        "GeneratedRelationalInterpreterMixedOriginalStaticReachability"
      ]
    ' "$out/phase-manifest.json" >/dev/null
    test -s \
      "$out/interpreter-mixed-original-static-reachability.json"
    test -s \
      "$out/StageA/GeneratedRelationalInterpreterMixedOriginalStaticReachability.lean"
  '';

  mixedOriginalStaticReachabilityProofSources = mkPhase
    "stage-a-gnu-hello-roundtrip-mixed-original-static-reachability-proof-sources" [] ''
    ${aggregatePython} ${proofSourceAggregateDriver} \
      --source ${leanSourceRoot} \
      --source ${originalPeLean} \
      --source ${staticMachineImportContractsLean} \
      --source ${mixedOriginalWritableSlotAuthorityLean} \
      --source ${mixedOriginalRegisterIndirectAuthorityLean} \
      --source ${mixedOriginalDirectCallProposalsLean} \
      --source ${mixedOriginalDirectCallSemanticsLean} \
      --source ${mixedOriginalDirectCallClosureProposalsLean} \
      --source ${mixedOriginalDirectCallClosureSemanticsLean} \
      --source ${mixedOriginalLean} \
      --source ${mixedOriginalStaticReachabilityLean} \
      --target GeneratedRelationalInterpreterMixedOriginalStaticReachability \
      --out "$out"
  '';
  mixedOriginalStaticReachabilityProofModules = builtins.fromJSON (
    builtins.readFile
      "${mixedOriginalStaticReachabilityProofSources}/standalone-modules.json"
  );
  mixedOriginalStaticReachabilityProofResources = builtins.fromJSON (
    builtins.readFile
      "${mixedOriginalStaticReachabilityProofSources}/module-resources.json"
  );
  mixedOriginalStaticReachabilityProof = mkLeanGraph {
    inherit pkgs;
    contentAddressed = true;
    standaloneSourceRoot =
      mixedOriginalStaticReachabilityProofSources + "/StageA";
    standaloneModules = mixedOriginalStaticReachabilityProofModules;
    standaloneModuleResources = mixedOriginalStaticReachabilityProofResources;
    targetNodes = [
      "GeneratedRelationalInterpreterMixedOriginalStaticReachability"
    ];
    targetBundle = true;
  };

  mixedOriginalCarrierBindingLean = mkPhase
    "stage-a-gnu-hello-roundtrip-mixed-original-carrier-binding-lean" [] ''
    ${python} ${driver} mixed-original-carrier-binding \
      --mixed-original ${mixedOriginalLean} \
      --out "$out"
    jq -e '
      .phase == "mixed-original-carrier-binding-lean" and
      .status == "source-ready" and
      (.proof_authority | not) and
      .targets == ["GeneratedRelationalInterpreterOriginalCarrierBinding"] and
      .counts.targets > 0 and
      .counts.addresses >= .counts.targets
    ' "$out/phase-manifest.json" >/dev/null
    test -s \
      "$out/StageA/GeneratedRelationalInterpreterOriginalCarrierBinding.lean"
  '';

  mixedOriginalCarrierBindingProofSources = mkPhase
    "stage-a-gnu-hello-roundtrip-mixed-original-carrier-binding-proof-sources" [] ''
    ${aggregatePython} ${proofSourceAggregateDriver} \
      --source ${leanSourceRoot} \
      --source ${originalPeLean} \
      --source ${staticMachineImportContractsLean} \
      --source ${mixedOriginalWritableSlotAuthorityLean} \
      --source ${mixedOriginalDirectCallProposalsLean} \
      --source ${mixedOriginalDirectCallSemanticsLean} \
      --source ${mixedOriginalDirectCallClosureProposalsLean} \
      --source ${mixedOriginalDirectCallClosureSemanticsLean} \
      --source ${mixedOriginalLean} \
      --source ${mixedOriginalCarrierBindingLean} \
      --target GeneratedRelationalInterpreterOriginalCarrierBinding \
      --out "$out"
  '';
  mixedOriginalCarrierBindingProofModules = builtins.fromJSON (
    builtins.readFile
      "${mixedOriginalCarrierBindingProofSources}/standalone-modules.json"
  );
  mixedOriginalCarrierBindingProofResources = builtins.fromJSON (
    builtins.readFile
      "${mixedOriginalCarrierBindingProofSources}/module-resources.json"
  );
  mixedOriginalCarrierBindingProof = mkLeanGraph {
    inherit pkgs;
    contentAddressed = true;
    standaloneSourceRoot =
      mixedOriginalCarrierBindingProofSources + "/StageA";
    standaloneModules = mixedOriginalCarrierBindingProofModules;
    standaloneModuleResources = mixedOriginalCarrierBindingProofResources;
    targetNodes = [ "GeneratedRelationalInterpreterOriginalCarrierBinding" ];
    targetBundle = true;
  };

  programLean = mkPhase "stage-a-gnu-hello-roundtrip-program-lean" [] ''
    ${python} ${driver} program-source \
      --state-machine ${staticExport}/state-machine.jsonl --out "$out"
  '';

  normalizationLean = mkPhase "stage-a-gnu-hello-roundtrip-normalization-lean" [] ''
    ${python} ${driver} normalization-sources \
      --state-machine ${staticExport}/state-machine.jsonl \
      --shard-size 48 --out "$out"
  '';

  semanticRefinementLean = mkPhase "stage-a-gnu-hello-roundtrip-semantic-refinement-lean" [] ''
    ${python} ${driver} semantic-refinement-sources \
      --state-machine ${staticExport}/state-machine.jsonl \
      --shard-size 48 --out "$out"
  '';

  x87Lean = mkPhase "stage-a-gnu-hello-roundtrip-x87-lean" [] ''
    ${python} ${driver} x87-sources \
      --state-machine ${staticExport}/state-machine.jsonl \
      --original ${originalPe} \
      --pe-byte-pack-inventory ${originalPeLean}/pe-byte-packs.json \
      --out "$out"
  '';

  # Schedule 0034 is a real all-x87 singleton shard in the pinned GNU fixture.
  # Its focused closure isolates the exact-byte certificate path from the much
  # larger mixed-schedule reductions.  The node is assigned to the dedicated
  # high lane so measurements remain comparable with the former PE reductions.
  x87ScheduleBenchmarkModule = "GeneratedInterpreterX87Schedule0034";
  x87ScheduleBenchmarkSources = mkPhase
    "stage-a-gnu-hello-roundtrip-x87-schedule-benchmark-sources" [] ''
    ${aggregatePython} ${proofSourceAggregateDriver} \
      --source ${leanSourceRoot} \
      --source ${originalPeLean} \
      --source ${x87Lean} \
      --target ${x87ScheduleBenchmarkModule} \
      --out "$out"
  '';
  x87ScheduleBenchmarkModules = builtins.fromJSON (
    builtins.readFile
      "${x87ScheduleBenchmarkSources}/standalone-modules.json"
  );
  x87ScheduleBenchmarkBaseResources = builtins.fromJSON (
    builtins.readFile
      "${x87ScheduleBenchmarkSources}/module-resources.json"
  );
  x87ScheduleBenchmarkResources = x87ScheduleBenchmarkBaseResources // {
    "${x87ScheduleBenchmarkModule}" = {
      resource_class = "high-memory";
      estimated_memory_mb = 8192;
    };
  };
  x87ScheduleBenchmark = mkLeanGraph {
    inherit pkgs;
    contentAddressed = true;
    standaloneSourceRoot = x87ScheduleBenchmarkSources + "/StageA";
    standaloneModules = x87ScheduleBenchmarkModules;
    standaloneModuleResources = x87ScheduleBenchmarkResources;
    targetNodes = [ x87ScheduleBenchmarkModule ];
    targetBundle = true;
  };

  definednessLean = mkPhase "stage-a-gnu-hello-roundtrip-definedness-lean" [] ''
    ${python} ${driver} definedness-source \
      --state-machine ${staticExport}/state-machine.jsonl --out "$out"
  '';

  kernelLean = mkPhaseWithSource kernelDataPythonSource
    "stage-a-gnu-hello-roundtrip-compiled-kernel" [] ''
    ${python} ${compiledKernelDriver} \
      --candidate ${candidate}/candidate.exe \
      --linker-map ${candidate}/payload.map \
      --program-manifest ${interpreter}/state-machine-interpreter-program.json \
      --engine-layout ${candidate}/engine-layout.bin \
      --native-build-manifest ${candidate}/interpreter-native-build-manifest.json \
      --out "$out"
  '';

  kernelDataLean = mkPhaseWithSource kernelDataPythonSource
    "stage-a-gnu-hello-roundtrip-kernel-data-lean" [] ''
    ${python} ${kernelDataDriver} \
      --candidate ${candidate}/candidate.exe \
      --linker-map ${candidate}/payload.map \
      --state-machine ${staticExport}/state-machine.jsonl \
      --lean-source-root \
        ${kernelDataLeanSource}/src/spaghetti_extractor/lean/StageA \
      --shard-size 8 --out "$out"
  '';

  kernelAbiLean = mkPhase "stage-a-gnu-hello-roundtrip-kernel-abi-lean" [] ''
    ${python} ${driver} kernel-abi \
      --kernel-plan ${kernelLean}/interpreter-kernel-plan.json \
      --kernel-data-inventory ${kernelDataLean}/module-inventory.json \
      --engine-layout ${candidate}/engine-layout.bin \
      --out "$out"
    jq -e '
      .phase == "compiled-kernel-abi" and
      .status == "source-ready" and
      (.proof_authority | not) and
      .proposal_format ==
        "stage-a-relational-interpreter-kernel-abi-plan-v1" and
      .failure_mode == "none" and
      (.candidate_sha256 | test("^[0-9a-f]{64}$")) and
      (.proposal_sha256 | test("^[0-9a-f]{64}$")) and
      .operations == [
        "programLookup", "interpreterStep", "runFunction", "invokeCall"
      ] and
      .inputs.kernel_plan.path == "interpreter-kernel-plan.json" and
      .inputs.kernel_data_inventory.path == "module-inventory.json" and
      .inputs.engine_layout.path == "engine-layout.bin" and
      .public_outputs.plan == "interpreter-kernel-abi-plan.json" and
      .public_outputs.lean_module ==
        "StageA/GeneratedRelationalInterpreterKernelABI.lean" and
      .targets == ["GeneratedRelationalInterpreterKernelABI"]
    ' "$out/phase-manifest.json" >/dev/null
    test -s "$out/interpreter-kernel-abi-plan.json"
    test -s "$out/StageA/GeneratedRelationalInterpreterKernelABI.lean"
  '';

  x87CandidateReplayLean = mkPhase
    "stage-a-gnu-hello-roundtrip-x87-candidate-replay-lean" [] ''
    ${python} ${driver} x87-candidate-replay-sources \
      --state-machine ${staticExport}/state-machine.jsonl \
      --kernel-data-inventory ${kernelDataLean}/module-inventory.json \
      --out "$out"
  '';

  x87ReplayBridgeTargetLean = mkPhase
    "stage-a-gnu-hello-roundtrip-x87-replay-bridge-target-lean" [] ''
    ${python} ${driver} x87-replay-bridge-target-sources \
      --candidate ${candidate}/candidate.exe \
      --build-manifest ${candidate}/interpreter-native-build-manifest.json \
      --native-engine-plan ${nativeEngine}/native-engine-plan.json \
      --candidate-data-module GeneratedInterpreterKernelDataBase \
      --pack-size 32 \
      --out "$out"
    jq -e '
      .phase == "x87-replay-bridge-target-lean" and
      .status == "source-ready" and
      (.proof_authority | not) and
      (.candidate_sha256 | test("^[0-9a-f]{64}$")) and
      .counts.descriptors > 0 and
      .counts.finite_targets == .counts.descriptors and
      .counts.dynamic_frame_mappings == .counts.descriptors and
      .counts.runtime_refinement_goals == .counts.descriptors and
      .counts.static_frontiers == 0 and
      .targets == [
        "GeneratedRelationalInterpreterX87ReplayBridgeTarget"
      ]
    ' "$out/phase-manifest.json" >/dev/null
    test -s "$out/x87-replay-bridge-target-plan.json"
    test -s \
      "$out/StageA/GeneratedRelationalInterpreterX87ReplayBridgeTarget.lean"
  '';

  x87ReplayBridgeRuntimeLean = mkPhase
    "stage-a-gnu-hello-roundtrip-x87-replay-bridge-runtime-lean" [] ''
    ${python} ${driver} x87-replay-bridge-runtime-sources \
      --candidate ${candidate}/candidate.exe \
      --target-plan \
        ${x87ReplayBridgeTargetLean}/x87-replay-bridge-target-plan.json \
      --native-engine-plan ${nativeEngine}/native-engine-plan.json \
      --target-module GeneratedRelationalInterpreterX87ReplayBridgeTarget \
      --pack-size 32 \
      --out "$out"
    jq -e --argjson targetCount \
      "$(jq '.counts.descriptors' \
        ${x87ReplayBridgeTargetLean}/phase-manifest.json)" '
      .phase == "x87-replay-bridge-runtime-lean" and
      (.proof_authority | not) and
      (.candidate_sha256 | test("^[0-9a-f]{64}$")) and
      .counts.runtime_targets == $targetCount and
      .counts.relocated_operands > 0 and
      .counts.unbound_relocated_operands == 0 and
      .targets == [
        "GeneratedRelationalInterpreterX87ReplayBridgeRuntime"
      ]
    ' "$out/phase-manifest.json" >/dev/null
    jq -e --argjson targetCount \
      "$(jq '.counts.descriptors' \
        ${x87ReplayBridgeTargetLean}/phase-manifest.json)" '
      .format == "stage-a-relational-x87-replay-bridge-runtime-plan-v1" and
      (.acceptance_authority | not) and
      .counts.runtime_targets == $targetCount and
      .counts.relocated_operands > 0 and
      .counts.unbound_relocated_operands == 0
    ' "$out/x87-replay-bridge-runtime-plan.json" >/dev/null
    test -s \
      "$out/StageA/GeneratedRelationalInterpreterX87ReplayBridgeRuntime.lean"
  '';

  x87KernelExecutionLean = mkPhase
    "stage-a-gnu-hello-roundtrip-x87-kernel-execution-lean" [] ''
    ${python} ${driver} x87-kernel-execution-sources \
      --runtime-plan \
        ${x87ReplayBridgeRuntimeLean}/x87-replay-bridge-runtime-plan.json \
      --out "$out"
    jq -e --argjson runtimeCount \
      "$(jq '.counts.runtime_targets' \
        ${x87ReplayBridgeRuntimeLean}/phase-manifest.json)" '
      .phase == "x87-kernel-execution-lean" and
      .status == "source-ready" and
      .diagnostic_status == "semantic_premises_required" and
      (.proof_authority | not) and
      .failure_mode == "incomplete" and
      (.candidate_sha256 | test("^[0-9a-f]{64}$")) and
      .runtime_targets == $runtimeCount and
      .remaining_proof_premises == [
        "program_binding.peExact",
        "program_binding.importsExact",
        "program_binding.targetInventory",
        "endpoint_certificate.handlerResult",
        "endpoint_certificate.callTarget",
        "endpoint_certificate.callRun",
        "endpoint_certificate.entryRun",
        "endpoint_certificate.instructionRun",
        "endpoint_certificate.captureRun",
        "endpoint_certificate.returnRun",
        "endpoint_certificate.frameEffect"
      ] and
      .targets == [
        "GeneratedRelationalInterpreterKernelX87Execution"
      ]
    ' "$out/phase-manifest.json" >/dev/null
    jq -e --argjson runtimeCount \
      "$(jq '.counts.runtime_targets' \
        ${x87ReplayBridgeRuntimeLean}/phase-manifest.json)" '
      .format == "stage-a-gnu-hello-x87-kernel-execution-frontier-v1" and
      .status == "semantic_premises_required" and
      (.acceptance_authority | not) and
      .failure_mode == "incomplete" and
      .runtime_targets == $runtimeCount and
      .remaining_authority.program_binding_fields == [
        "peExact", "importsExact", "targetInventory"
      ] and
      (.remaining_authority.endpoint_certificate_proof_fields
        | index("callRun") != null) and
      (.remaining_authority.endpoint_certificate_proof_fields
        | index("returnRun") != null) and
      (.remaining_authority.endpoint_certificate_proof_fields
        | index("frameEffect") != null)
    ' "$out/x87-kernel-execution-frontier.json" >/dev/null
    test -s \
      "$out/StageA/GeneratedRelationalInterpreterKernelX87Execution.lean"
    test -s "$out/module-resources.json"
  '';

  kernelBlockLean = mkPhase "stage-a-gnu-hello-roundtrip-kernel-block-lean" [] ''
    ${python} ${driver} kernel-block \
      --candidate ${candidate}/candidate.exe \
      --kernel-plan ${kernelLean}/interpreter-kernel-plan.json \
      --shard-size 24 --out "$out"
  '';

  kernelLoopLean = mkPhase "stage-a-gnu-hello-roundtrip-kernel-loop-lean" [] ''
    ${python} ${driver} kernel-loop \
      --kernel-plan ${kernelLean}/interpreter-kernel-plan.json --out "$out"
  '';

  kernelCallbackLean = mkPhase "stage-a-gnu-hello-roundtrip-kernel-callback-lean" [] ''
    ${python} ${driver} kernel-callback \
      --candidate ${candidate}/candidate.exe \
      --kernel-plan ${kernelLean}/interpreter-kernel-plan.json \
      --linker-map ${candidate}/payload.map \
      --native-engine-plan ${nativeEngine}/native-engine-plan.json \
      --out "$out"
  '';

  kernelLookupLean = mkPhase "stage-a-gnu-hello-roundtrip-kernel-lookup-lean" [] ''
    ${python} ${driver} kernel-lookup \
      --kernel-plan ${kernelLean}/interpreter-kernel-plan.json \
      --kernel-data-inventory ${kernelDataLean}/module-inventory.json \
      --out "$out"
  '';

  kernelLookupNativeLean = mkPhase
    "stage-a-gnu-hello-roundtrip-kernel-lookup-native-lean" [] ''
    ${python} ${driver} kernel-lookup-native \
      --candidate ${candidate}/candidate.exe \
      --kernel-plan ${kernelLean}/interpreter-kernel-plan.json \
      --kernel-data-inventory ${kernelDataLean}/module-inventory.json \
      --out "$out"
  '';

  kernelLookupOperationLean = mkPhase
    "stage-a-gnu-hello-roundtrip-kernel-lookup-operation-lean" [] ''
    ${python} ${driver} kernel-lookup-operation \
      --candidate ${candidate}/candidate.exe \
      --kernel-plan ${kernelLean}/interpreter-kernel-plan.json \
      --kernel-data-inventory ${kernelDataLean}/module-inventory.json \
      --lookup-native-plan \
        ${kernelLookupNativeLean}/interpreter-kernel-lookup-native-plan.json \
      --abi-plan ${kernelAbiLean}/interpreter-kernel-abi-plan.json \
      --out "$out"
    jq -e '
      .phase == "compiled-kernel-program-lookup-operation" and
      .status == "source-ready" and
      (.proof_authority | not) and
      .failure_mode == "incomplete" and
      .remaining_proof_premises == [] and
      .theorem ==
        "StageA.GeneratedRelational.InterpreterKernelProgramLookupOperation.generatedProgramLookupOperationRefinesUsing" and
      (.inputs | keys) == [
        "abi_plan",
        "candidate",
        "kernel_data_inventory",
        "kernel_plan",
        "lookup_native_plan"
      ] and
      ([.inputs[]] | all(
        (.sha256 | test("^[0-9a-f]{64}$")) and
        (.path | length) > 0
      )) and
      .public_outputs.plan ==
        "interpreter-kernel-program-lookup-operation-plan.json" and
      .public_outputs.lean_module ==
        "StageA/GeneratedRelationalInterpreterKernelProgramLookupOperation.lean" and
      .public_outputs.module_resources == "module-resources.json" and
      .targets ==
        ["GeneratedRelationalInterpreterKernelProgramLookupOperation"]
    ' "$out/phase-manifest.json" >/dev/null
    test -s "$out/interpreter-kernel-program-lookup-operation-plan.json"
    test -s \
      "$out/StageA/GeneratedRelationalInterpreterKernelProgramLookupOperation.lean"
    test -s "$out/module-resources.json"
  '';

  kernelStepLean = mkPhase "stage-a-gnu-hello-roundtrip-kernel-step-lean" [] ''
    ${python} ${driver} kernel-step \
      --kernel-plan ${kernelLean}/interpreter-kernel-plan.json \
      --out "$out"
  '';

  kernelStepNativeLean = mkPhase
    "stage-a-gnu-hello-roundtrip-kernel-step-native-lean" [] ''
    ${python} ${driver} kernel-step-native \
      --candidate ${candidate}/candidate.exe \
      --kernel-plan ${kernelLean}/interpreter-kernel-plan.json \
      --callback-plan ${kernelCallbackLean}/interpreter-kernel-callback-plan.json \
      --out "$out"
  '';

  kernelRunLean = mkPhase "stage-a-gnu-hello-roundtrip-kernel-run-lean" [] ''
    ${python} ${driver} kernel-run \
      --candidate ${candidate}/candidate.exe \
      --kernel-plan ${kernelLean}/interpreter-kernel-plan.json \
      --out "$out"
  '';

  kernelRunNativeLean = mkPhase
    "stage-a-gnu-hello-roundtrip-kernel-run-native-lean" [] ''
    ${python} ${driver} kernel-run-native \
      --candidate ${candidate}/candidate.exe \
      --kernel-plan ${kernelLean}/interpreter-kernel-plan.json \
      --out "$out"
  '';

  kernelRunNativeProofSources = mkPhase
    "stage-a-gnu-hello-roundtrip-kernel-run-native-proof-sources" [] ''
    ${aggregatePython} ${proofSourceAggregateDriver} \
      --source ${leanSourceRoot} \
      --source ${kernelLean} \
      --source ${kernelDataLean} \
      --source ${kernelCallbackLean} \
      --source ${kernelRunLean} \
      --source ${kernelRunNativeLean} \
      --target GeneratedRelationalInterpreterKernelRunNative \
      --out "$out"
  '';
  kernelRunNativeProofModules = builtins.fromJSON (
    builtins.readFile
      "${kernelRunNativeProofSources}/standalone-modules.json"
  );
  kernelRunNativeProofResources = builtins.fromJSON (
    builtins.readFile "${kernelRunNativeProofSources}/module-resources.json"
  );
  kernelRunNativeProof = mkLeanGraph {
    inherit pkgs;
    contentAddressed = true;
    standaloneSourceRoot = kernelRunNativeProofSources + "/StageA";
    standaloneModules = kernelRunNativeProofModules;
    standaloneModuleResources = kernelRunNativeProofResources;
    targetNodes = [ "GeneratedRelationalInterpreterKernelRunNative" ];
    targetBundle = true;
    targetAxiomAudit = {
      module = "GeneratedRelationalInterpreterKernelRunNative";
      declaration =
        "StageA.GeneratedRelational.InterpreterKernelRunNative.GeneratedRunFunctionNativeRefinesUsing";
      approved_axioms = [ "propext" "Classical.choice" "Quot.sound" ];
    };
  };

  kernelInvokeLean = mkPhase "stage-a-gnu-hello-roundtrip-kernel-invoke-lean" [] ''
    ${python} ${driver} kernel-invoke \
      --candidate ${candidate}/candidate.exe \
      --kernel-plan ${kernelLean}/interpreter-kernel-plan.json \
      --out "$out"
  '';

  kernelInvokeNativeLean = mkPhase
    "stage-a-gnu-hello-roundtrip-kernel-invoke-native-lean" [] ''
    ${python} ${driver} kernel-invoke-native \
      --candidate ${candidate}/candidate.exe \
      --kernel-plan ${kernelLean}/interpreter-kernel-plan.json \
      --callback-plan ${kernelCallbackLean}/interpreter-kernel-callback-plan.json \
      --out "$out"
  '';

  kernelStepOperationLean = mkPhase
    "stage-a-gnu-hello-roundtrip-kernel-step-operation-lean" [] ''
    ${python} ${driver} kernel-step-operation \
      --candidate ${candidate}/candidate.exe \
      --kernel-plan ${kernelLean}/interpreter-kernel-plan.json \
      --kernel-data-inventory ${kernelDataLean}/module-inventory.json \
      --abi-plan ${kernelAbiLean}/interpreter-kernel-abi-plan.json \
      --step-native-plan \
        ${kernelStepNativeLean}/interpreter-kernel-step-native-plan.json \
      --callback-plan \
        ${kernelCallbackLean}/interpreter-kernel-callback-plan.json \
      --lookup-native-plan \
        ${kernelLookupNativeLean}/interpreter-kernel-lookup-native-plan.json \
      --lookup-operation-plan \
        ${kernelLookupOperationLean}/interpreter-kernel-program-lookup-operation-plan.json \
      --invoke-native-plan \
        ${kernelInvokeNativeLean}/interpreter-kernel-invoke-native-plan.json \
      --x87-replay-plan \
        ${x87ReplayBridgeTargetLean}/x87-replay-bridge-target-plan.json \
      --out "$out"
    jq -e '
      .phase == "compiled-kernel-interpreter-step-operation" and
      .status == "source-ready" and
      (.proof_authority | not) and
      .failure_mode == "incomplete" and
      .remaining_proof_premises == [
        "program_lookup_world_subroutine_composition",
        "per_action_loop_chunks",
        "direct_helper_subroutine_refinements",
        "invoke_call_subroutine_operation_refinement",
        "x87_replay_nested_callback_refinement",
        "cdecl_epilogue_response_and_memory_frame"
      ] and
      .theorem ==
        "StageA.GeneratedRelational.InterpreterKernelStepOperation.generatedInterpreterStepOperationRefinesUsing" and
      (.inputs | keys) == [
        "abi_plan",
        "callback_plan",
        "candidate",
        "invoke_native_plan",
        "kernel_data_inventory",
        "kernel_plan",
        "lookup_native_plan",
        "lookup_operation_plan",
        "step_native_plan",
        "x87_replay_plan"
      ] and
      ([.inputs[]] | all(
        (.sha256 | test("^[0-9a-f]{64}$")) and
        (.path | length) > 0
      )) and
      .public_outputs.plan ==
        "interpreter-kernel-step-operation-plan.json" and
      .public_outputs.lean_module ==
        "StageA/GeneratedRelationalInterpreterKernelStepOperation.lean" and
      .public_outputs.module_resources == "module-resources.json" and
      .targets == ["GeneratedRelationalInterpreterKernelStepOperation"]
    ' "$out/phase-manifest.json" >/dev/null
    test -s "$out/interpreter-kernel-step-operation-plan.json"
    test -s \
      "$out/StageA/GeneratedRelationalInterpreterKernelStepOperation.lean"
    test -s "$out/module-resources.json"
  '';

  kernelStepProgramLookupCallLean = mkPhase
    "stage-a-gnu-hello-roundtrip-kernel-step-program-lookup-call-lean" [] ''
    ${python} ${driver} kernel-step-program-lookup-call \
      --candidate ${candidate}/candidate.exe \
      --kernel-plan ${kernelLean}/interpreter-kernel-plan.json \
      --kernel-data-inventory ${kernelDataLean}/module-inventory.json \
      --abi-plan ${kernelAbiLean}/interpreter-kernel-abi-plan.json \
      --step-native-plan \
        ${kernelStepNativeLean}/interpreter-kernel-step-native-plan.json \
      --callback-plan \
        ${kernelCallbackLean}/interpreter-kernel-callback-plan.json \
      --lookup-native-plan \
        ${kernelLookupNativeLean}/interpreter-kernel-lookup-native-plan.json \
      --lookup-operation-plan \
        ${kernelLookupOperationLean}/interpreter-kernel-program-lookup-operation-plan.json \
      --invoke-native-plan \
        ${kernelInvokeNativeLean}/interpreter-kernel-invoke-native-plan.json \
      --x87-replay-plan \
        ${x87ReplayBridgeTargetLean}/x87-replay-bridge-target-plan.json \
      --step-operation-plan \
        ${kernelStepOperationLean}/interpreter-kernel-step-operation-plan.json \
      --out "$out"
    jq -e '
      .phase == "compiled-kernel-step-program-lookup-call" and
      .status == "typed-interface-ready" and
      (.proof_authority | not) and
      .failure_mode == "incomplete" and
      .remaining_proof_premises == [
        "exact_step_caller_prefix_and_program_lookup_call_chunk",
        "program_lookup_request_at_exact_nested_caller_frame",
        "exact_program_lookup_native_return_path_at_checked_continuation"
      ] and
      .theorem ==
        "StageA.GeneratedRelational.InterpreterKernelStepProgramLookupCall.generatedInterpreterStepProgramLookupWorldCall" and
      .targets == [
        "GeneratedRelationalInterpreterKernelStepProgramLookupCall"
      ]
    ' "$out/phase-manifest.json" >/dev/null
    test -s \
      "$out/interpreter-kernel-step-program-lookup-call-plan.json"
    test -s \
      "$out/StageA/GeneratedRelationalInterpreterKernelStepProgramLookupCall.lean"
  '';

  kernelStepProgramLookupCallClosureLean = mkPhase
    "stage-a-gnu-hello-roundtrip-kernel-step-program-lookup-call-closure-lean" [] ''
    ${python} ${driver} kernel-step-program-lookup-call-closure \
      --candidate ${candidate}/candidate.exe \
      --program-lookup-call-plan \
        ${kernelStepProgramLookupCallLean}/interpreter-kernel-step-program-lookup-call-plan.json \
      --out "$out"
    jq -e '
      .phase == "compiled-kernel-step-program-lookup-call-closure" and
      .status == "typed-interface-ready" and
      (.proof_authority | not) and
      .failure_mode == "incomplete" and
      .closed_premise_families == [
        "submitted_step_caller_path",
        "bare_program_lookup_request_relation",
        "submitted_program_lookup_return_path"
      ] and
      .remaining_proof_premises == [
        "exact_step_prefix_and_helper_runtime_endpoints",
        "nested_program_lookup_cdecl_image_and_table_facts",
        "exact_program_lookup_return_replay_fuel_and_endpoint"
      ] and
      .theorem ==
        "StageA.GeneratedRelational.InterpreterKernelStepProgramLookupCallClosure.generatedInterpreterStepProgramLookupCallClosureBindings" and
      .targets == [
        "GeneratedRelationalInterpreterKernelStepProgramLookupCallClosure"
      ]
    ' "$out/phase-manifest.json" >/dev/null
    test -s \
      "$out/interpreter-kernel-step-program-lookup-call-closure.json"
    test -s \
      "$out/StageA/GeneratedRelationalInterpreterKernelStepProgramLookupCallClosure.lean"
  '';

  kernelStepProgramLookupExactComputationLean = mkPhaseWithSource
    proofClosurePythonSource
    "stage-a-gnu-hello-roundtrip-kernel-step-program-lookup-exact-computation-lean"
    [] ''
    ${python} ${proofClosureDriver} step-program-lookup-exact-computation \
      --candidate ${candidate}/candidate.exe \
      --closure-plan \
        ${kernelStepProgramLookupCallClosureLean}/interpreter-kernel-step-program-lookup-call-closure.json \
      --out "$out"
    jq -e '
      .phase ==
        "compiled-kernel-step-program-lookup-exact-computation" and
      .status == "source-ready" and
      (.proof_authority | not) and
      .failure_mode == "incomplete" and
      .remaining_proof_premises == [
        "step_prefix_checked_chunk_and_helper_executor_equalities",
        "nested_program_lookup_cdecl_image_table_and_source_bound",
        "program_lookup_operation_response_and_memory_frame",
        "program_lookup_return_executor_equality_for_selected_response"
      ] and
      .targets == [
        "GeneratedRelationalInterpreterKernelStepProgramLookupExactComputation"
      ]
    ' "$out/phase-manifest.json" >/dev/null
    test -s \
      "$out/interpreter-kernel-step-program-lookup-exact-computation.json"
    test -s \
      "$out/StageA/GeneratedRelationalInterpreterKernelStepProgramLookupExactComputation.lean"
  '';

  kernelOperationFrameParametricLean = mkPhase
    "stage-a-gnu-hello-roundtrip-kernel-operation-frame-parametric-lean" [] ''
    ${python} ${driver} kernel-operation-frame-parametric \
      --candidate ${candidate}/candidate.exe \
      --step-operation-plan \
        ${kernelStepOperationLean}/interpreter-kernel-step-operation-plan.json \
      --out "$out"
    jq -e '
      .phase == "compiled-kernel-operation-frame-parametric" and
      .status == "source-ready" and
      (.proof_authority | not) and
      .failure_mode == "incomplete" and
      .remaining_proof_premises == [
        "standalone_interpreter_step_operation_for_every_world",
        "frame_event_world_context_path_refinement"
      ] and
      .theorem ==
        "StageA.GeneratedRelational.InterpreterKernelOperationFrameParametric.generatedInterpreterStepFrameParametricCertificate" and
      (.inputs | keys) == ["candidate", "step_operation_plan"] and
      .public_outputs.plan ==
        "interpreter-kernel-operation-frame-parametric-plan.json" and
      .public_outputs.lean_module ==
        "StageA/GeneratedRelationalInterpreterKernelOperationFrameParametric.lean" and
      .targets == [
        "GeneratedRelationalInterpreterKernelOperationFrameParametric"
      ]
    ' "$out/phase-manifest.json" >/dev/null
    test -s \
      "$out/interpreter-kernel-operation-frame-parametric-plan.json"
    test -s \
      "$out/StageA/GeneratedRelationalInterpreterKernelOperationFrameParametric.lean"
    test -s "$out/module-resources.json"
  '';

  kernelFrameExecutorLean = mkPhase
    "stage-a-gnu-hello-roundtrip-kernel-frame-executor-lean" [] ''
    ${python} ${driver} kernel-frame-executor \
      --candidate ${candidate}/candidate.exe \
      --frame-parametric-plan \
        ${kernelOperationFrameParametricLean}/interpreter-kernel-operation-frame-parametric-plan.json \
      --out "$out"
    jq -e '
      .phase == "compiled-kernel-frame-executor" and
      .status == "source-ready" and
      (.proof_authority | not) and
      .failure_mode == "incomplete" and
      .remaining_proof_premises == [
        "standalone_interpreter_step_operation_for_every_world",
        "imported_environment_shift_footprint_and_world_update_contract",
        "imported_footprint_disjoint_from_caller_return_slot",
        "exact_prefix_event_index_and_return_word_trace"
      ] and
      .theorem ==
        "StageA.GeneratedRelational.InterpreterKernelFrameExecutor.generatedInterpreterStepFrameExecutorCertificate" and
      (.inputs | keys) == ["candidate", "frame_parametric_plan"] and
      .public_outputs.plan ==
        "interpreter-kernel-frame-executor-plan.json" and
      .public_outputs.lean_module ==
        "StageA/GeneratedRelationalInterpreterKernelFrameExecutor.lean" and
      .targets == ["GeneratedRelationalInterpreterKernelFrameExecutor"]
    ' "$out/phase-manifest.json" >/dev/null
    test -s "$out/interpreter-kernel-frame-executor-plan.json"
    test -s \
      "$out/StageA/GeneratedRelationalInterpreterKernelFrameExecutor.lean"
    test -s "$out/module-resources.json"
  '';

  kernelRunOperationLean = mkPhase
    "stage-a-gnu-hello-roundtrip-kernel-run-operation-lean" [] ''
    ${python} ${driver} kernel-run-operation \
      --candidate ${candidate}/candidate.exe \
      --kernel-plan ${kernelLean}/interpreter-kernel-plan.json \
      --kernel-data-inventory ${kernelDataLean}/module-inventory.json \
      --abi-plan ${kernelAbiLean}/interpreter-kernel-abi-plan.json \
      --run-native-plan \
        ${kernelRunNativeLean}/interpreter-kernel-run-native-plan.json \
      --step-operation-plan \
        ${kernelStepOperationLean}/interpreter-kernel-step-operation-plan.json \
      --out "$out"
    jq -e '
      .phase == "compiled-kernel-run-function-operation" and
      .status == "source-ready" and
      (.proof_authority | not) and
      .failure_mode == "incomplete" and
      .remaining_proof_premises == [
        "frame_event_world_parametric_interpreter_step_certificate",
        "loop_invariant_and_step_prelude",
        "terminal_completion_dispatch_chunks",
        "continuation_and_resolver_callback_refinement",
        "entry_chunk_and_outer_frame",
        "cdecl_epilogue_response_and_memory_frame"
      ] and
      .theorem ==
        "StageA.GeneratedRelational.InterpreterKernelRunOperation.generatedRunFunctionOperationRefinesUsing" and
      (.inputs | keys) == [
        "abi_plan",
        "candidate",
        "kernel_data_inventory",
        "kernel_plan",
        "run_native_plan",
        "step_operation_plan"
      ] and
      ([.inputs[]] | all(
        (.sha256 | test("^[0-9a-f]{64}$")) and
        (.path | length) > 0
      )) and
      .public_outputs.plan ==
        "interpreter-kernel-run-operation-plan.json" and
      .public_outputs.lean_module ==
        "StageA/GeneratedRelationalInterpreterKernelRunOperation.lean" and
      .public_outputs.module_resources == "module-resources.json" and
      .targets == ["GeneratedRelationalInterpreterKernelRunOperation"]
    ' "$out/phase-manifest.json" >/dev/null
    test -s "$out/interpreter-kernel-run-operation-plan.json"
    test -s \
      "$out/StageA/GeneratedRelationalInterpreterKernelRunOperation.lean"
    test -s "$out/module-resources.json"
  '';

  kernelCdeclEpilogueLean = mkPhase
    "stage-a-gnu-hello-roundtrip-kernel-cdecl-epilogue-lean" [] ''
    ${python} ${driver} kernel-cdecl-epilogue \
      --candidate ${candidate}/candidate.exe \
      --step-operation-plan \
        ${kernelStepOperationLean}/interpreter-kernel-step-operation-plan.json \
      --run-operation-plan \
        ${kernelRunOperationLean}/interpreter-kernel-run-operation-plan.json \
      --step-epilogue-fuel 9 \
      --run-epilogue-fuel 8 \
      --out "$out"
    jq -e '
      .phase == "compiled-kernel-cdecl-epilogue" and
      .status == "typed-interface-ready" and
      (.proof_authority | not) and
      .failure_mode == "incomplete" and
      .remaining_proof_premises == [
        "exact_decoded_epilogue_prefix_and_return_execution",
        "checked_stack_return_word",
        "preserved_cdecl_registers_and_stack_pop",
        "checked_write_footprint_disjointness",
        "loaded_image_and_program_table_preservation",
        "typed_response_payload_at_computed_return"
      ] and
      .theorem ==
        "StageA.GeneratedRelational.InterpreterKernelCdeclEpilogue.generatedKernelCDeclEpiloguesChecked" and
      .targets == ["GeneratedRelationalInterpreterKernelCdeclEpilogue"]
    ' "$out/phase-manifest.json" >/dev/null
    test -s "$out/interpreter-kernel-cdecl-epilogue-plan.json"
    test -s \
      "$out/StageA/GeneratedRelationalInterpreterKernelCdeclEpilogue.lean"
  '';

  kernelCdeclEpilogueSymbolicClosureLean = mkPhase
    "stage-a-gnu-hello-roundtrip-kernel-cdecl-epilogue-symbolic-closure-lean" [] ''
    ${python} ${driver} kernel-cdecl-epilogue-symbolic-closure \
      --candidate ${candidate}/candidate.exe \
      --cdecl-epilogue-plan \
        ${kernelCdeclEpilogueLean}/interpreter-kernel-cdecl-epilogue-plan.json \
      --out "$out"
    jq -e '
      .phase == "compiled-kernel-cdecl-epilogue-symbolic-closure" and
      .status == "typed-interface-ready" and
      (.proof_authority | not) and
      .failure_mode == "incomplete" and
      .closed_premise_families == [
        "checked_stack_return_word",
        "preserved_cdecl_registers_and_stack_pop",
        "checked_write_footprint_disjointness"
      ] and
      .remaining_proof_premises == [
        "loaded_image_and_original_program_table_preservation",
        "environmental_typed_response_payload"
      ] and
      .theorem ==
        "StageA.GeneratedRelational.InterpreterKernelCdeclEpilogueSymbolicClosure.generatedKernelCDeclSymbolicClosureBindings" and
      .targets == [
        "GeneratedRelationalInterpreterKernelCdeclEpilogueSymbolicClosure"
      ]
    ' "$out/phase-manifest.json" >/dev/null
    test -s \
      "$out/interpreter-kernel-cdecl-epilogue-symbolic-closure.json"
    test -s \
      "$out/StageA/GeneratedRelationalInterpreterKernelCdeclEpilogueSymbolicClosure.lean"
  '';

  kernelCdeclEpilogueStaticPreservationLean = mkPhase
    "stage-a-gnu-hello-roundtrip-kernel-cdecl-epilogue-static-preservation-lean" [] ''
    ${python} ${driver} kernel-cdecl-epilogue-static-preservation \
      --candidate ${candidate}/candidate.exe \
      --symbolic-closure-plan \
        ${kernelCdeclEpilogueSymbolicClosureLean}/interpreter-kernel-cdecl-epilogue-symbolic-closure.json \
      --out "$out"
    jq -e '
      .phase == "compiled-kernel-cdecl-epilogue-static-preservation" and
      .status == "typed-interface-ready" and
      (.proof_authority | not) and
      .failure_mode == "incomplete" and
      .closed_premise_families == [
        "loaded_image_and_original_program_table_preservation"
      ] and
      .remaining_proof_premises == [
        "environmental_typed_response_payload"
      ] and
      .theorem ==
        "StageA.GeneratedRelational.InterpreterKernelCdeclEpilogueStaticPreservation.generatedKernelCDeclStaticPreservationBindings" and
      .targets == [
        "GeneratedRelationalInterpreterKernelCdeclEpilogueStaticPreservation"
      ]
    ' "$out/phase-manifest.json" >/dev/null
    test -s \
      "$out/interpreter-kernel-cdecl-epilogue-static-preservation.json"
    test -s \
      "$out/StageA/GeneratedRelationalInterpreterKernelCdeclEpilogueStaticPreservation.lean"
  '';

  kernelCdeclEpilogueExternalPayloadLean = mkPhase
    "stage-a-gnu-hello-roundtrip-kernel-cdecl-epilogue-external-payload-lean" [] ''
    ${python} ${driver} kernel-cdecl-epilogue-external-payload \
      --candidate ${candidate}/candidate.exe \
      --static-preservation-plan \
        ${kernelCdeclEpilogueStaticPreservationLean}/interpreter-kernel-cdecl-epilogue-static-preservation.json \
      --out "$out"
    jq -e '
      .phase == "compiled-kernel-cdecl-epilogue-external-payload" and
      .status == "typed-interface-ready" and
      (.proof_authority | not) and
      .failure_mode == "incomplete" and
      .closed_premise_families == [
        "environmental_typed_response_payload"
      ] and
      .remaining_proof_premises == [
        "exact_abstract_operation_transition",
        "exact_operation_result_encoding",
        "checked_one_to_one_external_response_trace"
      ] and
      .theorem ==
        "StageA.GeneratedRelational.InterpreterKernelCdeclEpilogueExternalPayload.generatedKernelCDeclExternalPayloadBindings" and
      .targets == [
        "GeneratedRelationalInterpreterKernelCdeclEpilogueExternalPayload"
      ]
    ' "$out/phase-manifest.json" >/dev/null
    test -s \
      "$out/interpreter-kernel-cdecl-epilogue-external-payload.json"
    test -s \
      "$out/StageA/GeneratedRelationalInterpreterKernelCdeclEpilogueExternalPayload.lean"
  '';

  kernelOperationResultEncodingLean = mkPhaseWithSource
    proofClosurePythonSource
    "stage-a-gnu-hello-roundtrip-kernel-operation-result-encoding-lean"
    [] ''
    ${python} ${proofClosureDriver} operation-result-encoding \
      --candidate ${candidate}/candidate.exe \
      --external-payload-plan \
        ${kernelCdeclEpilogueExternalPayloadLean}/interpreter-kernel-cdecl-epilogue-external-payload.json \
      --out "$out"
    jq -e '
      .phase == "compiled-kernel-operation-result-encoding" and
      .status == "source-ready" and
      (.proof_authority | not) and
      .failure_mode == "incomplete" and
      .remaining_proof_premises == [
        "exact_abstract_operation_transition",
        "interpreter_step_exact_result_words_and_engine_state",
        "run_function_exact_status_and_output_engine_state",
        "invoke_call_exact_status_and_output_engine_state",
        "checked_one_to_one_external_response_trace"
      ] and
      .targets == [
        "GeneratedRelationalInterpreterKernelOperationResultEncoding"
      ]
    ' "$out/phase-manifest.json" >/dev/null
    test -s "$out/interpreter-kernel-operation-result-encoding.json"
    test -s \
      "$out/StageA/GeneratedRelationalInterpreterKernelOperationResultEncoding.lean"
  '';

  kernelAbstractOperationTransitionLean = mkPhaseWithSource
    proofClosurePythonSource
    "stage-a-gnu-hello-roundtrip-kernel-abstract-operation-transition-lean"
    [] ''
    ${python} ${proofClosureDriver} abstract-operation-transition \
      --candidate ${candidate}/candidate.exe \
      --operation-result-plan \
        ${kernelOperationResultEncodingLean}/interpreter-kernel-operation-result-encoding.json \
      --out "$out"
    jq -e '
      .phase == "compiled-kernel-abstract-operation-transition" and
      .status == "source-ready" and
      (.proof_authority | not) and
      .failure_mode == "incomplete" and
      .remaining_proof_premises == [
        "interpreter_step_exact_result_words_and_engine_state",
        "run_function_exact_status_and_output_engine_state",
        "invoke_call_exact_status_and_output_engine_state",
        "checked_one_to_one_external_response_trace"
      ] and
      .targets == [
        "GeneratedRelationalInterpreterKernelAbstractOperationTransition"
      ]
    ' "$out/phase-manifest.json" >/dev/null
    test -s "$out/interpreter-kernel-abstract-operation-transition.json"
    test -s \
      "$out/StageA/GeneratedRelationalInterpreterKernelAbstractOperationTransition.lean"
  '';

  kernelInvokeOperationLean = mkPhase
    "stage-a-gnu-hello-roundtrip-kernel-invoke-operation-lean" [] ''
    ${python} ${driver} kernel-invoke-operation \
      --candidate ${candidate}/candidate.exe \
      --kernel-plan ${kernelLean}/interpreter-kernel-plan.json \
      --kernel-data-inventory ${kernelDataLean}/module-inventory.json \
      --abi-plan ${kernelAbiLean}/interpreter-kernel-abi-plan.json \
      --callback-plan \
        ${kernelCallbackLean}/interpreter-kernel-callback-plan.json \
      --invoke-native-plan \
        ${kernelInvokeNativeLean}/interpreter-kernel-invoke-native-plan.json \
      --out "$out"
    jq -e '
      .phase == "compiled-kernel-invoke-call-operation" and
      .status == "source-ready" and
      (.proof_authority | not) and
      .failure_mode == "incomplete" and
      .remaining_proof_premises == [
        "run_function_internal_and_indirect_frame_certificates",
        "external_helper_path_certificate_and_wrapper_completion",
        "external_environment_abi_frame_refinement",
        "internal_run_function_arm_composition",
        "indirect_callback_run_function_arm_composition"
      ] and
      .theorem ==
        "StageA.GeneratedRelational.InterpreterKernelInvokeOperation.generatedInvokeCallOperationRefinesUsing" and
      (.inputs | keys) == [
        "abi_plan",
        "callback_plan",
        "candidate",
        "invoke_native_plan",
        "kernel_data_inventory",
        "kernel_plan"
      ] and
      ([.inputs[]] | all(
        (.sha256 | test("^[0-9a-f]{64}$")) and
        (.path | length) > 0
      )) and
      .public_outputs.plan ==
        "interpreter-kernel-invoke-operation-plan.json" and
      .public_outputs.lean_module ==
        "StageA/GeneratedRelationalInterpreterKernelInvokeOperation.lean" and
      .public_outputs.module_resources == "module-resources.json" and
      .targets == ["GeneratedRelationalInterpreterKernelInvokeOperation"]
    ' "$out/phase-manifest.json" >/dev/null
    test -s "$out/interpreter-kernel-invoke-operation-plan.json"
    test -s \
      "$out/StageA/GeneratedRelationalInterpreterKernelInvokeOperation.lean"
    test -s "$out/module-resources.json"
  '';

  mixedCandidateAuthorityLean = mkPhase
    "stage-a-gnu-hello-roundtrip-mixed-candidate-authority-lean" [] ''
    ${python} ${driver} mixed-candidate-authority \
      --kernel-data-inventory ${kernelDataLean}/module-inventory.json \
      --out "$out"
  '';

  constructiveSourceCoverageLean = mkPhaseWithSource
    constructiveSourceCoveragePythonSource
    "stage-a-gnu-hello-roundtrip-constructive-source-coverage-lean" [] ''
    ${python} ${constructiveSourceCoverageDriver} \
      --mixed-original-plan \
        ${mixedOriginalLean}/interpreter-mixed-original-plan.json \
      --static-reachability-plan \
        ${mixedOriginalStaticReachabilityLean}/interpreter-mixed-original-static-reachability.json \
      --kernel-data-inventory ${kernelDataLean}/module-inventory.json \
      --kernel-plan ${kernelLean}/interpreter-kernel-plan.json \
      --out "$out"
    jq -e '
      .format == "stage-a-gnu-hello-constructive-source-coverage-v1" and
      .phase == "constructive-source-coverage" and
      .status == "source-ready" and
      (.acceptance_authority | not) and
      .failure_mode == "incomplete" and
      (.candidate_sha256 | test("^[0-9a-f]{64}$")) and
      (.state_machine_sha256 | test("^[0-9a-f]{64}$")) and
      .counts.candidate_records >= .counts.reachable_targets and
      .targets == [
        "GeneratedGnuHelloConstructiveSourceCoverageBindings",
        "GeneratedRelationalInterpreterMixedSourceCoverage",
        "GeneratedGnuHelloConstructiveSourceRules"
      ]
    ' "$out/phase-manifest.json" >/dev/null
    test -s "$out/StageA/GeneratedGnuHelloConstructiveSourceCoverageBindings.lean"
    test -s "$out/StageA/GeneratedRelationalInterpreterMixedSourceCoverage.lean"
    test -s "$out/StageA/GeneratedGnuHelloConstructiveSourceRules.lean"
  '';

  constructiveSourceCoverageProofSources = mkPhase
    "stage-a-gnu-hello-roundtrip-constructive-source-coverage-proof-sources" [] ''
    ${aggregatePython} ${proofSourceAggregateDriver} \
      --source ${leanSourceRoot} \
      --source ${originalPeLean} \
      --source ${staticMachineImportContractsLean} \
      --source ${mixedOriginalWritableSlotAuthorityLean} \
      --source ${mixedOriginalRegisterIndirectAuthorityLean} \
      --source ${mixedOriginalDirectCallProposalsLean} \
      --source ${mixedOriginalDirectCallSemanticsLean} \
      --source ${mixedOriginalDirectCallClosureProposalsLean} \
      --source ${mixedOriginalDirectCallClosureSemanticsLean} \
      --source ${mixedOriginalLean} \
      --source ${mixedOriginalStaticReachabilityLean} \
      --source ${kernelDataLean} \
      --source ${kernelLean} \
      --source ${mixedCandidateAuthorityLean} \
      --source ${constructiveSourceCoverageLean} \
      --target GeneratedGnuHelloConstructiveSourceRules \
      --out "$out"
  '';
  constructiveSourceCoverageProofModules = builtins.fromJSON (
    builtins.readFile
      "${constructiveSourceCoverageProofSources}/standalone-modules.json"
  );
  constructiveSourceCoverageProofResources = builtins.fromJSON (
    builtins.readFile
      "${constructiveSourceCoverageProofSources}/module-resources.json"
  );
  constructiveSourceCoverageProof = mkLeanGraph {
    inherit pkgs;
    contentAddressed = true;
    standaloneSourceRoot = constructiveSourceCoverageProofSources + "/StageA";
    standaloneModules = constructiveSourceCoverageProofModules;
    standaloneModuleResources = constructiveSourceCoverageProofResources;
    targetNodes = [ "GeneratedGnuHelloConstructiveSourceRules" ];
    targetBundle = true;
    targetAxiomAudit = {
      module = "GeneratedGnuHelloConstructiveSourceRules";
      declaration =
        "StageA.GeneratedRelational.GnuHelloConstructiveSourceRules.generatedRulesTargetIds";
      approved_axioms = [ "propext" "Classical.choice" "Quot.sound" ];
    };
  };

  canonicalRelationCoreLean = mkPhaseWithSource
    canonicalRelationCorePythonSource
    "stage-a-gnu-hello-roundtrip-canonical-relation-core-lean" [] ''
    ${python} ${canonicalRelationCoreDriver} \
      --mixed-original-plan \
        ${mixedOriginalLean}/interpreter-mixed-original-plan.json \
      --static-reachability-plan \
        ${mixedOriginalStaticReachabilityLean}/interpreter-mixed-original-static-reachability.json \
      --kernel-data-inventory ${kernelDataLean}/module-inventory.json \
      --out "$out"
    jq -e '
      .format == "stage-a-gnu-hello-canonical-relation-core-v1" and
      .phase == "canonical-relation-core" and
      .status == "source-ready" and
      (.acceptance_authority | not) and
      .failure_mode == "incomplete" and
      (.candidate_sha256 | test("^[0-9a-f]{64}$")) and
      (.state_machine_sha256 | test("^[0-9a-f]{64}$")) and
      .outputs.binding_module ==
        "StageA/GeneratedGnuHelloCanonicalRelationCoreBindings.lean" and
      .outputs.core_module ==
        "StageA/GeneratedGnuHelloCanonicalRelationCore.lean"
    ' "$out/phase-manifest.json" >/dev/null
    test -s "$out/interpreter-mixed-relation-core-plan.json"
    test -s \
      "$out/StageA/GeneratedGnuHelloCanonicalRelationCoreBindings.lean"
    test -s "$out/StageA/GeneratedGnuHelloCanonicalRelationCore.lean"
  '';

  canonicalRelationCoreProofSources = mkPhase
    "stage-a-gnu-hello-roundtrip-canonical-relation-core-proof-sources" [] ''
    ${aggregatePython} ${proofSourceAggregateDriver} \
      --source ${leanSourceRoot} \
      --source ${originalPeLean} \
      --source ${staticMachineImportContractsLean} \
      --source ${mixedOriginalWritableSlotAuthorityLean} \
      --source ${mixedOriginalRegisterIndirectAuthorityLean} \
      --source ${mixedOriginalDirectCallProposalsLean} \
      --source ${mixedOriginalDirectCallSemanticsLean} \
      --source ${mixedOriginalDirectCallClosureProposalsLean} \
      --source ${mixedOriginalDirectCallClosureSemanticsLean} \
      --source ${mixedOriginalLean} \
      --source ${mixedOriginalStaticReachabilityLean} \
      --source ${mixedOriginalCarrierBindingLean} \
      --source ${kernelDataLean} \
      --source ${kernelLean} \
      --source ${kernelAbiLean} \
      --source ${mixedCandidateAuthorityLean} \
      --source ${canonicalRelationCoreLean} \
      --target GeneratedGnuHelloCanonicalRelationCore \
      --out "$out"
  '';
  canonicalRelationCoreProofModules = builtins.fromJSON (
    builtins.readFile
      "${canonicalRelationCoreProofSources}/standalone-modules.json"
  );
  canonicalRelationCoreProofResources = builtins.fromJSON (
    builtins.readFile
      "${canonicalRelationCoreProofSources}/module-resources.json"
  );
  canonicalRelationCoreProof = mkLeanGraph {
    inherit pkgs;
    contentAddressed = true;
    standaloneSourceRoot = canonicalRelationCoreProofSources + "/StageA";
    standaloneModules = canonicalRelationCoreProofModules;
    standaloneModuleResources = canonicalRelationCoreProofResources;
    targetNodes = [ "GeneratedGnuHelloCanonicalRelationCore" ];
    targetBundle = true;
    targetAxiomAudit = {
      module = "GeneratedGnuHelloCanonicalRelationCore";
      declaration =
        "StageA.GeneratedRelational.GnuHelloCanonicalRelationCore.generatedCanonicalMixedRelationCore";
      approved_axioms = [ "propext" "Classical.choice" "Quot.sound" ];
    };
  };

  proofSources = mkPhase "stage-a-gnu-hello-roundtrip-proof-sources" [] ''
    ${aggregatePython} ${proofSourceAggregateDriver} \
      --source ${leanSourceRoot} \
      --source ${originalPeLean} \
      --source ${staticMachineImportContractsLean} \
      --source ${universalPairedExternalEnvironmentLean} \
      --source ${mixedOriginalWritableSlotAuthorityLean} \
      --source ${mixedOriginalRegisterIndirectAuthorityLean} \
      --source ${mixedOriginalDirectCallProposalsLean} \
      --source ${mixedOriginalDirectCallSemanticsLean} \
      --source ${mixedOriginalDirectCallClosureProposalsLean} \
      --source ${mixedOriginalDirectCallClosureSemanticsLean} \
      --source ${mixedOriginalStackDynamicAuthorityLean} \
      --source ${mixedOriginalLean} \
      --source ${mixedOriginalStaticReachabilityLean} \
      --source ${mixedOriginalCarrierBindingLean} \
      --source ${programLean} \
      --source ${normalizationLean} \
      --source ${semanticRefinementLean} \
      --source ${x87Lean} \
      --source ${definednessLean} \
      --source ${kernelLean} \
      --source ${kernelDataLean} \
      --source ${kernelAbiLean} \
      --source ${x87CandidateReplayLean} \
      --source ${x87ReplayBridgeTargetLean} \
      --source ${x87ReplayBridgeRuntimeLean} \
      --source ${x87KernelExecutionLean} \
      --source ${kernelBlockLean} \
      --source ${kernelLoopLean} \
      --source ${kernelCallbackLean} \
      --source ${kernelLookupLean} \
      --source ${kernelLookupNativeLean} \
      --source ${kernelLookupOperationLean} \
      --source ${kernelStepLean} \
      --source ${kernelStepNativeLean} \
      --source ${kernelRunLean} \
      --source ${kernelRunNativeLean} \
      --source ${kernelInvokeLean} \
      --source ${kernelInvokeNativeLean} \
      --source ${kernelStepOperationLean} \
      --source ${kernelStepProgramLookupCallLean} \
      --source ${kernelStepProgramLookupCallClosureLean} \
      --source ${kernelStepProgramLookupExactComputationLean} \
      --source ${kernelOperationFrameParametricLean} \
      --source ${kernelFrameExecutorLean} \
      --source ${kernelRunOperationLean} \
      --source ${kernelCdeclEpilogueLean} \
      --source ${kernelCdeclEpilogueSymbolicClosureLean} \
      --source ${kernelCdeclEpilogueStaticPreservationLean} \
      --source ${kernelCdeclEpilogueExternalPayloadLean} \
      --source ${kernelOperationResultEncodingLean} \
      --source ${kernelAbstractOperationTransitionLean} \
      --source ${kernelInvokeOperationLean} \
      --source ${mixedCandidateAuthorityLean} \
      --source ${nativeLaunchGraphLean} \
      --source ${constructiveSourceCoverageLean} \
      --source ${canonicalRelationCoreLean} \
      --target RelationalSymbolicSoundness \
      --out "$out"
  '';

  # The generated module inventory is intentionally discovered from immutable
  # phase outputs.  IFD is limited to this manifest boundary; each resulting
  # Lean module is still an independent, remote-buildable derivation.
  proofModules = builtins.fromJSON (
    builtins.readFile "${proofSources}/standalone-modules.json"
  );
  proofTargets = builtins.fromJSON (
    builtins.readFile "${proofSources}/proof-targets.json"
  );
  proofResources = builtins.fromJSON (
    builtins.readFile "${proofSources}/module-resources.json"
  );
  proofFragments = mkLeanGraph {
    inherit pkgs;
    contentAddressed = true;
    standaloneSourceRoot = proofSources + "/StageA";
    standaloneModules = proofModules;
    standaloneModuleResources = proofResources;
    targetNodes = proofTargets;
    targetBundle = true;
  };

  kernelRunOperationProof = mkLeanGraph {
    inherit pkgs;
    contentAddressed = true;
    standaloneSourceRoot = proofSources + "/StageA";
    standaloneModules = proofModules;
    standaloneModuleResources = proofResources;
    targetNodes = [
      "GeneratedRelationalInterpreterKernelRunOperation"
    ];
    targetBundle = true;
    targetAxiomAudit = {
      module = "GeneratedRelationalInterpreterKernelRunOperation";
      declaration =
        "StageA.GeneratedRelational.InterpreterKernelRunOperation.generatedRunFunctionOperationRefinesUsing";
      approved_axioms = [ "propext" "Classical.choice" "Quot.sound" ];
    };
  };

  # Keep the exact call and epilogue closures independently buildable. They
  # share the generated source inventory, while Nix compiles only each
  # target's transitive Lean dependency closure.
  kernelStepProgramLookupCallClosureProof = mkLeanGraph {
    inherit pkgs;
    contentAddressed = true;
    standaloneSourceRoot = proofSources + "/StageA";
    standaloneModules = proofModules;
    standaloneModuleResources = proofResources;
    targetNodes = [
      "GeneratedRelationalInterpreterKernelStepProgramLookupCallClosure"
    ];
    targetBundle = true;
  };

  kernelCdeclEpilogueSymbolicClosureProof = mkLeanGraph {
    inherit pkgs;
    contentAddressed = true;
    standaloneSourceRoot = proofSources + "/StageA";
    standaloneModules = proofModules;
    standaloneModuleResources = proofResources;
    targetNodes = [
      "GeneratedRelationalInterpreterKernelCdeclEpilogueSymbolicClosure"
    ];
    targetBundle = true;
  };

  kernelCdeclEpilogueStaticPreservationProof = mkLeanGraph {
    inherit pkgs;
    contentAddressed = true;
    standaloneSourceRoot = proofSources + "/StageA";
    standaloneModules = proofModules;
    standaloneModuleResources = proofResources;
    targetNodes = [
      "GeneratedRelationalInterpreterKernelCdeclEpilogueStaticPreservation"
    ];
    targetBundle = true;
  };

  kernelCdeclEpilogueExternalPayloadProof = mkLeanGraph {
    inherit pkgs;
    contentAddressed = true;
    standaloneSourceRoot = proofSources + "/StageA";
    standaloneModules = proofModules;
    standaloneModuleResources = proofResources;
    targetNodes = [
      "GeneratedRelationalInterpreterKernelCdeclEpilogueExternalPayload"
    ];
    targetBundle = true;
  };

  kernelStepProgramLookupExactComputationProof = mkLeanGraph {
    inherit pkgs;
    contentAddressed = true;
    standaloneSourceRoot = proofSources + "/StageA";
    standaloneModules = proofModules;
    standaloneModuleResources = proofResources;
    targetNodes = [
      "GeneratedRelationalInterpreterKernelStepProgramLookupExactComputation"
    ];
    targetBundle = true;
  };

  kernelOperationResultEncodingProof = mkLeanGraph {
    inherit pkgs;
    contentAddressed = true;
    standaloneSourceRoot = proofSources + "/StageA";
    standaloneModules = proofModules;
    standaloneModuleResources = proofResources;
    targetNodes = [
      "GeneratedRelationalInterpreterKernelOperationResultEncoding"
    ];
    targetBundle = true;
  };

  kernelAbstractOperationTransitionProof = mkLeanGraph {
    inherit pkgs;
    contentAddressed = true;
    standaloneSourceRoot = proofSources + "/StageA";
    standaloneModules = proofModules;
    standaloneModuleResources = proofResources;
    targetNodes = [
      "GeneratedRelationalInterpreterKernelAbstractOperationTransition"
    ];
    targetBundle = true;
  };

  # Qualify the ordinary transfer inventory independently of unrelated kernel,
  # callback, x87, and acceptance frontiers.  It shares the same generated
  # source DAG and therefore the same cached .olean dependencies.
  ordinaryRefinementFragments = mkLeanGraph {
    inherit pkgs;
    contentAddressed = true;
    standaloneSourceRoot = proofSources + "/StageA";
    standaloneModules = proofModules;
    standaloneModuleResources = proofResources;
    targetNodes = [ "GeneratedInterpreterSemanticRefinementBundle" ];
    targetBundle = true;
  };

  x87CandidateReplayProofSources = mkPhase
    "stage-a-gnu-hello-roundtrip-x87-candidate-replay-proof-sources" [] ''
    ${aggregatePython} ${proofSourceAggregateDriver} \
      --source ${leanSourceRoot} \
      --source ${originalPeLean} \
      --source ${x87Lean} \
      --source ${kernelDataLean} \
      --source ${x87CandidateReplayLean} \
      --target GeneratedInterpreterX87CandidateReplayBundle \
      --out "$out"
  '';
  x87CandidateReplayProofModules = builtins.fromJSON (
    builtins.readFile
      "${x87CandidateReplayProofSources}/standalone-modules.json"
  );
  x87CandidateReplayProofResources = builtins.fromJSON (
    builtins.readFile
      "${x87CandidateReplayProofSources}/module-resources.json"
  );
  x87CandidateReplayFragments = mkLeanGraph {
    inherit pkgs;
    contentAddressed = true;
    standaloneSourceRoot = x87CandidateReplayProofSources + "/StageA";
    standaloneModules = x87CandidateReplayProofModules;
    standaloneModuleResources = x87CandidateReplayProofResources;
    targetNodes = [ "GeneratedInterpreterX87CandidateReplayBundle" ];
    targetBundle = true;
  };

  x87ReplayBridgeTargetProofSources = mkPhase
    "stage-a-gnu-hello-roundtrip-x87-replay-bridge-target-proof-sources" [] ''
    ${aggregatePython} ${proofSourceAggregateDriver} \
      --source ${leanSourceRoot} \
      --source ${kernelDataLean} \
      --source ${x87ReplayBridgeTargetLean} \
      --target GeneratedRelationalInterpreterX87ReplayBridgeTarget \
      --out "$out"
  '';

  x87ReplayBridgeRuntimeProofSources = mkPhase
    "stage-a-gnu-hello-roundtrip-x87-replay-bridge-runtime-proof-sources" [] ''
    ${aggregatePython} ${proofSourceAggregateDriver} \
      --source ${leanSourceRoot} \
      --source ${kernelDataLean} \
      --source ${x87ReplayBridgeTargetLean} \
      --source ${x87ReplayBridgeRuntimeLean} \
      --target GeneratedRelationalInterpreterX87ReplayBridgeRuntime \
      --out "$out"
  '';
  x87ReplayBridgeRuntimeProofModules = builtins.fromJSON (
    builtins.readFile
      "${x87ReplayBridgeRuntimeProofSources}/standalone-modules.json"
  );
  x87ReplayBridgeRuntimeProofResources = builtins.fromJSON (
    builtins.readFile
      "${x87ReplayBridgeRuntimeProofSources}/module-resources.json"
  );
  x87ReplayBridgeRuntimeFragments = mkLeanGraph {
    inherit pkgs;
    contentAddressed = true;
    standaloneSourceRoot = x87ReplayBridgeRuntimeProofSources + "/StageA";
    standaloneModules = x87ReplayBridgeRuntimeProofModules;
    standaloneModuleResources = x87ReplayBridgeRuntimeProofResources;
    targetNodes = [ "GeneratedRelationalInterpreterX87ReplayBridgeRuntime" ];
    targetBundle = true;
  };

  x87KernelExecutionProofSources = mkPhase
    "stage-a-gnu-hello-roundtrip-x87-kernel-execution-proof-sources" [] ''
    ${aggregatePython} ${proofSourceAggregateDriver} \
      --source ${leanSourceRoot} \
      --source ${kernelDataLean} \
      --source ${x87ReplayBridgeTargetLean} \
      --source ${x87ReplayBridgeRuntimeLean} \
      --source ${x87KernelExecutionLean} \
      --target GeneratedRelationalInterpreterKernelX87Execution \
      --out "$out"
  '';
  x87KernelExecutionProofModules = builtins.fromJSON (
    builtins.readFile
      "${x87KernelExecutionProofSources}/standalone-modules.json"
  );
  x87KernelExecutionProofResources = builtins.fromJSON (
    builtins.readFile
      "${x87KernelExecutionProofSources}/module-resources.json"
  );
  x87KernelExecutionFragments = mkLeanGraph {
    inherit pkgs;
    contentAddressed = true;
    standaloneSourceRoot = x87KernelExecutionProofSources + "/StageA";
    standaloneModules = x87KernelExecutionProofModules;
    standaloneModuleResources = x87KernelExecutionProofResources;
    targetNodes = [ "GeneratedRelationalInterpreterKernelX87Execution" ];
    targetBundle = true;
  };

  acceptanceLean = mkPhase "stage-a-gnu-hello-roundtrip-acceptance-lean" [] ''
    ${python} ${driver} acceptance-sources \
      --kernel-block-manifest ${kernelBlockLean}/phase-manifest.json \
      --mixed-original-manifest ${mixedOriginalLean}/phase-manifest.json \
      --original-carrier-manifest \
        ${mixedOriginalCarrierBindingLean}/phase-manifest.json \
      --native-launch-request \
        ${nativeLaunchRequest}/native-launch-route-request.json \
      --x87-kernel-execution-manifest \
        ${x87KernelExecutionLean}/phase-manifest.json \
      --out "$out"
    jq -e --argjson runtimeCount \
      "$(jq '.runtime_targets' \
        ${x87KernelExecutionLean}/phase-manifest.json)" '
      .phase == "whole-program-acceptance-lean" and
      .status == "proof-obligations-generated" and
      .diagnostic_status == "incomplete" and
      .acceptance_theorem == null and
      (.counts.remaining_original_control_frontiers > 0) and
      ([.semantic_blockers[].id] | index(
        "exact_candidate_native_launch_wrapper_missing") != null) and
      ([.semantic_blockers[].id] | index(
        "universal_paired_environment_refinement_missing") != null) and
      ([.semantic_blockers[].id] | index(
        "x87_replay_kernel_execution_premises_missing") != null) and
      .counts.remaining_x87_kernel_execution_premises == 11 and
      .counts.x87_runtime_targets == $runtimeCount
    ' "$out/phase-manifest.json" >/dev/null
  '';

  finalProofSources = mkPhase "stage-a-gnu-hello-roundtrip-final-proof-sources" [] ''
    ${aggregatePython} ${proofSourceAggregateDriver} \
      --source ${proofSources} \
      --source ${acceptanceLean} \
      --out "$out"
  '';
  finalProofModules = builtins.fromJSON (
    builtins.readFile "${finalProofSources}/standalone-modules.json"
  );
  finalProofTargets = builtins.fromJSON (
    builtins.readFile "${finalProofSources}/proof-targets.json"
  );
  finalProofResources = builtins.fromJSON (
    builtins.readFile "${finalProofSources}/module-resources.json"
  );
  final = mkLeanGraph {
    inherit pkgs;
    contentAddressed = true;
    standaloneSourceRoot = finalProofSources + "/StageA";
    standaloneModules = finalProofModules;
    standaloneModuleResources = finalProofResources;
    targetNodes = finalProofTargets;
    targetBundle = true;
  };

  proofReport = mkPhase "stage-a-gnu-hello-roundtrip-proof-report" [] ''
    mkdir -p "$out"
    ln -s ${proofFragments} "$out/lean-fragments"
    ln -s ${proofSources} "$out/proof-sources"
    ln -s ${engineSegments} "$out/engine-segments"
    ln -s ${acceptanceLean} "$out/acceptance-source"
    ${python} - "$out/proof-result.json" \
      ${proofSources}/phase-manifest.json \
      ${proofFragments}/bundle.json \
      ${acceptanceLean}/phase-manifest.json <<'PY'
    import json, pathlib, sys
    sources = json.loads(pathlib.Path(sys.argv[2]).read_text(encoding="utf-8"))
    bundle = json.loads(pathlib.Path(sys.argv[3]).read_text(encoding="utf-8"))
    acceptance = json.loads(pathlib.Path(sys.argv[4]).read_text(encoding="utf-8"))
    result = {
      "format": "stage-a-gnu-hello-roundtrip-proof-result-v1",
      "status": "incomplete",
      "acceptance_authority": False,
      "executes_original_binary": False,
      "executes_candidate_binary": False,
      "compiled_modules": len(bundle["nodes"]),
      "generated_modules": sources["counts"]["modules"],
      "frontiers": acceptance["semantic_blockers"],
    }
    pathlib.Path(sys.argv[1]).write_text(
      json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    PY
  '';

in
{
  inherit
    smoke
    staticExport
    interpreter
    nativeEngine
    nativeRuntime
    candidate
    nativeLaunchRequest
    engineSegments
    nativeLaunchGraphLean
    nativeLaunchGraphProofSources
    nativeLaunchGraphProof
    originalPeLean
    staticMachineImportContractsLean
    universalPairedExternalEnvironmentLean
    staticMachineImportProofSources
    staticMachineImportProof
    mixedOriginalDiagnostic
    mixedOriginalBaseLean
    mixedOriginalWritableSlotAuthorityLean
    mixedOriginalRegisterIndirectAuthorityLean
    mixedOriginalRegisterIndirectAuthorityProofSources
    mixedOriginalRegisterIndirectAuthorityProof
    mixedOriginalDirectCallProposalsLean
    mixedOriginalDirectCallProposalProofSources
    mixedOriginalDirectCallProposalProof
    mixedOriginalDirectCallSemanticsLean
    mixedOriginalDirectCallSemanticsProofSources
    mixedOriginalDirectCallSemanticsProof
    mixedOriginalDirectCallClosureProposalsLean
    mixedOriginalDirectCallClosureProposalProofSources
    mixedOriginalDirectCallClosureProposalProof
    mixedOriginalDirectCallClosureSemanticsLean
    mixedOriginalDirectCallClosureSemanticsProofSources
    mixedOriginalDirectCallClosureSemanticsProof
    mixedOriginalDirectCallFixedPointProposalsLean
    mixedOriginalDirectCallFixedPointSemanticsLean
    mixedOriginalDirectCallFixedPointCheck
    mixedOriginalStackDynamicAuthorityLean
    mixedOriginalStackDynamicAuthorityProofSources
    mixedOriginalStackDynamicAuthorityProof
    mixedOriginalLean
    mixedOriginalStaticReachabilityLean
    mixedOriginalStaticReachabilityProofSources
    mixedOriginalStaticReachabilityProof
    mixedOriginalCarrierBindingLean
    mixedOriginalCarrierBindingProofSources
    mixedOriginalCarrierBindingProof
    programLean
    normalizationLean
    semanticRefinementLean
    x87Lean
    x87ScheduleBenchmarkSources
    x87ScheduleBenchmark
    definednessLean
    kernelLean
    kernelDataLean
    kernelAbiLean
    x87CandidateReplayLean
    x87ReplayBridgeTargetLean
    x87ReplayBridgeRuntimeLean
    x87KernelExecutionLean
    kernelBlockLean
    kernelLoopLean
    kernelCallbackLean
    kernelLookupLean
    kernelLookupNativeLean
    kernelLookupOperationLean
    kernelStepLean
    kernelStepNativeLean
    kernelRunLean
    kernelRunNativeLean
    kernelRunNativeProofSources
    kernelRunNativeProof
    kernelRunOperationLean
    kernelRunOperationProof
    kernelCdeclEpilogueLean
    kernelCdeclEpilogueSymbolicClosureLean
    kernelCdeclEpilogueSymbolicClosureProof
    kernelCdeclEpilogueStaticPreservationLean
    kernelCdeclEpilogueStaticPreservationProof
    kernelCdeclEpilogueExternalPayloadLean
    kernelCdeclEpilogueExternalPayloadProof
    kernelOperationResultEncodingLean
    kernelOperationResultEncodingProof
    kernelAbstractOperationTransitionLean
    kernelAbstractOperationTransitionProof
    kernelInvokeLean
    kernelInvokeNativeLean
    kernelInvokeOperationLean
    kernelStepOperationLean
    kernelStepProgramLookupCallLean
    kernelStepProgramLookupCallClosureLean
    kernelStepProgramLookupCallClosureProof
    kernelStepProgramLookupExactComputationLean
    kernelStepProgramLookupExactComputationProof
    kernelOperationFrameParametricLean
    kernelFrameExecutorLean
    mixedCandidateAuthorityLean
    constructiveSourceCoverageLean
    constructiveSourceCoverageProofSources
    constructiveSourceCoverageProof
    canonicalRelationCoreLean
    canonicalRelationCoreProofSources
    canonicalRelationCoreProof
    proofSources
    proofFragments
    ordinaryRefinementFragments
    x87CandidateReplayFragments
    x87CandidateReplayProofSources
    x87ReplayBridgeTargetProofSources
    x87ReplayBridgeRuntimeProofSources
    x87ReplayBridgeRuntimeFragments
    x87KernelExecutionProofSources
    x87KernelExecutionFragments
    acceptanceLean
    finalProofSources
    proofReport
    final
    ;
}
