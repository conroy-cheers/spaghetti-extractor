# spaghetti-extractor-python-role: authority
{
  pkgs,
  pythonEnv,
  kernelCache,
  binary,
  machineIr,
  namePrefix,
}:

let
  phase = import ./ca-python-json-phase.nix {
    inherit pkgs pythonEnv;
    name = "${namePrefix}-semantic-isa-requirements-v2";
    kind = "semantic-isa-requirements";
    artifactName = "machine-ir-isa-requirements.json";
    expectedFormat = "spaghetti-extractor-machine-ir-isa-requirements-v2";
    allowedStatuses = [ "complete" "incomplete" "violated" ];
    pythonModules = [
      "spaghetti_extractor.extraction.isa_requirements"
      "spaghetti_extractor.qualified_platform.requirements"
    ];
    pythonExtraPaths = [ "spaghetti_extractor/lean/SpaghettiExtractor/ISA" ];
    phaseRole = "authority";
    extraNativeBuildInputs = [ pkgs.lean4 ];
    inputs = {
      binary = binary;
      machine_ir = machineIr;
      kernel_cache = kernelCache;
    };
    program = ''
      import os

      from spaghetti_extractor.extraction.isa_requirements import (
          extract_lean_instruction_forms_side,
      )
      from spaghetti_extractor.qualified_platform.requirements import (
          build_machine_ir_isa_extraction_request_v2,
          build_machine_ir_isa_requirements_v2,
          parse_machine_ir_isa_requirements_v2,
      )
      from spaghetti_extractor.util import sha256_file, write_json

      os.environ["SPAGHETTI_LEAN_KERNEL_CACHE"] = str(inputs["kernel_cache"])
      units = [
          json.loads(line)
          for line in inputs["machine_ir"].read_text(
              encoding="utf-8"
          ).splitlines()
          if line.strip()
      ]
      request = build_machine_ir_isa_extraction_request_v2(
          units=units,
          binary_sha256=sha256_file(inputs["binary"]),
          include_structural_universe=True,
      )
      rows, evidence = extract_lean_instruction_forms_side(
          binary=inputs["binary"],
          request=request,
          timeout_seconds=1800,
          allow_decode_gaps=True,
      )
      requirements = build_machine_ir_isa_requirements_v2(
          request=request,
          machine_ir_sha256=sha256_file(inputs["machine_ir"]),
          lean_rows=rows,
          lean_evidence=evidence,
          lean_gaps=evidence.get("decode_gaps", []),
      )
      parse_machine_ir_isa_requirements_v2(requirements)
      write_json(output, requirements)
    '';
  };
in
{
  inherit (phase) derivation manifest artifact phasePythonSource;
}
