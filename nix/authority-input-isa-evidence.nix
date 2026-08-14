{
  pkgs,
  pythonEnv,
  pythonSource,
  isaPythonSource,
  kernelCache,
  semanticKernel,
  bochsRunner,
  name,
  binary,
  machineIr,
  semanticIndex,
  contentAddressed ? true,
}:

let
  lib = pkgs.lib;
  caAttrs = lib.optionalAttrs contentAddressed { __contentAddressed = true; };
  requirementsPythonSource = import ./python-module-closure.nix {
    inherit pkgs;
    source = isaPythonSource;
    modules = [
      "spaghetti_extractor.extraction.isa_requirements"
      "spaghetti_extractor.machine_ir_isa_requirements_v2"
    ];
    extraPaths = [ "spaghetti_extractor/lean/StageA" ];
    name = "${name}-requirements-python-closure";
  };
  requirements = pkgs.runCommand "${name}-requirements" (
    {
      nativeBuildInputs = [ pythonEnv pkgs.lean4 pkgs.jq ];
      preferLocalBuild = false;
      allowSubstitutes = true;
    }
    // caAttrs
  ) ''
    set -euo pipefail
    export PYTHONHASHSEED=0
    export PYTHONDONTWRITEBYTECODE=1
    export LC_ALL=C.UTF-8
    export SOURCE_DATE_EPOCH=1
    export SPAGHETTI_ORIGINAL_EXECUTION_FORBIDDEN=1
    export SPAGHETTI_LEAN_KERNEL_CACHE=${kernelCache}
    export PYTHONPATH=${requirementsPythonSource}/src
    mkdir -p "$out"

    ${pythonEnv}/bin/python3 - \
      ${lib.escapeShellArg (toString binary)} \
      ${lib.escapeShellArg (toString machineIr)} \
      "$out/requirements.json" <<'PY'
    import json
    import pathlib
    import sys

    from spaghetti_extractor.extraction.isa_requirements import (
        extract_lean_instruction_forms_side,
    )
    from spaghetti_extractor.machine_ir_isa_requirements_v2 import (
        build_machine_ir_isa_extraction_request_v2,
        build_machine_ir_isa_requirements_v2,
    )
    from spaghetti_extractor.util import sha256_file

    binary, machine_ir, output = map(pathlib.Path, sys.argv[1:])
    units = [
        json.loads(line)
        for line in machine_ir.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    request = build_machine_ir_isa_extraction_request_v2(
        units=units,
        binary_sha256=sha256_file(binary),
        include_structural_universe=True,
    )
    rows, evidence = extract_lean_instruction_forms_side(
        binary=binary,
        request=request,
        timeout_seconds=1800,
        allow_decode_gaps=True,
    )
    requirements = build_machine_ir_isa_requirements_v2(
        request=request,
        machine_ir_sha256=sha256_file(machine_ir),
        lean_rows=rows,
        lean_evidence=evidence,
        lean_gaps=evidence.get("decode_gaps", []),
    )
    output.write_text(
        json.dumps(requirements, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    PY

    jq -e '
      .format == "spaghetti-extractor-machine-ir-isa-requirements-v2" and
      (.status == "complete" or .status == "incomplete" or .status == "violated") and
      (.requirements_sha256 | test("^[0-9a-f]{64}$")) and
      .counts.regions == (.occurrences | length)
    ' "$out/requirements.json" >/dev/null
  '';
  qualification = import ./stage-a-machine-ir-isa-qualification-v2.nix {
    inherit
      pkgs
      pythonEnv
      isaPythonSource
      kernelCache
      semanticKernel
      bochsRunner
      ;
    pythonSource = pythonSource;
    requirements = "${requirements}/requirements.json";
    name = "${name}-qualification";
  };
  projectionPythonSource = import ./python-module-closure.nix {
    inherit pkgs;
    source = pythonSource;
    modules = [ "spaghetti_extractor.authority_inputs.isa_evidence" ];
    name = "${name}-projection-python-closure";
  };
  projection = pkgs.runCommand "${name}-projection" (
    {
      nativeBuildInputs = [ pythonEnv pkgs.jq ];
      preferLocalBuild = false;
      allowSubstitutes = true;
    }
    // caAttrs
  ) ''
    set -euo pipefail
    export PYTHONHASHSEED=0
    export PYTHONDONTWRITEBYTECODE=1
    export LC_ALL=C.UTF-8
    export SOURCE_DATE_EPOCH=1
    export SPAGHETTI_ORIGINAL_EXECUTION_FORBIDDEN=1
    export PYTHONPATH=${projectionPythonSource}/src

    ${pythonEnv}/bin/python3 -m spaghetti_extractor.authority_inputs.isa_evidence \
      --requirements ${requirements}/requirements.json \
      --selection-authority ${qualification.selectionAuthority.artifact} \
      --semantic-index ${semanticIndex} \
      --out "$out"

    jq -e '
      .format == "spaghetti-extractor-isa-evidence-projection-v3" and
      (.status == "complete" or .status == "incomplete") and
      .counts.evidence_records <= .counts.semantic_occurrences
    ' "$out/metadata.json" >/dev/null
  '';
  metadata = builtins.fromJSON (builtins.readFile "${projection}/metadata.json");
  frontiers = import ./authority-isa-frontiers.nix {
    inherit pkgs pythonEnv pythonSource;
    name = "${name}-frontiers";
    requirements = "${requirements}/requirements.json";
    selectionAuthority = qualification.selectionAuthority.artifact;
  };
in
assert metadata.format == "spaghetti-extractor-isa-evidence-projection-v3";
{
  inherit requirements qualification projection metadata frontiers;
  artifact = "${projection}/artifact";
}
