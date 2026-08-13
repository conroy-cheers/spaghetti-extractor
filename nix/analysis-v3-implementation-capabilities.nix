{
  pkgs,
  pythonEnv,
  pythonSource,
  machineIr,
  semanticIndex,
  isaQualification,
  interpreterPackage,
  fallbackCoverageReceipt ? null,
  namePrefix,
  capabilityId ? "machine-ir-fallback-v3",
  compiler ? pkgs.pkgsCross.mingw32.stdenv.cc,
}:

let
  lib = pkgs.lib;
  phasePythonSource = import ./python-module-closure.nix {
    inherit pkgs;
    source = pythonSource;
    modules = [
      "spaghetti_extractor.stage_a_implementation_capabilities_v3"
    ];
    name = "${namePrefix}-implementation-capabilities-python-closure";
  };
in
pkgs.runCommand "${namePrefix}-implementation-capabilities-v3" {
  nativeBuildInputs = [ pythonEnv compiler pkgs.jq pkgs.coreutils ];
  preferLocalBuild = false;
  allowSubstitutes = true;
  __contentAddressed = true;
} ''
  set -euo pipefail
  export PYTHONHASHSEED=0
  export LC_ALL=C.UTF-8
  export SOURCE_DATE_EPOCH=1
  export PYTHONPATH=${phasePythonSource}/src

  work="$TMPDIR/fallback-engine"
  mkdir -p "$work"
  ${compiler}/bin/i686-w64-mingw32-gcc \
    -std=c11 -Os -ffreestanding -fno-builtin \
    -I ${interpreterPackage} \
    -c ${interpreterPackage}/state-machine-interpreter.c \
    -o "$work/interpreter.o"
  ${compiler}/bin/i686-w64-mingw32-gcc \
    -std=c11 -Os -ffreestanding -fno-builtin \
    -I ${interpreterPackage} \
    -c ${interpreterPackage}/state-machine-program.c \
    -o "$work/program.o"

  receipt_args=()
  ${lib.optionalString (fallbackCoverageReceipt != null) ''
    receipt_args+=(
      --fallback-coverage-receipt
      ${fallbackCoverageReceipt}/fallback-coverage-receipt.json
    )
  ''}

  ${pythonEnv}/bin/python3 -m \
    spaghetti_extractor.stage_a_implementation_capabilities_v3 \
    --machine-ir ${machineIr}/machine-ir.jsonl \
    --machine-ir-manifest ${machineIr}/machine-ir-manifest.json \
    --semantic-index ${semanticIndex} \
    --isa-qualification ${isaQualification} \
    --interpreter-package ${interpreterPackage} \
    "''${receipt_args[@]}" \
    --implementation-file "interpreter-object=$work/interpreter.o" \
    --implementation-file "program-object=$work/program.o" \
    --capability-id ${lib.escapeShellArg capabilityId} \
    --build-package-identity ${lib.escapeShellArg (toString compiler)} \
    --out "$out"

  jq -e '
    .format == "spaghetti-extractor-fallback-engine-capability-manifest-v3" and
    (.status == "complete" or .status == "incomplete" or .status == "violated") and
    (.implementation_sha256 | test("^[0-9a-f]{64}$")) and
    .coverage.projected_units <= .coverage.required_units and
    (.built_files | length) == 2 and
    (.issues | type == "array")
  ' "$out/engine-capability-manifest.json" >/dev/null
''
