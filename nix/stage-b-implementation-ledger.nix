{
  pkgs,
  pythonEnv,
  pythonSource,
  namePrefix,
  machineIr,
  profile,
  sourceBinding ? null,
  sourceQualification ? null,
  linkedIslands ? null,
  libraryQualifications ? [ ],
  fallbackCoverage ? null,
}:

let
  lib = pkgs.lib;
  pythonClosure = import ./python-module-closure.nix {
    inherit pkgs;
    source = pythonSource;
    modules = [ "spaghetti_extractor.stage_b_ownership_ledger_v2" ];
    name = "${namePrefix}-implementation-ledger-python-closure";
  };
  optionalArgument = flag: value:
    lib.optionalString (value != null) "${flag} ${lib.escapeShellArg (toString value)}";
  repeatedArguments = flag: values:
    lib.concatMapStringsSep " \\\n+    " (value: "${flag} ${lib.escapeShellArg (toString value)}") values;
in
assert builtins.elem profile [
  "static-baseline-v1"
  "portable-application-v1"
  "validation-qualified-v1"
];
pkgs.runCommand "${namePrefix}-${profile}-implementation-ledger-v2" {
  nativeBuildInputs = [ pythonEnv ];
  preferLocalBuild = false;
  allowSubstitutes = true;
  __contentAddressed = true;
} ''
  set -euo pipefail
  export PYTHONHASHSEED=0
  export PYTHONDONTWRITEBYTECODE=1
  export LC_ALL=C.UTF-8
  export SOURCE_DATE_EPOCH=1
  export SPAGHETTI_ORIGINAL_EXECUTION_FORBIDDEN=1
  export PYTHONPATH=${pythonClosure}/src

  ${pythonEnv}/bin/python3 -m spaghetti_extractor.stage_b_ownership_ledger_v2 \
    --machine-ir ${lib.escapeShellArg (toString machineIr)} \
    --profile ${lib.escapeShellArg profile} \
    ${optionalArgument "--source-binding" sourceBinding} \
    ${optionalArgument "--source-qualification" sourceQualification} \
    ${optionalArgument "--linked-islands" linkedIslands} \
    ${repeatedArguments "--library-qualification" libraryQualifications} \
    ${optionalArgument "--fallback-coverage" fallbackCoverage} \
    --out "$out"
''
