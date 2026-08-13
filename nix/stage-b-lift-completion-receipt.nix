{
  pkgs,
  pythonEnv,
  pythonSource,
  namePrefix,
  profile,
  finalAuthority,
  fallbackCoverage,
  implementationLedger,
  runtimeLock,
  authorityDiagnostics ? null,
  pe32Candidate ? null,
  nonX86Candidate ? null,
  sourceQualifications ? [ ],
  libraryQualifications ? [ ],
  validation ? null,
}:

let
  lib = pkgs.lib;
  pythonClosure = import ./python-module-closure.nix {
    inherit pkgs;
    source = pythonSource;
    modules = [ "spaghetti_extractor.stage_b_lift_completion_v2" ];
    name = "${namePrefix}-lift-completion-python-closure";
  };
  optionalArgument = flag: value:
    lib.optionalString (value != null) "${flag} ${lib.escapeShellArg (toString value)}";
  repeatedArguments = flag: values:
    lib.concatMapStringsSep " \
    " (value: "${flag} ${lib.escapeShellArg (toString value)}") values;
in
assert builtins.elem profile [
  "static-baseline-v1"
  "portable-application-v1"
  "validation-qualified-v1"
];
pkgs.runCommand "${namePrefix}-${profile}-lift-completion-receipt-v2" {
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

  ${pythonEnv}/bin/python3 -m spaghetti_extractor.stage_b_lift_completion_v2 \
    --profile ${lib.escapeShellArg profile} \
    --final-authority ${lib.escapeShellArg (toString finalAuthority)} \
    --fallback-coverage ${lib.escapeShellArg (toString fallbackCoverage)} \
    --implementation-ledger ${lib.escapeShellArg (toString implementationLedger)} \
    --runtime-lock ${lib.escapeShellArg (toString runtimeLock)} \
    ${optionalArgument "--authority-diagnostics" authorityDiagnostics} \
    ${optionalArgument "--pe32-candidate" pe32Candidate} \
    ${optionalArgument "--non-x86-candidate" nonX86Candidate} \
    ${repeatedArguments "--source-qualification" sourceQualifications} \
    ${repeatedArguments "--library-qualification" libraryQualifications} \
    ${optionalArgument "--validation" validation} \
    --out "$out"
''
