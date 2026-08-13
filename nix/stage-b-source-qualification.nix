{
  pkgs,
  pythonEnv,
  pythonSource,
  namePrefix,
  sourceBinding,
  componentAssurance,
  sourceCallReport,
  candidateDependencyAudit,
}:

let
  pythonClosure = import ./python-module-closure.nix {
    inherit pkgs;
    source = pythonSource;
    modules = [ "spaghetti_extractor.stage_b_source_qualification_v1" ];
    name = "${namePrefix}-source-qualification-python-closure";
  };
in
pkgs.runCommand "${namePrefix}-source-qualification-v1" {
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

  ${pythonEnv}/bin/python3 -m spaghetti_extractor.stage_b_source_qualification_v1 \
    --source-binding ${pkgs.lib.escapeShellArg (toString sourceBinding)} \
    --component-assurance ${pkgs.lib.escapeShellArg (toString componentAssurance)} \
    --source-call-report ${pkgs.lib.escapeShellArg (toString sourceCallReport)} \
    --candidate-dependency-audit ${pkgs.lib.escapeShellArg (toString candidateDependencyAudit)} \
    --out "$out"
''
