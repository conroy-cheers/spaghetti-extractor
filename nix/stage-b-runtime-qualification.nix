{
  pkgs,
  pythonEnv,
  pythonSource,
  namePrefix,
  linkedIslands,
  runtimeLock,
  candidateDependencyAudit,
  componentAssurance,
  substitutionPlan,
}:

let
  pythonClosure = import ./python-module-closure.nix {
    inherit pkgs;
    source = pythonSource;
    modules = [ "spaghetti_extractor.stage_b_runtime_qualification_v1" ];
    name = "${namePrefix}-runtime-qualification-python-closure";
  };
  escape = value: pkgs.lib.escapeShellArg (toString value);
in
pkgs.runCommand "${namePrefix}-runtime-qualification-v1" {
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

  ${pythonEnv}/bin/python3 -m spaghetti_extractor.stage_b_runtime_qualification_v1 \
    --linked-islands ${escape linkedIslands} \
    --runtime-lock ${escape runtimeLock} \
    --candidate-dependency-audit ${escape candidateDependencyAudit} \
    --component-assurance ${escape componentAssurance} \
    --substitution-plan ${escape substitutionPlan} \
    --out "$out"
''
