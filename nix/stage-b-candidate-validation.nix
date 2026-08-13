{
  pkgs,
  pythonEnv,
  pythonSource,
  namePrefix,
  pe32Report,
  nonX86Report,
}:

let
  pythonClosure = import ./python-module-closure.nix {
    inherit pkgs;
    source = pythonSource;
    modules = [ "spaghetti_extractor.candidate_validation_v1" ];
    name = "${namePrefix}-candidate-validation-python-closure";
  };
  escape = value: pkgs.lib.escapeShellArg (toString value);
in
pkgs.runCommand "${namePrefix}-candidate-validation-v1" {
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
  ${pythonEnv}/bin/python3 -m spaghetti_extractor.candidate_validation_v1 \
    --pe32-report ${escape pe32Report} \
    --non-x86-report ${escape nonX86Report} \
    --out "$out"
''
