{
  pkgs,
  pythonEnv,
  pythonSource,
  namePrefix,
  dependencies,
}:

let
  pythonClosure = import ./python-module-closure.nix {
    inherit pkgs;
    source = pythonSource;
    modules = [ "spaghetti_extractor.runtime_lock_v1" ];
    name = "${namePrefix}-runtime-lock-python-closure";
  };
  specification = pkgs.writeText "${namePrefix}-runtime-lock-spec-v1.json" (
    builtins.toJSON {
      format = "spaghetti-extractor-runtime-lock-spec-v1";
      dependencies = map (row: {
        inherit (row) kind identity;
        # Preserve each path's string context so the lock derivation receives
        # exactly the dependency it hashes, including repository files.
        path = row.path;
      }) dependencies;
    }
  );
in
assert builtins.isList dependencies && dependencies != [ ];
pkgs.runCommand "${namePrefix}-runtime-lock-v1" {
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
  export PYTHONPATH=${pythonClosure}/src
  mkdir -p "$out"
  ${pythonEnv}/bin/python3 -m spaghetti_extractor.runtime_lock_v1 \
    --specification ${specification} \
    --out "$out/runtime-lock-v1.json"
''
