{
  pkgs,
  pythonEnv,
  pythonSource,
}:

let
  pythonCheck = pkgs.runCommand
    "spaghetti-extractor-linked-semantic-module-unit-check"
    { nativeBuildInputs = [ pythonEnv ]; }
    ''
      set -euo pipefail
      export PYTHONHASHSEED=0
      export PYTHONDONTWRITEBYTECODE=1
      export LC_ALL=C.UTF-8
      export PYTHONPATH=${pythonSource}/src:${pythonSource}
      python -m unittest \
        tests.unit.semantic_link.test_diagnostics \
        tests.unit.semantic_link.test_frontiers_v2 \
        tests.unit.semantic_link.test_module_v2
      mkdir -p "$out"
      touch "$out/passed"
    '';
in
pkgs.linkFarm "spaghetti-extractor-linked-semantic-module-check" [
  { name = "unit"; path = pythonCheck; }
]
