{
  pkgs,
  pythonEnv,
  pythonSource,
}:

pkgs.runCommand "spaghetti-extractor-semantic-providers-check"
  { nativeBuildInputs = [ pythonEnv ]; }
  ''
    set -euo pipefail
    export PYTHONHASHSEED=0
    export PYTHONDONTWRITEBYTECODE=1
    export LC_ALL=C.UTF-8
    export PYTHONPATH=${pythonSource}/src:${pythonSource}
    python -m unittest \
      tests.unit.semantic_providers.test_slices_v2 \
      tests.unit.semantic_providers.test_qualification_and_selection_v2 \
      tests.unit.semantic_providers.test_intrinsic
    mkdir -p "$out"
    touch "$out/passed"
  ''
