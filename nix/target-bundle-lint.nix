# spaghetti-extractor-python-role: operator
{
  pkgs,
  pythonEnv,
  pythonSource,
  targetRoot,
  targetId,
  declaredAssets,
  namePrefix,
}:

let
  phaseSource = import ./python-module-closure.nix {
    phaseRole = "operator";
    inherit pkgs;
    modules = [ "spaghetti_extractor.target_bundles.lint" ];
    name = "${namePrefix}-target-bundle-lint-python-closure";
  };
  assets = pkgs.writeText "${namePrefix}-target-assets.json"
    (builtins.toJSON declaredAssets);
in
pkgs.runCommand "${namePrefix}-target-bundle-lint-v1" {
  nativeBuildInputs = [ pythonEnv pkgs.jq ];
  preferLocalBuild = false;
  allowSubstitutes = true;
  __contentAddressed = true;
} ''
  set -euo pipefail
  export PYTHONHASHSEED=0
  export PYTHONDONTWRITEBYTECODE=1
  export PYTHONPATH=${phaseSource.pythonPath}
  mkdir -p "$out"
  ${pythonEnv}/bin/python3 - \
    ${targetRoot} \
    ${pkgs.lib.escapeShellArg targetId} \
    ${assets} \
    "$out/target-bundle-lint.json" <<'PY'
  import json
  import pathlib
  import sys

  from spaghetti_extractor.target_bundles.lint import lint_target_bundle

  lint_target_bundle(
      target_root=pathlib.Path(sys.argv[1]),
      target_id=sys.argv[2],
      declared_assets=json.loads(pathlib.Path(sys.argv[3]).read_text()),
      out=pathlib.Path(sys.argv[4]),
  )
  PY
  jq -e '
    .format == "spaghetti-extractor-target-bundle-lint-v1" and
    .status == "checked" and
    .counts.issues == 0 and
    .policy.exact_file_ownership and
    (.policy.symlinks_allowed | not) and
    (.policy.generated_target_assets_allowed | not)
  ' "$out/target-bundle-lint.json" >/dev/null || {
    jq '{target_id, status, counts, issues}' "$out/target-bundle-lint.json" >&2
    exit 1
  }
''
