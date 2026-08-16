{
  pkgs,
  namePrefix,
  receipt,
}:

pkgs.runCommand "${namePrefix}-structural-executable-gate-v1" {
  nativeBuildInputs = [ pkgs.jq pkgs.coreutils ];
  preferLocalBuild = false;
  allowSubstitutes = true;
  __contentAddressed = true;
} ''
  set -euo pipefail
  jq -e '
    .format == "spaghetti-extractor-structural-executable-v1" and
    .status == "complete" and
    .executable and
    (.release_accepted | not) and
    (.receipt_sha256 | test("^[0-9a-f]{64}$"))
  ' ${receipt}/structural-executable.json >/dev/null
  mkdir -p "$out"
  cp ${receipt}/structural-executable.json "$out/structural-executable.json"
  sha256sum "$out/structural-executable.json" | cut -d' ' -f1 \
    > "$out/structural-executable.sha256"
''
