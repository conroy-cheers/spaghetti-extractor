{
  pkgs,
  namePrefix,
  receipt,
}:

pkgs.runCommand "${namePrefix}-release-acceptance-gate-v1" {
  nativeBuildInputs = [ pkgs.jq pkgs.coreutils ];
  preferLocalBuild = false;
  allowSubstitutes = true;
  __contentAddressed = true;
} ''
  set -euo pipefail
  jq -e '
    .format == "spaghetti-extractor-release-acceptance-v1" and
    .status == "complete" and
    .executable and .release_accepted and
    (.receipt_sha256 | test("^[0-9a-f]{64}$"))
  ' ${receipt}/release-acceptance.json >/dev/null
  mkdir -p "$out"
  cp ${receipt}/release-acceptance.json "$out/release-acceptance.json"
  sha256sum "$out/release-acceptance.json" | cut -d' ' -f1 \
    > "$out/release-acceptance.sha256"
''
