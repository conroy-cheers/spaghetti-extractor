# spaghetti-extractor-python-role: candidate
{ pkgs, package, namePrefix }:

pkgs.runCommand
  "${namePrefix}-behavioral-c-completion-gate-v1"
  {
    nativeBuildInputs = [ pkgs.jq pkgs.coreutils ];
    preferLocalBuild = false;
    allowSubstitutes = true;
    __contentAddressed = true;
  }
  ''
    set -euo pipefail
    jq -e '
      .format == "spaghetti-extractor-behavioral-c-package-v1" and
      .status == "ready" and .completion_status == "complete"
    ' ${package}/behavioral-c-package.json >/dev/null
    jq -e '
      .format == "spaghetti-extractor-behavioral-c-completion-v1" and
      .status == "complete" and .complete and .blockers == []
    ' ${package}/behavioral-c-completion.json >/dev/null
    mkdir -p "$out"
    cp ${package}/behavioral-c-completion.json "$out/behavioral-c-completion.json"
    jq -n \
      --arg packageSha256 "$(sha256sum ${package}/behavioral-c-package.json | cut -d' ' -f1)" \
      --arg completionSha256 "$(sha256sum ${package}/behavioral-c-completion.json | cut -d' ' -f1)" '
      {
        format: "spaghetti-extractor-behavioral-c-completion-gate-v1",
        status: "complete",
        package_sha256: $packageSha256,
        completion_sha256: $completionSha256
      }
    ' > "$out/gate.json"
  ''
