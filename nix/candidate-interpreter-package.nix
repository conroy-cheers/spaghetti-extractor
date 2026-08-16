# spaghetti-extractor-python-role: candidate
{
  pkgs,
  supportPackage,
  executionGate,
  namePrefix,
}:

let
  gateFile = "${executionGate}/structural-executable.json";
  gateCheck = ''
    .format == "spaghetti-extractor-structural-executable-v1" and
    .status == "complete" and .executable
  '';
in
pkgs.runCommand
  "${namePrefix}-machine-ir-interpreter-v1"
  {
    nativeBuildInputs = [ pkgs.jq pkgs.coreutils ];
    preferLocalBuild = false;
    allowSubstitutes = true;
    __contentAddressed = true;
  }
  ''
    set -euo pipefail
    export LC_ALL=C.UTF-8
    export SOURCE_DATE_EPOCH=1
    jq -e '${gateCheck}' ${gateFile} >/dev/null
    jq -e '
      .format == "spaghetti-extractor-semantic-interpreter-package-v1" and
      .status == "ready" and
      .input_mode == "sanitized_machine_ir_v2" and
      .counts.input_transfers > 0 and
      .counts.transfers == .counts.input_transfers and
      .counts.blocked_transfers == 0 and
      .execution_policy == "complete_transfer_inventory_v1" and
      .semantic_coverage.status == "complete"
    ' ${supportPackage}/state-machine-interpreter-package.json >/dev/null
    mkdir -p "$out"
    cp -a ${supportPackage}/. "$out/"
    jq -n --arg executionGateSha256 \
      "$(sha256sum ${gateFile} | cut -d' ' -f1)" \
      --arg executionGateFormat "$(jq -r .format ${gateFile})" \
      --arg supportPackage ${builtins.toJSON (toString supportPackage)} '
      {
        format: "spaghetti-extractor-candidate-interpreter-gate-v2",
        status: "authorized",
        execution_gate: {
          format: $executionGateFormat,
          sha256: $executionGateSha256
        },
        support_package: $supportPackage
      }
    ' > "$out/candidate-interpreter-gate.json"
  ''
