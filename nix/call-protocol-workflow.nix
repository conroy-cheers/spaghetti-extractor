# spaghetti-extractor-python-role: expert
{
  pkgs,
  pythonEnv,
  pythonSource,
  namePrefix,
  protocols ? { },
}:

let
  lib = pkgs.lib;
  checked = lib.mapAttrs (id: spec:
    let safeId = lib.replaceStrings [ ":" ] [ "-" ] id;
    in
    assert builtins.isPath spec.intent || builtins.isString spec.intent;
    assert builtins.isPath spec.layouts || builtins.isString spec.layouts;
    assert builtins.isPath spec.transferPlan || builtins.isString spec.transferPlan;
    assert (builtins.isList (spec.machineEvidence or [ ])
      && ((spec.machineEvidence or [ ]) != [ ]
        || (spec.runtimeProfiles or [ ]) != [ ]));
    assert !(spec ? callbackProtocolId);
    pkgs.runCommand
      "${namePrefix}-${safeId}-checked-call-protocol"
      {
        nativeBuildInputs = [ pythonEnv ];
        __contentAddressed = true;
      }
      ''
        set -euo pipefail
        export PYTHONPATH=${pythonSource}/src
        ${pythonEnv}/bin/python3 -m spaghetti_extractor expert call-protocol-check \
          --intent ${lib.escapeShellArg "${spec.intent}"} \
          --layouts ${lib.escapeShellArg "${spec.layouts}"} \
          ${lib.optionalString (spec ? frame)
            "--frame ${lib.escapeShellArg "${spec.frame}"}"} \
          --transfer-plan ${lib.escapeShellArg "${spec.transferPlan}"} \
          ${lib.concatMapStringsSep " "
            (value: "--interaction-contract-id ${lib.escapeShellArg value}")
            (spec.interactionContractIds or [ ])} \
          ${lib.concatMapStringsSep " "
            (value: "--machine-evidence ${lib.escapeShellArg "${value}"}")
            (spec.machineEvidence or [ ])} \
          ${lib.concatMapStringsSep " "
            (value: "--runtime-profile ${lib.escapeShellArg "${value}"}")
            (spec.runtimeProfiles or [ ])} \
          ${lib.optionalString (spec ? compilerProposal)
            "--compiler-proposal ${lib.escapeShellArg "${spec.compilerProposal}"}"} \
          --out "$out"
      '') protocols;
  subjects = lib.mapAttrs (id: result: {
    source = result;
    check = result;
    intent = protocols.${id}.intent;
  }) checked;
  assetInventory = lib.concatLists (lib.mapAttrsToList (id: spec: [
    { path = spec.intent; role = "call_intent"; owner = id; }
    { path = spec.layouts; role = "call_layout"; owner = id; }
  ]) protocols);
  status = pkgs.runCommand
    "${namePrefix}-call-protocol-status"
    {
      nativeBuildInputs = [ pkgs.jq ];
      __contentAddressed = true;
    }
    ''
      set -euo pipefail
      mkdir -p "$out"
      ${lib.concatStringsSep "\n" (lib.mapAttrsToList (id: result: ''
        jq --arg id ${lib.escapeShellArg id} '. + {id: $id}' \
          ${result}/call-status.json > ${lib.escapeShellArg "subject-${id}.json"}
      '') checked)}
      jq -s '
        sort_by(.id) as $subjects
        | {
            format: "spaghetti-extractor-call-status-v1",
            status: (if any($subjects[]; .status == "violated") then "violated"
                     elif any($subjects[]; .status != "complete") then "incomplete"
                     else "complete" end),
            counts: {
              subjects: ($subjects | length),
              complete: ([$subjects[] | select(.status == "complete")] | length),
              incomplete: ([$subjects[] | select(.status == "incomplete")] | length),
              violated: ([$subjects[] | select(.status == "violated")] | length)
            },
            subjects: $subjects
          }
      ' ${lib.concatStringsSep " " (map (id: lib.escapeShellArg "subject-${id}.json") (builtins.attrNames checked))} \
        > "$out/call-status.json"
    '';
in
{
  configured = protocols != { };
  inherit assetInventory checked status subjects;
  check = pkgs.linkFarm "${namePrefix}-checked-call-protocols"
    (lib.mapAttrsToList (name: path: { inherit name path; }) checked);
}
