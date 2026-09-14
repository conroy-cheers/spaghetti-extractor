{ pkgs, pythonEnv }:

let
  subject = "service:fixture";
  intent = pkgs.writeText "spaghetti-extractor-boundary-fixture-intent.json" ''
    {"format":"spaghetti-extractor-boundary-check-spec-v1"}
  '';
  package = pkgs.runCommand "spaghetti-extractor-boundary-fixture-package" {
    __contentAddressed = true;
  } ''
    mkdir -p "$out"
    printf '%s\n' \
      '{"format":"spaghetti-extractor-boundary-check-result-v1","status":"complete","blockers":[]}' \
      > "$out/boundary-status.json"
  '';
  componentSubject = "component:fixture";
  componentPackageDrv = pkgs.runCommand
    "spaghetti-extractor-boundary-component-fixture-package"
    { __contentAddressed = true; }
    ''
      mkdir -p "$out"
      printf '%s\n' '${builtins.toJSON {
        format = "spaghetti-extractor-component-work-package-v6";
        status = "ready";
        component_id = "fixture";
        proof_classification = "machine_overlay";
        operations = [ {
          operation_id = "run";
          symbol = "fixture_run";
          entry_rvas = [ 4096 ];
        } ];
        faithful_c_slices = [ ];
        requirements = { };
        blockers = [ ];
        bindings.semantic_slice_sha256 = builtins.concatStringsSep "" (
          builtins.genList (_: "a") 64
        );
        authority = false;
      }}' > "$out/component-work-package-v6.json"
      printf '%s\n' \
        '{"format":"spaghetti-extractor-semantic-slice-v2"}' \
        > "$out/semantic-slice-v2.json"
    '';
  componentPackage.derivation = componentPackageDrv;
  workbench = import ../boundary-workbench.nix {
    inherit pkgs pythonEnv;
    namePrefix = "spaghetti-extractor-boundary-fixture";
    targetId = "fixture";
    suppliedPackages.${subject} = package;
    boundaryIntents.${subject} = intent;
    componentPackages.${componentSubject} = componentPackage;
  };
in
pkgs.runCommand "spaghetti-extractor-boundary-workbench-check" {
  nativeBuildInputs = [ pkgs.jq ];
} ''
  set -euo pipefail
  jq -e --arg subject ${pkgs.lib.escapeShellArg subject} '
    .format == "spaghetti-extractor-operator-work-status-v2" and
    .target_id == "fixture" and .scope == "boundary" and
    .status == "complete" and
    .counts.subjects == 2 and .counts.authority_held == 0 and
    ([.subjects[].subject] | contains([$subject])) and
    ([.subjects[] | select(.subject == "component:fixture")][0] |
      .state == "complete" and .authority == "not-applicable" and
      .next_action == "run the component qualification check")
  ' ${workbench.status}/boundary-status.json >/dev/null
  jq -e '
    .format == "spaghetti-extractor-boundary-check-result-v1" and
    .status == "complete"
  ' ${workbench.subjects.${subject}.source}/boundary-status.json >/dev/null
  cmp ${intent} ${workbench.subjects.${subject}.intent}
  jq -e '
    .format == "spaghetti-extractor-component-work-package-v6" and
    .status == "ready" and .component_id == "fixture" and
    .authority == false
  ' ${workbench.subjects.${componentSubject}.source}/component-work-package-v6.json \
    >/dev/null
  touch "$out"
''
