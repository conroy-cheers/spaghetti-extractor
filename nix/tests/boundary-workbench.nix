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
    .format == "spaghetti-extractor-operator-work-status-v1" and
    .status == "complete" and .authority == false and
    .counts.subjects == 2 and .counts.authoritative == 0 and
    ([.subjects[].subject] | contains([$subject])) and
    ([.subjects[] | select(.subject == "component:fixture")][0] |
      .state == "complete" and .authority == false and
      .ranked_next_action == "author component C and run contextual refinement")
  ' ${workbench.status}/boundary-status.json >/dev/null
  jq -e --arg subject ${pkgs.lib.escapeShellArg subject} '
    .subject == $subject and .status == "complete"
  ' ${workbench.subjects.${subject}.inspection}/call-inspection.json >/dev/null
  cmp ${intent} ${workbench.subjects.${subject}.intentTemplate}/call-intent.json
  jq -e '
    .format == "spaghetti-extractor-component-work-package-inspection-v1" and
    .status == "complete" and .component_id == "fixture" and
    .authority == false
  ' ${workbench.subjects.${componentSubject}.inspection}/component-inspection.json \
    >/dev/null
  jq -e '
    .format == "spaghetti-extractor-component-adoption-intent-v1" and
    .component_id == "fixture" and
    ([paths(scalars) as $path | $path[-1] | tostring |
      select(endswith("_sha256"))] | length) == 0
  ' ${workbench.subjects.${componentSubject}.intentTemplate}/component-adoption-intent.json \
    >/dev/null
  touch "$out"
''
