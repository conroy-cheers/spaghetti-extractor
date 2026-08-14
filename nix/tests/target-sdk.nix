{ pkgs }:

let
  sdk = import ../target-sdk.nix { inherit pkgs; };
  artifact = pkgs.writeText "minimal-sdk-consumer-artifact" "checked\n";
  acceptance = pkgs.writeText "minimal-sdk-acceptance-artifact" "accepted\n";
  target = sdk.target.bundle {
    targetRoot = ../../tests/fixtures/minimal-target-bundle;
    artifacts.baseline = artifact;
    checks.artifact = pkgs.runCommand "minimal-sdk-consumer-check" { } ''
      grep -Fx checked ${artifact}
      touch "$out"
    '';
    acceptanceChecks.acceptance = pkgs.runCommand
      "minimal-sdk-acceptance-check" { } ''
        grep -Fx accepted ${acceptance}
        touch "$out"
      '';
  };
  registry = sdk.target.registry {
    minimal-sdk-consumer = target;
  };
in
assert sdk.format == "spaghetti-extractor-target-sdk-v3";
assert registry.minimal-sdk-consumer.metadata.id == "minimal-sdk-consumer";
assert registry.minimal-sdk-consumer.artifacts.baseline == artifact;
assert registry.minimal-sdk-consumer.acceptanceChecks.acceptance != null;
pkgs.linkFarm "spaghetti-extractor-target-sdk-check" [
  { name = "regression"; path = registry.minimal-sdk-consumer.defaultCheck; }
  { name = "acceptance"; path = registry.minimal-sdk-consumer.acceptanceCheck; }
]
