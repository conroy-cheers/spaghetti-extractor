{ pkgs }:

let
  sdk = import ../target-sdk-v1.nix { inherit pkgs; };
  artifact = pkgs.writeText "minimal-sdk-consumer-artifact" "checked\n";
  target = sdk.target.bundle {
    targetRoot = ../../tests/fixtures/target-sdk-v1;
    artifacts.baseline = artifact;
    checks.artifact = pkgs.runCommand "minimal-sdk-consumer-check" { } ''
      grep -Fx checked ${artifact}
      touch "$out"
    '';
  };
  registry = sdk.target.registry {
    minimal-sdk-consumer = target;
  };
in
assert sdk.format == "spaghetti-extractor-target-sdk-v1";
assert registry.minimal-sdk-consumer.metadata.id == "minimal-sdk-consumer";
assert registry.minimal-sdk-consumer.artifacts.baseline == artifact;
registry.minimal-sdk-consumer.defaultCheck
