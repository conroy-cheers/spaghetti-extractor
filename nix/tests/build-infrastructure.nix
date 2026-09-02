# spaghetti-extractor-python-role: developer
{ pkgs, pythonEnv }:

let
  input = pkgs.writeText "spaghetti-extractor-build-infrastructure-input.json" ''
    {"seed": "checked"}
  '';
  sharedPythonSource = import ../python-module-closure.nix {
    inherit pkgs;
    phaseRole = "developer";
    modules = [
      "spaghetti_extractor.artifacts.build_manifest"
      "spaghetti_extractor.util"
    ];
    name = "spaghetti-extractor-build-infrastructure-shared-python-closure";
  };
  phase = import ../ca-python-json-phase.nix {
    inherit pkgs pythonEnv;
    name = "spaghetti-extractor-build-infrastructure-phase";
    kind = "build-infrastructure-fixture";
    artifactName = "behavioral-c-package.json";
    expectedFormat = "spaghetti-extractor-behavioral-c-package-v2";
    allowedStatuses = [ "ready" ];
    pythonModules = [
      "spaghetti_extractor.artifacts.build_manifest"
      "spaghetti_extractor.util"
    ];
    phaseRole = "developer";
    pythonSource = sharedPythonSource;
    inputs = { inherit input; };
    program = ''
      from spaghetti_extractor.util import write_json

      seed = json.loads(inputs["input"].read_text(encoding="utf-8"))
      write_json(
          output,
          {
              "format": "spaghetti-extractor-behavioral-c-package-v2",
              "status": "ready",
              "seed": seed["seed"],
          },
      )
    '';
  };
  gate = import ../ca-json-receipt-gate.nix {
    inherit pkgs pythonEnv;
    name = "spaghetti-extractor-build-infrastructure-gate";
    kind = "build-infrastructure-fixture";
    artifact = phase.artifact;
    artifactName = "behavioral-c-package.json";
    expectedFormat = "spaghetti-extractor-behavioral-c-package-v2";
    allowedStatuses = [ "ready" ];
    pythonModules = [ "spaghetti_extractor.artifacts.build_manifest" ];
    phaseRole = "developer";
    inputs = {
      phase = phase.derivation;
      inherit input;
    };
    program = ''
      if artifact.get("seed") != "checked":
          fail("fixture payload did not survive its deterministic phase")
    '';
  };
in
pkgs.runCommand "spaghetti-extractor-build-infrastructure-check" {
  nativeBuildInputs = [ pkgs.jq ];
} ''
  set -euo pipefail
  jq -e '
    .format == "spaghetti-extractor-ca-phase-manifest-v1" and
    .phase == "build-infrastructure-fixture" and
    .content_addressed == true and
    .artifact.format == "spaghetti-extractor-behavioral-c-package-v2" and
    .artifact.status == "ready" and
    ([.inputs[].name] == ["input"])
  ' ${phase.manifest} >/dev/null
  test ! -e ${phase.derivation}/phase-manifest.json
  jq -e '
    .format == "spaghetti-extractor-ca-receipt-gate-v1" and
    .gate == "build-infrastructure-fixture" and
    .phase_role == "developer" and
    .acceptance_authority == "none" and
    .artifact.status == "ready" and
    ([.inputs[].name] == ["input", "phase"])
  ' ${gate.manifest} >/dev/null
  cmp ${phase.artifact} ${gate.receipt}
  touch "$out"
''
