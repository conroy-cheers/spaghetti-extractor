# spaghetti-extractor-python-role: developer
{ pkgs }:

let
  context = import ../toolkit-context.nix { inherit pkgs; };
  pythonEnv = context.pythonEnv;
  fixturePhase = import ../ca-python-json-phase.nix {
    inherit pkgs pythonEnv;
    name = "spaghetti-extractor-behavioral-c-differential-fixture";
    kind = "behavioral-c-differential-fixture";
    artifactName = "behavioral-c-package.json";
    expectedFormat = "spaghetti-extractor-behavioral-c-package-v2";
    allowedStatuses = [ "ready" ];
    pythonModules = [
      "spaghetti_extractor.candidate.behavioral_c"
      "spaghetti_extractor.testkit.transfer_fixture"
    ];
    phaseRole = "developer";
    program = ''
    import json

    from spaghetti_extractor.testkit.transfer_fixture import (
        as_machine_ir_unit, transfer_row, write_fixture_transfer_plan,
    )
    from spaghetti_extractor.candidate.behavioral_c import (
        write_spx_behavioral_c_package,
    )

    root = output.parent
    row = transfer_row()
    row["outcome"] = {
        "kind": "return",
        "value": {"op": "reg", "name": "eax", "width": 32},
    }
    machine = root / "machine-ir.jsonl"
    machine.write_text(
        json.dumps(as_machine_ir_unit(row), sort_keys=True) + "\n",
        encoding="utf-8",
    )
    transfer = write_fixture_transfer_plan(machine)
    write_spx_behavioral_c_package(
        transfer_plan=transfer, out=root / "behavioral",
    )
    output.write_bytes((root / "behavioral/behavioral-c-package.json").read_bytes())
    '';
  };
  fixture = fixturePhase.derivation;
  differential = import ../behavioral-c-differential.nix {
    inherit pkgs pythonEnv;
    transferPlan = "${fixture}/machine-ir-transfer/executable-transfer-plan.json";
    behavioralCPackage = "${fixture}/behavioral";
    namePrefix = "spaghetti-extractor-behavioral-c-fixture";
  };
in
pkgs.runCommand "spaghetti-extractor-behavioral-c-differential-check" {
  nativeBuildInputs = [ pkgs.jq ];
} ''
  set -euo pipefail
  jq -e '
    .format == "spaghetti-extractor-behavioral-c-differential-v1" and
    .status == "match" and
    .authority == "none; generated differential cases are veto-only" and
    (.case_ids | length == 4) and
    (.backends | keys == ["behavioral_c"]) and
    .mismatches == []
  ' ${differential.artifact} >/dev/null
  touch "$out"
''
