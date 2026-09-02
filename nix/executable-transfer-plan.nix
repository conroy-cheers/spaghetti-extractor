# spaghetti-extractor-python-role: candidate
{
  pkgs,
  pythonEnv,
  machineIr,
  namePrefix,
}:

let
  phase = import ./ca-python-json-phase.nix {
    inherit pkgs pythonEnv;
    name = "${namePrefix}-executable-transfer-plan-v2";
    kind = "executable-transfer-plan";
    artifactName = "executable-transfer-plan.json";
    expectedFormat = "spaghetti-extractor-executable-transfer-plan-v2";
    allowedStatuses = [ "complete" "incomplete" ];
    pythonModules = [ "spaghetti_extractor.transfer.plan" ];
    phaseRole = "candidate";
    inputs = {
      machine_ir = "${machineIr}/machine-ir.jsonl";
      machine_ir_manifest = "${machineIr}/machine-ir-manifest.json";
    };
    program = ''
      from spaghetti_extractor.transfer.plan import (
          write_executable_transfer_plan,
      )

      write_executable_transfer_plan(
          machine_ir=inputs["machine_ir"],
          machine_ir_manifest=inputs["machine_ir_manifest"],
          out=output.parent,
      )
    '';
  };
in
{
  inherit (phase) derivation manifest artifact;
  plan = phase.artifact;
}
