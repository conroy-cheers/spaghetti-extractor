# spaghetti-extractor-python-role: developer
{
  pkgs,
  pythonEnv,
  transferPlan,
  behavioralCPackage,
  compiler ? pkgs.stdenv.cc,
  namePrefix,
}:

let
  phase = import ./ca-python-json-phase.nix {
    inherit pkgs pythonEnv;
    name = "${namePrefix}-behavioral-c-differential-v1";
    kind = "behavioral-c-differential";
    artifactName = "behavioral-c-differential.json";
    expectedFormat = "spaghetti-extractor-behavioral-c-differential-v1";
    # The phase records both veto outcomes.  Authority-bearing consumers gate
    # on `match`; rejecting `mismatch` here would discard the counterexample
    # before the dedicated differential gate can inspect it.
    allowedStatuses = [ "match" "mismatch" ];
    pythonModules = [
      "spaghetti_extractor.candidate.behavioral_c_differential"
    ];
    phaseRole = "developer";
    extraNativeBuildInputs = [ compiler ];
    inputs = {
      transfer_plan = transferPlan;
      behavioral_c_package = behavioralCPackage;
      compiler = "${compiler}/bin/cc";
    };
    program = ''
      from spaghetti_extractor.candidate.behavioral_c_differential import (
          run_behavioral_c_differential,
      )

      run_behavioral_c_differential(
          transfer_plan=inputs["transfer_plan"],
          behavioral_c_package=inputs["behavioral_c_package"],
          compiler=inputs["compiler"],
          out=output.parent,
      )
    '';
  };
in
{
  inherit (phase) derivation manifest artifact;
  receipt = phase.artifact;
}
