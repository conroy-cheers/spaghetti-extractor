# spaghetti-extractor-python-role: candidate
{
  pkgs,
  pythonEnv,
  semanticObject,
  namePrefix,
}:

let
  phase = import ./ca-python-json-phase.nix {
    inherit pkgs pythonEnv;
    name = "${namePrefix}-linked-semantic-module-v2";
    kind = "linked-semantic-module";
    artifactName = "linked-semantic-module.json";
    expectedFormat = "spaghetti-extractor-linked-semantic-module-v2";
    allowedStatuses = [
      "complete"
      "incomplete"
    ];
    pythonModules = [
      "spaghetti_extractor.semantic_link.module_v2"
    ];
    phaseRole = "candidate";
    inputs = {
      semantic_object = semanticObject;
    };
    program = ''
      from spaghetti_extractor.semantic_link.module_v2 import (
          write_linked_semantic_module_from_inputs_v2,
      )

      write_linked_semantic_module_from_inputs_v2(
          semantic_object=inputs["semantic_object"],
          out=output.parent,
      )
    '';
  };
  replay = import ./ca-python-json-phase.nix {
    inherit pkgs pythonEnv;
    name = "${namePrefix}-linked-semantic-module-independent-replay";
    kind = "linked-semantic-module-replay";
    artifactName = "linked-semantic-module-replay.json";
    expectedFormat =
      "spaghetti-extractor-linked-semantic-module-replay-v2";
    allowedStatuses = [ "complete" ];
    pythonModules = [ "spaghetti_extractor.semantic_link.replay" ];
    phaseRole = "candidate";
    inputs = {
      linked_semantic_module = phase.artifact;
    };
    program = ''
      from spaghetti_extractor.semantic_link.replay import (
          write_linked_semantic_module_replay_receipt_v2,
      )

      write_linked_semantic_module_replay_receipt_v2(
          linked_semantic_module=inputs["linked_semantic_module"],
          out=output,
      )
    '';
  };
in
{
  inherit (phase)
    derivation
    manifest
    artifact
    phasePythonSource
    ;
  replayCheck = replay.derivation;
  replayReceipt = replay.artifact;
  linkedSemanticModule = phase.artifact;
  semanticObject = "${phase.derivation}/semantic-object.json";
  transferPlan = "${phase.derivation}/executable-transfer-plan.json";
  moduleInterface = "${phase.derivation}/module-interface.json";
}
