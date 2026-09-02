# spaghetti-extractor-python-role: candidate
{
  pkgs,
  pythonEnv,
  linkedSemanticModule,
  definitionIds ? [ ],
  obligationIds ? [ ],
  namePrefix,
}:

assert builtins.isList definitionIds;
assert builtins.isList obligationIds;
assert definitionIds != [ ] || obligationIds != [ ];

let
  request = pkgs.writeText "${namePrefix}-semantic-slice-request-v2.json"
    (builtins.toJSON {
      definitions = builtins.sort builtins.lessThan (pkgs.lib.unique definitionIds);
      obligations = builtins.sort builtins.lessThan (pkgs.lib.unique obligationIds);
    });
  phase = import ./ca-python-json-phase.nix {
    inherit pkgs pythonEnv;
    name = "${namePrefix}-semantic-slice-v2";
    kind = "semantic-slice";
    artifactName = "semantic-slice.json";
    expectedFormat = "spaghetti-extractor-semantic-slice-v2";
    pythonModules = [
      "spaghetti_extractor.semantic_providers.slices_v2"
    ];
    phaseRole = "candidate";
    inputs = {
      linked_semantic_module = linkedSemanticModule;
      inherit request;
    };
    program = ''
      import json

      from spaghetti_extractor.semantic_link.module_v2 import (
          LinkedSemanticModuleV2,
      )
      from spaghetti_extractor.semantic_providers.slices_v2 import (
          write_semantic_slice_v2,
      )

      request = json.loads(inputs["request"].read_text(encoding="utf-8"))
      write_semantic_slice_v2(
          linked_semantic_module=LinkedSemanticModuleV2.load(
              inputs["linked_semantic_module"], require_complete=False,
          ),
          definition_ids=request["definitions"],
          obligation_ids=request["obligations"],
          out=output,
      )
    '';
  };
in
{
  inherit (phase) derivation manifest artifact;
  semanticSlice = phase.artifact;
}
