# spaghetti-extractor-python-role: candidate
{
  pkgs,
  pythonEnv,
  linkedSemanticModule,
  qualificationsById,
  definitionChoices ? null,
  obligationChoices ? null,
  choicesFile ? null,
  choiceFiles ? null,
  selectedProviderIds ? null,
  mode ? "faithful",
  namePrefix,
}:

assert builtins.isAttrs qualificationsById;
assert builtins.length (builtins.filter (value: value) [
  (definitionChoices != null && obligationChoices != null)
  (choicesFile != null)
  (choiceFiles != null)
]) == 1;
assert definitionChoices == null || builtins.isAttrs definitionChoices;
assert obligationChoices == null || builtins.isAttrs obligationChoices;
assert choicesFile == null || builtins.isList selectedProviderIds;
assert choiceFiles == null || (
  builtins.isList choiceFiles && choiceFiles != [ ]
  && builtins.isList selectedProviderIds
);
assert builtins.elem mode [ "faithful" "hybrid" "portable" ];

let
  lib = pkgs.lib;
  effectiveProviderIds = builtins.sort builtins.lessThan (
    lib.unique (
      if choicesFile != null || choiceFiles != null then selectedProviderIds
      else (builtins.attrValues definitionChoices)
        ++ (builtins.attrValues obligationChoices)
    )
  );
  missingProviderIds = builtins.filter
    (providerId: !(builtins.hasAttr providerId qualificationsById))
    effectiveProviderIds;
  qualificationInputs = builtins.listToAttrs (
    lib.imap0 (index: providerId: {
      name = "qualification_${lib.fixedWidthNumber 4 index}";
      value = qualificationsById.${providerId};
    }) effectiveProviderIds
  );
  effectiveChoiceFiles =
    if choiceFiles != null then choiceFiles
    else if choicesFile != null then [ choicesFile ]
    else [ (pkgs.writeText
      "${namePrefix}-implementation-choices-v2.json"
      (builtins.toJSON {
        definitions = definitionChoices;
        obligations = obligationChoices;
      })) ];
  choiceInputs = builtins.listToAttrs (
    lib.imap0 (index: value: {
      name = "choices_${lib.fixedWidthNumber 4 index}";
      inherit value;
    }) effectiveChoiceFiles
  );
  phase = import ./ca-python-json-phase.nix {
    inherit pkgs pythonEnv;
    name = "${namePrefix}-implementation-selection-v2";
    kind = "implementation-selection";
    artifactName = "implementation-selection.json";
    expectedFormat = "spaghetti-extractor-implementation-selection-v2";
    allowedStatuses = [ "complete" "incomplete" ];
    pythonModules = [
      "spaghetti_extractor.semantic_providers.selection_v2"
    ];
    phaseRole = "candidate";
    inputs = ({
      linked_semantic_module = linkedSemanticModule;
    } // choiceInputs // qualificationInputs);
    program = ''
      import json

      from spaghetti_extractor.semantic_link.module_v2 import (
          LinkedSemanticModuleV2,
      )
      from spaghetti_extractor.semantic_providers.qualification_v2 import (
          SemanticProviderQualificationV2,
      )
      from spaghetti_extractor.semantic_providers.selection_v2 import (
          write_implementation_selection_v2,
      )

      qualifications = tuple(
          SemanticProviderQualificationV2.load(value)
          for name, value in sorted(inputs.items())
          if name.startswith("qualification_")
      )
      provider_kinds = {
          qualification.provider_id: qualification.provider_kind
          for qualification in qualifications
      }
      choices = {"definitions": {}, "obligations": {}}
      for name, path in sorted(inputs.items()):
          if not name.startswith("choices_"):
              continue
          fragment = json.loads(path.read_text(encoding="utf-8"))
          if not isinstance(fragment, dict):
              raise SystemExit("V2 implementation choices must be objects")
          # Definition-only provider packages retain a compact direct map.
          if "definitions" not in fragment and "obligations" not in fragment:
              fragment = {"definitions": fragment, "obligations": {}}
          for kind in ("definitions", "obligations"):
              rows = fragment.get(kind)
              if not isinstance(rows, dict):
                  raise SystemExit(f"V2 {kind} choices must be objects")
              for identity, provider_id in rows.items():
                  if identity not in choices[kind]:
                      choices[kind][identity] = provider_id
                      continue
                  previous_id = choices[kind][identity]
                  allowed_override = (
                      kind == "definitions"
                      and provider_kinds.get(previous_id)
                      == "generated_behavioral_c"
                      and provider_kinds.get(provider_id)
                      == "qualified_portable_c"
                  )
                  if not allowed_override:
                      raise SystemExit(
                          f"V2 {kind} choice {identity!r} overlaps "
                          f"providers {previous_id!r} and {provider_id!r}"
                      )
                  choices[kind][identity] = provider_id
      write_implementation_selection_v2(
          linked_semantic_module=LinkedSemanticModuleV2.load(
              inputs["linked_semantic_module"], require_complete=False,
          ),
          qualifications=qualifications,
          definition_choices=choices["definitions"],
          obligation_choices=choices["obligations"],
          mode=${builtins.toJSON mode},
          out=output,
      )
    '';
  };
in
assert missingProviderIds == [ ] || throw
  "V2 implementation choices name missing qualifications: ${builtins.toJSON missingProviderIds}";
{
  inherit (phase) derivation manifest artifact;
  selection = phase.artifact;
  selectedProviderIds = effectiveProviderIds;
}
