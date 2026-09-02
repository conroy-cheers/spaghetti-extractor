# spaghetti-extractor-python-role: operator
{
  pkgs,
  pythonEnv,
  namePrefix,
  checkedProtocols ? { },
  suppliedPackages ? { },
  boundaryIntents ? { },
  rawAssetInventory ? [ ],
  componentPackages ? { },
}:

let
  lib = pkgs.lib;
  checkedSubjects = builtins.attrNames checkedProtocols;
  suppliedSubjects = builtins.attrNames suppliedPackages;
  componentSubjects = builtins.attrNames componentPackages;
  allSubjects = builtins.sort builtins.lessThan (
    checkedSubjects ++ suppliedSubjects ++ componentSubjects
  );
  _disjoint = assert
    lib.intersectLists checkedSubjects suppliedSubjects == [ ]
    && lib.intersectLists checkedSubjects componentSubjects == [ ]
    && lib.intersectLists suppliedSubjects componentSubjects == [ ];
    true;
  _intents = assert builtins.all
    (subject: builtins.hasAttr subject boundaryIntents)
    (checkedSubjects ++ suppliedSubjects); true;
  safe = value: lib.replaceStrings [ ":" "_" ] [ "-" "-" ] value;
  schemaAdapters = lib.mapAttrs (subject: package:
    pkgs.runCommand
      "${namePrefix}-${safe subject}-boundary-subject"
      { nativeBuildInputs = [ pkgs.jq ]; __contentAddressed = true; }
      ''
        set -euo pipefail
        mkdir -p "$out"
        jq --arg subject ${lib.escapeShellArg subject} '
          . + {
            subject: $subject,
            abi_dialect: null,
            calling_convention: null,
            faithful_prototype: null,
            idiomatic_prototype: null,
            issues: (.blockers // [])
          }
        ' ${package}/boundary-status.json > "$out/call-inspection.json"
        cp ${boundaryIntents.${subject}} "$out/call-intent.json"
      '') suppliedPackages;
  schemaSubjects = lib.mapAttrs (subject: package: {
    proposal = package;
    inspection = schemaAdapters.${subject};
    check = package;
    intentTemplate = schemaAdapters.${subject};
    kind = "checked_schema";
    inspectionArtifact = "call-inspection.json";
    intentArtifact = "call-intent.json";
    checkArtifact = "boundary-status.json";
  }) suppliedPackages;
  componentAdapters = lib.mapAttrs (subject: package:
    pkgs.runCommand
      "${namePrefix}-${safe subject}-component-subject"
      { nativeBuildInputs = [ pkgs.jq ]; __contentAddressed = true; }
      ''
        set -euo pipefail
        mkdir -p "$out"
        jq --arg subject ${lib.escapeShellArg subject} '
          {
            format: "spaghetti-extractor-component-work-package-inspection-v1",
            status: (if (.blockers | length) == 0 then "complete" else "incomplete" end),
            subject: $subject,
            component_id,
            proof_classification,
            semantic_slice_sha256: .bindings.semantic_slice_sha256,
            operations,
            faithful_c_slices,
            requirements,
            issues: .blockers,
            authority: false
          }
        ' ${package.derivation}/component-work-package-v6.json \
          > "$out/component-inspection.json"
        jq '
          {
            format: "spaghetti-extractor-component-adoption-intent-v1",
            component_id,
            proof_classification,
            operations: [.operations[] | {
              id: .operation_id,
              symbol,
              entry_rvas
            }],
            proposal_kinds: []
          }
        ' ${package.derivation}/component-work-package-v6.json \
          > "$out/component-adoption-intent.json"
      '') componentPackages;
  componentSubjectsById = lib.mapAttrs (subject: package: {
    proposal = package.derivation;
    inspection = componentAdapters.${subject};
    check = package.derivation;
    intentTemplate = componentAdapters.${subject};
    kind = "component";
    inspectionArtifact = "component-inspection.json";
    intentArtifact = "component-adoption-intent.json";
    checkArtifact = "component-work-package-v6.json";
  }) componentPackages;
  checkedProtocolSubjects = lib.mapAttrs (_: value: value // {
    kind = "checked_protocol";
    inspectionArtifact = "call-inspection.json";
    intentArtifact = "call-intent.json";
    checkArtifact = "call-status.json";
  }) checkedProtocols;
  subjects = checkedProtocolSubjects // schemaSubjects // componentSubjectsById;
  indexed = lib.imap0 (index: subject: {
    name = "boundary_${lib.fixedWidthNumber 3 index}";
    value = subjects.${subject}.check;
    inherit subject;
    kind = subjects.${subject}.kind;
  }) allSubjects;
  phase = import ./ca-python-json-phase.nix {
    inherit pkgs pythonEnv;
    name = "${namePrefix}-operator-boundary-work-status-v1";
    kind = "operator-boundary-work-status";
    artifactName = "boundary-status.json";
    expectedFormat = "spaghetti-extractor-operator-work-status-v1";
    allowedStatuses = [ "complete" "incomplete" "violated" ];
    pythonModules = [ "spaghetti_extractor.boundary.work_status" ];
    phaseRole = "operator";
    inputs = builtins.listToAttrs (map (row: {
      inherit (row) name value;
    }) indexed);
    program = ''
      from spaghetti_extractor.boundary.work_status import (
          write_operator_boundary_status,
      )

      subject_inputs = ${builtins.toJSON (builtins.listToAttrs (map (row: {
        name = row.subject;
        value = row.name;
      }) indexed))}
      subject_kinds = ${builtins.toJSON (builtins.listToAttrs (map (row: {
        name = row.subject;
        value = row.kind;
      }) indexed))}
      write_operator_boundary_status(
          packages={
              subject: inputs[input_name]
              for subject, input_name in subject_inputs.items()
          },
          kinds=subject_kinds,
          out=output.parent,
      )
    '';
  };
in
assert _disjoint && _intents;
{
  configured = allSubjects != [ ];
  inherit subjects;
  status = phase.derivation;
  check = pkgs.linkFarm "${namePrefix}-checked-boundaries" (
    map (subject: { name = safe subject; path = subjects.${subject}.check; })
      allSubjects
  );
  assetInventory = rawAssetInventory;
}
