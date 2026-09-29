# spaghetti-extractor-python-role: operator
args@{
  pkgs,
  pythonEnv,
  namePrefix,
  targetId,
  checkedProtocols ? { },
  suppliedPackages ? { },
  boundaryIntents ? { },
  rawAssetInventory ? [ ],
  componentPackages ? { },
  componentChecks ? { },
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
  schemaSubjects = lib.mapAttrs (subject: package: {
    source = package;
    check = package;
    intent = boundaryIntents.${subject};
    kind = "checked_schema";
  }) suppliedPackages;
  componentSubjectsById = lib.mapAttrs (subject: package: {
    source = package.derivation;
    kind = "component";
  } // lib.optionalAttrs (builtins.hasAttr subject componentChecks) {
    check = componentChecks.${subject};
  }) componentPackages;
  checkedProtocolSubjects = lib.mapAttrs (_: value: value // {
    kind = "checked_protocol";
  }) checkedProtocols;
  subjects = checkedProtocolSubjects // schemaSubjects // componentSubjectsById;
  indexed = lib.imap0 (index: subject: {
    name = "boundary_${lib.fixedWidthNumber 3 index}";
    value = subjects.${subject}.source;
    inherit subject;
    kind = subjects.${subject}.kind;
  }) allSubjects;
  phase = import ./ca-python-json-phase.nix {
    inherit pkgs pythonEnv;
    name = "${namePrefix}-operator-boundary-work-status-v2";
    kind = "operator-boundary-work-status";
    artifactName = "boundary-status.json";
    expectedFormat = "spaghetti-extractor-operator-work-status-v2";
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
          target_id=${builtins.toJSON targetId},
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
  withComponentPackages = packages: import ./boundary-workbench.nix
    (args // { componentPackages = packages; });
  configured = allSubjects != [ ];
  inherit subjects;
  status = phase.derivation;
  check = pkgs.linkFarm "${namePrefix}-checked-boundaries" (
    map (subject: { name = safe subject; path = subjects.${subject}.source; })
      allSubjects
  );
  assetInventory = rawAssetInventory;
}
