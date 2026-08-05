{
  pkgs,
  pythonEnv,
  pythonSource,
  target,
  componentProposals ? null,
}:

let
  lib = pkgs.lib;
  python = "${pythonEnv}/bin/python3";
  targetManifest = builtins.fromJSON (builtins.readFile (target + "/target.json"));
  targetId = targetManifest.id;
  phasePythonSource = import ./python-module-closure.nix {
    inherit pkgs;
    source = pythonSource;
    modules = [
      "spaghetti_extractor.component_selection"
      "spaghetti_extractor.target_intent"
      "spaghetti_extractor.util"
    ];
    name = "stage-b-${targetId}-intent-python-closure";
  };
  originalSha256 = targetManifest.input.expected_sha256;
  paths = targetManifest.paths;
  mkGenerated = name: script:
    pkgs.runCommand "stage-b-${targetId}-${name}-v1"
      {
        nativeBuildInputs = [ pythonEnv ];
        preferLocalBuild = false;
        allowSubstitutes = true;
        __contentAddressed = true;
      }
      ''
        set -euo pipefail
        export PYTHONHASHSEED=0
        export LC_ALL=C.UTF-8
        export PYTHONPATH=${phasePythonSource}/src
        mkdir -p "$out"
        ${script}
      '';
  validation = mkGenerated "target-intent-check" ''
    ${python} - ${target} "$out" <<'PY'
    import pathlib
    import sys
    from spaghetti_extractor.target_intent import load_target_bundle
    from spaghetti_extractor.util import write_json

    bundle = load_target_bundle(pathlib.Path(sys.argv[1]))
    write_json(pathlib.Path(sys.argv[2]) / "target-intent-check.json", {
        "format": "spaghetti-extractor-target-intent-check-v1",
        "status": "checked",
        "target_id": bundle.identity.target_id,
        "expected_sha256": bundle.identity.expected_sha256,
        "generated_artifacts_committed": False,
    })
    PY
  '';
  componentSelection =
    if componentProposals == null || !(paths ? components) then null else
    mkGenerated "component-selection" ''
      ${python} - \
        ${componentProposals}/component-proposals.json \
        ${target + "/${paths.components}"} "$out" <<'PY'
      import pathlib
      import sys
      from spaghetti_extractor.target_intent import resolve_component_intent

      resolve_component_intent(
          proposals=pathlib.Path(sys.argv[1]),
          intent=pathlib.Path(sys.argv[2]),
          out=pathlib.Path(sys.argv[3]) / "component-selection.json",
      )
      PY
    '';
  linkedIslandReview =
    if !(paths ? linked_islands) then null else
    mkGenerated "linked-island-review" ''
      ${python} - \
        ${target + "/${paths.linked_islands}"} \
        ${lib.escapeShellArg originalSha256} "$out" <<'PY'
      import pathlib
      import sys
      from spaghetti_extractor.target_intent import resolve_linked_island_intent

      resolve_linked_island_intent(
          intent=pathlib.Path(sys.argv[1]),
          original_sha256=sys.argv[2],
          out=pathlib.Path(sys.argv[3]) / "linked-island-review.json",
      )
      PY
    '';
  sourceProjectPaths = paths.source_projects or [ ];
  sourceProjects = lib.imap0 (
    index: relative:
    mkGenerated "source-project-${toString index}" ''
      ${python} - \
        ${target + "/${relative}"} \
        ${lib.escapeShellArg originalSha256} "$out" <<'PY'
      import pathlib
      import sys
      from spaghetti_extractor.target_intent import resolve_source_project_intent

      resolve_source_project_intent(
          intent=pathlib.Path(sys.argv[1]),
          original_sha256=sys.argv[2],
          out=pathlib.Path(sys.argv[3]) / "source-project.json",
      )
      PY
    ''
  ) sourceProjectPaths;
  sourceEvidencePaths = paths.source_evidence or [ ];
  sourceEvidence = lib.imap0 (
    index: relative:
    let project = builtins.elemAt sourceProjects index;
    in mkGenerated "source-evidence-${toString index}" ''
      ${python} - \
        ${target + "/${relative}"} \
        ${project}/source-project.json "$out" <<'PY'
      import json
      import pathlib
      import sys
      from spaghetti_extractor.target_intent import (
          resolve_source_component_evidence_intent,
      )

      project = json.loads(pathlib.Path(sys.argv[2]).read_text(encoding="utf-8"))
      resolve_source_component_evidence_intent(
          intent=pathlib.Path(sys.argv[1]),
          source_project_sha256=project["specification_sha256"],
          out=pathlib.Path(sys.argv[3]) / "source-component-evidence.json",
      )
      PY
    ''
  ) sourceEvidencePaths;
in
{
  inherit
    targetId
    validation
    componentSelection
    linkedIslandReview
    sourceProjects
    sourceEvidence
    ;
}
