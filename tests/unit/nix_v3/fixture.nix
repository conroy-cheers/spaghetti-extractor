{
  pkgs,
  structuralMutation ? false,
  structuralMismatch ? false,
  edgeMutation ? false,
  recordMutation ? false,
  phaseSourceMutation ? false,
  externalKindMismatch ? false,
  structuralSchedule ? null,
  dependencySchedule ? null,
}:

let
  repositoryRoot = ../../..;
  pythonEnv = pkgs.python3;
  frameworkSource = pkgs.lib.fileset.toSource {
    root = repositoryRoot;
    fileset = pkgs.lib.fileset.unions [
      ../../../src/spaghetti_extractor/__init__.py
      ../../../src/spaghetti_extractor/artifact_set_v3.py
      ../../../src/spaghetti_extractor/phase_framework_v3.py
      ../../../src/spaghetti_extractor/analysis_v3/__init__.py
      ../../../src/spaghetti_extractor/analysis_v3/_schema.py
      ../../../src/spaghetti_extractor/analysis_v3/planning.py
    ];
  };
  phaseFixtureSource = pkgs.lib.fileset.toSource {
    root = ./.;
    fileset = ./fixture_phase_v3.py;
  };
  mkPythonSource =
    name: marker:
    pkgs.runCommand "authority-graph-v3-python-source-${name}" { } ''
      mkdir -p "$out/src/spaghetti_extractor"
      ln -s ${frameworkSource}/src/spaghetti_extractor/__init__.py \
        "$out/src/spaghetti_extractor/__init__.py"
      ln -s ${frameworkSource}/src/spaghetti_extractor/artifact_set_v3.py \
        "$out/src/spaghetti_extractor/artifact_set_v3.py"
      ln -s ${frameworkSource}/src/spaghetti_extractor/phase_framework_v3.py \
        "$out/src/spaghetti_extractor/phase_framework_v3.py"
      mkdir -p "$out/src/spaghetti_extractor/analysis_v3"
      ln -s ${frameworkSource}/src/spaghetti_extractor/analysis_v3/__init__.py \
        "$out/src/spaghetti_extractor/analysis_v3/__init__.py"
      ln -s ${frameworkSource}/src/spaghetti_extractor/analysis_v3/_schema.py \
        "$out/src/spaghetti_extractor/analysis_v3/_schema.py"
      ln -s ${frameworkSource}/src/spaghetti_extractor/analysis_v3/planning.py \
        "$out/src/spaghetti_extractor/analysis_v3/planning.py"
      ln -s ${phaseFixtureSource}/fixture_phase_v3.py \
        "$out/src/fixture_phase_v3.py"
      printf '%s\n' ${pkgs.lib.escapeShellArg marker} > "$out/source-identity"
    '';
  pythonSource = mkPythonSource "framework" "shared-framework";
  phasePythonSources = {
    transition = mkPythonSource "transition" "transition-v1";
    "scc-summarize" = mkPythonSource "scc-summarize" "scc-summarize-v1";
    composition = mkPythonSource "composition" (
      if phaseSourceMutation then "composition-v2" else "composition-v1"
    );
  };
  changedStructure = structuralMutation || structuralMismatch;
  structuralInventory = {
    format = "spaghetti-extractor-structural-inventory-v3";
    universe_sha256 =
      if structuralMutation then
        "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
      else
        "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
    units = [
      {
        unit_id = "unit:a";
        start = 4096;
        end = if changedStructure then 4113 else 4112;
        dependencies = [ "unit:b" ];
        resource_class = "small";
      }
      {
        unit_id = "unit:b";
        start = 4112;
        end = 4128;
        dependencies = [ "unit:a" ];
        resource_class = "medium";
      }
      {
        unit_id = "unit:c";
        start = 8192;
        end = 8224;
        dependencies = [ ];
        resource_class = "large";
      }
      {
        unit_id = "unit:d";
        start = 12288;
        end = 12320;
        dependencies = [ "unit:a" ];
        resource_class = "oracle";
      }
    ];
  };
  recordEdges = {
    format = "spaghetti-extractor-record-edges-v3";
    nodes = [
      {
        node_id = "unit:a";
        dependencies = [ "unit:b" ] ++ pkgs.lib.optional edgeMutation "unit:c";
        records = [ ];
        resource_class = "small";
      }
      {
        node_id = "unit:b";
        dependencies = [ "unit:a" ];
        records = [ ];
        resource_class = "small";
      }
      {
        node_id = "unit:c";
        dependencies = [ ];
        records = [ ];
        resource_class = "medium";
      }
      {
        node_id = "unit:d";
        dependencies = [ "unit:a" ];
        records = [ ];
        resource_class = "large";
      }
    ];
  };
  graphManifest = {
    format = "spaghetti-extractor-authority-graph-v3";
    graph_id = "generic-fixture";
    external_artifact_kinds.evidence = "optional-evidence";
    external_artifact_kinds.units = if externalKindMismatch then "wrong-kind" else "units";
    phases = [
      {
        phase_id = "transition";
        phase_reference = "fixture_phase_v3:transition";
        form = "map_units";
        source_input = "units";
        expected_kind = "transitions";
        inputs.units = {
          source = "external";
          id = "units";
        };
      }
      {
        phase_id = "scc-summarize";
        phase_reference = "fixture_phase_v3:summarize";
        form = "map_sccs";
        schedule_record_inputs = [ "transitions" ];
        expected_kind = "scc-summary";
        inputs.transitions = {
          source = "phase";
          id = "transition";
        };
      }
      {
        phase_id = "composition";
        phase_reference = "fixture_phase_v3:composition";
        form = "reduce";
        expected_kind = "composition";
        inputs.evidence = {
          source = "external";
          id = "evidence";
        };
        inputs.summaries = {
          source = "phase";
          id = "scc-summarize";
        };
      }
    ];
    outputs = [ "composition" ];
  };
  fixtureBinding = {
    name = "fixture";
    kind = "structural-universe";
    identity = "generic-fixture";
    sha256 = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
  };
  mkSeedArtifact =
    name: value:
    pkgs.runCommand "authority-graph-v3-fixture-input-${name}"
      {
        nativeBuildInputs = [ pythonEnv ];
      }
      ''
        export PYTHONDONTWRITEBYTECODE=1
        export PYTHONPATH=${pythonSource}/src
        ${pythonEnv}/bin/python3 - "$out" ${toString value} ${name} <<'PY'
        import pathlib
        import sys

        from spaghetti_extractor.artifact_set_v3 import (
            ArtifactBindingV3,
            ArtifactRecordV3,
            ArtifactSetWriterV3,
        )

        output = pathlib.Path(sys.argv[1])
        value = int(sys.argv[2])
        name = sys.argv[3]
        binding = ArtifactBindingV3(
            "fixture", "structural-universe", "generic-fixture", "a" * 64
        )
        ArtifactSetWriterV3(artifact_kind="units", bindings=(binding,)).write(
            output,
            (ArtifactRecordV3.create(f"unit:{name}", {"value": value}),),
        )
        PY
      '';
  unitValues = {
    a = if recordMutation then 101 else 1;
    b = 2;
    c = 3;
    d = 4;
  };
  unitIds = map (name: "unit:${name}") (builtins.attrNames unitValues);
  seedArtifacts = pkgs.lib.mapAttrs mkSeedArtifact unitValues;
  packHelpers = import ../../../nix/authority-graph-v3-packs.nix {
    inherit pkgs pythonSource;
    pythonEnv = pkgs.python3;
  };
  packedBC = packHelpers.mergeArtifactShards {
    name = "authority-graph-v3-fixture-packed-b-c";
    artifacts = [ seedArtifacts.b seedArtifacts.c ];
    expectedKind = "units";
    expectedRecordIds = [ "unit:b" "unit:c" ];
  };
  emptyEvidence = pkgs.runCommand "authority-graph-v3-fixture-empty-evidence"
    { nativeBuildInputs = [ pythonEnv ]; }
    ''
      export PYTHONDONTWRITEBYTECODE=1
      export PYTHONPATH=${pythonSource}/src
      ${pythonEnv}/bin/python3 - "$out" <<'PY'
      import pathlib
      import sys

      from spaghetti_extractor.artifact_set_v3 import (
          ArtifactBindingV3,
          ArtifactSetWriterV3,
      )

      binding = ArtifactBindingV3(
          "fixture", "structural-universe", "generic-fixture", "a" * 64
      )
      ArtifactSetWriterV3(
          artifact_kind="optional-evidence", bindings=(binding,)
      ).write(pathlib.Path(sys.argv[1]), ())
      PY
    '';
  seedShards = {
    a = {
      artifact = seedArtifacts.a;
      expectedRecordIds = [ "unit:a" ];
    };
    packed-b-c = {
      artifact = packedBC.artifact;
      expectedRecordIds = [ "unit:b" "unit:c" ];
    };
    d = {
      artifact = seedArtifacts.d;
      expectedRecordIds = [ "unit:d" ];
    };
  };
  graph = import ../../../nix/authority-graph-v3.nix {
    inherit
      pkgs
      pythonEnv
      pythonSource
      structuralInventory
      recordEdges
      structuralSchedule
      dependencySchedule
      phasePythonSources
      ;
    manifest = graphManifest;
    externalArtifacts.units = {
      shards = seedShards;
      expectedKind = "units";
      expectedRecordIds = unitIds;
    };
    externalArtifacts.evidence = {
      artifact = emptyEvidence;
      expectedKind = "optional-evidence";
      expectedRecordIds = [ ];
    };
    bindings = [ fixtureBinding ];
  };
in
graph // { inherit pkgs; }
