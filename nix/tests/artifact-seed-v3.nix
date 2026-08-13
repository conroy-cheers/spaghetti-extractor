{ pkgs, pythonEnv, pythonSource }:

let
  input = pkgs.writeText "artifact-seed-v3-input.ndjson" ''
    {"id":"unit:a","value":1}
    {"id":"unit:b","value":2}
  '';
  seed = import ../artifact-seed-v3.nix {
    inherit pkgs pythonEnv pythonSource input;
    name = "artifact-seed-v3-fixture";
    artifactKind = "seed-fixture-v3";
    bindings = [ {
      name = "fixture";
      kind = "test";
      identity = "seed";
      sha256 = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    } ];
  };
  shardSeed = import ../artifact-seed-v3.nix {
    inherit pkgs pythonEnv pythonSource input;
    name = "artifact-seed-v3-shard-fixture";
    artifactKind = "seed-fixture-v3";
    bindInputSource = false;
    bindings = [ {
      name = "fixture";
      kind = "test";
      identity = "seed";
      sha256 = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    } ];
  };
in
pkgs.runCommand "artifact-seed-v3-check" {
  nativeBuildInputs = [ pythonEnv ];
  __contentAddressed = true;
  preferLocalBuild = false;
  allowSubstitutes = true;
} ''
  export PYTHONPATH=${pythonSource}/src
  ${pythonEnv}/bin/python3 - ${seed}/manifest.json ${shardSeed}/manifest.json "$out" <<'PY'
  import json
  import pathlib
  import sys

  manifest = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="ascii"))
  shard_manifest = json.loads(pathlib.Path(sys.argv[2]).read_text(encoding="ascii"))
  assert manifest["artifact_kind"] == "seed-fixture-v3"
  assert manifest["record_count"] == 2
  assert {row["name"] for row in manifest["bindings"]} == {"fixture", "source"}
  assert {row["name"] for row in shard_manifest["bindings"]} == {"fixture"}
  pathlib.Path(sys.argv[3]).write_text("pass\n", encoding="ascii")
  PY
''
