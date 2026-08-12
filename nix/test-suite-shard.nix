{
  pkgs,
  pythonEnv,
  repositoryRoot,
  shard,
  fixtureSet,
}:

let
  lib = pkgs.lib;
  sanitize = value: lib.replaceStrings [ "." "_" "/" ] [ "-" "-" "-" ] value;
  fixtureInputs = fixtureSet.forIds shard.fixtures;
  invalidEnvironmentKeys = builtins.filter
    (key: builtins.match "[A-Za-z_][A-Za-z0-9_]*" key == null)
    (builtins.attrNames fixtureInputs.environment);
  environmentExports = lib.concatStringsSep "\n" (
    lib.mapAttrsToList
      (key: value: "export ${key}=${lib.escapeShellArg (toString value)}")
      fixtureInputs.environment
  );
  fileRows = map
    (relative: {
      path = relative;
      source = toString (builtins.path {
        path = repositoryRoot + "/${relative}";
        name = "spaghetti-test-input-${sanitize relative}";
      });
    })
    shard.files;
  fileRowsJson = builtins.toJSON fileRows;
  testPathsJson = builtins.toJSON shard.test_paths;
in
assert invalidEnvironmentKeys == [ ];
pkgs.runCommand "spaghetti-extractor-test-${sanitize shard.id}" {
  nativeBuildInputs = [ pythonEnv ] ++ fixtureInputs.nativeBuildInputs;
  preferLocalBuild = shard.resource_class != "small";
  allowSubstitutes = true;
  __contentAddressed = true;
} ''
  set -euo pipefail
  export PYTHONHASHSEED=0
  export LC_ALL=C.UTF-8
  export SOURCE_DATE_EPOCH=1
  export SPAGHETTI_TEST_FIXTURES=${fixtureInputs.manifest}
  ${environmentExports}
  work="$TMPDIR/test-source"
  mkdir -p "$work"
  python - "$work" ${lib.escapeShellArg fileRowsJson} <<'PY'
  import json
  import pathlib
  import shutil
  import sys

  root = pathlib.Path(sys.argv[1])
  rows = sorted(json.loads(sys.argv[2]), key=lambda row: (row["path"].count("/"), row["path"]))
  for row in rows:
      destination = root / row["path"]
      source = pathlib.Path(row["source"])
      if source.is_dir():
          shutil.copytree(source, destination, dirs_exist_ok=True)
      else:
          destination.parent.mkdir(parents=True, exist_ok=True)
          shutil.copyfile(source, destination)
  PY
  export PYTHONPATH="$work/src:$work/tests:$work"
  cd "$work"
  mapfile -t test_paths < <(python - ${lib.escapeShellArg testPathsJson} <<'PY'
  import json
  import sys
  for path in json.loads(sys.argv[1]):
      print(path)
  PY
  )
  python -m unittest "''${test_paths[@]}"
  mkdir -p "$out"
  cat > "$out/test-shard-report.json" <<EOF
  {
    "format": "spaghetti-extractor-test-shard-report-v1",
    "status": "pass",
    "shard_id": ${builtins.toJSON shard.id},
    "input_sha256": ${builtins.toJSON shard.input_sha256},
    "test_count": ${toString (builtins.length shard.tests)}
  }
  EOF
''
