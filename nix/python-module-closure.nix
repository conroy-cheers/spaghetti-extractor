{
  pkgs,
  source,
  modules,
  extraPaths ? [ ],
  name ? "spaghetti-extractor-python-module-closure",
  moduleIndexFile ? ./python-module-index.json,
  repositoryRoot ? ../.,
}:

let
  lib = pkgs.lib;
  index = builtins.fromJSON (
    builtins.unsafeDiscardStringContext (builtins.readFile moduleIndexFile)
  );
  moduleRecords = index.modules or (throw "Python module index has no modules");
  visit = pending: selected:
    if pending == [ ] then
      selected
    else
      let
        current = builtins.head pending;
        rest = builtins.tail pending;
        record =
          if builtins.hasAttr current moduleRecords then
            moduleRecords.${current}
          else
            throw "local Python module is absent from the checked index: ${current}";
      in
      if builtins.hasAttr current selected then
        visit rest selected
      else
        visit
          (rest ++ record.dependencies)
          (selected // { "${current}" = true; });
  selectedModules = builtins.sort builtins.lessThan (
    builtins.attrNames (visit modules { })
  );
  sanitize = value: lib.replaceStrings [ "." "_" "/" ] [ "-" "-" "-" ] value;
  moduleFiles = map
    (module:
      let
        record = moduleRecords.${module};
        sourcePath = repositoryRoot + "/${record.path}";
      in {
        inherit module;
        path = lib.removePrefix "src/" record.path;
        source = toString (builtins.path {
          path = sourcePath;
          name = "spaghetti-python-${sanitize module}";
        });
      })
    selectedModules;
  extraFiles = map
    (relative: {
      path = relative;
      source = toString (builtins.path {
        path = repositoryRoot + "/src/${relative}";
        name = "spaghetti-python-extra-${sanitize relative}";
      });
    })
    (builtins.sort builtins.lessThan (lib.unique extraPaths));
  moduleFilesJson = builtins.toJSON moduleFiles;
  extraFilesJson = builtins.toJSON extraFiles;
  rootsJson = builtins.toJSON (builtins.sort builtins.lessThan modules);
  moduleValidations = map
    (module: {
      inherit module;
      path = toString (import ./python-module-validation.nix {
        inherit pkgs module repositoryRoot;
        moduleRecord = moduleRecords.${module};
      });
    })
    selectedModules;
  moduleValidationsJson = builtins.toJSON moduleValidations;
in
assert index.format == "spaghetti-extractor-python-module-index-v1";
assert builtins.isList modules && modules != [ ];
assert builtins.isList extraPaths;
pkgs.runCommand name {
  nativeBuildInputs = [ pkgs.python3 ];
  preferLocalBuild = false;
  allowSubstitutes = true;
  __contentAddressed = true;
} ''
  set -euo pipefail
  export PYTHONHASHSEED=0
  export LC_ALL=C.UTF-8
  ${pkgs.python3}/bin/python3 - "$out" \
      ${lib.escapeShellArg rootsJson} \
      ${lib.escapeShellArg moduleFilesJson} \
      ${lib.escapeShellArg extraFilesJson} \
      ${lib.escapeShellArg moduleValidationsJson} <<'PY'
  from __future__ import annotations

  import hashlib
  import json
  import pathlib
  import shutil
  import sys

  output = pathlib.Path(sys.argv[1])
  roots = json.loads(sys.argv[2])
  module_files = json.loads(sys.argv[3])
  extra_files = json.loads(sys.argv[4])
  module_validations = json.loads(sys.argv[5])
  output_root = output / "src"
  rows = []
  copied = set()

  validated_modules = set()
  for row in module_validations:
      validation_path = pathlib.Path(row["path"]) / "python-module-validation.json"
      validation = json.loads(validation_path.read_text(encoding="utf-8"))
      if (
          validation.get("format")
          != "spaghetti-extractor-python-module-validation-v1"
          or validation.get("module") != row["module"]
      ):
          raise SystemExit(f"invalid module validation for {row['module']}")
      validated_modules.add(row["module"])
  if validated_modules != {row["module"] for row in module_files}:
      raise SystemExit("module validation inventory does not match closure")

  def copy_file(source: pathlib.Path, relative: pathlib.PurePosixPath) -> None:
      if relative in copied:
          return
      target = output_root / pathlib.Path(*relative.parts)
      target.parent.mkdir(parents=True, exist_ok=True)
      shutil.copyfile(source, target)
      rows.append({
          "path": relative.as_posix(),
          "sha256": hashlib.sha256(target.read_bytes()).hexdigest(),
      })
      copied.add(relative)

  for row in module_files:
      copy_file(pathlib.Path(row["source"]), pathlib.PurePosixPath(row["path"]))

  for row in extra_files:
      source = pathlib.Path(row["source"])
      relative = pathlib.PurePosixPath(row["path"])
      if source.is_file():
          copy_file(source, relative)
          continue
      for path in sorted(item for item in source.rglob("*") if item.is_file()):
          copy_file(path, relative / path.relative_to(source).as_posix())

  rows.sort(key=lambda row: row["path"])
  manifest = {
      "format": "spaghetti-extractor-python-module-closure-v1",
      "dependency_source": "checked-module-index-v1",
      "root_modules": roots,
      "extra_paths": sorted(row["path"] for row in extra_files),
      "files": rows,
  }
  output.mkdir(parents=True, exist_ok=True)
  (output / "python-module-closure.json").write_text(
      json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8"
  )
  PY
''
