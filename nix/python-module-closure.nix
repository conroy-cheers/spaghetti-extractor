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
        recordPath = record.path;
        dependencies = record.dependencies;
        resources = record.resources;
        source = toString (builtins.path {
          path = sourcePath;
          name = "spaghetti-python-${sanitize module}";
        });
      })
    selectedModules;
  moduleResourcePaths = builtins.sort builtins.lessThan (
    lib.unique (
      lib.concatMap (module: moduleRecords.${module}.resources) selectedModules
    )
  );
  moduleResourceFiles = map
    (relative: {
      path = lib.removePrefix "src/" relative;
      recordPath = relative;
      source = toString (builtins.path {
        path = repositoryRoot + "/${relative}";
        name = "spaghetti-python-resource-${sanitize relative}";
      });
    })
    moduleResourcePaths;
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
  moduleResourceFilesJson = builtins.toJSON moduleResourceFiles;
  extraFilesJson = builtins.toJSON extraFiles;
  rootsJson = builtins.toJSON (builtins.sort builtins.lessThan modules);
in
assert index.format == "spaghetti-extractor-python-module-index-v2";
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
      ${lib.escapeShellArg moduleResourceFilesJson} \
      ${lib.escapeShellArg extraFilesJson} <<'PY'
  from __future__ import annotations

  import ast
  import hashlib
  import json
  import pathlib
  import shutil
  import sys

  output = pathlib.Path(sys.argv[1])
  roots = json.loads(sys.argv[2])
  module_files = json.loads(sys.argv[3])
  module_resource_files = json.loads(sys.argv[4])
  extra_files = json.loads(sys.argv[5])
  output_root = output / "src"
  rows = []
  copied = set()

  def observed_dependencies(row):
      module = row["module"]
      package = module.split(".", 1)[0]
      source = pathlib.Path(row["source"])
      record_path = row["recordPath"]
      tree = ast.parse(source.read_text(encoding="utf-8"), filename=record_path)
      current_package = (
          module if pathlib.PurePosixPath(record_path).name == "__init__.py"
          else module.rpartition(".")[0]
      )
      observed = {
          ".".join(module.split(".")[:size])
          for size in range(1, len(module.split(".")))
      }
      for node in ast.walk(tree):
          if isinstance(node, ast.Import):
              observed.update(
                  alias.name
                  for alias in node.names
                  if alias.name == package
                  or alias.name.startswith(f"{package}.")
              )
          elif isinstance(node, ast.ImportFrom):
              if node.level:
                  base = current_package.split(".") if current_package else []
                  trim = node.level - 1
                  if trim > len(base):
                      raise SystemExit(
                          f"relative import escapes package in {record_path}"
                      )
                  base = base[: len(base) - trim]
                  if node.module:
                      base.extend(node.module.split("."))
                  target = ".".join(base)
              else:
                  target = node.module or ""
              if target == package or target.startswith(f"{package}."):
                  observed.add(target)
                  if node.module is None or target == package:
                      observed.update(
                          f"{target}.{alias.name}"
                          for alias in node.names
                          if alias.name != "*"
                      )
      observed.discard(module)
      return sorted(observed)

  def observed_resources(row):
      source = pathlib.Path(row["source"])
      tree = ast.parse(source.read_text(encoding="utf-8"), filename=row["recordPath"])
      value = []
      for node in tree.body:
          if not isinstance(node, (ast.Assign, ast.AnnAssign)):
              continue
          targets = node.targets if isinstance(node, ast.Assign) else [node.target]
          if not any(
              isinstance(target, ast.Name) and target.id == "PYTHON_RESOURCES"
              for target in targets
          ):
              continue
          try:
              value = ast.literal_eval(node.value)
          except (TypeError, ValueError) as exc:
              raise SystemExit(
                  f"dynamic PYTHON_RESOURCES in {row['recordPath']}"
              ) from exc
      if not isinstance(value, (list, tuple)) or not all(
          isinstance(item, str) for item in value
      ):
          raise SystemExit(f"malformed PYTHON_RESOURCES in {row['recordPath']}")
      return sorted(set(value))

  for row in module_files:
      required_fields = {
          "module", "path", "recordPath", "dependencies", "resources", "source"
      }
      if set(row) != required_fields:
          raise SystemExit(
              f"malformed checked module row for {row.get('module', '<unknown>')}"
          )
      expected = row["dependencies"]
      observed = observed_dependencies(row)
      if observed != expected:
          raise SystemExit(
              f"stale checked imports for {row['module']}: "
              f"expected {expected!r}, observed {observed!r}; "
              "run `nix run .#dev -- refresh`"
          )
      observed_data = observed_resources(row)
      if observed_data != row["resources"]:
          raise SystemExit(
              f"stale checked resources for {row['module']}: "
              f"expected {row['resources']!r}, observed {observed_data!r}; "
              "run `nix run .#dev -- refresh`"
          )

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

  for row in module_resource_files:
      source = pathlib.Path(row["source"])
      relative = pathlib.PurePosixPath(row["path"])
      if source.is_file():
          copy_file(source, relative)
          continue
      for path in sorted(item for item in source.rglob("*") if item.is_file()):
          copy_file(path, relative / path.relative_to(source).as_posix())

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
      "dependency_source": "inline-checked-module-index-v1",
      "root_modules": roots,
      "module_resources": sorted(row["recordPath"] for row in module_resource_files),
      "extra_paths": sorted(row["path"] for row in extra_files),
      "files": rows,
  }
  output.mkdir(parents=True, exist_ok=True)
  (output / "python-module-closure.json").write_text(
      json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8"
  )
  PY
''
