{
  pkgs,
  module,
  moduleRecord,
  repositoryRoot ? ../.,
}:

let
  lib = pkgs.lib;
  sanitize = value: lib.replaceStrings [ "." "_" "/" ] [ "-" "-" "-" ] value;
  sourceFile = builtins.path {
    path = repositoryRoot + "/${moduleRecord.path}";
    name = "spaghetti-python-source-${sanitize module}";
  };
  moduleRecordJson = builtins.toJSON moduleRecord;
in
assert builtins.isString module;
assert builtins.isAttrs moduleRecord;
pkgs.runCommand "spaghetti-python-module-validation-${sanitize module}" {
  nativeBuildInputs = [ pkgs.python3 ];
  preferLocalBuild = false;
  allowSubstitutes = true;
  __contentAddressed = true;
} ''
  set -euo pipefail
  export PYTHONHASHSEED=0
  export LC_ALL=C.UTF-8
  ${pkgs.python3}/bin/python3 - "$out" \
      ${lib.escapeShellArg module} \
      ${lib.escapeShellArg (toString sourceFile)} \
      ${lib.escapeShellArg moduleRecordJson} <<'PY'
  from __future__ import annotations

  import ast
  import hashlib
  import json
  import pathlib
  import sys

  output = pathlib.Path(sys.argv[1])
  module = sys.argv[2]
  source = pathlib.Path(sys.argv[3])
  record = json.loads(sys.argv[4])
  package = module.split(".", 1)[0]

  if set(record) != {"path", "dependencies"}:
      raise SystemExit(f"invalid checked module row for {module}")
  dependencies = record["dependencies"]
  if (
      not isinstance(record["path"], str)
      or not isinstance(dependencies, list)
      or any(not isinstance(item, str) for item in dependencies)
      or dependencies != sorted(set(dependencies))
  ):
      raise SystemExit(f"malformed checked module row for {module}")
  tree = ast.parse(source.read_text(encoding="utf-8"), filename=record["path"])
  current_package = (
      module if pathlib.PurePosixPath(record["path"]).name == "__init__.py"
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
              if alias.name == package or alias.name.startswith(f"{package}.")
          )
      elif isinstance(node, ast.ImportFrom):
          if node.level:
              base = current_package.split(".") if current_package else []
              trim = node.level - 1
              if trim > len(base):
                  raise SystemExit(f"relative import escapes package in {record['path']}")
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
  observed_dependencies = sorted(observed)
  if observed_dependencies != dependencies:
      raise SystemExit(
          f"stale checked imports for {module}: expected {dependencies!r}, "
          f"observed {observed_dependencies!r}"
      )

  payload = {
      "format": "spaghetti-extractor-python-module-validation-v1",
      "module": module,
      "path": record["path"],
      "dependencies": dependencies,
      "source_sha256": hashlib.sha256(source.read_bytes()).hexdigest(),
  }
  output.mkdir(parents=True, exist_ok=True)
  (output / "python-module-validation.json").write_text(
      json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8"
  )
  PY
''
