{
  pkgs,
  source,
  modules,
  name ? "spaghetti-extractor-python-module-closure",
}:

let
  lib = pkgs.lib;
  moduleArgs = lib.concatMapStringsSep " " lib.escapeShellArg modules;
in
pkgs.runCommand name {
  nativeBuildInputs = [ pkgs.python3 ];
  preferLocalBuild = false;
  allowSubstitutes = true;
  __contentAddressed = true;
} ''
  set -euo pipefail
  export PYTHONHASHSEED=0
  export LC_ALL=C.UTF-8
  ${pkgs.python3}/bin/python3 - ${source}/src "$out/src" ${moduleArgs} <<'PY'
  from __future__ import annotations

  import ast
  import hashlib
  import json
  import pathlib
  import shutil
  import sys

  source_root = pathlib.Path(sys.argv[1]).resolve()
  output_root = pathlib.Path(sys.argv[2])
  requested = tuple(sys.argv[3:])
  if not requested:
      raise SystemExit("python module closure requires at least one root module")

  package = "spaghetti_extractor"

  def local_module_path(module: str) -> pathlib.Path | None:
      if module != package and not module.startswith(package + "."):
          return None
      relative = pathlib.Path(*module.split("."))
      source = source_root / relative.with_suffix(".py")
      if source.is_file():
          return source
      initializer = source_root / relative / "__init__.py"
      return initializer if initializer.is_file() else None

  def module_name(path: pathlib.Path) -> str:
      relative = path.relative_to(source_root)
      if relative.name == "__init__.py":
          relative = relative.parent
      else:
          relative = relative.with_suffix("")
      return ".".join(relative.parts)

  def parent_initializers(path: pathlib.Path) -> list[pathlib.Path]:
      result = []
      parent = path.parent
      while parent != source_root:
          initializer = parent / "__init__.py"
          if initializer.is_file():
              result.append(initializer)
          parent = parent.parent
      return result

  pending = list(requested)
  selected: dict[str, pathlib.Path] = {}
  while pending:
      module = pending.pop()
      path = local_module_path(module)
      if path is None:
          raise SystemExit(f"local Python module does not exist: {module}")
      canonical = module_name(path)
      if canonical in selected:
          continue
      selected[canonical] = path
      for initializer in parent_initializers(path):
          pending.append(module_name(initializer))

      tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
      current_package = (
          canonical if path.name == "__init__.py" else canonical.rpartition(".")[0]
      )
      for node in ast.walk(tree):
          candidates: list[str] = []
          if isinstance(node, ast.Import):
              candidates.extend(alias.name for alias in node.names)
          elif isinstance(node, ast.ImportFrom):
              if node.level:
                  base = current_package.split(".") if current_package else []
                  trim = node.level - 1
                  if trim > len(base):
                      raise SystemExit(f"relative import escapes package in {path}")
                  base = base[: len(base) - trim]
                  if node.module:
                      base.extend(node.module.split("."))
                  target = ".".join(base)
              else:
                  target = node.module or ""
              if target:
                  candidates.append(target)
              candidates.extend(
                  f"{target}.{alias.name}" if target else alias.name
                  for alias in node.names
                  if alias.name != "*"
              )
          for candidate in candidates:
              if local_module_path(candidate) is not None:
                  pending.append(candidate)

  rows = []
  for path in sorted(set(selected.values())):
      relative = path.relative_to(source_root)
      target = output_root / relative
      target.parent.mkdir(parents=True, exist_ok=True)
      shutil.copyfile(path, target)
      digest = hashlib.sha256(target.read_bytes()).hexdigest()
      rows.append({"path": relative.as_posix(), "sha256": digest})

  manifest = {
      "format": "spaghetti-extractor-python-module-closure-v1",
      "root_modules": sorted(requested),
      "files": rows,
  }
  output_root.parent.mkdir(parents=True, exist_ok=True)
  (output_root.parent / "python-module-closure.json").write_text(
      json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8"
  )
  PY
''
