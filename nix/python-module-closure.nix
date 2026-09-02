# spaghetti-extractor-python-role: developer
{
  pkgs,
  modules,
  phaseRole,
  extraPaths ? [ ],
  # Retained while callers migrate away from naming closures.  Exact source and
  # manifest store paths intentionally depend on content, not the consuming
  # phase's display name.
  name ? "spaghetti-extractor-python-module-closure",
  moduleIndexFile ? ./generated/python-module-index.json,
  moduleIndex ? null,
  repositoryRoot ? ../.,
}:

let
  lib = pkgs.lib;
  index = if moduleIndex != null then moduleIndex else builtins.fromJSON (
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
  sharedInfrastructureModules = builtins.attrNames (visit [
    "spaghetti_extractor.artifacts.build_manifest"
    "spaghetti_extractor.util"
  ] { });
  roleClosures = index.role_closures or
    (throw "Python module index has no checked role closures");
  allowedModules = roleClosures.${phaseRole} or
    (throw "Python module index has no closure for role ${phaseRole}");
  unauthorizedModules = builtins.filter
    (module:
      !(builtins.elem module allowedModules)
      && !(builtins.elem module sharedInfrastructureModules))
    selectedModules;
  staticPhaseRoles = [ "operator" "authority" "proposal" ];
  phaseSourceClass =
    if builtins.elem phaseRole staticPhaseRoles then "static" else "runtime";
  forbiddenSourceModules = builtins.filter
    (module:
      phaseSourceClass == "static"
      && lib.hasPrefix "src/spaghetti_extractor/candidate/"
        moduleRecords.${module}.path)
    selectedModules;
  staleSourceModules = builtins.filter
    (module:
      let
        record = moduleRecords.${module};
      in
      !(record ? source_sha256)
      || builtins.hashFile "sha256" (repositoryRoot + "/${record.path}")
        != record.source_sha256)
    selectedModules;
  unauthorizedExtraPaths = builtins.filter
    (path:
      !(builtins.elem phaseRole [ "authority" "developer" ]
        && lib.hasPrefix "spaghetti_extractor/lean/SpaghettiExtractor/ISA" path))
    extraPaths;
  moduleFiles = map
    (module:
      let
        record = moduleRecords.${module};
      in {
        inherit module;
        path = lib.removePrefix "src/" record.path;
        recordPath = record.path;
        dependencies = record.dependencies;
        resources = record.resources;
        source = repositoryRoot + "/${record.path}";
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
      source = repositoryRoot + "/${relative}";
    })
    moduleResourcePaths;
  extraFiles = map
    (relative: {
      path = relative;
      source = repositoryRoot + "/src/${relative}";
    })
    (builtins.sort builtins.lessThan (lib.unique extraPaths));
  supportedPhaseRoles = [
    "operator"
    "authority"
    "candidate"
    "diagnostic"
    "proposal"
    "expert"
    "developer"
  ];

  # Convert the checked inventory directly to one filtered Nix source path.
  # This is a store import, not a scheduled derivation, so every phase can use
  # its precise closure without paying for a Python copy/validation build.
  selectedSourcePaths = lib.unique (
    (map (row: row.source) moduleFiles)
    ++ (map (row: row.source) moduleResourceFiles)
    ++ (map (row: row.source) extraFiles)
  );
  pythonRoot = repositoryRoot + "/src";
  source = lib.fileset.toSource {
    root = pythonRoot;
    fileset = lib.fileset.unions selectedSourcePaths;
  };

  rowsForPath = logicalPath: sourcePath:
    let
      kind = builtins.readFileType sourcePath;
      walkDirectory = prefix: directory:
        lib.concatMap
          (entry:
            let
              child = directory + "/${entry}";
              childLogical = "${prefix}/${entry}";
              childKind = (builtins.readDir directory).${entry};
            in
            if childKind == "regular" then [ {
              path = childLogical;
              sha256 = builtins.hashFile "sha256" child;
            } ] else if childKind == "directory" then
              walkDirectory childLogical child
            else
              throw "Python closure contains unsupported ${childKind} node: ${childLogical}")
          (builtins.sort builtins.lessThan (builtins.attrNames (builtins.readDir directory)));
    in
    if kind == "regular" then [ {
      path = logicalPath;
      sha256 = builtins.hashFile "sha256" sourcePath;
    } ] else if kind == "directory" then
      walkDirectory logicalPath sourcePath
    else
      throw "Python closure contains unsupported ${kind} node: ${logicalPath}";
  moduleRows = lib.concatMap
    (row: rowsForPath row.path row.source)
    moduleFiles;
  resourceRows = lib.concatMap
    (row: rowsForPath row.path row.source)
    moduleResourceFiles;
  extraRows = lib.concatMap
    (row: rowsForPath row.path row.source)
    extraFiles;
  rowsByPath = builtins.foldl'
    (selected: row:
      if builtins.hasAttr row.path selected then
        if selected.${row.path}.sha256 == row.sha256 then selected else
          throw "Python closure maps conflicting sources to ${row.path}"
      else
        selected // { "${row.path}" = row; })
    { }
    (moduleRows ++ resourceRows ++ extraRows);
  manifestRows = map
    (path: rowsByPath.${path})
    (builtins.sort builtins.lessThan (builtins.attrNames rowsByPath));
  manifest = builtins.toFile "spaghetti-python-module-closure.json" (
    builtins.toJSON {
      format = "spaghetti-extractor-python-module-closure-v2";
      dependency_source = "role-checked-module-index-v3";
      source_class = phaseSourceClass;
      source_policy = "role-derived-source-class-v1";
      phase_role = phaseRole;
      root_modules = builtins.sort builtins.lessThan modules;
      module_resources = map (row: row.recordPath) moduleResourceFiles;
      extra_paths = map (row: row.path) extraFiles;
      files = manifestRows;
    } + "\n"
  );
in
assert index.format == "spaghetti-extractor-python-module-index-v3";
assert builtins.isList modules && modules != [ ];
assert builtins.isList extraPaths;
assert builtins.elem phaseRole supportedPhaseRoles;
assert unauthorizedModules == [ ] || throw
  "Python modules are outside the checked ${phaseRole} role closure: ${builtins.toJSON unauthorizedModules}";
assert forbiddenSourceModules == [ ] || throw
  "Python modules violate the ${phaseSourceClass} source class for role ${phaseRole}: ${builtins.toJSON forbiddenSourceModules}";
assert staleSourceModules == [ ] || throw
  "Python module index has stale source records: ${builtins.toJSON staleSourceModules}; run `nix run .#dev -- refresh`";
assert unauthorizedExtraPaths == [ ] || throw
  "Python extra paths are not permitted for role ${phaseRole}: ${builtins.toJSON unauthorizedExtraPaths}";
{
  # The filtered root is itself the Python import path.  Keeping it separate
  # from outPath makes callers state the intended use and prevents another
  # whole-repository source traversal from returning unnoticed.
  outPath = source;
  pythonPath = source;
  inherit source manifest selectedModules phaseSourceClass;
}
