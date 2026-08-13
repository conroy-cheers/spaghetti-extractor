{
  pkgs,
  pythonEnv,
  pythonSource,
  manifest,
  structuralInventory,
  recordEdges,
  externalArtifacts,
  bindings,
  phasePythonSources ? { },
  moduleIndexFile ? ./python-module-index.json,
  repositoryRoot ? ../.,
  structuralSchedule ? null,
  dependencySchedule ? null,
  preplannedBoundaries ? null,
  requireStructuralCoverage ? true,
  contentAddressed ? true,
  scheduleBucketCount ? 4,
  resourceClasses ? import ./authority-resource-classes-v3.nix,
  phaseConstructor ? import ./artifact-phase-v3.nix,
  artifactSetConstructor ? import ./artifact-set-v3.nix,
}:

let
  lib = pkgs.lib;
  ensure = condition: message: if condition then true else throw "authority-graph-v3: ${message}";
  graph =
    if builtins.isAttrs manifest then manifest else builtins.fromJSON (builtins.readFile manifest);
  externalArtifactKinds = graph.external_artifact_kinds or null;
  sanitize =
    value:
    lib.concatStrings (
      map (character: if builtins.match "[A-Za-z0-9.+_-]" character != null then character else "-") (
        lib.stringToCharacters value
      )
    );
  graphId = graph.graph_id or "";
  boundaries = import ./authority-graph-v3-boundaries.nix {
    inherit
      pkgs
      pythonEnv
      pythonSource
      contentAddressed
      ;
  };
  packHelpers = import ./authority-graph-v3-packs.nix {
    inherit
      pkgs
      pythonEnv
      pythonSource
      contentAddressed
      ;
  };
  caAttrs = lib.optionalAttrs contentAddressed { __contentAddressed = true; };

  validPreplannedBoundary = value:
    builtins.isAttrs value
    && builtins.attrNames value == [
      "derivation"
      "manifest"
      "packIndex"
      "packsDirectory"
      "validation"
    ]
    && builtins.isString value.manifest
    && builtins.isString value.validation
    && builtins.isString value.packIndex
    && builtins.isString value.packsDirectory;
  structuralBoundary =
    if preplannedBoundaries != null then
      preplannedBoundaries.structural
    else
      boundaries.mkStructural {
        # Structural and SCC topology are root-independent source facts.  A
        # phase interface edit must not alter their derivation identity; the
        # inventory, policy, and checker closure already provide all inputs.
        name = "authority-graph-v3-structural";
        inventory = structuralInventory;
        schedule = structuralSchedule;
        inherit scheduleBucketCount resourceClasses;
      };
  # IFD boundary 1: Nix reads only the compact pack routing index. Full unit
  # schedules remain checked files and are never expanded as evaluator values.
  structuralPackPlan = builtins.fromJSON (builtins.readFile structuralBoundary.packIndex);

  dependencyBoundary =
    if preplannedBoundaries != null then
      preplannedBoundaries.dependency
    else
      boundaries.mkDependency {
        name = "authority-graph-v3-dependency";
        structuralSchedule = structuralBoundary.manifest;
        inherit recordEdges requireStructuralCoverage;
        schedule = dependencySchedule;
        inherit scheduleBucketCount;
      };
  # IFD boundary 2: Nix reads only routing and inventory hashes. Full SCC
  # schedules remain checked per-pack files consumed by Python phase runners.
  dependencyPackPlan = builtins.fromJSON (builtins.readFile dependencyBoundary.packIndex);
  dependencyPackRows = dependencyPackPlan.packs or [ ];
  dependencyPackKeys = map (row: row.key or "") dependencyPackRows;
  selectedPackSccIds = lib.sort builtins.lessThan (
    lib.concatMap (row: row.selected_scc_ids or [ ]) dependencyPackRows
  );
  validDependencyPackRow = row:
    builtins.isAttrs row
    && builtins.attrNames row == [
      "closure_node_ids"
      "closure_scc_ids"
      "filename"
      "identity_bucket"
      "key"
      "resource_class"
      "schedule_sha256"
      "selected_node_ids"
      "selected_scc_ids"
    ]
    && builtins.isString row.key
    && row.key != ""
    && row.filename == "${row.key}.json"
    && builtins.isInt row.identity_bucket
    && row.identity_bucket >= 0
    && row.identity_bucket < scheduleBucketCount
    && builtins.hasAttr row.resource_class resourceClasses
    && builtins.match "[0-9a-f]{64}" row.schedule_sha256 != null
    && builtins.isList row.selected_scc_ids
    && row.selected_scc_ids != [ ]
    && row.selected_scc_ids == lib.sort builtins.lessThan (lib.unique row.selected_scc_ids)
    && builtins.isList row.closure_scc_ids
    && row.closure_scc_ids == lib.sort builtins.lessThan (lib.unique row.closure_scc_ids)
    && builtins.all (sccId: builtins.elem sccId row.closure_scc_ids) row.selected_scc_ids
    && builtins.isList row.selected_node_ids
    && row.selected_node_ids == lib.sort builtins.lessThan (lib.unique row.selected_node_ids)
    && builtins.isList row.closure_node_ids
    && row.closure_node_ids == lib.sort builtins.lessThan (lib.unique row.closure_node_ids)
    && builtins.all (nodeId: builtins.elem nodeId row.closure_node_ids) row.selected_node_ids;

  validatePolicy =
    resourceClass: policy:
    let
      resource = policy.resource or { };
      timing = policy.timing or { };
      memory = resource.memory_mib or null;
      maximum =
        if resourceClass == "oracle" then
          null
        else if resourceClass == "large" then
          4096
        else
          2048;
    in
    assert ensure (builtins.isAttrs resource) "resource policy ${resourceClass} has no resource set";
    assert ensure (builtins.isAttrs timing) "resource policy ${resourceClass} has no timing set";
    assert ensure (
      builtins.isInt (resource.cores or null) && resource.cores > 0
    ) "resource policy ${resourceClass} has invalid cores";
    assert ensure (
      builtins.isInt memory && memory >= 256
    ) "resource policy ${resourceClass} has invalid memory_mib";
    assert ensure (
      maximum == null || memory < maximum
    ) "resource policy ${resourceClass} exceeds its memory class ceiling";
    assert ensure (
      builtins.isInt (resource.disk_mib or null) && resource.disk_mib > 0
    ) "resource policy ${resourceClass} has invalid disk_mib";
    assert ensure (
      builtins.isInt (timing.expected_seconds or null) && timing.expected_seconds > 0
    ) "resource policy ${resourceClass} has invalid expected_seconds";
    assert ensure (
      builtins.isInt (timing.timeout_seconds or null) && timing.timeout_seconds >= timing.expected_seconds
    ) "resource policy ${resourceClass} has invalid timeout_seconds";
    {
      inherit resource timing;
    };
  policyFor =
    resourceClass:
    if builtins.hasAttr resourceClass resourceClasses then
      validatePolicy resourceClass resourceClasses.${resourceClass}
    else
      throw "authority-graph-v3: no resource policy for ${resourceClass}";
  bucketName = bucket: if bucket < 10 then "0${toString bucket}" else toString bucket;

  validStructuralPackRow = row:
    builtins.isAttrs row
    && builtins.attrNames row == [
      "filename"
      "identity_bucket"
      "item_count"
      "item_ids"
      "item_ids_sha256"
      "key"
      "pack_id"
      "pack_sha256"
      "resource_class"
    ]
    && builtins.isString row.key
    && row.key == "${row.resource_class}-${bucketName row.identity_bucket}"
    && row.filename == "${row.key}.json"
    && builtins.isInt row.identity_bucket
    && row.identity_bucket >= 0
    && row.identity_bucket < scheduleBucketCount
    && builtins.hasAttr row.resource_class resourceClasses
    && builtins.isInt row.item_count
    && row.item_count > 0
    && builtins.isList row.item_ids
    && row.item_ids == lib.sort builtins.lessThan (lib.unique row.item_ids)
    && builtins.length row.item_ids == row.item_count
    && builtins.match "[0-9a-f]{64}" row.item_ids_sha256 != null
    && builtins.match "schedule-pack-v3:[0-9a-f]{64}" row.pack_id != null
    && builtins.match "[0-9a-f]{64}" row.pack_sha256 != null
    && builtins.hashString "sha256" (builtins.toJSON row.item_ids)
      == row.item_ids_sha256;
  mkStructuralPack =
    row:
    let
      policy = policyFor row.resource_class;
      itemIds = row.item_ids;
      packPath = "${structuralBoundary.packsDirectory}/${row.filename}";
      scheduleSource =
        assert ensure (
          builtins.hashFile "sha256" packPath == row.pack_sha256
        ) "structural pack ${row.key} bytes differ from its checked routing index";
        builtins.toFile "authority-graph-v3-structural-${row.key}.json" (
          builtins.readFile packPath
        );
    in
    {
      derivation = scheduleSource;
      memoryLimitMiB = policy.resource.memory_mib;
      packId = row.pack_id;
      inherit itemIds;
      inherit (policy) resource timing;
      payload = {
        identity_bucket = row.identity_bucket;
        resource_class = row.resource_class;
        pack_id = row.pack_id;
      };
      manifest = scheduleSource;
    };
  structuralPackRows = structuralPackPlan.packs or [ ];
  structuralPacks =
    assert ensure (
      builtins.isAttrs structuralPackPlan
      && builtins.attrNames structuralPackPlan == [
        "bucket_count"
        "format"
        "packs"
        "plan_id"
        "schema_version"
        "unit_count"
      ]
      && structuralPackPlan.format == "spaghetti-extractor-structural-pack-index-v3"
      && structuralPackPlan.schema_version == 3
      && structuralPackPlan.bucket_count == scheduleBucketCount
      && builtins.isString structuralPackPlan.plan_id
      && builtins.isInt structuralPackPlan.unit_count
      && structuralPackPlan.unit_count > 0
      && builtins.isList structuralPackRows
      && structuralPackRows != [ ]
      && builtins.all validStructuralPackRow structuralPackRows
      && builtins.foldl' (total: row: total + row.item_count) 0 structuralPackRows
        == structuralPackPlan.unit_count
    ) "structural pack index differs from checked source routing";
    builtins.listToAttrs (
      map (row: { name = row.key; value = mkStructuralPack row; }) structuralPackRows
    );

  mkDependencyPack = row:
    let
      policy = policyFor row.resource_class;
      packPath = "${dependencyBoundary.packsDirectory}/${row.filename}";
      scheduleSource =
        assert ensure (
          builtins.hashFile "sha256" packPath == row.schedule_sha256
        ) "dependency pack ${row.key} bytes differ from its checked routing index";
        builtins.toFile "authority-graph-v3-dependency-${row.key}.json" (
          builtins.readFile packPath
        );
      payload = {
        format = "spaghetti-extractor-prepared-dependency-pack-v3";
        schema_version = 3;
        pack_id = "dependency-pack-v3:${row.schedule_sha256}";
        identity_bucket = row.identity_bucket;
        resource_class = row.resource_class;
        selected_scc_ids = row.selected_scc_ids;
        selected_node_ids = row.selected_node_ids;
        closure_node_ids = row.closure_node_ids;
        closure_scc_ids = row.closure_scc_ids;
        inherit (policy) resource timing;
        schedule_sha256 = row.schedule_sha256;
      };
      packManifest = builtins.toFile "authority-graph-v3-dependency-${row.key}-pack.json" (
        builtins.toJSON payload
      );
    in {
      derivation = scheduleSource;
      memoryLimitMiB = policy.resource.memory_mib;
      packId = payload.pack_id;
      inherit (policy) resource timing;
      itemIds = row.selected_scc_ids;
      selectedSccIds = row.selected_scc_ids;
      inherit payload;
      manifest = packManifest;
      schedule = scheduleSource;
    };
  dependencyPacks =
    assert ensure (
      builtins.isAttrs dependencyPackPlan
      && builtins.attrNames dependencyPackPlan == [
        "bucket_count"
        "format"
        "node_count"
        "packs"
        "plan_id"
        "scc_count"
        "scc_ids_sha256"
        "schema_version"
      ]
      && dependencyPackPlan.format == "spaghetti-extractor-dependency-pack-index-v3"
      && dependencyPackPlan.schema_version == 3
      && dependencyPackPlan.bucket_count == scheduleBucketCount
      && builtins.isString dependencyPackPlan.plan_id
      && builtins.isInt dependencyPackPlan.node_count
      && dependencyPackPlan.node_count > 0
      && builtins.isInt dependencyPackPlan.scc_count
      && dependencyPackPlan.scc_count > 0
      && builtins.match "[0-9a-f]{64}" dependencyPackPlan.scc_ids_sha256 != null
    ) "dependency pack index has the wrong schema or authority binding";
    assert ensure (
      builtins.all validDependencyPackRow dependencyPackRows
    ) "dependency pack index contains a malformed pack";
    assert ensure (
      dependencyPackKeys == lib.unique dependencyPackKeys
    ) "dependency pack index repeats a pack key";
    assert ensure (
      builtins.length selectedPackSccIds == dependencyPackPlan.scc_count
      && builtins.hashString "sha256" (builtins.toJSON selectedPackSccIds)
        == dependencyPackPlan.scc_ids_sha256
    ) "dependency packs do not partition every checked SCC exactly once";
    builtins.listToAttrs (
    map (row: {
      name = row.key;
      value = mkDependencyPack row;
    }) dependencyPackRows
  );

  derivationMetadata =
    result:
    let
      value = result.derivation;
      isDerivation = lib.isDerivation value;
      outputPath = toString value;
    in
    {
      name = if isDerivation then value.name else builtins.baseNameOf outputPath;
      drv_path = if isDerivation then value.drvPath else null;
      output_path = outputPath;
      content_addressed = contentAddressed;
      memory_limit_mib = result.memoryLimitMiB or null;
    };

  uniqueDescriptors =
    descriptors:
    let
      grouped = lib.groupBy (
        descriptor: builtins.unsafeDiscardStringContext (toString descriptor.artifact)
      ) descriptors;
    in
    map (key: builtins.head grouped.${key}) (builtins.attrNames grouped);

  composeDescriptors =
    name: descriptors: aggregateDependencies:
    assert ensure (
      builtins.isList descriptors && descriptors != [ ]
    ) "composition ${name} has no shards";
    let
      atomic = lib.concatMap (descriptor: descriptor.leaves or [ descriptor ]) descriptors;
      unique = uniqueDescriptors atomic;
      prototype = builtins.head unique;
      sameKinds = builtins.all (descriptor: descriptor.expectedKind == prototype.expectedKind) unique;
      dependencies =
        if aggregateDependencies != null then
          aggregateDependencies
        else
          { };
      itemIds = lib.sort builtins.lessThan (
        lib.unique (lib.concatMap (descriptor: descriptor.itemIds) unique)
      );
      bundle = packHelpers.bundleArtifactShards {
        name = "authority-graph-v3-bundle-${sanitize name}";
        artifacts = map (descriptor: descriptor.artifact) unique;
        expectedKind = prototype.expectedKind;
        expectedRecordIds = itemIds;
        memoryLimitMiB = 512;
      };
    in
    assert ensure sameKinds "composition ${name} mixes artifact kinds";
    if builtins.length unique == 1 then
      prototype
    else
      {
        inherit (bundle)
          artifact
          derivation
          manifest
          result
          memoryLimitMiB
          ;
        inherit dependencies itemIds;
        expectedKind = prototype.expectedKind;
        composition = bundle;
        leaves = unique;
      };

  validateExternalShard =
    artifactName: expectedKind: allowedStatuses: shardKey: shardSpec:
    assert ensure (builtins.isAttrs shardSpec)
      "external artifact ${artifactName} shard ${shardKey} is invalid";
    assert ensure (
      shardSpec ? artifact
    ) "external artifact ${artifactName} shard ${shardKey} has no artifact";
    assert ensure (
      shardSpec ? expectedRecordIds
      && builtins.isList shardSpec.expectedRecordIds
    ) "external artifact ${artifactName} shard ${shardKey} has no record inventory";
    let
      itemIds = lib.sort builtins.lessThan shardSpec.expectedRecordIds;
      validation = artifactSetConstructor {
        inherit
          pkgs
          pythonEnv
          pythonSource
          contentAddressed
          expectedKind
          ;
        name = "authority-graph-v3-input-${sanitize artifactName}-${sanitize shardKey}";
        artifact = shardSpec.artifact;
        allowedStatuses = shardSpec.allowedStatuses or allowedStatuses;
        expectedRecordIds = itemIds;
      };
      gatedArtifact =
        pkgs.runCommand "authority-graph-v3-validated-${sanitize artifactName}-${sanitize shardKey}"
          (
            {
              preferLocalBuild = false;
              allowSubstitutes = true;
            }
            // caAttrs
          )
          ''
            set -euo pipefail
            test -s ${validation.validation}
            ln -s ${toString shardSpec.artifact} "$out"
          '';
    in
    {
      artifact = toString gatedArtifact;
      derivation = gatedArtifact;
      manifest = "${gatedArtifact}/manifest.json";
      inherit expectedKind itemIds validation;
      dependencies = { };
    };

  checkedExternalArtifacts = lib.mapAttrs (
    artifactName: spec:
    assert ensure (builtins.isAttrs spec) "external artifact ${artifactName} is not an attribute set";
    assert ensure (spec ? expectedKind) "external artifact ${artifactName} has no expectedKind";
    assert ensure (
      spec.expectedKind == externalArtifactKinds.${artifactName}
    ) "external artifact ${artifactName} kind differs from the graph manifest";
    assert ensure (
      (spec ? artifact) != (spec ? shards)
    ) "external artifact ${artifactName} must provide exactly one of artifact or shards";
    let
      allowedStatuses =
        spec.allowedStatuses or [
          "complete"
          "incomplete"
          "violated"
        ];
      shardSpecs =
        if spec ? shards then
          spec.shards
        else
          {
            whole = {
              inherit (spec) artifact;
              expectedRecordIds = spec.expectedRecordIds or [ ];
            };
          };
      shards = lib.mapAttrs (validateExternalShard artifactName spec.expectedKind
        allowedStatuses
      ) shardSpecs;
      descriptors = builtins.attrValues shards;
      declaredIds = lib.sort builtins.lessThan (spec.expectedRecordIds or [ ]);
      observedIds = lib.sort builtins.lessThan (
        lib.concatMap (descriptor: descriptor.itemIds) descriptors
      );
      aggregate = composeDescriptors "external-${artifactName}-aggregate" descriptors null;
    in
    assert ensure (
      builtins.isAttrs shardSpecs && shardSpecs != { }
    ) "external artifact ${artifactName} has no shards";
    assert ensure (
      observedIds == declaredIds
    ) "external artifact ${artifactName} shards do not exactly cover its record inventory";
    aggregate
    // {
      inherit shards;
      descriptor = aggregate;
    }
  ) externalArtifacts;

  allowedPhaseFields = [
    "expected_kind"
    "form"
    "inputs"
    "max_pack_bytes"
    "phase_id"
    "phase_reference"
    "resource"
    "resource_class"
    "schedule_record_inputs"
    "scc_aligned_inputs"
    "source_input"
    "status"
    "timing"
    "unit_aligned_inputs"
  ];
  normalizePhase =
    spec:
    assert ensure (builtins.isAttrs spec) "phase entry is not an attribute set";
    assert ensure (
      lib.subtractLists allowedPhaseFields (builtins.attrNames spec) == [ ]
    ) "phase ${(spec.phase_id or "<unknown>")} has unexpected fields";
    assert ensure (
      spec ? phase_id && builtins.isString spec.phase_id && spec.phase_id != ""
    ) "phase has no stable phase_id";
    assert ensure (
      spec ? phase_reference && builtins.isString spec.phase_reference
    ) "phase ${spec.phase_id} has no phase_reference";
    assert ensure (
      spec ? expected_kind && builtins.isString spec.expected_kind
    ) "phase ${spec.phase_id} has no expected_kind";
    assert ensure (
      spec ? inputs && builtins.isAttrs spec.inputs && spec.inputs != { }
    ) "phase ${spec.phase_id} has no inputs";
    assert ensure (builtins.elem (spec.form or null) [
      "map_units"
      "map_sccs"
      "reduce"
    ]) "phase ${spec.phase_id} has invalid form";
    assert ensure (
      if spec.form == "map_units" then
        spec ? source_input && builtins.hasAttr spec.source_input spec.inputs
      else
        !(spec ? source_input)
    ) "phase ${spec.phase_id} has an invalid source_input declaration";
    assert ensure (
      if spec.form == "map_sccs" then
        spec ? schedule_record_inputs
        && builtins.isList spec.schedule_record_inputs
        && spec.schedule_record_inputs != [ ]
        && lib.sort builtins.lessThan (lib.unique spec.schedule_record_inputs)
          == spec.schedule_record_inputs
        && builtins.all (name: builtins.hasAttr name spec.inputs)
          spec.schedule_record_inputs
      else
        !(spec ? schedule_record_inputs)
        || spec.schedule_record_inputs == [ ]
    ) "phase ${spec.phase_id} has invalid schedule_record_inputs";
    assert ensure (
      builtins.all (name: builtins.hasAttr name spec.inputs)
        ((spec.unit_aligned_inputs or [ ]) ++ (spec.scc_aligned_inputs or [ ]))
      && lib.intersectLists (spec.unit_aligned_inputs or [ ])
        (spec.scc_aligned_inputs or [ ]) == [ ]
      && (spec.form != "reduce"
        || ((spec.unit_aligned_inputs or [ ]) == [ ]
          && (spec.scc_aligned_inputs or [ ]) == [ ]))
      && (spec.form != "map_units" || (spec.scc_aligned_inputs or [ ]) == [ ])
    ) "phase ${spec.phase_id} has invalid aligned input declarations";
    spec
    // {
      status = spec.status or "complete";
      resource_class = spec.resource_class or "small";
      unit_aligned_inputs = spec.unit_aligned_inputs or [ ];
      scc_aligned_inputs = spec.scc_aligned_inputs or [ ];
      schedule_record_inputs = spec.schedule_record_inputs or [ ];
    };
  phaseSpecs = map normalizePhase (graph.phases or [ ]);
  phaseIds = map (spec: spec.phase_id) phaseSpecs;
  externalIds = builtins.attrNames externalArtifacts;
  inputReferences = spec: builtins.attrValues spec.inputs;
  validateReference =
    phaseId: reference:
    assert ensure (builtins.isAttrs reference)
      "phase ${phaseId} input reference is not an attribute set";
    assert ensure (
      builtins.attrNames reference == [
        "id"
        "source"
      ]
    ) "phase ${phaseId} input reference must contain only id and source";
    assert ensure (builtins.elem reference.source [
      "external"
      "phase"
    ]) "phase ${phaseId} input has invalid source ${(reference.source or "<missing>")}";
    assert ensure (
      if reference.source == "external" then
        builtins.elem reference.id externalIds
      else
        builtins.elem reference.id phaseIds
    ) "phase ${phaseId} input refers to unknown ${reference.source} ${reference.id}";
    reference;
  checkedPhaseSpecs = map (
    spec:
    spec
    // {
      inputs = lib.mapAttrs (_: validateReference spec.phase_id) spec.inputs;
    }
  ) phaseSpecs;
  phaseDependencies =
    spec:
    map (reference: reference.id) (
      builtins.filter (reference: reference.source == "phase") (inputReferences spec)
    );
  topo = lib.toposort (
    left: right: builtins.elem left.phase_id (phaseDependencies right)
  ) checkedPhaseSpecs;
  orderedPhases =
    if topo ? result then
      topo.result
    else
      throw "authority-graph-v3: phase manifest contains a dependency cycle";

  phaseModule = spec: builtins.head (lib.splitString ":" spec.phase_reference);
  phasePythonSourceFor =
    spec:
    if builtins.hasAttr spec.phase_id phasePythonSources then
      phasePythonSources.${spec.phase_id}
    else if
      phaseModule spec == "spaghetti_extractor" || lib.hasPrefix "spaghetti_extractor." (phaseModule spec)
    then
      import ./python-module-closure.nix {
        inherit
          pkgs
          moduleIndexFile
          repositoryRoot
          ;
        source = pythonSource;
        modules = [ (phaseModule spec) ];
        name = "authority-graph-v3-${sanitize spec.phase_id}-python-closure";
      }
    else
      throw "authority-graph-v3: custom phase ${spec.phase_id} requires phasePythonSources.${spec.phase_id}";

  resolveDescriptor =
    state: phaseId: reference:
    if reference.source == "external" then
      checkedExternalArtifacts.${reference.id}.descriptor
    else if builtins.hasAttr reference.id state then
      state.${reference.id}.descriptor
    else
      throw "authority-graph-v3: phase ${phaseId} depends on unscheduled phase ${reference.id}";
  resolveSource =
    state: phaseId: reference:
    if reference.source == "external" then
      checkedExternalArtifacts.${reference.id}
    else if builtins.hasAttr reference.id state then
      state.${reference.id}
    else
      throw "authority-graph-v3: phase ${phaseId} depends on unscheduled phase ${reference.id}";
  phasePolicy =
    spec: resourceClass:
    let
      base = policyFor resourceClass;
      policy = {
        resource = spec.resource or base.resource;
        timing = base.timing // (spec.timing or { });
      };
    in
    validatePolicy resourceClass policy;

  selectRecordDescriptors =
    name: source: requiredIds: exact:
    let
      candidates = builtins.attrValues source.shards;
      selected = builtins.filter (
        descriptor: builtins.any (recordId: builtins.elem recordId requiredIds) descriptor.itemIds
      ) candidates;
      observedIds = lib.sort builtins.lessThan (
        lib.unique (lib.concatMap (descriptor: descriptor.itemIds) selected)
      );
      missing = lib.subtractLists observedIds requiredIds;
      prototype = builtins.head selected;
      bundle = packHelpers.bundleArtifactShards {
        name = "authority-graph-v3-bundle-${sanitize name}";
        artifacts = map (descriptor: descriptor.artifact) selected;
        expectedKind = prototype.expectedKind;
        expectedRecordIds = requiredIds;
        memoryLimitMiB = 512;
      };
      selection = {
        inherit (bundle)
          artifact
          derivation
          manifest
          result
          memoryLimitMiB
          ;
        dependencies = { };
        expectedKind = prototype.expectedKind;
        itemIds = requiredIds;
        composition = bundle;
        leaves = selected;
      };
    in
    assert ensure (requiredIds != [ ]) "record selection ${name} is empty";
    assert ensure (selected != [ ]) "record selection ${name} found no source shards";
    assert ensure (missing == [ ]) "record selection ${name} is missing records";
    if builtins.length selected == 1 && prototype.itemIds == requiredIds then
      prototype
    else
      selection;

  selectStructuralDescriptor =
    name: source: packKey: itemIds:
    if
      builtins.hasAttr packKey (source.shards or { })
      && source.shards.${packKey}.itemIds == itemIds
    then
      source.shards.${packKey}
    else
      selectRecordDescriptors name source itemIds true;

  instantiatePhase =
    state: spec:
    let
      fullInputDescriptors = lib.mapAttrs (_: resolveDescriptor state spec.phase_id) spec.inputs;
      maxPackBytes = spec.max_pack_bytes or null;
      commonFor = inputs: memoryLimitMiB: {
        inherit
          pkgs
          pythonEnv
          bindings
          contentAddressed
          memoryLimitMiB
          ;
        pythonSource = phasePythonSourceFor spec;
        inputs = lib.mapAttrs (_: descriptor: descriptor.artifact) inputs;
        phaseReference = spec.phase_reference;
        expectedKind = spec.expected_kind;
        status = spec.status;
        inherit maxPackBytes;
      };
    in
    if spec.form == "map_units" then
      assert ensure (
        structuralPacks != { }
      ) "map_units phase ${spec.phase_id} cannot run with an empty structural schedule";
      let
        source = resolveSource state spec.phase_id spec.inputs.${spec.source_input};
        shards = lib.mapAttrs (
          packKey: pack:
          let
            policy = phasePolicy spec pack.payload.resource_class;
            inputDescriptors = lib.mapAttrs (
              inputName: descriptor:
              if inputName == spec.source_input || builtins.elem inputName spec.unit_aligned_inputs then
                selectStructuralDescriptor
                  "${spec.phase_id}-${packKey}-${inputName}"
                  (resolveSource state spec.phase_id spec.inputs.${inputName})
                  packKey pack.itemIds
              else
                descriptor
            ) fullInputDescriptors;
            result = phaseConstructor (
              commonFor inputDescriptors policy.resource.memory_mib
              // {
                name = "authority-graph-v3-${sanitize spec.phase_id}-${packKey}";
                selectedRecordIds = pack.itemIds;
                workManifest = pack.manifest;
              }
            );
            descriptor = result // {
              expectedKind = spec.expected_kind;
              itemIds = pack.itemIds;
              dependencies = inputDescriptors;
            };
          in
          descriptor
          // {
            descriptor = descriptor;
            schedulePack = pack;
            inputCompositions = inputDescriptors;
            metadata = {
              phase_id = spec.phase_id;
              artifact_kind = spec.expected_kind;
              form = spec.form;
              schedule_pack_id = pack.packId;
              selected_record_ids = pack.itemIds;
              inherit (policy) resource timing;
              derivation = derivationMetadata result;
            };
          }
        ) structuralPacks;
        aggregate = composeDescriptors "${spec.phase_id}-aggregate" (
          map (shard: shard.descriptor) (builtins.attrValues shards)
        ) fullInputDescriptors;
      in
      aggregate
      // {
        descriptor = aggregate;
        inherit shards;
        metadata = {
          phase_id = spec.phase_id;
          artifact_kind = spec.expected_kind;
          form = spec.form;
          record_ids = aggregate.itemIds;
          derivation = derivationMetadata aggregate;
          shards = lib.mapAttrs (_: shard: shard.metadata) shards;
        };
      }
    else if spec.form == "map_sccs" then
      assert ensure (
        dependencyPacks != { }
      ) "map_sccs phase ${spec.phase_id} cannot run with an empty dependency schedule";
      let
        sources = lib.mapAttrs (_: resolveSource state spec.phase_id) spec.inputs;
        shards = lib.mapAttrs (
          packKey: pack:
          let
            policy = phasePolicy spec pack.payload.resource_class;
            unitIds = pack.payload.closure_node_ids;
            inputDescriptors = lib.mapAttrs (
              inputName: source:
              if builtins.elem inputName spec.schedule_record_inputs
                || builtins.elem inputName spec.unit_aligned_inputs then
                selectRecordDescriptors
                  "${spec.phase_id}-${packKey}-${inputName}-units"
                  source unitIds true
              else if builtins.elem inputName spec.scc_aligned_inputs then
                selectRecordDescriptors
                  "${spec.phase_id}-${packKey}-${inputName}-sccs"
                  source pack.itemIds true
              else
                source.descriptor
            ) sources;
            result = phaseConstructor (
              commonFor inputDescriptors policy.resource.memory_mib
              // {
                name = "authority-graph-v3-${sanitize spec.phase_id}-${packKey}";
                schedule = pack.schedule;
                selectedSccIds = pack.itemIds;
                workManifest = pack.manifest;
              }
            );
            descriptor = result // {
              expectedKind = spec.expected_kind;
              itemIds = pack.itemIds;
              dependencies = inputDescriptors;
            };
          in
          descriptor
          // {
            descriptor = descriptor;
            schedulePack = pack;
            inputCompositions = inputDescriptors;
            metadata = {
              phase_id = spec.phase_id;
              artifact_kind = spec.expected_kind;
              form = spec.form;
              schedule_pack_id = pack.packId;
              selected_scc_ids = pack.itemIds;
              inherit (policy) resource timing;
              derivation = derivationMetadata result;
            };
          }
        ) dependencyPacks;
        aggregate = composeDescriptors "${spec.phase_id}-aggregate" (
          map (shard: shard.descriptor) (builtins.attrValues shards)
        ) fullInputDescriptors;
      in
      aggregate
      // {
        descriptor = aggregate;
        inherit shards;
        metadata = {
          phase_id = spec.phase_id;
          artifact_kind = spec.expected_kind;
          form = spec.form;
          record_ids = aggregate.itemIds;
          derivation = derivationMetadata aggregate;
          shards = lib.mapAttrs (_: shard: shard.metadata) shards;
        };
      }
    else
      let
        policy = phasePolicy spec spec.resource_class;
        result = phaseConstructor (
          commonFor fullInputDescriptors policy.resource.memory_mib
          // {
            name = "authority-graph-v3-${sanitize spec.phase_id}";
          }
        );
        descriptor = result // {
          expectedKind = spec.expected_kind;
          itemIds = [ ];
          dependencies = fullInputDescriptors;
        };
      in
      result
      // {
        inherit descriptor;
        shards = { };
        metadata = {
          phase_id = spec.phase_id;
          artifact_kind = spec.expected_kind;
          form = spec.form;
          inherit (policy) resource timing;
          derivation = derivationMetadata result;
        };
      };

  phases = builtins.foldl' (
    state: spec:
    state
    // {
      "${spec.phase_id}" = instantiatePhase state spec;
    }
  ) { } orderedPhases;
  outputIds = graph.outputs or phaseIds;
  outputs = lib.genAttrs outputIds (
    phaseId:
    if builtins.hasAttr phaseId phases then
      phases.${phaseId}.artifact
    else
      throw "authority-graph-v3: output names unknown phase ${phaseId}"
  );

  packMetadata =
    packs:
    lib.mapAttrs (_: pack: {
      inherit (pack)
        packId
        itemIds
        resource
        timing
        ;
      derivation = derivationMetadata pack;
    }) packs;
  metadataValue = {
    format = "spaghetti-extractor-authority-graph-metadata-v3";
    schema_version = 3;
    graph_id = graphId;
    boundaries = {
      structural = {
        plan_id = structuralPackPlan.plan_id;
        unit_count = structuralPackPlan.unit_count;
        derivation = derivationMetadata structuralBoundary;
      };
      dependency = {
        plan_id = dependencyPackPlan.plan_id;
        node_count = dependencyPackPlan.node_count;
        scc_count = dependencyPackPlan.scc_count;
        derivation = derivationMetadata dependencyBoundary;
      };
    };
    packs = {
      structural = packMetadata structuralPacks;
      dependency_scc = packMetadata dependencyPacks;
    };
    phases = lib.mapAttrs (_: phase: phase.metadata) phases;
    outputs = outputIds;
  };
  # Graph metadata records derivation and output paths, so its string context
  # must remain attached through a derivation-backed store file.
  metadata = pkgs.writeText "authority-graph-v3-${sanitize graphId}-metadata.json" (
    builtins.toJSON metadataValue
  );
in
assert ensure (builtins.isAttrs graph) "manifest is not an attribute set";
assert ensure (
  preplannedBoundaries == null
  || (
    builtins.isAttrs preplannedBoundaries
    && builtins.attrNames preplannedBoundaries == [ "dependency" "structural" ]
    && validPreplannedBoundary preplannedBoundaries.structural
    && validPreplannedBoundary preplannedBoundaries.dependency
    && structuralSchedule == null
    && dependencySchedule == null
    && requireStructuralCoverage
  )
) "preplanned boundaries must be complete checked framework outputs with default coverage";
assert ensure (builtins.elem scheduleBucketCount [ 1 2 4 8 16 32 64 ])
  "scheduleBucketCount must be a power-of-two divisor of 64";
assert ensure (
  (graph.format or null) == "spaghetti-extractor-authority-graph-v3"
) "manifest format is not spaghetti-extractor-authority-graph-v3";
assert ensure (builtins.isString graphId && graphId != "") "manifest has no graph_id";
assert ensure (builtins.isList (graph.phases or null)) "manifest phases are not an array";
assert ensure (phaseIds == lib.unique phaseIds) "manifest repeats a phase_id";
assert ensure (bindings != [ ] && builtins.isList bindings) "bindings must be a nonempty list";
assert ensure (builtins.isAttrs phasePythonSources) "phasePythonSources is not an attribute set";
assert ensure (
  lib.subtractLists phaseIds (builtins.attrNames phasePythonSources) == [ ]
) "phasePythonSources contains an unknown phase_id";
assert ensure (builtins.isAttrs externalArtifactKinds)
  "manifest external_artifact_kinds is not an attribute set";
assert ensure (
  builtins.attrNames externalArtifactKinds == builtins.attrNames externalArtifacts
) "manifest external_artifact_kinds does not exactly cover external artifacts";
assert ensure (builtins.all (kind: builtins.isString kind && kind != "") (
  builtins.attrValues externalArtifactKinds
)) "manifest external_artifact_kinds contains an invalid kind";
assert ensure (builtins.all
  (
    artifactName:
    builtins.isAttrs externalArtifacts.${artifactName}
    && (externalArtifacts.${artifactName}.expectedKind or null) == externalArtifactKinds.${artifactName}
  )
  (builtins.attrNames externalArtifacts)
) "external artifact expectedKind values differ from the graph manifest";
assert ensure (builtins.isString structuralPackPlan.plan_id)
  "structural boundary did not produce a plan";
assert ensure (builtins.isString dependencyPackPlan.plan_id)
  "dependency boundary did not produce a plan";
{
  inherit
    dependencyPacks
    metadata
    metadataValue
    outputs
    phases
    structuralPacks
    ;
  structural = {
    boundary = structuralBoundary;
    plan = structuralPackPlan;
    packs = structuralPacks;
  };
  dependency = {
    boundary = dependencyBoundary;
    plan = dependencyPackPlan;
    packs = dependencyPacks;
  };
  external = checkedExternalArtifacts;
}
