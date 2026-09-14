# spaghetti-extractor-python-role: authority
{
  pkgs,
  pythonEnv,
  pythonSource ? null,
  intent,
  interfaceRoot,
  sourceRoot,
  bindingIntentRoot,
  relationRoot ? null,
  namePrefix,
  behavioralCPackage,
  linkedSemanticModule,
}:

let
  lib = pkgs.lib;
  intentPayload = builtins.fromJSON (builtins.readFile intent);
  intentRoot = builtins.dirOf intent;
  liftingIntent = import ./component-lifting-intent.nix {
    inherit pkgs pythonEnv namePrefix intent;
  };

  interfaceIndexPath = interfaceRoot + "/index.json";
  interfaceIndex = builtins.fromJSON (builtins.readFile interfaceIndexPath);
  interfaceIndexPhase = import ./component-v5-index.nix {
    inherit pkgs pythonEnv namePrefix;
    root = interfaceRoot;
    kind = "interface";
  };
  interfaceRows = interfaceIndex.components or [ ];
  interfaceRowsById = builtins.listToAttrs (map (row: {
    name = row.component_id;
    value = row;
  }) interfaceRows);
  bindingIndexPath = bindingIntentRoot + "/index.json";
  bindingIndex = builtins.fromJSON (builtins.readFile bindingIndexPath);
  bindingIndexPhase = import ./component-v5-index.nix {
    inherit pkgs pythonEnv namePrefix;
    root = bindingIntentRoot;
    kind = "machine_binding";
  };
  bindingRows = bindingIndex.components or [ ];
  bindingRowsById = builtins.listToAttrs (map (row: {
    name = row.component_id;
    value = row;
  }) bindingRows);
  componentRowsById = builtins.listToAttrs (map (row: {
    name = row.id;
    value = row;
  }) intentPayload.components);
  groupRowsById = builtins.listToAttrs (map (row: {
    name = row.id;
    value = row;
  }) (intentPayload.groups or [ ]));

  v5InterfaceIds = builtins.attrNames interfaceRowsById;
  v5ComponentIds = builtins.filter
    (id: builtins.hasAttr id interfaceRowsById)
    (builtins.attrNames bindingRowsById);
  sourcePackageComponentIds = builtins.filter
    (id:
      builtins.hasAttr id componentRowsById
      && (componentRowsById.${id}.source or null) != null)
    v5InterfaceIds;
  sourceComponentIds = builtins.filter
    (id:
      builtins.hasAttr id componentRowsById
      && (componentRowsById.${id}.source or null) != null)
    v5ComponentIds;

  # Direct-provider admission is a proof-supported machine-overlay shape, not
  # a target allowlist. Multi-unit operations, checked external/callback
  # services, component-operation services, and reviewed relation intents are
  # and contextual bisimulation are handled by the direct qualifier. Explicit object
  # selectors remain transitional until their direct proof inputs migrate.
  directV6ProviderIds = builtins.filter (id:
    let
      component = componentRowsById.${id};
      payload = bindingIntentPayloads.${id};
      operations = payload.operations or [ ];
      operation = if builtins.length operations == 1
        then builtins.head operations else { };
    in
      builtins.elem id sourceComponentIds
      && (payload.status or null) == "complete"
      && (payload.blockers or [ ]) == [ ]
      && builtins.length operations == 1
      && builtins.length (operation.unit_ids or [ ]) > 0
      && (operation.object_authority_selectors or [ ]) == [ ]
      && builtins.all
        (binding:
          let kind = binding.provider.kind or null;
          in builtins.elem (binding.mediation or null) [ "direct" "callback" ]
            && builtins.elem kind [
              "external_call"
              "interface_method"
              "component_operation"
            ])
        (((operation.machine_projection or { }).service_bindings or [ ]))
  ) sourceComponentIds;

  interfaceIntentPath = id:
    interfaceRoot + "/${interfaceRowsById.${id}.interface_intent}";
  bindingIntentPath = id:
    bindingIntentRoot + "/${bindingRowsById.${id}.binding_intent}";
  bindingIntentPayloads = builtins.listToAttrs (map (id: {
    name = id;
    value = builtins.fromJSON (builtins.readFile (bindingIntentPath id));
  }) v5ComponentIds);
  bindingIntentPaths = builtins.listToAttrs (map (id: {
    name = id;
    value = bindingIntentPath id;
  }) v5ComponentIds);
  proofClassifications = builtins.listToAttrs (map (id: {
    name = id;
    value = componentRowsById.${id}.proof_classification or "machine_overlay";
  }) v5ComponentIds);
  directProviderNeedsLinkedModule = builtins.listToAttrs (map (id: {
    name = id;
    value = builtins.any (candidateId:
      proofClassifications.${candidateId} == "encapsulated_owned"
      || builtins.any
        (operation:
          (operation.callback_ids or [ ]) != [ ]
          || builtins.any
            (binding: (binding.mediation or null) == "callback")
            (((operation.machine_projection or { }).service_bindings or [ ])))
        bindingIntentPayloads.${candidateId}.operations
    ) (dependencyClosure [ id ]);
  }) v5ComponentIds);

  v5Interfaces = builtins.listToAttrs (map (id: {
    name = id;
    value = import ./component-v5-interface-package.nix {
      inherit pkgs pythonEnv namePrefix;
      componentId = id;
      intent = interfaceIntentPath id;
    };
  }) v5InterfaceIds);

  sourcePackagePhases = builtins.listToAttrs (map (id: {
    name = id;
    value = import ./component-source-package-v3.nix {
      inherit pkgs pythonEnv namePrefix sourceRoot;
      componentId = id;
      sourceIntent = componentRowsById.${id}.source;
    };
  }) sourcePackageComponentIds);
  sourcePackages = lib.mapAttrs (_: value: value.package) sourcePackagePhases;

  operationServiceBindings = operation:
    let projection = operation.machine_projection or { };
    in projection.service_bindings or [ ];

  firstEntryUnit = id:
    let operation = builtins.head bindingIntentPayloads.${id}.operations;
        projection = operation.machine_projection.operation or { };
    in builtins.head projection.entry_unit_ids;
  providerEntryUnits = builtins.listToAttrs (map (id: {
    name = id;
    value = firstEntryUnit id;
  }) v5ComponentIds);

  relationComponentIds = builtins.filter
    (id: componentRowsById.${id} ? relation_intent)
    sourceComponentIds;
  relationIntents = builtins.listToAttrs (map (id: {
    name = id;
    value = intentRoot + "/${componentRowsById.${id}.relation_intent}";
  }) relationComponentIds);
  bisimulationComponentIds = builtins.filter
    (id: componentRowsById.${id} ? bisimulation_intent)
    sourceComponentIds;
  bisimulationIntents = builtins.listToAttrs (map (id: {
    name = id;
    value = intentRoot + "/${componentRowsById.${id}.bisimulation_intent}";
  }) bisimulationComponentIds);

  componentDependencies = id: lib.unique (lib.concatMap
    (service:
      let provider = service.provider or { };
      in lib.optional
        ((provider.kind or null) == "component_operation"
          && builtins.hasAttr (provider.component_id or "") sourcePackages)
        provider.component_id)
    (lib.concatMap operationServiceBindings
      (bindingIntentPayloads.${id}.operations or [ ])));
  dependencyClosure = ids:
    let expanded = lib.unique (ids ++ lib.concatMap componentDependencies ids);
    in if builtins.length expanded == builtins.length ids
      then builtins.sort builtins.lessThan expanded
      else dependencyClosure expanded;
  expandSelection = selection:
    let
      expandId = id:
        if builtins.hasAttr id componentRowsById then [ id ]
        else lib.concatMap expandId groupRowsById.${id}.members;
    in if selection.activation != "enabled" then [ ] else expandId selection.id;
  rootIdsFor = configuration: builtins.filter
    (id: builtins.hasAttr id sourcePackages)
    (lib.unique (lib.concatMap expandSelection configuration.selections));
  selectedIdsFor = configuration: dependencyClosure (rootIdsFor configuration);
  selectedComponentIdsByConfiguration = builtins.listToAttrs
    (map (configuration: {
      name = configuration.id;
      value = selectedIdsFor configuration;
    }) intentPayload.configurations);

  # Qualification consumes this independently content-addressed projection.
  # Presentation work packages can change without invalidating CBMC or object
  # compilation when the owned semantic facts remain byte-identical.
  v6SemanticSlices = builtins.listToAttrs (map (id: {
    name = id;
    value = import ./component-semantic-slice-v2.nix {
      inherit pkgs pythonEnv namePrefix;
      componentId = id;
      inherit linkedSemanticModule;
      bindingIntent = bindingIntentPaths.${id};
    };
  }) v5ComponentIds);
  directProviderComponentsByConsumer = builtins.listToAttrs (map (id: {
    name = id;
    value = builtins.listToAttrs (map (providerId: {
      name = providerId;
      value = {
        interfacePackage = v5Interfaces.${providerId}.derivation;
        bindingIntent = bindingIntentPaths.${providerId};
        semanticSlice = v6SemanticSlices.${providerId}.semanticSlice;
        sourcePackage = sourcePackages.${providerId};
        proofClassification = proofClassifications.${providerId};
      };
    }) (builtins.filter (providerId: providerId != id)
      (dependencyClosure [ id ])));
  }) v5ComponentIds);

  # V6 is the direct operator projection over the canonical semantic module.
  # It intentionally bypasses the public V4 contract / V5 machine-binding
  # reducer chain retained temporarily by provider qualification.
  v6WorkPackages = builtins.listToAttrs (map (id: {
    name = id;
    value = import ./component-v6-work-package.nix {
      inherit pkgs pythonEnv namePrefix behavioralCPackage;
      componentId = id;
      interfacePackage = v5Interfaces.${id}.derivation;
      bindingIntent = bindingIntentPath id;
      inherit linkedSemanticModule;
      proofClassification = componentRowsById.${id}.proof_classification
        or "machine_overlay";
      sourcePackage = if builtins.hasAttr id sourcePackages
        then sourcePackages.${id} else null;
    };
  }) v5ComponentIds);
  componentBoundarySubjects = lib.mapAttrs' (id: value:
    lib.nameValuePair "component:${id}" value
  ) v6WorkPackages;
  componentEntryRvas = lib.mapAttrs (_: payload:
    builtins.sort builtins.lessThan (
      lib.unique (lib.concatMap (operation: operation.entry_rvas) payload.operations)
    )
  ) bindingIntentPayloads;
  allComponentEntryRvas = lib.concatLists (builtins.attrValues componentEntryRvas);
  _uniqueComponentEntryRvas = assert
    builtins.length allComponentEntryRvas
      == builtins.length (lib.unique allComponentEntryRvas);
    true;
  boundarySubjects = componentBoundarySubjects;

  sourceAssets = lib.concatMap (row:
    let source = row.source or null;
    in if source == null then [ ] else map (relative: {
      path = toString (sourceRoot + "/${relative}");
      role = "component_source";
      owner = row.id;
    }) (source.files ++ source.shared_inputs)
  ) intentPayload.components;
  relationAssets = lib.concatMap (row:
    lib.optional (row ? relation_intent) {
      path = toString (intentRoot + "/${row.relation_intent}");
      role = "component_relation_intent";
      owner = row.id;
    }
  ) intentPayload.components;
  bisimulationAssets = lib.concatMap (row:
    lib.optional (row ? bisimulation_intent) {
      path = toString (intentRoot + "/${row.bisimulation_intent}");
      role = "component_bisimulation_intent";
      owner = row.id;
    }
  ) intentPayload.components;
  interfaceAssets = [ {
    path = toString interfaceIndexPath;
    role = "component_interface_index";
    owner = "component-workflow";
  } ] ++ map (row: {
    path = toString (interfaceRoot + "/${row.interface_intent}");
    role = "component_interface_intent";
    owner = row.component_id;
  }) interfaceRows;
  bindingAssets = [ {
    path = toString bindingIndexPath;
    role = "component_binding_index";
    owner = "component-workflow";
  } ] ++ map (row: {
    path = toString (bindingIntentRoot + "/${row.binding_intent}");
    role = "component_binding_intent";
    owner = row.component_id;
  }) bindingRows;
  assetInventory = [ {
    path = toString intent;
    role = "component_lifting_intent";
    owner = "component-workflow";
  } ] ++ sourceAssets ++ relationAssets ++ bisimulationAssets
    ++ interfaceAssets ++ bindingAssets;

  liftUnitIndex = builtins.listToAttrs (map (row: {
    name = row.id;
    value = {
      kind = "component";
      label = row.label;
      entryRvas = componentEntryRvas.${row.id} or [ ];
      members = [ ];
      hasSource = builtins.hasAttr row.id sourcePackages;
      hasInterfaceV5 = builtins.hasAttr row.id v5Interfaces;
      hasBindingIntent = builtins.hasAttr row.id bindingIntentPaths;
      hasSemanticSliceV2 = builtins.hasAttr row.id v6SemanticSlices;
      directProviderEligible = builtins.elem row.id directV6ProviderIds;
      hasWorkPackageV6 = builtins.hasAttr row.id v6WorkPackages;
    };
  }) intentPayload.components ++ map (row: {
    name = row.id;
    value = {
      kind = "group";
      label = row.label;
      entryRvas = [ ];
      members = row.members;
      hasSource = false;
      hasInterfaceV5 = false;
      hasBindingIntent = false;
      hasSemanticSliceV2 = false;
      directProviderEligible = false;
      hasWorkPackageV6 = false;
    };
  }) (intentPayload.groups or [ ]));
  configurationIndex = builtins.listToAttrs (map (configuration: {
    name = configuration.id;
    value = {
      kind = "configuration";
      label = configuration.label;
      selections = configuration.selections;
      selectedComponentIds =
        selectedComponentIdsByConfiguration.${configuration.id};
      allSelectedProvidersEligible = builtins.all
        (id: builtins.elem id directV6ProviderIds)
        selectedComponentIdsByConfiguration.${configuration.id};
      mode = configuration.mode or "hybrid";
    };
  }) intentPayload.configurations);
  bundle = pkgs.linkFarm "${namePrefix}-component-lifting-v5" (
    [
      { name = "lifting-intent"; path = liftingIntent.derivation; }
      { name = "interface-index"; path = interfaceIndexPhase.derivation; }
      { name = "machine-binding-index"; path = bindingIndexPhase.derivation; }
    ]
    ++ lib.mapAttrsToList (name: value: {
      inherit name;
      path = value.derivation;
    }) v5Interfaces
    ++ lib.mapAttrsToList (name: value: {
      name = "semantic-slice-${name}";
      path = value.derivation;
    }) v6SemanticSlices
    ++ lib.mapAttrsToList (name: path: {
      name = "source-${name}";
      inherit path;
    }) sourcePackages
    ++ lib.mapAttrsToList (name: value: {
      name = "work-package-${name}";
      path = value.derivation;
    }) v6WorkPackages
  );
in
assert intentPayload.format
  == "spaghetti-extractor-component-lifting-intent-v1";
assert interfaceIndex.format
  == "spaghetti-extractor-component-interface-index-v5";
assert bindingIndex.format
  == "spaghetti-extractor-component-machine-binding-index-v5";
assert _uniqueComponentEntryRvas;
{
  inherit liftingIntent interfaceIndexPhase bindingIndexPhase
    sourcePackages sourcePackagePhases
    v5Interfaces v6WorkPackages
    v6SemanticSlices bindingIntentPaths proofClassifications
    directProviderNeedsLinkedModule directProviderComponentsByConsumer
    componentBoundarySubjects boundarySubjects componentEntryRvas
    selectedComponentIdsByConfiguration directV6ProviderIds providerEntryUnits
    relationIntents bisimulationIntents
    liftUnitIndex configurationIndex assetInventory bundle;
  v5InterfaceIndex = interfaceIndex;
  v5BindingIndex = bindingIndex;
  contractIds = builtins.attrNames liftUnitIndex;
}
