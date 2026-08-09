{
  pkgs,
  pythonEnv,
  pythonSource,
}:

let
  mkInput =
    name:
    pkgs.writeText "static-hybrid-v2-fixture-${name}.json" (
      builtins.toJSON {
        format = "spaghetti-extractor-static-hybrid-v2-fixture-input-v1";
        inherit name;
      }
    );
  mkProgram = format: status: ''
    payload = {
        "format": "${format}",
        "status": "${status}",
        "declared_inputs": {
            name: path.as_posix()
            for name, path in sorted(inputs.items())
        },
    }
    output.write_text(
        json.dumps(payload, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
  '';
  mkSpec =
    {
      derivationSuffix,
      kind,
      artifactName,
      expectedFormat,
      allowedStatuses ? [
        "complete"
        "incomplete"
        "violated"
      ],
      pythonModules,
      inputs ? { },
      status ? "complete",
    }:
    {
      inherit
        derivationSuffix
        kind
        artifactName
        expectedFormat
        allowedStatuses
        pythonModules
        inputs
        ;
      program = mkProgram expectedFormat status;
    };
  phaseSpecs = {
    exactUnitPrep = mkSpec {
      derivationSuffix = "exact-unit-prep";
      kind = "exact-unit-prep";
      artifactName = "exact-unit-prep.json";
      expectedFormat = "stage-a-prepared-machine-ir-v1";
      allowedStatuses = [
        "prepared"
        "incomplete"
        "violated"
      ];
      status = "prepared";
      pythonModules = [ "spaghetti_extractor.reconstruction_ir" ];
      inputs = {
        exact_binary = mkInput "exact-binary";
        state_machine = mkInput "state-machine";
      };
    };
    baseGraph = mkSpec {
      derivationSuffix = "base-graph";
      kind = "base-graph";
      artifactName = "base-graph.json";
      expectedFormat = "spaghetti-extractor-base-control-graph-v2";
      pythonModules = [ "spaghetti_extractor.reconstruction_control" ];
      inputs.behavioral_roots = mkInput "behavioral-roots";
    };
    interproceduralSeed = mkSpec {
      derivationSuffix = "interprocedural-seed";
      kind = "interprocedural-seed-v2";
      artifactName = "interprocedural-seed-v2.json";
      expectedFormat = "stage-a-interprocedural-analysis-v2";
      pythonModules = [ "spaghetti_extractor.interprocedural_phase_v2" ];
      inputs.call_profile = mkInput "call-profile";
    };
    controlInvariantCertificates = mkSpec {
      derivationSuffix = "control-invariants";
      kind = "control-invariants-v2";
      artifactName = "control-invariants-v2.json";
      expectedFormat = "spaghetti-extractor-control-invariant-phase-v2";
      pythonModules = [
        "spaghetti_extractor.control_invariant_phase_v2"
      ];
    };
    memoryRangeInvariants = mkSpec {
      derivationSuffix = "memory-range-invariants";
      kind = "memory-range-invariants-v2";
      artifactName = "memory-range-invariants-v2.json";
      expectedFormat = "spaghetti-extractor-memory-range-invariants-v2";
      pythonModules = [
        "spaghetti_extractor.memory_range_invariants_v2"
      ];
    };
    jointInterproceduralV2 = mkSpec {
      derivationSuffix = "joint-interprocedural";
      kind = "joint-interprocedural-v2";
      artifactName = "joint-interprocedural-v2.json";
      expectedFormat = "spaghetti-extractor-joint-interprocedural-analysis-v2";
      pythonModules = [
        "spaghetti_extractor.joint_fixed_point_v2"
        "spaghetti_extractor.joint_interprocedural_analysis_v2"
      ];
      inputs.joint_policy = mkInput "joint-policy";
    };
    interproceduralV2 = mkSpec {
      derivationSuffix = "interprocedural-v2";
      kind = "interprocedural-v2";
      artifactName = "interprocedural-v2.json";
      expectedFormat = "stage-a-interprocedural-analysis-v2";
      pythonModules = [ "spaghetti_extractor.artifact_projection_v2" ];
      inputs.analysis_profile = mkInput "interprocedural-profile";
    };
    rootedClosure = mkSpec {
      derivationSuffix = "rooted-closure";
      kind = "rooted-closure-v2";
      artifactName = "rooted-closure-v2.json";
      expectedFormat = "stage-a-rooted-control-graph-v2";
      pythonModules = [ "spaghetti_extractor.static_hybrid_pipeline_v2" ];
    };
    externalProfileAuthority = mkSpec {
      derivationSuffix = "external-profile-authority";
      kind = "external-profile-authority-v2";
      artifactName = "external-profile-authority-v2.json";
      expectedFormat = "spaghetti-extractor-external-profile-authority-phase-v2";
      pythonModules = [
        "spaghetti_extractor.external_profile_authority_v2"
      ];
      inputs.external_profiles = mkInput "external-profiles";
    };
    checkedExternalSites = mkSpec {
      derivationSuffix = "external-site-proposals";
      kind = "external-site-proposals-v2";
      artifactName = "external-site-proposals-v2.json";
      expectedFormat = "spaghetti-extractor-external-site-proposals-v2";
      pythonModules = [ "spaghetti_extractor.external_site_proposals_v2" ];
    };
    globalSlotAnalysis = mkSpec {
      derivationSuffix = "global-slot-analysis";
      kind = "global-slot-analysis";
      artifactName = "global-slot-analysis.json";
      expectedFormat = "stage-a-global-slot-analysis-v2";
      pythonModules = [ "spaghetti_extractor.artifact_projection_v2" ];
      inputs.memory_profile = mkInput "memory-profile";
    };
    globalSlotAuthority = mkSpec {
      derivationSuffix = "global-slot-authority";
      kind = "global-slot-authority";
      artifactName = "global-slot-authority.json";
      expectedFormat = "spaghetti-extractor-global-slot-authority-v2";
      pythonModules = [ "spaghetti_extractor.artifact_projection_v2" ];
      inputs.promotion_policy = mkInput "global-slot-promotion-policy";
    };
    callbackEntryContracts = mkSpec {
      derivationSuffix = "callback-entry-contracts";
      kind = "callback-entry-contracts-v2";
      artifactName = "callback-entry-contracts-v2.json";
      expectedFormat = "spaghetti-extractor-callback-entry-state-analysis-v2";
      pythonModules = [ "spaghetti_extractor.entry_state_analysis_v2" ];
    };
    finalizedLaunchProfile = mkSpec {
      derivationSuffix = "finalized-launch-profile";
      kind = "finalized-launch-profile-v2";
      artifactName = "finalized-launch-profile-v2.json";
      expectedFormat = "spaghetti-extractor-finalized-launch-profile-phase-v2";
      pythonModules = [ "spaghetti_extractor.launch_profile_v2" ];
      inputs.launch_profile = mkInput "launch-profile";
    };
    entryRootClosure = mkSpec {
      derivationSuffix = "entry-root-closure";
      kind = "entry-root-closure";
      artifactName = "entry-root-closure.json";
      expectedFormat = "stage-a-entry-state-analysis-v2";
      pythonModules = [
        "spaghetti_extractor.behavioral_roots"
        "spaghetti_extractor.callback_contracts"
      ];
    };
    isaRequirements = mkSpec {
      derivationSuffix = "isa-requirements";
      kind = "isa-requirements";
      artifactName = "isa-requirements.json";
      expectedFormat = "spaghetti-extractor-machine-ir-isa-requirements-v2";
      pythonModules = [
        "spaghetti_extractor.machine_ir_isa_requirements_v2"
      ];
    };
    isaSelectionAuthority = mkSpec {
      derivationSuffix = "isa-selection-authority";
      kind = "isa-selection-authority";
      artifactName = "isa-selection-authority.json";
      expectedFormat = "stage-a-binary-isa-kernel-selection-authority-v1";
      pythonModules = [
        "spaghetti_extractor.analysis.isa_qualification"
        "spaghetti_extractor.isa_kernel_qualification"
      ];
      inputs.qualification = mkInput "isa-qualification";
    };
    exceptionCertificates = mkSpec {
      derivationSuffix = "exception-certificates";
      kind = "exception-certificates";
      artifactName = "exception-certificates.json";
      expectedFormat = "spaghetti-extractor-exception-certificates-phase-v2";
      pythonModules = [ "spaghetti_extractor.exception_phase_v2" ];
      inputs.exception_policy = mkInput "exception-policy";
    };
    staticAuthority = mkSpec {
      derivationSuffix = "static-authority";
      kind = "static-authority-v2";
      artifactName = "static-authority-v2.json";
      expectedFormat = "spaghetti-extractor-static-hybrid-authority-v2";
      pythonModules = [ "spaghetti_extractor.static_hybrid_authority_v2" ];
      inputs.authority_policy = mkInput "authority-policy";
    };
    authorityBundle = mkSpec {
      derivationSuffix = "authority-bundle";
      kind = "authority-bundle";
      artifactName = "authority-bundle.json";
      expectedFormat = "spaghetti-extractor-hybrid-authority-bundle-v2";
      pythonModules = [ "spaghetti_extractor.static_hybrid_authority_v2" ];
    };
    finalAudit = mkSpec {
      derivationSuffix = "final-audit";
      kind = "final-audit";
      artifactName = "final-audit.json";
      expectedFormat = "spaghetti-extractor-static-hybrid-final-audit-v2";
      allowedStatuses = [
        "pass"
        "incomplete"
        "violated"
      ];
      status = "pass";
      pythonModules = [
        "spaghetti_extractor.static_hybrid_authority_v2"
        "spaghetti_extractor.stage_b_candidate_authority_v2"
      ];
      inputs.audit_policy = mkInput "audit-policy";
    };
  };
  mkGraph =
    specs:
    import ../stage-b-static-hybrid-authority-v2.nix {
      inherit pkgs pythonEnv pythonSource;
      namePrefix = "spaghetti-extractor-static-hybrid-v2-fixture";
      phases = specs;
    };
  graph = mkGraph phaseSpecs;
  auditMutation = mkGraph (
    phaseSpecs
    // {
      finalAudit = phaseSpecs.finalAudit // {
        inputs = phaseSpecs.finalAudit.inputs // {
          audit_policy = mkInput "audit-policy-mutated";
        };
      };
    }
  );
  externalProfileMutation = mkGraph (
    phaseSpecs
    // {
      externalProfileAuthority = phaseSpecs.externalProfileAuthority // {
        inputs = phaseSpecs.externalProfileAuthority.inputs // {
          external_profiles = mkInput "external-profiles-mutated";
        };
      };
    }
  );
  jointInterproceduralMutation = mkGraph (
    phaseSpecs
    // {
      jointInterproceduralV2 = phaseSpecs.jointInterproceduralV2 // {
        inputs = phaseSpecs.jointInterproceduralV2.inputs // {
          joint_policy = mkInput "joint-policy-mutated";
        };
      };
    }
  );
  sameDrv = left: right: left.derivation.drvPath == right.derivation.drvPath;
  invalidationContract =
    pkgs.writeText "spaghetti-extractor-static-hybrid-v2-invalidation-contract.json"
      (
        builtins.toJSON {
          format = "spaghetti-extractor-static-hybrid-v2-invalidation-check-v1";
          audit_policy_only = {
            exact_unit_prep_unchanged = sameDrv graph.exactUnitPrep auditMutation.exactUnitPrep;
            base_graph_unchanged = sameDrv graph.baseGraph auditMutation.baseGraph;
            memory_range_invariants_unchanged =
              sameDrv graph.memoryRangeInvariants auditMutation.memoryRangeInvariants;
            interprocedural_unchanged = sameDrv graph.interproceduralV2 auditMutation.interproceduralV2;
            rooted_closure_unchanged = sameDrv graph.rootedClosure auditMutation.rootedClosure;
            external_profile_authority_unchanged = sameDrv graph.externalProfileAuthority auditMutation.externalProfileAuthority;
            checked_external_sites_unchanged = sameDrv graph.checkedExternalSites auditMutation.checkedExternalSites;
            global_slot_analysis_unchanged = sameDrv graph.globalSlotAnalysis auditMutation.globalSlotAnalysis;
            global_slot_authority_unchanged = sameDrv graph.globalSlotAuthority auditMutation.globalSlotAuthority;
            callback_entry_contracts_unchanged = sameDrv graph.callbackEntryContracts auditMutation.callbackEntryContracts;
            finalized_launch_profile_unchanged = sameDrv graph.finalizedLaunchProfile auditMutation.finalizedLaunchProfile;
            entry_root_closure_unchanged = sameDrv graph.entryRootClosure auditMutation.entryRootClosure;
            isa_selection_unchanged = sameDrv graph.isaSelectionAuthority auditMutation.isaSelectionAuthority;
            exception_certificates_unchanged = sameDrv graph.exceptionCertificates auditMutation.exceptionCertificates;
            static_authority_unchanged = sameDrv graph.staticAuthority auditMutation.staticAuthority;
            authority_bundle_unchanged = sameDrv graph.authorityBundle auditMutation.authorityBundle;
            final_audit_changed = !(sameDrv graph.finalAudit auditMutation.finalAudit);
          };
          external_profile_only = {
            exact_unit_prep_unchanged = sameDrv graph.exactUnitPrep externalProfileMutation.exactUnitPrep;
            base_graph_unchanged = sameDrv graph.baseGraph externalProfileMutation.baseGraph;
            memory_range_invariants_unchanged =
              sameDrv graph.memoryRangeInvariants externalProfileMutation.memoryRangeInvariants;
            interprocedural_unchanged = sameDrv graph.interproceduralV2 externalProfileMutation.interproceduralV2;
            rooted_closure_unchanged = sameDrv graph.rootedClosure externalProfileMutation.rootedClosure;
            isa_selection_unchanged = sameDrv graph.isaSelectionAuthority externalProfileMutation.isaSelectionAuthority;
            external_profile_authority_changed =
              !(sameDrv graph.externalProfileAuthority externalProfileMutation.externalProfileAuthority);
            checked_external_sites_changed =
              !(sameDrv graph.checkedExternalSites externalProfileMutation.checkedExternalSites);
            global_slot_analysis_unchanged =
              sameDrv graph.globalSlotAnalysis externalProfileMutation.globalSlotAnalysis;
            global_slot_authority_unchanged =
              sameDrv graph.globalSlotAuthority externalProfileMutation.globalSlotAuthority;
            callback_entry_contracts_unchanged =
              sameDrv graph.callbackEntryContracts externalProfileMutation.callbackEntryContracts;
            finalized_launch_profile_unchanged =
              sameDrv graph.finalizedLaunchProfile externalProfileMutation.finalizedLaunchProfile;
            entry_root_closure_changed =
              !(sameDrv graph.entryRootClosure externalProfileMutation.entryRootClosure);
            exception_certificates_unchanged =
              sameDrv graph.exceptionCertificates externalProfileMutation.exceptionCertificates;
            static_authority_changed =
              !(sameDrv graph.staticAuthority externalProfileMutation.staticAuthority);
            authority_bundle_changed = !(sameDrv graph.authorityBundle externalProfileMutation.authorityBundle);
            final_audit_changed = !(sameDrv graph.finalAudit externalProfileMutation.finalAudit);
          };
          joint_interprocedural_only = {
            exact_unit_prep_unchanged = sameDrv graph.exactUnitPrep jointInterproceduralMutation.exactUnitPrep;
            base_graph_unchanged = sameDrv graph.baseGraph jointInterproceduralMutation.baseGraph;
            interprocedural_seed_unchanged =
              sameDrv graph.interproceduralSeed jointInterproceduralMutation.interproceduralSeed;
            memory_range_invariants_unchanged =
              sameDrv graph.memoryRangeInvariants jointInterproceduralMutation.memoryRangeInvariants;
            joint_interprocedural_changed =
              !(sameDrv graph.jointInterproceduralV2 jointInterproceduralMutation.jointInterproceduralV2);
            global_slot_analysis_changed =
              !(sameDrv graph.globalSlotAnalysis jointInterproceduralMutation.globalSlotAnalysis);
            global_slot_authority_changed =
              !(sameDrv graph.globalSlotAuthority jointInterproceduralMutation.globalSlotAuthority);
            interprocedural_changed =
              !(sameDrv graph.interproceduralV2 jointInterproceduralMutation.interproceduralV2);
            rooted_closure_changed =
              !(sameDrv graph.rootedClosure jointInterproceduralMutation.rootedClosure);
            external_profile_authority_unchanged =
              sameDrv graph.externalProfileAuthority jointInterproceduralMutation.externalProfileAuthority;
            checked_external_sites_changed =
              !(sameDrv graph.checkedExternalSites jointInterproceduralMutation.checkedExternalSites);
            callback_entry_contracts_changed =
              !(sameDrv graph.callbackEntryContracts jointInterproceduralMutation.callbackEntryContracts);
            finalized_launch_profile_changed =
              !(sameDrv graph.finalizedLaunchProfile jointInterproceduralMutation.finalizedLaunchProfile);
            entry_root_closure_changed =
              !(sameDrv graph.entryRootClosure jointInterproceduralMutation.entryRootClosure);
            isa_selection_unchanged =
              sameDrv graph.isaSelectionAuthority jointInterproceduralMutation.isaSelectionAuthority;
            exception_certificates_changed =
              !(sameDrv graph.exceptionCertificates jointInterproceduralMutation.exceptionCertificates);
            static_authority_changed =
              !(sameDrv graph.staticAuthority jointInterproceduralMutation.staticAuthority);
            authority_bundle_changed =
              !(sameDrv graph.authorityBundle jointInterproceduralMutation.authorityBundle);
            final_audit_changed =
              !(sameDrv graph.finalAudit jointInterproceduralMutation.finalAudit);
          };
        }
      );
  phases = [
    graph.exactUnitPrep
    graph.baseGraph
    graph.interproceduralSeed
    graph.controlInvariantCertificates
    graph.memoryRangeInvariants
    graph.jointInterproceduralV2
    graph.interproceduralV2
    graph.rootedClosure
    graph.externalProfileAuthority
    graph.checkedExternalSites
    graph.globalSlotAnalysis
    graph.globalSlotAuthority
    graph.callbackEntryContracts
    graph.finalizedLaunchProfile
    graph.entryRootClosure
    graph.isaRequirements
    graph.isaSelectionAuthority
    graph.exceptionCertificates
    graph.staticAuthority
    graph.authorityBundle
    graph.finalAudit
  ];
  manifestArgs = pkgs.lib.concatMapStringsSep " " (
    phase: pkgs.lib.escapeShellArg phase.manifest
  ) phases;
  check =
    pkgs.runCommand "spaghetti-extractor-static-hybrid-v2-graph-check"
      {
        nativeBuildInputs = [ pkgs.jq ];
        preferLocalBuild = false;
        allowSubstitutes = true;
        __contentAddressed = true;
      }
      ''
          set -euo pipefail
          for manifest in ${manifestArgs}; do
            jq -e '
              .format == "spaghetti-extractor-ca-phase-manifest-v1" and
              .content_addressed and
              (.artifact.sha256 | test("^[0-9a-f]{64}$"))
            ' "$manifest" >/dev/null
          done
          jq -e '
            .format == "spaghetti-extractor-static-hybrid-final-audit-v2" and
            .status == "pass" and
        ([.declared_inputs | keys[]] | sort) == [
              "audit_policy",
              "authority_bundle",
              "static_authority"
            ]
          ' ${graph.finalAudit.artifact} >/dev/null
          jq -e '
            ([.declared_inputs | keys[]] | sort) == [
              "static_authority"
            ]
          ' ${graph.authorityBundle.artifact} >/dev/null
          jq -e '
            ([.declared_inputs | keys[]] | sort) == [
              "authority_policy",
              "base_graph",
              "checked_external_sites",
              "entry_root_closure",
              "exact_unit_prep",
              "exception_certificates",
              "external_profile_authority",
              "interprocedural_v2",
              "isa_requirements",
              "isa_selection_authority",
              "rooted_closure"
            ]
          ' ${graph.staticAuthority.artifact} >/dev/null
          jq -e '
            .format == "spaghetti-extractor-static-hybrid-v2-invalidation-check-v1" and
            ([.audit_policy_only[]] | all) and
            ([.external_profile_only[]] | all) and
            ([.joint_interprocedural_only[]] | all)
          ' ${invalidationContract} >/dev/null
          touch "$out"
      '';
in
graph // { inherit check; }
