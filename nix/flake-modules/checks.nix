# spaghetti-extractor-python-role: developer
{ ... }:

{
  perSystem =
    { config, pkgs, ... }:
    let
      context = import ../toolkit-context.nix { inherit pkgs; };
      testManifest = builtins.fromJSON (builtins.readFile ../generated/test-suite-manifest.json);
      testSource = pkgs.lib.fileset.toSource {
        root = ../..;
        fileset = pkgs.lib.fileset.unions [
          ../../README.md
          ../../REPOSITORY_MAP.md
          ../../docs
          ../../flake.nix
          ../../flake.lock
          ../../isa-catalogs
          ../../native
          ../../nix
          ../../profiles
          ../../pyproject.toml
          ../../src
          ../../targets
          ../../tests
          ../../tools
        ];
      };
      mkTestSuite =
        mode:
        import ../test-suite.nix {
          inherit pkgs mode;
          # Transfer-v2 closure is a canonical kernel service, so every shard
          # gets one uniform environment instead of maintaining a second test
          # classification and silently losing the kernel in component tests.
          pythonEnv = context.transferPythonEnv;
          inherit (context) fixtures;
          repositoryRoot = ../..;
        };
      smokeSuite = mkTestSuite "smoke";
      fullSuite = mkTestSuite "full";
      catalogSuite = mkTestSuite "catalog";
      benchmarkSuite = mkTestSuite "benchmark";
      repositoryMetadataFreshness =
        pkgs.runCommand "spaghetti-extractor-repository-metadata-freshness"
          {
            nativeBuildInputs = [ context.packages.testkitDeveloper ];
            preferLocalBuild = true;
            allowSubstitutes = true;
            __contentAddressed = true;
          }
          ''
            spaghetti-extractor-dev --repository ${testSource} refresh --check
            touch "$out"
          '';
      productionPythonLint =
        pkgs.runCommand "spaghetti-extractor-production-python-lint"
          {
            nativeBuildInputs = [ pkgs.ruff ];
            preferLocalBuild = true;
            allowSubstitutes = true;
            __contentAddressed = true;
          }
          ''
            ruff check --select F401,F811,F821 \
              ${testSource}/src/spaghetti_extractor/candidate \
              ${testSource}/src/spaghetti_extractor/transfer \
              ${testSource}/src/spaghetti_extractor/static_program \
              ${testSource}/src/spaghetti_extractor/extraction \
              ${testSource}/src/spaghetti_extractor/target_bundles \
              ${testSource}/src/spaghetti_extractor/commands \
              ${testSource}/src/spaghetti_extractor/semantic_objects \
              ${testSource}/src/spaghetti_extractor/semantic_link \
              ${testSource}/src/spaghetti_extractor/semantic_providers \
              ${testSource}/src/spaghetti_extractor/qualified_platform \
              ${testSource}/src/spaghetti_extractor/pe32/resources.py \
              ${testSource}/src/spaghetti_extractor/isa/formats.py \
              ${testSource}/src/spaghetti_extractor/isa/qualification_certificate.py \
              ${testSource}/src/spaghetti_extractor/isa/qualification_worker.py \
              ${testSource}/src/spaghetti_extractor/artifacts/formats.py
            touch "$out"
          '';
      formatRegistryCheck =
        pkgs.runCommand "spaghetti-extractor-format-registry-check"
          {
            nativeBuildInputs = [ context.pythonEnv ];
            preferLocalBuild = true;
            allowSubstitutes = true;
            __contentAddressed = true;
          }
          ''
            export PYTHONHASHSEED=0
            export PYTHONDONTWRITEBYTECODE=1
            export PYTHONPATH=${testSource}/src
            python ${testSource}/tools/generate-format-registry.py \
              --root ${testSource} \
              --check ${testSource}/nix/generated/format-registry.json
            touch "$out"
          '';
      architectureBoundaryCheck =
        pkgs.runCommand "spaghetti-extractor-retired-architecture-boundary"
          { nativeBuildInputs = [ pkgs.ripgrep ]; }
          ''
            set -euo pipefail
            test ! -e ${testSource}/src/spaghetti_extractor/reference_contract
            test ! -e ${testSource}/src/spaghetti_extractor/authority_inputs
            test ! -e ${testSource}/src/spaghetti_extractor/authority
            test ! -e ${testSource}/src/spaghetti_extractor/artifacts/phases.py
            test ! -e ${testSource}/src/spaghetti_extractor/artifacts/scheduling.py
            test ! -e ${testSource}/src/spaghetti_extractor/candidate/modes.py
            test ! -e ${testSource}/src/spaghetti_extractor/candidate/machine_ir_scope.py
            test ! -e ${testSource}/src/spaghetti_extractor/candidate/rooted_projection.py
            test ! -e ${testSource}/src/spaghetti_extractor/candidate/runtime_core.py
            test ! -e ${testSource}/src/spaghetti_extractor/candidate/runtime_core_analysis.py
            test ! -e ${testSource}/src/spaghetti_extractor/candidate/runtime_core_components.py
            test ! -e ${testSource}/src/spaghetti_extractor/candidate/runtime_core_x87.py
            test ! -e ${testSource}/src/spaghetti_extractor/candidate/runtime_provider_dispatch.py
            test ! -e ${testSource}/src/spaghetti_extractor/semantic_providers/qualification.py
            test ! -e ${testSource}/src/spaghetti_extractor/semantic_providers/selection.py
            test ! -e ${testSource}/src/spaghetti_extractor/native_realization/receipt.py
            test ! -e ${testSource}/src/spaghetti_extractor/semantic_link/module_compile_v1.py
            test ! -e ${testSource}/src/spaghetti_extractor/semantic_link/replay_import_uses.py
            test ! -e ${testSource}/src/spaghetti_extractor/components/external_sites.py
            test ! -e ${testSource}/src/spaghetti_extractor/external/site_authority.py
            test ! -e ${testSource}/nix/generated-behavioral-c-provider.nix
            test ! -e ${testSource}/nix/intrinsic-semantic-providers.nix
            test ! -e ${testSource}/nix/semantic-provider-selection.nix
            test ! -e ${testSource}/nix/native-realization.nix
            test ! -e ${testSource}/nix/structural-diagnostics.nix
            test ! -e ${testSource}/nix/rooted-behavioral-projection.nix
            test ! -e ${testSource}/nix/machine-ir-isa-qualification.nix
            test ! -e ${testSource}/nix/authority-isa-frontiers.nix
            if rg -n \
                -e 'isa-qualification-migration' \
                -e 'qualifiedPlatformMigrationParity' \
                ${testSource}/nix/target-sdk.nix ${testSource}/targets; then
              echo "target-local ISA qualification campaign reintroduced" >&2
              exit 1
            fi
            if grep -R -n -E \
              'spaghetti_extractor\.reference_contract|candidate_mode|allow_deferred_potential_transfers|spaghetti-extractor-run-functional-suite' \
              ${testSource}/src ${testSource}/nix \
              --exclude='checks.nix' \
              --exclude='python-module-index.json' \
              --exclude='test-suite-manifest.json'; then
              echo "retired binary-pair or diagnostic-candidate API reintroduced" >&2
              exit 1
            fi
            if rg -n \
                -g '!checks.nix' \
                -e 'spaghetti-extractor-structural-executable-v1' \
                -e 'rootedBehavioralProjection' \
                ${testSource}/src ${testSource}/nix; then
              echo "retired parallel structural-execution authority reintroduced" >&2
              exit 1
            fi
            if rg -n \
                -e 'spaghetti_extractor\.(semantic_objects|target_bundles|components|authority|authority_inputs)' \
                ${testSource}/src/spaghetti_extractor/qualified_platform/release.py; then
              echo "qualified platform release acquired target or occurrence inputs" >&2
              exit 1
            fi
            if rg -n \
                -e 'semanticObject' -e 'machineIr' -e 'originalPe' -e 'binary[[:space:]]*=' \
                ${testSource}/nix/qualified-platform.nix; then
              echo "qualified platform derivation acquired a target-specific input" >&2
              exit 1
            fi
            if rg -n \
                -e 'machine_ir' \
                -e 'capstone' \
                -e 'spaghetti_extractor\.candidate' \
                ${testSource}/src/spaghetti_extractor/semantic_link; then
              echo "semantic linker acquired a raw decoder or candidate pipeline" >&2
              exit 1
            fi
            if rg -n 'transferPlan[[:space:]]*=[[:space:]]*authority[.]transferPlan' \
                ${testSource}/nix/target-sdk.nix; then
              echo "canonical transfer compilation returned to the authority workflow" >&2
              exit 1
            fi
            if test -e ${testSource}/nix/authority-workflow.nix || \
               test -e ${testSource}/nix/authority-final-gate.nix || \
               test -e ${testSource}/nix/authority-graph-manifest.nix || \
               test -e ${testSource}/nix/authority-graph-v3.nix || \
               test -e ${testSource}/nix/authority-graph-v3-boundaries.nix || \
               test -e ${testSource}/nix/authority-graph-v3-packs.nix || \
               test -e ${testSource}/nix/authority-input-isa-evidence.nix || \
               test -e ${testSource}/nix/authority-source-plan.nix || \
               test -e ${testSource}/nix/authority-machine-ir-input.nix || \
               test -e ${testSource}/nix/artifact-seed-v3.nix || \
               test -e ${testSource}/nix/artifact-set-v3.nix || \
               test -e ${testSource}/nix/artifact-phase-v3.nix; then
              echo "retired target authority DAG, workflow, or ISA reducer reintroduced" >&2
              exit 1
            fi
            if test -e ${testSource}/src/spaghetti_extractor/authority/graph.py || \
               test -e ${testSource}/src/spaghetti_extractor/authority/registry.py; then
              echo "retired Python authority DAG orchestration reintroduced" >&2
              exit 1
            fi
            for retiredAbiPath in \
              abi/extraction.py abi/matching.py abi/compatibility.py abi/legacy.py \
              authority/external_site_records.py \
              authority/parametric_summary_records.py; do
              if test -e ${testSource}/src/spaghetti_extractor/$retiredAbiPath; then
                echo "retired target-local ABI pipeline reintroduced: $retiredAbiPath" >&2
                exit 1
              fi
            done
            for module in \
              authority_common exact_units identities isa_qualification \
              planning semantic_index source_plan \
              final_authority exceptional_transitions external_site_checker \
              fallback_coverage inductive memory_versions \
              parametric_summary_checker root_closure structural_targets \
              target_certificate_checker transition_summaries; do
              if test -e ${testSource}/src/spaghetti_extractor/authority/$module.py; then
                echo "retired Python authority-DAG producer reintroduced: $module" >&2
                exit 1
              fi
            done
            for module in \
              callback_evidence exception_evidence external_inputs \
              external_site_evidence implementation_capabilities \
              indexed_target_evidence isa_evidence \
              parametric_summary_proposals standard_evidence; do
              if test -e ${testSource}/src/spaghetti_extractor/authority_inputs/$module.py; then
                echo "retired authority-DAG evidence adapter reintroduced: $module" >&2
                exit 1
              fi
            done
            if rg -n \
                -e 'memoryLimitMiB' \
                -e 'memory_mib' \
                ${testSource}/src ${testSource}/nix \
                -g '!generated/**' -g '!checks.nix'; then
              echo "fixed project memory tier reintroduced" >&2
              exit 1
            fi
            if rg -n \
                -e 'plan_phase_scaffold' \
                -e 'mkArtifactPhaseV3' \
                ${testSource}/src ${testSource}/nix -g '!checks.nix'; then
              echo "retired artifact-v3 phase framework reintroduced" >&2
              exit 1
            fi
            if ! rg -q \
                'compile_semantic_may_link_facts_v2' \
                ${testSource}/src/spaghetti_extractor/semantic_link/module_v2.py || \
               rg -n \
                -e 'derive_execution_closure_context_v1' \
                -e 'write_bound_semantic_link_kernel_v1' \
                -e 'build_semantic_link_worklist_facts' \
                ${testSource}/src/spaghetti_extractor/semantic_link/may_link.py \
                ${testSource}/src/spaghetti_extractor/semantic_link/module_v2.py; then
              echo "production semantic link regained optional must analysis" >&2
              exit 1
            fi
            if ! rg -q \
                'compile_semantic_link_worklist_facts' \
                ${testSource}/src/spaghetti_extractor/semantic_link/benchmark.py; then
              echo "optional semantic precision analysis lost its veto-only check" >&2
              exit 1
            fi
            if rg -n \
                -e 'LinkedSemanticModuleV1' \
                -e 'linked_execution_view_v1' \
                -e 'build_linked_semantic_module_v1' \
                ${testSource}/src ${testSource}/nix ${testSource}/targets \
                -g '!formats.py' -g '!checks.nix'; then
              echo "retired linked-semantic-module V1 API was reintroduced" >&2
              exit 1
            fi
            test "$(rg -c 'SemanticObjectV1\.load_link_view\(semantic_object\)' \
              ${testSource}/src/spaghetti_extractor/semantic_link/worklist.py)" = 1
            if rg -n \
                'load_link_view' \
                ${testSource}/src/spaghetti_extractor/semantic_link/replay.py; then
              echo "independent semantic replay adopted the production link view" >&2
              exit 1
            fi
            if ! rg -q \
                'transfer relocations contradict the transfer plan' \
                ${testSource}/native/src/reference_kernel.rs || \
               ! rg -q \
                'runtime dependencies contradict the transfer plan' \
                ${testSource}/native/src/reference_kernel.rs; then
              echo "native semantic link no longer recomputes compact transfer facts" >&2
              exit 1
            fi
            if rg -n \
                'write_bound_semantic_link_closure_v1' \
                ${testSource}/src/spaghetti_extractor/semantic_link/module.py; then
              echo "production semantic link regressed to closure-only native evaluation" >&2
              exit 1
            fi
            if rg -n \
                -e 'provider_sources' -e 'external_sources' \
                ${testSource}/src/spaghetti_extractor/semantic_link/module.py \
                ${testSource}/native/src/reference_kernel.rs; then
              echo "semantic link regained parallel provider/external source channels" >&2
              exit 1
            fi
            if ! rg -q \
                '"runtime_primitive_dependencies"' \
                ${testSource}/src/spaghetti_extractor/semantic_objects/semantic_object.py; then
              echo "runtime requirements are no longer typed semantic effects" >&2
              exit 1
            fi
            if ! rg -q \
                '"environment_contract_sha256"' \
                ${testSource}/src/spaghetti_extractor/semantic_objects/semantic_object.py || \
               ! rg -q \
                '"loader_service_contract_sha256"' \
                ${testSource}/src/spaghetti_extractor/semantic_objects/semantic_object.py || \
               ! rg -q \
                'external declaration contradicts the resolved external catalog' \
                ${testSource}/native/src/reference_kernel.rs; then
              echo "external profiles are no longer checked semantic declarations" >&2
              exit 1
            fi
            if rg -n \
                -e '_environment_contracts' \
                -e 'machine_import_contracts' \
                -e 'loader_service_contracts' \
                ${testSource}/src/spaghetti_extractor/semantic_link/module.py; then
              echo "semantic link regained an external-environment join side channel" >&2
              exit 1
            fi
            if ! rg -q \
                '"object_symbol_bindings"' \
                ${testSource}/src/spaghetti_extractor/semantic_objects/semantic_object.py || \
               ! rg -q \
                '_object_symbol_bindings\(semantic\)' \
                ${testSource}/src/spaghetti_extractor/semantic_link/module.py; then
              echo "object authority is no longer linked through semantic declarations" >&2
              exit 1
            fi
            if ! rg -q \
                '_definitions_with_evidence_dependencies' \
                ${testSource}/src/spaghetti_extractor/semantic_objects/semantic_object.py || \
               ! rg -q \
                '"evidence_dependencies": dependencies' \
                ${testSource}/src/spaghetti_extractor/semantic_link/module.py || \
               ! rg -q \
                'semantic definition evidence dependencies are stale' \
                ${testSource}/src/spaghetti_extractor/semantic_objects/replay.py; then
              echo "per-definition semantic evidence dependencies are no longer exact" >&2
              exit 1
            fi
            if ! rg -q \
                '"generation_policy": rule\.generation_policy' \
                ${testSource}/src/spaghetti_extractor/semantic_link/may_link.py || \
               ! rg -q \
                '"typed_views": typed_views' \
                ${testSource}/src/spaghetti_extractor/semantic_link/may_link.py || \
               ! rg -q \
                '"machine_object_authority_content_sha256"' \
                ${testSource}/src/spaghetti_extractor/semantic_link/may_link.py; then
              echo "object view and generation semantics escaped the semantic link" >&2
              exit 1
            fi
            if ! rg -q \
                '"kind": "exception_transition_activation"' \
                ${testSource}/src/spaghetti_extractor/semantic_objects/exception_projection.py || \
               ! rg -q \
                'initially_reachable_symbols' \
                ${testSource}/native/src/reference_kernel.rs || \
               ! rg -q \
                '_exception_effects_v2' \
                ${testSource}/src/spaghetti_extractor/semantic_link/module_v2.py; then
              echo "exception transitions are no longer total linked definitions" >&2
              exit 1
            fi
            if ! rg -q \
                'callable_domain_activates_every_checked_external_member' \
                ${testSource}/tests/unit/semantic_link/test_module_v2.py; then
              echo "post-propagation reachability can duplicate external policy" >&2
              exit 1
            fi
            if ! rg -q \
                'derive_pe32_machine_object_authority_v2' \
                ${testSource}/nix/semantic-object.nix || \
               ! rg -q \
                'spaghetti_extractor\.semantic_objects\.object_authority' \
                ${testSource}/nix/semantic-object.nix || \
               ! rg -q \
                'moduleObjectAuthority = semanticObject\.derivation;' \
                ${testSource}/nix/target-sdk.nix; then
              echo "semantic object lost ownership of its object-authority member" >&2
              exit 1
            fi
            test ! -e ${testSource}/src/spaghetti_extractor/components/object_authority.py
            test ! -e ${testSource}/nix/pe32-machine-object-authority.nix
            if rg -n \
                -g '!checks.nix' \
                'components\.object_authority' \
                ${testSource}/src ${testSource}/nix ${testSource}/targets; then
              echo "object authority regained component-subsystem ownership" >&2
              exit 1
            fi
            if rg -n \
                -g '!checks.nix' \
                -e 'pe32MachineObjectAuthority' \
                -e 'machineObjectAuthority[[:space:]]*=' \
                ${testSource}/nix ${testSource}/targets; then
              echo "standalone object-authority scheduling was reintroduced" >&2
              exit 1
            fi
            if rg -n \
                -e 'objectAuthority' -e 'inputs\["object_authority"\]' \
                ${testSource}/nix/semantic-object.nix \
                ${testSource}/nix/linked-semantic-module.nix; then
              echo "semantic link or closure regained a separately scheduled object authority" >&2
              exit 1
            fi
            if rg -n \
                -e 'resolvedExternalEnvironment' \
                -e 'inputs\["resolved_external_environment"\]' \
                ${testSource}/nix/linked-semantic-module.nix; then
              echo "semantic link regained a separately scheduled environment" >&2
              exit 1
            fi
            if rg -n \
                -e '^[[:space:]]*original,' \
                -e '^[[:space:]]*behavioralRoots,' \
                -e 'maximumWorklistSteps' \
                -e 'maximumCpuMilliseconds' \
                -e 'maximumPreparedLinkMilliseconds' \
                -e 'linked-semantic-module-performance\.nix' \
                ${testSource}/nix/linked-semantic-module.nix; then
              echo "production semantic linker regained optional analysis inputs" >&2
              exit 1
            fi
            if ! rg -q 'phaseRole = "developer";' \
                ${testSource}/nix/linked-semantic-module-performance.nix; then
              echo "optional semantic-link analysis is not independently scheduled" >&2
              exit 1
            fi
            if rg -n \
                'resolved_external_environment:[[:space:]]*Path' \
                ${testSource}/src/spaghetti_extractor/semantic_link; then
              echo "semantic-link API regained an independent environment path" >&2
              exit 1
            fi
            if ! rg -q \
                'resolved_external_environment=inputs\[' \
                ${testSource}/nix/semantic-object.nix || \
               ! rg -q \
                'resolved_external_environment_path' \
                ${testSource}/src/spaghetti_extractor/semantic_link/worklist.py; then
              echo "resolved environment is not a semantic-object member" >&2
              exit 1
            fi
            if rg -n \
                -e 'spaghetti_extractor\.boundary' \
                -e 'spaghetti_extractor\.calls' \
                -e 'spaghetti_extractor\.components' \
                -e 'spaghetti_extractor\.transfer' \
                ${testSource}/src/spaghetti_extractor/external/resolved.py; then
              echo "resolved-environment codec acquired a semantic producer" >&2
              exit 1
            fi
            if rg -n \
                -e 'moduleExecutionClosure' \
                -e 'parityExecutionClosure' \
                -e 'linked-semantic-module-closure-parity' \
                ${testSource}/nix/target-sdk.nix \
                ${testSource}/nix/linked-semantic-module.nix \
                ${testSource}/targets; then
              echo "independently scheduled target closure parity was reintroduced" >&2
              exit 1
            fi
            if rg -n \
                -g '!checks.nix' \
                -e 'migration_shadow' \
                -e 'semantic-object-v1-shadow' \
                -e 'linked-semantic-module-v1-shadow' \
                ${testSource}/src ${testSource}/nix \
                ${testSource}/targets ${testSource}/tests; then
              echo "retired semantic migration-shadow role was reintroduced" >&2
              exit 1
            fi
            if rg -n \
                -e 'compatibilityExecutionClosure' \
                -e 'compatibilityProjection' \
                -e 'linked-semantic-module-closure-compatibility' \
                ${testSource}/nix/linked-semantic-module.nix \
                ${testSource}/nix/target-sdk.nix \
                ${testSource}/targets; then
              echo "retired linked-module closure compatibility surface was reintroduced" >&2
              exit 1
            fi
            if rg -n \
                -e 'linked\["effects"\]' \
                -e "linked\['effects'\]" \
                -e 'linked\.get\("effects"' \
                -e "linked\.get\('effects'" \
                ${testSource}/src/spaghetti_extractor/semantic_link/module_v2.py; then
              echo "linked-semantic-module V2 regained a V1 effect projection" >&2
              exit 1
            fi
            if ! rg -q 'class SemanticLinkFactsV2' \
                ${testSource}/src/spaghetti_extractor/semantic_link/module_v2_core.py || \
               ! rg -q 'self.assertNotIn\("effects", facts.payload\)' \
                ${testSource}/tests/unit/semantic_link/test_module_v2.py; then
              echo "V2 no longer has a closed effect-free conservative-link carrier" >&2
              exit 1
            fi
            test ! -e ${testSource}/nix/module-execution-closure.nix
            test ! -e ${testSource}/nix/tests/module-execution-closure.nix
            if ! rg -q \
                '\.link_provenance\.algorithm' \
                ${testSource}/targets/gnu-hello/default.nix; then
              echo "Hello checks bypassed canonical may-link provenance" >&2
              exit 1
            fi
            if ! rg -q \
                'resolvedExternalEnvironment = "\$\{fixture\}/environment";' \
                ${testSource}/nix/tests/native-module.nix; then
              echo "native-module fixture semantic object lost its checked environment" >&2
              exit 1
            fi
            if rg -n \
                -e 'maximumPeakRssKib' \
                -e 'maximum-peak-rss-kib' \
                -e 'maximum_peak_rss_kib' \
                -e 'arguments\.maximum_peak_rss_kib' \
                -e 'semantic-link memory budget exceeded' \
                -e 'execution-closure memory budget exceeded' \
                -e 'validated_semantic_object_member_paths_v1' \
                -e 'isolated semantic-object validation' \
                ${testSource}/nix/linked-semantic-module.nix \
                ${testSource}/src/spaghetti_extractor/semantic_objects/semantic_object.py \
                ${testSource}/src/spaghetti_extractor/semantic_link/benchmark.py \
                ${testSource}/targets/gnu-hello/default.nix; then
              echo "speed-first semantic phases regained a fixed RSS veto" >&2
              exit 1
            fi
            if rg -n \
                -e 'nativeIngressPlan' \
                -e 'native_ingress_plan' \
                ${testSource}/nix/component-workflow.nix \
                ${testSource}/nix/linked-libraries.nix \
                ${testSource}/nix/portable-c-work-package-provider-v2.nix \
                ${testSource}/src/spaghetti_extractor/semantic_providers/portable_c_work_package.py; then
              echo "component refinement regained a native-ingress artifact dependency" >&2
              exit 1
            fi
            if test -e \
                ${testSource}/src/spaghetti_extractor/candidate/runtime_abi.py || \
               ! rg -q \
                'from \.\.transfer\.runtime_abi import exact_runtime_header' \
                ${testSource}/src/spaghetti_extractor/semantic_providers/portable_c_work_package.py; then
              echo "portable implementation regained a candidate Behavioral-C ABI dependency" >&2
              exit 1
            fi
            if rg -n \
                -e 'nativeRealizationProjectionPhase' \
                -e 'write_native_realization_v1' \
                -e 'write_native_realization_from_linked_payload_v1' \
                -e 'import ../native-module-build-plan\.nix' \
                -e 'import ../native-module-link-receipt\.nix' \
                -e 'import ../native-linked-skeleton\.nix' \
                -e 'import ../pe32-module-composition\.nix' \
                -e 'import ../pe32-loader-surface-receipt\.nix' \
                -e 'import ../pe32-module-deployment\.nix' \
                -e 'moduleDeployments\."fixture\.dll"' \
                ${testSource}/nix/tests/native-module.nix; then
              echo "native-module fixture regained retired realization orchestration" >&2
              exit 1
            fi
            if ! rg -q \
                'faithfulNativeRealizationV2 = import ../native-realization-v2\.nix' \
                ${testSource}/nix/tests/native-module.nix || \
               rg -n \
                'nativeRealization = import ../native-realization\.nix' \
                ${testSource}/nix/tests/native-module.nix; then
              echo "native fixture is not exclusively owned by V2 realization" >&2
              exit 1
            fi
            if rg -n \
                -e '^  originalModuleInterface,' \
                -e '^  transferPlan,' \
                -e '^  executionClosure,' \
                -e '^  resolvedExternalEnvironment,' \
                -e '^  objectAuthority,' \
                -e '^  qualifiedPlatformSha256' \
                -e 'componentObjectPackages' \
                -e 'structuralExecutionReceipt' \
                -e 'activationPlan' \
                -e 'nativeIngressPlan' \
                -e 'runtimeQualification' \
                -e 'behavioralCPackage' \
                -e 'sharedModuleRuntimePackage' \
                ${testSource}/nix/native-realization-v2.nix; then
              echo "native realization regained duplicate semantic-module inputs" >&2
              exit 1
            fi
            if rg -n \
                -e 'supplemental_object_packages' \
                -e 'structural_execution_receipt: Path' \
                -e 'activation_plan: Path' \
                ${testSource}/src/spaghetti_extractor/native_realization/build.py \
                ${testSource}/src/spaghetti_extractor/candidate/build_workflow.py; then
              echo "native realization regained a superseded ownership input" >&2
              exit 1
            fi
            if rg -n \
                -e 'execution_closure: Path' \
                -e 'behavioral_c_package: Path' \
                -e 'shared_module_runtime_package: Path' \
                ${testSource}/src/spaghetti_extractor/native_realization/build.py; then
              echo "native realization regained a source package or independent closure" >&2
              exit 1
            fi
            if test -e \
                ${testSource}/src/spaghetti_extractor/candidate/build_sources.py; then
              echo "retired candidate source recompilation subsystem reintroduced" >&2
              exit 1
            fi
            if ! rg -q \
                'linked\.semantic_object' \
                ${testSource}/src/spaghetti_extractor/native_realization/build_v2.py || \
               ! rg -q \
                'linked\.semantic_object\.transfer_plan_path' \
                ${testSource}/src/spaghetti_extractor/native_realization/build_v2.py || \
               ! rg -q \
                'publish_semantic_package_v1' \
                ${testSource}/src/spaghetti_extractor/semantic_link/module_v2.py; then
              echo "linked semantic module no longer owns its packaged members" >&2
              exit 1
            fi
            if rg -n \
                -e 'execution_closure[[:space:]]*=' \
                ${testSource}/nix/linked-semantic-module.nix || \
               ! rg -q \
                'write_linked_semantic_module_replay_receipt_v2' \
                ${testSource}/nix/linked-semantic-module.nix; then
              echo "linked replay regained separately keyed semantic inputs" >&2
              exit 1
            fi
            if rg -n \
                -e 'intrinsicProviderProjection' \
                -e 'portableProviderQualification' \
                -e 'write_portable_c_provider_v1' \
                -e 'implementation-selection-v1' \
                -e 'native-realization-v1' \
                ${testSource}/nix/tests/native-module.nix; then
              echo "native-module fixture regained the retired V1 realization branch" >&2
              exit 1
            fi
            test ! -e ${testSource}/nix/portable-c-semantic-provider.nix
            test ! -e ${testSource}/nix/portable-c-semantic-provider-v2.nix
            test ! -e \
              ${testSource}/src/spaghetti_extractor/semantic_providers/portable_c.py
            if ! rg -q \
                'generatedSemanticProvider = generatedBehavioralCProviderV2' \
                ${testSource}/nix/target-sdk.nix || \
               ! rg -q \
                'externalSemanticProvider = externalEnvironmentProviderV2' \
                ${testSource}/nix/target-sdk.nix || \
               ! rg -q \
                'runtimeSemanticProvider = qualifiedRuntimeProviderV2' \
                ${testSource}/nix/target-sdk.nix || \
               ! rg -q \
                'portableSemanticProvidersByComponent = builtins.listToAttrs' \
                ${testSource}/nix/target-sdk.nix || \
               ! rg -q \
                'portableCWorkPackageProviderV2' \
                ${testSource}/nix/target-sdk.nix || \
               ! rg -q \
                'semanticImplementationSelections = lib.genAttrs' \
                ${testSource}/nix/target-sdk.nix; then
              echo "target SDK no longer owns the consolidated V2 semantic-provider path" >&2
              exit 1
            fi
            if rg -n \
                -e 'generatedBehavioralCProvider = callWith' \
                -e 'intrinsicSemanticProviders = callWith' \
                -e 'portableCSemanticProvider = callWith' \
                -e 'implementationSelection = callWith' \
                -e 'nativeRealization = callWith' \
                ${testSource}/nix/target-sdk.nix; then
              echo "retired V1 provider, selection, or realization constructor reentered the target SDK" >&2
              exit 1
            fi
            if rg -n \
                'native-realization-v1' \
                ${testSource}/nix/candidate-test-suite.nix \
                ${testSource}/nix/candidate-test-aggregate.nix; then
              echo "candidate test execution gate still accepts native-realization V1" >&2
              exit 1
            fi
            test ! -e ${testSource}/src/spaghetti_extractor/boundary/formats.py
            test ! -e ${testSource}/src/spaghetti_extractor/target_bundles/runtime_frontiers.py
            test ! -e ${testSource}/nix/runtime-frontier-report.nix
            test ! -e ${testSource}/src/spaghetti_extractor/authority/diagnostics.py
            test ! -e ${testSource}/nix/authority-diagnostics.nix
            test ! -e ${testSource}/src/spaghetti_extractor/target_bundles/candidate_status.py
            if rg -n \
                -g '!checks.nix' \
                -e 'workflow\.authority\.diagnostics' \
                -e 'authorityDiagnostics' \
                -e 'authority-diagnostics\.nix' \
                ${testSource}/src ${testSource}/nix ${testSource}/targets; then
              echo "retired authority-diagnostics projection reintroduced" >&2
              exit 1
            fi
            if rg -n \
                -e 'authority_diagnostics' \
                -e 'AUTHORITY_DIAGNOSTICS' \
                -e 'spaghetti-extractor-project-status-v2' \
                ${testSource}/src/spaghetti_extractor/target_bundles/project_status.py \
                ${testSource}/src/spaghetti_extractor/commands/workflows.py \
                ${testSource}/nix/target-sdk.nix; then
              echo "project status regained its legacy authority-diagnostics projection" >&2
              exit 1
            fi
            if ! rg -q \
                'linked_semantic_module=inputs\["linked_semantic_module"\]' \
                ${testSource}/nix/target-sdk.nix || \
               ! rg -q \
                'workflow\.linkedSemanticModule\.derivation' \
                ${testSource}/nix/target-sdk.nix || \
               ! rg -q \
                'write_operator_work_status_v2' \
                ${testSource}/src/spaghetti_extractor/target_bundles/project_status.py; then
              echo "project status is not a semantic-module operator view" >&2
              exit 1
            fi
            if rg -n \
                -g '!checks.nix' \
                -e 'spaghetti-extractor-candidate-status-v2' \
                -e 'candidate-status\.json' \
                ${testSource}/src ${testSource}/nix ${testSource}/targets; then
              echo "retired candidate-status reducer or format reintroduced" >&2
              exit 1
            fi
            if rg -n \
                -e 'candidateStatusReports' \
                -e 'defaultCandidateStatusReport' \
                -e 'componentConfigurations' \
                ${testSource}/nix/target-sdk.nix || \
               rg -n \
                -e 'schemaAdapters' \
                -e 'componentAdapters' \
                ${testSource}/nix/boundary-workbench.nix || \
               rg -n \
                -e 'intentTemplates' \
                ${testSource}/nix/call-protocol-workflow.nix || \
               rg -n \
                -e 'componentSeedSubjects' \
                ${testSource}/nix/component-workflow.nix; then
              echo "retired operator aliases or boundary adapter derivations reintroduced" >&2
              exit 1
            fi
            if rg -n \
                -e '"name": "component bind"' \
                -e '"name": "component relation"' \
                -e '"name": "candidate check"' \
                ${testSource}/src/spaghetti_extractor/commands/manifest.py; then
              echo "retired public operator command reintroduced" >&2
              exit 1
            fi
            if rg -n \
                -e 'library-release-hypotheses-empty' \
                -e 'emptyReleaseSource' \
                -e '"target_binary_sha256": "0" \* 64' \
                ${testSource}/nix/linked-libraries.nix; then
              echo "synthetic empty library workflow reintroduced" >&2
              exit 1
            fi
            if ! rg -q \
                'format = "spaghetti-extractor-operator-index-v1"' \
                ${testSource}/nix/target-sdk.nix || \
               ! rg -q \
                'format = "spaghetti-extractor-target-sdk-v5"' \
                ${testSource}/nix/target-sdk.nix; then
              echo "target SDK no longer exposes the strict V5 operator product tree" >&2
              exit 1
            fi
            if ! rg -q \
                'project_candidate_selection' \
                ${testSource}/src/spaghetti_extractor/commands/workflows.py || \
               ! rg -q \
                'candidate\.configurations' \
                ${testSource}/src/spaghetti_extractor/commands/workflows.py; then
              echo "candidate status is not a local projection of one indexed selection" >&2
              exit 1
            fi
            if rg -n \
                -e 'materializedIntrinsicSemanticProviderPackages' \
                -e 'nativeImplementationSelections' \
                ${testSource}/nix/target-sdk.nix; then
              echo "target SDK regained duplicate provider materialization or selection" >&2
              exit 1
            fi
            if test -e \
                ${testSource}/src/spaghetti_extractor/components/transfer_proof_projection.py || \
               ! rg -q \
                'load_transfer_v2_refinement_universe' \
                ${testSource}/src/spaghetti_extractor/components/refinement_v5.py || \
               ! rg -q \
                'machine_ir=transfer_universe' \
                ${testSource}/src/spaghetti_extractor/components/refinement_v5.py; then
              echo "component refinement regained its serialized proof projection" >&2
              exit 1
            fi
            if rg -n \
                -g '!checks.nix' \
                -e 'materialize_transfer_proof_projection' \
                -e 'transfer-proof-units\.jsonl' \
                -e 'transfer-proof-manifest\.json' \
                ${testSource}/src ${testSource}/nix ${testSource}/targets; then
              echo "retired component transfer-proof serialization reintroduced" >&2
              exit 1
            fi
            if rg -n \
                -e 'v5ProofExecutionClosure' \
                -e 'componentProofEntryRvas' \
                -e 'componentProofExitUnitIds' \
                -e 'executionClosure' \
                -e 'execution_closure' \
                ${testSource}/nix/component-workflow.nix \
                ${testSource}/src/spaghetti_extractor/components/refinement_v5.py; then
              echo "component refinement regained its duplicate execution closure" >&2
              exit 1
            fi
            if ! rg -q \
                'runtimeSemanticProvider = qualifiedRuntimeProviderV2' \
                ${testSource}/nix/target-sdk.nix || \
               ! rg -q \
                'nativeRealizations = lib\.mapAttrs' \
                ${testSource}/nix/target-sdk.nix || \
               ! rg -q \
                'nativeRealizationV2 \{' \
                ${testSource}/nix/target-sdk.nix || \
               ! rg -q \
                'candidateConfigurations = lib\.genAttrs' \
                ${testSource}/nix/target-sdk.nix || \
               ! rg -q \
                'realization = checkedCandidateBuilds' \
                ${testSource}/nix/target-sdk.nix; then
              echo "target SDK no longer exposes lazy native realization" >&2
              exit 1
            fi
            if ! rg -q \
                'effectiveProviderIds = builtins.sort' \
                ${testSource}/nix/semantic-provider-selection-v2.nix || \
               ! rg -q \
                'qualificationInputs = builtins.listToAttrs' \
                ${testSource}/nix/semantic-provider-selection-v2.nix; then
              echo "implementation selection regained unused-provider invalidation" >&2
              exit 1
            fi
            if rg -n \
                -g '!checks.nix' \
                -e 'spaghetti-extractor-native-ingress-plan-v1' \
                -e 'root_closure_sha256' \
                -e '_checked_callback_root_scope' \
                -e '_callback_authority_call' \
                -e 'call_protocol_packages' \
                -e 'callProtocolPackages' \
                ${testSource}/src ${testSource}/nix; then
              echo "retired native-ingress authority input reintroduced" >&2
              exit 1
            fi
            if rg -n \
                -g 'default.nix' \
                -e 'callbackAuthority' \
                -e 'callbackProtocolId' \
                -e 'machineIr[[:space:]]*=' \
                ${testSource}/targets; then
              echo "target boundary declarations reintroduced workflow-owned evidence inputs" >&2
              exit 1
            fi
            if rg -n \
                -e 'phases\."exceptional-transitions-v5"' \
                -e 'callbackAuthority' \
                ${testSource}/nix/target-sdk.nix; then
              echo "target semantic construction regained an authority-v3 side edge" >&2
              exit 1
            fi
            if rg -n \
                -e 'authorityWorkflow[[:space:]]*[{]' \
                -e 'authority\.graph' \
                -e 'isaQualification[[:space:]]*=' \
                ${testSource}/nix/target-sdk.nix; then
              echo "target release construction regained the authority-v3 workflow" >&2
              exit 1
            fi
            if rg -n \
                -e 'authorityWorkflow' \
                -e 'authority-workflow\.nix' \
                -e 'analysis[[:space:]]*=[[:space:]]*[{][^}]*authority' \
                ${testSource}/nix/target-sdk.nix; then
              echo "target SDK re-exposed the retired authority-v3 constructor" >&2
              exit 1
            fi
            if test -e ${testSource}/src/spaghetti_extractor/candidate/policy_gates.py; then
              echo "retired structural/release policy pipeline was reintroduced" >&2
              exit 1
            fi
            if rg -n \
                -e 'final = workflow\.authority\.finalAuthority' \
                -e 'phases = lib\.mapAttrs .*workflow\.authority\.graph\.phases' \
                ${testSource}/nix/target-sdk.nix; then
              echo "target bundle re-exposed the retired authority-v3 graph" >&2
              exit 1
            fi
            if rg -n \
                -e 'callBoundaryContracts' \
                -e 'call_boundary_contracts' \
                ${testSource}/nix/component-workflow.nix \
                ${testSource}/src/spaghetti_extractor/components/refinement_v5.py; then
              echo "component refinement regained authority-v3 call-boundary input" >&2
              exit 1
            fi
            if rg -n \
                -e 'canonicalExternalSites' \
                -e 'canonical_external_sites' \
                -e 'externalSiteSlices' \
                -e 'component-v5-external-sites\.nix' \
                ${testSource}/nix/component-workflow.nix \
                ${testSource}/src/spaghetti_extractor/components/refinement_v5.py \
                ${testSource}/src/spaghetti_extractor/components/semantic_contract.py \
                ${testSource}/src/spaghetti_extractor/components/machine_overlay_v5.py; then
              echo "component production regained canonical external-site authority" >&2
              exit 1
            fi
            if rg -n \
                -e 'canonicalExternalSites' \
                -e 'canonical_external_sites' \
                -e 'targetCertificates' \
                -e 'target_certificates' \
                ${testSource}/nix/library-island-check.nix \
                ${testSource}/src/spaghetti_extractor/libraries/v4_activation.py; then
              echo "library activation regained authority-v3 crossing inputs" >&2
              exit 1
            fi
            if rg -n \
                -e 'canonicalExternalSites' \
                -e 'canonical_external_sites' \
                -e 'parametricSummaries' \
                -e 'parametric_summaries' \
                -e 'spaghetti_extractor\.abi\.extraction' \
                -e 'extract_checked_abi_evidence_from_artifacts' \
                ${testSource}/nix/linked-libraries.nix \
                ${testSource}/nix/library-recognition.nix; then
              echo "library production regained target-local authority-v3 ABI extraction" >&2
              exit 1
            fi
            if rg -n \
                -e 'exceptionalTransitions' \
                -e 'authority_v3_migration' \
                -e 'transfer\.exception_authority' \
                ${testSource}/nix/semantic-object.nix \
                ${testSource}/nix/tests/native-module.nix \
                ${testSource}/src/spaghetti_extractor/semantic_objects; then
              echo "semantic-object construction regained a parallel exception authority" >&2
              exit 1
            fi
            if ! rg -q \
                'checked_exception_protocols' \
                ${testSource}/src/spaghetti_extractor/external/resolved.py || \
               ! rg -q \
                'checked_exception_protocols' \
                ${testSource}/src/spaghetti_extractor/transfer/exception_semantics.py; then
              echo "checked exception protocols are not environment-bound transfer semantics" >&2
              exit 1
            fi
            if ! rg -q \
                'runtimeProfiles = machineImportProfiles' \
                ${testSource}/nix/target-sdk.nix || \
               ! rg -q \
                'derive_transfer_callback_evidence_v1' \
                ${testSource}/src/spaghetti_extractor/commands/call_protocols.py; then
              echo "callback transport is not derived directly from transfer-v2 and runtime profiles" >&2
              exit 1
            fi
            if rg -n \
                -e 'spec\.machineIr' \
                -e 'args\.machine_ir' \
                -e '--machine-ir' \
                ${testSource}/nix/call-protocol-workflow.nix \
                ${testSource}/src/spaghetti_extractor/commands/call_protocols.py; then
              echo "boundary checking bypassed executable-transfer-plan-v2" >&2
              exit 1
            fi
            if rg -n \
                -e 'canonicalExternalSites' \
                -e 'canonical_external_sites' \
                -e 'callbackAuthority' \
                -e 'callback_authority' \
                -e 'rootClosure' \
                -e 'root_closure' \
                -e 'targetCertificates' \
                -e 'target_certificates' \
                -e 'parametricSummaries' \
                -e 'parametric_summaries' \
                -e 'machineIr' \
                ${testSource}/nix/external-environment-provider-v2.nix \
                ${testSource}/nix/native-realization-v2.nix; then
              echo "production runtime reconstructed semantics outside the canonical transfer universe" >&2
              exit 1
            fi
            if rg -n \
                -e '^[[:space:]]*transferPlan,' \
                -e '^[[:space:]]*executionClosure,' \
                -e '^[[:space:]]*resolvedExternalEnvironment,' \
                -e '^[[:space:]]*objectAuthority,' \
                -e '^[[:space:]]*nativeIngressPlan,' \
                ${testSource}/nix/external-environment-provider-v2.nix \
                ${testSource}/nix/native-realization-v2.nix; then
              echo "intrinsic provider or realization regained separately keyed semantic inputs" >&2
              exit 1
            fi
            if ! rg -q \
                'write_external_environment_provider_v2' \
                ${testSource}/nix/external-environment-provider-v2.nix || \
               rg -n \
                'write_shared_module_runtime_package_from_linked_module' \
                ${testSource}/src/spaghetti_extractor/semantic_providers/intrinsic.py || \
               ! rg -q \
                'materialize_native_realization_support_v1' \
                ${testSource}/src/spaghetti_extractor/native_realization/runtime_provider_v2.py || \
               ! rg -q \
                'write_shared_module_runtime_package_from_linked_module' \
                ${testSource}/src/spaghetti_extractor/native_realization/materialize.py; then
              echo "runtime materialization escaped the one native realization boundary" >&2
              exit 1
            fi
            if ! rg -q \
                '_write_native_ingress_plan_from_loaded_module' \
                ${testSource}/src/spaghetti_extractor/candidate/runtime.py || \
               rg -n \
                -e 'native_ingress_plan[[:space:]]*=' \
                ${testSource}/nix/external-environment-provider-v2.nix; then
              echo "native realization no longer derives ingress inside the loaded linked-package boundary" >&2
              exit 1
            fi
            if rg -n \
                'module-execution-closure\.json' \
               ${testSource}/src/spaghetti_extractor/candidate/runtime.py \
                ${testSource}/src/spaghetti_extractor/candidate/native_ingress_plan.py || \
               ! rg -q \
                'linked_execution_view_v2' \
                ${testSource}/src/spaghetti_extractor/candidate/runtime.py \
                ${testSource}/src/spaghetti_extractor/candidate/native_ingress_plan.py; then
              echo "native runtime or ingress regained the packaged execution-closure sidecar" >&2
              exit 1
            fi
            if rg -n \
                -e 'linked-semantic-module-performance' \
                -e 'linked-semantic-module-independent-replay' \
                -e 'module-execution-closure[[:space:]]*=[[:space:]]*workflow\\.linkedSemanticModule\\.compatibilityExecutionClosureDerivation' \
                ${testSource}/nix/target-sdk.nix; then
              echo "compatibility or veto-only semantic-link work reentered the default target path" >&2
              exit 1
            fi
            if rg -n \
                -e 'nativeIngressPlan' \
                -e 'moduleNativeIngressPlan' \
                ${testSource}/nix/target-sdk.nix; then
              echo "SDK regained a standalone native-ingress derivation" >&2
              exit 1
            fi
            if rg -n \
                'LinkedSemanticModuleV1' \
                ${testSource}/src/spaghetti_extractor/candidate/project_load_plan.py || \
               ! rg -q \
                'LinkedSemanticModuleV2' \
                ${testSource}/src/spaghetti_extractor/candidate/project_load_plan.py || \
               ! rg -q \
                'linkedSemanticModule\.linkedSemanticModule' \
                ${testSource}/nix/target-sdk.nix || \
               rg -n \
                '/linked-semantic-module\.json' \
                ${testSource}/nix/pe32-project-load-plan.nix; then
              echo "project load planning escaped linked-semantic-module V2 packages" >&2
              exit 1
            fi
            if rg -n \
                'candidate-native-ingress-plan' \
                ${testSource}/src/spaghetti_extractor/commands/manifest.py \
                ${testSource}/src/spaghetti_extractor/commands/runtime.py || \
               rg -n \
                '"write_native_ingress_plan"' \
                ${testSource}/src/spaghetti_extractor/candidate/native_ingress.py; then
              echo "standalone native-ingress public API was reintroduced" >&2
              exit 1
            fi
            if rg -n \
                -e 'write_shared_module_runtime_package' \
                -e 'NATIVE_INGRESS_PLAN_FORMAT' \
                ${testSource}/src/spaghetti_extractor/testkit/native_module_fixture.py || \
               rg -n \
                -e '\$\{fixture\}/ingress' \
                -e '\$\{fixture\}/runtime' \
                ${testSource}/nix/tests/native-module.nix; then
              echo "native fixture regained a second ingress or runtime pipeline" >&2
              exit 1
            fi
            if rg -n \
                'intrinsicProviderPackage' \
                ${testSource}/nix/tests/native-module.nix || \
               rg -n \
                -e 'behavioralCPackage' \
               -e 'componentObjectPackages' \
                ${testSource}/nix/native-realization-v2.nix || \
               ! rg -q \
                'linkedSemanticModule = fixtureLinkedSemanticModule.linkedSemanticModule' \
                ${testSource}/nix/tests/native-module.nix; then
              echo "native fixture runtime no longer uses the linked semantic module" >&2
              exit 1
            fi
            if test -e \
                ${testSource}/nix/tests/native-realization-v2-fixture.nix || \
               ! rg -q \
                'faithfulNativeRealizationV2 = import ../native-realization-v2\.nix' \
                ${testSource}/nix/tests/native-module.nix; then
              echo "native fixture regained a fabricated V2 realization receipt" >&2
              exit 1
            fi
            if rg -n \
                -e 'ComponentContractV4' \
                -e 'ComponentMachineBindingV5' \
                -e 'ComponentUnitInventoryV1' \
                -e 'component-contract-v4' \
                -e 'component-machine-binding-v5' \
                -e 'component-unit-inventory-v1' \
                ${testSource}/src/spaghetti_extractor/components/work_package_v6.py \
                ${testSource}/nix/component-v6-work-package.nix; then
              echo "component work-package V6 regained the legacy reducer chain" >&2
              exit 1
            fi
            if ! rg -q \
                'linkedSemanticModule' \
                ${testSource}/nix/component-v6-work-package.nix || \
               ! rg -q \
                'semanticSlice = components.v6SemanticSlices' \
                ${testSource}/nix/target-sdk.nix; then
              echo "public component work packages are not direct V2 projections" >&2
              exit 1
            fi
            if rg -n \
                -e 'componentImplementations' \
                -e 'component-implementation-v4' \
                -e 'contractPackage' \
                -e 'machine_binding' \
                -e 'work_package[[:space:]]*=' \
                ${testSource}/nix/portable-c-work-package-provider-v2.nix || \
               rg -n \
                -e 'COMPONENT_IMPLEMENTATION_V4_FORMAT' \
                -e 'component-implementation-v4' \
                -e 'component-machine-binding-v5[.]json' \
                ${testSource}/src/spaghetti_extractor/semantic_providers/portable_c_work_package.py || \
               ! rg -q \
                'portableCWorkPackageProviderV2' \
                ${testSource}/nix/target-sdk.nix; then
              echo "direct V6 portable qualification regained a legacy artifact input" >&2
              exit 1
            fi
            if ! rg -q '__contentAddressed = true' \
                ${testSource}/nix/ca-python-json-phase.nix || \
               ! rg -q 'component-semantic-slice-v2[.]nix' \
                ${testSource}/nix/component-workflow.nix || \
               ! rg -Fq 'pkgs.lib.optionalAttrs (linkedSemanticModule != null)' \
                ${testSource}/nix/portable-c-work-package-provider-v2.nix; then
              echo "portable qualification lost its semantic-slice cache boundary" >&2
              exit 1
            fi
            if rg -n \
                -e '(^|[[:space:]])import (z3|cbmc)' \
                -e 'from .*refinement import' \
                -e 'machine_ir' \
                ${testSource}/src/spaghetti_extractor/semantic_providers/encapsulated_owned.py || \
               test "$(rg -c 'check_bisimulation_refinement\(' \
                 ${testSource}/src/spaghetti_extractor/semantic_providers/portable_c_work_package.py)" != 1 || \
               test "$(rg -c 'build_contextual_refinement_v2\(' \
                 ${testSource}/src/spaghetti_extractor/semantic_providers/portable_c_work_package.py)" != 1 || \
               test "$(rg -c 'check_encapsulated_owned_admission\(' \
                 ${testSource}/src/spaghetti_extractor/semantic_providers/portable_c_work_package.py)" != 1 || \
               ! rg -q \
                 'proof_classification=proof_classification' \
                 ${testSource}/src/spaghetti_extractor/semantic_providers/portable_c_work_package.py || \
               ! rg -q \
                 'proofClassification = componentRowsById' \
                 ${testSource}/nix/component-workflow.nix; then
              echo "encapsulated-owned qualification forked the semantic proof path" >&2
              exit 1
            fi
            if rg -n \
                -e 'bootstrapSharedModuleRuntime' \
                -e 'qualifiedBehavioral' \
                ${testSource}/nix/tests/native-module.nix || \
               rg -n \
                -e 'behavioralCByConfiguration' \
                ${testSource}/nix/target-sdk.nix; then
              echo "runtime qualification regained a duplicate Behavioral-C package" >&2
              exit 1
            fi
            if test -e ${testSource}/nix/module-runtime-core-package.nix; then
              echo "retired public module-runtime-core package phase reintroduced" >&2
              exit 1
            fi
            for retiredRuntimeModule in \
              runtime_core.py runtime_core_analysis.py runtime_core_components.py \
              runtime_core_model.py runtime_core_render.py runtime_core_layout.py \
              runtime_core_package.py runtime_core_x87.py; do
              if test -e ${testSource}/src/spaghetti_extractor/candidate/$retiredRuntimeModule; then
                echo "retired runtime-core module reintroduced: $retiredRuntimeModule" >&2
                exit 1
              fi
            done
            if rg -n \
                -e 'module-runtime-core-package\.nix' \
                -e 'runtimeCore' \
                -e 'runtime_core_package' \
                ${testSource}/nix/external-environment-provider-v2.nix \
                ${testSource}/nix/native-realization-v2.nix; then
              echo "production graph reintroduced a separate runtime-core package" >&2
              exit 1
            fi
            if rg -n \
                -e 'structuralExecutionGate' \
                -e 'structural_executable' \
                ${testSource}/nix/external-environment-provider-v2.nix \
                ${testSource}/nix/native-realization-v2.nix; then
              echo "shared runtime regained a duplicate structural receipt input" >&2
              exit 1
            fi
            for retiredComponentPhase in \
              component-v5-contract.nix \
              component-v5-semantic-refinement.nix \
              component-v5-relation.nix \
              component-v5-external-sites.nix \
              component-v5-work-package.nix \
              component-v4-implementation.nix \
              component-v4-dependency-graph.nix \
              component-v5-unit-inventory.nix; do
              if test -e ${testSource}/nix/$retiredComponentPhase; then
                echo "retired public component phase reintroduced: $retiredComponentPhase" >&2
                exit 1
              fi
            done
            for retiredComponentModule in \
              contracts_v5.py \
              generated_behavioral_v4.py \
              implementation_facets_v4.py \
              implementation_v4.py \
              lifecycle_v4.py \
              work_package_v5.py; do
              if test -e \
                ${testSource}/src/spaghetti_extractor/components/$retiredComponentModule; then
                echo "retired component codec reintroduced: $retiredComponentModule" >&2
                exit 1
              fi
            done
            if rg -n \
                -e 'ComponentContractV4' \
                -e 'ComponentMachineBindingV5' \
                -e 'ComponentImplementationV4' \
                -e 'ComponentDependencyGraphV4' \
                -e 'ComponentWorkPackageV5' \
                ${testSource}/src ${testSource}/tools ${testSource}/targets; then
              echo "retired V4/V5 component model reentered production" >&2
              exit 1
            fi
            if rg -n \
                -e 'v5Bindings' \
                -e 'v5UnitInventories' \
                -e 'v4Implementations' \
                -e 'v4DependencyGraphs' \
                -e 'v5WorkPackages' \
                -e 'portableCSemanticProviderV2' \
                -e 'legacyProvider' \
                ${testSource}/nix/component-workflow.nix \
                ${testSource}/nix/target-sdk.nix \
                ${testSource}/targets/gnu-hello/default.nix \
                ${testSource}/targets/jq/default.nix \
                ${testSource}/targets/dxball/default.nix; then
              echo "retired V4/V5 component orchestration reentered a production root" >&2
              exit 1
            fi
            if ! rg -q 'directV6ProviderIds' \
                ${testSource}/nix/component-workflow.nix || \
               ! rg -q 'v6SemanticSlices' \
                ${testSource}/nix/component-workflow.nix || \
               ! rg -q 'v6WorkPackages' \
                ${testSource}/nix/component-workflow.nix || \
               ! rg -q 'portableCWorkPackageProviderV2' \
                ${testSource}/nix/target-sdk.nix || \
               ! rg -q 'authored-component-v6-honest-blockers' \
                ${testSource}/targets/jq/default.nix || \
               ! rg -q 'directdraw-init-v6-honest-blockers' \
                ${testSource}/targets/dxball/default.nix; then
              echo "direct V6 component qualification or honest blocker gates are missing" >&2
              exit 1
            fi
            if rg -n \
                -e 'machineIr' \
                -e 'inputs\["machine_ir"\]' \
                -e 'inputs\["machine_ir_manifest"\]' \
                ${testSource}/nix/native-realization-v2.nix; then
              echo "native linking bypassed the canonical transfer universe" >&2
              exit 1
            fi
            if rg -n \
                -e 'machine_ir: Path' \
                -e 'machine_ir_manifest: Path' \
                ${testSource}/src/spaghetti_extractor/candidate/build_validation.py \
                ${testSource}/src/spaghetti_extractor/candidate/build_workflow.py; then
              echo "native build API reintroduced raw machine-IR inputs" >&2
              exit 1
            fi
            if rg -n \
                -e 'machineIr' \
                -e 'inputs\["machine_ir"\]' \
                -e 'inputs\["original_pe"\]' \
                ${testSource}/nix/library-provider-binding.nix \
                ${testSource}/nix/library-island-check.nix; then
              echo "library provider binding bypassed the canonical transfer universe" >&2
              exit 1
            fi
            if rg -n \
                -e 'transferPlan' \
                -e 'resolvedExternalEnvironment' \
                -e 'behavioralCPackage' \
                -e 'transfer_plan[[:space:]]*=' \
                -e 'resolved_external_environment[[:space:]]*=' \
                ${testSource}/nix/library-island-check.nix || \
               ! rg -q 'linkedSemanticModule' \
                ${testSource}/nix/library-island-check.nix || \
               ! rg -q 'LinkedSemanticModuleV2\.load' \
                ${testSource}/src/spaghetti_extractor/libraries/v4_activation.py; then
              echo "library island authority bypassed linked semantic package members" >&2
              exit 1
            fi
            if rg -n \
                -e 'behavioralCPackage' \
                -e 'resolvedExternalEnvironment' \
                -e 'transferPlan' \
                ${testSource}/nix/linked-libraries.nix; then
              echo "linked-library orchestration regained dead generated-C or environment inputs" >&2
              exit 1
            fi
            test ! -e ${testSource}/nix/library-component-v5-generation.nix
            test ! -e ${testSource}/nix/library-component-v4-implementation.nix
            if rg -n \
                -e 'generatedComponents' \
                -e 'generatedLibraryComponents' \
                -e 'component-implementation-v4' \
                ${testSource}/nix/linked-libraries.nix \
                ${testSource}/nix/library-provider-binding.nix \
                ${testSource}/src/spaghetti_extractor/libraries/component_v5.py || \
               ! rg -q 'providerBindings' \
                ${testSource}/nix/linked-libraries.nix || \
               ! rg -q 'providerSemanticSlices' \
                ${testSource}/nix/linked-libraries.nix || \
               ! rg -q 'providerInputs' \
                ${testSource}/nix/linked-libraries.nix || \
               ! rg -q 'portableSemanticProvidersByLibrary' \
                ${testSource}/nix/target-sdk.nix || \
               ! rg -q 'portableCWorkPackageProviderV2' \
                ${testSource}/nix/target-sdk.nix; then
              echo "library adoption bypassed the direct semantic-provider path" >&2
              exit 1
            fi
            if rg -n \
                -e 'transferPlan' \
                -e 'transfer_plan[[:space:]]*=' \
                ${testSource}/nix/library-provider-binding.nix || \
               ! rg -q 'linkedSemanticModule' \
                ${testSource}/nix/library-provider-binding.nix || \
               ! rg -q 'linked\.require_member\("transfer_plan"\)' \
                ${testSource}/src/spaghetti_extractor/libraries/component_v5.py; then
              echo "library provider binding bypassed linked semantic transfer member" >&2
              exit 1
            fi
            if rg -n \
                -e 'machine_ir: Path' \
                ${testSource}/src/spaghetti_extractor/libraries/v4_activation.py \
                ${testSource}/src/spaghetti_extractor/libraries/component_v5.py; then
              echo "library authority API reintroduced raw machine-IR inputs" >&2
              exit 1
            fi
            if rg -n \
                -g '!matching_support.py' \
                -g '!signature_graph.py' \
                -g '!discovery_model.py' \
                -e 'load_machine_package' \
                -e 'machine-ir\.jsonl' \
                ${testSource}/src/spaghetti_extractor/candidate \
                ${testSource}/src/spaghetti_extractor/components \
                ${testSource}/src/spaghetti_extractor/libraries \
                ${testSource}/src/spaghetti_extractor/boundary \
                ${testSource}/src/spaghetti_extractor/external; then
              echo "production consumer reintroduced a second machine-IR semantic path" >&2
              exit 1
            fi
            if ! rg -q \
                -e 'content_addressed_admitted_domains_v2' \
                ${testSource}/src/spaghetti_extractor/candidate/module_runtime_plan.py \
                ${testSource}/src/spaghetti_extractor/candidate/runtime_model.py || \
               ! rg -q 'class NativeGuestDispatchDomain' \
                ${testSource}/src/spaghetti_extractor/candidate/runtime_model.py || \
               ! rg -q 'def guest_dispatch_from_linked_module_v2' \
                ${testSource}/src/spaghetti_extractor/candidate/runtime_canonical_common.py || \
               ! rg -q 'callable external member is disconnected' \
                ${testSource}/src/spaghetti_extractor/candidate/runtime_canonical_common.py || \
               ! rg -q 'linked_module=linked_v2.payload' \
                ${testSource}/src/spaghetti_extractor/candidate/runtime_canonical_build.py || \
               ! rg -q 'def external_loader_targets' \
                ${testSource}/src/spaghetti_extractor/candidate/runtime_model.py || \
               ! rg -q 'domain_sha256=domain_sha256' \
                ${testSource}/src/spaghetti_extractor/candidate/runtime_canonical_common.py; then
              echo "canonical runtime lost content-addressed admitted dispatch domains" >&2
              exit 1
            fi
            if rg -n \
                -g '!checks.nix' \
                -e 'exact_site_scoped_closure_targets_v1' \
                ${testSource}/src ${testSource}/nix ${testSource}/targets; then
              echo "retired repeated per-site guest target policy was reintroduced" >&2
              exit 1
            fi
            if rg -n \
                -g '!checks.nix' \
                -g '!formats.py' \
                -g '!format-registry.json' \
                -e 'spaghetti-extractor-module-runtime-core-plan-v[1]' \
                -e 'spaghetti-extractor-module-runtime-plan-v[2]' \
                -e 'spaghetti-extractor-module-runtime-plan-v[3]' \
                -e 'module-runtime-core' \
                -e 'EngineRep' \
                ${testSource}/src ${testSource}/nix; then
              echo "retired runtime plan format or terminology re-entered production" >&2
              exit 1
            fi
            if rg -n \
                -g '!checks.nix' \
                -e 'code_capability_passthroughs' \
                -e 'NativeCallbackPassthrough' \
                -e 'pass_through_environment_pointer' \
                ${testSource}/src ${testSource}/nix; then
              echo "retired callback passthrough subsystem reintroduced" >&2
              exit 1
            fi
            if rg -n \
                -e 'authority\.root_closure' \
                -e 'authority\.callbacks' \
                -e 'authority\.target_certificate' \
                -e 'reconstruction\.static_indirect_replay' \
                ${testSource}/src/spaghetti_extractor/candidate \
                ${testSource}/src/spaghetti_extractor/transfer; then
              echo "canonical execution path re-imported fragmented static authority" >&2
              exit 1
            fi
            if rg -n \
                -e 'launch-root-closure-v3' \
                -e 'callback-authority-v4' \
                -e 'indirect-target-certificates-v3' \
                ${testSource}/nix/executable-transfer-plan.nix \
                ${testSource}/nix/behavioral-c-package.nix \
                ${testSource}/nix/external-environment-provider-v2.nix \
                ${testSource}/nix/native-realization-v2.nix; then
              echo "deployment path re-read a fragmented static authority receipt" >&2
              exit 1
            fi
            for retiredNativePhase in \
              native-ingress-plan.nix \
              shared-module-runtime-package.nix \
              behavioral-c-exact-runtime.nix \
              behavioral-c-runtime-qualification.nix \
              behavioral-c-completion-gate.nix \
              candidate-deployment.nix candidate-policy-gate.nix \
              candidate-policy-receipt.nix candidate-release-gate.nix \
              candidate-release-receipt.nix native-linked-skeleton.nix \
              native-module-build-plan.nix native-module-link-receipt.nix \
              pe32-loader-surface-receipt.nix pe32-module-composition.nix \
              pe32-module-deployment.nix; do
              if test -e ${testSource}/nix/$retiredNativePhase; then
                echo "retired native/deployment phase reintroduced: $retiredNativePhase" >&2
                exit 1
              fi
            done
            if rg -n \
                -e 'high = spx_native_transfer_count' \
                ${testSource}/src/spaghetti_extractor/candidate/runtime_render_core.py; then
              echo "computed guest dispatch regained module-global transfer authority" >&2
              exit 1
            fi
            if rg -n \
                -g '!checks.nix' \
                -e 'owned_by_interprocedural_v2_phase' \
                -e 'awaiting_interprocedural_v2' \
                -e 'spaghetti-extractor-interprocedural-analysis-v2' \
                ${testSource}/src ${testSource}/nix; then
              echo "retired extraction-owned interprocedural authority reintroduced" >&2
              exit 1
            fi
            if rg -n \
                -g '!checks.nix' \
                -g '!formats.py' \
                -g '!format-registry.json' \
                -e 'exception-evidence-v3' \
                -e 'exceptional-transitions-v3' \
                -e 'exceptional-transitions-v4' \
                ${testSource}/src ${testSource}/nix ${testSource}/native \
                ${testSource}/targets; then
              echo "retired exception authority artifact kind reintroduced" >&2
              exit 1
            fi
            if rg -n \
                -g '!checks.nix' \
                -e 'Stage [AB]' -e 'STAGE_[AB]' -e 'stage_[ab]_' \
                -e 'stage-[ab]-' -e 'spaghetti-extractor-spaghetti-extractor' \
                ${testSource}/src ${testSource}/nix ${testSource}/docs \
                ${testSource}/tools ${testSource}/README.md \
                ${testSource}/REPOSITORY_MAP.md; then
              echo "retired phase terminology or duplicated wire prefix reintroduced" >&2
              exit 1
            fi
            touch "$out"
          '';
      nativeKernelDependencyBoundary =
        pkgs.runCommand "spaghetti-extractor-native-kernel-dependency-boundary"
          {
            preferLocalBuild = true;
            allowSubstitutes = true;
            __contentAddressed = true;
          }
          ''
            set -euo pipefail
            ${context.pythonEnv}/bin/python3 -c \
              'import spaghetti_extractor_native; import importlib.util; assert importlib.util.find_spec("spaghetti_extractor_transfer_native") is None'
            ${context.transferPythonEnv}/bin/python3 -c \
              'import spaghetti_extractor_native as core, spaghetti_extractor_transfer_native as transfer; assert core.NATIVE_API_VERSION == 1; assert transfer.REFERENCE_KERNEL_API_VERSION == 1'
            touch "$out"
          '';
      roundtrip = import ../roundtrip-corpus.nix {
        inherit pkgs;
        inherit (context) pythonEnv;
        source = context.sources.staticSource;
        count = 6;
      };
      candidateTestSuiteCheck = import ../tests/candidate-test-suite.nix {
        inherit pkgs;
      };
      pe32ProjectCheck = import ../tests/pe32-project.nix {
        inherit pkgs;
        inherit (context) pythonEnv;
      };
      nativeIngressRuntimeCheck = import ../tests/native-ingress-runtime.nix {
        inherit pkgs;
      };
      nativeModuleCheck = import ../tests/native-module.nix { inherit pkgs; };
      behavioralCDifferentialCheck = import ../tests/behavioral-c-differential.nix {
        inherit pkgs;
      };
      componentV5Check = import ../tests/component-v5.nix {
        inherit pkgs;
        inherit (context) pythonEnv;
      };
      semanticObjectCheck = import ../tests/semantic-object.nix {
        inherit pkgs;
        pythonEnv = context.transferPythonEnv;
      };
      linkedSemanticModuleCheck = import ../tests/linked-semantic-module.nix {
        inherit pkgs;
        pythonEnv = context.transferPythonEnv;
        pythonSource = testSource;
      };
      semanticProvidersCheck = import ../tests/semantic-providers.nix {
        inherit pkgs;
        pythonEnv = context.transferPythonEnv;
        pythonSource = testSource;
      };
      nativeRealizationCheck = import ../tests/native-realization.nix {
        inherit pkgs;
        pythonEnv = context.transferPythonEnv;
        pythonSource = testSource;
      };
      qualifiedPlatformCheck = import ../tests/qualified-platform.nix {
        inherit pkgs;
        inherit (context) pythonEnv;
        kernelCache = context.kernels.isaConformanceKernel;
        semanticKernel = "${context.kernels.isaSemanticKernel}/semantic-kernel.json";
        isaFormInventory = builtins.path {
          path = ../../src/spaghetti_extractor/qualified_platform/pe32_i686_isa_forms.json;
          name = "spaghetti-qualified-platform-pe32-i686-isa-forms.json";
        };
        bochsRunner = context.tools.bochsRunner;
        sharedISACampaign = context.platforms.qualifiedPlatform.isaCampaign;
      };
      profileRegistryCheck = import ../profile-registry-check.nix {
        inherit pkgs;
        inherit (context) pythonEnv;
        pythonSource = context.sources.staticSource;
        profiles = context.sources.profileSource;
      };
      fullGate = pkgs.linkFarm "spaghetti-extractor-test-full" [
        {
          name = "repository-metadata-freshness";
          path = repositoryMetadataFreshness;
        }
        {
          name = "production-python-lint";
          path = productionPythonLint;
        }
        {
          name = "retired-architecture-boundary";
          path = architectureBoundaryCheck;
        }
        {
          name = "native-kernel-dependency-boundary";
          path = nativeKernelDependencyBoundary;
        }
        {
          name = "python-suite";
          path = fullSuite.aggregate;
        }
        {
          name = "candidate-test-suite";
          path = candidateTestSuiteCheck;
        }
        {
          name = "pe32-project";
          path = pe32ProjectCheck;
        }
        {
          name = "native-ingress-runtime";
          path = nativeIngressRuntimeCheck;
        }
        {
          name = "native-module";
          path = nativeModuleCheck;
        }
        {
          name = "behavioral-c-differential";
          path = behavioralCDifferentialCheck;
        }
        {
          name = "component-v5";
          path = componentV5Check;
        }
        {
          name = "semantic-object";
          path = semanticObjectCheck;
        }
        {
          name = "linked-semantic-module";
          path = linkedSemanticModuleCheck;
        }
        {
          name = "semantic-providers";
          path = semanticProvidersCheck;
        }
        {
          name = "native-realization";
          path = nativeRealizationCheck;
        }
        {
          name = "qualified-platform";
          path = qualifiedPlatformCheck;
        }
        {
          name = "profile-registry";
          path = profileRegistryCheck;
        }
        {
          name = "roundtrip-qualification";
          path = roundtrip.qualification;
        }
      ];
      smokeGate = pkgs.linkFarm "spaghetti-extractor-test-smoke" [
        {
          name = "repository-metadata-freshness";
          path = repositoryMetadataFreshness;
        }
        {
          name = "production-python-lint";
          path = productionPythonLint;
        }
        {
          name = "retired-architecture-boundary";
          path = architectureBoundaryCheck;
        }
        {
          name = "python-suite";
          path = smokeSuite.aggregate;
        }
      ];
      benchmarkGate = pkgs.linkFarm "spaghetti-extractor-test-benchmark" [
        {
          name = "repository-metadata-freshness";
          path = repositoryMetadataFreshness;
        }
        {
          name = "python-suite";
          path = benchmarkSuite.aggregate;
        }
      ];
      transferEvaluatorPythonClosure = import ../python-module-closure.nix {
        phaseRole = "developer";
        inherit pkgs;
        modules = [ "spaghetti_extractor.transfer.evaluator" ];
        name = "spaghetti-extractor-transfer-evaluator-python-closure-smoke";
      };
      isaClassifierPythonClosure = import ../python-module-closure.nix {
        phaseRole = "developer";
        inherit pkgs;
        modules = [ "spaghetti_extractor.isa.semantic_forms" ];
        name = "spaghetti-extractor-isa-classifier-python-closure-smoke";
      };
      qualifiedPlatformPythonClosure = import ../python-module-closure.nix {
        phaseRole = "developer";
        inherit pkgs;
        modules = [
          "spaghetti_extractor.qualified_platform.release"
          "spaghetti_extractor.qualified_platform.replay"
        ];
        name = "spaghetti-extractor-qualified-platform-python-closure-smoke";
      };
      linkedSemanticModulePythonClosure = import ../python-module-closure.nix {
        phaseRole = "candidate";
        inherit pkgs;
        modules = [ "spaghetti_extractor.semantic_link.module_v2" ];
        name = "spaghetti-extractor-linked-semantic-module-python-closure-smoke";
      };
      qualifiedRuntimePythonClosure = import ../python-module-closure.nix {
        phaseRole = "candidate";
        inherit pkgs;
        modules = [
          "spaghetti_extractor.native_realization.runtime_provider_v2"
        ];
        name = "spaghetti-extractor-qualified-runtime-python-closure-smoke";
      };
      linkedSemanticModuleRuntimeLeaks = builtins.filter
        (module:
          module == "spaghetti_extractor.candidate.runtime"
          || pkgs.lib.hasPrefix
            ("spaghetti_extractor.candidate." + "runtime_") module
          || module ==
            "spaghetti_extractor.native_realization.runtime_provider_v2")
        linkedSemanticModulePythonClosure.selectedModules;
      qualifiedPlatformCandidateAllowlist = [
        "spaghetti_extractor.candidate"
        "spaghetti_extractor.candidate.behavioral_c_model"
        "spaghetti_extractor.candidate.behavioral_c_render"
        "spaghetti_extractor.candidate.formats"
        "spaghetti_extractor.candidate.runtime_helpers"
      ];
      qualifiedPlatformRuntimeLeaks = builtins.filter
        (module:
          pkgs.lib.hasPrefix "spaghetti_extractor.candidate" module
          && !(builtins.elem module qualifiedPlatformCandidateAllowlist))
        qualifiedPlatformPythonClosure.selectedModules;
      qualifiedPlatformProvenanceLeaks = builtins.filter
        (module:
          pkgs.lib.hasPrefix "spaghetti_extractor.transfer.provenance" module
          && module != "spaghetti_extractor.transfer.provenance_coverage")
        qualifiedPlatformPythonClosure.selectedModules;
      checkedPythonModuleIndex = builtins.fromJSON (
        builtins.readFile ../generated/python-module-index.json
      );
      stalePythonModuleIndex = checkedPythonModuleIndex // {
        modules = checkedPythonModuleIndex.modules // {
          "spaghetti_extractor.transfer.evaluator" =
            checkedPythonModuleIndex.modules."spaghetti_extractor.transfer.evaluator"
            // { source_sha256 = builtins.concatStringsSep "" (builtins.genList (_: "0") 64); };
        };
      };
      staleSourceClosure = builtins.tryEval (
        (import ../python-module-closure.nix {
          phaseRole = "developer";
          inherit pkgs;
          modules = [ "spaghetti_extractor.transfer.evaluator" ];
          moduleIndex = stalePythonModuleIndex;
        }).outPath
      );
      crossRoleClosure = builtins.tryEval (
        (import ../python-module-closure.nix {
          phaseRole = "operator";
          inherit pkgs;
          modules = [ "spaghetti_extractor.transfer.evaluator" ];
          name = "spaghetti-extractor-invalid-cross-role-closure";
        }).outPath
      );
      machineImportControlProfileFixture = import ../tests/machine-import-control-profile.nix {
        inherit pkgs;
        inherit (context) pythonEnv;
      };
      targetSdkCheck = import ../tests/target-sdk.nix { inherit pkgs; };
      buildInfrastructureCheck = import ../tests/build-infrastructure.nix {
        inherit pkgs;
        inherit (context) pythonEnv;
      };
      externalEnvironmentCheck = import ../tests/external-environment.nix {
        inherit pkgs;
        inherit (context) pythonEnv;
      };
      boundaryWorkbenchCheck = import ../tests/boundary-workbench.nix {
        inherit pkgs;
        inherit (context) pythonEnv;
      };
    in
    {
      legacyPackages = {
        test-smoke = smokeGate;
        test-full = fullGate;
        test-benchmark = benchmarkGate;
        test-shards = catalogSuite.shards;
        roundtrip-corpus = roundtrip.corpus;
        roundtrip-qualification = roundtrip.qualification;
      };

      checks = {
        import-smoke =
          pkgs.runCommand "spaghetti-extractor-import-smoke"
            {
              nativeBuildInputs = [ config.packages.spaghetti-extractor ];
            }
            ''
              spaghetti-extractor --help >/dev/null
              spaghetti-extractor project status --help >/dev/null
              spaghetti-extractor component list --help >/dev/null
              spaghetti-extractor component status --help >/dev/null
              spaghetti-extractor candidate list --help >/dev/null
              spaghetti-extractor candidate status --help >/dev/null
              spaghetti-extractor candidate test --help >/dev/null
              spaghetti-extractor expert static-inventory-binary --help >/dev/null
              touch "$out"
            '';
        test-suite = fullGate;
        repository-metadata = repositoryMetadataFreshness;
        format-registry = formatRegistryCheck;
        build-infrastructure = buildInfrastructureCheck;
        external-environment = externalEnvironmentCheck;
        boundary-workbench = boundaryWorkbenchCheck;
        production-python-lint = productionPythonLint;
        retired-architecture-boundary = architectureBoundaryCheck;
        native-kernel-dependency-boundary = nativeKernelDependencyBoundary;
        python-module-closure =
          assert !crossRoleClosure.success;
          assert !staleSourceClosure.success;
          assert !(transferEvaluatorPythonClosure ? drvPath);
          assert linkedSemanticModuleRuntimeLeaks == [ ];
          assert builtins.elem "spaghetti_extractor.candidate.runtime"
            qualifiedRuntimePythonClosure.selectedModules;
          assert qualifiedPlatformRuntimeLeaks == [ ];
          assert qualifiedPlatformProvenanceLeaks == [ ];
          pkgs.runCommand "spaghetti-extractor-python-module-closure-check"
            { nativeBuildInputs = [ context.pythonEnv ]; }
            ''
              export PYTHONPATH=${transferEvaluatorPythonClosure.pythonPath}
              python -c 'import spaghetti_extractor.transfer.evaluator'
              test -s ${transferEvaluatorPythonClosure.manifest}
              export PYTHONPATH=${isaClassifierPythonClosure.pythonPath}
              python -c 'from spaghetti_extractor.isa.semantic_forms import lean_semantic_form_classifier_sha256; assert len(lean_semantic_form_classifier_sha256()) == 64'
              test -s ${isaClassifierPythonClosure.manifest}
              export PYTHONPATH=${qualifiedPlatformPythonClosure.pythonPath}
              python -c 'from spaghetti_extractor.qualified_platform.native_catalog import native_primitive_catalog_payload_v1; assert len(native_primitive_catalog_payload_v1()) == 8'
              test -s ${qualifiedPlatformPythonClosure.manifest}
              export PYTHONPATH=${linkedSemanticModulePythonClosure.pythonPath}
              python -c 'from spaghetti_extractor.semantic_link.module_v2 import LinkedSemanticModuleV2; assert LinkedSemanticModuleV2 is not None'
              test -s ${linkedSemanticModulePythonClosure.manifest}
              export PYTHONPATH=${qualifiedRuntimePythonClosure.pythonPath}
              python -c 'from spaghetti_extractor.candidate.runtime import plan_shared_module_runtime; assert callable(plan_shared_module_runtime)'
              test -s ${qualifiedRuntimePythonClosure.manifest}
              touch "$out"
            '';
        machine-import-control-profile = machineImportControlProfileFixture;
        isa-kernel = context.kernels.isaConformanceKernel;
        inductive-certificate-kernel = context.kernels.inductiveCertificateKernel;
        relation-kernel = context.kernels.relationKernel;
        roundtrip = roundtrip.qualification;
        target-sdk = targetSdkCheck;
        pe32-project = pe32ProjectCheck;
        native-ingress-runtime = nativeIngressRuntimeCheck;
        native-module = nativeModuleCheck;
        behavioral-c-differential = behavioralCDifferentialCheck;
        component-v5 = componentV5Check;
        semantic-object = semanticObjectCheck;
        linked-semantic-module = linkedSemanticModuleCheck;
        semantic-providers = semanticProvidersCheck;
        native-realization = nativeRealizationCheck;
        qualified-platform = qualifiedPlatformCheck;
        candidate-test-suite = candidateTestSuiteCheck;
        profile-registry = profileRegistryCheck;
      };
    };
}
