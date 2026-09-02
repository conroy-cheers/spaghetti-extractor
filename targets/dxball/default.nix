{ pkgs, sdk }:

let
  target = builtins.fromJSON (builtins.readFile ./target.json);
  archive = pkgs.fetchurl {
    name = "dxball-1.09-distributable.zip";
    url = "https://archive.org/download/dxball-19/DXBall19.zip";
    hash = "sha256-ARvV4Ge3rNrGxdbEeqIAmpcb07FSayOGbUsz/ZfdUQ0=";
  };
  wine = pkgs.wineWow64Packages.stableFull;
  installer =
    pkgs.runCommand "dxball-1.09-installer"
      {
        nativeBuildInputs = [ pkgs.unzip ];
        __contentAddressed = true;
      }
      ''
        mkdir -p "$out"
        unzip -j ${archive} DXBall19.EXE -d "$out"
        test "$(sha256sum "$out/DXBall19.EXE" | cut -d ' ' -f 1)" = \
          2472a555ba5cbda459f6c7b9df9e2aebc37eaca2c730e86d31b46a088d81ae77
      '';
  original =
    pkgs.runCommand "dxball-1.09-original"
      {
        nativeBuildInputs = [
          wine
          pkgs.xvfb-run
        ];
        __contentAddressed = true;
      }
      ''
        export HOME="$TMPDIR/home"
        export WINEPREFIX="$TMPDIR/wine"
        export WINEDEBUG=-all
        export WINEDLLOVERRIDES="mscoree,mshtml="
        mkdir -p "$HOME"
        xvfb-run -a -s '-screen 0 640x480x24' sh -eu -c '
          wineboot -u >/dev/null 2>&1
          wine ${installer}/DXBall19.EXE /s >/dev/null 2>&1
          wineserver -w
        '
        installed="$WINEPREFIX/drive_c/Program Files (x86)/DX-Ball"
        mkdir -p "$out/runtime"
        cp "$installed/DXBall.exe" "$out/DXBall.exe"
        cp -a "$installed/." "$out/runtime/"
        # The installer log contains its wall-clock start time and is not consumed
        # by the game.  Exclude it from this content-addressed runtime fixture.
        rm -f "$out/runtime/INSTALL.LOG"
      '';
  interfaceProfile = sdk.analysis.externalInterfaceProfile {
    spec = "${sdk.profiles}/pe32-mingw-directx-interface-extraction-v1.json";
  };
  runtimeMachineImportProfiles = [
    "${sdk.profiles}/pe32-msvcrt-machine-runtime-v1.json"
    "${sdk.profiles}/pe32-kernel32-runtime-v1.json"
    "${sdk.profiles}/pe32-native-callthrough-runtime-v1.json"
    "${sdk.profiles}/pe32-win32-windowing-runtime-v1.json"
    "${sdk.profiles}/pe32-winmm-runtime-v1.json"
  ];
  boundaries = sdk.lifting.boundarySchema {
    name = "spaghetti-extractor-dxball-1.09";
    spec = ./intent/boundaries.json;
    sources = [ ./source/window-class-boundary.c ];
  };
  environment = sdk.environment.pe32 {
    id = "dxball-win32";
    targetAbi = "pe32-i686-msvc";
    profilePacks = runtimeMachineImportProfiles;
    interfacePacks = [
      "${interfaceProfile}/interface-profile.json"
    ];
    launchProfile = "${sdk.profiles}/pe32-win32-gui-launch-assumptions-v1.json";
    boundaryIntents."service:window-class-boundary" = ./intent/boundaries.json;
    support.processTermination = {
      dll = "kernel32.dll";
      symbol = "ExitProcess";
    };
  };
  workflow = sdk.workflow.pe32 {
    targetId = target.id;
    original = "${original}/DXBall.exe";
    binaryIdentity = "DXBall.exe";
    externalEnvironment = environment;
    lifting = {
      boundaries = [
        {
          subject = "service:window-class-boundary";
          package = boundaries;
        }
      ];
      components = {
        intent = ./intent/components.json;
        operatorRoot = ./intent;
        sourceRoot = ./source;
      };
      libraries = {
        packs = [ ];
        adoptionRoot = ./intent/libraries;
      };
    };
    backend = {
      kind = "behavioral-c";
      sourcePresentation = null;
    };
    analysisLimits = {
      maxUnits = 512;
      maxCandidatesPerSeed = 12;
    };
  };
  components = workflow.components;
  componentMigrationStatus = pkgs.writeTextFile {
    name = "dxball-component-v6-migration-status";
    destination = "/component-v6-migration-status.json";
    text = builtins.readFile ./intent/bindings-v5/index.json;
  };
  v6ComponentChecks = builtins.listToAttrs (
    pkgs.lib.concatMap (componentId: [
      {
        name = "${componentId}-interface-v5";
        value = components.v5Interfaces.${componentId}.derivation;
      }
      {
        name = "${componentId}-semantic-slice-v2";
        value = components.v6SemanticSlices.${componentId}.derivation;
      }
      {
        name = "${componentId}-work-package-v6";
        value = components.v6WorkPackages.${componentId}.derivation;
      }
    ]) (builtins.attrNames components.v6SemanticSlices)
  );
  directdrawBlockerGate =
    pkgs.runCommand "dxball-directdraw-init-v6-honest-blockers"
      {
        nativeBuildInputs = [ pkgs.jq ];
        __contentAddressed = true;
      }
      ''
            jq -e '
              (.blockers[] | select(
                .code == "machine_effect_service_callback_outcome_projection_unreviewed"
              )) as $machine_frontier |
              (.blockers[] | select(
                .code == "contextual_tail_live_in_object_outcome_projection_unreviewed"
              )) as $contextual_tail |
              (.operations[0].machine_projection.service_bindings[] | select(
                .service_id == "attach_clipper"
              )) as $attach_clipper |
              (.operations[0].machine_projection.service_bindings[] | select(
                .service_id == "create_backbuffer"
              )) as $backbuffer |
              (.operations[0].machine_projection.service_bindings[] | select(
                .service_id == "create_clipper"
              )) as $create_clipper |
              (.operations[0].machine_projection.service_bindings[] | select(
                .service_id == "create_primary_surface"
              )) as $primary |
              (.operations[0].machine_projection.service_bindings[] | select(
                .service_id == "directdraw_create"
              )) as $directdraw_create |
              (.operations[0].machine_projection.service_bindings[] | select(
                .service_id == "destroy_window"
              )) as $destroy_window |
              (.operations[0].machine_projection.service_bindings[] | select(
                .service_id == "get_caps"
              )) as $get_caps |
              (.operations[0].machine_projection.service_bindings[] | select(
                .service_id == "hide_window"
              )) as $hide_window |
              (.operations[0].machine_projection.service_bindings[] | select(
                .service_id == "message_box"
              )) as $message_box |
              (.operations[0].machine_projection.service_bindings[] | select(
                .service_id == "set_clipper_window"
              )) as $set_clipper_window |
              (.operations[0].machine_projection.service_bindings[] | select(
                .service_id == "set_cooperative_level"
              )) as $cooperative |
              .format == "spaghetti-extractor-component-work-package-v6" and
              .authority == false and
              .status == "ready" and
              ([.blockers[].code] | sort) == [
                "contextual_tail_live_in_object_outcome_projection_unreviewed",
                "machine_effect_service_callback_outcome_projection_unreviewed"
              ] and
              ([.blockers[] | .component_id] | unique) == ["directdraw-init"] and
              ([.blockers[] | .source] | unique) == ["component_binding_intent"] and
              $machine_frontier.review_frontier.authority == false and
              $contextual_tail.entry_rva == 52572 and
        $contextual_tail.excluded_prefix_rva_start == 52320 and
        $contextual_tail.excluded_prefix_rva_end == 52572 and
        $contextual_tail.required_review == [
          "checked_faithful_continuation_portal_state",
          "six_zero_failure_one_success_outcome_projections",
          "two_internal_call_effects"
        ] and
        .operations[0].machine_projection.operation.parameters == [
          {
            id:"window",
            projection:{
              kind:"resource",
              resource_kind:"window_handle",
              source:{kind:"static_slot",rva:215412,width:32,at:"entry"}
            }
          }
        ] and
        $machine_frontier.review_frontier.source_format ==
                "spaghetti-extractor-executable-transfer-plan-v2" and
              $machine_frontier.review_frontier.policy == {
                adopts_service_bindings:false,
                authorizes_effects:false,
                authorizes_outcomes:false,
                lexical_candidates_are_presentation_only:true,
                structural_candidates_are_presentation_only:true,
                tests_authorize:false
              } and
              ($machine_frontier.review_frontier.operations | length) == 1 and
              $machine_frontier.review_frontier.operations[0].operation_id == "initialize" and
              $machine_frontier.review_frontier.operations[0].counts == {
                call_events:27,
                control_outcomes:65,
                declared_services:11,
                indirect_calls:14,
                internal_calls:2,
                lexical_candidates:11,
                mapped_services:11,
                memory_writes:83,
                named_external_calls:11,
                structural_interface_candidates:130,
                structurally_classified_indirect_calls:7,
                transfers:65,
                unmapped_services:0
              } and
              $machine_frontier.review_frontier.operations[0].unmapped_service_ids == [] and
              ([.operations[0].machine_projection.service_bindings[].service_id]) == [
                "attach_clipper",
                "create_backbuffer",
                "create_clipper",
                "create_primary_surface",
                "destroy_window",
                "directdraw_create",
                "get_caps",
                "hide_window",
                "message_box",
                "set_clipper_window",
                "set_cooperative_level"
              ] and
              ([$backbuffer, $primary] | all(
                .mediation == "direct" and
                .provider.kind == "interface_method" and
                (.provider.events | length) == 1 and
                .provider.events[0].event_index == 0 and
                .provider.method_contract_sha256 ==
                  "4152365210559748cb015b9ceb3de1869517cb49d1c87015fefca5ce28e38ba3" and
                .provider.argument_transducers[0] == {
                  kind:"logical_argument", parameter_index:0
                } and
                .provider.argument_transducers[1].kind == "local_cell" and
                .provider.argument_transducers[1].cell_id == "surface_descriptor" and
                .provider.argument_transducers[1].local_cell_relation_sha256 ==
                  "62be9a58f0d0c09e24124fd198d97d89145ec23b3937ce54da8e7a229b83dfc5" and
                (.provider.argument_transducers[1].initial_words | length) == 27 and
                .provider.argument_transducers[2] == {
                  kind:"out_interface",
                  parameter_index:1,
                  out_interface_relation_sha256:
                    "4febf70c23ce02fac743a70767a0deec8491140db6da607afe3193b96f1c8ec1"
                } and
                .provider.argument_transducers[3] == {kind:"constant",value:0}
              )) and
              ($backbuffer.provider.events[0].unit_id ==
                "semantic-transfer:original-cutpoint-0000cedf-0000cee9") and
              ($backbuffer.provider.argument_transducers[1].initial_words | {
                nonnull:([.[] | select(. != null)]),
                discriminant:.[1], width:.[2], height:.[3], caps:.[26]
              }) == {
                nonnull:[108,7,480,640,16448],
                discriminant:7, width:480, height:640, caps:16448
              } and
              ($primary.provider.events[0].unit_id ==
                "semantic-transfer:original-cutpoint-0000ce6b-0000ce70") and
              ($primary.provider.argument_transducers[1].initial_words | {
                nonnull:([.[] | select(. != null)]),
                discriminant:.[1], caps:.[26]
              }) == {nonnull:[108,1,512],discriminant:1,caps:512} and
              $directdraw_create.provider == {
                kind:"external_call",
                events:[{
                  unit_id:"semantic-transfer:original-cutpoint-0000cd5c-0000cd6a",
                  event_index:0
                }],
                identity:{dll:"ddraw.dll",symbol:"DirectDrawCreate",ordinal:null},
                argument_transducers:[
                  {kind:"constant",value:0},
                  {
                    kind:"out_interface",
                    parameter_index:0,
                    out_interface_relation_sha256:
                      "e220809dd3ac1eafffe3d242346078485f32a55910d5537f699d54616b0a567d"
                  },
                  {kind:"constant",value:0}
                ]
              } and
              $destroy_window.mediation == "direct" and
              $destroy_window.provider == {
                kind:"external_call",
                events:[
                  {unit_id:"semantic-transfer:original-cutpoint-0000cd92-0000cd9e",event_index:0},
                  {unit_id:"semantic-transfer:original-cutpoint-0000cde4-0000cdf1",event_index:0},
                  {unit_id:"semantic-transfer:original-cutpoint-0000ce97-0000cea4",event_index:0},
                  {unit_id:"semantic-transfer:original-cutpoint-0000cf10-0000cf1d",event_index:0},
                  {unit_id:"semantic-transfer:original-cutpoint-0000cfcf-0000cfdc",event_index:0}
                ],
                identity:{dll:"user32.dll",symbol:"DestroyWindow",ordinal:null}
              } and
              $get_caps.provider.kind == "interface_method" and
              ($get_caps.provider.events | length) == 1 and
              $get_caps.provider.events[0].unit_id ==
                "semantic-transfer:original-cutpoint-0000ce2c-0000ce31" and
              $get_caps.provider.events[0].event_index == 0 and
              $get_caps.provider.method_contract_sha256 ==
                "96a3e77ac70ac8b67b894c27d72632aed6dbe29d427470a5b3c5f3cb209847b4" and
              $get_caps.provider.argument_transducers[0] == {
                kind:"logical_argument",parameter_index:0
              } and
              $get_caps.provider.argument_transducers[1].kind == "local_cell" and
              $get_caps.provider.argument_transducers[1].cell_id == "driver_caps" and
              $get_caps.provider.argument_transducers[1].local_cell_relation_sha256 ==
                "ff1bd7282bf7187d68601727627579830206329d296f9241c1ea0503ea930abf" and
              ($get_caps.provider.argument_transducers[1].initial_words | length) == 95 and
              $get_caps.provider.argument_transducers[1].initial_words[0] == 380 and
              $get_caps.provider.argument_transducers[1].initial_words[1] == {
                kind:"entry_projection",
                projection:{kind:"stack",offset:160,width:32,at:"entry"}
              } and
              ([$get_caps.provider.argument_transducers[1].initial_words[] |
                select(. != null)] | length) == 2 and
              $get_caps.provider.argument_transducers[2] == {
                kind:"constant",value:0
              } and
              $get_caps.provider.result_projection == {
                kind:"local_cell_word",cell_id:"driver_caps",word_index:1
              } and
              $hide_window.provider == {
                kind:"external_call",
                events:[
                  {unit_id:"semantic-transfer:original-cutpoint-0000cd6e-0000cd79",event_index:0},
                  {unit_id:"semantic-transfer:original-cutpoint-0000cdc1-0000cdcb",event_index:0},
                  {unit_id:"semantic-transfer:original-cutpoint-0000ce74-0000ce7e",event_index:0},
                  {unit_id:"semantic-transfer:original-cutpoint-0000ceed-0000cef7",event_index:0},
                  {unit_id:"semantic-transfer:original-cutpoint-0000cf4c-0000cf57",event_index:0},
                  {unit_id:"semantic-transfer:original-cutpoint-0000cf7d-0000cf88",event_index:0},
                  {unit_id:"semantic-transfer:original-cutpoint-0000cfac-0000cfb7",event_index:0}
                ],
                identity:{dll:"user32.dll",symbol:"ShowWindow",ordinal:null},
                target_projection:{kind:"register",register:"esi",width:32,at:"entry"},
                argument_transducers:[
                  {kind:"logical_argument",parameter_index:0},
                  {kind:"constant",value:0}
                ]
              } and
              $message_box.provider == {
                kind:"external_call",
                events:[
                  {unit_id:"semantic-transfer:original-cutpoint-0000cd8b-0000cd92",event_index:0},
                  {unit_id:"semantic-transfer:original-cutpoint-0000cddd-0000cde4",event_index:0},
                  {unit_id:"semantic-transfer:original-cutpoint-0000ce90-0000ce97",event_index:0},
                  {unit_id:"semantic-transfer:original-cutpoint-0000cf09-0000cf10",event_index:0},
                  {unit_id:"semantic-transfer:original-cutpoint-0000cfc3-0000cfcf",event_index:0}
                ],
                identity:{dll:"user32.dll",symbol:"MessageBoxA",ordinal:null},
                argument_transducers:[
                  {kind:"logical_argument",parameter_index:0},
                  {
                    kind:"finite_word_map",parameter_index:1,
                    cases:[
                      {logical_value:1,physical_value:4291244},
                      {logical_value:2,physical_value:4291568},
                      {logical_value:3,physical_value:4291520},
                      {logical_value:4,physical_value:4291468},
                      {logical_value:5,physical_value:4291420},
                      {logical_value:6,physical_value:4291364},
                      {logical_value:7,physical_value:4291304}
                    ]
                  },
                  {kind:"constant",value:4285340},
                  {kind:"constant",value:0}
                ]
              } and
              .operations[0].machine_projection.operation.state == [
                {
                  id:"capability_mode",
                  entry:{kind:"static_slot",rva:96764,width:32,at:"entry"},
                  exit:{kind:"static_slot",rva:96764,width:32,at:"exit"}
                },
                {
                  id:"clipper_mode",
                  entry:{kind:"static_slot",rva:215452,width:32,at:"entry"},
                  exit:{kind:"static_slot",rva:215452,width:32,at:"exit"}
                },
                {
                  id:"directdraw_initialized",
                  entry:{kind:"static_slot",rva:96772,width:32,at:"entry"},
                  exit:{kind:"static_slot",rva:96772,width:32,at:"exit"}
                },
                {
                  id:"video_memory_capability",
                  entry:{kind:"static_slot",rva:96776,width:32,at:"entry"},
                  exit:{kind:"static_slot",rva:96776,width:32,at:"exit"}
                }
              ] and
        .operations[0].machine_projection.operation.preserved_state_ids == [
          "clipper_mode"
        ] and
        .operations[0].machine_projection.operation.results == [{
          id:"status",
          projection:{kind:"register",register:"eax",width:32,at:"exit"}
        }] and
        .operations[0].outcome_protocol_ids == ["normal"] and
        $create_clipper.provider == {
          kind:"interface_method",
          events:[{
            unit_id:"semantic-transfer:original-cutpoint-0000cf42-0000cf48",
            event_index:0
          }],
          method_contract_sha256:
            "7e57d0c03f00822f7233fc192514b72fff8658221b9a6a829862c65ef298e79f",
          argument_transducers:[
            {kind:"logical_argument",parameter_index:0},
            {kind:"constant",value:0},
            {
              kind:"out_interface",
              parameter_index:1,
              out_interface_relation_sha256:
                "a66a1a57efe267d4fea7e372f4b67a63534a34abe571bd15d3328b853f26a0c1"
            },
            {kind:"constant",value:0}
          ]
        } and
        $set_clipper_window.provider == {
          kind:"interface_method",
          events:[{
            unit_id:"semantic-transfer:original-cutpoint-0000cf73-0000cf79",
            event_index:0
          }],
          method_contract_sha256:
            "065ab57257b7b0cc87709f680082615dc27eba4fbb5e0502f0a92e1700094aaa",
          argument_transducers:[
            {kind:"logical_argument",parameter_index:0},
            {kind:"constant",value:0},
            {kind:"logical_argument",parameter_index:1}
          ]
        } and
        $attach_clipper.provider == {
          kind:"interface_method",
          events:[{
            unit_id:"semantic-transfer:original-cutpoint-0000cfa3-0000cfa8",
            event_index:0
          }],
          method_contract_sha256:
            "8d07447c4dea3fcd45b50c1eaca59f07f0c021ccba8f1f4500ef5c6c4bc11282",
          argument_transducers:[
            {kind:"logical_argument",parameter_index:0},
            {kind:"logical_argument",parameter_index:1}
          ]
        } and
        $cooperative.provider == {
          kind:"interface_method",
          events:[{
            unit_id:"semantic-transfer:original-cutpoint-0000cdb7-0000cdbd",
            event_index:0
          }],
                method_contract_sha256:
                  "e68d1604d068317fdeb07334d453db3634f120f4b09d94b3b69385cff1c07f85"
              } and
              ([$machine_frontier.review_frontier.operations[0].lexical_service_candidates |
                group_by(.service_id)[] | {
                  service_id:.[0].service_id,
                  count:length,
                  authorities:([.[].authority] | unique)
                }]) == [
                {service_id:"destroy_window",count:5,authorities:[false]},
                {service_id:"directdraw_create",count:1,authorities:[false]},
                {service_id:"message_box",count:5,authorities:[false]}
              ] and
              ([$machine_frontier.review_frontier.operations[0].exact_call_events[] |
                select(.call.kind == "external_call") | .call.symbol] | unique) == [
                "DestroyWindow",
                "DirectDrawCreate",
                "MessageBoxA"
              ] and
              ([$machine_frontier.review_frontier.operations[0].exact_call_events[] |
                select(.structural_interface_candidates | length > 0) | {
                  instruction_rva:.call.instruction_rva,
                  offsets:([.structural_interface_candidates[].offset] | unique),
                  candidate_count:(.structural_interface_candidates | length),
                  authorities:([.structural_interface_candidates[].authority] | unique)
                }]) == [
                {instruction_rva:52666,offsets:[80],candidate_count:13,authorities:[false]},
                {instruction_rva:52782,offsets:[44],candidate_count:17,authorities:[false]},
                {instruction_rva:52845,offsets:[24],candidate_count:21,authorities:[false]},
                {instruction_rva:52966,offsets:[24],candidate_count:21,authorities:[false]},
                {instruction_rva:53061,offsets:[16],candidate_count:32,authorities:[false]},
                {instruction_rva:53110,offsets:[32],candidate_count:20,authorities:[false]},
                {instruction_rva:53157,offsets:[112],candidate_count:6,authorities:[false]}
              ]
            ' \
              ${components.v6WorkPackages.directdraw-init.derivation}/component-work-package-v6.json \
              >/dev/null
            touch "$out"
      '';
  semanticMigrationGate =
    pkgs.runCommand "dxball-semantic-module-v2-migration-checkpoint"
      {
        nativeBuildInputs = [ pkgs.jq ];
        __contentAddressed = true;
      }
      ''
        jq -e '
          .status == "complete" and
          .authority == "checked_static_environment" and
          .blockers == [] and
          ([.machine_import_contracts[] | select(
            .identity.symbol == "RtlUnwind"
          ) | .boundary.physical_call_frame_v3.transport.outcomes] | unique) == [
            ["nonlocal"]
          ] and
          ([.machine_import_contracts[] | select(
            .identity.symbol == "UnhandledExceptionFilter"
          ) | .contract.payload.external_service_protocol.object_view.kind] | unique) == [
            "win32_exception_pointers_v1"
          ]
        ' ${workflow.resolvedEnvironment.derivation}/resolved-external-environment.json >/dev/null

        jq -e '
          .control.target_cutpoint_materialization.status == "complete" and
          .control.target_cutpoint_materialization.counts.materialized_units == 69 and
          ([.control.target_cutpoint_materialization.static_recovery_refreshes[].changed]) == [
            true,
            true,
            false
          ] and
          .control.executable_classification.status == "complete" and
          .control.executable_classification.counts.conflicts == 0 and
          .counts.units == 9022 and
          .counts.materialized_target_units == 69 and
          ([.control.recovered_indirect_targets[] | select(
            .status == "recovered" and .unit_binding.status != "complete"
          )] | length) == 0
        ' ${workflow.analysis.machineIr}/machine-ir-manifest.json >/dev/null

        jq -e '
          .status == "incomplete" and
          .counts.issues == 27 and
          ([.issues | group_by(.code)[] | {
            code: .[0].code,
            count: length
          }]) == [
            {"code":"lean_semantic_form_unsupported","count":27}
          ] and
          .counts.forms_native_exact_replay == 4 and
          .counts.occurrences_native_exact_replay == 4 and
          ([.forms[] | select(
            .qualification_kind == "native_exact_replay"
          ) | {form_id, oracle_status}] | sort_by(.form_id)) == [
            {
              "form_id":"lean-x86-form-116c436887dce20a7a64",
              "oracle_status":"incomplete"
            },
            {
              "form_id":"lean-x86-form-778743d41d38fc5ca4c4",
              "oracle_status":"incomplete"
            },
            {
              "form_id":"lean-x86-form-8b016de8bb47ea2d8303",
              "oracle_status":"incomplete"
            },
            {
              "form_id":"lean-x86-form-e03835bfea60392cef8a",
              "oracle_status":"vetoed"
            }
          ]
        ' ${workflow.semanticObject.derivation}/qualified-platform-selection.json >/dev/null

        jq -e '
          .status == "complete" and
          .counts.roots == 14 and
          .counts.direct_control_edges == 11591 and
          .counts.active_symbols == 9269 and
          .counts.active_relocations == 12287 and
          .counts.residual_obligations == 261 and
          .counts.semantic_holes == 0 and
          .semantic_holes == [] and
          ([.residual_obligations | group_by(.class)[] | select(
            .[0].class | startswith("checked_external_")
          ) | {class: .[0].class, count: length}]) == [
            {"class":"checked_external_exception_object_service","count":1},
            {"class":"checked_external_nonlocal_service","count":1}
          ]
        ' ${workflow.linkedSemanticModule.linkedSemanticModule} >/dev/null

        jq -e '
          .format == "spaghetti-extractor-module-runtime-plan-v8" and
          .status == "ready" and
          .counts.blockers == 0 and
          .blockers == [] and
          .counts.external_sites == 426 and
          .counts.external_site_target_pairs == 167558 and
          .counts.external_target_contracts == 1408 and
          .counts.external_contract_domains == 92 and
          .counts.external_contract_domain_members == 1408 and
          .counts.callback_target_domains == 1 and
          .counts.external_service_routes == 2 and
          .counts.compact_code_capability_domains == 13 and
          .counts.compact_code_capability_domain_targets == 117286 and
          .counts.compact_code_capability_publications == 784 and
          ([.compact_code_capability_publications | group_by(
            .authority_kind
          )[] | {authority_kind:.[0].authority_kind,count:length}]) == [
            {"authority_kind":"checked_external_site_contract","count":764},
            {"authority_kind":"interface_method_contract","count":20}
          ] and
          ([.external_service_routes | sort_by(
            .admitted_domain.protocol.id
          )[] | {
            obligation_class,
            protocol_id:.admitted_domain.protocol.id,
            protocol_kind:.admitted_domain.protocol.kind,
            implementation,
            sites:(.admitted_domain.sites | length)
          }]) == [
            {
              "obligation_class":"checked_external_nonlocal_service",
              "protocol_id":"win32-rtl-unwind-v1",
              "protocol_kind":"nonlocal_unwind",
              "implementation":"checked_runtime",
              "sites":2
            },
            {
              "obligation_class":"checked_external_exception_object_service",
              "protocol_id":"win32-unhandled-exception-filter-v1",
              "protocol_kind":"unhandled_exception_filter",
              "implementation":"checked_runtime",
              "sites":1
            }
          ]
        ' ${workflow.runtimeSemanticProvider}/module-runtime-plan.json >/dev/null
        test "$(stat -c %s ${workflow.runtimeSemanticProvider}/module-runtime-plan.json)" \
          -le 16777216

        jq -e '
          .format == "spaghetti-extractor-shared-module-runtime-package-v2" and
          .status == "ready" and
          .acceptance_authority == false and
          .blockers == [] and
          ([.sources[].role] | sort) == [
            "machine_object_authority",
            "module_runtime_bridge_assembly",
            "module_runtime_header",
            "module_runtime_layout_source",
            "module_runtime_plan",
            "module_runtime_source",
            "native_ingress_bridge_assembly",
            "native_ingress_plan",
            "native_ingress_runtime_header",
            "native_ingress_source",
            "shared_module_runtime_bindings_source",
            "shared_module_runtime_header",
            "shared_module_runtime_source"
          ]
        ' ${workflow.runtimeSemanticProvider}/shared-module-runtime-package.json >/dev/null
        test -s ${workflow.runtimeSemanticProvider}/module-runtime.c
        test -s ${workflow.runtimeSemanticProvider}/shared-module-runtime.c
        touch "$out"
      '';
  runtimeData =
    pkgs.runCommand "dxball-1.09-candidate-runtime-data"
      {
        __contentAddressed = true;
      }
      ''
        mkdir -p "$out"
        cp -a ${original}/runtime/. "$out/"
        rm -f "$out/DXBall.exe"
      '';
  candidateTests = {
    "dxball-default-candidate" = workflow.candidateTestFor {
      id = "dxball-default-candidate";
      configurationId = target.workflow.default_configuration;
      suite = ./tests/candidate-suite.json;
      inherit runtimeData;
      timeoutSeconds = 20;
    };
  };
in
sdk.target.pe32Bundle {
  targetRoot = ./.;
  inherit workflow candidateTests;
  inputs = {
    inherit archive installer original;
  };
  profiles.interface = interfaceProfile;
  targetAssets.documentation = [ "intent/libraries/README.md" ];
  targetAssets.boundary_schema = [ "intent/boundaries.json" ];
  targetAssets.boundary_source = [ "source/window-class-boundary.c" ];
  extraArtifacts.boundaries = boundaries;
  checks = v6ComponentChecks // {
    component-v6-migration-status = componentMigrationStatus;
    directdraw-init-v6-work-package = components.v6WorkPackages.directdraw-init.derivation;
    directdraw-init-v6-honest-blockers = directdrawBlockerGate;
    semantic-module-v2-migration-checkpoint = semanticMigrationGate;
    canonical-boundaries = boundaries;
  };
}
