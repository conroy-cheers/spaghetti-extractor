# spaghetti-extractor-python-role: candidate
{
  pkgs,
  behavioralCPackage,
  interpreterPackage,
  nativeRuntimePackage,
  namePrefix,
}:

pkgs.runCommand
  "${namePrefix}-behavioral-c-runtime-qualification-v1"
  {
    nativeBuildInputs = [ pkgs.jq pkgs.coreutils pkgs.ripgrep ];
    preferLocalBuild = false;
    allowSubstitutes = true;
    __contentAddressed = true;
  }
  ''
    set -euo pipefail
    behavioral_manifest=${behavioralCPackage}/behavioral-c-package.json
    interpreter_manifest=${interpreterPackage}/state-machine-interpreter-package.json
    runtime_manifest=${nativeRuntimePackage}/native-runtime-package.json
    jq -e '.status == "ready" and ((.blockers // []) | length == 0)' \
      "$runtime_manifest" >/dev/null
    behavioral_machine="$(jq -er .machine_ir.sha256 "$behavioral_manifest")"
    interpreter_machine="$(jq -er .machine_ir.sha256 "$interpreter_manifest")"
    runtime_machine="$(jq -er .inputs.state_machine_sha256 "$runtime_manifest")"
    test "$behavioral_machine" = "$interpreter_machine"
    test "$behavioral_machine" = "$runtime_machine"
    behavioral_header_sha="$(
      jq -er '.sources[] | select(.role == "runtime_header") | .sha256' \
        "$behavioral_manifest"
    )"
    interpreter_header_sha="$(
      jq -er '.sources[] | select(.role == "runtime_header") | .sha256' \
        "$interpreter_manifest"
    )"
    test "$behavioral_header_sha" = "$interpreter_header_sha"
    runtime_source="$(
      jq -er '.sources[] | select(.role == "native_runtime_source") | .path' \
        "$runtime_manifest"
    )"
    runtime_source=${nativeRuntimePackage}/"$runtime_source"
    for symbol in \
      spx_native_flat_read spx_native_flat_write \
      spx_dispatch_external_call \
      spx_native_atomic_compare_exchange spx_native_atomic_exchange \
      spx_native_undefined_value spx_native_resolve_code_target; do
      rg -q "\b$symbol\b" "$runtime_source"
    done
    typed_x87="$(jq -er '.inputs.runtime_abi.typed_native_x87_handler' "$runtime_manifest")"
    if [ "$typed_x87" = true ]; then
      rg -q '\bspx_native_execute_typed_x87_operation\b' "$runtime_source"
    fi
    ingress_plan_sha="$(jq -r '.inputs.native_ingress_plan.sha256 // empty' "$runtime_manifest")"
    ingress_features="$(jq -c '.policy.native_ingress.features // []' "$runtime_manifest")"
    ingress_stack="$(jq -r '.policy.native_ingress.private_stack_bytes // 0' "$runtime_manifest")"
    mkdir -p "$out"
    jq -n \
      --arg machine "$behavioral_machine" \
      --arg behavioralPackageSha256 "$(sha256sum "$behavioral_manifest" | cut -d' ' -f1)" \
      --arg interpreterPackageSha256 "$(sha256sum "$interpreter_manifest" | cut -d' ' -f1)" \
      --arg nativeRuntimePackageSha256 "$(sha256sum "$runtime_manifest" | cut -d' ' -f1)" \
      --arg runtimeHeaderSha256 "$behavioral_header_sha" \
      --argjson typedX87 "$typed_x87" \
      --arg ingressPlanSha256 "$ingress_plan_sha" \
      --argjson ingressFeatures "$ingress_features" \
      --argjson ingressStack "$ingress_stack" '
      [
        "atomic.rmw",
        "call.dispatch",
        "code_target.resolve",
        "definedness.choice",
        "memory.read",
        "memory.write"
      ] + (if $typedX87 then ["x87.typed_exact"] else [] end) as $providers |
      {
        format: "spaghetti-extractor-behavioral-c-runtime-qualification-v1",
        status: "complete",
        machine_ir_sha256: $machine,
        qualified_providers: $providers,
        native_ingress_plan_sha256: (
          if $ingressPlanSha256 == "" then null else $ingressPlanSha256 end
        ),
        qualified_native_ingress_features: ($ingressFeatures | sort | unique),
        qualified_private_stack_bytes: $ingressStack,
        runtime_abi_sha256: $runtimeHeaderSha256,
        bindings: {
          behavioral_c_package_sha256: $behavioralPackageSha256,
          interpreter_package_sha256: $interpreterPackageSha256,
          native_runtime_package_sha256: $nativeRuntimePackageSha256
        },
        proof_authority: false
      }
    ' > "$out/runtime-qualification.json"
  ''
