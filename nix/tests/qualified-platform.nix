# spaghetti-extractor-python-role: developer
{
  pkgs,
  pythonEnv,
  kernelCache,
  semanticKernel,
  isaFormInventory,
  bochsRunner,
  sharedISACampaign,
}:

let
  first = import ../qualified-platform.nix {
    inherit
      pkgs
      pythonEnv
      kernelCache
      semanticKernel
      isaFormInventory
      bochsRunner
      sharedISACampaign
      ;
    namePrefix = "spaghetti-extractor-platform-first";
  };
  second = import ../qualified-platform.nix {
    inherit
      pkgs
      pythonEnv
      kernelCache
      semanticKernel
      isaFormInventory
      bochsRunner
      sharedISACampaign
      ;
    namePrefix = "spaghetti-extractor-platform-second";
  };
in
pkgs.runCommand "spaghetti-extractor-qualified-platform-v1-check" {
  nativeBuildInputs = [ pkgs.jq pythonEnv ];
} ''
  set -euo pipefail
  cmp ${first.qualifiedPlatform} ${second.qualifiedPlatform}
  jq -e '
    .format == "spaghetti-extractor-qualified-platform-v1" and
    .status == "complete" and .role == "qualified_platform_release" and
    .authority == true and .target_independent == true and
    .counts.transfer_primitives > 0 and
    .counts.runtime_providers > 0 and
    .counts.abi_profiles == 2 and
    .counts.native_primitives == 8 and
    .counts.behavioral_c_rejections == 0 and
    .counts.isa_forms == 450 and
    .counts.isa_form_constructors == 95 and
    (.holes | length > 0) and
    ([.holes[].kind] | index("abi_profile_catalog_unlinked") == null) and
    ([.holes[].kind] | index("finite_isa_form_inventory_unreviewed") == null) and
    ([.native_primitives[].qualification.status] | unique == ["complete"]) and
    ([.native_primitives[].qualification.test_results_authorizing] | unique ==
      [false]) and
    ([.holes[].kind] | index("native_primitive_qualification_unlinked") == null) and
    ([.primitive_catalog[].primitive_id] | length == (unique | length)) and
    (.platform_sha256 | test("^[0-9a-f]{64}$"))
  ' ${first.qualifiedPlatform} >/dev/null
  test -L ${first.derivation}/semantic-kernel.json
  test -L ${first.derivation}/isa-form-inventory.json
  test -L ${first.derivation}/isa-form-replay.json
  test -L ${first.derivation}/isa-form-qualification-certificate.json
  cmp ${semanticKernel} ${first.derivation}/semantic-kernel.json
  cmp ${isaFormInventory} ${first.derivation}/isa-form-inventory.json
  jq -e '
    .format == "spaghetti-extractor-qualified-platform-isa-form-replay-v1" and
    .status == "complete" and .authority == false and
    .counts.forms == 450 and .counts.checked == 450 and
    .counts.rejected == 0
  ' ${first.derivation}/isa-form-replay.json >/dev/null
  jq -e '
    .format == "spaghetti-extractor-isa-kernel-qualification-certificate-v1" and
    .status == "complete" and .authority == false and
    .target_independent == true and .counts.forms == 450 and
    .counts.qualified == 446 and .counts.incomplete == 3 and
    .counts.disputed == 0 and .counts.vetoed == 1
  ' ${first.derivation}/isa-form-qualification-certificate.json >/dev/null
  touch "$out"
''
