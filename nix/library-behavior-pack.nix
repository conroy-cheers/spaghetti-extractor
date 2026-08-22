# spaghetti-extractor-python-role: candidate
{
  pkgs,
  pythonEnv,
  pythonSource,
  name,
  implementation,
  sourcePackage,
  interface,
  sourceProfile,
  compileReceipt,
  qualificationReceipt,
  behaviorContract ? null,
}:

let
  lib = pkgs.lib;
  identifier = value:
    builtins.isString value && value != ""
    && builtins.match "[A-Za-z0-9][A-Za-z0-9._-]*" value != null;
  asInput = inputName: value:
    if builtins.typeOf value == "path" then
      builtins.path { path = value; name = inputName; }
    else value;
  implementationInput = asInput "${name}-implementation.json" implementation;
  sourcePackageInput = asInput "${name}-source-package" sourcePackage;
  interfaceInput = asInput "${name}-portable-interface.json" interface;
  sourceProfileInput = asInput "${name}-source-profile.json" sourceProfile;
  compileReceiptInput = asInput "${name}-compile-receipt.json" compileReceipt;
  qualificationReceiptInput =
    asInput "${name}-qualification-receipt.json" qualificationReceipt;
  behaviorContractInput =
    if behaviorContract == null then null
    else asInput "${name}-behavior-contract.json" behaviorContract;
  phaseSource = import ./python-module-closure.nix {
    phaseRole = "candidate";
    inherit pkgs;
    modules = [ "spaghetti_extractor.libraries.v4_behavior_pack" ];
    name = "${name}-library-behavior-pack-python-closure";
  };
in
assert lib.assertMsg (identifier name) "library behavior-pack name is invalid";
pkgs.runCommand "${name}-reusable-library-behavior-pack-${if behaviorContractInput == null then "v1" else "v2"}" {
  nativeBuildInputs = [ pythonEnv pkgs.jq ];
  preferLocalBuild = false;
  allowSubstitutes = true;
  __contentAddressed = true;
} ''
  set -euo pipefail
  export PYTHONHASHSEED=0
  export PYTHONDONTWRITEBYTECODE=1
  export LC_ALL=C.UTF-8
  export SOURCE_DATE_EPOCH=1
  export PYTHONPATH=${phaseSource}/src
  ${pythonEnv}/bin/python3 - \
    ${lib.escapeShellArg implementationInput} \
    ${lib.escapeShellArg sourcePackageInput} \
    ${lib.escapeShellArg interfaceInput} \
    ${lib.escapeShellArg sourceProfileInput} \
    ${lib.escapeShellArg compileReceiptInput} \
    ${lib.escapeShellArg qualificationReceiptInput} \
    "$out" <<'PY'
  import pathlib
  import sys

  from spaghetti_extractor.libraries.v4_behavior_pack import (
      build_reusable_library_behavior_pack_v1,
      build_reusable_library_behavior_pack_v2,
  )

  common = dict(
      implementation=pathlib.Path(sys.argv[1]),
      source_package=pathlib.Path(sys.argv[2]),
      interface=pathlib.Path(sys.argv[3]),
      source_profile=pathlib.Path(sys.argv[4]),
      compile_receipt=pathlib.Path(sys.argv[5]),
      qualification_receipt=pathlib.Path(sys.argv[6]),
      out_dir=pathlib.Path(sys.argv[7]),
  )
  behavior = ${if behaviorContractInput == null then "None" else "pathlib.Path(" + builtins.toJSON (toString behaviorContractInput) + ")"}
  if behavior is None:
      build_reusable_library_behavior_pack_v1(**common)
  else:
      build_reusable_library_behavior_pack_v2(
          **common,
          behavior_contract=behavior,
      )
  PY
  jq -e '
    (.format == "spaghetti-extractor-reusable-library-behavior-pack-v1" or
     .format == "spaghetti-extractor-reusable-library-behavior-pack-v2") and
    (.pack_sha256 | type == "string")
  ' "$out/behavior-pack.json" >/dev/null
''
