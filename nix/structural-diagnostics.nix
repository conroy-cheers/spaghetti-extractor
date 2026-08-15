# spaghetti-extractor-python-role: diagnostic
{
  pkgs,
  pythonEnv,
  pythonSource,
  machineIr,
  staticExport,
  machineImportProfiles,
  namePrefix,
}:

let
  lib = pkgs.lib;
  python = "${pythonEnv}/bin/python3";
  loadImageContract = "${staticExport}/load-image-contract.json";
  profileArgs = lib.concatMapStringsSep " "
    (profile: lib.escapeShellArg (toString profile)) machineImportProfiles;
  phaseSource = import ./python-module-closure.nix {
    phaseRole = "diagnostic";
    inherit pkgs;
    modules = [
      "spaghetti_extractor.candidate.engine"
      "spaghetti_extractor.candidate.image"
      "spaghetti_extractor.external.machine_import_profiles"
      "spaghetti_extractor.util"
    ];
    name = "${namePrefix}-structural-diagnostics-python-closure";
  };
  profileBundle = pkgs.runCommand
    "${namePrefix}-structural-diagnostic-profile-bundle"
    {
      nativeBuildInputs = [ pythonEnv ];
      preferLocalBuild = false;
      allowSubstitutes = true;
      __contentAddressed = true;
    }
    ''
      set -euo pipefail
      export PYTHONHASHSEED=0
      export PYTHONPATH=${phaseSource}/src
      mkdir -p "$out"
      ${python} - "$out/profile.json" ${profileArgs} <<'PY'
      import pathlib
      import sys

      from spaghetti_extractor.external.machine_import_profiles import (
          load_machine_import_profile_set,
      )
      from spaghetti_extractor.util import write_json

      selected = load_machine_import_profile_set(
          [pathlib.Path(value) for value in sys.argv[2:]]
      )
      write_json(pathlib.Path(sys.argv[1]), {
          "format": "stage-a-external-environment-profile-v1",
          "id": "${namePrefix}-structural-diagnostic-profile-bundle",
          "provenance": {
              "kind": "resolved_machine_import_profile_graph_v1",
              "source_profiles": [
                  {"id": row.profile_id, "sha256": row.sha256}
                  for row in selected.profiles
              ],
          },
          "machine_import_call_contracts": [
              dict(row.contract) for row in selected.contracts
          ],
      })
      PY
    '';
in
pkgs.runCommand "${namePrefix}-structural-diagnostics-v1" {
  nativeBuildInputs = [ pythonEnv pkgs.jq pkgs.findutils pkgs.gnugrep ];
  preferLocalBuild = false;
  allowSubstitutes = true;
  __contentAddressed = true;
} ''
  set -euo pipefail
  export PYTHONHASHSEED=0
  export LC_ALL=C.UTF-8
  export SOURCE_DATE_EPOCH=1
  export SPAGHETTI_ORIGINAL_EXECUTION_FORBIDDEN=1
  export PYTHONPATH=${phaseSource}/src

  ${python} - \
    ${machineIr}/machine-ir.jsonl \
    ${machineIr}/machine-ir-manifest.json \
    ${machineIr}/recovered-executable-data.json \
    ${loadImageContract} \
    ${profileBundle}/profile.json \
    "$out" ${profileArgs} <<'PY'
  import json
  import pathlib
  import sys

  from spaghetti_extractor.candidate.engine import (
      write_stage_b_native_engine_package,
  )
  from spaghetti_extractor.candidate.image import (
      derive_native_image_inputs,
      select_native_termination_import,
  )
  from spaghetti_extractor.util import sha256_file, write_json

  machine_ir = pathlib.Path(sys.argv[1])
  machine_ir_manifest = pathlib.Path(sys.argv[2])
  recovered_executable_data = pathlib.Path(sys.argv[3])
  load_contract = pathlib.Path(sys.argv[4])
  profile_bundle = pathlib.Path(sys.argv[5])
  output = pathlib.Path(sys.argv[6])
  profiles = tuple(pathlib.Path(value) for value in sys.argv[7:])

  static_program_sha256 = None
  with machine_ir.open(encoding="utf-8") as source:
      for line in source:
          if not line.strip():
              continue
          unit = json.loads(line)
          export = unit.get("source", {}).get("semantic_export")
          if isinstance(export, dict):
              static_program_sha256 = export.get("static_program_contract_sha256")
          if static_program_sha256 is not None:
              break
  inputs = derive_native_image_inputs(
      load_image_contract=load_contract,
      static_program_contract_sha256=static_program_sha256,
  )
  termination = select_native_termination_import(
      profile_paths=profiles,
      import_iat_vas=inputs.import_iat_vas,
  )
  package = write_stage_b_native_engine_package(
      machine_ir=machine_ir,
      machine_ir_manifest=machine_ir_manifest,
      recovered_executable_data=recovered_executable_data,
      entry_rva=inputs.entry_rva,
      callback_targets=inputs.callback_targets,
      import_iat_vas=inputs.import_iat_vas,
      termination_import=termination,
      base_relocation_evidence=inputs.base_relocation_evidence,
      fixed_image_base=inputs.fixed_image_base,
      preferred_image_base=inputs.image_base,
      machine_import_profiles=(profile_bundle,),
      canonical_external_sites=None,
      candidate_mode="structural-diagnostic",
      allow_deferred_potential_transfers=True,
      out=output,
      initial_zero_ranges=inputs.initial_zero_ranges,
      selected_portable_components=(),
  )
  write_json(output / "structural-diagnostics.json", {
      "format": "spaghetti-extractor-structural-diagnostics-v1",
      "status": "usable-incomplete" if package["diagnostic_frontiers"] else "complete",
      "engine_package_sha256": sha256_file(output / "native-engine-package.json"),
      "diagnostic_frontiers": package["diagnostic_frontiers"],
      "counts": package["counts"],
      "policy": {
          "static_only": True,
          "executable": False,
          "object_code_emitted": False,
          "runtime_package_emitted": False,
          "wine_execution_permitted": False,
          "candidate_authority": False,
      },
  })
  PY

  jq -e '
    .format == "spaghetti-extractor-structural-diagnostics-v1" and
    (.status == "complete" or .status == "usable-incomplete") and
    .policy.static_only and
    (.policy.executable | not) and
    (.policy.object_code_emitted | not) and
    (.policy.runtime_package_emitted | not) and
    (.policy.wine_execution_permitted | not) and
    (.policy.candidate_authority | not)
  ' "$out/structural-diagnostics.json" >/dev/null
  test ! -e "$out/candidate.exe"
  if find "$out" -type f \( -name '*.o' -o -name '*.obj' -o -name '*.exe' \) \
      -print -quit | grep -q .; then
    echo "structural diagnostics emitted executable or object code" >&2
    exit 1
  fi
''
