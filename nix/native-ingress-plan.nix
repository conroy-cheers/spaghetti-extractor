# spaghetti-extractor-python-role: candidate
{ pkgs, pythonEnv, moduleInterface, behavioralRoots, objectAuthority
, machineIr, rootClosure, callProtocolPackages ? [ ], callbackAuthority ? null
, outcomeProtocols ? [ ], sehProtocols ? [ ]
, runtimeTlsBytes ? 0, privateStackSize ? null, namePrefix }:

let
  lib = pkgs.lib;
  pythonSource = import ./python-module-closure.nix {
    phaseRole = "candidate";
    inherit pkgs;
    modules = [ "spaghetti_extractor.candidate.native_ingress" ];
    name = "${namePrefix}-native-ingress-plan-python-closure";
  };
  outcomeArgs = lib.concatMapStringsSep " " lib.escapeShellArg outcomeProtocols;
  sehArgs = lib.concatMapStringsSep " " lib.escapeShellArg sehProtocols;
  callArgs = lib.concatMapStringsSep " "
    (value: lib.escapeShellArg (toString value)) callProtocolPackages;
in
pkgs.runCommand "${namePrefix}-native-ingress-plan-v1" {
  nativeBuildInputs = [ pythonEnv pkgs.jq ];
  __contentAddressed = true;
} ''
  set -euo pipefail
  export PYTHONHASHSEED=0
  export PYTHONPATH=${pythonSource}/src
  ${pythonEnv}/bin/python3 - \
    ${moduleInterface}/module-interface.json ${behavioralRoots} \
    ${objectAuthority}/machine-object-authority.json \
    ${machineIr}/machine-ir.jsonl ${lib.escapeShellArg (toString rootClosure)} \
    ${lib.escapeShellArg (if callbackAuthority == null then "" else toString callbackAuthority)} \
    "$out" ${toString runtimeTlsBytes} \
    ${if privateStackSize == null then "none" else toString privateStackSize} \
    ${toString (builtins.length outcomeProtocols)} \
    ${toString (builtins.length sehProtocols)} \
    ${toString (builtins.length callProtocolPackages)} \
    ${outcomeArgs} ${sehArgs} ${callArgs} <<'PY'
  import json
  import pathlib
  import sys
  from spaghetti_extractor.candidate.native_ingress import write_native_ingress_plan

  outcome_count = int(sys.argv[10])
  seh_count = int(sys.argv[11])
  call_count = int(sys.argv[12])
  protocol_paths = tuple(pathlib.Path(value) for value in sys.argv[13:])
  outcomes = protocol_paths[:outcome_count]
  seh = protocol_paths[outcome_count:outcome_count + seh_count]
  calls = protocol_paths[outcome_count + seh_count:]
  if len(calls) != call_count:
      raise ValueError("native ingress call-protocol package count changed")
  load = lambda path: json.loads(path.read_text(encoding="utf-8"))
  write_native_ingress_plan(
      module_interface=pathlib.Path(sys.argv[1]),
      behavioral_roots=pathlib.Path(sys.argv[2]),
      object_authority=pathlib.Path(sys.argv[3]),
      machine_ir=pathlib.Path(sys.argv[4]),
      root_closure=pathlib.Path(sys.argv[5]),
      callback_authority=(
          None if not sys.argv[6] else pathlib.Path(sys.argv[6])
      ),
      call_protocol_packages=calls,
      outcome_protocols=[load(path) for path in outcomes],
      seh_protocols=[load(path) for path in seh],
      runtime_tls_bytes=int(sys.argv[8]),
      private_stack_size=None if sys.argv[9] == "none" else int(sys.argv[9]),
      out=pathlib.Path(sys.argv[7]),
  )
  PY
  jq -e '
    .format == "spaghetti-extractor-native-ingress-plan-v1" and
    .status == "complete" and (.plan_sha256 | length == 64)
  ' "$out/native-ingress-plan.json" >/dev/null
''
