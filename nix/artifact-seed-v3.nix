{
  pkgs,
  pythonEnv,
  pythonSource,
  name,
  artifactKind,
  bindings,
  input ? null,
  inputFormat ? "ndjson",
  recordIdField ? "id",
  bindInputSource ? true,
  status ? "complete",
  maxPackBytes ? null,
  contentAddressed ? true,
}:

assert builtins.isString name && name != "";
assert builtins.isString artifactKind && artifactKind != "";
assert builtins.isList bindings && bindings != [ ];
assert builtins.elem inputFormat [ "ndjson" "json-array" "empty" ];
assert builtins.isBool bindInputSource;
assert inputFormat == "empty" || input != null;
assert inputFormat != "empty" || input == null;
assert builtins.elem status [ "complete" "incomplete" "violated" ];

let
  lib = pkgs.lib;
  caAttrs = lib.optionalAttrs contentAddressed { __contentAddressed = true; };
in
pkgs.runCommand name (
  {
    nativeBuildInputs = [ pythonEnv ];
    preferLocalBuild = false;
    allowSubstitutes = true;
  }
  // caAttrs
) ''
  set -euo pipefail
  export PYTHONHASHSEED=0
  export PYTHONDONTWRITEBYTECODE=1
  export LC_ALL=C.UTF-8
  export SOURCE_DATE_EPOCH=1
  export SPAGHETTI_ORIGINAL_EXECUTION_FORBIDDEN=1
  export PYTHONPATH=${pythonSource}/src

  ${pythonEnv}/bin/python3 - \
    ${if input == null then "-" else lib.escapeShellArg (toString input)} \
    ${lib.escapeShellArg inputFormat} \
    ${lib.escapeShellArg (if bindInputSource then "true" else "false")} \
    ${lib.escapeShellArg recordIdField} \
    ${lib.escapeShellArg artifactKind} \
    ${lib.escapeShellArg status} \
    ${lib.escapeShellArg (builtins.toJSON bindings)} \
    ${if maxPackBytes == null then "-" else toString maxPackBytes} \
    "$out" <<'PY'
  from __future__ import annotations

  import hashlib
  import json
  import pathlib
  import sys

  from spaghetti_extractor.artifact_set_v3 import (
      ArtifactBindingV3,
      ArtifactRecordV3,
      ArtifactSetWriterV3,
      parse_canonical_json_v3,
  )


  source_arg, input_format, bind_input_source, id_field, artifact_kind, status, bindings_json, max_pack_bytes, output = sys.argv[1:]
  bindings = [
      ArtifactBindingV3.parse(row)
      for row in parse_canonical_json_v3(bindings_json.encode("ascii"), location="seed bindings")
  ]
  values = []
  if input_format != "empty":
      source = pathlib.Path(source_arg)
      data = source.read_bytes()
      if bind_input_source == "true":
          bindings.append(ArtifactBindingV3(
              "source",
              "source-artifact",
              source.name,
              hashlib.sha256(data).hexdigest(),
          ))
      if input_format == "ndjson":
          for line_number, line in enumerate(data.splitlines(), start=1):
              if not line.strip():
                  continue
              values.append(parse_canonical_json_v3(line, location=f"{source}:{line_number}"))
      else:
          payload = parse_canonical_json_v3(data, location=str(source))
          if not isinstance(payload, list):
              raise SystemExit("json-array seed input must be an array")
          values.extend(payload)
  records = []
  for index, value in enumerate(values):
      if not isinstance(value, dict):
          raise SystemExit(f"seed record {index} must be an object")
      record_id = value.get(id_field)
      if not isinstance(record_id, str) or not record_id:
          raise SystemExit(f"seed record {index} has no nonempty {id_field!r}")
      records.append(ArtifactRecordV3.create(record_id, value))
  if len({record.record_id for record in records}) != len(records):
      raise SystemExit("seed input repeats a record ID")
  options = {} if max_pack_bytes == "-" else {"max_pack_bytes": int(max_pack_bytes)}
  ArtifactSetWriterV3(
      artifact_kind=artifact_kind,
      bindings=tuple(sorted(bindings)),
      status=status,
      **options,
  ).write(pathlib.Path(output), records)
  PY
''
