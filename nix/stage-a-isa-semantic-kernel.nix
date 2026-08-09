{
  pkgs,
  leanSource,
  name ? "spaghetti-extractor-isa-semantic-kernel",
}:

pkgs.runCommand name {
  nativeBuildInputs = [ pkgs.lean4 pkgs.python3 ];
  preferLocalBuild = false;
  allowSubstitutes = true;
  __contentAddressed = true;
} ''
  set -euo pipefail
  mkdir -p "$out"
  ${pkgs.python3}/bin/python3 - \
    ${leanSource}/StageA \
    "$out/semantic-kernel.json" \
    "$(lean --version | head -n 1)" <<'PY'
  import hashlib
  import json
  import pathlib
  import sys

  source = pathlib.Path(sys.argv[1])
  output = pathlib.Path(sys.argv[2])
  lean_version = sys.argv[3]

  def digest(files):
      value = hashlib.sha256()
      for name in files:
          data = (source / name).read_bytes()
          value.update(name.encode("ascii") + b"\0")
          value.update(len(data).to_bytes(8, "big"))
          value.update(data)
      return value.hexdigest()

  decoder = digest(["Formal.lean", "ISAInventory.lean"])
  semantics = digest([
      "X87.lean",
      "Formal.lean",
      "ISAQualification.lean",
      "ISAConformance.lean",
  ])
  payload = {
      "format": "stage-a-isa-semantic-kernel-binding-v1",
      "id": "stage-a-lean-machine-semantics:" + semantics[:24],
      "decoder_sha256": decoder,
      "semantics_sha256": semantics,
      "lean_version": lean_version,
  }
  output.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n")
  PY
''
