#!/usr/bin/env bash
set -euo pipefail

repo_root=${SPAGHETTI_EXTRACTOR_SLICE_REPO_ROOT:-}
if [[ -z "$repo_root" ]]; then
  repo_root=$(git rev-parse --show-toplevel)
fi
export PYTHONPATH="$repo_root/src${PYTHONPATH:+:$PYTHONPATH}"
spaghetti_extractor_cmd=(python -m spaghetti_extractor)

abs_path() {
  case "$1" in
    /*) printf '%s\n' "$1" ;;
    *) printf '%s/%s\n' "$repo_root" "$1" ;;
  esac
}

workspace=$(abs_path "${SPAGHETTI_EXTRACTOR_SLICE_WORKSPACE:?SPAGHETTI_EXTRACTOR_SLICE_WORKSPACE is required}")
build_dir=$(abs_path "${SPAGHETTI_EXTRACTOR_SLICE_BUILD_DIR:?SPAGHETTI_EXTRACTOR_SLICE_BUILD_DIR is required}")
out_dir=$(abs_path "${SPAGHETTI_EXTRACTOR_SLICE_OUT_DIR:?SPAGHETTI_EXTRACTOR_SLICE_OUT_DIR is required}")
source_dir=$(abs_path "${SPAGHETTI_EXTRACTOR_SLICE_SOURCE_DIR:?SPAGHETTI_EXTRACTOR_SLICE_SOURCE_DIR is required}")
target=${SPAGHETTI_EXTRACTOR_SLICE_TARGET:-jq}

if [[ "$target" != "jq" ]]; then
  echo "spaghetti-extractor-build-jq-candidate only supports target jq, got: $target" >&2
  exit 2
fi

mkdir -p "$build_dir" "$out_dir"

strip_import_library_text_stubs() {
  local import_lib=$1
  local tmp
  tmp=$(mktemp -d "$import_lib_dir/strip.XXXXXX")
  (
    cd "$tmp"
    i686-w64-mingw32-ar x "$import_lib"
    shopt -s nullglob
    for object_file in *_s*.o; do
      i686-w64-mingw32-objcopy --remove-section .text "$object_file" "$object_file.stripped"
      mv "$object_file.stripped" "$object_file"
    done
    rm -f "$import_lib"
    i686-w64-mingw32-ar crs "$import_lib" ./*.o
  )
  rm -rf "$tmp"
}

reference_contract="$workspace/contracts/reference_contract.json"
current_candidate="$workspace/candidate/current-candidate.json"
source_file="$source_dir/jq_stage_b_skeleton.c"
object_file="$build_dir/jq_stage_b_skeleton.o"
link_roots_dir="$build_dir/link-roots"
import_lib_dir="$build_dir/import-libs"
strict_map="$build_dir/jq-stage-b-generated-closure-candidate.strict.map"
strict_exe="$build_dir/jq-stage-b-generated-closure-candidate.strict.exe"
link_exe="$build_dir/jq.exe"
candidate_map="$out_dir/jq-stage-b-generated-closure-candidate.map"
candidate_exe="$out_dir/jq-stage-b-generated-closure-candidate.exe"
build_report="$out_dir/decompiled-c-generated-closure-link-report.json"
out_manifest="$out_dir/skeleton-manifest.json"
provenance="$out_dir/candidate-provenance.json"

original=$(
  python - "$reference_contract" <<'PY'
import json
import sys
from pathlib import Path

payload = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
print(payload["inputs"]["original"]["path"])
PY
)
fixture_dir=$(dirname "$original")

skeleton_manifest=$(
  python - "$current_candidate" <<'PY'
import json
import sys
from pathlib import Path

payload = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
print(payload["skeleton_manifest"])
PY
)
skeleton_directory=$(
  python - "$current_candidate" <<'PY'
import json
import sys
from pathlib import Path

payload = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
print(payload["directory"])
PY
)
skeleton_functions=$(
  python - "$current_candidate" <<'PY'
import json
import sys
from pathlib import Path

payload = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
print(payload["functions"])
PY
)

skeleton_manifest=$(abs_path "$skeleton_manifest")
skeleton_directory=$(abs_path "$skeleton_directory")
prepared_manifest="$skeleton_directory/manifest.json"
if [[ ! -f "$skeleton_manifest" || "$(readlink -m "$skeleton_manifest")" == "$(readlink -m "$out_manifest")" ]]; then
  if [[ -f "$prepared_manifest" ]]; then
    skeleton_manifest="$prepared_manifest"
  fi
fi

rm -f "$candidate_exe" "$candidate_map" "$build_report" "$provenance" "$strict_exe" "$link_exe"
if [[ "$(readlink -m "$skeleton_manifest")" != "$(readlink -m "$out_manifest")" ]]; then
  rm -f "$out_manifest"
  cp "$skeleton_manifest" "$out_manifest"
else
  chmod u+w "$out_manifest" 2>/dev/null || true
fi

i686-w64-mingw32-gcc -std=gnu11 -Os \
  -fno-align-functions -fno-align-labels -fno-align-loops -fno-align-jumps \
  -c "$source_file" -o "$object_file" \
  >"$build_dir/compile.stdout.txt" 2>"$build_dir/compile.stderr.txt"

set +e
"${spaghetti_extractor_cmd[@]}" stage-b-generate-link-roots \
  --original "$original" \
  --reference-contract "$reference_contract" \
  --skeleton-functions "$skeleton_functions" \
  --object-file "$object_file" \
  --out "$link_roots_dir" \
  --nm i686-w64-mingw32-nm \
  >"$build_dir/link-roots.stdout.json" 2>"$build_dir/link-roots.stderr.txt"
link_roots_rc=$?
set -e

mkdir -p "$import_lib_dir"
mapfile -t imported_dlls < <(
  python - "$reference_contract" <<'PY'
import json
import sys
from pathlib import Path

payload = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
system = {"kernel32.dll"}
dlls = sorted({
    str(item.get("dll") or "")
    for item in payload.get("original", {}).get("imports", [])
    if isinstance(item, dict)
    and str(item.get("dll") or "").lower() not in system
})
for dll in dlls:
    print(dll)
PY
)

lib_args=()
generated_import_libraries=()
for dll in "${imported_dlls[@]}"; do
  [[ -n "$dll" ]] || continue
  dll_path="$fixture_dir/$dll"
  def_file="$import_lib_dir/${dll%.dll}.def"
  import_lib="$import_lib_dir/$dll.a"
  {
    printf 'LIBRARY %s\n' "$dll"
    printf 'EXPORTS\n'
    python - "$reference_contract" "$dll" <<'PY'
import json
import sys
from pathlib import Path

payload = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
dll = sys.argv[2].lower()
seen = set()
for item in payload.get("original", {}).get("imports", []):
    if not isinstance(item, dict) or str(item.get("dll") or "").lower() != dll:
        continue
    symbol = str(item.get("symbol") or "")
    if not symbol or symbol in seen:
        continue
    seen.add(symbol)
    print(f"  {symbol}")
PY
  } >"$def_file"
  if ! grep -q '^  ' "$def_file"; then
    if [[ ! -f "$dll_path" ]]; then
      echo "missing fixture DLL and reference imports for import library: $dll_path" >&2
      exit 1
    fi
    {
      printf 'LIBRARY %s\n' "$dll"
      printf 'EXPORTS\n'
      llvm-readobj --coff-exports "$dll_path" | awk '/  Name: / {print "  " $2}'
    } >"$def_file"
  fi
  i686-w64-mingw32-dlltool -d "$def_file" -D "$dll" -l "$import_lib"
  strip_import_library_text_stubs "$import_lib"
  lib_args+=("-l:$dll.a")
  generated_import_libraries+=("$dll.a")
done

mapfile -t root_flags < <(
  cat \
    "$link_roots_dir/link-root-flags.txt" \
    "$link_roots_dir/import-thunk-root-flags.txt" \
    "$link_roots_dir/runtime-crt-root-flags.txt" \
    | sed '/^$/d'
)

common_flags=(
  -nostartfiles
  -Wl,-e,_mainCRTStartup
  -Wl,--image-base,0x400000
  -Wl,--gc-sections
)
strict_layout_flags=(
  -Wl,--section-start,.text=0x401000
  -Wl,--section-start,.data=0x40d000
  -Wl,--section-start,.rdata=0x40e000
  -Wl,--section-start,.bss=0x410000
  -Wl,--section-start,.edata=0x411000
  -Wl,--section-start,.idata=0x412000
  -Wl,--section-start,.tls=0x413000
  -Wl,--section-start,.reloc=0x414000
)

set +e
i686-w64-mingw32-gcc \
  "${common_flags[@]}" \
  "${strict_layout_flags[@]}" \
  "-Wl,-Map,$strict_map" \
  "${root_flags[@]}" \
  "$object_file" \
  "-L$import_lib_dir" \
  "${lib_args[@]}" \
  -o "$link_exe" \
  >"$build_dir/strict-link.stdout.txt" 2>"$build_dir/strict-link.stderr.txt"
strict_rc=$?
set -e

diagnostic_fallback=false
if [[ "$strict_rc" -eq 0 ]]; then
  cp "$link_exe" "$strict_exe"
  cp "$link_exe" "$candidate_exe"
  cp "$strict_map" "$candidate_map"
  link_stdout="$build_dir/strict-link.stdout.txt"
  link_stderr="$build_dir/strict-link.stderr.txt"
  link_rc=0
else
  diagnostic_fallback=true
  rm -f "$link_exe"
  set +e
  i686-w64-mingw32-gcc \
    "${common_flags[@]}" \
    "-Wl,-Map,$candidate_map" \
    "${root_flags[@]}" \
    "$object_file" \
    "-L$import_lib_dir" \
    "${lib_args[@]}" \
    -o "$link_exe" \
    >"$build_dir/link.stdout.txt" 2>"$build_dir/link.stderr.txt"
  link_rc=$?
  set -e
  if [[ "$link_rc" -eq 0 ]]; then
    cp "$link_exe" "$candidate_exe"
  fi
  link_stdout="$build_dir/link.stdout.txt"
  link_stderr="$build_dir/link.stderr.txt"
fi

if [[ "$link_rc" -ne 0 ]]; then
  cat "$link_stderr" >&2
  exit "$link_rc"
fi

python - "$build_report" "$link_roots_dir/link-roots.json" "$link_roots_rc" "$strict_rc" "$link_rc" "$diagnostic_fallback" "$strict_map" "$strict_exe" "$candidate_map" "$candidate_exe" "$build_dir/strict-link.stdout.txt" "$build_dir/strict-link.stderr.txt" "$link_stdout" "$link_stderr" "${generated_import_libraries[@]}" <<'PY'
import json
import sys
from pathlib import Path

(
    report_path,
    roots_path,
    link_roots_rc,
    strict_rc,
    link_rc,
    diagnostic_fallback,
    strict_map,
    strict_exe,
    candidate_map,
    candidate_exe,
    strict_stdout,
    strict_stderr,
    link_stdout,
    link_stderr,
    *generated_import_libraries,
) = sys.argv[1:]

def tail(path: str, limit: int = 12000) -> str:
    item = Path(path)
    if not item.exists():
        return ""
    text = item.read_text(encoding="utf-8", errors="replace")
    return text[-limit:]

def undefined_samples(stderr_path: str) -> list[str]:
    return [line for line in tail(stderr_path).splitlines() if "undefined reference" in line][:100]

roots = json.loads(Path(roots_path).read_text(encoding="utf-8")) if Path(roots_path).exists() else {}
report = {
    "format": "stage-b-decompiled-c-link-diagnostic-v1",
    "status": "pass" if int(link_rc) == 0 else "incomplete",
    "linker_flags": [
        "-nostartfiles",
        "-Wl,-e,_mainCRTStartup",
        "-Wl,--image-base,0x400000",
        "-Wl,--gc-sections",
        f"-Wl,-Map,{candidate_map}",
        *roots.get("linker_flags", []),
        *roots.get("import_thunk_linker_flags", []),
        *roots.get("runtime_crt_linker_flags", []),
        *[f"-l:{name}" for name in generated_import_libraries],
    ],
    "rooted_link_diagnostic": {
        "status": roots.get("status"),
        "returncode": int(link_roots_rc),
        "counts": roots.get("counts", {}),
        "issues": roots.get("issues", []),
        "linker_flags": [
            *roots.get("linker_flags", []),
            *roots.get("import_thunk_linker_flags", []),
            *roots.get("runtime_crt_linker_flags", []),
        ],
    },
    "strict_layout_link": {
        "status": "pass" if int(strict_rc) == 0 else "incomplete",
        "returncode": int(strict_rc),
        "candidate": strict_exe,
        "linker_map": strict_map,
        "stdout": strict_stdout,
        "stderr": strict_stderr,
        "stderr_tail": tail(strict_stderr),
    },
    "diagnostic_layout_fallback": diagnostic_fallback == "true",
    "standalone_link_diagnostic": {
        "status": "pass" if int(link_rc) == 0 else "incomplete",
        "returncode": int(link_rc),
        "stdout": link_stdout,
        "stderr": link_stderr,
        "undefined_reference_samples": undefined_samples(link_stderr),
        "unresolved_reference_lines": len(undefined_samples(link_stderr)),
    },
    "generated_import_libraries": generated_import_libraries,
    "candidate": candidate_exe,
    "linker_map": candidate_map,
}
Path(report_path).write_text(json.dumps(report, indent=2, sort_keys=True), encoding="utf-8")
PY

set +e
"${spaghetti_extractor_cmd[@]}" stage-b-generate-candidate-provenance \
  --target-name jq \
  --skeleton-manifest "$out_manifest" \
  --candidate "$candidate_exe" \
  --build-target i686-w64-mingw32 \
  --build-compiler i686-w64-mingw32-cc \
  --build-output "$(basename "$candidate_exe")" \
  --build-report "$build_report" \
  --fixed-up-source "$source_file" \
  --out "$out_dir" \
  >"$build_dir/provenance.stdout.json" 2>"$build_dir/provenance.stderr.txt"
provenance_rc=$?
set -e

if [[ ! -f "$provenance" ]]; then
  cat "$build_dir/provenance.stderr.txt" >&2
  exit "$provenance_rc"
fi
