{
  pkgs,
  leanSource,
  name ? "spaghetti-extractor-inductive-certificate-kernel",
}:

pkgs.runCommand name {
  nativeBuildInputs = [ pkgs.lean4 ];
  preferLocalBuild = false;
  allowSubstitutes = true;
  __contentAddressed = true;
} ''
  set -euo pipefail
  mkdir -p StageA
  cp ${leanSource}/StageA/InductiveCertificates.lean \
    StageA/InductiveCertificates.lean
  mkdir -p "$out/StageA"
  export LEAN_PATH="$out:$PWD"
  lean --trust=0 \
    -o "$out/StageA/InductiveCertificates.olean" \
    -c "$out/StageA/InductiveCertificates.c" \
    StageA/InductiveCertificates.lean
  leanc -c \
    -o "$out/StageA/InductiveCertificates.o" \
    "$out/StageA/InductiveCertificates.c"
  cat > InductiveCertificateAudit.lean <<'EOF'
  import StageA.InductiveCertificates
  #print axioms StageA.InductiveCertificates.cutpoint_reachable_satisfies
  #print axioms StageA.InductiveCertificates.checkFiniteCertificate_sound
  EOF
  lean --trust=0 InductiveCertificateAudit.lean \
    > "$out/axiom-audit.txt"
  if grep -q 'sorryAx\|Classical.choice' "$out/axiom-audit.txt"; then
    cat "$out/axiom-audit.txt" >&2
    exit 1
  fi
''
