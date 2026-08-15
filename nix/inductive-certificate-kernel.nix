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
  mkdir -p SpaghettiExtractor/ISA
  cp ${leanSource}/SpaghettiExtractor/ISA/InductiveCertificates.lean \
    SpaghettiExtractor/ISA/InductiveCertificates.lean
  mkdir -p "$out/SpaghettiExtractor/ISA"
  export LEAN_PATH="$out:$PWD"
  lean --trust=0 \
    -o "$out/SpaghettiExtractor/ISA/InductiveCertificates.olean" \
    -c "$out/SpaghettiExtractor/ISA/InductiveCertificates.c" \
    SpaghettiExtractor/ISA/InductiveCertificates.lean
  leanc -c \
    -o "$out/SpaghettiExtractor/ISA/InductiveCertificates.o" \
    "$out/SpaghettiExtractor/ISA/InductiveCertificates.c"
  cat > InductiveCertificateAudit.lean <<'EOF'
  import SpaghettiExtractor.ISA.InductiveCertificates
  #print axioms SpaghettiExtractor.ISA.InductiveCertificates.cutpoint_reachable_satisfies
  #print axioms SpaghettiExtractor.ISA.InductiveCertificates.checkFiniteCertificate_sound
  EOF
  lean --trust=0 InductiveCertificateAudit.lean \
    > "$out/axiom-audit.txt"
  if grep -q 'sorryAx\|Classical.choice' "$out/axiom-audit.txt"; then
    cat "$out/axiom-audit.txt" >&2
    exit 1
  fi
''
