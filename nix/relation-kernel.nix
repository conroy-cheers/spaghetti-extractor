{
  pkgs,
  leanSource,
  name ? "spaghetti-extractor-relation-kernel",
}:

pkgs.runCommand name {
  nativeBuildInputs = [ pkgs.lean4 ];
  preferLocalBuild = false;
  allowSubstitutes = true;
  __contentAddressed = true;
} ''
  set -euo pipefail
  mkdir -p SpaghettiExtractor/Components "$out/SpaghettiExtractor/Components"
  cp ${leanSource}/SpaghettiExtractor/Components/Relations.lean \
    SpaghettiExtractor/Components/Relations.lean
  export LEAN_PATH="$out:$PWD"
  lean --trust=0 \
    -o "$out/SpaghettiExtractor/Components/Relations.olean" \
    -c "$out/SpaghettiExtractor/Components/Relations.c" \
    SpaghettiExtractor/Components/Relations.lean
  leanc -c \
    -o "$out/SpaghettiExtractor/Components/Relations.o" \
    "$out/SpaghettiExtractor/Components/Relations.c"
  cat > RelationKernelAudit.lean <<'EOF'
  import SpaghettiExtractor.Components.Relations
  #print axioms SpaghettiExtractor.Components.Relations.Reference.derive_preserves_origin
  #print axioms SpaghettiExtractor.Components.Relations.Reference.derive_is_bounded
  #print axioms SpaghettiExtractor.Components.Relations.Reference.offset_add_remaining
  #print axioms SpaghettiExtractor.Components.Relations.LiveOrigin.resolve_realize
  #print axioms SpaghettiExtractor.Components.Relations.LiveOrigin.generation_change_expires
  #print axioms SpaghettiExtractor.Components.Relations.LiveCapabilityAuthority.import_export
  #print axioms SpaghettiExtractor.Components.Relations.compose_lawful
  #print axioms SpaghettiExtractor.Components.Relations.baseOffset_observe_realize
  #print axioms SpaghettiExtractor.Components.Relations.baseOffset_realize_observe
  #print axioms SpaghettiExtractor.Components.Relations.checkBoundaryPlanCertificate_sound
  EOF
  lean --trust=0 RelationKernelAudit.lean > "$out/axiom-audit.txt"
  if grep -q 'sorryAx\|Classical.choice\|native_decide[.]ax' "$out/axiom-audit.txt"; then
    cat "$out/axiom-audit.txt" >&2
    exit 1
  fi
''
