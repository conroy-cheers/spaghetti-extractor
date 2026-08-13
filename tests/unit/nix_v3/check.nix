{ pkgs }:
let
  evaluation = import ./evaluation.nix { inherit pkgs; };
in
assert evaluation.success;
assert builtins.length evaluation.transition_invalidated == 1;
assert builtins.length evaluation.transition_stable == 3;
assert builtins.length evaluation.scc_invalidated == 2;
assert builtins.length evaluation.scc_stable == 1;
assert builtins.length evaluation.composition_invalidated == 2;
assert builtins.length evaluation.composition_stable == 1;
import ./build.nix { inherit pkgs; }
