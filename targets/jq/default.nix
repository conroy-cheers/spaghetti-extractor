{
  pkgs,
  pythonEnv,
  pythonSource,
  componentProposals ? null,
}:

{
  intent = import ../../nix/stage-b-target-intent.nix {
    inherit pkgs pythonEnv pythonSource componentProposals;
    target = ./.;
  };
}
