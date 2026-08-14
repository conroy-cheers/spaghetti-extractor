{
  description = "Spaghetti Extractor static PE32 reconstruction and source-lifting toolkit";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";
    flake-parts.url = "github:hercules-ci/flake-parts";
  };

  outputs = inputs@{ flake-parts, ... }:
    flake-parts.lib.mkFlake { inherit inputs; } {
      systems = [ "x86_64-linux" ];
      imports = [
        ./nix/flake-modules/toolkit.nix
        ./nix/flake-modules/checks.nix
      ];

      flake.lib = {
        mkTargetSdkV2 = import ./nix/target-sdk-v2.nix;
      };
    };
}
