{
  description = "Halo CE decompilation development environment";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";
    flake-parts.url = "github:hercules-ci/flake-parts";
  };

  outputs =
    inputs@{
      flake-parts,
      nixpkgs,
      ...
    }:
    let
      systems = [ "x86_64-linux" ];

      overlays.default = import ./nix/overlays;
    in
    flake-parts.lib.mkFlake { inherit inputs; } {
      inherit systems;

      flake.overlays = overlays;

      perSystem =
        { system, ... }:
        let
          pkgs = import nixpkgs {
            inherit system;
            overlays = [ overlays.default ];
          };

          python = pkgs.python3.withPackages (
            ps: with ps; [
              capstone
              keystone-engine
              lief
              pefile
              unicorn
            ]
          );
        in
        {
          _module.args.pkgs = pkgs;

          packages = {
            inherit (pkgs) dynamorio;
            default = pkgs.dynamorio;
          };

          devShells.default = pkgs.mkShell {
            packages = [
              pkgs.binutils
              pkgs.llvm
              python
              pkgs.dynamorio
              pkgs.frida-tools
              pkgs.qemu
              pkgs.radare2
              pkgs.rizin
              pkgs.jq
              pkgs.sqlite
            ];

            shellHook = ''
              export DYNAMORIO_HOME=${pkgs.dynamorio}
            '';
          };
        };
    };
}
