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
              pytest
              unicorn
            ]
          );

          haloce-tools = pkgs.python3Packages.buildPythonApplication {
            pname = "haloce-decomp-tools";
            version = "0.1.0";
            src = ./.;
            pyproject = true;

            build-system = with pkgs.python3Packages; [
              setuptools
            ];

            dependencies = with pkgs.python3Packages; [
              capstone
              lief
              pefile
              unicorn
            ];

            nativeCheckInputs = with pkgs.python3Packages; [
              pytestCheckHook
            ];

            pythonImportsCheck = [ "haloce_catalog" ];

            preCheck = ''
              export PYTHONPATH="$PWD/src:$PYTHONPATH"
            '';
          };
        in
        {
          _module.args.pkgs = pkgs;

          packages = {
            inherit haloce-tools;
            inherit (pkgs) dynamorio;
            default = haloce-tools;
          };

          apps = {
            default = {
              type = "app";
              program = "${haloce-tools}/bin/haloce-catalog";
            };

            haloce-catalog = {
              type = "app";
              program = "${haloce-tools}/bin/haloce-catalog";
            };
          };

          checks = {
            inherit haloce-tools;
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
              export PYTHONPATH="$PWD/src''${PYTHONPATH:+:$PYTHONPATH}"
            '';
          };
        };
    };
}
