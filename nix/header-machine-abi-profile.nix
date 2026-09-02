# spaghetti-extractor-python-role: authority
{
  pkgs,
  pythonEnv,
  id,
  providerDll,
  headers,
  functionPrefixes,
  abiDialect ? "pe32-i386-gnu-v1",
  sdkHeaders ? pkgs.pkgsCross.mingw32.windows.mingw_w64_headers,
  name ? "spaghetti-extractor-${id}-header-machine-abi-profile",
}:

let
  lib = pkgs.lib;
  includes = map (binding: binding.include) headers;
  headerInputNames = lib.imap0 (index: _: "header_${toString index}") headers;
  headerInputs = builtins.listToAttrs (lib.imap0 (index: binding: {
    name = builtins.elemAt headerInputNames index;
    value = binding.path;
  }) headers);
  translationSource = pkgs.writeText "${id}-header-machine-abi-translation.c" (
    lib.concatMapStringsSep "\n" (include: "#include <${include}>") includes
    + "\n"
  );
  phase = import ./ca-python-json-phase.nix {
    inherit pkgs pythonEnv name;
    kind = "header-machine-abi-profile";
    artifactName = "machine-import-profile.json";
    expectedFormat = "spaghetti-extractor-static-machine-import-profile-v2";
    allowedStatuses = [ "complete" ];
    pythonModules = [ "spaghetti_extractor.external.header_machine_abi" ];
    phaseRole = "authority";
    extraNativeBuildInputs = [ pkgs.llvmPackages.clang-unwrapped ];
    inputs = headerInputs // {
      translation_source = translationSource;
    };
    program = ''
      from spaghetti_extractor.external.header_machine_abi import (
          build_header_machine_abi_profile,
      )

      header_names = ${builtins.toJSON headerInputNames}
      header_paths = [inputs[name] for name in header_names]
      build_header_machine_abi_profile(
          clang=pathlib.Path(${builtins.toJSON "${pkgs.llvmPackages.clang-unwrapped}/bin/clang"}),
          translation_source=inputs["translation_source"],
          headers=header_paths,
          includes=${builtins.toJSON includes},
          include_directories=[
              pathlib.Path(${builtins.toJSON "${sdkHeaders}/include"}),
              *sorted({path.parent for path in header_paths}),
          ],
          function_prefixes=${builtins.toJSON functionPrefixes},
          profile_id=${builtins.toJSON id},
          provider_dll=${builtins.toJSON providerDll},
          out=output,
      )
    '';
  };
in
assert lib.assertMsg (builtins.isString id && id != "")
  "header machine ABI profile requires an ID";
assert lib.assertMsg (builtins.isString providerDll && providerDll != "")
  "header machine ABI profile requires a provider DLL";
assert lib.assertMsg (
  builtins.isList headers && headers != [ ]
  && builtins.all (
    binding:
    builtins.isAttrs binding
    && builtins.attrNames binding == [ "include" "path" ]
    && builtins.isString binding.include
  ) headers
) "header machine ABI profile requires exact include/path bindings";
assert lib.assertMsg (
  builtins.isList functionPrefixes && functionPrefixes != [ ]
  && builtins.all builtins.isString functionPrefixes
) "header machine ABI profile requires function prefixes";
assert lib.assertMsg (abiDialect == "pe32-i386-gnu-v1")
  "header machine ABI profile currently supports the PE32 GNU C ABI";
phase.derivation
