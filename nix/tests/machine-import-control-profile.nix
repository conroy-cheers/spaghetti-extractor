{
  pkgs,
  pythonEnv,
  pythonSource,
}:

let
  profile = name: entries: pkgs.writeText "${name}.json" (builtins.toJSON {
    format = "stage-a-static-machine-import-profile-v1";
    id = name;
    default_callback_effect = "none";
    machine_import_signatures = entries;
  });
  terminating = {
    id = "exit";
    import = { dll = "fixture.dll"; symbol = "Exit"; };
    abi_template = "pe32-stdcall-v1";
    argument_words = 1;
    disposition = "terminates";
  };
  returning = {
    id = "ordinary";
    import = { dll = "fixture.dll"; symbol = "Ordinary"; };
    abi_template = "pe32-stdcall-v1";
    argument_words = 2;
    disposition = "returns";
  };
  baseProfile = profile "control-profile-base" [ terminating ];
  extendedProfile = profile "control-profile-extended" [ returning terminating ];
  mkProjection = profiles: import ../machine-import-control-profile.nix {
    inherit pkgs pythonEnv pythonSource profiles;
    name = "spaghetti-extractor-control-profile-invalidation-fixture";
  };
  baseProjection = mkProjection [ baseProfile ];
  extendedProjection = mkProjection [ extendedProfile ];
  mkConsumer = projection: pkgs.runCommand
    "spaghetti-extractor-control-profile-consumer-fixture"
    { __contentAddressed = true; }
    ''
      mkdir -p "$out"
      cp ${projection}/control-dispositions.json "$out/control-dispositions.json"
    '';
  baseConsumer = mkConsumer baseProjection;
  extendedConsumer = mkConsumer extendedProjection;
in
pkgs.runCommand "spaghetti-extractor-control-profile-invalidation-check" {
  nativeBuildInputs = [ pkgs.jq ];
} ''
  test ${baseProjection} = ${extendedProjection}
  test ${baseConsumer} = ${extendedConsumer}
  cmp \
    ${baseProjection}/control-dispositions.json \
    ${extendedProjection}/control-dispositions.json
  jq -e '
    (.machine_import_signatures | length) == 1 and
    .machine_import_signatures[0].import.symbol == "Exit"
  ' ${baseProjection}/control-dispositions.json >/dev/null
  touch "$out"
''
