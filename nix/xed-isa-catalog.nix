{
  lib,
  stdenv,
  xed,
  xedCatalogSrc,
}:

let
  generatorVersion = "1";
  profile = {
    id = "pe32-i686-v1";
    chip = "PENTIUMPRO";
    machineMode = "LEGACY_32";
    stackAddressWidth = 32;
    privilege = "ring3";
  };
in
stdenv.mkDerivation {
  pname = "xed-isa-catalog";
  version = generatorVersion;

  src = lib.cleanSource xedCatalogSrc;
  strictDeps = true;
  dontConfigure = true;

  buildPhase = ''
    runHook preBuild

    $CC \
      -std=c11 \
      -O2 \
      -Wall \
      -Wextra \
      -Werror \
      -I${xed}/include \
      main.c \
      ${xed}/lib/libxed.a \
      -o xed-isa-catalog

    runHook postBuild
  '';

  installPhase = ''
    runHook preInstall

    install -D -m 0755 xed-isa-catalog "$out/bin/xed-isa-catalog"

    runHook postInstall
  '';

  doInstallCheck = true;
  installCheckPhase = ''
    runHook preInstallCheck

    "$out/bin/xed-isa-catalog" > first.json
    "$out/bin/xed-isa-catalog" > second.json
    cmp first.json second.json
    grep -F '"format":"spaghetti-extractor-xed-inst-catalog-v1"' first.json >/dev/null
    grep -F '"generator":{"name":"xed-isa-catalog","xed_version":"' first.json >/dev/null
    grep -F '"profile":{"id":"pe32-i686-v1","chip":"PENTIUMPRO","machine_mode":"LEGACY_32","stack_address_width":32,"privilege":"ring3"}' first.json >/dev/null
    grep -F '"templates":[{' first.json >/dev/null

    runHook postInstallCheck
  '';

  passthru = {
    inherit generatorVersion profile;
    upstreamXed = xed;
  };

  meta = {
    description = "Deterministic raw Intel XED catalog for the PE32 i686 profile";
    license = lib.licenses.asl20;
    mainProgram = "xed-isa-catalog";
    platforms = lib.platforms.linux;
  };
}
