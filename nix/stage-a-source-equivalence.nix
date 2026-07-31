{
  pkgs,
  sourceProject,
  profileTemplate ? ../profiles/i686-mingw-freestanding-c0-v1.json,
  name ? "stage-a-source-equivalence",
  contentAddressed ? true,
}:

let
  mingw32 = pkgs.pkgsCross.mingw32;
  cc = mingw32.stdenv.cc;
  binutils = cc.bintools;
  ca = {
    preferLocalBuild = false;
    allowSubstitutes = true;
    __contentAddressed = contentAddressed;
  };

  toolchainProfile = pkgs.runCommand "${name}-toolchain-profile" (
    ca // { nativeBuildInputs = [ pkgs.coreutils ]; }
  ) ''
    mkdir -p "$out"
    compiler=${cc}/bin/i686-w64-mingw32-gcc
    assembler=${binutils}/bin/i686-w64-mingw32-as
    linker=${binutils}/bin/i686-w64-mingw32-ld
    test -x "$compiler"
    test -x "$assembler"
    test -x "$linker"
    substitute ${profileTemplate} "$out/profile.json" \
      --replace-fail '@CC@' '${cc}' \
      --replace-fail '@BINUTILS@' '${binutils}' \
      --replace-fail '@CC_SHA256@' "$(sha256sum "$compiler" | cut -d ' ' -f 1)" \
      --replace-fail '@AS_SHA256@' "$(sha256sum "$assembler" | cut -d ' ' -f 1)" \
      --replace-fail '@LD_SHA256@' "$(sha256sum "$linker" | cut -d ' ' -f 1)" \
      --replace-fail '@RUNTIME_SHA256@' \
        "$(sha256sum ${sourceProject}/spaghetti-c0-runtime-v1.c | cut -d ' ' -f 1)"
  '';

  candidate = pkgs.runCommand "${name}-candidate-pe32" (
    ca // { nativeBuildInputs = [ cc ]; }
  ) ''
    mkdir -p "$out/bin"
    i686-w64-mingw32-gcc \
      -std=c11 -O0 -ffreestanding -fno-builtin \
      -fno-asynchronous-unwind-tables -nostdlib \
      -Wl,--entry,_mainCRTStartup \
      -Wl,--subsystem,console \
      -Wl,--no-insert-timestamp \
      -I${sourceProject} \
      ${sourceProject}/c0-program.c \
      ${sourceProject}/spaghetti-c0-runtime-v1.c \
      -o "$out/bin/candidate.exe"
  '';

in
{
  inherit candidate toolchainProfile;
}
