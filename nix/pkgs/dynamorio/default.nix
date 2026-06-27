{
  lib,
  stdenv,
  fetchFromGitHub,
  cmake,
  coreutils,
  ninja,
  makeWrapper,
  perl,
  python3,
  zlib,
  libunwind,
}:

stdenv.mkDerivation rec {
  pname = "dynamorio";
  version = "11.91.20630";

  src = fetchFromGitHub {
    owner = "DynamoRIO";
    repo = "dynamorio";
    rev = "063342093dd1e5e6820a18c5d1cab1b39ca90809";
    hash = "sha256-0O8LvJAQAI7Fqz5F91yR4Q7w7MGdd6PqfIrN/zNu74c=";
    fetchSubmodules = true;
  };

  nativeBuildInputs = [
    cmake
    ninja
    makeWrapper
    perl
    python3
  ];

  buildInputs = [
    libunwind
    zlib
  ];

  postPatch = ''
    substituteInPlace CMakeLists.txt \
      --replace-fail \
        'if (EXISTS "''${PROJECT_SOURCE_DIR}/third_party/libipt/.git" )' \
        'if (EXISTS "''${PROJECT_SOURCE_DIR}/third_party/libipt/CMakeLists.txt" )'
  '';

  cmakeFlags = [
    "-DVERSION_NUMBER=${version}"
    "-DBUILD_NUMBER=0"
    "-DBUILD_DOCS=OFF"
    "-DBUILD_TESTS=OFF"
  ];

  dontMoveLib64 = true;

  enableParallelBuilding = true;

  postInstall = ''
    mkdir -p "$out/bin"

    for tool in drrun drconfig drdeploy drinject; do
      makeWrapper "$out/bin64/$tool" "$out/bin/$tool" \
        --set DYNAMORIO_HOME "$out"
    done

    ln -s "$out/bin/drrun" "$out/bin/dynamorio"
  '';

  doInstallCheck = true;
  installCheckPhase = ''
    runHook preInstallCheck

    "$out/bin/drrun" -version | grep -F "drrun version ${version}"
    logdir="$(mktemp -d)"
    "$out/bin/drrun" -64 -quiet -t drcov -dump_text -logdir "$logdir" -- "${coreutils}/bin/true"

    runHook postInstallCheck
  '';

  meta = {
    description = "Dynamic instrumentation runtime for analysis, instrumentation, and optimization";
    homepage = "https://dynamorio.org/";
    license = lib.licenses.bsd3;
    mainProgram = "drrun";
    platforms = [ "x86_64-linux" ];
  };
}
