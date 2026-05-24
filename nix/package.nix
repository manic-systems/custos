{
  lib,
  rustPlatform,
}:

rustPlatform.buildRustPackage {
  pname = "custos";
  version = "0.1.0";

  src = lib.fileset.toSource {
    root = ../.;
    fileset = lib.fileset.unions [
      ../Cargo.lock
      ../Cargo.toml
      ../src
    ];
  };

  cargoLock.lockFile = ../Cargo.lock;

  meta = {
    description = "Sleek and simple USB authorization daemon";
    license = lib.licenses.agpl3Plus;
    mainProgram = "custos";
    platforms = lib.platforms.linux;
  };
}
