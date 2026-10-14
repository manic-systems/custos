{
  mkShell,
  pkg-config,
  rustc,
  clippy,
  rust-analyzer-unwrapped,
  tombi,
  rustPlatform,
  cargo,
  rustfmt,
  dbus,
}:
mkShell {
  packages = [
    pkg-config
    clippy
    rustc
    rust-analyzer-unwrapped
    (rustfmt.override { asNightly = true; })
    tombi
    cargo
  ];
  buildInputs = [ dbus ];
  env.RUST_SRC_PATH = rustPlatform.rustLibSrc;
}
