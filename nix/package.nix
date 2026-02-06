{
  lib,
  rustPlatform,
  versionSuffix ? ""
}:

rustPlatform.buildRustPackage {
  pname = "portail";
  version = "unstable${versionSuffix}";

  src = lib.sources.cleanSourceWith {
    # Do not keep the Rust target/ directory which is heavy.
    filter = path: type: type == "directory" -> !lib.hasPrefix path (toString ../target);
    src = lib.sources.cleanSource ../.;
  };
  cargoLock = {
    lockFile = ../Cargo.lock;
  };

  meta = {
    description = "An access proxy for terminals";
    homepage = "https://github.com/cloud-gouv/portail";
    license = lib.licenses.mit;
    maintainers = with lib.maintainers; [ raitobezarius ];
    mainProgram = "portail";
  };
}
