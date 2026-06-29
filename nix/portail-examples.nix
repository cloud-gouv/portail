{
  lib,
  rustPlatform,
}:

rustPlatform.buildRustPackage {
  pname = "portail-examples";
  version = "unstable";

  src = lib.sources.cleanSourceWith {
    filter = path: type: type == "directory" -> !lib.hasPrefix path (toString ../target);
    src = lib.sources.cleanSource ../.;
  };
  cargoLock = {
    lockFile = ../Cargo.lock;
  };

  cargoBuildFlags = [
    "--example"
    "h2_proxy_multiplex"
    "--example"
    "socks5_udp"
  ];

  doCheck = false;

  # Override https://github.com/NixOS/nixpkgs/blob/master/pkgs/build-support/rust/hooks/cargo-install-hook.sh
  # which does not install examples
  installPhase = ''
    runHook preInstall
    mkdir -p "$out/bin"
    for example in h2_proxy_multiplex socks5_udp; do
      binary=$(find target -path "*/release/examples/$example" -type f -print -quit)
      if [ -z "$binary" ]; then
        echo "$example not found under target/" >&2
        find target -type f || true
        exit 1
      fi
      install -Dm755 "$binary" "$out/bin/$(echo "$example" | tr '_' '-')"
    done
    runHook postInstall
  '';

  meta = {
    description = "Portail examples for E2E tests";
    homepage = "https://github.com/cloud-gouv/portail";
    license = lib.licenses.mit;
    maintainers = with lib.maintainers; [ raitobezarius ];
    mainProgram = "h2-proxy-multiplex";
  };
}
