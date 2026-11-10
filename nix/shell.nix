{ pkgs }:

pkgs.mkShell {
  packages = with pkgs; [
    cargo
    rustc
    rustfmt
    clippy
    cargo-update
    mdbook
    xtr
  ];
}
