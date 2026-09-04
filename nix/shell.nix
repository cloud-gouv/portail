{ pkgs ? import <nixpkgs> {
  overlays = [ (import ./overlay.nix) ];
} }:

pkgs.mkShell {
  packages = with pkgs; [
    cargo
    rustc
    rustfmt
    clippy
    cargo-update
    xtr
  ];
}
