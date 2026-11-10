{ pkgs ? import <nixpkgs> {
  overlays = [ (import ./nix/overlay.nix) ];
} }:
(import ./. { inherit pkgs; }).shell
