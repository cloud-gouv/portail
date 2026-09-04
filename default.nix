{ pkgs ? import <nixpkgs> {
  overlays = [ (import ./nix/overlay.nix) ];
} }:
import ./nix { inherit pkgs; }
