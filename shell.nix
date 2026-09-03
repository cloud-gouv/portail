{ pkgs ? import <nixpkgs> {
  overlays = [ (import ./nix/overlay.nix) ];
} }:
import ./nix/shell.nix { inherit pkgs; }
