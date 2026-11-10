{ sources ? import ./nix/npins,
  pkgs ? import sources.nixpkgs {
    overlays = [ (import ./nix/overlay.nix) ];
} }:
(import ./. { inherit pkgs; }).shells.development
