{ pkgs ? import <nixpkgs> {
  overlays = [ (import ./overlay.nix) ];
} }: {
  tests = import ./tests { inherit pkgs; };
}
