{ pkgs ? import <nixpkgs> {
  overlays = [ (import ./overlay.nix) ];
} }: {
  package = pkgs.portail;
  tests = import ./tests { inherit pkgs; };
}
