{ pkgs ? import <nixpkgs> {
  overlays = [ (import ./overlay.nix) ];
} }: {
  inherit pkgs;
  package = pkgs.portail;
  shell = import ./shell.nix { inherit pkgs; };
  tests = import ./tests { inherit pkgs; };
}
