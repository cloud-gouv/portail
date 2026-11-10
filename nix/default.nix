{ pkgs }: {
  inherit pkgs;
  package = pkgs.portail;
  shell = import ./shell.nix { inherit pkgs; };
  tests = import ./tests { inherit pkgs; };
}
