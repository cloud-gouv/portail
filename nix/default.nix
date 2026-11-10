{ pkgs }: {
  inherit pkgs;

  package = pkgs.portail;
  tests = import ./tests { inherit pkgs; };

  shells = {
    development = import ./shell.nix { inherit pkgs; };
  };
}
