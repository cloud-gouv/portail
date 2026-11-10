{ pkgs }: {
  inherit pkgs;

  package = pkgs.portail;
  tests = import ./tests { inherit pkgs; };

  shells = {
    ci = import ./ci-shell.nix { inherit pkgs; };
    development = import ./shell.nix { inherit pkgs; };
  };
}
