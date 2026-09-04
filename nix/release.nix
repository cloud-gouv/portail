let
  pkgs = import <nixpkgs> { overlays = [ (import ./overlay.nix) ]; };
  entrypoint = import ./. { inherit pkgs; };
in
  {
    packages = pkgs.lib.recurseIntoAttrs {
      portail = entrypoint.package;
      xtr = pkgs.xtr;
    };

    checks = pkgs.lib.recurseIntoAttrs {
      integration = pkgs.lib.recurseIntoAttrs entrypoint.tests;
      devShell = entrypoint.shell;
    };
  }
