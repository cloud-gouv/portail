let
  pkgs = import <nixpkgs> { overlays = [ (import ./overlay.nix) ]; };
  entrypoint = import ./. { inherit pkgs; };
in
  {
    packages = pkgs.lib.recurseIntoAttrs {
      portail = entrypoint.package;
    };

    checks = pkgs.lib.recurseIntoAttrs {
      integration = pkgs.lib.recurseIntoAttrs entrypoint.tests;
    };
  }
