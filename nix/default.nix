{ pkgs }:
let
  inherit (pkgs)
    lib
    portail
    xtr
  ;

  attrs = {
    package = portail;
    tests = import ./tests { inherit pkgs; };

    shells = {
      ci = import ./ci-shell.nix { inherit pkgs; };
      development = import ./shell.nix { inherit pkgs; };
    };
  };

  withRelease = let
    releaseFrom = attrs: {
      packages = lib.recurseIntoAttrs {
        portail = attrs.package;
        xtr = xtr;
      };

      checks = lib.recurseIntoAttrs {
        integration = lib.recurseIntoAttrs attrs.tests;
        devShell = attrs.shells.development;
      };
    };
  in
    attrs: attrs // { release = (releaseFrom attrs); };
in
  withRelease attrs
