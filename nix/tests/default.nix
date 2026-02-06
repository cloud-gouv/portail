{ pkgs, ... }:
{
  daemon = pkgs.testers.nixosTest {
    name = "daemon";
    nodes = {
      node = {
        imports = [ ../module.nix ];
        services.portail = {
          enable = true;
          enableAtBoot = true;
        };
      };
    };
    testScript = ''
      node.wait_for_unit("multi-user.target")
      node.wait_for_unit("portail.service")
    '';
  };
}
