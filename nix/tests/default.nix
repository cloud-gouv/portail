{ pkgs, ... }:
let
  # Import nixpkgs snakeoil certs.
  mkVirtualHost = svcName: {
    extraConfig = ''
      location / {
        default_type application/json;
        return 200 '{"remote_addr":"$remote_addr","service": "${svcName}"}';
      }
    '';
  };
  mkServiceNode = {}: {
      networking.interfaces.eth1.ipv4.addresses = [
        {
          address = "192.168.1.200";
          prefixLength = 24;
        }
      ];

    services.nginx = {
      enable = true;
      virtualHosts."hello.corp.example.com" = mkVirtualHost "hello.corp";
      virtualHosts."bad.corp.example.com" = mkVirtualHost "bad.corp";
    };
    networking.firewall.allowedTCPPorts = [
      80
      443
    ];
  };
in
{
  exit-node = pkgs.testers.nixosTest {
    name = "exit-node";
    nodes = {
      corp-server = mkServiceNode { };
      node = { nodes, ... }: {
        imports = [ ../module.nix ];

        networking.hosts."${nodes.corp-server.networking.primaryIPAddress}" = [ "hello.corp.example.com" "bad.corp.example.com" ];

        networking.interfaces.eth1.ipv4.addresses = [
          {
            address = "192.168.1.100";
            prefixLength = 24;
          }
        ];
        services.portail = {
          enable = true;
          enableAtBoot = true;
          acl.filter.rules = [
            "hello.corp.example.com -> allow"
            ".* -> deny"
          ];
        };
      };
    };
    testScript = ''
      import json

      start_all()

      node.wait_for_unit("multi-user.target")
      node.wait_for_unit("portail.service")

      self_ip = "192.168.1.100"

      # Wait for the server to be ready.
      corp_server.wait_for_unit("multi-user.target")

      # Wait for NGINX to be ready.
      corp_server.wait_for_open_port(80)
      # corp_server.wait_for_open_port(443)

      # Wait for the SOCK5 server to be ready.
      node.wait_for_open_port(8080)

      # Let's test SOCKS5 to hello.corp.example.com.

      # This tests without DNS resolution.
      result = json.loads(node.succeed(
        "curl --fail --socks5 127.0.0.1:8080 http://hello.corp.example.com"
      ))
      assert result['service'] == 'hello.corp' and result['remote_addr'] == self_ip, "Unexpected result from the web service: {}".format(json.dumps(result))
      # This exercise the SOCKS5 DNS resolution.
      result = json.loads(node.succeed(
        "curl --fail --socks5-hostname 127.0.0.1:8080 http://hello.corp.example.com"
      ))
      assert result['service'] == 'hello.corp' and result['remote_addr'] == self_ip, "Unexpected result from the web service: {}".format(json.dumps(result))
      # TODO: Test HTTPS as well.

      # This exercises rejections and ACLs.
      # TODO: once ACLs are stabilized, uncomment.
      # This tests without DNS resolution.
      # node.fail(
      #  "curl --fail --socks5 127.0.0.1:8080 http://bad.corp.example.com"
      # )
      # This exercise the SOCKS5 DNS resolution.
      # node.fail(
      #  "curl --fail --socks5-hostname 127.0.0.1:8080 http://bad.corp.example.com"
      # )
    '';
  };

  # This tests Portail connecting to microsocks as an upstream.
  microsocks-upstream = pkgs.testers.nixosTest {
    name = "microsocks-upstream";
    nodes = {
      microsocks = { nodes, ... }: {
        networking.interfaces.eth1.ipv4.addresses = [
          {
            address = "192.168.1.50";
            prefixLength = 24;
          }
        ];

        services.microsocks = {
          enable = true;
          ip = "0.0.0.0";
          port = 8080;
        };

        networking.hosts."${nodes.corp-server.networking.primaryIPAddress}" = [ "hello.corp.example.com" "bad.corp.example.com" ];
        networking.firewall.allowedTCPPorts = [ 8080 ];
      };
      corp-server = mkServiceNode { };
      node = { nodes, ... }: { 
        imports = [ ../module.nix ];
        networking.hosts."${nodes.corp-server.networking.primaryIPAddress}" = [ "hello.corp.example.com" "bad.corp.example.com" ];
        networking.interfaces.eth1.ipv4.addresses = [
          {
            address = "192.168.1.100";
            prefixLength = 24;
          }
        ];
        services.portail = {
          enable = true;
          enableAtBoot = true;
          settings = {
            default-backend = "default";
            backends.default = {
              target-address = "192.168.1.50:8080";
            };
          };
          acl.filter.rules = [
            "hello.corp.example.com -> allow"
          ];
        };
      };
    };
    testScript = ''
      import json

      start_all()

      node.wait_for_unit("multi-user.target")
      node.wait_for_unit("portail.service")

      self_ip = "192.168.1.100"

      # Wait for the server to be ready.
      corp_server.wait_for_unit("multi-user.target")

      # Wait for NGINX to be ready.
      corp_server.wait_for_open_port(80)
      # corp_server.wait_for_open_port(443)

      # Wait for microsocks to be ready.
      microsocks.wait_for_unit("microsocks.service")
      microsocks.wait_for_open_port(8080)

      # Wait for the SOCK5 server to be ready.
      node.wait_for_open_port(8080)

      # Let's test SOCKS5 to hello.corp.example.com.

      # This tests without DNS resolution.
      result = json.loads(node.succeed(
        "curl --fail --socks5 127.0.0.1:8080 http://hello.corp.example.com"
      ))
      assert result['service'] == 'hello.corp' and result['remote_addr'] != self_ip, "Unexpected result from the web service: {}".format(json.dumps(result))
      # This exercise the SOCKS5 DNS resolution.
      result = json.loads(node.succeed(
        "curl --fail --socks5-hostname 127.0.0.1:8080 http://hello.corp.example.com"
      ))
      assert result['service'] == 'hello.corp' and result['remote_addr'] != self_ip, "Unexpected result from the web service: {}".format(json.dumps(result))
    '';
  };

}
