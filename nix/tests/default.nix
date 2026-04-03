{ pkgs, ... }:
let
  certs = import ./certs/snakeoil-certs.nix;
  portailDomain = certs.proxyCerts.proxyDomain;
  helloDomain = certs.workloadCerts.workloadDomain;

  mkVirtualHost = svcName: {
    extraConfig = ''
      location / {
        default_type application/json;
        return 200 '{"remote_addr":"$remote_addr","service": "${svcName}","tls":false,"protocol":"$server_protocol"}';
      }
    '';
  };

  mkVirtualHostWithTLS = svcName: certs: {
    sslCertificate = certs.cert;
    sslCertificateKey = certs.key;
    addSSL = true;

    extraConfig = ''
      location / {
        default_type application/json;
        set $tls_flag false;
        if ($ssl_protocol) {
          set $tls_flag true;
        }
        return 200 '{"remote_addr":"$remote_addr","service":"${svcName}","tls":$tls_flag,"protocol":"$server_protocol"}';
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
      virtualHosts."${helloDomain}" = mkVirtualHostWithTLS "hello.corp" certs.workloadCerts.${helloDomain};
      virtualHosts."bad.corp.example.com" = mkVirtualHost "bad.corp";
    };
    networking.firewall.allowedTCPPorts = [
      80
      443
    ];
  };

  mkPortailNode = { address, allowedHostsRegex ? "hello.corp.example.com" }: { nodes, ... }: {
    imports = [ ../module.nix portailEnv ];

    networking.interfaces.eth1.ipv4.addresses = [
      {
        inherit address;
        prefixLength = 24;
      }
    ];

    networking.hosts."${nodes.corp-server.networking.primaryIPAddress}" =
      [ "hello.corp.example.com" "bad.corp.example.com" ];

    networking.firewall.allowedTCPPorts = [ 8080 ];

    services.portail = {
      enable = true;
      enableAtBoot = true;
      proxyListenStream = "0.0.0.0:8080";
      acl.filter.rules = [
        ''
          policy hello {
            when host =~ "${allowedHostsRegex}"
            action allow
          }
        ''
      ];
    };
  };

  mkMicrosocksNode = { address }: { nodes, ... }: {
    networking.interfaces.eth1.ipv4.addresses = [
      {
        inherit address;
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

  mkTinyproxyNode = { address }: { nodes, ... }: {
    networking.interfaces.eth1.ipv4.addresses = [
      {
        inherit address;
        prefixLength = 24;
      }
    ];

    networking.hosts."${nodes.corp-server.networking.primaryIPAddress}" =
      [ "hello.corp.example.com" "bad.corp.example.com" ];

    services.tinyproxy = {
      enable = true;
      settings = {
        Port = 8080;
        Listen = "0.0.0.0";
        Allow = [ "192.168.1.0/24" ];
        ConnectPort = [ 80 443 ];
      };
    };

    networking.firewall.allowedTCPPorts = [ 8080 ];
  };

  portailEnv = {
    systemd.services.portail.environment = {
      RUST_LOG = "portail=debug";
    };
  };
in
{
  exit-node = pkgs.testers.nixosTest {
    name = "exit-node";
    nodes = {
      corp-server = mkServiceNode { };
      node = { nodes, ... }: {
        imports = [ ../module.nix portailEnv ];

        networking.hosts."${nodes.corp-server.networking.primaryIPAddress}" = [ "hello.corp.example.com" "bad.corp.example.com" ];
        networking.hosts."192.168.1.100" = [ portailDomain ];

        networking.interfaces.eth1.ipv4.addresses = [
          {
            address = "192.168.1.100";
            prefixLength = 24;
          }
        ];

        networking.firewall.allowedTCPPorts = [ 8080 ];

        security.pki.certificates = [
          # Trust the proxy TLS
          (builtins.readFile certs.proxyCerts.ca.cert)
          # Trust the workload TLS
          (builtins.readFile certs.workloadCerts.ca.cert)
        ];
        services.portail = {
          enable = true;
          enableAtBoot = true;
          proxyListenStream = "0.0.0.0:8080";
          settings.listener = {
            tls-privkey = certs.proxyCerts.${portailDomain}.key;
            # NOTE: we already possess part of the chain in the local trust store.
            tls-chain = certs.proxyCerts.${portailDomain}.cert;
          };
          acl.filter.rules = [
            # DNS resolution takes place now here.
            ''
              policy hello {
                when host =~ "192.168.1.1|hello.corp.example.com"
                action allow
              }
            ''
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
      corp_server.wait_for_open_port(443)

      # Wait for the SOCK5 server to be ready.
      node.wait_for_open_port(8080)

      # Let's test SOCKS5 to hello.corp.example.com.

      # This tests without DNS resolution.
      result = json.loads(node.succeed(
        "curl --fail --socks5 127.0.0.1:8080 http://hello.corp.example.com"
      ))
      assert (
        result['service'] == 'hello.corp'
        and result['remote_addr'] == self_ip
        and result['protocol'] == 'HTTP/1.1'
      ), "Unexpected result from the web service: {}".format(json.dumps(result))

      # This exercise the SOCKS5 DNS resolution.
      result = json.loads(node.succeed(
        "curl --fail --socks5-hostname 127.0.0.1:8080 http://hello.corp.example.com"
      ))
      assert (
        result['service'] == 'hello.corp'
        and result['remote_addr'] == self_ip
        and result['protocol'] == 'HTTP/1.1'
      ), "Unexpected result from the web service: {}".format(json.dumps(result))

      # TODO: test downstream TLS via SOCKS5.

      # Test HTTP CONNECT
      # --proxytunnel will force HTTP CONNECT
      result = json.loads(node.succeed(
        "curl --fail --proxytunnel --proxy http://127.0.0.1:8080 http://hello.corp.example.com"
      ))
      assert (
        result['service'] == 'hello.corp'
        and result['remote_addr'] == self_ip
        and not result['tls']
        and result['protocol'] == 'HTTP/1.1'
      ), "Unexpected result from the web service: {}".format(json.dumps(result))

      # No --proxytunnel since curl uses CONNECT by default for HTTPS
      result = json.loads(node.succeed(
        "curl --fail --proxy http://127.0.0.1:8080 https://hello.corp.example.com"
      ))
      assert (
        result['service'] == 'hello.corp'
        and result['remote_addr'] == self_ip
        and result['tls']
        and result['protocol'] == 'HTTP/2.0'
      ), "Unexpected result from the web service: {}".format(json.dumps(result))

      # Test HTTPS CONNECT
      # --proxytunnel will force HTTPS CONNECT
      result = json.loads(node.succeed(
        "curl --fail --proxytunnel --proxy https://${portailDomain}:8080 http://hello.corp.example.com"
      ))
      assert (
        result['service'] == 'hello.corp'
        and result['remote_addr'] == self_ip
        and not result['tls']
        and result['protocol'] == 'HTTP/1.1'
      ), "Unexpected result from the web service: {}".format(json.dumps(result))

      # FIXME: TLS over TLS is not cleaning up properly the tunnel.
      # node # [   15.560560] portail[623]: 2026-03-05T00:43:56.909060Z ERROR portail::proxy::http_connect: CONNECT tunnel error: peer closed connection without sending TLS close_notify: https://docs.rs/rustls/latest/rustls/manual/_03_howto/index.html#unexpected-eof
      # The curl succeeds but the next assertion fails.
      result = json.loads(node.succeed(
        "curl --fail --proxy https://${portailDomain}:8080 https://hello.corp.example.com"
      ))
      assert (
        result['service'] == 'hello.corp'
        and result['remote_addr'] == self_ip
        and result['tls']
        and result['protocol'] == 'HTTP/2.0'
      ), "Unexpected result from the web service: {}".format(json.dumps(result))

      # Test HTTP2 CONNECT
      # --proxy-http2 will force HTTP2 CONNECT
      result = json.loads(node.succeed(
        "curl --fail --proxy-http2 --proxy https://${portailDomain}:8080 https://hello.corp.example.com"
      ))
      assert (
        result['service'] == 'hello.corp'
        and result['remote_addr'] == self_ip
        and result['tls']
        and result['protocol'] == 'HTTP/2.0'
      ), "Unexpected result from the web service: {}".format(json.dumps(result))

      # Test HTTP2 CONNECT multiplexing
      # For curl to multiplex requests, we have to:
      # - add --parallel
      # - add multiple requests with the same domain
      node.succeed(
        "curl --fail --trace-ascii /tmp/multiplex-trace --proxy-http2 --parallel --proxy https://${portailDomain}:8080 -o /tmp/multiplex-out1 -o /tmp/multiplex-out2 https://hello.corp.example.com https://hello.corp.example.com"
      )
      for i in ["1", "2"]:
        result = json.loads(node.succeed("cat /tmp/multiplex-out" + i))
        assert (
          result['service'] == 'hello.corp'
          and result['remote_addr'] == self_ip
          and result['tls']
          and result['protocol'] == 'HTTP/2.0'
        ), "Unexpected result from multiplexed request {}: {}".format(i, json.dumps(result))
      curl_trace = node.succeed("cat /tmp/multiplex-trace")
      assert "Multiplexed connection found" in curl_trace, "Expected 'Multiplexed connection found', got: " + curl_trace
      # Note: this string might change between curl versions
      assert "Reusing existing https: connection with proxy portail.corp.example.com" in curl_trace, "Expected 'Reusing existing https: connection with proxy portail.corp.example.com', got: " + curl_trace


      # This exercises rejections and ACLs.
      # This exercise the SOCKS5 DNS resolution otherwise 192.168.1.1 is allowed.
      node.fail(
       "curl --fail --socks5-hostname 127.0.0.1:8080 http://bad.corp.example.com"
      )
    '';
  };

  # This tests Portail connecting to microsocks as an upstream.
  microsocks-upstream = pkgs.testers.nixosTest {
    name = "microsocks-upstream";
    nodes = {
      microsocks = mkMicrosocksNode { address = "192.168.1.50"; };

      corp-server = mkServiceNode { };
      node = { nodes, ... }: { 
        imports = [ ../module.nix portailEnv ];
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
            ''
              policy hello {
                when host =~ "hello.corp.example.com|192.168.1.1" and port == 80
                action allow
              }
            ''
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
      assert (
        result['service'] == 'hello.corp'
        and result['remote_addr'] != self_ip
        and result['protocol'] == 'HTTP/1.1'
      ), "Unexpected result from the web service: {}".format(json.dumps(result))
      # This exercise the SOCKS5 DNS resolution.
      result = json.loads(node.succeed(
        "curl --fail --socks5-hostname 127.0.0.1:8080 http://hello.corp.example.com"
      ))
      assert (
        result['service'] == 'hello.corp'
        and result['remote_addr'] != self_ip
        and result['protocol'] == 'HTTP/1.1'
      ), "Unexpected result from the web service: {}".format(json.dumps(result))
    '';
  };

  # This tests Portail connecting to tinyproxy as an upstream (uses HTTP CONNECT).
  tinyproxy-upstream =
    let
      upstreamIp = "192.168.1.51";
    in
    pkgs.testers.nixosTest {
      name = "tinyproxy-upstream";
      nodes = {
        tinyproxy = mkTinyproxyNode { address = upstreamIp; };

        corp-server = mkServiceNode { };
        node = { nodes, ... }: {
          imports = [ ../module.nix portailEnv ];
          networking.hosts."${nodes.corp-server.networking.primaryIPAddress}" =
            [ "hello.corp.example.com" "bad.corp.example.com" ];
          networking.interfaces.eth1.ipv4.addresses = [
            {
              address = "192.168.1.100";
              prefixLength = 24;
            }
          ];
          security.pki.certificates = [
            (builtins.readFile certs.workloadCerts.ca.cert)
          ];
          services.portail = {
            enable = true;
            enableAtBoot = true;
            settings = {
              default-backend = "default";
              backends.default = {
                target-address = "${upstreamIp}:8080";
              };
            };
            acl.filter.rules = [
              ''
                policy hello {
                  when host =~ "hello.corp.example.com|192.168.1.1" and (port == 80 or port == 443)
                  action allow
                }
              ''
            ];
          };
        };
      };
      testScript = ''
        import json

        start_all()

        node.wait_for_unit("multi-user.target")
        node.wait_for_unit("portail.service")

        upstream_ip = "${upstreamIp}"

        # Wait for the server to be ready.
        corp_server.wait_for_unit("multi-user.target")

        # Wait for NGINX to be ready.
        corp_server.wait_for_open_port(80)
        corp_server.wait_for_open_port(443)

        # Wait for tinyproxy to be ready.
        tinyproxy.wait_for_unit("tinyproxy.service")
        tinyproxy.wait_for_open_port(8080)

        # Wait for portail to open its port.
        node.wait_for_open_port(8080)

        # HTTP CONNECT: client -> portail -> tinyproxy -> corp-server
        result = json.loads(node.succeed(
          "curl --fail --proxytunnel --proxy http://127.0.0.1:8080 http://hello.corp.example.com"
        ))
        assert (
          result['service'] == 'hello.corp'
          and result['remote_addr'] == upstream_ip
          and not result['tls']
          and result['protocol'] == 'HTTP/1.1'
        ), "Unexpected result from the web service: {}".format(json.dumps(result))

        # HTTPS via CONNECT through tinyproxy
        result = json.loads(node.succeed(
          "curl --fail --proxy http://127.0.0.1:8080 https://hello.corp.example.com"
        ))
        assert (
          result['service'] == 'hello.corp'
          and result['remote_addr'] == upstream_ip
          and result['tls']
          and result['protocol'] == 'HTTP/2.0'
        ), "Unexpected result from the web service: {}".format(json.dumps(result))
      '';
    };

  # curl -> portail -> portail (hop) -> corp-server
  portail-upstream = pkgs.testers.nixosTest {
    name = "portail-upstream";
    nodes = {
      corp-server = mkServiceNode { };

      portail-hop = mkPortailNode { address = "192.168.1.60"; };

      node = { nodes, ... }: {
        imports = [ ../module.nix portailEnv ];

        networking.interfaces.eth1.ipv4.addresses = [
          {
            address = "192.168.1.100";
            prefixLength = 24;
          }
        ];

        networking.hosts."${nodes.corp-server.networking.primaryIPAddress}" =
          [ "hello.corp.example.com" "bad.corp.example.com" ];

        services.portail = {
          enable = true;
          enableAtBoot = true;

          settings = {
            default-backend = "default";
            backends.default = {
              # portail -> portail (hop)
              target-address =
                "${nodes.portail-hop.networking.primaryIPAddress}:8080";
            };
          };

          acl.filter.rules = [
            ''
              policy hello {
                when host == "hello.corp.example.com"
                action allow
              }
            ''
          ];
        };
      };
    };

    testScript = ''
      import json

      start_all()

      node.wait_for_unit("multi-user.target")
      node.wait_for_unit("portail.service")

      portail_hop.wait_for_unit("multi-user.target")
      portail_hop.wait_for_unit("portail.service")

      corp_server.wait_for_unit("multi-user.target")
      corp_server.wait_for_open_port(80)

      node.wait_for_open_port(8080)
      portail_hop.wait_for_open_port(8080)

      self_ip = "192.168.1.100"

      # Test HTTP CONNECT curl -> portail -> portail (hop) -> corp-server
      result = json.loads(node.succeed(
        "curl --fail --proxytunnel --proxy http://127.0.0.1:8080 http://hello.corp.example.com"
      ))

      assert (
        result['service'] == 'hello.corp'
        and result['remote_addr'] != self_ip
        and result['protocol'] == 'HTTP/1.1'
      ), "Unexpected result from the web service: {}".format(json.dumps(result))
    '';
  };

  # curl -> portail -(TLS)-> portail (hop) -> corp-server
  #
  # Block any direct TCP from first portail to corp.
  # This blocks the portail fallback path (direct connection).
  #
  portail-identity-aware-upstream =
    let
      upstreamId = "192.168.1.60";
    in
    pkgs.testers.nixosTest {
      name = "portail-identity-aware-upstream";
      nodes = {
        corp-server = mkServiceNode { };

        portail-hop = { nodes, ... }@args: {
          imports = [
            (mkPortailNode { address = upstreamId; } args)
            {
              services.portail.settings.listener = {
                tls-privkey = certs.proxyCerts.${portailDomain}.key;
                tls-chain = certs.proxyCerts.${portailDomain}.cert;
              };
            }
          ];
        };

        node = { nodes, ... }@args: {
          imports = [
            (mkPortailNode { address = "192.168.1.100"; } args)
            (
              { nodes, ... }:
              {
                # Prevent any direct TCP from this host to corp.
                # This blocks the portail fallback path.
                # We use REJECT instead of DROP to reduce test latency.
                networking.firewall.extraCommands = ''
                  iptables -I OUTPUT -p tcp -d ${nodes.corp-server.networking.primaryIPAddress} -j REJECT --reject-with tcp-reset
                '';

                security.pki.certificates = [
                  (builtins.readFile certs.proxyCerts.ca.cert)
                  (builtins.readFile certs.workloadCerts.ca.cert)
                ];

                services.portail.settings = {
                  default-backend = "default";
                  backends.default = {
                    target-address = "${nodes.portail-hop.networking.primaryIPAddress}:8080";
                    identity-aware = true;
                  };
                  listener = {
                    # Trust anchor for verifying the upstream (hop) TLS server certificate.
                    cacert-file = certs.proxyCerts.ca.cert;
                  };
                };
              }
            )
          ];
        };
      };

      testScript = ''
        import json

        start_all()

        node.wait_for_unit("multi-user.target")
        node.wait_for_unit("portail.service")

        portail_hop.wait_for_unit("multi-user.target")
        portail_hop.wait_for_unit("portail.service")

        corp_server.wait_for_unit("multi-user.target")
        corp_server.wait_for_open_port(443)

        node.wait_for_open_port(8080)
        portail_hop.wait_for_open_port(8080)

        # The direct route is blocked, so the proxy cannot fallback.
        node.fail(
          "curl --fail --max-time 5 https://hello.corp.example.com/"
        )

        # Test HTTP CONNECT curl -> portail -(TLS)-> portail (hop) -> corp-server
        result = json.loads(node.succeed(
          "curl --fail --max-time 5 --proxy http://127.0.0.1:8080 https://hello.corp.example.com"
        ))
        assert (
          result['service'] == 'hello.corp'
          and result['remote_addr'] == "${upstreamId}"
          and result['tls']
          and result['protocol'] == 'HTTP/2.0'
        ), "Unexpected result from the web service: {}".format(json.dumps(result))
      '';
    };

  portail-backend-dynamic-switching = pkgs.testers.nixosTest {
    name = "portail-multiple-backends";
    nodes = {
      corp-server = mkServiceNode { };

      portail-alpha = mkPortailNode {
        address = "192.168.1.60";
        allowedHostsRegex = "hello.corp.example.com|192.168.1.1";
      };

      microsocks-beta = mkMicrosocksNode {
        address = "192.168.1.61";
      };

      node = { nodes, ... }: {
        imports = [ ../module.nix portailEnv ];

        networking.interfaces.eth1.ipv4.addresses = [
          {
            address = "192.168.1.100";
            prefixLength = 24;
          }
        ];

        networking.hosts."${nodes.corp-server.networking.primaryIPAddress}" =
          [ "hello.corp.example.com" "bad.corp.example.com" ];

        services.portail = {
          enable = true;
          enableAtBoot = true;

          settings = {
            default-backend = "alpha";
            backends = {
              alpha = {
                target-address =
                  "${nodes.portail-alpha.networking.primaryIPAddress}:8080";
              };

              beta.target-address = "${nodes.microsocks-beta.networking.primaryIPAddress}:8080";
            };
          };

          acl.filter.rules = [
            ''
              policy hello {
                when host =~ "hello.corp.example.com|192.168.1.1" and port == 80
                action allow
              }
            ''
          ];
        };
      };
    };

    testScript = ''
      import json

      start_all()

      node.wait_for_unit("multi-user.target")
      node.wait_for_unit("portail.service")

      portail_alpha.wait_for_unit("multi-user.target")
      portail_alpha.wait_for_unit("portail.service")

      microsocks_beta.wait_for_unit("multi-user.target")
      microsocks_beta.wait_for_unit("microsocks.service")

      corp_server.wait_for_unit("multi-user.target")
      corp_server.wait_for_open_port(80)

      node.wait_for_open_port(8080)
      portail_alpha.wait_for_open_port(8080)
      microsocks_beta.wait_for_open_port(8080)

      alpha_ip = "192.168.1.60"
      beta_ip = "192.168.1.61"
      self_ip = "192.168.1.100"

      def rpc(*flags):
        return json.loads(node.succeed(
          "portail rpc --json " + ' '.join(flags)
        ))

      # Verify the current default backend is alpha
      assert rpc("print-current-backend")["backend_id"] == "alpha", "Expected current backend to alpha"

      # Test SOCKS5 curl -> portail -> portail alpha -> corp-server
      result = json.loads(node.succeed(
        "curl --fail --socks5 http://127.0.0.1:8080 http://hello.corp.example.com"
      ))

      assert (
        result['service'] == 'hello.corp'
        and result['remote_addr'] == alpha_ip
      ), "Unexpected result from the web service: {}".format(json.dumps(result))

      # Dynamic switch to backend beta
      assert rpc("set-default-backend", "beta").get("success", False), "Unable to switch the default backend"
      assert rpc("print-current-backend")["backend_id"] == "beta", "Expected current backend to beta"

      # Test SOCKS5 curl -> portail -> microsocks beta -> corp-server
      result = json.loads(node.succeed(
        "curl --fail --socks5 http://127.0.0.1:8080 http://hello.corp.example.com"
      ))

      assert (
        result['service'] == 'hello.corp'
        and result['remote_addr'] == beta_ip
      ), "Unexpected result from the web service: {}".format(json.dumps(result))
    '';
  };
}
