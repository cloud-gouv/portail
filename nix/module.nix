{ config, lib, pkgs, ... }:

let
  inherit (lib) mkEnableOption mkPackageOption mkOption types mkDefault concatStringsSep mkIf sort lessThan attrNames;
  cfg = config.services.portail;

  toml = pkgs.formats.toml { };

  configFile = toml.generate "portail-config.toml" cfg.settings;
  aclRulesFilePath =
  let
    # We cannot use `configFile` because it depends on `aclRulesFilePath`.
    partialConfigFile = toml.generate "portail-config.toml" (removeAttrs cfg.settings [ "filter-acl-rules-path" ]);
  in
  pkgs.writeTextFile {
    name = "portail-acl";
    text = 
    let
      sortedKeys = sort lessThan (attrNames cfg.acl.filter.rules);
      sortedRules = map (key: cfg.acl.filter.rules.${key}) sortedKeys;
    in
    concatStringsSep "\n" sortedRules;
    checkPhase = ''
      echo checking ACL syntax...
      ${cfg.package}/bin/portail check-acl-syntax --config ${partialConfigFile} "$target"
      echo checked.
    '';
  };
in
{
  options = {
    services.portail = {
      enable = mkEnableOption "portail access proxy";

      package = mkPackageOption pkgs "portail" { };

      enableAtBoot = mkEnableOption ''
        the start-up of the proxy at boot.
        Note: portail will start automatically when requested over its listeners
        via socket activation.

        Starting at boot is a pre-start if it never gets requested during
        the boot phase.
      '';

      enableFreeBind = mkEnableOption ''
        free bind of the proxy listeners.
        Use this option if you are binding to specific IP addresses
        which might not be ready when the service is called.
      '';

      acl.filter.rules = mkOption {
        type = types.attrsOf types.str;
        default = {
          "99-default-deny" = ''
            policy default_deny {
              action deny
            }
          '';
        };
        example = {
          "99-default-allow" = ''
            policy default_allow {
              action allow
            }
          '';
        };
        description = ''
          Attribute set of ACL filter rules.

          Keys are used to sort the blocks of policies according to the lexicographical order.
          This allows for easy extensibility and prioritization based on the attribute name keys lexicographical order.
        '';
      };

      proxyListenStream = mkOption {
        type = types.str;
        default = "127.0.0.1:8080";
        description = "Proxy listen stream in the systemd.socket(5) ListenStream= syntax.";
      };

      metricsPort = mkOption {
        type = types.port;
        default = 10992;
      };

      settings = mkOption {
        type = toml.type;
        description = "Settings for the proxy.";
      };
    };
  };

  config = mkIf cfg.enable {
    environment.systemPackages = [
      # For the RPC CLI.
      cfg.package
    ];

    services.portail.settings = {
      filter-acl-rules-path = aclRulesFilePath;
      request-timeout = mkDefault 30;
      tcp-nodelay = mkDefault false;
    };

    systemd.sockets = {
      portail-proxy = {
        description = "Portail proxy sockets";
        socketConfig = {
          Service = "portail.service";
          Accept = "no";
          ListenStream = cfg.proxyListenStream;
          FreeBind = cfg.enableFreeBind;
          FileDescriptorName = "proxy";
        };

        wantedBy = [ "sockets.target" ];
      };
      portail-rpc = {
        description = "Portail control sockets";
        socketConfig = {
          Service = "portail.service";
          Accept = "no";
          ListenStream = "/run/fr.gouv.portail.Control";
          PassCredentials = true;
          FileDescriptorName = "control";
        };

        wantedBy = [ "sockets.target" ];
      };
      portail-metrics = {
        description = "Portail metrics sockets";
        socketConfig = {
          Service = "portail.service";
          Accept = "no";
          ListenStream = "127.0.0.1:${toString cfg.metricsPort}";
          FileDescriptorName = "metrics";
        };

        wantedBy = [ "sockets.target" ];
      };
    };

    systemd.services.portail = {
      description = "Portail access proxy";
      wantedBy = mkIf cfg.enableAtBoot [ "multi-user.target" ];

      serviceConfig = {
        # Use "notify-reload" when https://github.com/cloud-gouv/portail/issues/9 is done.
        Type = "notify";
        NotifyAccess = "main";
        ExecStart = "${cfg.package}/bin/portail daemon --log-preset systemd --config ${configFile}";

        # Enable when https://github.com/cloud-gouv/portail/issues/10 is done.
        # FileDescriptorStoreMax = 1000;
        # FileDescriptorStorePreserve = "yes";

        PrivateTmp = true;
        PrivateIPC = true;
        ProtectKernelTunables = true;
        ProtectKernelModules = true;
        ProtectKernelLogs = true;
        PrivateBPF = true;
        MemoryDenyWriteExecute = true;
        RestrictSUIDSGID = true;
        ProtectControlGroups = "strict";
        ProtectSystem = "strict";
        DynamicUser = true;
        NoNewPrivileges = true;

        RuntimeDirectory = "portail";
        StateDirectory = "portail";
        LogsDirectory = "portail";
      };
    };
  };
}
