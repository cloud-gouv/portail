{ config, lib, pkgs, ... }:

let
  inherit (lib) mkEnableOption mkPackageOption mkOption types mkDefault concatStringsSep mkIf;
  cfg = config.services.portail;

  toml = pkgs.formats.toml { };

  aclRulesFilePath = pkgs.writeText "portail-acl" (concatStringsSep "\n" cfg.acl.filter.rules);
  configFile = toml.generate "portail-config.toml" cfg.settings;
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
        type = types.listOf types.str;
        default = [ ".* -> deny" ];
        description = ''
          List of ACL filter rules.
          By default, it denies all requests.
        '';
      };

      proxyListenStream = mkOption {
        type = types.str;
        default = "127.0.0.1:8080";
        description = "Proxy listen stream in the systemd.socket(5) ListenStream= syntax.";
      };

      settings = mkOption {
        type = toml.type;
        description = "Settings for the proxy.";
      };
    };
  };

  config = mkIf cfg.enable {
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
          ListenStream = "/run/portail/control.socket";
          PassCredentials = true;
          FileDescriptorName = "control";
        };

        wantedBy = [ "sockets.target" ];
      };
    };

    systemd.services.portail = {
      description = "Portail access proxy";
      wantedBy = mkIf cfg.enableAtBoot [ "multi-user.target" ];

      serviceConfig = {
        # Use "notify-reload" when https://github.com/cloud-gouv/portail/issues/9 is done.
        Type = "exec"; # TODO: notify
        NotifyAccess = "main";
        ExecStart = "${cfg.package}/bin/portail daemon --config ${configFile}";

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
      };
    };
  };
}
