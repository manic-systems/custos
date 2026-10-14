{
  config,
  lib,
  pkgs,
  ...
}:

let
  inherit (lib)
    getExe
    literalExpression
    mkEnableOption
    mkIf
    mkOption
    types
    ;

  cfg = config.services.custos;
  toml = pkgs.formats.toml { };

  defaultConfig = {
    mode = "enforce";
    policy_path = "/etc/custos/policy.toml";
    socket_path = "/run/custos/control.sock";
    sysfs_root = "/sys";
    unsafe_allow_empty_policy = false;
    default_action = "block";
    controllers = {
      authorized_default = "none";
      restore_on_shutdown = false;
    };
  };

  defaultPolicy = {
    default = "block";
    rules = [ ];
  };

  socketPath = cfg.config.socket_path or defaultConfig.socket_path;
  sysfsRoot = cfg.config.sysfs_root or defaultConfig.sysfs_root;
  socketDir = dirOf socketPath;
  usbDevicesPath = "${sysfsRoot}/bus/usb/devices";
in
{
  options.services.custos = {
    enable = mkEnableOption "the custos USB authorization daemon";

    package = mkOption {
      type = types.package;
      default = pkgs.callPackage ./package.nix { };
      defaultText = literalExpression "pkgs.callPackage ./nix/package.nix { }";
      description = "custos package to run.";
    };

    config = mkOption {
      type = toml.type;
      default = defaultConfig;
      description = ''
        Custos daemon configuration written directly to
        /etc/custos/config.toml. Use the same snake_case field names as the
        TOML file.
      '';
      example = literalExpression ''
        {
          mode = "enforce";
          policy_path = "/etc/custos/policy.toml";
          socket_path = "/run/custos/control.sock";
          sysfs_root = "/sys";
          unsafe_allow_empty_policy = false;
          default_action = "block";
          controllers = {
            authorized_default = "none";
            restore_on_shutdown = false;
          };
        }
      '';
    };

    policy = mkOption {
      type = toml.type;
      default = defaultPolicy;
      description = ''
        Custos policy written directly to /etc/custos/policy.toml. Use the
        same snake_case field names as the TOML file.
      '';
      example = literalExpression ''
        {
          default = "block";
          rules = [
            {
              name = "built-in keyboard";
              action = "allow";
              match = {
                vendor_id = "feed";
                product_id = "1307";
                connect_type = "hardwired";
                is_hub = false;
                interfaces.any = [ "03:*:*" ];
              };
            }
          ];
        }
      '';
    };

    group = mkOption {
      type = types.str;
      default = "custos";
      description = "Group allowed to connect to the control socket.";
    };

    controlUsers = mkOption {
      type = types.listOf types.str;
      default = [ ];
      description = ''
        User accounts that should be added to the custos control group so they
        can run the CLI against the system daemon without root.
      '';
      example = [
        "alice"
      ];
    };
  };

  config = mkIf cfg.enable {
    users.groups.${cfg.group}.members = cfg.controlUsers;

    environment.systemPackages = [ cfg.package ];
    environment.etc = {
      "custos/config.toml".source = toml.generate "custos-config.toml" cfg.config;
      "custos/policy.toml".source = toml.generate "custos-policy.toml" cfg.policy;
    };

    systemd.tmpfiles.rules = [
      "d ${socketDir} 2770 root ${cfg.group} - -"
    ];

    systemd.services.custos = {
      description = "Custos USB authorization daemon";
      wantedBy = [ "multi-user.target" ];
      after = [
        "systemd-tmpfiles-setup.service"
        "systemd-udevd.service"
      ];

      serviceConfig = {
        Type = "simple";
        ExecStartPre = "${pkgs.coreutils}/bin/install -d -m 2770 -o root -g ${cfg.group} ${socketDir}";
        ExecStart = "${getExe cfg.package} daemon --config /etc/custos/config.toml";
        Restart = "on-failure";
        RestartSec = "1s";
        PrivateTmp = true;
        ProtectHome = true;
        ProtectSystem = "strict";
        ReadWritePaths = [
          socketDir
          usbDevicesPath
        ];
      };
    };
  };
}
