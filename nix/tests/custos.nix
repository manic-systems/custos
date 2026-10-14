{ pkgs, self }:

pkgs.testers.nixosTest {
  name = "custos";

  nodes.machine =
    { lib, ... }:
    {
      imports = [ self.nixosModules.custos ];

      users.users.alice = {
        isNormalUser = true;
        group = "users";
      };

      services.custos = {
        enable = true;
        controlUsers = [ "alice" ];
        config = {
          mode = "enforce";
          policy_path = "/var/lib/custos-test-policy.toml";
          sysfs_root = "/var/lib/custos-test-sys";
          controllers.authorized_default = "keep";
        };

        # The mutable policy path above is populated by the test script. This
        # static allow rule keeps the module's first-run assertion honest.
        policy.rules = [
          {
            name = "module safety allow";
            action = "allow";
            match.vendor_id = "ffff";
          }
        ];
      };

      systemd.services.custos.wantedBy = lib.mkForce [ ];
      system.stateVersion = "26.05";
    };

  testScript = ''
    import json
    from textwrap import dedent

    machine.start()
    machine.wait_for_unit("multi-user.target")

    machine.succeed(dedent("""
      mkdir -p /var/lib/custos-test-sys/bus/usb/devices/usb1
      printf '1\n' > /var/lib/custos-test-sys/bus/usb/devices/usb1/authorized_default
      mkdir -p /var/lib/custos-test-sys/bus/usb/devices/1-2/port
      printf 'DEVTYPE=usb_device\n' > /var/lib/custos-test-sys/bus/usb/devices/1-2/uevent
      printf 'feed\n' > /var/lib/custos-test-sys/bus/usb/devices/1-2/idVendor
      printf '1307\n' > /var/lib/custos-test-sys/bus/usb/devices/1-2/idProduct
      printf '00\n' > /var/lib/custos-test-sys/bus/usb/devices/1-2/bDeviceClass
      printf 'Test Keyboard\n' > /var/lib/custos-test-sys/bus/usb/devices/1-2/product
      printf 'abc123\n' > /var/lib/custos-test-sys/bus/usb/devices/1-2/serial
      printf 'hardwired\n' > /var/lib/custos-test-sys/bus/usb/devices/1-2/port/connect_type
      printf '1\n' > /var/lib/custos-test-sys/bus/usb/devices/1-2/authorized
    """))

    machine.succeed(dedent("""
      cat > /var/lib/custos-test-policy.toml <<'EOF'
      default = "block"

      [[rules]]
      name = "test keyboard"
      action = "allow"

      [rules.match]
      vendor_id = "feed"
      product_id = "1307"
      is_hub = false
      EOF
    """))

    machine.succeed(dedent("""
      cat > /tmp/custos-refuse.toml <<'EOF'
      mode = "enforce"
      policy_path = "/tmp/custos-empty-policy.toml"
      socket_path = "/run/custos/refuse.sock"
      sysfs_root = "/var/lib/custos-test-sys"
      unsafe_allow_empty_policy = false
      default_action = "block"

      [controllers]
      authorized_default = "keep"
      restore_on_shutdown = false
      EOF
      printf 'default = "block"\n' > /tmp/custos-empty-policy.toml
      timeout 5s custos daemon --config /tmp/custos-refuse.toml 2>&1 | grep -q 'refusing to enforce'
    """))

    dry_run = json.loads(machine.succeed("custos dry-run --json --config /etc/custos/config.toml"))
    assert dry_run["type"] == "dry-run"
    assert dry_run["devices"][0]["decision"]["action"] == "allow"
    assert dry_run["devices"][0]["is_hub"] == False

    machine.succeed("systemctl start custos.service")
    machine.wait_for_unit("custos.service")
    machine.wait_for_file("/run/custos/control.sock")

    status = json.loads(machine.succeed("custos status --json"))
    assert status["type"] == "status"
    assert status["mode"] == "enforce"
    assert status["device_count"] == 1

    alice_status = json.loads(machine.succeed("su -s /bin/sh alice -c 'custos status --json'"))
    assert alice_status["device_count"] == 1

    devices = json.loads(machine.succeed("custos devices --json"))["devices"]
    assert devices[0]["decision"]["action"] == "allow"
    assert machine.succeed("cat /var/lib/custos-test-sys/bus/usb/devices/1-2/authorized").strip() == "1"

    alice_block = json.loads(machine.succeed("su -s /bin/sh alice -c 'custos block 1 --json'"))
    assert alice_block["type"] == "ok"
    assert machine.succeed("cat /var/lib/custos-test-sys/bus/usb/devices/1-2/authorized").strip() == "0"

    alice_allow = json.loads(machine.succeed("su -s /bin/sh alice -c 'custos allow 1 --json'"))
    assert alice_allow["type"] == "ok"
    assert machine.succeed("cat /var/lib/custos-test-sys/bus/usb/devices/1-2/authorized").strip() == "1"

    alice_clear = json.loads(machine.succeed("su -s /bin/sh alice -c 'custos clear-override 1 --json'"))
    assert alice_clear["type"] == "ok"
    assert machine.succeed("cat /var/lib/custos-test-sys/bus/usb/devices/1-2/authorized").strip() == "1"

    machine.succeed(dedent("""
      cat > /var/lib/custos-test-policy.toml <<'EOF'
      default = "block"

      [[rules]]
      name = "block target"
      action = "block"

      [rules.match]
      vendor_id = "feed"
      product_id = "1307"

      [[rules]]
      name = "safety allow"
      action = "allow"

      [rules.match]
      vendor_id = "ffff"
      EOF
    """))
    reload = json.loads(machine.succeed("custos reload --json"))
    assert reload["type"] == "decisions"
    assert reload["decisions"][0]["action"] == "block"
    assert machine.succeed("cat /var/lib/custos-test-sys/bus/usb/devices/1-2/authorized").strip() == "0"
  '';
}
