use std::{
  error::Error as StdError,
  fs,
  os::unix::fs::PermissionsExt,
  path::{
    Path,
    PathBuf,
  },
};

use super::{
  changes::{
    DeviceChangeKind,
    ExplicitDecisionSource,
    collect_device_change_events,
    explicit_decision_source,
  },
  control_server::{
    bind_control_socket,
    handle_client,
  },
  state::State,
};
use crate::{
  config::{
    Config,
    Mode,
  },
  control::{
    Request,
    Response,
    send_request,
  },
  device::DeviceState,
  policy::{
    Action,
    Decision,
    DeviceMatcher,
    Policy,
    Rule,
  },
  sysfs::Scanner,
};

type TestResult<T = ()> =
  std::result::Result<T, Box<dyn StdError + Send + Sync>>;

fn test_error(message: impl Into<String>) -> Box<dyn StdError + Send + Sync> {
  Box::new(std::io::Error::other(message.into()))
}

fn write_fake_device(root: &Path) -> TestResult {
  let device_dir = root.join("bus/usb/devices/1-2");
  fs::create_dir_all(&device_dir)?;
  fs::write(device_dir.join("uevent"), "DEVTYPE=usb_device\n")?;
  fs::write(device_dir.join("idVendor"), "feed\n")?;
  fs::write(device_dir.join("idProduct"), "1307\n")?;
  fs::write(device_dir.join("authorized"), "1\n")?;
  Ok(())
}

fn write_fake_device_without_authorized(root: &Path) -> TestResult {
  let device_dir = root.join("bus/usb/devices/1-2");
  fs::create_dir_all(&device_dir)?;
  fs::write(device_dir.join("uevent"), "DEVTYPE=usb_device\n")?;
  fs::write(device_dir.join("idVendor"), "feed\n")?;
  fs::write(device_dir.join("idProduct"), "1307\n")?;
  Ok(())
}

fn report_device(id: u32, port_path: &str) -> crate::sysfs::UsbDevice {
  crate::sysfs::UsbDevice {
    id,
    sysfs_path: PathBuf::from(format!("/sys/bus/usb/devices/{port_path}")),
    port_path: port_path.to_string(),
    vendor_id: "feed".to_string(),
    product_id: "1307".to_string(),
    product_name: Some("Test Keyboard".to_string()),
    serial: Some("abc123".to_string()),
    ..crate::sysfs::UsbDevice::default()
  }
}

fn report_decision(device_id: u32, action: Action) -> Decision {
  Decision {
    device_id,
    action,
    reason: "matched rule".to_string(),
    rule: Some("trusted device".to_string()),
  }
}

fn report_state(
  device_id: u32,
  port_path: &str,
  action: Action,
) -> DeviceState {
  DeviceState::new(
    report_device(device_id, port_path),
    report_decision(device_id, action),
  )
}

fn allow_policy() -> Policy {
  Policy {
    default: Action::Block,
    rules:   vec![Rule {
      name:    "trusted device".to_string(),
      action:  Action::Allow,
      matcher: DeviceMatcher {
        vendor_id: Some("feed".to_string()),
        product_id: Some("1307".to_string()),
        ..DeviceMatcher::default()
      },
    }],
  }
}

fn serve_control_requests(
  listener: std::os::unix::net::UnixListener,
  scanner: Scanner,
  mut state: State,
  request_count: usize,
) -> std::thread::JoinHandle<TestResult<State>> {
  std::thread::spawn(move || {
    for _ in 0..request_count {
      let (stream, _address) = listener.accept()?;
      handle_client(stream, &scanner, &mut state)?;
    }
    Ok(state)
  })
}

fn join_server(
  handle: std::thread::JoinHandle<TestResult<State>>,
) -> TestResult<State> {
  let Ok(result) = handle.join() else {
    return Err(test_error("control server thread panicked"));
  };
  result
}

fn require_devices(response: Response) -> TestResult<Vec<DeviceState>> {
  match response {
    Response::Devices { devices } => Ok(devices),
    other => {
      Err(test_error(format!(
        "expected devices response, got {other:?}"
      )))
    },
  }
}

fn require_decisions(response: Response) -> TestResult<Vec<Decision>> {
  match response {
    Response::Decisions { decisions } => Ok(decisions),
    other => {
      Err(test_error(format!(
        "expected decisions response, got {other:?}"
      )))
    },
  }
}

fn require_ok(response: Response) -> TestResult<String> {
  match response {
    Response::Ok { message } => Ok(message),
    other => Err(test_error(format!("expected ok response, got {other:?}"))),
  }
}

fn require_error(response: Response) -> TestResult<String> {
  match response {
    Response::Error { message } => Ok(message),
    other => {
      Err(test_error(format!(
        "expected error response, got {other:?}"
      )))
    },
  }
}

#[test]
fn dry_run_reload_does_not_replace_active_policy() -> TestResult {
  let root = tempfile::tempdir()?;
  write_fake_device(root.path())?;
  let policy_path = root.path().join("policy.toml");
  fs::write(
    &policy_path,
    r#"
default = "block"

[[rules]]
name = "candidate block"
action = "block"

[rules.match]
vendor_id = "feed"
product_id = "1307"
"#,
  )?;

  let config = Config {
    policy_path,
    sysfs_root: root.path().to_path_buf(),
    ..Config::default()
  };
  let scanner = Scanner::new(config.sysfs_root.clone());
  let state = State::new(config, allow_policy());

  let decisions = state.dry_run_reload(&scanner)?;

  assert_eq!(decisions[0].action, Action::Block);
  assert_eq!(state.active_policy().rules[0].action, Action::Allow);
  assert!(state.devices.is_empty());
  Ok(())
}

#[test]
fn failed_reload_does_not_replace_active_policy() -> TestResult {
  let root = tempfile::tempdir()?;
  write_fake_device(root.path())?;
  let policy_path = root.path().join("policy.toml");
  fs::write(&policy_path, "default = \"block\"\n")?;

  let config = Config {
    policy_path,
    sysfs_root: root.path().to_path_buf(),
    ..Config::default()
  };
  let scanner = Scanner::new(config.sysfs_root.clone());
  let mut state = State::new(config, allow_policy());

  let Err(error) = state.reload(&scanner) else {
    return Err(test_error("expected reload to fail"));
  };

  assert!(error.to_string().contains("refusing to enforce"));
  assert_eq!(state.active_policy().rules[0].name, "trusted device");
  Ok(())
}

#[test]
fn reports_connected_device_with_decision() {
  let device = report_state(1, "1-2", Action::Allow);

  let events = collect_device_change_events(&[], &[device]);

  assert_eq!(events.len(), 1);
  assert_eq!(events[0].kind, DeviceChangeKind::Connected);
  assert_eq!(events[0].action, Action::Allow);
  assert_eq!(events[0].rule.as_deref(), Some("trusted device"));
  assert_eq!(
    explicit_decision_source(
      Some(&events[0].reason),
      events[0].rule.as_deref()
    ),
    Some(ExplicitDecisionSource::PolicyRule)
  );
}

#[test]
fn reports_removed_device_with_last_decision() {
  let device = report_state(1, "1-2", Action::Block);

  let events = collect_device_change_events(&[device], &[]);

  assert_eq!(events.len(), 1);
  assert_eq!(events[0].kind, DeviceChangeKind::Removed);
  assert_eq!(events[0].action, Action::Block);
}

#[test]
fn reports_same_path_identity_change_as_remove_and_connect() {
  let previous = report_state(1, "1-2", Action::Allow);
  let mut current = report_device(2, "1-2");
  current.vendor_id = "cafe".to_string();
  current.product_id = "babe".to_string();
  let current_decision = Decision {
    device_id: 2,
    action:    Action::Block,
    reason:    "default action".to_string(),
    rule:      None,
  };
  let current = DeviceState::new(current, current_decision);

  let events = collect_device_change_events(&[previous], &[current]);

  assert_eq!(events.len(), 2);
  assert_eq!(events[0].kind, DeviceChangeKind::Connected);
  assert_eq!(events[1].kind, DeviceChangeKind::Removed);
}

#[test]
fn reports_existing_device_decision_change() {
  let previous = report_state(1, "1-2", Action::Block);
  let current = report_state(1, "1-2", Action::Allow);

  let events = collect_device_change_events(&[previous], &[current]);

  assert_eq!(events.len(), 1);
  assert_eq!(events[0].kind, DeviceChangeKind::DecisionChanged);
  assert_eq!(events[0].previous_action, Some(Action::Block));
  assert_eq!(events[0].action, Action::Allow);
}

#[test]
fn default_decision_is_not_explicit() {
  let device = DeviceState::new(report_device(1, "1-2"), Decision {
    device_id: 1,
    action:    Action::Block,
    reason:    "default action".to_string(),
    rule:      None,
  });

  let events = collect_device_change_events(&[], &[device]);

  assert_eq!(
    explicit_decision_source(
      Some(&events[0].reason),
      events[0].rule.as_deref()
    ),
    None
  );
}

#[test]
fn manual_override_decision_is_explicit() {
  assert_eq!(
    explicit_decision_source(Some("manual override"), None),
    Some(ExplicitDecisionSource::ManualOverride)
  );
}

#[test]
fn control_socket_is_private_to_owner_and_group() -> TestResult {
  let root = tempfile::tempdir()?;
  let socket_path = root.path().join("control.sock");

  let _listener = bind_control_socket(&socket_path)?;

  let mode = fs::metadata(socket_path)?.permissions().mode() & 0o777;
  assert_eq!(mode, 0o660);
  Ok(())
}

#[test]
fn control_request_lists_devices() -> TestResult {
  let root = tempfile::tempdir()?;
  write_fake_device(root.path())?;
  let socket_path = root.path().join("control.sock");
  let listener = bind_control_socket(&socket_path)?;
  let config = Config {
    mode: Mode::DryRun,
    socket_path: socket_path.clone(),
    sysfs_root: root.path().to_path_buf(),
    ..Config::default()
  };
  let scanner = Scanner::new(config.sysfs_root.clone());
  let mut state = State::new(config, allow_policy());
  state.refresh(&scanner)?;

  let server = serve_control_requests(listener, scanner, state, 1);
  let devices =
    require_devices(send_request(&socket_path, &Request::ListDevices)?)?;
  join_server(server)?;

  assert_eq!(devices.len(), 1);
  assert_eq!(devices[0].device.vendor_id, "feed");
  assert_eq!(devices[0].decision.action, Action::Allow);
  Ok(())
}

#[test]
fn control_socket_workflow_applies_overrides_clear_and_reload() -> TestResult {
  let root = tempfile::tempdir()?;
  write_fake_device(root.path())?;
  let authorized_path = root.path().join("bus/usb/devices/1-2/authorized");
  let socket_path = root.path().join("control.sock");
  let policy_path = root.path().join("policy.toml");
  fs::write(
    &policy_path,
    r#"
default = "block"

[[rules]]
name = "trusted device"
action = "allow"

[rules.match]
vendor_id = "feed"
product_id = "1307"
"#,
  )?;
  let listener = bind_control_socket(&socket_path)?;
  let config = Config {
    socket_path: socket_path.clone(),
    policy_path: policy_path.clone(),
    sysfs_root: root.path().to_path_buf(),
    ..Config::default()
  };
  let policy = Policy::load(&policy_path, &config)?;
  let scanner = Scanner::new(config.sysfs_root.clone());
  let mut state = State::new(config, policy);
  state.refresh(&scanner)?;
  assert_eq!(fs::read_to_string(&authorized_path)?, "1\n");
  let server = serve_control_requests(listener, scanner, state, 6);

  let devices =
    require_devices(send_request(&socket_path, &Request::ListDevices)?)?;
  assert_eq!(devices[0].decision.action, Action::Allow);

  require_ok(send_request(&socket_path, &Request::Apply {
    id:     devices[0].device.id,
    action: Action::Block,
  })?)?;
  assert_eq!(fs::read_to_string(&authorized_path)?, "0\n");

  let devices =
    require_devices(send_request(&socket_path, &Request::ListDevices)?)?;
  assert_eq!(devices[0].decision.action, Action::Block);

  let message =
    require_ok(send_request(&socket_path, &Request::ClearOverride {
      id: devices[0].device.id,
    })?)?;
  assert!(message.contains("policy now allow"));
  assert_eq!(fs::read_to_string(&authorized_path)?, "1\n");

  fs::write(
    &policy_path,
    r#"
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
"#,
  )?;
  let decisions =
    require_decisions(send_request(&socket_path, &Request::Reload)?)?;
  assert_eq!(decisions[0].action, Action::Block);
  assert_eq!(fs::read_to_string(&authorized_path)?, "0\n");

  let status = send_request(&socket_path, &Request::Status)?;
  let (device_count, override_count) = match status {
    Response::Status {
      device_count,
      override_count,
      ..
    } => (device_count, override_count),
    other => {
      return Err(test_error(format!(
        "expected status response, got {other:?}"
      )));
    },
  };
  assert_eq!(device_count, 1);
  assert_eq!(override_count, 0);

  let state = join_server(server)?;
  assert_eq!(state.devices.len(), 1);
  assert_eq!(state.devices[0].decision.action, Action::Block);
  Ok(())
}

#[test]
fn control_request_reports_command_errors() -> TestResult {
  let root = tempfile::tempdir()?;
  let socket_path = root.path().join("control.sock");
  let listener = bind_control_socket(&socket_path)?;
  let config = Config {
    mode: Mode::DryRun,
    socket_path: socket_path.clone(),
    sysfs_root: root.path().to_path_buf(),
    ..Config::default()
  };
  let scanner = Scanner::new(config.sysfs_root.clone());
  let state = State::new(config, Policy::default());

  let server = serve_control_requests(listener, scanner, state, 1);
  let response = send_request(&socket_path, &Request::Apply {
    id:     99,
    action: Action::Block,
  })?;
  join_server(server)?;

  let message = require_error(response)?;
  assert!(message.contains("unknown device id 99"));
  Ok(())
}

#[test]
fn oversized_control_request_is_rejected() -> TestResult {
  use std::{
    io::{
      BufRead,
      BufReader,
      Write,
    },
    os::unix::net::UnixStream,
  };

  let root = tempfile::tempdir()?;
  let socket_path = root.path().join("control.sock");
  let listener = bind_control_socket(&socket_path)?;
  let config = Config {
    mode: Mode::DryRun,
    socket_path: socket_path.clone(),
    sysfs_root: root.path().to_path_buf(),
    ..Config::default()
  };
  let scanner = Scanner::new(config.sysfs_root.clone());
  let state = State::new(config, Policy::default());
  let server = serve_control_requests(listener, scanner, state, 1);

  let mut stream = UnixStream::connect(&socket_path)?;
  stream.write_all(&vec![b' '; 70 * 1024])?;
  stream.write_all(b"\n")?;
  let mut response = String::new();
  BufReader::new(stream).read_line(&mut response)?;
  join_server(server)?;

  assert!(response.contains("control request exceeds"));
  Ok(())
}

#[test]
fn manual_allow_override_survives_refresh_for_same_identity() -> TestResult {
  let root = tempfile::tempdir()?;
  write_fake_device(root.path())?;
  let config = Config {
    mode: Mode::DryRun,
    sysfs_root: root.path().to_path_buf(),
    ..Config::default()
  };
  let policy = Policy {
    default: Action::Block,
    rules:   Vec::new(),
  };
  let scanner = Scanner::new(config.sysfs_root.clone());
  let mut state = State::new(config, policy);

  let decisions = state.refresh(&scanner)?;
  assert_eq!(decisions[0].action, Action::Block);

  let override_decision = state.apply_override(1, Action::Allow)?;
  assert_eq!(override_decision.action, Action::Allow);
  assert_eq!(override_decision.reason, "manual override");

  let decisions = state.refresh(&scanner)?;
  assert_eq!(decisions[0].action, Action::Allow);
  assert_eq!(decisions[0].reason, "manual override");
  Ok(())
}

#[test]
fn manual_override_survives_late_descriptor_metadata() -> TestResult {
  let root = tempfile::tempdir()?;
  write_fake_device(root.path())?;
  let device_dir = root.path().join("bus/usb/devices/1-2");
  let config = Config {
    mode: Mode::DryRun,
    sysfs_root: root.path().to_path_buf(),
    ..Config::default()
  };
  let scanner = Scanner::new(config.sysfs_root.clone());
  let mut state = State::new(config, Policy::default());

  state.refresh(&scanner)?;
  state.apply_override(1, Action::Allow)?;
  fs::write(device_dir.join("product"), "Late Metadata\n")?;
  fs::write(device_dir.join("descriptors"), [
    9, 4, 0, 0, 1, 0x03, 0x01, 0x01, 0,
  ])?;

  let decisions = state.refresh(&scanner)?;

  assert_eq!(state.devices[0].device.id, 1);
  assert_eq!(decisions[0].action, Action::Allow);
  assert_eq!(decisions[0].reason, "manual override");
  Ok(())
}

#[test]
fn manual_override_does_not_transfer_to_new_identity_on_same_path() -> TestResult
{
  let root = tempfile::tempdir()?;
  write_fake_device(root.path())?;
  let device_dir = root.path().join("bus/usb/devices/1-2");
  let config = Config {
    mode: Mode::DryRun,
    sysfs_root: root.path().to_path_buf(),
    ..Config::default()
  };
  let scanner = Scanner::new(config.sysfs_root.clone());
  let mut state = State::new(config, Policy::default());

  state.refresh(&scanner)?;
  state.apply_override(1, Action::Allow)?;
  fs::write(device_dir.join("idVendor"), "cafe\n")?;
  fs::write(device_dir.join("idProduct"), "babe\n")?;

  let decisions = state.refresh(&scanner)?;

  assert_eq!(decisions[0].action, Action::Block);
  assert_eq!(decisions[0].reason, "default action");
  assert!(state.overrides.is_empty());
  assert_ne!(state.devices[0].device.id, 1);
  Ok(())
}

#[test]
fn manual_allow_override_forces_sysfs_write_after_policy_block() -> TestResult {
  let root = tempfile::tempdir()?;
  write_fake_device(root.path())?;
  let authorized_path = root.path().join("bus/usb/devices/1-2/authorized");
  let config = Config {
    sysfs_root: root.path().to_path_buf(),
    ..Config::default()
  };
  let scanner = Scanner::new(config.sysfs_root.clone());
  let mut state = State::new(config, Policy::default());

  state.refresh(&scanner)?;
  assert_eq!(fs::read_to_string(&authorized_path)?, "0\n");
  assert_eq!(state.devices[0].device.authorized, Some(false));

  state.apply_override(1, Action::Allow)?;

  assert_eq!(fs::read_to_string(&authorized_path)?, "1\n");
  assert_eq!(state.devices[0].device.authorized, Some(true));
  Ok(())
}

#[test]
fn refresh_does_not_crash_when_authorized_file_disappears() -> TestResult {
  let root = tempfile::tempdir()?;
  write_fake_device_without_authorized(root.path())?;
  let config = Config {
    sysfs_root: root.path().to_path_buf(),
    ..Config::default()
  };
  let scanner = Scanner::new(config.sysfs_root.clone());
  let mut state = State::new(config, Policy::default());

  let decisions = state.refresh(&scanner)?;

  assert_eq!(decisions[0].action, Action::Block);
  assert_eq!(state.devices[0].device.authorized, None);
  Ok(())
}

#[test]
fn manual_override_errors_when_device_disappears_before_write() -> TestResult {
  let root = tempfile::tempdir()?;
  write_fake_device(root.path())?;
  let authorized_path = root.path().join("bus/usb/devices/1-2/authorized");
  let config = Config {
    sysfs_root: root.path().to_path_buf(),
    ..Config::default()
  };
  let scanner = Scanner::new(config.sysfs_root.clone());
  let mut state = State::new(config, Policy::default());
  state.refresh(&scanner)?;
  fs::remove_file(&authorized_path)?;

  let Err(error) = state.apply_override(1, Action::Allow) else {
    return Err(test_error("expected manual override to fail"));
  };

  assert!(error.to_string().contains("disappeared"));
  assert!(state.overrides.is_empty());
  assert_eq!(state.devices[0].device.authorized, Some(false));
  Ok(())
}

#[test]
fn clearing_manual_override_reapplies_policy() -> TestResult {
  let root = tempfile::tempdir()?;
  write_fake_device(root.path())?;
  let authorized_path = root.path().join("bus/usb/devices/1-2/authorized");
  let config = Config {
    sysfs_root: root.path().to_path_buf(),
    ..Config::default()
  };
  let scanner = Scanner::new(config.sysfs_root.clone());
  let mut state = State::new(config, Policy::default());

  state.refresh(&scanner)?;
  state.apply_override(1, Action::Allow)?;
  assert_eq!(fs::read_to_string(&authorized_path)?, "1\n");

  let decision = state.clear_override(1)?;

  assert_eq!(decision.action, Action::Block);
  assert_eq!(decision.reason, "default action");
  assert!(state.overrides.is_empty());
  assert_eq!(fs::read_to_string(&authorized_path)?, "0\n");
  assert_eq!(state.devices[0].device.authorized, Some(false));
  Ok(())
}

#[test]
fn clearing_manual_override_can_reapply_explicit_policy_rule() -> TestResult {
  let root = tempfile::tempdir()?;
  write_fake_device(root.path())?;
  let authorized_path = root.path().join("bus/usb/devices/1-2/authorized");
  let config = Config {
    sysfs_root: root.path().to_path_buf(),
    ..Config::default()
  };
  let scanner = Scanner::new(config.sysfs_root.clone());
  let mut state = State::new(config, allow_policy());

  state.refresh(&scanner)?;
  state.apply_override(1, Action::Block)?;
  assert_eq!(fs::read_to_string(&authorized_path)?, "0\n");

  let decision = state.clear_override(1)?;

  assert_eq!(decision.action, Action::Allow);
  assert_eq!(decision.rule.as_deref(), Some("trusted device"));
  assert_eq!(fs::read_to_string(&authorized_path)?, "1\n");
  assert_eq!(
    state
      .devices
      .iter()
      .find(|state| state.device.id == 1)
      .and_then(|state| state.decision.rule.as_deref()),
    Some("trusted device")
  );
  Ok(())
}

#[test]
fn control_clear_override_reapplies_policy() -> TestResult {
  let root = tempfile::tempdir()?;
  write_fake_device(root.path())?;
  let socket_path = root.path().join("control.sock");
  let listener = bind_control_socket(&socket_path)?;
  let config = Config {
    mode: Mode::DryRun,
    socket_path: socket_path.clone(),
    sysfs_root: root.path().to_path_buf(),
    ..Config::default()
  };
  let scanner = Scanner::new(config.sysfs_root.clone());
  let mut state = State::new(config, Policy::default());
  state.refresh(&scanner)?;
  state.apply_override(1, Action::Allow)?;

  let server = serve_control_requests(listener, scanner, state, 1);
  let response = send_request(&socket_path, &Request::ClearOverride { id: 1 })?;
  join_server(server)?;

  let message = require_ok(response)?;
  assert!(message.contains("policy now block"));
  Ok(())
}
