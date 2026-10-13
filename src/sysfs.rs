use std::{
  collections::BTreeMap,
  fs,
  io::Write,
  path::{
    Path,
    PathBuf,
  },
};

use base64::{
  Engine,
  engine::general_purpose::STANDARD,
};
use nix::errno::Errno;
use serde::{
  Deserialize,
  Serialize,
};
use sha2::{
  Digest,
  Sha256,
};
use tracing::{
  info,
  warn,
};

use crate::{
  config::AuthorizedDefault,
  error::{
    Error,
    Result,
  },
  policy::Action,
};

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct UsbDevice {
  pub id:              u32,
  pub sysfs_path:      PathBuf,
  pub port_path:       String,
  pub vendor_id:       String,
  pub product_id:      String,
  pub product_name:    Option<String>,
  pub serial:          Option<String>,
  pub connect_type:    Option<String>,
  pub authorized:      Option<bool>,
  pub descriptor_hash: Option<String>,
  pub interfaces:      Vec<String>,
  pub is_hub:          bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ControllerAuthorizationUpdate {
  pub controller: String,
  pub current:    Option<String>,
  pub desired:    String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ControllerAuthorizationState {
  pub controller:         String,
  pub authorized_default: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ControllerAuthorization {
  controller: String,
  path:       PathBuf,
  current:    String,
}

#[derive(Clone, Debug)]
pub struct Scanner {
  sysfs_root: PathBuf,
}

impl Scanner {
  pub fn new(sysfs_root: impl Into<PathBuf>) -> Self {
    Self {
      sysfs_root: sysfs_root.into(),
    }
  }

  pub fn scan(&self) -> Result<Vec<UsbDevice>> {
    let devices_dir = self.sysfs_root.join("bus/usb/devices");
    let entries = fs::read_dir(&devices_dir).map_err(|error| {
      Error::io(
        format!(
          "failed to read USB sysfs directory {}",
          devices_dir.display()
        ),
        error,
      )
    })?;
    let mut devices = Vec::new();

    for entry in entries {
      let entry = entry
        .map_err(|error| Error::io("failed to read sysfs entry", error))?;
      let path = entry.path();

      match Self::read_device(&path) {
        Ok(Some(device)) => devices.push(device),
        Ok(None) => {},
        Err(error) => {
          warn!(
              path = %path.display(),
              error = %error,
              "skipping USB sysfs entry"
          );
        },
      }
    }

    devices.sort_by(|left, right| left.port_path.cmp(&right.port_path));
    Ok(devices)
  }

  pub fn controller_authorization_updates(
    &self,
    default: AuthorizedDefault,
  ) -> Result<Vec<ControllerAuthorizationUpdate>> {
    let Some(desired) = desired_authorized_default(default) else {
      return Ok(Vec::new());
    };
    Ok(
      self
        .controller_authorizations()?
        .into_iter()
        .filter_map(|authorization| controller_update(authorization, desired))
        .collect(),
    )
  }

  pub fn controller_authorization_states(
    &self,
  ) -> Result<Vec<ControllerAuthorizationState>> {
    Ok(
      self
        .controller_authorizations()?
        .into_iter()
        .map(|authorization| {
          ControllerAuthorizationState {
            controller:         authorization.controller,
            authorized_default: authorization.current,
          }
        })
        .collect(),
    )
  }

  fn controller_authorizations(&self) -> Result<Vec<ControllerAuthorization>> {
    let devices_dir = self.sysfs_root.join("bus/usb/devices");
    let entries = fs::read_dir(&devices_dir).map_err(|error| {
      Error::io(
        format!(
          "failed to read USB sysfs directory {}",
          devices_dir.display()
        ),
        error,
      )
    })?;
    let mut authorizations = Vec::new();

    for entry in entries {
      let entry = entry
        .map_err(|error| Error::io("failed to read sysfs entry", error))?;
      let path = entry.path();
      let Some(controller) = path.file_name().and_then(|name| name.to_str())
      else {
        continue;
      };
      if !is_root_hub_name(controller) {
        continue;
      }

      let path = path.join("authorized_default");
      let Some(current) = read_trimmed_optional(&path)? else {
        continue;
      };
      authorizations.push(ControllerAuthorization {
        controller: controller.to_string(),
        path,
        current,
      });
    }

    authorizations
      .sort_by(|left, right| left.controller.cmp(&right.controller));
    Ok(authorizations)
  }

  pub fn apply_controller_authorized_default(
    &self,
    default: AuthorizedDefault,
  ) -> Result<Vec<ControllerAuthorizationUpdate>> {
    let Some(desired) = desired_authorized_default(default) else {
      return Ok(Vec::new());
    };
    let mut updates = Vec::new();

    for authorization in self.controller_authorizations()? {
      if let Some(update) = controller_update(authorization.clone(), desired) {
        fs::write(&authorization.path, desired).map_err(|error| {
          Error::io(
            format!("failed to write {}", authorization.path.display()),
            error,
          )
        })?;
        updates.push(update);
      }
    }

    Ok(updates)
  }

  pub fn restore_controller_authorized_defaults(
    &self,
    states: &[ControllerAuthorizationState],
  ) -> Result<Vec<ControllerAuthorizationUpdate>> {
    let mut updates = Vec::new();

    for state in states {
      let path = self
        .sysfs_root
        .join("bus/usb/devices")
        .join(&state.controller)
        .join("authorized_default");
      let Some(current) = read_trimmed_optional(path.clone())? else {
        continue;
      };
      if current == state.authorized_default {
        continue;
      }

      fs::write(&path, &state.authorized_default).map_err(|error| {
        Error::io(format!("failed to write {}", path.display()), error)
      })?;
      updates.push(ControllerAuthorizationUpdate {
        controller: state.controller.clone(),
        current:    Some(current),
        desired:    state.authorized_default.clone(),
      });
    }

    Ok(updates)
  }

  fn read_device(path: &Path) -> Result<Option<UsbDevice>> {
    let port_path = path
      .file_name()
      .and_then(|name| name.to_str())
      .map_or_else(String::new, ToString::to_string);

    if is_root_hub_name(&port_path) {
      return Ok(None);
    }

    let uevent = read_optional(path.join("uevent"))?
      .map_or_else(BTreeMap::new, |contents| parse_uevent(&contents));

    if let Some(devtype) = uevent.get("DEVTYPE")
      && devtype != "usb_device"
    {
      return Ok(None);
    }

    let Some(vendor_id) = read_trimmed_optional(path.join("idVendor"))? else {
      return Ok(None);
    };
    let Some(product_id) = read_trimmed_optional(path.join("idProduct"))?
    else {
      return Ok(None);
    };

    let descriptors = fs::read(path.join("descriptors")).ok();
    let descriptor_hash = descriptors.as_ref().map(|data| {
      let digest = Sha256::digest(data);
      STANDARD.encode(digest)
    });
    let interfaces = descriptors
      .as_deref()
      .map_or_else(Vec::new, parse_interfaces);
    let device_class = read_trimmed_optional(path.join("bDeviceClass"))?
      .map(|value| value.to_ascii_lowercase());
    let is_hub = device_class.as_deref() == Some("09")
      || interfaces.iter().any(|interface| {
        interface
          .split_once(':')
          .is_some_and(|(class, _rest)| class.eq_ignore_ascii_case("09"))
      });

    Ok(Some(UsbDevice {
      id: 0,
      sysfs_path: path.to_path_buf(),
      port_path,
      vendor_id: vendor_id.to_ascii_lowercase(),
      product_id: product_id.to_ascii_lowercase(),
      product_name: read_trimmed_optional(path.join("product"))?,
      serial: read_trimmed_optional(path.join("serial"))?,
      connect_type: read_trimmed_optional(path.join("port/connect_type"))?,
      authorized: read_trimmed_optional(path.join("authorized"))?.and_then(
        |value| {
          match value.as_str() {
            "0" => Some(false),
            "1" => Some(true),
            _ => None,
          }
        },
      ),
      descriptor_hash,
      interfaces,
      is_hub,
    }))
  }
}

fn controller_update(
  authorization: ControllerAuthorization,
  desired: &str,
) -> Option<ControllerAuthorizationUpdate> {
  (authorization.current != desired).then(|| {
    ControllerAuthorizationUpdate {
      controller: authorization.controller,
      current:    Some(authorization.current),
      desired:    desired.to_string(),
    }
  })
}

const fn desired_authorized_default(
  default: AuthorizedDefault,
) -> Option<&'static str> {
  match default {
    AuthorizedDefault::Keep => None,
    AuthorizedDefault::None => Some("0"),
    AuthorizedDefault::All => Some("1"),
  }
}

fn is_root_hub_name(name: &str) -> bool {
  let Some(suffix) = name.strip_prefix("usb") else {
    return false;
  };
  !suffix.is_empty() && suffix.bytes().all(|byte| byte.is_ascii_digit())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EnforcementOutcome {
  Applied,
  DeviceGone,
}

pub fn apply_authorization(
  device: &UsbDevice,
  action: Action,
) -> Result<EnforcementOutcome> {
  write_authorized(device, action, false)
}

pub fn force_authorization(
  device: &UsbDevice,
  action: Action,
) -> Result<EnforcementOutcome> {
  write_authorized(device, action, true)
}

pub fn preview_authorization(
  device: &UsbDevice,
  action: Action,
) -> EnforcementOutcome {
  info!(
      action = action.as_str(),
      port_path = %device.port_path,
      vendor_id = %device.vendor_id,
      product_id = %device.product_id,
      product_name = device
          .product_name
          .as_deref()
          .map_or("", |product_name| product_name),
      "dry-run USB authorization decision"
  );
  EnforcementOutcome::Applied
}

fn write_authorized(
  device: &UsbDevice,
  action: Action,
  force: bool,
) -> Result<EnforcementOutcome> {
  let desired = action.authorized();

  if !force && device.authorized == Some(desired) {
    return Ok(EnforcementOutcome::Applied);
  }

  let value = if desired { "1\n" } else { "0\n" };
  let path = device.sysfs_path.join("authorized");
  let mut file = match fs::OpenOptions::new().write(true).open(&path) {
    Ok(file) => file,
    Err(error) if is_device_gone(&error) => {
      return Ok(EnforcementOutcome::DeviceGone);
    },
    Err(error) => {
      return Err(Error::io(
        format!("failed to open {}", path.display()),
        error,
      ));
    },
  };
  match file.write_all(value.as_bytes()) {
    Ok(()) => {},
    Err(error) if is_device_gone(&error) => {
      return Ok(EnforcementOutcome::DeviceGone);
    },
    Err(error) => {
      return Err(Error::io(
        format!("failed to write {}", path.display()),
        error,
      ));
    },
  }

  Ok(EnforcementOutcome::Applied)
}

fn is_device_gone(error: &std::io::Error) -> bool {
  error.kind() == std::io::ErrorKind::NotFound
    || error.raw_os_error().map(Errno::from_raw) == Some(Errno::ENODEV)
}

fn read_trimmed_optional(path: impl AsRef<Path>) -> Result<Option<String>> {
  Ok(read_optional(path)?.map(|value| trim_sysfs_value(&value)))
}

fn read_optional(path: impl AsRef<Path>) -> Result<Option<String>> {
  let path = path.as_ref();
  match fs::read_to_string(path) {
    Ok(contents) => Ok(Some(contents)),
    Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
    Err(error) => {
      Err(Error::io(
        format!("failed to read {}", path.display()),
        error,
      ))
    },
  }
}

fn trim_sysfs_value(value: &str) -> String {
  value.trim_end_matches(['\0', '\n', '\r', '\t']).to_string()
}

fn parse_uevent(contents: &str) -> BTreeMap<String, String> {
  contents
    .lines()
    .filter_map(|line| {
      let (key, value) = line.split_once('=')?;
      Some((key.to_string(), value.to_string()))
    })
    .collect()
}

fn parse_interfaces(descriptors: &[u8]) -> Vec<String> {
  let mut interfaces = Vec::new();
  let mut index = 0;

  while index + 2 <= descriptors.len() {
    let length = descriptors[index] as usize;
    let descriptor_type = descriptors[index + 1];

    if length < 2 || index + length > descriptors.len() {
      break;
    }

    if descriptor_type == 0x04 && length >= 9 {
      interfaces.push(format!(
        "{:02x}:{:02x}:{:02x}",
        descriptors[index + 5],
        descriptors[index + 6],
        descriptors[index + 7]
      ));
    }

    index += length;
  }

  interfaces.sort();
  interfaces.dedup();
  interfaces
}

#[cfg(test)]
mod tests {
  use std::fs;

  use super::*;

  type TestResult<T = ()> = std::result::Result<T, Box<dyn std::error::Error>>;

  #[test]
  fn parses_interface_descriptors() {
    let descriptors = [
      9, 4, 0, 0, 1, 0x03, 0x01, 0x01, 0, 9, 4, 1, 0, 1, 0x08, 0x06, 0x50, 0,
    ];

    assert_eq!(parse_interfaces(&descriptors), vec![
      "03:01:01".to_string(),
      "08:06:50".to_string()
    ]);
  }

  #[test]
  fn scanner_reads_usb_device_from_fake_sysfs() -> TestResult {
    let root = tempfile::tempdir()?;
    let root_hub_dir = root.path().join("bus/usb/devices/usb1");
    fs::create_dir_all(&root_hub_dir)?;
    fs::write(root_hub_dir.join("idVendor"), "1d6b\n")?;
    fs::write(root_hub_dir.join("idProduct"), "0002\n")?;
    fs::write(root_hub_dir.join("authorized_default"), "1\n")?;

    let device_dir = root.path().join("bus/usb/devices/1-2");
    fs::create_dir_all(device_dir.join("port"))?;
    fs::write(device_dir.join("uevent"), "DEVTYPE=usb_device\n")?;
    fs::write(device_dir.join("idVendor"), "FEED\n")?;
    fs::write(device_dir.join("idProduct"), "1307\n")?;
    fs::write(device_dir.join("bDeviceClass"), "00\n")?;
    fs::write(device_dir.join("product"), "Test Keyboard\n")?;
    fs::write(device_dir.join("serial"), "abc123\n")?;
    fs::write(device_dir.join("authorized"), "1\n")?;
    fs::write(device_dir.join("port/connect_type"), "hardwired\n")?;
    fs::write(device_dir.join("descriptors"), [
      9, 4, 0, 0, 1, 0x03, 0x01, 0x01, 0,
    ])?;

    let devices = Scanner::new(root.path()).scan()?;

    assert_eq!(devices.len(), 1);
    assert_eq!(devices[0].port_path, "1-2");
    assert_eq!(devices[0].vendor_id, "feed");
    assert_eq!(devices[0].product_id, "1307");
    assert_eq!(devices[0].product_name.as_deref(), Some("Test Keyboard"));
    assert_eq!(devices[0].serial.as_deref(), Some("abc123"));
    assert_eq!(devices[0].connect_type.as_deref(), Some("hardwired"));
    assert_eq!(devices[0].authorized, Some(true));
    assert_eq!(devices[0].interfaces, vec!["03:01:01".to_string()]);
    assert!(devices[0].descriptor_hash.is_some());
    assert!(!devices[0].is_hub);
    Ok(())
  }

  #[test]
  fn scanner_classifies_usb_hubs() -> TestResult {
    let root = tempfile::tempdir()?;
    let device_dir = root.path().join("bus/usb/devices/1-2");
    fs::create_dir_all(&device_dir)?;
    fs::write(device_dir.join("uevent"), "DEVTYPE=usb_device\n")?;
    fs::write(device_dir.join("idVendor"), "05e3\n")?;
    fs::write(device_dir.join("idProduct"), "0610\n")?;
    fs::write(device_dir.join("bDeviceClass"), "09\n")?;
    fs::write(device_dir.join("authorized"), "1\n")?;

    let devices = Scanner::new(root.path()).scan()?;

    assert_eq!(devices.len(), 1);
    assert!(devices[0].is_hub);
    Ok(())
  }

  #[test]
  fn computes_controller_authorized_default_updates() -> TestResult {
    let root = tempfile::tempdir()?;
    let root_hub_dir = root.path().join("bus/usb/devices/usb1");
    fs::create_dir_all(&root_hub_dir)?;
    fs::write(root_hub_dir.join("authorized_default"), "1\n")?;

    let scanner = Scanner::new(root.path());
    let updates =
      scanner.controller_authorization_updates(AuthorizedDefault::None)?;

    assert_eq!(updates, vec![ControllerAuthorizationUpdate {
      controller: "usb1".to_string(),
      current:    Some("1".to_string()),
      desired:    "0".to_string(),
    }]);
    assert!(
      scanner
        .controller_authorization_updates(AuthorizedDefault::Keep)?
        .is_empty()
    );
    Ok(())
  }

  #[test]
  fn applies_controller_authorized_default_updates() -> TestResult {
    let root = tempfile::tempdir()?;
    let root_hub_dir = root.path().join("bus/usb/devices/usb1");
    fs::create_dir_all(&root_hub_dir)?;
    fs::write(root_hub_dir.join("authorized_default"), "1\n")?;

    let scanner = Scanner::new(root.path());
    let updates =
      scanner.apply_controller_authorized_default(AuthorizedDefault::None)?;

    assert_eq!(updates.len(), 1);
    assert_eq!(
      fs::read_to_string(root_hub_dir.join("authorized_default"))?,
      "0"
    );
    Ok(())
  }

  #[test]
  fn forced_device_authorization_ignores_cached_state() -> TestResult {
    let root = tempfile::tempdir()?;
    let device_dir = root.path().join("bus/usb/devices/1-2");
    fs::create_dir_all(&device_dir)?;
    fs::write(device_dir.join("authorized"), "0\n")?;
    let device = UsbDevice {
      sysfs_path: device_dir.clone(),
      authorized: Some(true),
      ..UsbDevice::default()
    };

    force_authorization(&device, Action::Allow)?;

    assert_eq!(fs::read_to_string(device_dir.join("authorized"))?, "1\n");
    Ok(())
  }

  #[test]
  fn authorization_reports_disappeared_device() -> TestResult {
    let root = tempfile::tempdir()?;
    let device_dir = root.path().join("bus/usb/devices/1-2");
    fs::create_dir_all(&device_dir)?;
    let device = UsbDevice {
      sysfs_path: device_dir,
      authorized: Some(false),
      ..UsbDevice::default()
    };

    let outcome = force_authorization(&device, Action::Allow)?;

    assert_eq!(outcome, EnforcementOutcome::DeviceGone);
    Ok(())
  }

  #[test]
  fn captures_and_restores_controller_authorized_defaults() -> TestResult {
    let root = tempfile::tempdir()?;
    let root_hub_dir = root.path().join("bus/usb/devices/usb1");
    fs::create_dir_all(&root_hub_dir)?;
    fs::write(root_hub_dir.join("authorized_default"), "1\n")?;

    let scanner = Scanner::new(root.path());
    let states = scanner.controller_authorization_states()?;
    scanner.apply_controller_authorized_default(AuthorizedDefault::None)?;
    let updates = scanner.restore_controller_authorized_defaults(&states)?;

    assert_eq!(updates, vec![ControllerAuthorizationUpdate {
      controller: "usb1".to_string(),
      current:    Some("0".to_string()),
      desired:    "1".to_string(),
    }]);
    assert_eq!(
      fs::read_to_string(root_hub_dir.join("authorized_default"))?,
      "1"
    );
    Ok(())
  }

  #[test]
  fn recognizes_only_root_hub_names() {
    assert!(is_root_hub_name("usb1"));
    assert!(is_root_hub_name("usb42"));
    assert!(!is_root_hub_name("usb"));
    assert!(!is_root_hub_name("1-2"));
    assert!(!is_root_hub_name("1-2:1.0"));
  }
}
