use std::{
  fs,
  path::Path,
};

use serde::{
  Deserialize,
  Serialize,
};

use crate::{
  config::{
    Config,
    Mode,
  },
  error::{
    Error,
    Result,
  },
  sysfs::UsbDevice,
};

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Action {
  Allow,
  Block,
}

impl Action {
  pub const fn as_str(self) -> &'static str {
    match self {
      Self::Allow => "allow",
      Self::Block => "block",
    }
  }

  pub const fn authorized(self) -> bool {
    match self {
      Self::Allow => true,
      Self::Block => false,
    }
  }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct Policy {
  pub default: Action,
  pub rules:   Vec<Rule>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Rule {
  pub name:    String,
  pub action:  Action,
  #[serde(rename = "match", default)]
  pub matcher: DeviceMatcher,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct DeviceMatcher {
  pub vendor_id:       Option<String>,
  pub product_id:      Option<String>,
  pub serial:          Option<String>,
  pub product_name:    Option<String>,
  pub connect_type:    Option<String>,
  pub port_path:       Option<String>,
  pub descriptor_hash: Option<String>,
  pub is_hub:          Option<bool>,
  pub interfaces:      InterfaceMatcher,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct InterfaceMatcher {
  pub any: Vec<String>,
  pub all: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Decision {
  pub device_id: u32,
  pub action:    Action,
  pub reason:    String,
  pub rule:      Option<String>,
}

impl Default for Policy {
  fn default() -> Self {
    Self {
      default: Action::Block,
      rules:   Vec::new(),
    }
  }
}

impl Policy {
  pub fn load(path: &Path, config: &Config) -> Result<Self> {
    match fs::read_to_string(path) {
      Ok(contents) => {
        let policy: Self = toml::from_str(&contents).map_err(|error| {
          Error::Policy(format!("{}: {error}", path.display()))
        })?;
        policy.validate()?;
        Ok(policy)
      },
      Err(error)
        if error.kind() == std::io::ErrorKind::NotFound
          && (config.mode == Mode::DryRun
            || config.unsafe_allow_empty_policy) =>
      {
        Ok(Self {
          default: config.default_action,
          rules:   Vec::new(),
        })
      },
      Err(error) => {
        Err(Error::io(
          format!("failed to read policy {}", path.display()),
          error,
        ))
      },
    }
  }

  pub fn validate_for_start(&self, config: &Config) -> Result<()> {
    self.validate()?;
    if config.mode == Mode::DryRun || config.unsafe_allow_empty_policy {
      return Ok(());
    }

    if !self.has_endpoint_allow_rule() {
      return Err(Error::Policy(
        "refusing to enforce without at least one allow rule that can match a \
         non-hub USB device; add a policy or set unsafe_allow_empty_policy = \
         true"
          .to_string(),
      ));
    }

    Ok(())
  }

  pub fn validate(&self) -> Result<()> {
    for rule in &self.rules {
      rule.validate()?;
    }
    Ok(())
  }

  pub fn has_endpoint_allow_rule(&self) -> bool {
    self.rules.iter().any(|rule| {
      rule.action == Action::Allow && rule.matcher.can_match_endpoint()
    })
  }

  pub fn decide(&self, device: &UsbDevice) -> Decision {
    for rule in &self.rules {
      if rule.matcher.matches(device) {
        return Decision {
          device_id: device.id,
          action:    rule.action,
          reason:    "matched rule".to_string(),
          rule:      Some(rule.name.clone()),
        };
      }
    }

    Decision {
      device_id: device.id,
      action:    default_action(self.default, device),
      reason:    default_reason(self.default, device).to_string(),
      rule:      None,
    }
  }

  pub fn to_pretty_toml(&self) -> Result<String> {
    toml::to_string_pretty(self).map_err(|error| {
      Error::Policy(format!("failed to serialize policy: {error}"))
    })
  }
}

impl Rule {
  fn validate(&self) -> Result<()> {
    if self.name.trim().is_empty() {
      return Err(Error::Policy(
        "policy rule name cannot be empty".to_string(),
      ));
    }
    self.matcher.validate(&self.name)
  }
}

impl DeviceMatcher {
  fn validate(&self, rule_name: &str) -> Result<()> {
    if !self.has_criteria() {
      return Err(Error::Policy(format!(
        "policy rule {rule_name:?} has an empty matcher; add at least one \
         match field"
      )));
    }
    validate_optional_hex(
      rule_name,
      "vendor_id",
      self.vendor_id.as_deref(),
      4,
    )?;
    validate_optional_hex(
      rule_name,
      "product_id",
      self.product_id.as_deref(),
      4,
    )?;
    validate_optional_non_empty(rule_name, "serial", self.serial.as_deref())?;
    validate_optional_non_empty(
      rule_name,
      "product_name",
      self.product_name.as_deref(),
    )?;
    validate_optional_non_empty(
      rule_name,
      "connect_type",
      self.connect_type.as_deref(),
    )?;
    validate_optional_non_empty(
      rule_name,
      "port_path",
      self.port_path.as_deref(),
    )?;
    validate_optional_non_empty(
      rule_name,
      "descriptor_hash",
      self.descriptor_hash.as_deref(),
    )?;
    self.interfaces.validate(rule_name)
  }

  const fn has_criteria(&self) -> bool {
    self.vendor_id.is_some()
      || self.product_id.is_some()
      || self.serial.is_some()
      || self.product_name.is_some()
      || self.connect_type.is_some()
      || self.port_path.is_some()
      || self.descriptor_hash.is_some()
      || self.is_hub.is_some()
      || !self.interfaces.any.is_empty()
      || !self.interfaces.all.is_empty()
  }

  const fn can_match_endpoint(&self) -> bool {
    !matches!(self.is_hub, Some(true))
  }

  fn matches(&self, device: &UsbDevice) -> bool {
    matches_required_case_insensitive(
      self.vendor_id.as_deref(),
      &device.vendor_id,
    ) && matches_required_case_insensitive(
      self.product_id.as_deref(),
      &device.product_id,
    ) && matches_opt(self.serial.as_deref(), device.serial.as_deref())
      && matches_opt(
        self.product_name.as_deref(),
        device.product_name.as_deref(),
      )
      && matches_opt(
        self.connect_type.as_deref(),
        device.connect_type.as_deref(),
      )
      && matches_opt(self.port_path.as_deref(), Some(device.port_path.as_str()))
      && matches_opt(
        self.descriptor_hash.as_deref(),
        device.descriptor_hash.as_deref(),
      )
      && self.is_hub.is_none_or(|expected| expected == device.is_hub)
      && self.interfaces.matches(&device.interfaces)
  }
}

impl InterfaceMatcher {
  fn validate(&self, rule_name: &str) -> Result<()> {
    for pattern in &self.any {
      validate_interface_pattern(rule_name, "interfaces.any", pattern)?;
    }
    for pattern in &self.all {
      validate_interface_pattern(rule_name, "interfaces.all", pattern)?;
    }
    Ok(())
  }
}

fn validate_optional_hex(
  rule_name: &str,
  field: &str,
  value: Option<&str>,
  expected_len: usize,
) -> Result<()> {
  let Some(value) = value else {
    return Ok(());
  };
  if value.len() == expected_len
    && value.bytes().all(|byte| byte.is_ascii_hexdigit())
  {
    return Ok(());
  }
  Err(Error::Policy(format!(
    "policy rule {rule_name:?} field {field} must be {expected_len} \
     hexadecimal characters"
  )))
}

fn validate_optional_non_empty(
  rule_name: &str,
  field: &str,
  value: Option<&str>,
) -> Result<()> {
  let Some(value) = value else {
    return Ok(());
  };
  if !value.is_empty() {
    return Ok(());
  }
  Err(Error::Policy(format!(
    "policy rule {rule_name:?} field {field} cannot be empty"
  )))
}

fn validate_interface_pattern(
  rule_name: &str,
  field: &str,
  pattern: &str,
) -> Result<()> {
  let mut parts = pattern.split(':');
  let (Some(class), Some(subclass), Some(protocol)) =
    (parts.next(), parts.next(), parts.next())
  else {
    return Err(invalid_interface_pattern(rule_name, field, pattern));
  };
  if parts.next().is_some() {
    return Err(invalid_interface_pattern(rule_name, field, pattern));
  }
  for part in [class, subclass, protocol] {
    if part == "*"
      || (part.len() == 2 && part.bytes().all(|byte| byte.is_ascii_hexdigit()))
    {
      continue;
    }
    return Err(invalid_interface_pattern(rule_name, field, pattern));
  }
  Ok(())
}

fn invalid_interface_pattern(
  rule_name: &str,
  field: &str,
  pattern: &str,
) -> Error {
  Error::Policy(format!(
    "policy rule {rule_name:?} field {field} has invalid interface pattern \
     {pattern:?}; expected cc:ss:pp with two hex digits or * per segment"
  ))
}

fn default_action(default: Action, device: &UsbDevice) -> Action {
  if default == Action::Block && device.is_hub {
    Action::Allow
  } else {
    default
  }
}

fn default_reason(default: Action, device: &UsbDevice) -> &'static str {
  if default == Action::Block && device.is_hub {
    "USB hub passthrough"
  } else {
    "default action"
  }
}

impl InterfaceMatcher {
  fn matches(&self, interfaces: &[String]) -> bool {
    let any_matches = self.any.is_empty()
      || self.any.iter().any(|pattern| {
        interfaces
          .iter()
          .any(|value| interface_matches(pattern, value))
      });
    let all_matches = self.all.iter().all(|pattern| {
      interfaces
        .iter()
        .any(|value| interface_matches(pattern, value))
    });
    any_matches && all_matches
  }
}

fn matches_required_case_insensitive(
  expected: Option<&str>,
  actual: &str,
) -> bool {
  expected.is_none_or(|expected| expected.eq_ignore_ascii_case(actual))
}

fn matches_opt(expected: Option<&str>, actual: Option<&str>) -> bool {
  expected.is_none_or(|expected| actual == Some(expected))
}

fn interface_matches(pattern: &str, value: &str) -> bool {
  let mut pattern_parts = pattern.split(':');
  let mut value_parts = value.split(':');
  let (Some(pattern_class), Some(pattern_subclass), Some(pattern_protocol)) = (
    pattern_parts.next(),
    pattern_parts.next(),
    pattern_parts.next(),
  ) else {
    return false;
  };
  let (Some(value_class), Some(value_subclass), Some(value_protocol)) =
    (value_parts.next(), value_parts.next(), value_parts.next())
  else {
    return false;
  };
  if pattern_parts.next().is_some() || value_parts.next().is_some() {
    return false;
  }

  [
    (pattern_class, value_class),
    (pattern_subclass, value_subclass),
    (pattern_protocol, value_protocol),
  ]
  .into_iter()
  .all(|(expected, actual)| {
    expected == "*" || expected.eq_ignore_ascii_case(actual)
  })
}

pub fn generate_policy(devices: &[UsbDevice]) -> Policy {
  let rules = devices
    .iter()
    .map(|device| {
      let mut matcher = DeviceMatcher {
        vendor_id:       Some(device.vendor_id.clone()),
        product_id:      Some(device.product_id.clone()),
        serial:          device
          .serial
          .clone()
          .filter(|value| !value.is_empty()),
        product_name:    None,
        connect_type:    device
          .connect_type
          .clone()
          .filter(|value| !value.is_empty()),
        port_path:       None,
        descriptor_hash: device.descriptor_hash.clone(),
        is_hub:          Some(device.is_hub),
        interfaces:      InterfaceMatcher::default(),
      };

      if matcher.serial.is_none() {
        matcher.port_path = Some(device.port_path.clone());
      }

      Rule {
        name: generated_rule_name(device),
        action: Action::Allow,
        matcher,
      }
    })
    .collect();

  Policy {
    default: Action::Block,
    rules,
  }
}

#[allow(clippy::option_if_let_else)]
fn generated_rule_name(device: &UsbDevice) -> String {
  match device
    .product_name
    .clone()
    .filter(|value| !value.is_empty())
  {
    Some(product_name) => product_name,
    None => format!("USB {}:{}", device.vendor_id, device.product_id),
  }
}

#[cfg(test)]
mod tests {
  use std::path::PathBuf;

  use super::*;

  fn sample_device() -> UsbDevice {
    UsbDevice {
      id:              42,
      sysfs_path:      PathBuf::from("/sys/bus/usb/devices/1-2"),
      port_path:       "1-2".to_string(),
      vendor_id:       "feed".to_string(),
      product_id:      "1307".to_string(),
      product_name:    Some("Test Keyboard".to_string()),
      serial:          Some("abc123".to_string()),
      connect_type:    Some("hotplug".to_string()),
      authorized:      Some(true),
      descriptor_hash: Some("descriptor-sha256".to_string()),
      interfaces:      vec!["03:01:01".to_string(), "03:00:00".to_string()],
      is_hub:          false,
    }
  }

  #[test]
  fn startup_validation_refuses_empty_enforcing_policy() {
    let policy = Policy::default();

    assert!(policy.validate_for_start(&Config::default()).is_err());

    let dry_run = Config {
      mode: Mode::DryRun,
      ..Config::default()
    };
    assert!(policy.validate_for_start(&dry_run).is_ok());

    let unsafe_empty = Config {
      unsafe_allow_empty_policy: true,
      ..Config::default()
    };
    assert!(policy.validate_for_start(&unsafe_empty).is_ok());
  }

  #[test]
  fn startup_validation_requires_endpoint_allow_rule() {
    let policy = Policy {
      default: Action::Block,
      rules:   vec![Rule {
        name:    "hub passthrough".to_string(),
        action:  Action::Allow,
        matcher: DeviceMatcher {
          is_hub: Some(true),
          ..DeviceMatcher::default()
        },
      }],
    };

    assert!(matches!(
        policy.validate_for_start(&Config::default()),
        Err(error) if error.to_string().contains("non-hub")
    ));
  }

  #[test]
  fn policy_validation_rejects_empty_matcher() {
    let policy = Policy {
      default: Action::Block,
      rules:   vec![Rule {
        name:    "empty".to_string(),
        action:  Action::Block,
        matcher: DeviceMatcher::default(),
      }],
    };

    assert!(matches!(
        policy.validate(),
        Err(error) if error.to_string().contains("empty matcher")
    ));
  }

  #[test]
  fn policy_validation_rejects_malformed_interface_pattern() {
    let policy = Policy {
      default: Action::Block,
      rules:   vec![Rule {
        name:    "bad interface".to_string(),
        action:  Action::Allow,
        matcher: DeviceMatcher {
          interfaces: InterfaceMatcher {
            any: vec!["03:*".to_string()],
            all: Vec::new(),
          },
          ..DeviceMatcher::default()
        },
      }],
    };

    assert!(matches!(
        policy.validate(),
        Err(error) if error.to_string().contains("invalid interface pattern")
    ));
  }

  #[test]
  fn toml_policy_matches_device_fields_and_interfaces() -> Result<()> {
    let policy: Policy = toml::from_str(
      r#"
default = "block"

[[rules]]
name = "test keyboard"
action = "allow"

[rules.match]
vendor_id = "FEED"
product_id = "1307"
serial = "abc123"
descriptor_hash = "descriptor-sha256"

[rules.match.interfaces]
any = ["03:*:*"]
all = ["03:01:01"]
"#,
    )
    .map_err(|error| Error::Policy(error.to_string()))?;

    let decision = policy.decide(&sample_device());

    assert_eq!(decision.action, Action::Allow);
    assert_eq!(decision.rule.as_deref(), Some("test keyboard"));
    Ok(())
  }

  #[test]
  fn first_matching_rule_wins_for_allow_and_block() {
    let policy = Policy {
      default: Action::Block,
      rules:   vec![
        Rule {
          name:    "serial block".to_string(),
          action:  Action::Block,
          matcher: DeviceMatcher {
            serial: Some("abc123".to_string()),
            ..DeviceMatcher::default()
          },
        },
        Rule {
          name:    "vendor allow".to_string(),
          action:  Action::Allow,
          matcher: DeviceMatcher {
            vendor_id: Some("feed".to_string()),
            product_id: Some("1307".to_string()),
            ..DeviceMatcher::default()
          },
        },
      ],
    };

    let decision = policy.decide(&sample_device());

    assert_eq!(decision.action, Action::Block);
    assert_eq!(decision.rule.as_deref(), Some("serial block"));
  }

  #[test]
  fn default_block_allows_hubs_for_downstream_enforcement() {
    let mut device = sample_device();
    device.is_hub = true;
    let policy = Policy::default();

    let decision = policy.decide(&device);

    assert_eq!(decision.action, Action::Allow);
    assert_eq!(decision.reason, "USB hub passthrough");
    assert!(decision.rule.is_none());
  }

  #[test]
  fn explicit_hub_rule_overrides_hub_passthrough() {
    let mut device = sample_device();
    device.is_hub = true;
    let policy = Policy {
      default: Action::Block,
      rules:   vec![Rule {
        name:    "block hubs".to_string(),
        action:  Action::Block,
        matcher: DeviceMatcher {
          is_hub: Some(true),
          ..DeviceMatcher::default()
        },
      }],
    };

    let decision = policy.decide(&device);

    assert_eq!(decision.action, Action::Block);
    assert_eq!(decision.rule.as_deref(), Some("block hubs"));
  }

  #[test]
  fn generated_policy_defaults_to_block_and_allows_present_devices() {
    let policy = generate_policy(&[sample_device()]);

    assert_eq!(policy.default, Action::Block);
    assert_eq!(policy.rules.len(), 1);
    assert_eq!(policy.rules[0].action, Action::Allow);
    assert_eq!(policy.rules[0].matcher.is_hub, Some(false));
    assert_eq!(
      policy.decide(&sample_device()).rule.as_deref(),
      Some("Test Keyboard")
    );
  }
}
