use std::{
  fs,
  path::{
    Path,
    PathBuf,
  },
};

use serde::{
  Deserialize,
  Serialize,
};

use crate::{
  error::{
    Error,
    Result,
  },
  policy::Action,
};

pub const DEFAULT_CONFIG_PATH: &str = "/etc/custos/config.toml";

#[derive(
  Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize,
)]
#[serde(rename_all = "kebab-case")]
pub enum Mode {
  #[default]
  Enforce,
  DryRun,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct Config {
  pub mode:                      Mode,
  pub policy_path:               PathBuf,
  pub socket_path:               PathBuf,
  pub sysfs_root:                PathBuf,
  pub unsafe_allow_empty_policy: bool,
  pub default_action:            Action,
  pub controllers:               ControllerConfig,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct ControllerConfig {
  pub authorized_default:  AuthorizedDefault,
  pub restore_on_shutdown: bool,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum AuthorizedDefault {
  Keep,
  None,
  All,
}

impl Default for Config {
  fn default() -> Self {
    Self {
      mode:                      Mode::default(),
      policy_path:               PathBuf::from("/etc/custos/policy.toml"),
      socket_path:               PathBuf::from("/run/custos/control.sock"),
      sysfs_root:                PathBuf::from("/sys"),
      unsafe_allow_empty_policy: false,
      default_action:            Action::Block,
      controllers:               ControllerConfig::default(),
    }
  }
}

impl Default for ControllerConfig {
  fn default() -> Self {
    Self {
      authorized_default:  AuthorizedDefault::None,
      restore_on_shutdown: false,
    }
  }
}

pub fn load_config(path: &Path) -> Result<Config> {
  match fs::read_to_string(path) {
    Ok(contents) => {
      toml::from_str(&contents)
        .map_err(|error| Error::Config(format!("{}: {error}", path.display())))
    },
    Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
      Ok(Config::default())
    },
    Err(error) => {
      Err(Error::io(
        format!("failed to read config {}", path.display()),
        error,
      ))
    },
  }
}
