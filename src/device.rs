use serde::{
  Deserialize,
  Serialize,
};

use crate::{
  policy::Decision,
  sysfs::UsbDevice,
};

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct DeviceState {
  #[serde(flatten)]
  pub device:   UsbDevice,
  pub decision: Decision,
}

impl DeviceState {
  pub const fn new(device: UsbDevice, decision: Decision) -> Self {
    Self { device, decision }
  }
}
