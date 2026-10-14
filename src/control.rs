use std::{
  io::{
    BufRead,
    BufReader,
    Write,
  },
  os::unix::net::UnixStream,
  path::Path,
};

use serde::{
  Deserialize,
  Serialize,
};

use crate::{
  config::Mode,
  device::DeviceState,
  error::{
    Error,
    Result,
  },
  policy::{
    Action,
    Decision,
  },
};

pub const MAX_CONTROL_FRAME: usize = 64 * 1024;

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(tag = "command", rename_all = "kebab-case")]
pub enum Request {
  Status,
  ListDevices,
  Reload,
  DryRunReload,
  Apply { id: u32, action: Action },
  ClearOverride { id: u32 },
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(tag = "type", rename_all = "kebab-case")]
pub enum Response {
  Ok {
    message: String,
  },
  Status {
    mode:           Mode,
    device_count:   usize,
    override_count: usize,
    socket_path:    String,
    policy_path:    String,
  },
  Devices {
    devices: Vec<DeviceState>,
  },
  Decisions {
    decisions: Vec<Decision>,
  },
  Error {
    message: String,
  },
}

pub fn send_request(socket_path: &Path, request: &Request) -> Result<Response> {
  let mut payload = serde_json::to_vec(request).map_err(|error| {
    Error::Protocol(format!("failed to encode request: {error}"))
  })?;
  payload.push(b'\n');
  if payload.len() > MAX_CONTROL_FRAME {
    return Err(Error::Protocol(format!(
      "control request exceeds {MAX_CONTROL_FRAME} bytes"
    )));
  }

  let mut stream = UnixStream::connect(socket_path).map_err(|error| {
    Error::io(
      format!("failed to connect to {}", socket_path.display()),
      error,
    )
  })?;
  stream
    .write_all(&payload)
    .map_err(|error| Error::io("failed to write control request", error))?;

  let mut line = String::new();
  let mut reader = BufReader::new(stream);
  reader
    .read_line(&mut line)
    .map_err(|error| Error::io("failed to read control response", error))?;
  let response: Response = serde_json::from_str(&line).map_err(|error| {
    Error::Protocol(format!("failed to decode response: {error}"))
  })?;

  Ok(response)
}
