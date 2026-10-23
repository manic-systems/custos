use std::{
  io::{
    self,
    BufRead,
    BufReader,
    Read,
    Write,
  },
  os::{
    fd::{
      AsFd,
      BorrowedFd,
    },
    unix::net::UnixStream,
  },
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
  sysfs::UsbDevice,
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
  Subscribe,
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

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum DeviceEventKind {
  Connected,
  Removed,
  DecisionChanged,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct DeviceEvent {
  pub kind:            DeviceEventKind,
  pub device:          UsbDevice,
  pub action:          Action,
  pub previous_action: Option<Action>,
  pub reason:          String,
  pub rule:            Option<String>,
}

impl DeviceEvent {
  pub fn new(
    kind: DeviceEventKind,
    state: &DeviceState,
    previous_action: Option<Action>,
  ) -> Self {
    Self {
      kind,
      device: state.device.clone(),
      action: state.decision.action,
      previous_action,
      reason: state.decision.reason.clone(),
      rule: state.decision.rule.clone(),
    }
  }
}

pub struct EventStream {
  stream: UnixStream,
  buffer: Vec<u8>,
}

impl EventStream {
  pub fn subscribe(socket_path: &Path) -> Result<Self> {
    let payload = encode_request(&Request::Subscribe)?;
    let mut stream = connect(socket_path)?;
    stream
      .write_all(&payload)
      .map_err(|error| Error::io("failed to write control request", error))?;

    let mut events = Self {
      stream,
      buffer: Vec::new(),
    };
    let line = loop {
      if let Some(line) = events.take_line()? {
        break line;
      }
      let length = events.fill().map_err(|error| {
        Error::io("failed to read the subscription response", error)
      })?;
      if length == 0 {
        return Err(Error::Protocol(
          "daemon closed the connection before confirming the subscription"
            .to_string(),
        ));
      }
    };
    match decode_response(&line)? {
      Response::Ok { .. } => {},
      Response::Error { message } => return Err(Error::Protocol(message)),
      other => {
        return Err(Error::Protocol(format!(
          "unexpected subscription response: {other:?}"
        )));
      },
    }

    events.stream.set_nonblocking(true).map_err(|error| {
      Error::io("failed to configure the event stream", error)
    })?;
    Ok(events)
  }

  pub fn as_fd(&self) -> BorrowedFd<'_> {
    self.stream.as_fd()
  }

  pub fn read_events(&mut self) -> Result<Vec<DeviceEvent>> {
    loop {
      match self.fill() {
        Ok(0) => {
          return Err(Error::Protocol(
            "daemon closed the event stream".to_string(),
          ));
        },
        Ok(_length) => {},
        Err(error) if error.kind() == io::ErrorKind::WouldBlock => break,
        Err(error) => {
          return Err(Error::io("failed to read the event stream", error));
        },
      }
    }

    let mut events = Vec::new();
    while let Some(line) = self.take_line()? {
      events.push(serde_json::from_slice(&line).map_err(|error| {
        Error::Protocol(format!("failed to decode device event: {error}"))
      })?);
    }
    Ok(events)
  }

  fn fill(&mut self) -> io::Result<usize> {
    let mut chunk = [0; 4096];
    loop {
      match self.stream.read(&mut chunk) {
        Ok(length) => {
          self.buffer.extend_from_slice(&chunk[..length]);
          return Ok(length);
        },
        Err(error) if error.kind() == io::ErrorKind::Interrupted => {},
        Err(error) => return Err(error),
      }
    }
  }

  fn take_line(&mut self) -> Result<Option<Vec<u8>>> {
    let Some(newline) = self.buffer.iter().position(|byte| *byte == b'\n')
    else {
      if self.buffer.len() > MAX_CONTROL_FRAME {
        return Err(Error::Protocol(format!(
          "device event exceeds {MAX_CONTROL_FRAME} bytes"
        )));
      }
      return Ok(None);
    };

    let mut line: Vec<u8> = self.buffer.drain(..=newline).collect();
    line.pop();
    Ok(Some(line))
  }
}

pub fn send_request(socket_path: &Path, request: &Request) -> Result<Response> {
  let payload = encode_request(request)?;
  let mut stream = connect(socket_path)?;
  stream
    .write_all(&payload)
    .map_err(|error| Error::io("failed to write control request", error))?;

  let mut line = String::new();
  let mut reader = BufReader::new(stream);
  reader
    .read_line(&mut line)
    .map_err(|error| Error::io("failed to read control response", error))?;
  decode_response(line.as_bytes())
}

fn connect(socket_path: &Path) -> Result<UnixStream> {
  UnixStream::connect(socket_path).map_err(|error| {
    Error::io(
      format!("failed to connect to {}", socket_path.display()),
      error,
    )
  })
}

fn encode_request(request: &Request) -> Result<Vec<u8>> {
  let mut payload = serde_json::to_vec(request).map_err(|error| {
    Error::Protocol(format!("failed to encode request: {error}"))
  })?;
  payload.push(b'\n');
  if payload.len() > MAX_CONTROL_FRAME {
    return Err(Error::Protocol(format!(
      "control request exceeds {MAX_CONTROL_FRAME} bytes"
    )));
  }

  Ok(payload)
}

fn decode_response(line: &[u8]) -> Result<Response> {
  serde_json::from_slice(line).map_err(|error| {
    Error::Protocol(format!("failed to decode response: {error}"))
  })
}
