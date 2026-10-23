use std::{
  fs,
  io::{
    BufRead,
    BufReader,
    Write,
  },
  os::unix::{
    fs::PermissionsExt,
    net::{
      UnixListener,
      UnixStream,
    },
  },
  path::Path,
  time::Duration,
};

use tracing::warn;

use super::state::State;
use crate::{
  control::{
    DeviceEvent,
    MAX_CONTROL_FRAME,
    Request,
    Response,
  },
  error::{
    Error,
    Result,
  },
  sysfs::Scanner,
};

const CONTROL_IO_TIMEOUT: Duration = Duration::from_secs(1);

pub(super) fn bind_control_socket(path: &Path) -> Result<UnixListener> {
  if let Some(parent) = path.parent() {
    fs::create_dir_all(parent).map_err(|error| {
      Error::io(
        format!("failed to create socket directory {}", parent.display()),
        error,
      )
    })?;
  }

  if path.exists() {
    match UnixStream::connect(path) {
      Ok(_) => {
        return Err(Error::Config(format!(
          "control socket {} is already in use",
          path.display()
        )));
      },
      Err(error)
        if matches!(
          error.kind(),
          std::io::ErrorKind::ConnectionRefused | std::io::ErrorKind::NotFound
        ) => {},
      Err(error) => {
        return Err(Error::io(
          format!("failed to inspect existing socket {}", path.display()),
          error,
        ));
      },
    }

    fs::remove_file(path).map_err(|error| {
      Error::io(
        format!("failed to remove stale socket {}", path.display()),
        error,
      )
    })?;
  }

  let listener = UnixListener::bind(path).map_err(|error| {
    Error::io(format!("failed to bind {}", path.display()), error)
  })?;
  fs::set_permissions(path, fs::Permissions::from_mode(0o660)).map_err(
    |error| {
      Error::io(
        format!("failed to set permissions on {}", path.display()),
        error,
      )
    },
  )?;
  Ok(listener)
}

pub(super) fn cleanup_control_socket(path: &Path) -> Result<()> {
  match fs::remove_file(path) {
    Ok(()) => Ok(()),
    Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
    Err(error) => {
      Err(Error::io(
        format!("failed to remove control socket {}", path.display()),
        error,
      ))
    },
  }
}

enum Reply {
  Response(Response),
  Subscribe,
}

pub(super) fn handle_client(
  stream: UnixStream,
  scanner: &Scanner,
  state: &mut State,
) -> Result<Option<UnixStream>> {
  configure_client_stream(&stream)?;
  let mut reader = BufReader::new(stream.try_clone().map_err(|error| {
    Error::io("failed to clone control stream for reading", error)
  })?);
  let reply = match read_request(&mut reader)? {
    Ok(request) => {
      match handle_request(&request, scanner, state) {
        Ok(reply) => reply,
        Err(error) => {
          Reply::Response(Response::Error {
            message: error.to_string(),
          })
        },
      }
    },
    Err(message) => Reply::Response(Response::Error { message }),
  };

  match reply {
    Reply::Response(response) => {
      write_response(&stream, &response)?;
      Ok(None)
    },
    Reply::Subscribe => {
      write_response(&stream, &Response::Ok {
        message: "subscribed to device events".to_string(),
      })?;
      stream.set_nonblocking(true).map_err(|error| {
        Error::io("failed to configure event subscriber", error)
      })?;
      Ok(Some(stream))
    },
  }
}

pub(super) fn publish_events(
  subscribers: &mut Vec<UnixStream>,
  events: &[DeviceEvent],
) {
  for event in events {
    let mut payload = match serde_json::to_vec(event) {
      Ok(payload) => payload,
      Err(error) => {
        warn!(error = %error, "failed to encode device event");
        continue;
      },
    };
    payload.push(b'\n');

    subscribers.retain(|mut subscriber| {
      let Err(error) = subscriber.write_all(&payload) else {
        return true;
      };
      if error.kind() != std::io::ErrorKind::BrokenPipe {
        warn!(error = %error, "dropping device event subscriber");
      }
      false
    });
  }
}

fn configure_client_stream(stream: &UnixStream) -> Result<()> {
  stream
    .set_read_timeout(Some(CONTROL_IO_TIMEOUT))
    .map_err(|error| {
      Error::io("failed to set control stream read timeout", error)
    })?;
  stream
    .set_write_timeout(Some(CONTROL_IO_TIMEOUT))
    .map_err(|error| {
      Error::io("failed to set control stream write timeout", error)
    })
}

fn read_request(
  reader: &mut impl BufRead,
) -> Result<std::result::Result<Request, String>> {
  let mut payload = Vec::new();

  loop {
    let available = reader
      .fill_buf()
      .map_err(|error| Error::io("failed to read control request", error))?;
    if available.is_empty() {
      if payload.is_empty() {
        return Ok(Err("empty control request".to_string()));
      }
      return Ok(Err("unterminated control request".to_string()));
    }

    let newline = available.iter().position(|byte| *byte == b'\n');
    let count = newline.map_or(available.len(), |index| index + 1);
    if payload.len() + count > MAX_CONTROL_FRAME {
      return Ok(Err(format!(
        "control request exceeds {MAX_CONTROL_FRAME} bytes"
      )));
    }

    payload.extend_from_slice(&available[..count]);
    reader.consume(count);

    if newline.is_some() {
      break;
    }
  }

  Ok(
    serde_json::from_slice(&payload)
      .map_err(|error| format!("invalid control request: {error}")),
  )
}

fn handle_request(
  request: &Request,
  scanner: &Scanner,
  state: &mut State,
) -> Result<Reply> {
  let response = match request {
    Request::Status => {
      Response::Status {
        mode:           state.config.mode,
        device_count:   state.devices.len(),
        override_count: state.overrides.len(),
        socket_path:    state.config.socket_path.display().to_string(),
        policy_path:    state.config.policy_path.display().to_string(),
      }
    },
    Request::ListDevices => {
      let devices = state.devices.clone();
      Response::Devices { devices }
    },
    Request::DryRunReload => {
      Response::Decisions {
        decisions: state.dry_run_reload(scanner)?,
      }
    },
    Request::Reload => {
      Response::Decisions {
        decisions: state.reload(scanner)?,
      }
    },
    Request::Apply { id, action } => {
      state.apply_override(*id, *action)?;
      Response::Ok {
        message: format!(
          "{} device {id} with manual override",
          action.as_str()
        ),
      }
    },
    Request::ClearOverride { id } => {
      let decision = state.clear_override(*id)?;
      Response::Ok {
        message: format!(
          "cleared manual override for device {id}; policy now {}",
          decision.action.as_str()
        ),
      }
    },
    Request::Subscribe => return Ok(Reply::Subscribe),
  };

  Ok(Reply::Response(response))
}

fn write_response(mut stream: &UnixStream, response: &Response) -> Result<()> {
  let mut payload = serde_json::to_vec(response).map_err(|error| {
    Error::Protocol(format!("failed to encode response: {error}"))
  })?;
  payload.push(b'\n');
  stream
    .write_all(&payload)
    .map_err(|error| Error::io("failed to write control response", error))
}

#[cfg(test)]
mod tests {
  use std::{
    error::Error as StdError,
    io::Cursor,
    os::unix::net::UnixStream,
    time::{
      Duration,
      Instant,
    },
  };

  use super::*;

  type TestResult<T = ()> =
    std::result::Result<T, Box<dyn StdError + Send + Sync>>;

  #[test]
  fn idle_control_request_is_bounded_by_stream_timeout() -> TestResult {
    let (server, _client) = UnixStream::pair()?;
    server.set_read_timeout(Some(Duration::from_millis(10)))?;

    let start = Instant::now();
    let result = read_request(&mut BufReader::new(&server));

    assert!(result.is_err());
    assert!(start.elapsed() < Duration::from_secs(1));
    Ok(())
  }

  #[test]
  fn oversized_control_request_is_rejected() -> TestResult {
    let mut request = vec![b' '; MAX_CONTROL_FRAME + 1];
    request.push(b'\n');
    let Err(message) = read_request(&mut Cursor::new(request))? else {
      return Err("oversized control request was accepted".into());
    };

    assert!(message.contains("control request exceeds"));
    Ok(())
  }
}
