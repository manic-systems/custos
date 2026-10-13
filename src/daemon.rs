mod activity;
mod changes;
mod control_server;
mod state;

#[cfg(test)] mod tests;

use std::path::PathBuf;

use activity::wait_for_activity;
use control_server::{
  bind_control_socket,
  cleanup_control_socket,
  handle_client,
};
use tracing::{
  info,
  warn,
};

use self::state::State;
use crate::{
  config::Config,
  error::Result,
  policy::Policy,
  signal::ShutdownSignal,
  sysfs::{
    ControllerAuthorizationState,
    Scanner,
  },
  uevent::UsbEventMonitor,
};

pub fn run_daemon(config: Config, policy: Policy) -> Result<()> {
  policy.validate_for_start(&config)?;
  let scanner = Scanner::new(config.sysfs_root.clone());
  let mut state = State::new(config, policy);
  state.capture_controller_restore_state(&scanner)?;
  let listener = bind_control_socket(&state.config.socket_path)?;
  listener.set_nonblocking(true).map_err(|error| {
    crate::error::Error::io("failed to configure control socket", error)
  })?;
  let _cleanup = DaemonCleanup::new(
    scanner.clone(),
    state.config.socket_path.clone(),
    state.controller_restore.clone(),
  );
  info!(
      socket = %state.config.socket_path.display(),
      "custos daemon listening"
  );

  let mut event_monitor = UsbEventMonitor::open()?;
  info!("listening for USB kernel uevents");
  state.refresh(&scanner)?;
  let shutdown_signal = ShutdownSignal::install()?;

  loop {
    let activity = wait_for_activity(
      &listener,
      event_monitor.as_fd(),
      shutdown_signal.as_fd(),
    )?;

    if activity.shutdown && shutdown_signal.drain()? {
      info!("shutdown signal received");
      return Ok(());
    }

    if activity.control {
      loop {
        let stream = match listener.accept() {
          Ok((stream, _address)) => stream,
          Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => break,
          Err(error) => {
            return Err(crate::error::Error::io(
              "failed to accept control connection",
              error,
            ));
          },
        };

        if let Err(error) = handle_client(stream, &scanner, &mut state) {
          warn!(error = %error, "control request failed");
        }
      }
    }

    if activity.usb_event {
      match event_monitor.drain_usb_device_changes() {
        Ok(true) => {
          info!("rescanning after USB kernel uevent");
          state.refresh(&scanner)?;
        },
        Ok(false) => {},
        Err(error) => {
          warn!(error = %error, "USB kernel uevent monitor failed; exiting");
          return Err(error);
        },
      }
    }
  }
}

struct DaemonCleanup {
  scanner:            Scanner,
  socket_path:        PathBuf,
  controller_restore: Vec<ControllerAuthorizationState>,
}

impl DaemonCleanup {
  const fn new(
    scanner: Scanner,
    socket_path: PathBuf,
    controller_restore: Vec<ControllerAuthorizationState>,
  ) -> Self {
    Self {
      scanner,
      socket_path,
      controller_restore,
    }
  }
}

impl Drop for DaemonCleanup {
  fn drop(&mut self) {
    if !self.controller_restore.is_empty()
      && let Err(error) = self
        .scanner
        .restore_controller_authorized_defaults(&self.controller_restore)
    {
      warn!(error = %error, "failed to restore USB controller authorized_default on daemon exit");
    }

    if let Err(error) = cleanup_control_socket(&self.socket_path) {
      warn!(error = %error, "failed to clean up control socket on daemon exit");
    }
  }
}
