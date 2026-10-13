use std::{
  io,
  os::fd::{
    AsFd,
    BorrowedFd,
  },
};

use nix::{
  errno::Errno,
  sys::{
    signal::{
      SigSet,
      SigmaskHow,
      Signal,
    },
    signalfd::{
      SfdFlags,
      SignalFd,
    },
  },
};

use crate::error::{
  Error,
  Result,
};

pub struct ShutdownSignal {
  fd:            SignalFd,
  previous_mask: SigSet,
}

impl ShutdownSignal {
  pub fn install() -> Result<Self> {
    let mask = shutdown_signal_mask();
    let previous_mask =
      mask
        .thread_swap_mask(SigmaskHow::SIG_BLOCK)
        .map_err(|error| {
          Error::io("failed to block shutdown signals", io::Error::from(error))
        })?;

    let fd = SignalFd::with_flags(
      &mask,
      SfdFlags::SFD_NONBLOCK | SfdFlags::SFD_CLOEXEC,
    )
    .map_err(|error| {
      restore_mask_after_install_failure(previous_mask);
      Error::io(
        "failed to create shutdown signal descriptor",
        io::Error::from(error),
      )
    })?;

    Ok(Self { fd, previous_mask })
  }

  pub fn as_fd(&self) -> BorrowedFd<'_> {
    self.fd.as_fd()
  }

  pub fn drain(&self) -> Result<bool> {
    let mut saw_signal = false;

    loop {
      match self.fd.read_signal() {
        Ok(Some(_signal)) => saw_signal = true,
        Ok(None) => return Ok(saw_signal),
        Err(Errno::EINTR) => (),
        Err(error) => {
          return Err(Error::io(
            "failed to read shutdown signal descriptor",
            io::Error::from(error),
          ));
        },
      }
    }
  }
}

impl Drop for ShutdownSignal {
  fn drop(&mut self) {
    let _restore_result = self.previous_mask.thread_set_mask();
  }
}

fn shutdown_signal_mask() -> SigSet {
  let mut mask = SigSet::empty();
  mask.add(Signal::SIGTERM);
  mask.add(Signal::SIGINT);
  mask
}

fn restore_mask_after_install_failure(previous_mask: SigSet) {
  let _restore_result = previous_mask.thread_set_mask();
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn shutdown_signal_drain_reports_no_signal_when_empty() -> Result<()> {
    let signal = ShutdownSignal::install()?;

    assert!(!signal.drain()?);
    Ok(())
  }
}
