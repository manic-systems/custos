use std::{
  fs::File,
  io::{
    self,
    Read,
  },
  mem,
  os::fd::{
    AsFd,
    BorrowedFd,
    FromRawFd,
  },
  ptr,
};

use crate::error::{
  Error,
  Result,
};

pub struct ShutdownSignal {
  fd:            File,
  previous_mask: libc::sigset_t,
}

impl ShutdownSignal {
  pub fn install() -> Result<Self> {
    let mask = shutdown_signal_mask();
    let mut previous_mask = empty_signal_set();
    // SAFETY: both pointers refer to initialized sigsets that outlive the call.
    let rc = unsafe {
      libc::pthread_sigmask(
        libc::SIG_BLOCK,
        &raw const mask,
        &raw mut previous_mask,
      )
    };
    if rc != 0 {
      return Err(Error::io(
        "failed to block shutdown signals",
        io::Error::from_raw_os_error(rc),
      ));
    }

    // SAFETY: `mask` is an initialized sigset and -1 asks for a new descriptor.
    let raw_fd = unsafe {
      libc::signalfd(
        -1,
        &raw const mask,
        libc::SFD_NONBLOCK | libc::SFD_CLOEXEC,
      )
    };
    if raw_fd < 0 {
      let error = io::Error::last_os_error();
      restore_mask(&previous_mask);
      return Err(Error::io(
        "failed to create shutdown signal descriptor",
        error,
      ));
    }

    // SAFETY: signalfd returned a fresh descriptor that nothing else owns.
    let fd = unsafe { File::from_raw_fd(raw_fd) };
    Ok(Self { fd, previous_mask })
  }

  pub fn as_fd(&self) -> BorrowedFd<'_> {
    self.fd.as_fd()
  }

  pub fn drain(&self) -> Result<bool> {
    let mut saw_signal = false;
    let mut buffer = [0; mem::size_of::<libc::signalfd_siginfo>()];

    loop {
      match (&self.fd).read(&mut buffer) {
        Ok(_length) => saw_signal = true,
        Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
          return Ok(saw_signal);
        },
        Err(error) if error.kind() == io::ErrorKind::Interrupted => (),
        Err(error) => {
          return Err(Error::io(
            "failed to read shutdown signal descriptor",
            error,
          ));
        },
      }
    }
  }
}

impl Drop for ShutdownSignal {
  fn drop(&mut self) {
    restore_mask(&self.previous_mask);
  }
}

fn empty_signal_set() -> libc::sigset_t {
  let mut set = mem::MaybeUninit::uninit();
  // SAFETY: sigemptyset fully initializes the set it is given.
  unsafe {
    libc::sigemptyset(set.as_mut_ptr());
    set.assume_init()
  }
}

fn shutdown_signal_mask() -> libc::sigset_t {
  let mut mask = empty_signal_set();
  // SAFETY: `mask` is an initialized sigset and both signals are valid.
  unsafe {
    libc::sigaddset(&raw mut mask, libc::SIGTERM);
    libc::sigaddset(&raw mut mask, libc::SIGINT);
  }
  mask
}

fn restore_mask(previous_mask: &libc::sigset_t) {
  // SAFETY: `previous_mask` is the initialized sigset pthread_sigmask filled.
  unsafe {
    libc::pthread_sigmask(libc::SIG_SETMASK, previous_mask, ptr::null_mut());
  }
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
