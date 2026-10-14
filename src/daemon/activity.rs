use std::{
  io,
  os::{
    fd::{
      AsFd,
      AsRawFd,
      BorrowedFd,
    },
    unix::net::{
      UnixListener,
      UnixStream,
    },
  },
};

use crate::error::{
  Error,
  Result,
};

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub(super) struct Activity {
  pub(super) shutdown:           bool,
  pub(super) control:            bool,
  pub(super) usb_event:          bool,
  pub(super) closed_subscribers: Vec<usize>,
}

pub(super) fn wait_for_activity(
  listener: &UnixListener,
  event_fd: BorrowedFd<'_>,
  shutdown_fd: BorrowedFd<'_>,
  subscribers: &[UnixStream],
) -> Result<Activity> {
  let mut fds = vec![
    poll_fd(listener.as_fd()),
    poll_fd(event_fd),
    poll_fd(shutdown_fd),
  ];
  fds.extend(
    subscribers
      .iter()
      .map(|subscriber| poll_fd(subscriber.as_fd())),
  );

  let rc = loop {
    // SAFETY: the pointer and count describe `fds`, which is exclusively
    // borrowed for the call.
    let rc =
      unsafe { libc::poll(fds.as_mut_ptr(), fds.len() as libc::nfds_t, -1) };
    if rc >= 0 {
      break rc;
    }

    let error = io::Error::last_os_error();
    if error.kind() != io::ErrorKind::Interrupted {
      return Err(Error::io("failed to wait for daemon activity", error));
    }
  };

  if rc == 0 {
    return Ok(Activity::default());
  }

  // A subscriber only ever reads, so any readiness on its socket is a hangup,
  // an error, or a protocol violation, and each one ends the subscription.
  let closed_subscribers = fds[3..]
    .iter()
    .enumerate()
    .filter(|(_index, fd)| fd.revents != 0)
    .map(|(index, _fd)| index)
    .collect();

  Ok(Activity {
    shutdown: poll_in(fds[2]),
    control: poll_in(fds[0]),
    usb_event: poll_in(fds[1]),
    closed_subscribers,
  })
}

fn poll_fd(fd: BorrowedFd<'_>) -> libc::pollfd {
  libc::pollfd {
    fd:      fd.as_raw_fd(),
    events:  libc::POLLIN,
    revents: 0,
  }
}

const fn poll_in(fd: libc::pollfd) -> bool {
  fd.revents & libc::POLLIN != 0
}
