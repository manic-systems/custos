use std::{
  io,
  os::{
    fd::{
      AsFd,
      BorrowedFd,
    },
    unix::net::UnixListener,
  },
};

use nix::{
  errno::Errno,
  poll::{
    PollFd,
    PollFlags,
    PollTimeout,
    poll,
  },
};

use crate::error::{
  Error,
  Result,
};

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(super) struct Activity {
  pub(super) shutdown:  bool,
  pub(super) control:   bool,
  pub(super) usb_event: bool,
}

pub(super) fn wait_for_activity(
  listener: &UnixListener,
  event_fd: BorrowedFd<'_>,
  shutdown_fd: BorrowedFd<'_>,
) -> Result<Activity> {
  let mut fds = [
    PollFd::new(listener.as_fd(), PollFlags::POLLIN),
    PollFd::new(event_fd, PollFlags::POLLIN),
    PollFd::new(shutdown_fd, PollFlags::POLLIN),
  ];

  let rc = loop {
    match poll(&mut fds, PollTimeout::NONE) {
      Ok(rc) => break rc,
      Err(Errno::EINTR) => {},
      Err(error) => {
        return Err(Error::io(
          "failed to wait for daemon activity",
          io::Error::from(error),
        ));
      },
    }
  };

  if rc == 0 {
    return Ok(Activity::default());
  }

  Ok(Activity {
    shutdown:  poll_in(&fds[2]),
    control:   poll_in(&fds[0]),
    usb_event: poll_in(&fds[1]),
  })
}

fn poll_in(fd: &PollFd<'_>) -> bool {
  fd.revents()
    .is_some_and(|events| events.contains(PollFlags::POLLIN))
}
