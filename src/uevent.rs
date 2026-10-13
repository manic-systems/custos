use std::{
  io,
  os::fd::{
    AsFd,
    AsRawFd,
    BorrowedFd,
    OwnedFd,
  },
};

use nix::{
  errno::Errno,
  sys::socket::{
    AddressFamily,
    MsgFlags,
    NetlinkAddr,
    SockFlag,
    SockProtocol,
    SockType,
    bind,
    recv,
    socket,
  },
};

use crate::error::{
  Error,
  Result,
};

const BUFFER_SIZE: usize = 16 * 1024;

#[derive(Debug)]
pub struct UsbEventMonitor {
  fd:     OwnedFd,
  buffer: [u8; BUFFER_SIZE],
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct Uevent {
  header:    String,
  action:    Option<String>,
  subsystem: Option<String>,
  devtype:   Option<String>,
}

impl UsbEventMonitor {
  pub fn open() -> Result<Self> {
    let fd = socket(
      AddressFamily::Netlink,
      SockType::Datagram,
      SockFlag::SOCK_CLOEXEC | SockFlag::SOCK_NONBLOCK,
      SockProtocol::NetlinkKObjectUEvent,
    )
    .map_err(|error| {
      Error::io(
        "failed to open kobject uevent netlink socket",
        io::Error::from(error),
      )
    })?;

    let address = NetlinkAddr::new(0, 1);
    bind(fd.as_raw_fd(), &address).map_err(|error| {
      Error::io(
        "failed to bind kobject uevent netlink socket",
        io::Error::from(error),
      )
    })?;

    Ok(Self {
      fd,
      buffer: [0; BUFFER_SIZE],
    })
  }

  pub fn drain_usb_device_changes(&mut self) -> Result<bool> {
    let mut changed = false;

    loop {
      match self.recv_one()? {
        Some(event) => {
          if event.is_usb_device_change() {
            changed = true;
          }
        },
        None => return Ok(changed),
      }
    }
  }

  pub fn as_fd(&self) -> BorrowedFd<'_> {
    self.fd.as_fd()
  }

  fn recv_one(&mut self) -> Result<Option<Uevent>> {
    let length = match recv(
      self.fd.as_raw_fd(),
      &mut self.buffer,
      MsgFlags::MSG_DONTWAIT,
    ) {
      Ok(length) => length,
      Err(Errno::EAGAIN | Errno::EINTR) => return Ok(None),
      Err(error) => {
        return Err(Error::io(
          "failed to receive kobject uevent",
          io::Error::from(error),
        ));
      },
    };

    if length == 0 {
      return Ok(None);
    }

    Ok(Some(Uevent::parse(&self.buffer[..length])))
  }
}

impl Uevent {
  fn parse(payload: &[u8]) -> Self {
    let parts = payload
      .split(|byte| *byte == b'\0')
      .filter(|part| !part.is_empty())
      .filter_map(|part| std::str::from_utf8(part).ok());
    let mut event = Self {
      header:    String::new(),
      action:    None,
      subsystem: None,
      devtype:   None,
    };

    for (index, part) in parts.enumerate() {
      if index == 0 && !part.contains('=') {
        event.header = part.to_string();
        continue;
      }

      let Some((key, value)) = part.split_once('=') else {
        continue;
      };

      match key {
        "ACTION" => event.action = Some(value.to_string()),
        "SUBSYSTEM" => event.subsystem = Some(value.to_string()),
        "DEVTYPE" => event.devtype = Some(value.to_string()),
        _ => {},
      }
    }

    event
  }

  fn is_usb_device_change(&self) -> bool {
    let subsystem_is_usb = self.subsystem.as_deref() == Some("usb");
    let devtype_is_device = self.devtype.as_deref() == Some("usb_device");
    let action_is_relevant = matches!(
      self.action.as_deref(),
      Some("add" | "bind" | "change" | "remove" | "unbind")
    );

    subsystem_is_usb && devtype_is_device && action_is_relevant
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn parses_usb_device_add_event() {
    let event = Uevent::parse(
            b"add@/devices/pci0000:00/usb1/1-2\0ACTION=add\0SUBSYSTEM=usb\0DEVTYPE=usb_device\0PRODUCT=feed/1307/1\0",
        );

    assert_eq!(event.header, "add@/devices/pci0000:00/usb1/1-2");
    assert!(event.is_usb_device_change());
  }

  #[test]
  fn ignores_usb_interface_events() {
    let event = Uevent::parse(
            b"add@/devices/pci0000:00/usb1/1-2:1.0\0ACTION=add\0SUBSYSTEM=usb\0DEVTYPE=usb_interface\0",
        );

    assert!(!event.is_usb_device_change());
  }

  #[test]
  fn ignores_non_usb_events() {
    let event = Uevent::parse(
      b"add@/devices/virtual/block/dm-0\0ACTION=add\0SUBSYSTEM=block\0",
    );

    assert!(!event.is_usb_device_change());
  }

  #[test]
  fn parses_payload_without_header() {
    let event =
      Uevent::parse(b"ACTION=add\0SUBSYSTEM=usb\0DEVTYPE=usb_device\0");

    assert_eq!(event.header, "");
    assert!(event.is_usb_device_change());
  }
}
