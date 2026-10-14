use std::{
  collections::HashMap,
  io,
  os::fd::{
    AsRawFd,
    BorrowedFd,
  },
  path::Path,
  time::Duration,
};

use dbus::{
  Message,
  MessageType,
  arg::Variant,
  channel::{
    BusType,
    Channel,
    default_reply,
  },
};
use tracing::{
  info,
  warn,
};

use crate::{
  config::Mode,
  control::{
    DeviceEvent,
    DeviceEventKind,
    EventStream,
    Request,
    Response,
    send_request,
  },
  error::{
    Error,
    Result,
  },
  policy::Action,
};

const BUS_NAME: &str = "org.freedesktop.DBus";
const BUS_PATH: &str = "/org/freedesktop/DBus";
const BUS_LOCAL_INTERFACE: &str = "org.freedesktop.DBus.Local";
const NOTIFICATIONS_NAME: &str = "org.freedesktop.Notifications";
const NOTIFICATIONS_PATH: &str = "/org/freedesktop/Notifications";
const NOTIFICATION_SIGNALS: &str = concat!(
  "type='signal',",
  "sender='org.freedesktop.Notifications',",
  "path='/org/freedesktop/Notifications',",
  "interface='org.freedesktop.Notifications'",
);
const ALLOW_ONCE_ACTION: &str = "allow-once";
const CALL_TIMEOUT: Duration = Duration::from_secs(5);

pub fn run_notifier(socket_path: &Path) -> Result<()> {
  let mode = daemon_mode(socket_path)?;
  let mut notifier = Notifier::connect(socket_path, mode)?;
  let mut events = EventStream::subscribe(socket_path)?;
  info!(
      socket = %socket_path.display(),
      actions = notifier.actions,
      "watching custos device events"
  );

  loop {
    notifier.dispatch()?;

    let ready = wait(events.as_fd(), &notifier.bus)?;
    if ready.events {
      for event in events.read_events()? {
        notifier.show(&event);
      }
    }
    if ready.bus {
      notifier
        .bus
        .read_write(Some(Duration::ZERO))
        .map_err(|()| {
          Error::Protocol("disconnected from the session bus".to_string())
        })?;
    }
  }
}

fn daemon_mode(socket_path: &Path) -> Result<Mode> {
  match send_request(socket_path, &Request::Status)? {
    Response::Status { mode, .. } => Ok(mode),
    Response::Error { message } => Err(Error::Protocol(message)),
    other => {
      Err(Error::Protocol(format!(
        "unexpected status response: {other:?}"
      )))
    },
  }
}

struct Shown {
  notification_id: u32,
  server:          String,
}

struct Notifier<'a> {
  bus:         Channel,
  socket_path: &'a Path,
  mode:        Mode,
  actions:     bool,
  markup:      bool,
  shown:       HashMap<u32, Shown>,
}

impl<'a> Notifier<'a> {
  fn connect(socket_path: &'a Path, mode: Mode) -> Result<Self> {
    let mut bus = Channel::get_private(BusType::Session).map_err(|error| {
      Error::bus("failed to connect to the session bus", error)
    })?;
    bus.set_watch_enabled(true);

    let add_match = Message::method_call(
      &BUS_NAME.into(),
      &BUS_PATH.into(),
      &BUS_NAME.into(),
      &"AddMatch".into(),
    )
    .append1(NOTIFICATION_SIGNALS);
    call(
      &bus,
      add_match,
      "failed to subscribe to notification signals",
    )?;

    let capabilities: Vec<String> = call(
      &bus,
      notifications_call("GetCapabilities"),
      "failed to query the notification server",
    )?
    .read1()
    .map_err(|error| {
      Error::Protocol(format!("invalid notification capabilities: {error}"))
    })?;
    let supports = |capability: &str| {
      capabilities.iter().any(|supported| supported == capability)
    };

    Ok(Self {
      actions: supports("actions"),
      markup: supports("body-markup"),
      bus,
      socket_path,
      mode,
      shown: HashMap::new(),
    })
  }

  fn show(&mut self, event: &DeviceEvent) {
    let device_id = event.device.id;
    if event.kind == DeviceEventKind::Removed {
      if let Some(shown) = self.shown.remove(&device_id) {
        let close = notifications_call("CloseNotification")
          .append1(shown.notification_id);
        // The specification answers with an error when the notification is
        // already gone, which is the common case here.
        let _closed = self.bus.send_with_reply_and_block(close, CALL_TIMEOUT);
      }
      return;
    }

    let offer_allow =
      event.action == Action::Block && self.mode == Mode::Enforce;
    let actions: &[&str] = if offer_allow && self.actions {
      &[ALLOW_ONCE_ACTION, "Allow Once"]
    } else {
      &[]
    };
    let replaces_id = self
      .shown
      .get(&device_id)
      .map_or(0, |shown| shown.notification_id);

    let mut notify = notifications_call("Notify");
    notify.append_all((
      "custos",
      replaces_id,
      "drive-removable-media",
      self.summary(event.action),
      self.body(event),
      actions,
      HashMap::<&str, Variant<u8>>::new(),
      -1_i32,
    ));

    let reply = match call(&self.bus, notify, "failed to show a notification") {
      Ok(reply) => reply,
      Err(error) => {
        warn!(device_id, error = %error, "notification not shown");
        return;
      },
    };
    let (Ok(notification_id), Some(server)) = (reply.read1(), reply.sender())
    else {
      warn!(
        device_id,
        "notification server sent an invalid Notify reply"
      );
      return;
    };

    self.shown.insert(device_id, Shown {
      notification_id,
      server: server.to_string(),
    });
  }

  fn dispatch(&mut self) -> Result<()> {
    while let Some(message) = self.bus.pop_message() {
      self.handle(&message)?;
    }

    Ok(())
  }

  fn handle(&mut self, message: &Message) -> Result<()> {
    match message.msg_type() {
      MessageType::Signal => {},
      MessageType::MethodCall => {
        if let Some(reply) = default_reply(message) {
          self.bus.send(reply).map_err(|()| {
            Error::Protocol("failed to queue a D-Bus reply".to_string())
          })?;
        }
        return Ok(());
      },
      MessageType::MethodReturn | MessageType::Error => return Ok(()),
    }

    let interface = message.interface();
    let member = message.member();
    match (interface.as_deref(), member.as_deref()) {
      (Some(BUS_LOCAL_INTERFACE), Some("Disconnected")) => {
        Err(Error::Protocol(
          "disconnected from the session bus".to_string(),
        ))
      },
      (Some(NOTIFICATIONS_NAME), Some("ActionInvoked")) => {
        if let Ok((notification_id, action)) = message.read2::<u32, &str>()
          && action == ALLOW_ONCE_ACTION
          && let Some(device_id) = self.device_for(message, notification_id)
        {
          // Invoking an action closes the notification, so the decision
          // change that follows must not try to replace it.
          self.shown.remove(&device_id);
          self.allow_once(device_id);
        }
        Ok(())
      },
      (Some(NOTIFICATIONS_NAME), Some("NotificationClosed")) => {
        if let Ok((notification_id, _reason)) = message.read2::<u32, u32>()
          && let Some(device_id) = self.device_for(message, notification_id)
        {
          self.shown.remove(&device_id);
        }
        Ok(())
      },
      _ => Ok(()),
    }
  }

  // Unicast signals bypass match rules, so only the server that returned a
  // notification id may act on it.
  fn device_for(&self, message: &Message, notification_id: u32) -> Option<u32> {
    let sender = message.sender()?;
    self
      .shown
      .iter()
      .find(|(_device_id, shown)| {
        shown.notification_id == notification_id && *shown.server == *sender
      })
      .map(|(device_id, _shown)| *device_id)
  }

  fn allow_once(&self, device_id: u32) {
    let request = Request::Apply {
      id:     device_id,
      action: Action::Allow,
    };
    match send_request(self.socket_path, &request) {
      Ok(Response::Error { message }) => {
        warn!(device_id, message, "failed to allow USB device");
      },
      Ok(_response) => info!(device_id, "allowed USB device until removal"),
      Err(error) => {
        warn!(device_id, error = %error, "failed to allow USB device");
      },
    }
  }

  const fn summary(&self, action: Action) -> &'static str {
    match (action, self.mode) {
      (Action::Allow, Mode::Enforce) => "USB device allowed",
      (Action::Block, Mode::Enforce) => "USB device blocked",
      (Action::Allow, Mode::DryRun) => "USB device would be allowed",
      (Action::Block, Mode::DryRun) => "USB device would be blocked",
    }
  }

  fn body(&self, event: &DeviceEvent) -> String {
    let device = &event.device;
    let name = device
      .product_name
      .as_deref()
      .unwrap_or("Unknown USB device");
    let source = event
      .rule
      .as_ref()
      .map_or_else(|| event.reason.clone(), |rule| format!("rule \"{rule}\""));
    let body = format!(
      "{name}\n{}:{} on port {}\ndevice {}, {source}",
      device.vendor_id, device.product_id, device.port_path, device.id
    );

    body
      .chars()
      .filter(|character| *character == '\n' || !character.is_control())
      .fold(String::with_capacity(body.len()), |mut text, character| {
        match character {
          '&' if self.markup => text.push_str("&amp;"),
          '<' if self.markup => text.push_str("&lt;"),
          '>' if self.markup => text.push_str("&gt;"),
          _ => text.push(character),
        }
        text
      })
  }
}

fn notifications_call(member: &'static str) -> Message {
  Message::method_call(
    &NOTIFICATIONS_NAME.into(),
    &NOTIFICATIONS_PATH.into(),
    &NOTIFICATIONS_NAME.into(),
    &member.into(),
  )
}

fn call(bus: &Channel, message: Message, context: &str) -> Result<Message> {
  bus
    .send_with_reply_and_block(message, CALL_TIMEOUT)
    .map_err(|error| Error::bus(context, error))
}

struct Ready {
  events: bool,
  bus:    bool,
}

fn wait(events: BorrowedFd<'_>, bus: &Channel) -> Result<Ready> {
  let watch = bus.watch();
  let mut bus_events = 0;
  if watch.read {
    bus_events |= libc::POLLIN;
  }
  if watch.write {
    bus_events |= libc::POLLOUT;
  }

  let mut fds = [
    libc::pollfd {
      fd:      events.as_raw_fd(),
      events:  libc::POLLIN,
      revents: 0,
    },
    libc::pollfd {
      fd:      watch.fd,
      events:  bus_events,
      revents: 0,
    },
  ];

  loop {
    // SAFETY: the pointer and count describe `fds`, which is exclusively
    // borrowed for the call.
    let rc =
      unsafe { libc::poll(fds.as_mut_ptr(), fds.len() as libc::nfds_t, -1) };
    if rc >= 0 {
      return Ok(Ready {
        events: fds[0].revents != 0,
        bus:    fds[1].revents != 0,
      });
    }

    let error = io::Error::last_os_error();
    if error.kind() != io::ErrorKind::Interrupted {
      return Err(Error::io("failed to wait for notifier activity", error));
    }
  }
}
