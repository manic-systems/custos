use std::io;

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, thiserror::Error)]
pub enum Error {
  #[error("{context}: {source}")]
  Io {
    context: String,
    #[source]
    source:  io::Error,
  },
  #[error("configuration error: {0}")]
  Config(String),
  #[error("policy error: {0}")]
  Policy(String),
  #[error("protocol error: {0}")]
  Protocol(String),
  #[error("{context}: {source}")]
  Bus {
    context: String,
    #[source]
    source:  dbus::Error,
  },
}

impl Error {
  pub fn io(context: impl Into<String>, source: io::Error) -> Self {
    Self::Io {
      context: context.into(),
      source,
    }
  }

  pub fn bus(context: impl Into<String>, source: dbus::Error) -> Self {
    Self::Bus {
      context: context.into(),
      source,
    }
  }
}
