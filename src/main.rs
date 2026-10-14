mod config;
mod control;
mod daemon;
mod device;
mod error;
mod policy;
mod signal;
mod sysfs;
mod uevent;

use std::{
  fmt::{
    self,
    Write as _,
  },
  path::PathBuf,
};

use clap::{
  CommandFactory,
  Parser,
  Subcommand,
};
use serde::Serialize;
use tracing::level_filters::LevelFilter;
use tracing_subscriber::{
  filter::Targets,
  layer::SubscriberExt,
  util::SubscriberInitExt,
};

use crate::{
  config::{
    Config,
    DEFAULT_CONFIG_PATH,
    Mode,
    load_config,
  },
  control::{
    Request,
    Response,
    send_request,
  },
  daemon::run_daemon,
  device::DeviceState,
  error::{
    Error,
    Result,
  },
  policy::{
    Action,
    Policy,
    generate_policy,
  },
  sysfs::{
    ControllerAuthorizationUpdate,
    Scanner,
  },
};

fn main() {
  let targets = std::env::var("RUST_LOG")
    .ok()
    .and_then(|filter| filter.parse::<Targets>().ok())
    .unwrap_or_else(|| {
      Targets::new()
        .with_default(LevelFilter::WARN)
        .with_target("custos", LevelFilter::INFO)
    });
  tracing_subscriber::registry()
    .with(tracing_subscriber::fmt::layer())
    .with(targets)
    .init();

  if let Err(error) = run(std::env::args().collect()) {
    eprintln!("custos: {error}");
    std::process::exit(1);
  }
}

#[derive(Debug, Parser)]
#[command(name = "custos", about = "USB authorization daemon and control CLI")]
struct Cli {
  #[command(flatten)]
  daemon_options: DaemonOptions,

  #[command(flatten)]
  output_options: OutputOptions,

  #[command(subcommand)]
  command: Option<Command>,
}

#[derive(clap::Args, Debug)]
struct DaemonOptions {
  #[arg(long, help = "Run the daemon")]
  daemon: bool,

  #[arg(long, value_name = "PATH", help = "Daemon configuration path")]
  config: Option<PathBuf>,

  #[arg(long, help = "Run the daemon in dry-run mode")]
  dry_run: bool,

  #[arg(long, help = "Allow enforcing startup without an allow policy")]
  unsafe_empty_policy: bool,
}

#[derive(Clone, Copy, clap::Args, Debug)]
struct OutputOptions {
  #[arg(long, global = true, help = "Print supported command output as JSON")]
  json: bool,
}

#[derive(Debug, Subcommand)]
#[command(rename_all = "kebab-case")]
enum Command {
  /// Show daemon status.
  Status(SocketArgs),
  /// List devices known to the daemon.
  Devices(SocketArgs),
  /// Reload policy and apply it.
  Reload(SocketArgs),
  /// Preview a policy reload without applying it.
  DryRunReload(SocketArgs),
  /// Allow one known device by daemon device ID.
  Allow(ApplyArgs),
  /// Block one known device by daemon device ID.
  Block(ApplyArgs),
  /// Clear a manual allow/block override for one device.
  ClearOverride(ApplyArgs),
  /// Print decisions for the current sysfs state without writing sysfs.
  DryRun(ConfigArgs),
  /// Validate configuration and policy startup safety.
  Validate(ValidateArgs),
  /// Generate an initial allow policy from currently connected devices.
  GeneratePolicy(GeneratePolicyArgs),
}

#[derive(clap::Args, Debug)]
struct SocketArgs {
  /// Control socket path.
  #[arg(long, value_name = "PATH")]
  socket: Option<PathBuf>,
}

#[derive(clap::Args, Debug)]
struct ApplyArgs {
  /// Device ID from `custos devices`.
  device_id: u32,

  /// Control socket path.
  #[arg(long, value_name = "PATH")]
  socket: Option<PathBuf>,
}

#[derive(clap::Args, Debug)]
struct ConfigArgs {
  /// Configuration path.
  #[arg(long, value_name = "PATH")]
  config: Option<PathBuf>,
}

#[derive(clap::Args, Debug)]
struct ValidateArgs {
  /// Configuration path.
  #[arg(long, value_name = "PATH")]
  config: Option<PathBuf>,

  /// Validate as a dry run.
  #[arg(long)]
  dry_run: bool,

  /// Permit an empty enforcing policy during validation.
  #[arg(long)]
  unsafe_empty_policy: bool,
}

#[derive(clap::Args, Debug)]
struct GeneratePolicyArgs {
  /// sysfs root to scan.
  #[arg(long, value_name = "PATH")]
  sysfs_root: Option<PathBuf>,
}

fn run(args: Vec<String>) -> Result<()> {
  let Some(cli) = parse_cli(args)? else {
    return Ok(());
  };

  if cli.daemon_options.daemon {
    if cli.command.is_some() {
      return Err(Error::Usage(
        "`--daemon` cannot be combined with a subcommand".to_string(),
      ));
    }
    if cli.output_options.json {
      return Err(Error::Usage(
        "`--json` cannot be combined with `--daemon`".to_string(),
      ));
    }
    return run_daemon_command(cli);
  }

  if cli.daemon_options.config.is_some()
    || cli.daemon_options.dry_run
    || cli.daemon_options.unsafe_empty_policy
  {
    return Err(Error::Usage(
      "`--config`, `--dry-run`, and `--unsafe-empty-policy` are top-level \
       daemon options; use them with `--daemon` or the relevant subcommand"
        .to_string(),
    ));
  }

  match cli.command {
    Some(command) => run_command(command, cli.output_options),
    None => print_help(),
  }
}

fn parse_cli(args: Vec<String>) -> Result<Option<Cli>> {
  match Cli::try_parse_from(args) {
    Ok(cli) => Ok(Some(cli)),
    Err(error)
      if matches!(
        error.kind(),
        clap::error::ErrorKind::DisplayHelp
          | clap::error::ErrorKind::DisplayVersion
      ) =>
    {
      error
        .print()
        .map_err(|error| Error::io("failed to print clap output", error))?;
      Ok(None)
    },
    Err(error) => Err(Error::Usage(error.to_string())),
  }
}

fn run_daemon_command(cli: Cli) -> Result<()> {
  let config_path = config_path(cli.daemon_options.config);
  let mut config = load_config(&config_path)?;
  if cli.daemon_options.dry_run {
    config.mode = Mode::DryRun;
  }
  if cli.daemon_options.unsafe_empty_policy {
    config.unsafe_allow_empty_policy = true;
  }
  let policy = Policy::load(&config.policy_path, &config)?;
  run_daemon(config, policy)
}

fn run_command(command: Command, output: OutputOptions) -> Result<()> {
  match command {
    Command::Status(args) => {
      print_response(
        send_request(&socket_path(args.socket), &Request::Status)?,
        output,
      )
    },
    Command::Devices(args) => {
      print_response(
        send_request(&socket_path(args.socket), &Request::ListDevices)?,
        output,
      )
    },
    Command::Reload(args) => {
      print_response(
        send_request(&socket_path(args.socket), &Request::Reload)?,
        output,
      )
    },
    Command::DryRunReload(args) => {
      print_response(
        send_request(&socket_path(args.socket), &Request::DryRunReload)?,
        output,
      )
    },
    Command::Allow(args) => apply(args, Action::Allow, output),
    Command::Block(args) => apply(args, Action::Block, output),
    Command::ClearOverride(args) => clear_override(args, output),
    Command::DryRun(args) => dry_run(args, output),
    Command::Validate(args) => {
      reject_json(output, "validate")?;
      validate(args)
    },
    Command::GeneratePolicy(args) => {
      reject_json(output, "generate-policy")?;
      generate(args)
    },
  }
}

fn apply(args: ApplyArgs, action: Action, output: OutputOptions) -> Result<()> {
  print_response(
    send_request(&socket_path(args.socket), &Request::Apply {
      id: args.device_id,
      action,
    })?,
    output,
  )
}

fn clear_override(args: ApplyArgs, output: OutputOptions) -> Result<()> {
  print_response(
    send_request(&socket_path(args.socket), &Request::ClearOverride {
      id: args.device_id,
    })?,
    output,
  )
}

fn dry_run(args: ConfigArgs, output: OutputOptions) -> Result<()> {
  let mut config = load_config(&config_path(args.config))?;
  config.mode = Mode::DryRun;
  let policy = Policy::load(&config.policy_path, &config)?;
  let scanner = Scanner::new(config.sysfs_root);
  let controller_updates = scanner
    .controller_authorization_updates(config.controllers.authorized_default)?;
  let devices = scanner
    .scan()?
    .into_iter()
    .enumerate()
    .map(|(index, mut device)| {
      device.id = u32::try_from(index + 1).map_err(|_| {
        Error::Protocol("too many USB devices to report".to_string())
      })?;
      let decision = policy.decide(&device);
      Ok(DeviceState::new(device, decision))
    })
    .collect::<Result<Vec<_>>>()?;
  let report = DryRunReport {
    kind: "dry-run",
    controller_updates,
    devices,
  };

  print!("{}", render_dry_run_report(&report, output)?);
  Ok(())
}

#[derive(Clone, Debug, Serialize)]
struct DryRunReport {
  #[serde(rename = "type")]
  kind:               &'static str,
  controller_updates: Vec<ControllerAuthorizationUpdate>,
  devices:            Vec<DeviceState>,
}

fn render_dry_run_report(
  report: &DryRunReport,
  options: OutputOptions,
) -> Result<String> {
  if options.json {
    return serde_json::to_string_pretty(report)
      .map(|json| format!("{json}\n"))
      .map_err(|error| {
        Error::Protocol(format!("failed to encode JSON output: {error}"))
      });
  }

  let mut output = String::new();
  if !report.controller_updates.is_empty() {
    render_controller_updates_table(&mut output, &report.controller_updates)?;
  }
  render_device_table(
    &mut output,
    &["DRY RUN REPORT", "DEVICE DECISION PREVIEW"],
    &report.devices,
  )?;
  Ok(output)
}

fn validate(args: ValidateArgs) -> Result<()> {
  let mut config = load_config(&config_path(args.config))?;
  if args.dry_run {
    config.mode = Mode::DryRun;
  }
  if args.unsafe_empty_policy {
    config.unsafe_allow_empty_policy = true;
  }
  let policy = Policy::load(&config.policy_path, &config)?;
  policy.validate_for_start(&config)?;
  print!(
    "{}",
    render_message_report(
      "VALIDATION REPORT",
      "CONFIGURATION AND POLICY ARE VALID"
    )?
  );
  Ok(())
}

fn generate(args: GeneratePolicyArgs) -> Result<()> {
  let scanner = Scanner::new(sysfs_root_path(args.sysfs_root));
  let devices = scanner.scan()?;
  let policy = generate_policy(&devices);
  print!("{}", policy.to_pretty_toml()?);
  Ok(())
}

fn reject_json(options: OutputOptions, command: &str) -> Result<()> {
  if options.json {
    return Err(Error::Usage(format!(
      "`custos {command} --json` is not supported; JSON output is available \
       for daemon-backed commands and dry-run"
    )));
  }

  Ok(())
}

fn print_response(response: Response, output: OutputOptions) -> Result<()> {
  print!("{}", render_response(&response, output)?);
  if let Response::Error { message } = response {
    return Err(Error::Protocol(message));
  }

  Ok(())
}

fn render_response(
  response: &Response,
  options: OutputOptions,
) -> Result<String> {
  if options.json {
    return serde_json::to_string_pretty(response)
      .map(|json| format!("{json}\n"))
      .map_err(|error| {
        Error::Protocol(format!("failed to encode JSON output: {error}"))
      });
  }

  let mut output = String::new();
  match response {
    Response::Ok { message } => {
      output.push_str(&render_message_report(
        "COMMAND RESULT",
        &message.to_ascii_uppercase(),
      )?);
    },
    Response::Status {
      mode,
      device_count,
      override_count,
      socket_path,
      policy_path,
    } => {
      let rows = vec![
        vec!["MODE".to_string(), mode_label(*mode).to_string()],
        vec!["DEVICES".to_string(), device_count.to_string()],
        vec!["MANUAL OVERRIDES".to_string(), override_count.to_string()],
        vec!["SOCKET".to_string(), socket_path.clone()],
        vec!["POLICY".to_string(), policy_path.clone()],
      ];
      render_report_table(
        &mut output,
        &["STATUS REPORT"],
        &["FIELD", "VALUE"],
        &rows,
      )?;
    },
    Response::Devices { devices } => {
      render_device_table(&mut output, &["CONNECTED DEVICES REPORT"], devices)?;
    },
    Response::Decisions { decisions } => {
      render_decisions_table(&mut output, decisions)?;
    },
    Response::Error { message } => {
      return Err(Error::Protocol(message.clone()));
    },
  }

  Ok(output)
}

const REPORT_PRODUCT_TITLE: &str = "CUSTOS USB AUTHORIZATION DAEMON";

fn render_device_table(
  output: &mut String,
  titles: &[&str],
  devices: &[DeviceState],
) -> Result<()> {
  let rows = devices.iter().map(device_table_row).collect::<Vec<_>>();
  render_report_table(
    output,
    titles,
    &[
      "ID",
      "PORT",
      "VID:PID",
      "NAME",
      "HUB",
      "AUTHORIZED",
      "ACTION",
      "SOURCE",
    ],
    &rows,
  )
}

fn device_table_row(status: &DeviceState) -> Vec<String> {
  let device = &status.device;
  let decision = &status.decision;
  vec![
    device.id.to_string(),
    device.port_path.clone(),
    format!("{}:{}", device.vendor_id, device.product_id),
    non_empty_or_dash(device.product_name.as_deref()),
    yes_no(device.is_hub).to_string(),
    authorized_label(device.authorized).to_string(),
    decision.action.as_str().to_ascii_uppercase(),
    decision_source(decision.rule.as_deref(), &decision.reason),
  ]
}

fn render_decisions_table(
  output: &mut String,
  decisions: &[crate::policy::Decision],
) -> Result<()> {
  let rows = decisions
    .iter()
    .map(|decision| {
      vec![
        decision.device_id.to_string(),
        decision.action.as_str().to_ascii_uppercase(),
        decision_source(decision.rule.as_deref(), &decision.reason),
      ]
    })
    .collect::<Vec<_>>();
  render_report_table(
    output,
    &["POLICY DECISION REPORT"],
    &["DEVICE", "ACTION", "SOURCE"],
    &rows,
  )
}

fn render_controller_updates_table(
  output: &mut String,
  updates: &[ControllerAuthorizationUpdate],
) -> Result<()> {
  let rows = updates
    .iter()
    .map(|update| {
      vec![
        update.controller.clone(),
        update
          .current
          .as_deref()
          .map_or_else(|| "UNKNOWN".to_string(), ToString::to_string),
        update.desired.clone(),
      ]
    })
    .collect::<Vec<_>>();
  render_report_table(
    output,
    &["DRY RUN REPORT", "CONTROLLER DEFAULT PREVIEW"],
    &["CONTROLLER", "CURRENT", "DESIRED"],
    &rows,
  )
}

fn render_message_report(title: &str, message: &str) -> Result<String> {
  let mut output = String::new();
  render_report_table(&mut output, &[title], &["MESSAGE"], &[vec![
    message.to_string(),
  ]])?;
  Ok(output)
}

fn render_report_table(
  output: &mut String,
  titles: &[&str],
  headers: &[&str],
  rows: &[Vec<String>],
) -> Result<()> {
  let widths = report_table_widths(headers, rows)?;
  render_report_table_header(output, &widths);
  render_report_table_title(output, &widths, REPORT_PRODUCT_TITLE)?;
  for title in titles {
    render_report_table_title(output, &widths, title)?;
  }
  render_report_table_rule(output, &widths, '├', '┬', '┤');
  render_report_table_row(output, &widths, headers)?;
  render_report_table_rule(output, &widths, '├', '┼', '┤');
  for row in rows {
    let cells = row.iter().map(String::as_str).collect::<Vec<_>>();
    render_report_table_row(output, &widths, &cells)?;
  }
  render_report_table_rule(output, &widths, '└', '┴', '┘');
  Ok(())
}

fn report_table_widths(
  headers: &[&str],
  rows: &[Vec<String>],
) -> Result<Vec<usize>> {
  if headers.is_empty() {
    return Err(Error::Protocol(
      "cannot render a table without headers".to_string(),
    ));
  }

  let mut widths = headers
    .iter()
    .map(|header| header.len())
    .collect::<Vec<_>>();
  for row in rows {
    if row.len() != headers.len() {
      return Err(Error::Protocol(
        "cannot render a table with inconsistent row widths".to_string(),
      ));
    }
    for (index, cell) in row.iter().enumerate() {
      widths[index] = widths[index].max(cell.len());
    }
  }

  Ok(widths)
}

fn render_report_table_header(output: &mut String, widths: &[usize]) {
  let inner_width = report_table_width(widths) - 2;
  output.push('┌');
  output.push_str(&"┬".repeat(inner_width));
  output.push_str("┐\n");
  output.push('├');
  output.push_str(&"┴".repeat(inner_width));
  output.push_str("┤\n");
}

fn render_report_table_row(
  output: &mut String,
  widths: &[usize],
  cells: &[&str],
) -> Result<()> {
  for (cell, width) in cells.iter().zip(widths.iter().copied()) {
    push_fmt(output, format_args!("│ {cell:<width$} "))?;
  }
  output.push_str("│\n");
  Ok(())
}

fn render_report_table_rule(
  output: &mut String,
  widths: &[usize],
  left: char,
  middle: char,
  right: char,
) {
  output.push(left);
  for (index, width) in widths.iter().copied().enumerate() {
    output.push_str(&"─".repeat(width + 2));
    if index + 1 == widths.len() {
      output.push(right);
    } else {
      output.push(middle);
    }
  }
  output.push('\n');
}

fn render_report_table_title(
  output: &mut String,
  widths: &[usize],
  title: &str,
) -> Result<()> {
  let inner_width = report_table_width(widths) - 4;
  push_fmt(
    output,
    format_args!("│ {} │\n", center_text(title, inner_width)),
  )
}

fn report_table_width(widths: &[usize]) -> usize {
  widths.iter().sum::<usize>() + widths.len() * 3 + 1
}

fn center_text(value: &str, width: usize) -> String {
  let padding = width.saturating_sub(value.len());
  let left = padding / 2;
  let right = padding - left;
  format!("{}{}{}", " ".repeat(left), value, " ".repeat(right))
}

fn non_empty_or_dash(value: Option<&str>) -> String {
  value
    .filter(|value| !value.is_empty())
    .map_or_else(|| "-".to_string(), ToString::to_string)
}

const fn yes_no(value: bool) -> &'static str {
  if value { "YES" } else { "NO" }
}

const fn authorized_label(value: Option<bool>) -> &'static str {
  match value {
    Some(true) => "YES",
    Some(false) => "NO",
    None => "UNKNOWN",
  }
}

fn decision_source(rule: Option<&str>, reason: &str) -> String {
  rule.map_or_else(
    || format!("REASON {reason:?}"),
    |rule| format!("RULE {rule:?}"),
  )
}

const fn mode_label(mode: Mode) -> &'static str {
  match mode {
    Mode::Enforce => "ENFORCE",
    Mode::DryRun => "DRY RUN",
  }
}

fn push_fmt(output: &mut String, args: fmt::Arguments<'_>) -> Result<()> {
  output
    .write_fmt(args)
    .map_err(|_| Error::Protocol("failed to render output".to_string()))
}

fn print_help() -> Result<()> {
  let mut command = Cli::command();
  command
    .print_help()
    .map_err(|error| Error::io("failed to print help", error))?;
  println!();
  Ok(())
}

#[allow(clippy::option_if_let_else)]
fn config_path(config: Option<PathBuf>) -> PathBuf {
  match config {
    Some(path) => path,
    None => PathBuf::from(DEFAULT_CONFIG_PATH),
  }
}

#[allow(clippy::option_if_let_else)]
fn socket_path(socket: Option<PathBuf>) -> PathBuf {
  match socket {
    Some(path) => path,
    None => Config::default().socket_path,
  }
}

#[allow(clippy::option_if_let_else)]
fn sysfs_root_path(sysfs_root: Option<PathBuf>) -> PathBuf {
  match sysfs_root {
    Some(path) => path,
    None => Config::default().sysfs_root,
  }
}

#[cfg(test)]
mod tests {
  use std::error::Error as StdError;

  use serde_json::Value;

  use super::*;

  type TestResult<T = ()> = std::result::Result<T, Box<dyn StdError>>;
  const HUMAN_OUTPUT: OutputOptions = OutputOptions { json: false };
  const JSON_OUTPUT: OutputOptions = OutputOptions { json: true };

  fn test_error(message: impl Into<String>) -> Box<dyn StdError> {
    Box::new(std::io::Error::other(message.into()))
  }

  fn parse_command(args: &[&str]) -> TestResult<Cli> {
    parse_cli(args.iter().map(|arg| (*arg).to_string()).collect())?
      .map_or_else(|| Err(test_error("expected parsed command")), Ok)
  }

  #[test]
  fn parses_daemon_flags() -> TestResult {
    let cli = parse_command(&[
      "custos",
      "--daemon",
      "--dry-run",
      "--unsafe-empty-policy",
      "--config",
      "/tmp/config.toml",
    ])?;

    assert!(cli.daemon_options.daemon);
    assert!(cli.daemon_options.dry_run);
    assert!(cli.daemon_options.unsafe_empty_policy);
    assert_eq!(
      cli.daemon_options.config.as_deref(),
      Some(std::path::Path::new("/tmp/config.toml"))
    );
    Ok(())
  }

  #[test]
  fn parses_apply_command() -> TestResult {
    let cli =
      parse_command(&["custos", "allow", "7", "--socket", "/tmp/custos.sock"])?;

    let args = match cli.command {
      Some(Command::Allow(args)) => args,
      other => {
        return Err(test_error(format!(
          "expected allow command, got {other:?}"
        )));
      },
    };
    assert_eq!(args.device_id, 7);
    assert_eq!(
      args.socket.as_deref(),
      Some(std::path::Path::new("/tmp/custos.sock"))
    );
    Ok(())
  }

  #[test]
  fn parses_json_for_daemon_backed_commands() -> TestResult {
    let cli = parse_command(&["custos", "devices", "--json"])?;

    assert!(cli.output_options.json);
    assert!(matches!(cli.command, Some(Command::Devices(_))));
    Ok(())
  }

  #[test]
  fn renders_daemon_response_as_tagged_json() -> TestResult {
    let output = render_response(
      &Response::Status {
        mode:           Mode::DryRun,
        device_count:   3,
        override_count: 1,
        socket_path:    "/run/custos/control.sock".to_string(),
        policy_path:    "/etc/custos/policy.toml".to_string(),
      },
      JSON_OUTPUT,
    )?;
    let value: Value = serde_json::from_str(&output)?;

    assert_eq!(value["type"], "status");
    assert_eq!(value["mode"], "dry-run");
    assert_eq!(value["device_count"], 3);
    assert_eq!(value["override_count"], 1);
    Ok(())
  }

  #[test]
  fn renders_daemon_error_as_tagged_json() -> TestResult {
    let output = render_response(
      &Response::Error {
        message: "unknown device id 99".to_string(),
      },
      JSON_OUTPUT,
    )?;
    let value: Value = serde_json::from_str(&output)?;

    assert_eq!(value["type"], "error");
    assert_eq!(value["message"], "unknown device id 99");
    Ok(())
  }

  #[test]
  fn renders_devices_as_human_table() -> TestResult {
    let output = render_response(
      &Response::Devices {
        devices: vec![DeviceState {
          device:   crate::sysfs::UsbDevice {
            id: 1,
            port_path: "1-2".to_string(),
            vendor_id: "feed".to_string(),
            product_id: "1307".to_string(),
            product_name: Some("Test Keyboard".to_string()),
            authorized: Some(true),
            is_hub: false,
            ..crate::sysfs::UsbDevice::default()
          },
          decision: crate::policy::Decision {
            device_id: 1,
            action:    Action::Allow,
            reason:    "matched rule".to_string(),
            rule:      Some("trusted keyboard".to_string()),
          },
        }],
      },
      HUMAN_OUTPUT,
    )?;

    assert!(output.starts_with('┌'));
    assert!(output.contains("┌┬"));
    assert!(output.contains("├┴"));
    assert!(output.contains("CUSTOS USB AUTHORIZATION DAEMON"));
    assert!(output.contains("CONNECTED DEVICES REPORT"));
    assert!(output.contains('┬'));
    assert!(output.contains('┼'));
    assert!(output.contains('┴'));
    assert!(output.contains("│ ID "));
    assert!(output.contains("VID:PID"));
    assert!(output.contains("│ 1  "));
    assert!(output.contains("1-2"));
    assert!(output.contains("feed:1307"));
    assert!(output.contains("Test Keyboard"));
    assert!(output.contains("NO"));
    assert!(output.contains("YES"));
    assert!(output.contains("ALLOW"));
    assert!(output.contains("RULE \"trusted keyboard\""));
    Ok(())
  }

  #[test]
  fn renders_local_dry_run_as_tagged_json() -> TestResult {
    let report = DryRunReport {
      kind:               "dry-run",
      controller_updates: vec![ControllerAuthorizationUpdate {
        controller: "usb1".to_string(),
        current:    Some("1".to_string()),
        desired:    "0".to_string(),
      }],
      devices:            vec![DeviceState {
        device:   crate::sysfs::UsbDevice {
          id: 1,
          port_path: "1-2".to_string(),
          vendor_id: "feed".to_string(),
          product_id: "1307".to_string(),
          product_name: Some("Test Keyboard".to_string()),
          serial: Some("abc123".to_string()),
          connect_type: Some("hardwired".to_string()),
          authorized: Some(true),
          descriptor_hash: Some("descriptor-sha256".to_string()),
          interfaces: vec!["03:01:01".to_string()],
          is_hub: false,
          ..crate::sysfs::UsbDevice::default()
        },
        decision: crate::policy::Decision {
          device_id: 1,
          action:    Action::Allow,
          reason:    "matched rule".to_string(),
          rule:      Some("trusted keyboard".to_string()),
        },
      }],
    };

    let output = render_dry_run_report(&report, JSON_OUTPUT)?;
    let value: Value = serde_json::from_str(&output)?;

    assert_eq!(value["type"], "dry-run");
    assert_eq!(value["controller_updates"][0]["controller"], "usb1");
    assert_eq!(value["devices"][0]["is_hub"], false);
    assert_eq!(value["devices"][0]["decision"]["action"], "allow");
    Ok(())
  }

  #[test]
  fn renders_local_dry_run_as_human_text() -> TestResult {
    let report = DryRunReport {
      kind:               "dry-run",
      controller_updates: vec![ControllerAuthorizationUpdate {
        controller: "usb1".to_string(),
        current:    Some("1".to_string()),
        desired:    "0".to_string(),
      }],
      devices:            vec![DeviceState {
        device:   crate::sysfs::UsbDevice {
          id: 1,
          port_path: "1-2".to_string(),
          vendor_id: "feed".to_string(),
          product_id: "1307".to_string(),
          authorized: Some(false),
          is_hub: true,
          ..crate::sysfs::UsbDevice::default()
        },
        decision: crate::policy::Decision {
          device_id: 1,
          action:    Action::Allow,
          reason:    "USB hub passthrough".to_string(),
          rule:      None,
        },
      }],
    };

    let output = render_dry_run_report(&report, HUMAN_OUTPUT)?;

    assert!(output.contains("CONTROLLER DEFAULT PREVIEW"));
    assert!(output.contains("│ usb1       │ 1       │ 0"));
    assert!(output.contains("DEVICE DECISION PREVIEW"));
    assert!(output.contains("│ 1  "));
    assert!(output.contains("1-2"));
    assert!(output.contains("feed:1307"));
    assert!(output.contains("YES"));
    assert!(output.contains("ALLOW"));
    assert!(output.contains("REASON \"USB hub passthrough\""));
    Ok(())
  }

  #[test]
  fn rejects_json_for_local_commands() -> TestResult {
    let error = match reject_json(JSON_OUTPUT, "generate-policy") {
      Ok(()) => return Err(test_error("expected JSON rejection")),
      Err(error) => error,
    };

    assert!(error.to_string().contains("not supported"));
    Ok(())
  }

  #[test]
  fn parses_clear_override_command() -> TestResult {
    let cli = parse_command(&["custos", "clear-override", "7"])?;

    let args = match cli.command {
      Some(Command::ClearOverride(args)) => args,
      other => {
        return Err(test_error(format!(
          "expected clear-override command, got {other:?}"
        )));
      },
    };
    assert_eq!(args.device_id, 7);
    Ok(())
  }
}
