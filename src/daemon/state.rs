use std::collections::{
  BTreeMap,
  BTreeSet,
};

use tracing::{
  info,
  warn,
};

use super::changes::{
  collect_device_change_events,
  log_device_change,
  log_explicit_device_decision,
  log_manual_override,
  log_override_cleared,
};
use crate::{
  config::{
    Config,
    Mode,
  },
  control::{
    DeviceEvent,
    DeviceEventKind,
  },
  device::DeviceState,
  error::{
    Error,
    Result,
  },
  policy::{
    Action,
    Decision,
    Policy,
  },
  sysfs::{
    ControllerAuthorizationState,
    EnforcementOutcome,
    Scanner,
    UsbDevice,
    apply_authorization,
    force_authorization,
    preview_authorization,
  },
};

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub(super) struct DeviceKey {
  sysfs_path: String,
  vendor_id:  String,
  product_id: String,
  serial:     Option<String>,
}

impl From<&UsbDevice> for DeviceKey {
  fn from(device: &UsbDevice) -> Self {
    Self {
      sysfs_path: device.sysfs_path.to_string_lossy().into_owned(),
      vendor_id:  device.vendor_id.clone(),
      product_id: device.product_id.clone(),
      serial:     device.serial.clone(),
    }
  }
}

pub(super) struct State {
  pub(super) config:             Config,
  policy:                        Policy,
  pub(super) devices:            Vec<DeviceState>,
  pub(super) overrides:          BTreeMap<DeviceKey, Action>,
  ids_by_key:                    BTreeMap<DeviceKey, u32>,
  next_id:                       u32,
  pub(super) controller_restore: Vec<ControllerAuthorizationState>,
  events:                        Vec<DeviceEvent>,
}

struct RefreshSnapshot {
  devices:    Vec<DeviceState>,
  ids_by_key: BTreeMap<DeviceKey, u32>,
  next_id:    u32,
}

impl State {
  pub(super) const fn new(config: Config, policy: Policy) -> Self {
    Self {
      config,
      policy,
      devices: Vec::new(),
      overrides: BTreeMap::new(),
      ids_by_key: BTreeMap::new(),
      next_id: 1,
      controller_restore: Vec::new(),
      events: Vec::new(),
    }
  }

  pub(super) fn take_events(&mut self) -> Vec<DeviceEvent> {
    std::mem::take(&mut self.events)
  }

  #[cfg(test)]
  pub(super) const fn active_policy(&self) -> &Policy {
    &self.policy
  }

  pub(super) fn refresh(&mut self, scanner: &Scanner) -> Result<Vec<Decision>> {
    let dry_run = self.is_dry_run();
    self.refresh_controller_defaults(scanner)?;
    let policy = self.policy.clone();
    let mut snapshot = self.build_snapshot(scanner, &policy)?;
    Self::apply_snapshot(&mut snapshot, dry_run)?;
    let decisions = snapshot_decisions(&snapshot);
    self.commit_snapshot(snapshot);
    Ok(decisions)
  }

  pub(super) fn capture_controller_restore_state(
    &mut self,
    scanner: &Scanner,
  ) -> Result<()> {
    if !self.config.controllers.restore_on_shutdown || self.is_dry_run() {
      return Ok(());
    }

    self.controller_restore = scanner.controller_authorization_states()?;
    info!(
      controllers = self.controller_restore.len(),
      "captured USB controller authorized_default restore state"
    );
    Ok(())
  }

  fn decide_with_policy(
    &self,
    device: &UsbDevice,
    policy: &Policy,
  ) -> Decision {
    let key = DeviceKey::from(device);
    if let Some(action) = self.overrides.get(&key) {
      return Decision {
        device_id: device.id,
        action:    *action,
        reason:    "manual override".to_string(),
        rule:      None,
      };
    }

    policy.decide(device)
  }

  pub(super) fn apply_override(
    &mut self,
    id: u32,
    action: Action,
  ) -> Result<Decision> {
    let state = self.device_by_id(id)?;
    let device = state.device.clone();
    let previous_action = state.decision.action;
    let key = DeviceKey::from(&device);
    let decision = Decision {
      device_id: device.id,
      action,
      reason: "manual override".to_string(),
      rule: None,
    };
    if self.apply_device_authorization(&device, action, true)?
      == EnforcementOutcome::DeviceGone
    {
      return Err(Error::Protocol(format!(
        "device id {id} disappeared before manual override could be applied"
      )));
    }
    self.record_device_decision(id, decision.clone());
    log_manual_override(&device, &decision);
    self.overrides.insert(key, action);
    self.record_decision_change(id, previous_action);

    Ok(decision)
  }

  pub(super) fn clear_override(&mut self, id: u32) -> Result<Decision> {
    let state = self.device_by_id(id)?;
    let device = state.device.clone();
    let key = DeviceKey::from(&device);
    let previous_action = state.decision.action;

    let decision = self.policy.decide(&device);
    if self.apply_device_authorization(&device, decision.action, true)?
      == EnforcementOutcome::DeviceGone
    {
      self.overrides.remove(&key);
      return Err(Error::Protocol(format!(
        "device id {id} disappeared before policy could be reapplied"
      )));
    }
    self.record_device_decision(id, decision.clone());
    self.overrides.remove(&key);
    log_override_cleared(&device, previous_action, &decision);
    self.record_decision_change(id, previous_action);

    Ok(decision)
  }

  pub(super) fn dry_run_reload(
    &self,
    scanner: &Scanner,
  ) -> Result<Vec<Decision>> {
    let policy = Policy::load(&self.config.policy_path, &self.config)?;
    policy.validate_for_start(&Config {
      mode: Mode::DryRun,
      ..self.config.clone()
    })?;
    self.preview(scanner, &policy)
  }

  pub(super) fn reload(&mut self, scanner: &Scanner) -> Result<Vec<Decision>> {
    let policy = Policy::load(&self.config.policy_path, &self.config)?;
    policy.validate_for_start(&self.config)?;
    let dry_run = self.is_dry_run();

    self.refresh_controller_defaults(scanner)?;
    let mut candidate = self.build_snapshot(scanner, &policy)?;
    if let Err(error) = Self::apply_snapshot(&mut candidate, dry_run) {
      if !dry_run
        && let Err(rollback_error) = self.rollback_active_policy(scanner)
      {
        return Err(Error::Policy(format!(
          "reload failed after partial apply: {error}; rollback failed: \
           {rollback_error}"
        )));
      }
      return Err(error);
    }

    let decisions = snapshot_decisions(&candidate);
    self.policy = policy;
    self.commit_snapshot(candidate);
    Ok(decisions)
  }

  fn rollback_active_policy(&mut self, scanner: &Scanner) -> Result<()> {
    let policy = self.policy.clone();
    let mut snapshot = self.build_snapshot(scanner, &policy)?;
    Self::apply_snapshot(&mut snapshot, false)?;
    self.commit_snapshot(snapshot);
    Ok(())
  }

  fn preview(
    &self,
    scanner: &Scanner,
    policy: &Policy,
  ) -> Result<Vec<Decision>> {
    let snapshot = self.build_snapshot(scanner, policy)?;
    for state in &snapshot.devices {
      preview_authorization(&state.device, state.decision.action);
    }

    Ok(snapshot_decisions(&snapshot))
  }

  fn refresh_controller_defaults(&self, scanner: &Scanner) -> Result<()> {
    if self.is_dry_run() {
      for update in scanner.controller_authorization_updates(
        self.config.controllers.authorized_default,
      )? {
        info!(
            controller = %update.controller,
            current = update.current.as_deref().map_or("unknown", |current| current),
            desired = %update.desired,
            "would set USB controller authorized_default"
        );
      }
    } else {
      for update in scanner.apply_controller_authorized_default(
        self.config.controllers.authorized_default,
      )? {
        info!(
            controller = %update.controller,
            current = update.current.as_deref().map_or("unknown", |current| current),
            desired = %update.desired,
            "set USB controller authorized_default"
        );
      }
    }

    Ok(())
  }

  fn build_snapshot(
    &self,
    scanner: &Scanner,
    policy: &Policy,
  ) -> Result<RefreshSnapshot> {
    let mut ids_by_key = self.ids_by_key.clone();
    let mut next_id = self.next_id;
    let mut devices = scanner.scan()?;

    for device in &mut devices {
      let key = DeviceKey::from(&*device);
      let id = if let Some(id) = ids_by_key.get(&key) {
        *id
      } else {
        let id = next_id;
        next_id = next_id.checked_add(1).ok_or_else(|| {
          Error::Config("daemon device id counter exhausted".to_string())
        })?;
        ids_by_key.insert(key, id);
        id
      };
      device.id = id;
    }

    let devices = devices
      .into_iter()
      .map(|device| {
        let decision = self.decide_with_policy(&device, policy);
        DeviceState::new(device, decision)
      })
      .collect();

    Ok(RefreshSnapshot {
      devices,
      ids_by_key,
      next_id,
    })
  }

  fn apply_snapshot(
    snapshot: &mut RefreshSnapshot,
    dry_run: bool,
  ) -> Result<()> {
    if dry_run {
      for state in &snapshot.devices {
        preview_authorization(&state.device, state.decision.action);
      }
      return Ok(());
    }

    for state in &mut snapshot.devices {
      match apply_authorization(&state.device, state.decision.action)? {
        EnforcementOutcome::Applied => {
          state.device.authorized = Some(state.decision.action.authorized());
        },
        EnforcementOutcome::DeviceGone => {
          warn!(
              port_path = %state.device.port_path,
              vendor_id = %state.device.vendor_id,
              product_id = %state.device.product_id,
              "USB device disappeared before authorization could be applied"
          );
        },
      }
    }

    Ok(())
  }

  fn commit_snapshot(&mut self, snapshot: RefreshSnapshot) {
    let previous_devices = std::mem::take(&mut self.devices);

    for event in
      collect_device_change_events(&previous_devices, &snapshot.devices)
    {
      log_device_change(&event);
      log_explicit_device_decision(&event);
      self.events.push(event);
    }

    let current_keys: BTreeSet<DeviceKey> = snapshot
      .devices
      .iter()
      .map(|state| DeviceKey::from(&state.device))
      .collect();
    self
      .overrides
      .retain(|key, _action| current_keys.contains(key));
    self.devices = snapshot.devices;
    self.ids_by_key = snapshot.ids_by_key;
    self.next_id = snapshot.next_id;
  }

  fn device_by_id(&self, id: u32) -> Result<&DeviceState> {
    self
      .devices
      .iter()
      .find(|state| state.device.id == id)
      .ok_or_else(|| Error::Protocol(format!("unknown device id {id}")))
  }

  fn is_dry_run(&self) -> bool {
    self.config.mode == Mode::DryRun
  }

  fn apply_device_authorization(
    &self,
    device: &UsbDevice,
    action: Action,
    force: bool,
  ) -> Result<EnforcementOutcome> {
    if self.is_dry_run() {
      return Ok(preview_authorization(device, action));
    }
    if force {
      force_authorization(device, action)
    } else {
      apply_authorization(device, action)
    }
  }

  fn record_decision_change(&mut self, id: u32, previous_action: Action) {
    if let Some(state) = self.devices.iter().find(|state| state.device.id == id)
      && state.decision.action != previous_action
    {
      self.events.push(DeviceEvent::new(
        DeviceEventKind::DecisionChanged,
        state,
        Some(previous_action),
      ));
    }
  }

  fn record_device_decision(&mut self, id: u32, decision: Decision) {
    let dry_run = self.is_dry_run();
    if let Some(state) =
      self.devices.iter_mut().find(|state| state.device.id == id)
    {
      if !dry_run {
        state.device.authorized = Some(decision.action.authorized());
      }
      state.decision = decision;
    }
  }
}

fn snapshot_decisions(snapshot: &RefreshSnapshot) -> Vec<Decision> {
  snapshot
    .devices
    .iter()
    .map(|state| state.decision.clone())
    .collect()
}
