use std::collections::HashMap;
use std::sync::RwLock;

use anyhow::{Context, Result};

use crate::cli::args::GlobalCliOpts;
use crate::cli::http_client::{api_request_or_offline, ensure_api_ok, ApiHttpError};
use crate::config::ConfigStore;
use crate::control::ControlError;
use crate::i18n::Locale;
use crate::interceptor::dispatcher::ProxyNodeEntry;
use crate::router::{RuleEngine, RuleView};
use crate::transparent::TransparentSettings;

pub(super) const DEFAULT_SELF_PORTS: [u16; 3] = [40001, 40080, 1053];

pub(super) fn control_err_to_cli(err: ControlError, locale: Locale) -> anyhow::Error {
    anyhow::Error::new(ApiHttpError::from_value(
        err.kind.status_code(),
        err.to_localized_value(locale),
        true,
    ))
}

pub(super) struct OfflineRuntime {
    pub(super) store: ConfigStore,
    pub(super) nodes: RwLock<HashMap<u32, ProxyNodeEntry>>,
    pub(super) engine: RuleEngine,
    pub(super) transparent: TransparentSettings,
}

impl OfflineRuntime {
    pub(super) fn save(&self) -> Result<()> {
        self.store
            .save_runtime_with_transparent(&self.nodes, &self.engine, Some(&self.transparent))
    }
}

pub(super) fn load_offline_runtime(config_path: &str) -> Result<OfflineRuntime> {
    let store = ConfigStore::new(config_path);
    let rt = store
        .load_existing_or_default(&DEFAULT_SELF_PORTS)
        .with_context(|| format!("Failed to load configuration file: {}", config_path))?;
    Ok(OfflineRuntime {
        store,
        nodes: RwLock::new(rt.proxy_nodes),
        engine: RuleEngine::new(rt.rules, rt.default_action),
        transparent: rt.transparent_settings,
    })
}

pub(super) fn load_offline_runtime_readonly(config_path: &str) -> Result<OfflineRuntime> {
    let store = ConfigStore::new(config_path);
    let rt = store
        .load_existing(&DEFAULT_SELF_PORTS)
        .with_context(|| format!("Failed to load configuration file: {}", config_path))?;
    Ok(OfflineRuntime {
        store,
        nodes: RwLock::new(rt.proxy_nodes),
        engine: RuleEngine::new(rt.rules, rt.default_action),
        transparent: rt.transparent_settings,
    })
}

pub(super) fn resolve_rule_id_from_views(rules: &[RuleView], id_or_index: u64) -> Option<u64> {
    if rules.iter().any(|r| r.id == id_or_index) {
        return Some(id_or_index);
    }
    if id_or_index >= 1 {
        let idx = (id_or_index as usize) - 1;
        if let Some(r) = rules.get(idx) {
            return Some(r.id);
        }
    }
    None
}

pub(super) fn offline_resolve_rule_id(
    rule_engine: &RuleEngine,
    id_or_index: u64,
    locale: Locale,
) -> Option<u64> {
    let views = rule_engine.list_rules_view_with_locale(locale);
    resolve_rule_id_from_views(&views, id_or_index)
}

pub(super) enum RuleBackend {
    Online { rules: Vec<RuleView> },
    Offline(OfflineRuntime),
}

pub(super) async fn load_rule_backend(opts: &GlobalCliOpts) -> Result<RuleBackend> {
    if let Some((st, val)) = api_request_or_offline(opts, "GET", "/api/rules", None).await? {
        let rules: Vec<RuleView> = serde_json::from_value(ensure_api_ok(st, val)?)?;
        Ok(RuleBackend::Online { rules })
    } else {
        Ok(RuleBackend::Offline(load_offline_runtime(
            &opts.config_path,
        )?))
    }
}
