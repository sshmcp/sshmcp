use crate::errors::ArrtError;
use crate::storage::{CredentialStore, FileCredentialStore};
use base64::{engine::general_purpose::STANDARD_NO_PAD, Engine};
use directories::{BaseDirs, ProjectDirs};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::path::{Path, PathBuf};
use tokio::io::AsyncWriteExt;

const APP_QUALIFIER: &str = "";
const APP_ORG: &str = "";
const APP_NAME: &str = "sshmcp";

#[derive(Debug, Serialize, Deserialize, Clone, Default)]
pub struct AppConfig {
    #[serde(default)]
    pub profiles: Vec<Profile>,
    #[serde(default)]
    pub mcp: McpConfig,
    #[serde(default)]
    pub approval: ApprovalConfig,
    #[serde(default)]
    pub runtime: RuntimeConfig,
    #[serde(skip)]
    source_path: PathBuf,
    #[serde(skip)]
    source_hash: String,
    /// Internal authorization partition for agent/MCP execution. Never read from YAML.
    #[serde(skip)]
    pub authorization_namespace: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Profile {
    pub name: String,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub via_profile: Option<String>,
    pub target: HostEndpoint,
    #[serde(default)]
    pub bastions: Vec<HostEndpoint>,
    #[serde(default)]
    pub auth: Option<AuthConfig>,
    #[serde(default)]
    pub remote: RemoteConfig,
    #[serde(default)]
    pub agent: AgentConfig,
    #[serde(default)]
    pub bootstrap: BootstrapConfig,
    #[serde(default)]
    pub timeouts: TimeoutConfig,
    #[serde(default)]
    pub keepalive: KeepaliveConfig,
    #[serde(default)]
    pub agent_policy: AgentPolicyConfig,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct AgentPolicyConfig {
    #[serde(default)]
    pub capabilities: AgentCapabilities,
    #[serde(default)]
    pub allowed_read_paths: Vec<String>,
    #[serde(default)]
    pub allowed_write_paths: Vec<String>,
    /// Legacy exact shell command strings agents may execute. When `rules` is
    /// non-empty and this list is empty, ordered command matchers supply the
    /// command authorization.
    #[serde(default)]
    pub allowed_commands: Vec<String>,
    /// Deprecated insecure blacklist. Non-empty values fail validation.
    #[serde(default)]
    pub deny_commands: Vec<String>,
    #[serde(default = "default_audit_command")]
    pub audit_command: bool,
    #[serde(default)]
    pub rules: Vec<PolicyRuleConfig>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct PolicyRuleConfig {
    pub id: String,
    #[serde(rename = "match")]
    pub matcher: PolicyMatchConfig,
    pub effect: PolicyEffectConfig,
    #[serde(default)]
    pub risk: Option<RiskLevelConfig>,
    #[serde(default)]
    pub reason: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone, Default)]
pub struct PolicyMatchConfig {
    pub operation: String,
    #[serde(default)]
    pub commands: Vec<String>,
    #[serde(default)]
    pub paths: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum PolicyEffectConfig {
    Allow,
    Confirm,
    Deny,
}

#[derive(Debug, Serialize, Deserialize, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RiskLevelConfig {
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ApprovalConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default = "default_approval_ttl")]
    pub ttl_seconds: u64,
    #[serde(default)]
    pub storage: ApprovalStorageConfig,
    #[serde(default)]
    pub grants: GrantConfig,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct GrantConfig {
    #[serde(default = "default_grant_max_ttl")]
    pub max_ttl_seconds: u64,
    #[serde(default = "default_grant_max_uses")]
    pub default_max_uses: u64,
    #[serde(default)]
    pub low: GrantRiskConfig,
    #[serde(default)]
    pub medium: GrantRiskConfig,
    #[serde(default = "default_high_grants")]
    pub high: GrantRiskConfig,
    #[serde(default = "default_critical_grants")]
    pub critical: GrantRiskConfig,
}
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct GrantRiskConfig {
    #[serde(default = "default_true")]
    pub task: bool,
    #[serde(default = "default_true")]
    pub time: bool,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ApprovalStorageConfig {
    #[serde(rename = "type", default = "default_sqlite_type")]
    pub kind: String,
    #[serde(default)]
    pub path: Option<String>,
}

impl Default for ApprovalStorageConfig {
    fn default() -> Self {
        Self {
            kind: default_sqlite_type(),
            path: None,
        }
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct AgentCapabilities {
    #[serde(default = "default_true")]
    pub exec: bool,
    #[serde(default = "default_true")]
    pub read: bool,
    #[serde(default = "default_true")]
    pub write: bool,
    #[serde(default = "default_true")]
    pub upload: bool,
    #[serde(default = "default_true")]
    pub download: bool,
    #[serde(default)]
    pub tunnel: bool,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct McpConfig {
    #[serde(default = "default_mcp_listen")]
    pub listen: String,
    #[serde(default)]
    pub auth: McpAuthConfig,
    #[serde(default)]
    pub tenants: Vec<McpTenantConfig>,
    #[serde(default)]
    pub allowed_origins: Vec<String>,
    #[serde(default)]
    pub local_file_root: Option<String>,
    #[serde(default)]
    pub task_id_env: Option<String>,
    #[serde(default)]
    pub profile_management: ProfileManagementConfig,
}

#[derive(Debug, Serialize, Deserialize, Clone, Default)]
pub struct ProfileManagementConfig {
    #[serde(default)]
    pub enabled: bool,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct McpAuthConfig {
    #[serde(rename = "type", default = "default_auth_type")]
    pub kind: String,
    #[serde(default = "default_token_env")]
    pub token_env: String,
    #[serde(default)]
    pub resource: Option<String>,
    #[serde(default)]
    pub issuer: Option<String>,
    #[serde(default)]
    pub jwks_url: Option<String>,
    #[serde(default)]
    pub scopes: Vec<String>,
    #[serde(default = "default_audience_claim")]
    pub audience_claim: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct McpTenantConfig {
    pub resource: String,
    #[serde(default)]
    pub tenant_id: Option<String>,
    pub config_path: String,
    #[serde(default)]
    pub local_file_root: Option<String>,
    #[serde(default)]
    pub task_id_env: Option<String>,
    #[serde(default)]
    pub profile_management: Option<ProfileManagementConfig>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct HostEndpoint {
    pub host: String,
    pub user: String,
    #[serde(default = "default_port")]
    pub port: u16,
    #[serde(default)]
    pub auth: Option<AuthConfig>,
    /// OpenSSH-style SHA256 fingerprint of this hop's server key.
    #[serde(default)]
    pub host_key_sha256: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone, Copy, Default, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RuntimeMode {
    #[default]
    SelfHosted,
    Cloud,
}

#[derive(Debug, Serialize, Deserialize, Clone, Copy, Default, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum HostKeyMode {
    Strict,
    #[default]
    InsecureCompatibility,
}

#[derive(Debug, Serialize, Deserialize, Clone, Default)]
pub struct RuntimeConfig {
    #[serde(default)]
    pub mode: RuntimeMode,
    #[serde(default)]
    pub host_key_mode: HostKeyMode,
}

#[derive(Debug, Serialize, Deserialize, Clone, Default)]
pub struct AuthConfig {
    #[serde(rename = "type", default)]
    pub kind: Option<AuthKind>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key_path: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub passphrase: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub password: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub credential_id: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AuthKind {
    Key,
    Password,
    External,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct RemoteConfig {
    #[serde(default = "default_shell")]
    pub shell: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct AgentConfig {
    #[serde(default = "default_agent_enabled")]
    pub manage: bool,
    #[serde(default = "default_agent_remote_path")]
    pub remote_path: String,
    #[serde(default = "default_agent_version")]
    pub version: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct BootstrapConfig {
    #[serde(default = "default_bootstrap_enabled")]
    pub enabled: bool,
    #[serde(default = "default_remote_temp_dir")]
    pub remote_temp_dir: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct TimeoutConfig {
    #[serde(default = "default_exec_timeout")]
    pub exec_seconds: u64,
    #[serde(default = "default_idle_timeout")]
    pub idle_session_seconds: u64,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct KeepaliveConfig {
    #[serde(default = "default_keepalive_interval")]
    pub interval_seconds: u64,
    #[serde(default = "default_keepalive_count")]
    pub count_max: u64,
}

#[derive(Debug, Clone)]
pub struct ResolvedProfile {
    pub name: String,
    pub transport: ResolvedTransport,
    pub agent: AgentConfig,
    pub timeouts: TimeoutConfig,
    pub keepalive: KeepaliveConfig,
    pub host_key_mode: HostKeyMode,
    pub runtime_mode: RuntimeMode,
}

#[derive(Debug, Clone)]
pub enum ResolvedTransport {
    Direct {
        target: ResolvedEndpoint,
        bastions: Vec<ResolvedEndpoint>,
    },
    Delegated {
        via_profile: String,
        target: DelegatedEndpoint,
    },
}

#[derive(Debug, Clone)]
pub struct ResolvedEndpoint {
    pub host: String,
    pub user: String,
    pub port: u16,
    pub auth: ResolvedAuthConfig,
    pub host_key_sha256: Option<String>,
}

#[derive(Debug, Clone)]
pub struct DelegatedEndpoint {
    pub host: String,
    pub user: String,
    pub port: u16,
}

#[derive(Debug, Clone)]
pub enum ResolvedAuthConfig {
    Key {
        key_path: PathBuf,
        passphrase: Option<String>,
    },
    Password {
        password: String,
    },
}

fn default_port() -> u16 {
    22
}

fn default_shell() -> String {
    "bash -lc".to_string()
}

fn default_agent_enabled() -> bool {
    true
}

fn default_agent_remote_path() -> String {
    "/tmp/sshmcpd".to_string()
}

fn default_agent_version() -> String {
    env!("CARGO_PKG_VERSION").to_string()
}

fn default_bootstrap_enabled() -> bool {
    true
}

fn default_remote_temp_dir() -> String {
    "/tmp".to_string()
}

fn default_exec_timeout() -> u64 {
    600
}

fn default_idle_timeout() -> u64 {
    900
}

fn default_keepalive_interval() -> u64 {
    30
}

fn default_keepalive_count() -> u64 {
    3
}

fn default_true() -> bool {
    true
}

fn default_audit_command() -> bool {
    true
}
fn default_approval_ttl() -> u64 {
    300
}
fn default_grant_max_ttl() -> u64 {
    3600
}
fn default_grant_max_uses() -> u64 {
    20
}
fn default_high_grants() -> GrantRiskConfig {
    GrantRiskConfig {
        task: true,
        time: false,
    }
}
fn default_critical_grants() -> GrantRiskConfig {
    GrantRiskConfig {
        task: false,
        time: false,
    }
}
fn default_sqlite_type() -> String {
    "sqlite".to_string()
}

fn default_mcp_listen() -> String {
    "127.0.0.1:8765".to_string()
}

fn default_auth_type() -> String {
    "bearer".to_string()
}

fn default_token_env() -> String {
    "SSHMCP_MCP_TOKEN".to_string()
}

fn default_audience_claim() -> String {
    "aud".to_string()
}

impl Default for RemoteConfig {
    fn default() -> Self {
        Self {
            shell: default_shell(),
        }
    }
}

impl Default for AgentConfig {
    fn default() -> Self {
        Self {
            manage: default_agent_enabled(),
            remote_path: default_agent_remote_path(),
            version: default_agent_version(),
        }
    }
}

impl Default for BootstrapConfig {
    fn default() -> Self {
        Self {
            enabled: default_bootstrap_enabled(),
            remote_temp_dir: default_remote_temp_dir(),
        }
    }
}

impl Default for TimeoutConfig {
    fn default() -> Self {
        Self {
            exec_seconds: default_exec_timeout(),
            idle_session_seconds: default_idle_timeout(),
        }
    }
}

impl Default for KeepaliveConfig {
    fn default() -> Self {
        Self {
            interval_seconds: default_keepalive_interval(),
            count_max: default_keepalive_count(),
        }
    }
}

impl Default for AgentCapabilities {
    fn default() -> Self {
        Self {
            exec: true,
            read: true,
            write: true,
            upload: true,
            download: true,
            tunnel: false,
        }
    }
}

impl Default for AgentPolicyConfig {
    fn default() -> Self {
        Self {
            capabilities: AgentCapabilities::default(),
            allowed_read_paths: Vec::new(),
            allowed_write_paths: Vec::new(),
            allowed_commands: Vec::new(),
            deny_commands: Vec::new(),
            audit_command: true,
            rules: Vec::new(),
        }
    }
}

impl Default for ApprovalConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            ttl_seconds: default_approval_ttl(),
            storage: ApprovalStorageConfig::default(),
            grants: GrantConfig::default(),
        }
    }
}

impl Default for GrantRiskConfig {
    fn default() -> Self {
        Self {
            task: true,
            time: true,
        }
    }
}
impl Default for GrantConfig {
    fn default() -> Self {
        Self {
            max_ttl_seconds: default_grant_max_ttl(),
            default_max_uses: default_grant_max_uses(),
            low: GrantRiskConfig::default(),
            medium: GrantRiskConfig::default(),
            high: default_high_grants(),
            critical: default_critical_grants(),
        }
    }
}

impl Default for McpAuthConfig {
    fn default() -> Self {
        Self {
            kind: default_auth_type(),
            token_env: default_token_env(),
            resource: None,
            issuer: None,
            jwks_url: None,
            scopes: Vec::new(),
            audience_claim: default_audience_claim(),
        }
    }
}

impl Default for McpConfig {
    fn default() -> Self {
        Self {
            listen: default_mcp_listen(),
            auth: McpAuthConfig::default(),
            tenants: Vec::new(),
            allowed_origins: Vec::new(),
            local_file_root: None,
            task_id_env: None,
            profile_management: ProfileManagementConfig::default(),
        }
    }
}

impl AppConfig {
    pub async fn load() -> Result<Self, ArrtError> {
        let path = config_path()?;
        Self::load_from_path(path).await
    }

    pub async fn load_from_path(path: PathBuf) -> Result<Self, ArrtError> {
        let raw = tokio::fs::read_to_string(&path).await.map_err(|err| {
            ArrtError::Config(format!("failed to read {}: {}", path.display(), err))
        })?;
        let mut config = parse_config(&raw, &path)?;
        config.source_path = path;
        config.source_hash = format!("{:x}", Sha256::digest(raw.as_bytes()));
        config.validate()?;
        Ok(config)
    }

    pub fn validate(&self) -> Result<(), ArrtError> {
        self.validate_with_credentials(&FileCredentialStore)
    }

    pub fn validate_with_credentials(
        &self,
        credentials: &dyn CredentialStore,
    ) -> Result<(), ArrtError> {
        let mut names = HashSet::new();
        if self.profiles.is_empty() && self.mcp.tenants.is_empty() {
            return Err(ArrtError::Config("no profiles configured".to_string()));
        }
        self.validate_mcp()?;
        if self.runtime.mode == RuntimeMode::Cloud
            && self.runtime.host_key_mode != HostKeyMode::Strict
        {
            return Err(ArrtError::Config(
                "Cloud runtime requires runtime.host_key_mode: strict".into(),
            ));
        }
        for profile in &self.profiles {
            if !names.insert(profile.name.clone()) {
                return Err(ArrtError::Config(format!(
                    "duplicate profile name: {}",
                    profile.name
                )));
            }
        }
        for profile in &self.profiles {
            let mut stack = Vec::new();
            let _ = self.resolve_profile_with(&profile.name, &mut stack, credentials)?;
        }
        if self.approval.ttl_seconds == 0 {
            return Err(ArrtError::Config(
                "approval.ttl_seconds must be greater than zero".into(),
            ));
        }
        if self.approval.storage.kind != "sqlite" {
            return Err(ArrtError::Config(
                "approval.storage.type must be sqlite".into(),
            ));
        }
        if self.approval.grants.max_ttl_seconds == 0 || self.approval.grants.default_max_uses == 0 {
            return Err(ArrtError::Config(
                "approval grant TTL and max uses must be greater than zero".into(),
            ));
        }
        Ok(())
    }

    fn validate_mcp(&self) -> Result<(), ArrtError> {
        if self.mcp.auth.kind.eq_ignore_ascii_case("bearer") {
            return Ok(());
        }
        if !self.mcp.auth.kind.eq_ignore_ascii_case("oauth_jwt") {
            return Err(ArrtError::Config(format!(
                "unsupported mcp.auth.type: {}",
                self.mcp.auth.kind
            )));
        }
        let auth = &self.mcp.auth;
        if auth.resource.as_deref().unwrap_or_default().is_empty() {
            return Err(ArrtError::Config(
                "mcp.auth.resource is required for oauth_jwt".into(),
            ));
        }
        if auth.issuer.as_deref().unwrap_or_default().is_empty() {
            return Err(ArrtError::Config(
                "mcp.auth.issuer is required for oauth_jwt".into(),
            ));
        }
        if auth.audience_claim.trim().is_empty() {
            return Err(ArrtError::Config(
                "mcp.auth.audience_claim must not be empty".into(),
            ));
        }
        let mut resources = HashSet::new();
        for tenant in &self.mcp.tenants {
            if tenant.resource.trim().is_empty() {
                return Err(ArrtError::Config(
                    "mcp.tenants[].resource must not be empty".into(),
                ));
            }
            if tenant.config_path.trim().is_empty() {
                return Err(ArrtError::Config(
                    "mcp.tenants[].config_path must not be empty".into(),
                ));
            }
            if tenant
                .tenant_id
                .as_deref()
                .is_some_and(|id| id.trim().is_empty())
            {
                return Err(ArrtError::Config(
                    "mcp.tenants[].tenant_id must not be empty".into(),
                ));
            }
            if !resources.insert(tenant.resource.clone()) {
                return Err(ArrtError::Config(format!(
                    "duplicate mcp tenant resource: {}",
                    tenant.resource
                )));
            }
        }
        Ok(())
    }

    pub fn profile_fingerprint(&self, name: &str) -> Result<String, ArrtError> {
        let profile = self.profile(name)?;
        let bytes = serde_json::to_vec(&profile)
            .map_err(|err| ArrtError::Config(format!("serialize profile: {err}")))?;
        Ok(format!("{:x}", Sha256::digest(bytes)))
    }

    pub fn require_mutable_yaml(&self) -> Result<(), ArrtError> {
        if std::fs::symlink_metadata(&self.source_path)
            .map(|metadata| metadata.file_type().is_symlink())
            .unwrap_or(false)
        {
            return Err(ArrtError::Config(
                "profile management does not write through configuration symlinks".into(),
            ));
        }
        let extension = self
            .source_path
            .extension()
            .and_then(|value| value.to_str())
            .unwrap_or_default()
            .to_ascii_lowercase();
        if extension == "yaml" || extension == "yml" {
            Ok(())
        } else {
            Err(ArrtError::UnsupportedConfigFormat(
                self.source_path.display().to_string(),
            ))
        }
    }

    pub async fn write_yaml_atomic(&self, expected_file_hash: &str) -> Result<(), ArrtError> {
        let path = &self.source_path;
        self.require_mutable_yaml()?;
        let current = tokio::fs::read(path).await?;
        let current_hash = format!("{:x}", Sha256::digest(&current));
        if current_hash != expected_file_hash {
            return Err(ArrtError::ConfigConflict(
                "configuration changed while the update was prepared".into(),
            ));
        }
        let serialized = serde_yaml::to_string(self)
            .map_err(|err| ArrtError::Config(format!("serialize YAML: {err}")))?;
        let parent = path.parent().unwrap_or_else(|| Path::new("."));
        let file_name = path
            .file_name()
            .and_then(|value| value.to_str())
            .unwrap_or("profiles.yaml");
        let temp_path = parent.join(format!(".{file_name}.{}.tmp", uuid::Uuid::new_v4()));
        let permissions = tokio::fs::metadata(path).await?.permissions();
        let result = async {
            let mut options = tokio::fs::OpenOptions::new();
            options.create_new(true).write(true);
            #[cfg(unix)]
            options.mode(0o600);
            let mut file = options.open(&temp_path).await?;
            file.write_all(serialized.as_bytes()).await?;
            file.flush().await?;
            file.sync_all().await?;
            tokio::fs::set_permissions(&temp_path, permissions).await?;
            let latest = tokio::fs::read(path).await?;
            if format!("{:x}", Sha256::digest(&latest)) != expected_file_hash {
                return Err(ArrtError::ConfigConflict(
                    "configuration changed before the update was committed".into(),
                ));
            }
            tokio::fs::rename(&temp_path, path).await?;
            #[cfg(unix)]
            std::fs::File::open(parent)?.sync_all()?;
            Ok::<(), ArrtError>(())
        }
        .await;
        if result.is_err() {
            let _ = tokio::fs::remove_file(&temp_path).await;
        }
        result
    }

    pub async fn file_hash(&self) -> Result<String, ArrtError> {
        if !self.source_hash.is_empty() {
            return Ok(self.source_hash.clone());
        }
        let bytes = tokio::fs::read(&self.source_path).await?;
        Ok(format!("{:x}", Sha256::digest(bytes)))
    }

    pub async fn reload_if_file_backed(&self) -> Result<Self, ArrtError> {
        if self.source_path.as_os_str().is_empty() {
            Ok(self.clone())
        } else {
            let raw = tokio::fs::read_to_string(&self.source_path)
                .await
                .map_err(|err| {
                    ArrtError::Config(format!(
                        "failed to read {}: {}",
                        self.source_path.display(),
                        err
                    ))
                })?;
            let mut config = parse_config(&raw, &self.source_path)?;
            config.source_path = self.source_path.clone();
            config.source_hash = format!("{:x}", Sha256::digest(raw.as_bytes()));
            config.validate()?;
            Ok(config)
        }
    }

    pub fn profile(&self, name: &str) -> Result<Profile, ArrtError> {
        self.profiles
            .iter()
            .find(|profile| profile.name == name)
            .cloned()
            .ok_or_else(|| ArrtError::ProfileNotFound(name.to_string()))
    }

    pub fn resolved_profile(&self, name: &str) -> Result<ResolvedProfile, ArrtError> {
        let mut stack = Vec::new();
        self.resolve_profile_with(name, &mut stack, &FileCredentialStore)
    }

    pub fn resolved_profile_with_credentials(
        &self,
        name: &str,
        credentials: &dyn CredentialStore,
    ) -> Result<ResolvedProfile, ArrtError> {
        self.resolve_profile_with(name, &mut Vec::new(), credentials)
    }

    #[cfg(test)]
    pub fn profile_summary(&self, name: &str) -> Result<Value, ArrtError> {
        self.profile_summary_with_credentials(name, &FileCredentialStore)
    }

    pub fn profile_summary_with_credentials(
        &self,
        name: &str,
        credentials: &dyn CredentialStore,
    ) -> Result<Value, ArrtError> {
        self.profile_summary_with_stack(name, &mut Vec::new(), credentials)
    }

    fn resolve_profile_with(
        &self,
        name: &str,
        stack: &mut Vec<String>,
        credentials: &dyn CredentialStore,
    ) -> Result<ResolvedProfile, ArrtError> {
        if stack.iter().any(|item| item == name) {
            let mut cycle = stack.clone();
            cycle.push(name.to_string());
            return Err(ArrtError::Config(format!(
                "profile dependency cycle: {}",
                cycle.join(" -> ")
            )));
        }
        stack.push(name.to_string());
        let profile = self.profile(name)?;
        let result = profile.resolve(self, self.config_base_dir(), stack, credentials);
        let _ = stack.pop();
        result
    }

    fn profile_summary_with_stack(
        &self,
        name: &str,
        stack: &mut Vec<String>,
        credentials: &dyn CredentialStore,
    ) -> Result<Value, ArrtError> {
        if stack.iter().any(|item| item == name) {
            let mut cycle = stack.clone();
            cycle.push(name.to_string());
            return Err(ArrtError::Config(format!(
                "profile dependency cycle: {}",
                cycle.join(" -> ")
            )));
        }
        stack.push(name.to_string());
        let profile = self.profile(name)?;
        let result = profile.sanitized_json(self, self.config_base_dir(), stack, credentials);
        let _ = stack.pop();
        result
    }

    fn config_base_dir(&self) -> &Path {
        self.source_path.parent().unwrap_or_else(|| Path::new("."))
    }

    pub fn source_path(&self) -> &Path {
        &self.source_path
    }
}

impl Profile {
    fn resolve(
        &self,
        config: &AppConfig,
        base_dir: &Path,
        stack: &mut Vec<String>,
        credentials: &dyn CredentialStore,
    ) -> Result<ResolvedProfile, ArrtError> {
        self.validate_common()?;

        let transport = if let Some(via_profile) = &self.via_profile {
            if !self.bastions.is_empty() {
                return Err(ArrtError::Config(format!(
                    "profile {} via_profile cannot be combined with bastions",
                    self.name
                )));
            }
            if self.auth.is_some() || self.target.auth.is_some() {
                return Err(ArrtError::Config(format!(
                    "profile {} via_profile uses the upstream profile's SSH capability and must not set auth",
                    self.name
                )));
            }

            let _ = config.resolve_profile_with(via_profile, stack, credentials)?;
            ResolvedTransport::Delegated {
                via_profile: via_profile.clone(),
                target: self
                    .target
                    .as_delegated(&format!("profile {} target", self.name))?,
            }
        } else {
            self.target.validate(
                self.auth.as_ref(),
                base_dir,
                &format!("profile {} target", self.name),
                credentials,
            )?;
            for (index, bastion) in self.bastions.iter().enumerate() {
                bastion.validate(
                    self.auth.as_ref(),
                    base_dir,
                    &format!("profile {} bastion {}", self.name, index + 1),
                    credentials,
                )?;
            }
            ResolvedTransport::Direct {
                target: self.target.resolve(
                    self.auth.as_ref(),
                    base_dir,
                    &format!("profile {} target", self.name),
                    credentials,
                )?,
                bastions: self
                    .bastions
                    .iter()
                    .enumerate()
                    .map(|(index, bastion)| {
                        bastion.resolve(
                            self.auth.as_ref(),
                            base_dir,
                            &format!("profile {} bastion {}", self.name, index + 1),
                            credentials,
                        )
                    })
                    .collect::<Result<Vec<_>, _>>()?,
            }
        };

        Ok(ResolvedProfile {
            name: self.name.clone(),
            transport,
            agent: self.agent.clone(),
            timeouts: self.timeouts.clone(),
            keepalive: self.keepalive.clone(),
            host_key_mode: config.runtime.host_key_mode,
            runtime_mode: config.runtime.mode,
        })
    }

    fn sanitized_json(
        &self,
        config: &AppConfig,
        base_dir: &Path,
        stack: &mut Vec<String>,
        credentials: &dyn CredentialStore,
    ) -> Result<Value, ArrtError> {
        let target = if self.via_profile.is_some() {
            self.target.sanitized_without_auth()?
        } else {
            self.target.sanitized_json(
                self.auth.as_ref(),
                base_dir,
                &format!("profile {} target", self.name),
            )?
        };

        let via_profile = if let Some(via_profile) = &self.via_profile {
            let _ = config.resolve_profile_with(via_profile, stack, credentials)?;
            json!(via_profile)
        } else {
            Value::Null
        };

        Ok(json!({
            "name": self.name,
            "description": self.description,
            "via_profile": via_profile,
            "target": target,
            "bastions": self.bastions.iter().enumerate().map(|(index, bastion)| {
                bastion.sanitized_json(
                    self.auth.as_ref(),
                    base_dir,
                    &format!("profile {} bastion {}", self.name, index + 1),
                )
            }).collect::<Result<Vec<_>, _>>()?,
            "remote": self.remote,
            "agent": self.agent,
            "bootstrap": self.bootstrap,
            "timeouts": self.timeouts,
            "keepalive": self.keepalive,
            "agent_policy": self.agent_policy,
        }))
    }

    fn validate_common(&self) -> Result<(), ArrtError> {
        if self.name.trim().is_empty() {
            return Err(ArrtError::Config("profile name is empty".to_string()));
        }
        if self.target.host.trim().is_empty() {
            return Err(ArrtError::Config(format!(
                "profile {} target host is empty",
                self.name
            )));
        }
        if self.target.user.trim().is_empty() {
            return Err(ArrtError::Config(format!(
                "profile {} target user is empty",
                self.name
            )));
        }
        if self.agent.manage && self.agent.remote_path.trim().is_empty() {
            return Err(ArrtError::Config(format!(
                "profile {} agent.remote_path is empty",
                self.name
            )));
        }
        for path in self
            .agent_policy
            .allowed_read_paths
            .iter()
            .chain(&self.agent_policy.allowed_write_paths)
        {
            if !path.starts_with('/') {
                return Err(ArrtError::Config(format!(
                    "profile {} agent policy path must be absolute: {}",
                    self.name, path
                )));
            }
        }
        if !self.agent_policy.deny_commands.is_empty() {
            return Err(ArrtError::Config(format!(
                "profile {} agent_policy.deny_commands is not a security boundary; use exact allowed_commands",
                self.name
            )));
        }
        let mut rule_ids = HashSet::new();
        for rule in &self.agent_policy.rules {
            if rule.id.trim().is_empty() {
                return Err(ArrtError::Config(format!(
                    "profile {} has an empty policy rule id",
                    self.name
                )));
            }
            if !rule_ids.insert(&rule.id) {
                return Err(ArrtError::Config(format!(
                    "profile {} has duplicate policy rule id {}",
                    self.name, rule.id
                )));
            }
            if !matches!(
                rule.matcher.operation.as_str(),
                "exec" | "read" | "write" | "upload" | "download"
            ) {
                return Err(ArrtError::Config(format!(
                    "profile {} rule {} has unsupported operation {}",
                    self.name, rule.id, rule.matcher.operation
                )));
            }
            if rule.matcher.operation == "exec" && rule.matcher.commands.is_empty() {
                return Err(ArrtError::Config(format!(
                    "profile {} exec rule {} has no commands",
                    self.name, rule.id
                )));
            }
            if rule.matcher.operation != "exec" && rule.matcher.paths.is_empty() {
                return Err(ArrtError::Config(format!(
                    "profile {} path rule {} has no paths",
                    self.name, rule.id
                )));
            }
        }
        Ok(())
    }
}

impl HostEndpoint {
    fn validate(
        &self,
        fallback_auth: Option<&AuthConfig>,
        base_dir: &Path,
        label: &str,
        credentials: &dyn CredentialStore,
    ) -> Result<(), ArrtError> {
        if self.host.trim().is_empty() {
            return Err(ArrtError::Config(format!("{label} host is empty")));
        }
        if self.user.trim().is_empty() {
            return Err(ArrtError::Config(format!("{label} user is empty")));
        }
        if let Some(pin) = &self.host_key_sha256 {
            let bytes = pin
                .strip_prefix("SHA256:")
                .and_then(|encoded| STANDARD_NO_PAD.decode(encoded).ok());
            if bytes.is_none_or(|bytes| bytes.len() != 32) {
                return Err(ArrtError::Config(format!(
                    "{label} host_key_sha256 must be an OpenSSH SHA256 fingerprint"
                )));
            }
        }
        let auth = self
            .auth
            .as_ref()
            .or(fallback_auth)
            .ok_or_else(|| ArrtError::Config(format!("{label} auth is missing")))?;
        let _ = credentials.resolve(auth, base_dir, label)?;
        Ok(())
    }

    fn resolve(
        &self,
        fallback_auth: Option<&AuthConfig>,
        base_dir: &Path,
        label: &str,
        credentials: &dyn CredentialStore,
    ) -> Result<ResolvedEndpoint, ArrtError> {
        self.validate(fallback_auth, base_dir, label, credentials)?;
        let auth = self
            .auth
            .as_ref()
            .or(fallback_auth)
            .ok_or_else(|| ArrtError::Config(format!("{label} auth is missing")))?;
        Ok(ResolvedEndpoint {
            host: self.host.clone(),
            user: self.user.clone(),
            port: self.port,
            auth: credentials.resolve(auth, base_dir, label)?,
            host_key_sha256: self.host_key_sha256.clone(),
        })
    }

    fn as_delegated(&self, label: &str) -> Result<DelegatedEndpoint, ArrtError> {
        if self.host.trim().is_empty() {
            return Err(ArrtError::Config(format!("{label} host is empty")));
        }
        if self.user.trim().is_empty() {
            return Err(ArrtError::Config(format!("{label} user is empty")));
        }
        Ok(DelegatedEndpoint {
            host: self.host.clone(),
            user: self.user.clone(),
            port: self.port,
        })
    }

    fn sanitized_json(
        &self,
        fallback_auth: Option<&AuthConfig>,
        base_dir: &Path,
        label: &str,
    ) -> Result<Value, ArrtError> {
        let auth = self
            .auth
            .as_ref()
            .or(fallback_auth)
            .ok_or_else(|| ArrtError::Config(format!("{label} auth is missing")))?;
        Ok(json!({
            "host": self.host,
            "user": self.user,
            "port": self.port,
            "auth": auth.summary(base_dir, label)?,
        }))
    }

    fn sanitized_without_auth(&self) -> Result<Value, ArrtError> {
        if self.host.trim().is_empty() {
            return Err(ArrtError::Config("target host is empty".to_string()));
        }
        if self.user.trim().is_empty() {
            return Err(ArrtError::Config("target user is empty".to_string()));
        }
        Ok(json!({
            "host": self.host,
            "user": self.user,
            "port": self.port,
            "auth": Value::Null,
        }))
    }
}

impl AuthConfig {
    pub(crate) fn resolve(
        &self,
        base_dir: &Path,
        label: &str,
    ) -> Result<ResolvedAuthConfig, ArrtError> {
        match self.infer_kind(label)? {
            AuthKind::Key => {
                if self.credential_id.is_some() {
                    return Err(ArrtError::Config(format!(
                        "{label} cannot combine credential_id with key_path"
                    )));
                }
                let key_path = self
                    .key_path
                    .as_deref()
                    .ok_or_else(|| ArrtError::Config(format!("{label} auth.key_path is empty")))?;
                if self.password.is_some() {
                    return Err(ArrtError::Config(format!(
                        "{label} auth.type=key cannot also set password"
                    )));
                }
                Ok(ResolvedAuthConfig::Key {
                    key_path: resolve_config_path(base_dir, key_path)?,
                    passphrase: self.passphrase.clone(),
                })
            }
            AuthKind::Password => {
                if self.credential_id.is_some() {
                    return Err(ArrtError::Config(format!(
                        "{label} cannot combine credential_id with password"
                    )));
                }
                let password = self
                    .password
                    .clone()
                    .ok_or_else(|| ArrtError::Config(format!("{label} auth.password is empty")))?;
                if self.key_path.is_some() {
                    return Err(ArrtError::Config(format!(
                        "{label} auth.type=password cannot also set key_path"
                    )));
                }
                if self.passphrase.is_some() {
                    return Err(ArrtError::Config(format!(
                        "{label} auth.type=password cannot also set passphrase"
                    )));
                }
                Ok(ResolvedAuthConfig::Password { password })
            }
            AuthKind::External => Err(ArrtError::Config(format!(
                "{label} credential_id requires an external CredentialStore"
            ))),
        }
    }

    fn infer_kind(&self, label: &str) -> Result<AuthKind, ArrtError> {
        if self
            .credential_id
            .as_deref()
            .is_some_and(|id| id.trim().is_empty())
        {
            return Err(ArrtError::Config(format!(
                "{label} credential_id must not be empty"
            )));
        }
        if self.kind == Some(AuthKind::External)
            && (self.credential_id.is_none()
                || self.key_path.is_some()
                || self.passphrase.is_some()
                || self.password.is_some())
        {
            return Err(ArrtError::Config(format!(
                "{label} external auth requires only credential_id"
            )));
        }
        match self.kind {
            Some(kind) => Ok(kind),
            None => match (
                self.key_path.is_some() || self.passphrase.is_some(),
                self.password.is_some(),
                self.credential_id.is_some(),
            ) {
                (true, false, false) => Ok(AuthKind::Key),
                (false, true, false) => Ok(AuthKind::Password),
                (false, false, true) => Ok(AuthKind::External),
                (false, false, false) => Err(ArrtError::Config(format!(
                    "{label} auth is missing type and credentials"
                ))),
                (true, true, false) => Err(ArrtError::Config(format!(
                    "{label} auth must not set both key credentials and password"
                ))),
                _ => Err(ArrtError::Config(format!(
                    "{label} auth must specify exactly one credential source"
                ))),
            },
        }
    }

    fn summary(&self, base_dir: &Path, label: &str) -> Result<Value, ArrtError> {
        if self.infer_kind(label)? == AuthKind::External {
            return Ok(json!({"type":"external","has_password":false,"has_passphrase":false}));
        }
        Ok(match self.resolve(base_dir, label)? {
            ResolvedAuthConfig::Key {
                key_path: _,
                passphrase,
            } => json!({
                "type": AuthKind::Key.as_str(),
                "has_password": false,
                "has_passphrase": passphrase.is_some(),
            }),
            ResolvedAuthConfig::Password { .. } => json!({
                "type": AuthKind::Password.as_str(),
                "has_password": true,
                "has_passphrase": false,
            }),
        })
    }
}

impl AuthKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Key => "key",
            Self::Password => "password",
            Self::External => "external",
        }
    }
}

impl ResolvedProfile {
    pub fn direct_chain(&self) -> Option<Vec<&ResolvedEndpoint>> {
        match &self.transport {
            ResolvedTransport::Direct { target, bastions } => {
                let mut chain = Vec::with_capacity(bastions.len() + 1);
                chain.extend(bastions.iter());
                chain.push(target);
                Some(chain)
            }
            ResolvedTransport::Delegated { .. } => None,
        }
    }
}

pub fn project_dirs() -> Result<ProjectDirs, ArrtError> {
    let current = ProjectDirs::from(APP_QUALIFIER, APP_ORG, APP_NAME).ok_or_else(|| {
        ArrtError::Config("failed to resolve application directories".to_string())
    })?;
    let legacy = ProjectDirs::from("opensource", "opensource", "ssh-gateway")
        .ok_or_else(|| ArrtError::Config("failed to resolve legacy directories".to_string()))?;
    if current.data_local_dir().exists() {
        return Ok(current);
    }
    if legacy.data_local_dir().exists() {
        return Ok(legacy);
    }
    if let Some(arrt) = ProjectDirs::from("opensource", "opensource", "arrt") {
        if arrt.data_local_dir().exists() {
            return Ok(arrt);
        }
    }
    Ok(current)
}

fn env_value_with_legacy<F: Fn(&str) -> Option<String>>(name: &str, lookup: F) -> Option<String> {
    let names: &[&str] = match name {
        "SSHMCP_CONFIG_PATH" | "SSH_GATEWAY_CONFIG_PATH" | "ARRT_CONFIG_PATH" => &[
            "SSHMCP_CONFIG_PATH",
            "SSH_GATEWAY_CONFIG_PATH",
            "ARRT_CONFIG_PATH",
        ],
        "SSHMCP_MCP_TOKEN" | "SSH_GATEWAY_MCP_TOKEN" => {
            &["SSHMCP_MCP_TOKEN", "SSH_GATEWAY_MCP_TOKEN"]
        }
        "SSHMCP_TASK_ID" | "SSH_GATEWAY_TASK_ID" => &["SSHMCP_TASK_ID", "SSH_GATEWAY_TASK_ID"],
        _ => std::slice::from_ref(&name),
    };
    names.iter().find_map(|candidate| lookup(candidate))
}

pub fn env_with_legacy(name: &str) -> Result<String, std::env::VarError> {
    env_value_with_legacy(name, |candidate| std::env::var(candidate).ok())
        .ok_or(std::env::VarError::NotPresent)
}

#[cfg_attr(windows, allow(dead_code))]
pub fn ensure_runtime_dirs() -> Result<PathBuf, ArrtError> {
    let dirs = project_dirs()?;
    let runtime_dir = dirs.data_local_dir().to_path_buf();
    std::fs::create_dir_all(runtime_dir.join("control"))?;
    std::fs::create_dir_all(runtime_dir.join("logs"))?;
    Ok(runtime_dir)
}

pub fn config_path() -> Result<PathBuf, ArrtError> {
    if let Some(override_path) =
        env_value_with_legacy("SSHMCP_CONFIG_PATH", |name| std::env::var(name).ok())
    {
        let path = PathBuf::from(override_path);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        return Ok(path);
    }
    let current = ProjectDirs::from(APP_QUALIFIER, APP_ORG, APP_NAME).ok_or_else(|| {
        ArrtError::Config("failed to resolve application directories".to_string())
    })?;
    let legacy = ProjectDirs::from("opensource", "opensource", "ssh-gateway")
        .ok_or_else(|| ArrtError::Config("failed to resolve legacy directories".to_string()))?;
    let mut dirs = vec![
        current.config_dir().to_path_buf(),
        legacy.config_dir().to_path_buf(),
    ];
    if let Some(arrt) = ProjectDirs::from("opensource", "opensource", "arrt") {
        dirs.push(arrt.config_dir().to_path_buf());
    }
    for dir in &dirs {
        for name in ["profiles.yaml", "profiles.yml", "profiles.toml"] {
            let path = dir.join(name);
            if path.exists() {
                return Ok(path);
            }
        }
    }
    let path = dirs[0].join("profiles.yaml");
    std::fs::create_dir_all(&dirs[0])?;
    Ok(path)
}

pub fn config_path_display() -> Result<String, ArrtError> {
    Ok(config_path()?.display().to_string())
}

fn resolve_config_path(base_dir: &Path, raw: &str) -> Result<PathBuf, ArrtError> {
    let expanded = expand_home(raw)?;
    if expanded.is_absolute() {
        return Ok(expanded);
    }
    Ok(base_dir.join(expanded))
}

fn expand_home(raw: &str) -> Result<PathBuf, ArrtError> {
    if raw == "~" {
        return home_dir();
    }
    if let Some(rest) = raw.strip_prefix("~/").or_else(|| raw.strip_prefix("~\\")) {
        return Ok(home_dir()?.join(rest));
    }
    Ok(PathBuf::from(raw))
}

fn home_dir() -> Result<PathBuf, ArrtError> {
    BaseDirs::new()
        .map(|dirs| dirs.home_dir().to_path_buf())
        .ok_or_else(|| ArrtError::Config("failed to resolve home directory".to_string()))
}

fn parse_config(raw: &str, path: &Path) -> Result<AppConfig, ArrtError> {
    match path
        .extension()
        .and_then(|value| value.to_str())
        .map(|value| value.to_ascii_lowercase())
        .as_deref()
    {
        Some("yaml") | Some("yml") => serde_yaml::from_str(raw)
            .map_err(|err| ArrtError::Config(format!("invalid yaml: {err}"))),
        Some("toml") => {
            toml::from_str(raw).map_err(|err| ArrtError::Config(format!("invalid toml: {err}")))
        }
        _ => serde_yaml::from_str(raw)
            .or_else(|_| toml::from_str(raw))
            .map_err(|err| ArrtError::Config(format!("invalid config: {err}"))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn external_credential_reference_uses_injected_store() {
        struct MockCredentials;
        impl CredentialStore for MockCredentials {
            fn resolve(
                &self,
                auth: &AuthConfig,
                _base_dir: &Path,
                _label: &str,
            ) -> Result<ResolvedAuthConfig, ArrtError> {
                assert_eq!(auth.credential_id.as_deref(), Some("credential-1"));
                Ok(ResolvedAuthConfig::Password {
                    password: "provider-secret".into(),
                })
            }
        }
        let config: AppConfig = serde_yaml::from_str("profiles:\n  - name: remote\n    target:\n      host: example.com\n      user: root\n      auth:\n        type: external\n        credential_id: credential-1\n").unwrap();
        assert!(config.validate().is_err());
        config.validate_with_credentials(&MockCredentials).unwrap();
        let resolved = config
            .resolved_profile_with_credentials("remote", &MockCredentials)
            .unwrap();
        assert!(matches!(
            resolved.transport,
            ResolvedTransport::Direct {
                target: ResolvedEndpoint {
                    auth: ResolvedAuthConfig::Password { .. },
                    ..
                },
                ..
            }
        ));
        let summary = config.profile_summary("remote").unwrap();
        assert_eq!(summary["target"]["auth"]["type"], "external");
        assert!(!summary.to_string().contains("provider-secret"));
    }
    fn set_base_dir(config: &mut AppConfig) {
        config.source_path = PathBuf::from("C:/config/profiles.yaml");
    }

    #[test]
    fn parses_legacy_profile_auth() {
        let raw = r#"
            [[profiles]]
            name = "gpu11"

            [profiles.target]
            host = "gpu11"
            user = "root"

            [profiles.auth]
            key_path = "~/.ssh/id_ed25519"
        "#;

        let mut config: AppConfig = toml::from_str(raw).unwrap();
        set_base_dir(&mut config);
        config.validate().unwrap();
        let resolved = config.resolved_profile("gpu11").unwrap();
        let ResolvedTransport::Direct { target, .. } = resolved.transport else {
            panic!("expected direct transport");
        };
        match target.auth {
            ResolvedAuthConfig::Key { .. } => {}
            _ => panic!("expected key auth"),
        }
        assert_eq!(target.port, 22);
        assert_eq!(resolved.agent.remote_path, "/tmp/sshmcpd");
    }

    #[test]
    fn resolves_per_hop_auth() {
        let raw = r#"
            [[profiles]]
            name = "gpu11"

            [profiles.target]
            host = "gpu11"
            user = "ubuntu"

            [profiles.target.auth]
            type = "password"
            password = "secret"

            [[profiles.bastions]]
            host = "vger"
            user = "root"

            [profiles.bastions.auth]
            type = "key"
            key_path = "./id_ed25519"
        "#;

        let mut config: AppConfig = toml::from_str(raw).unwrap();
        set_base_dir(&mut config);
        config.validate().unwrap();
        let resolved = config.resolved_profile("gpu11").unwrap();
        let ResolvedTransport::Direct { target, bastions } = resolved.transport else {
            panic!("expected direct transport");
        };
        match &target.auth {
            ResolvedAuthConfig::Password { password } => assert_eq!(password, "secret"),
            _ => panic!("expected password auth"),
        }
        match &bastions[0].auth {
            ResolvedAuthConfig::Key {
                key_path,
                passphrase,
            } => {
                assert_eq!(
                    key_path.file_name().and_then(|value| value.to_str()),
                    Some("id_ed25519")
                );
                assert!(passphrase.is_none());
            }
            _ => panic!("expected key auth"),
        }
    }

    #[test]
    fn resolves_via_profile_transport() {
        let raw = r#"
            [[profiles]]
            name = "vger"

            [profiles.target]
            host = "111.186.43.31"
            user = "root"

            [profiles.target.auth]
            type = "key"
            key_path = "./id_ed25519"

            [[profiles]]
            name = "gpu11"
            via_profile = "vger"

            [profiles.target]
            host = "gpu11"
            user = "root"
        "#;

        let mut config: AppConfig = toml::from_str(raw).unwrap();
        set_base_dir(&mut config);
        config.validate().unwrap();
        let resolved = config.resolved_profile("gpu11").unwrap();
        let ResolvedTransport::Delegated {
            via_profile,
            target,
        } = resolved.transport
        else {
            panic!("expected delegated transport");
        };
        assert_eq!(via_profile, "vger");
        assert_eq!(target.host, "gpu11");
        assert_eq!(target.user, "root");
    }

    #[test]
    fn detects_via_profile_cycle() {
        let raw = r#"
            [[profiles]]
            name = "a"
            via_profile = "b"

            [profiles.target]
            host = "a"
            user = "root"

            [[profiles]]
            name = "b"
            via_profile = "a"

            [profiles.target]
            host = "b"
            user = "root"
        "#;

        let mut config: AppConfig = toml::from_str(raw).unwrap();
        set_base_dir(&mut config);
        let error = config.validate().unwrap_err();
        assert!(error.to_string().contains("profile dependency cycle"));
    }

    #[test]
    fn profile_summary_redacts_password() {
        let raw = r#"
            [[profiles]]
            name = "vger"

            [profiles.target]
            host = "vger"
            user = "root"

            [profiles.target.auth]
            type = "password"
            password = "super-secret"
        "#;

        let mut config: AppConfig = toml::from_str(raw).unwrap();
        set_base_dir(&mut config);
        let summary = config.profile_summary("vger").unwrap();
        let encoded = serde_json::to_string(&summary).unwrap();
        assert!(encoded.contains("\"type\":\"password\""));
        assert!(encoded.contains("\"has_password\":true"));
        assert!(encoded.contains("\"has_passphrase\":false"));
        assert!(!encoded.contains("super-secret"));
    }

    #[test]
    fn resolves_key_passphrase_and_redacts_it() {
        let raw = r#"
            [[profiles]]
            name = "dcim"

            [profiles.target]
            host = "dcim"
            user = "root"

            [profiles.target.auth]
            type = "key"
            key_path = "./id_rsa_2048"
            passphrase = "secret-passphrase"
        "#;

        let mut config: AppConfig = toml::from_str(raw).unwrap();
        set_base_dir(&mut config);
        config.validate().unwrap();

        let resolved = config.resolved_profile("dcim").unwrap();
        let ResolvedTransport::Direct { target, .. } = resolved.transport else {
            panic!("expected direct transport");
        };
        match target.auth {
            ResolvedAuthConfig::Key {
                key_path,
                passphrase,
            } => {
                assert_eq!(
                    key_path.file_name().and_then(|value| value.to_str()),
                    Some("id_rsa_2048")
                );
                assert_eq!(passphrase.as_deref(), Some("secret-passphrase"));
            }
            _ => panic!("expected key auth"),
        }

        let summary = config.profile_summary("dcim").unwrap();
        let encoded = serde_json::to_string(&summary).unwrap();
        assert!(encoded.contains("\"type\":\"key\""));
        assert!(encoded.contains("\"has_passphrase\":true"));
        assert!(!encoded.contains("secret-passphrase"));
    }

    #[test]
    fn infers_key_auth_when_passphrase_is_present() {
        let raw = r#"
            [[profiles]]
            name = "dcim"

            [profiles.target]
            host = "dcim"
            user = "root"

            [profiles.target.auth]
            key_path = "./id_rsa_2048"
            passphrase = "secret-passphrase"
        "#;

        let mut config: AppConfig = toml::from_str(raw).unwrap();
        set_base_dir(&mut config);
        config.validate().unwrap();

        let resolved = config.resolved_profile("dcim").unwrap();
        let ResolvedTransport::Direct { target, .. } = resolved.transport else {
            panic!("expected direct transport");
        };
        match target.auth {
            ResolvedAuthConfig::Key {
                key_path,
                passphrase,
            } => {
                assert_eq!(
                    key_path.file_name().and_then(|value| value.to_str()),
                    Some("id_rsa_2048")
                );
                assert_eq!(passphrase.as_deref(), Some("secret-passphrase"));
            }
            _ => panic!("expected key auth"),
        }
    }

    #[test]
    fn rejects_password_auth_with_passphrase() {
        let raw = r#"
            [[profiles]]
            name = "bad"

            [profiles.target]
            host = "bad"
            user = "root"

            [profiles.target.auth]
            type = "password"
            password = "secret"
            passphrase = "nope"
        "#;

        let mut config: AppConfig = toml::from_str(raw).unwrap();
        set_base_dir(&mut config);
        let error = config.validate().unwrap_err();
        assert!(error
            .to_string()
            .contains("target auth.type=password cannot also set passphrase"));
    }

    #[test]
    fn rejects_mixed_password_and_key_passphrase_without_type() {
        let raw = r#"
            [[profiles]]
            name = "bad"

            [profiles.target]
            host = "bad"
            user = "root"

            [profiles.target.auth]
            password = "secret"
            passphrase = "nope"
        "#;

        let mut config: AppConfig = toml::from_str(raw).unwrap();
        set_base_dir(&mut config);
        let error = config.validate().unwrap_err();
        assert!(error
            .to_string()
            .contains("target auth must not set both key credentials and password"));
    }

    #[test]
    fn loads_yaml_preferred_over_toml() {
        let yaml = r#"
profiles:
  - name: vger
    target:
      host: 111.186.43.31
      user: root
      auth:
        type: key
        key_path: ./id_ed25519
"#;
        let mut config = parse_config(yaml, Path::new("profiles.yaml")).unwrap();
        set_base_dir(&mut config);
        config.validate().unwrap();
        assert_eq!(config.profiles[0].name, "vger");
    }

    #[test]
    fn legacy_config_gets_safe_agent_and_mcp_defaults() {
        let raw = r#"
profiles:
  - name: legacy
    target:
      host: legacy
      user: root
      auth:
        type: password
        password: secret
"#;
        let mut config = parse_config(raw, Path::new("profiles.yaml")).unwrap();
        set_base_dir(&mut config);
        config.validate().unwrap();
        assert!(config.profiles[0].agent_policy.capabilities.exec);
        assert!(!config.profiles[0].agent_policy.capabilities.tunnel);
        assert!(config.profiles[0].agent_policy.allowed_commands.is_empty());
        assert_eq!(config.mcp.listen, "127.0.0.1:8765");
    }

    #[test]
    fn rejects_relative_agent_policy_roots() {
        let raw = r#"
profiles:
  - name: bad
    target:
      host: bad
      user: root
      auth:
        type: password
        password: secret
    agent_policy:
      allowed_read_paths: [var/log]
"#;
        let mut config = parse_config(raw, Path::new("profiles.yaml")).unwrap();
        set_base_dir(&mut config);
        assert!(config
            .validate()
            .unwrap_err()
            .to_string()
            .contains("must be absolute"));
    }

    #[test]
    fn rejects_deprecated_command_blacklist() {
        let raw = r#"
profiles:
  - name: bad
    target:
      host: bad
      user: root
      auth:
        type: password
        password: secret
    agent_policy:
      deny_commands: [reboot]
"#;
        let mut config = parse_config(raw, Path::new("profiles.yaml")).unwrap();
        set_base_dir(&mut config);
        assert!(config
            .validate()
            .unwrap_err()
            .to_string()
            .contains("use exact allowed_commands"));
    }

    #[test]
    fn profile_management_does_not_require_server_approvals() {
        let raw = r#"
profiles:
  - name: test
    target: {host: example, user: root, auth: {type: password, password: secret}}
approval: {enabled: false}
mcp:
  profile_management: {enabled: true}
"#;
        let mut config = parse_config(raw, Path::new("profiles.yaml")).unwrap();
        set_base_dir(&mut config);
        config.validate().unwrap();
    }

    #[test]
    fn oauth_jwt_supports_tenant_only_gateway_config() {
        let raw = r#"
mcp:
  auth:
    type: oauth_jwt
    resource: https://gateway.example.com/mcp
    issuer: https://idp.example.com
    jwks_url: https://idp.example.com/jwks.json
    scopes: [sshmcp]
  tenants:
    - resource: https://gateway.example.com/mcp
      config_path: tenants/main/profiles.yaml
      profile_management: {enabled: true}
"#;
        let mut config = parse_config(raw, Path::new("gateway.yaml")).unwrap();
        set_base_dir(&mut config);
        config.validate().unwrap();
        assert_eq!(
            config.mcp.tenants[0].config_path,
            "tenants/main/profiles.yaml"
        );
    }

    #[test]
    fn oauth_jwt_rejects_duplicate_tenant_resources() {
        let raw = r#"
mcp:
  auth:
    type: oauth_jwt
    resource: https://gateway.example.com/mcp
    issuer: https://idp.example.com
  tenants:
    - resource: https://gateway.example.com/mcp
      config_path: a.yaml
    - resource: https://gateway.example.com/mcp
      config_path: b.yaml
"#;
        let mut config = parse_config(raw, Path::new("gateway.yaml")).unwrap();
        set_base_dir(&mut config);
        assert!(config
            .validate()
            .unwrap_err()
            .to_string()
            .contains("duplicate mcp tenant resource"));
    }

    #[tokio::test]
    async fn atomic_yaml_write_detects_conflicts() {
        let path =
            std::env::temp_dir().join(format!("sshmcp-config-{}.yaml", uuid::Uuid::new_v4()));
        let raw = "profiles:\n  - name: test\n    target: {host: example, user: root, auth: {type: password, password: secret}}\n";
        tokio::fs::write(&path, raw).await.unwrap();
        let mut config = parse_config(raw, &path).unwrap();
        config.source_path = path.clone();
        config.validate().unwrap();
        let hash = config.file_hash().await.unwrap();
        config.profiles[0].description = Some("updated".into());
        config.write_yaml_atomic(&hash).await.unwrap();
        assert!(tokio::fs::read_to_string(&path)
            .await
            .unwrap()
            .contains("updated"));
        assert!(matches!(
            config.write_yaml_atomic(&hash).await,
            Err(ArrtError::ConfigConflict(_))
        ));
        let _ = tokio::fs::remove_file(path).await;
    }
}

#[cfg(test)]
mod migration_env_tests {
    use super::env_value_with_legacy;
    #[test]
    fn new_env_names_take_precedence_and_legacy_names_fall_back() {
        let lookup = |name: &str| match name {
            "SSHMCP_MCP_TOKEN" => Some("new".to_string()),
            "SSH_GATEWAY_MCP_TOKEN" => Some("old".to_string()),
            _ => None,
        };
        assert_eq!(
            env_value_with_legacy("SSHMCP_MCP_TOKEN", lookup).as_deref(),
            Some("new")
        );
        assert_eq!(
            env_value_with_legacy("SSH_GATEWAY_MCP_TOKEN", |name| {
                if name == "SSH_GATEWAY_MCP_TOKEN" {
                    Some("old".into())
                } else {
                    None
                }
            })
            .as_deref(),
            Some("old")
        );
        assert_eq!(
            env_value_with_legacy("SSHMCP_CONFIG_PATH", |name| if name == "ARRT_CONFIG_PATH" {
                Some("legacy".into())
            } else {
                None
            })
            .as_deref(),
            Some("legacy")
        );
        assert_eq!(
            env_value_with_legacy("SSHMCP_TASK_ID", |name| if name == "SSH_GATEWAY_TASK_ID" {
                Some("task".into())
            } else {
                None
            })
            .as_deref(),
            Some("task")
        );
    }
}
