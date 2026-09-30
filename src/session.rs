use crate::agent::{expected_version, render_agent_script};
use crate::config::{
    AppConfig, DelegatedEndpoint, ResolvedProfile, ResolvedTransport, RuntimeMode,
};
use crate::errors::ArrtError;
use crate::protocol::{CommandResult, EnvVar, ErrorPayload, WriteMode};
use crate::ssh::{self, CommandOutput, EmbeddedSession};
use crate::storage::{CredentialStore, FileCredentialStore};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use serde_json::json;
use std::collections::HashMap;
use std::future::Future;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::fs::{self, OpenOptions};
use tokio::io::AsyncWriteExt;
use tokio::net::TcpListener;
use tokio::sync::oneshot;
use tokio::task::JoinHandle;

#[derive(Clone)]
pub struct SessionInfo {
    pub session_id: String,
    pub namespace: String,
    pub profile_name: String,
    pub transport: Arc<EmbeddedSession>,
    pub delegated_target: Option<DelegatedEndpoint>,
    pub upstream_profile: Option<String>,
    pub owns_transport: bool,
    pub agent_path: Option<String>,
    pub agent_version: Option<String>,
    pub last_used: Instant,
    pub idle_timeout: Duration,
    pub active_operations: usize,
}

pub struct PreparedExec {
    session_id: String,
    transport: Arc<EmbeddedSession>,
    delegated_target: Option<DelegatedEndpoint>,
    remote_args: Vec<String>,
    cwd: Option<String>,
    timeout_seconds: u64,
    started: Instant,
}

impl PreparedExec {
    pub fn session_id(&self) -> &str {
        &self.session_id
    }
}

#[derive(Debug)]
pub struct TunnelInfo {
    pub session_id: String,
    pub local_port: u16,
    pub remote_host: String,
    pub remote_port: u16,
    pub shutdown: Option<oneshot::Sender<()>>,
    pub task: JoinHandle<()>,
}

pub struct SessionManager {
    sessions: HashMap<String, SessionInfo>,
    profile_index: HashMap<(String, String), String>,
    tunnels: HashMap<String, TunnelInfo>,
    credentials: Arc<dyn CredentialStore>,
}

impl Default for SessionManager {
    fn default() -> Self {
        Self::with_credentials(Arc::new(FileCredentialStore))
    }
}

impl SessionManager {
    #[cfg(test)]
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_credentials(credentials: Arc<dyn CredentialStore>) -> Self {
        Self {
            sessions: HashMap::new(),
            profile_index: HashMap::new(),
            tunnels: HashMap::new(),
            credentials,
        }
    }

    pub fn sessions_json(&self, namespace: &str) -> serde_json::Value {
        json!(self
            .sessions
            .values()
            .filter(|session| session.namespace == namespace)
            .map(|session| self.session_summary(session))
            .collect::<Vec<_>>())
    }

    #[cfg(test)]
    pub fn has_profile_session(&self, namespace: &str, profile: &str) -> bool {
        self.sessions.values().any(|session| {
            session.namespace == namespace
                && (session.profile_name == profile
                    || session.upstream_profile.as_deref() == Some(profile))
        })
    }

    pub fn has_any_profile_session(&self, profile: &str) -> bool {
        self.sessions.values().any(|session| {
            session.profile_name == profile || session.upstream_profile.as_deref() == Some(profile)
        })
    }

    pub fn session_json(&self, namespace: &str, id: &str) -> Result<serde_json::Value, ArrtError> {
        let session = self
            .sessions
            .get(id)
            .filter(|session| session.namespace == namespace)
            .ok_or_else(|| ArrtError::SessionNotFound(id.to_string()))?;
        Ok(self.session_summary(session))
    }

    pub async fn close_session(
        &mut self,
        config: &AppConfig,
        namespace: &str,
        session_id: &str,
    ) -> Result<(), ArrtError> {
        self.sessions
            .get(session_id)
            .filter(|session| session.namespace == namespace)
            .ok_or_else(|| ArrtError::SessionNotFound(session_id.to_string()))?;
        let session = self
            .sessions
            .remove(session_id)
            .ok_or_else(|| ArrtError::SessionNotFound(session_id.to_string()))?;
        self.profile_index
            .remove(&(session.namespace.clone(), session.profile_name.clone()));

        let tunnel_ids = self
            .tunnels
            .iter()
            .filter_map(|(tunnel_id, tunnel)| {
                if tunnel.session_id == session_id {
                    Some(tunnel_id.clone())
                } else {
                    None
                }
            })
            .collect::<Vec<_>>();
        for tunnel_id in tunnel_ids {
            let _ = self.tunnel_close(config, namespace, &tunnel_id).await;
        }

        if session.owns_transport {
            session.transport.disconnect().await;
        }
        Ok(())
    }

    pub async fn close_all(&mut self, config: &AppConfig) {
        let ids = self.sessions.keys().cloned().collect::<Vec<_>>();
        for id in ids {
            let Some(namespace) = self
                .sessions
                .get(&id)
                .map(|session| session.namespace.clone())
            else {
                continue;
            };
            let _ = self.close_session(config, &namespace, &id).await;
        }
    }

    pub async fn reap_idle_sessions(&mut self, config: &AppConfig, namespace: &str) {
        self.reap_idle_sessions_matching(config, Some(namespace))
            .await;
    }

    pub async fn reap_all_idle_sessions(&mut self, config: &AppConfig) {
        self.reap_idle_sessions_matching(config, None).await;
    }

    async fn reap_idle_sessions_matching(&mut self, config: &AppConfig, namespace: Option<&str>) {
        let mut expired = Vec::new();
        for (session_id, session) in &self.sessions {
            if namespace.is_some_and(|namespace| session.namespace != namespace) {
                continue;
            }
            let has_tunnel = self
                .tunnels
                .values()
                .any(|tunnel| tunnel.session_id == *session_id);
            if session.active_operations > 0 || has_tunnel {
                continue;
            }
            if session.last_used.elapsed() > session.idle_timeout {
                expired.push(session_id.clone());
            }
        }
        for session_id in expired {
            let Some(namespace) = self
                .sessions
                .get(&session_id)
                .map(|session| session.namespace.clone())
            else {
                continue;
            };
            let _ = self.close_session(config, &namespace, &session_id).await;
        }
    }

    fn ensure_session<'a>(
        &'a mut self,
        config: &'a AppConfig,
        namespace: &'a str,
        profile: &'a ResolvedProfile,
    ) -> Pin<Box<dyn Future<Output = Result<String, ArrtError>> + Send + 'a>> {
        Box::pin(async move {
            let profile_key = (namespace.to_string(), profile.name.clone());
            if let Some(session_id) = self.profile_index.get(&profile_key).cloned() {
                if let Some(existing) = self.sessions.get_mut(&session_id) {
                    if existing.transport.is_alive().await {
                        existing.last_used = Instant::now();
                        return Ok(session_id);
                    }
                }
                self.sessions.remove(&session_id);
                self.profile_index.remove(&profile_key);
            }

            let session_id = uuid::Uuid::new_v4().to_string();
            let (transport, delegated_target, upstream_profile, owns_transport) =
                match &profile.transport {
                    ResolvedTransport::Direct { .. } => (
                        Arc::new(EmbeddedSession::connect(profile).await?),
                        None,
                        None,
                        true,
                    ),
                    ResolvedTransport::Delegated {
                        via_profile,
                        target,
                    } => {
                        if matches!(
                            config.runtime.mode,
                            RuntimeMode::Cloud | RuntimeMode::CloudBastion
                        ) {
                            return Err(ArrtError::PolicyDenied(
                            "Cloud target policy cannot verify delegated via_profile destinations"
                                .into(),
                        ));
                        }
                        let upstream = config.resolved_profile_with_credentials(
                            via_profile,
                            self.credentials.as_ref(),
                        )?;
                        let upstream_session_id =
                            self.ensure_session(config, namespace, &upstream).await?;
                        let upstream_transport = self
                            .sessions
                            .get(&upstream_session_id)
                            .ok_or_else(|| ArrtError::SessionNotFound(upstream_session_id.clone()))?
                            .transport
                            .clone();
                        (
                            upstream_transport,
                            Some(target.clone()),
                            Some(via_profile.clone()),
                            false,
                        )
                    }
                };
            let session = SessionInfo {
                session_id: session_id.clone(),
                namespace: namespace.to_string(),
                profile_name: profile.name.clone(),
                transport,
                delegated_target,
                upstream_profile,
                owns_transport,
                agent_path: None,
                agent_version: None,
                last_used: Instant::now(),
                idle_timeout: Duration::from_secs(profile.timeouts.idle_session_seconds),
                active_operations: 0,
            };
            self.profile_index.insert(profile_key, session_id.clone());
            self.sessions.insert(session_id.clone(), session);
            Ok(session_id)
        })
    }

    async fn ensure_agent(
        &mut self,
        profile: &ResolvedProfile,
        session_id: &str,
    ) -> Result<(), ArrtError> {
        let remote_path = profile.agent.remote_path.clone();
        let expected = expected_version(&profile.agent.version);
        let (transport, delegated_target) = {
            let session = self
                .sessions
                .get(session_id)
                .ok_or_else(|| ArrtError::SessionNotFound(session_id.to_string()))?;
            (session.transport.clone(), session.delegated_target.clone())
        };

        let current_version = self
            .query_agent_version(transport.as_ref(), delegated_target.as_ref(), &remote_path)
            .await;
        let version = match current_version {
            Ok(version) if version == expected => version,
            _ => {
                self.install_agent(
                    transport.as_ref(),
                    delegated_target.as_ref(),
                    &remote_path,
                    &expected,
                )
                .await?;
                let verified = self
                    .query_agent_version(
                        transport.as_ref(),
                        delegated_target.as_ref(),
                        &remote_path,
                    )
                    .await?;
                if verified != expected {
                    return Err(ArrtError::Agent(format!(
                        "agent version mismatch after install: expected {}, got {}",
                        expected, verified
                    )));
                }
                verified
            }
        };

        let session = self
            .sessions
            .get_mut(session_id)
            .ok_or_else(|| ArrtError::SessionNotFound(session_id.to_string()))?;
        session.agent_path = Some(remote_path);
        session.agent_version = Some(version);
        session.last_used = Instant::now();
        Ok(())
    }

    async fn query_agent_version(
        &self,
        transport: &EmbeddedSession,
        delegated_target: Option<&DelegatedEndpoint>,
        remote_path: &str,
    ) -> Result<String, ArrtError> {
        let output = run_remote_argv(
            transport,
            delegated_target,
            &[remote_path.to_string(), "version".to_string()],
            None,
        )
        .await?;
        if output.exit_code != 0 {
            return Err(ArrtError::Agent(
                String::from_utf8_lossy(&output.stderr).trim().to_string(),
            ));
        }
        let version = String::from_utf8_lossy(&output.stdout).trim().to_string();
        if version.is_empty() {
            return Err(ArrtError::Agent(
                "remote agent returned empty version".to_string(),
            ));
        }
        Ok(version)
    }

    async fn install_agent(
        &self,
        transport: &EmbeddedSession,
        delegated_target: Option<&DelegatedEndpoint>,
        remote_path: &str,
        version: &str,
    ) -> Result<(), ArrtError> {
        let script = render_agent_script(version);
        let parent = remote_parent(remote_path);
        let target_stage = format!("{}.{}", remote_path, uuid::Uuid::new_v4());
        let command = format!(
            "mkdir -p {} && cat > {} && chmod 700 {} && mv {} {}",
            ssh::shell_quote(&parent),
            ssh::shell_quote(&target_stage),
            ssh::shell_quote(&target_stage),
            ssh::shell_quote(&target_stage),
            ssh::shell_quote(remote_path)
        );
        let output = run_remote_command(
            transport,
            delegated_target,
            &command,
            Some(script.as_bytes()),
        )
        .await?;
        if output.exit_code == 0 {
            return Ok(());
        }
        Err(ArrtError::Agent(
            String::from_utf8_lossy(&output.stderr).trim().to_string(),
        ))
    }

    async fn invoke_agent(
        &mut self,
        session_id: &str,
        args: Vec<String>,
        input: Option<&[u8]>,
    ) -> Result<CommandResult, ArrtError> {
        let (transport, delegated_target, agent_path) = {
            let session = self
                .sessions
                .get(session_id)
                .ok_or_else(|| ArrtError::SessionNotFound(session_id.to_string()))?;
            (
                session.transport.clone(),
                session.delegated_target.clone(),
                session.agent_path.clone().ok_or_else(|| {
                    ArrtError::Agent(format!("agent is not ready for session {}", session_id))
                })?,
            )
        };

        let mut remote_args = Vec::with_capacity(1 + args.len());
        remote_args.push(agent_path);
        remote_args.extend(args);
        let output = run_remote_argv(
            transport.as_ref(),
            delegated_target.as_ref(),
            &remote_args,
            input,
        )
        .await?;
        let result = parse_agent_output(output)?;
        if let Some(session) = self.sessions.get_mut(session_id) {
            session.last_used = Instant::now();
        }
        Ok(result)
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn prepare_exec(
        &mut self,
        config: &AppConfig,
        namespace: &str,
        profile_name: &str,
        command: String,
        cwd: Option<String>,
        timeout_seconds: Option<u64>,
        env: Vec<EnvVar>,
    ) -> Result<PreparedExec, ArrtError> {
        let profile =
            config.resolved_profile_with_credentials(profile_name, self.credentials.as_ref())?;
        let session_id = self.ensure_session(config, namespace, &profile).await?;
        self.ensure_agent(&profile, &session_id).await?;
        let timeout_seconds = timeout_seconds.unwrap_or(profile.timeouts.exec_seconds);
        let mut args = vec![
            "exec".to_string(),
            cwd.as_ref()
                .map(|value| BASE64.encode(value))
                .unwrap_or_else(|| "-".to_string()),
            timeout_seconds.to_string(),
            BASE64.encode(command),
        ];
        args.extend(
            env.into_iter()
                .map(|item| BASE64.encode(format!("{}={}", item.key, item.value))),
        );
        let session = self
            .sessions
            .get_mut(&session_id)
            .ok_or_else(|| ArrtError::SessionNotFound(session_id.clone()))?;
        let agent_path = session.agent_path.clone().ok_or_else(|| {
            ArrtError::Agent(format!("agent is not ready for session {session_id}"))
        })?;
        session.active_operations += 1;
        let mut remote_args = Vec::with_capacity(1 + args.len());
        remote_args.push(agent_path);
        remote_args.extend(args);
        Ok(PreparedExec {
            session_id,
            transport: session.transport.clone(),
            delegated_target: session.delegated_target.clone(),
            remote_args,
            cwd,
            timeout_seconds,
            started: Instant::now(),
        })
    }

    pub async fn execute_prepared_exec(
        prepared: &PreparedExec,
    ) -> Result<CommandResult, ArrtError> {
        let operation = run_remote_argv(
            prepared.transport.as_ref(),
            prepared.delegated_target.as_ref(),
            &prepared.remote_args,
            None,
        );
        let output = if prepared.timeout_seconds == 0 {
            operation.await?
        } else {
            let deadline = Duration::from_secs(prepared.timeout_seconds.saturating_add(10));
            tokio::time::timeout(deadline, operation)
                .await
                .map_err(|_| {
                    ArrtError::RequestTimeout(format!(
                        "remote exec exceeded {} seconds including transport grace",
                        deadline.as_secs()
                    ))
                })??
        };
        let mut result = parse_agent_output(output)?;
        classify_remote_cwd_error(&mut result, prepared.cwd.as_deref());
        result.duration_ms = Some(prepared.started.elapsed().as_millis());
        result.session_id = Some(prepared.session_id.clone());
        Ok(result)
    }

    pub fn finish_exec(&mut self, session_id: &str) {
        if let Some(session) = self.sessions.get_mut(session_id) {
            session.active_operations = session.active_operations.saturating_sub(1);
            session.last_used = Instant::now();
        }
    }

    pub async fn read(
        &mut self,
        config: &AppConfig,
        namespace: &str,
        profile_name: &str,
        path: String,
        allowed_roots: &[String],
    ) -> Result<CommandResult, ArrtError> {
        let profile =
            config.resolved_profile_with_credentials(profile_name, self.credentials.as_ref())?;
        let session_id = self.ensure_session(config, namespace, &profile).await?;
        self.ensure_agent(&profile, &session_id).await?;
        let mut args = vec![
            if allowed_roots.is_empty() {
                "read"
            } else {
                "read-policy"
            }
            .to_string(),
            BASE64.encode(path),
        ];
        args.extend(allowed_roots.iter().map(|root| BASE64.encode(root)));
        let mut result = self.invoke_agent(&session_id, args, None).await?;
        let content_b64 = result
            .data
            .as_ref()
            .and_then(|value| value.get("stdout_b64"))
            .cloned()
            .unwrap_or_else(|| json!(BASE64.encode(result.stdout.as_bytes())));
        result.data = Some(json!({
            "content_b64": content_b64,
        }));
        result.session_id = Some(session_id);
        Ok(result)
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn write(
        &mut self,
        config: &AppConfig,
        namespace: &str,
        profile_name: &str,
        path: String,
        mode: WriteMode,
        content_b64: String,
        allowed_roots: &[String],
    ) -> Result<CommandResult, ArrtError> {
        let profile =
            config.resolved_profile_with_credentials(profile_name, self.credentials.as_ref())?;
        let session_id = self.ensure_session(config, namespace, &profile).await?;
        self.ensure_agent(&profile, &session_id).await?;
        let content = BASE64
            .decode(content_b64.as_bytes())
            .map_err(|err| ArrtError::InvalidArgument(format!("invalid content_b64: {err}")))?;
        let mut args = vec![
            if allowed_roots.is_empty() {
                "write"
            } else {
                "write-policy"
            }
            .to_string(),
            write_mode_name(mode).to_string(),
            BASE64.encode(path),
        ];
        args.extend(allowed_roots.iter().map(|root| BASE64.encode(root)));
        let mut result = self.invoke_agent(&session_id, args, Some(&content)).await?;
        result.session_id = Some(session_id);
        Ok(result)
    }

    pub async fn upload(
        &mut self,
        config: &AppConfig,
        namespace: &str,
        profile_name: &str,
        src: String,
        dst: String,
        allowed_roots: &[String],
    ) -> Result<CommandResult, ArrtError> {
        let src = absolute_local_path(src, "upload src")?;
        let content = fs::read(&src).await?;
        let mut result = self
            .write(
                config,
                namespace,
                profile_name,
                dst.clone(),
                WriteMode::Truncate,
                BASE64.encode(content),
                allowed_roots,
            )
            .await?;
        add_transfer_paths(
            &mut result,
            "local_src",
            &src.display().to_string(),
            "remote_dst",
            &dst,
        );
        Ok(result)
    }

    pub async fn download(
        &mut self,
        config: &AppConfig,
        namespace: &str,
        profile_name: &str,
        src: String,
        dst: String,
        allowed_roots: &[String],
    ) -> Result<CommandResult, ArrtError> {
        let dst = absolute_local_path(dst, "download dst")?;
        let mut result = self
            .read(config, namespace, profile_name, src.clone(), allowed_roots)
            .await?;
        if !result.ok {
            add_transfer_paths(
                &mut result,
                "remote_src",
                &src,
                "local_dst",
                &dst.display().to_string(),
            );
            return Ok(result);
        }
        let content_b64 = result
            .data
            .as_ref()
            .and_then(|value| value.get("content_b64"))
            .and_then(|value| value.as_str())
            .ok_or_else(|| ArrtError::Agent("missing content_b64 in read result".to_string()))?;
        let content = BASE64.decode(content_b64.as_bytes()).map_err(|err| {
            ArrtError::Agent(format!("invalid content_b64 in read result: {err}"))
        })?;
        let overwritten = dst.exists();
        atomic_write(&dst, &content).await?;
        result.data = Some(json!({
            "remote_src": src,
            "local_dst": dst.display().to_string(),
            "saved_to": dst.display().to_string(),
            "overwritten": overwritten,
        }));
        Ok(result)
    }

    pub async fn tunnel_open(
        &mut self,
        config: &AppConfig,
        namespace: &str,
        profile_name: &str,
        local_port: u16,
        remote_host: String,
        remote_port: u16,
    ) -> Result<CommandResult, ArrtError> {
        let profile =
            config.resolved_profile_with_credentials(profile_name, self.credentials.as_ref())?;
        let session_id = self.ensure_session(config, namespace, &profile).await?;
        let session = self
            .sessions
            .get(&session_id)
            .ok_or_else(|| ArrtError::SessionNotFound(session_id.clone()))?;
        if session.delegated_target.is_some() {
            return Err(ArrtError::InvalidArgument(
                "tunnel open is not supported for via_profile delegated sessions".to_string(),
            ));
        }
        let transport = session.transport.clone();

        let listener = TcpListener::bind(("127.0.0.1", local_port)).await?;
        let actual_local_port = listener.local_addr()?.port();
        let (shutdown_tx, mut shutdown_rx) = oneshot::channel::<()>();
        let remote_host_for_task = remote_host.clone();
        let transport_for_task = transport.clone();

        let task = tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = &mut shutdown_rx => break,
                    accepted = listener.accept() => {
                        let Ok((socket, originator)) = accepted else {
                            break;
                        };
                        let tunnel_transport = transport_for_task.clone();
                        let tunnel_host = remote_host_for_task.clone();
                        tokio::spawn(async move {
                            let _ = tunnel_transport
                                .proxy_tcp_stream(socket, &tunnel_host, remote_port, originator)
                                .await;
                        });
                    }
                }
            }
        });

        if let Some(session) = self.sessions.get_mut(&session_id) {
            session.last_used = Instant::now();
        }

        let tunnel_id = uuid::Uuid::new_v4().to_string();
        self.tunnels.insert(
            tunnel_id.clone(),
            TunnelInfo {
                session_id: session_id.clone(),
                local_port: actual_local_port,
                remote_host: remote_host.clone(),
                remote_port,
                shutdown: Some(shutdown_tx),
                task,
            },
        );

        let mut result = CommandResult::success();
        result.session_id = Some(session_id);
        result.data = Some(json!({
            "tunnel_id": tunnel_id,
            "local_port": actual_local_port,
            "remote_host": remote_host,
            "remote_port": remote_port,
        }));
        Ok(result)
    }

    pub async fn tunnel_close(
        &mut self,
        _config: &AppConfig,
        namespace: &str,
        tunnel_id: &str,
    ) -> Result<CommandResult, ArrtError> {
        let visible = self
            .tunnels
            .get(tunnel_id)
            .and_then(|tunnel| self.sessions.get(&tunnel.session_id))
            .is_some_and(|session| session.namespace == namespace);
        if !visible {
            return Err(ArrtError::InvalidArgument(format!(
                "unknown tunnel id: {}",
                tunnel_id
            )));
        }
        let mut tunnel = self.tunnels.remove(tunnel_id).ok_or_else(|| {
            ArrtError::InvalidArgument(format!("unknown tunnel id: {}", tunnel_id))
        })?;

        if let Some(session) = self.sessions.get_mut(&tunnel.session_id) {
            session.last_used = Instant::now();
        }

        if let Some(shutdown) = tunnel.shutdown.take() {
            let _ = shutdown.send(());
        }
        let _ = tunnel.task.await;

        let mut result = CommandResult::success();
        result.data = Some(json!({
            "closed": tunnel_id,
            "local_port": tunnel.local_port,
            "remote_host": tunnel.remote_host,
            "remote_port": tunnel.remote_port,
        }));
        Ok(result)
    }

    pub fn tunnel_profile(&self, namespace: &str, tunnel_id: &str) -> Option<&str> {
        let tunnel = self.tunnels.get(tunnel_id)?;
        self.sessions
            .get(&tunnel.session_id)
            .filter(|session| session.namespace == namespace)
            .map(|session| session.profile_name.as_str())
    }

    fn session_summary(&self, session: &SessionInfo) -> serde_json::Value {
        json!({
            "session_id": session.session_id,
            "profile": session.profile_name,
            "transport": session.transport.transport_name(),
            "upstream_profile": session.upstream_profile,
            "delegated_target": session.delegated_target.as_ref().map(|target| {
                json!({
                    "host": target.host,
                    "user": target.user,
                    "port": target.port,
                })
            }),
            "reused": true,
            "agent_path": session.agent_path,
            "agent_version": session.agent_version,
            "agent_ready": session.agent_path.is_some() && session.agent_version.is_some(),
        })
    }
}

pub(crate) fn absolute_local_path(path: String, argument: &str) -> Result<PathBuf, ArrtError> {
    if Path::new(&path).is_absolute() {
        return Ok(PathBuf::from(path));
    }
    Err(ArrtError::RelativeLocalPath(format!(
        "{argument} must be absolute; resolve it against the CLI caller's current directory before sending the RPC request"
    )))
}

fn add_transfer_paths(
    result: &mut CommandResult,
    local_key: &str,
    local_path: &str,
    remote_key: &str,
    remote_path: &str,
) {
    let data = result.data.get_or_insert_with(|| json!({}));
    if let Some(object) = data.as_object_mut() {
        object.insert(local_key.to_string(), json!(local_path));
        object.insert(remote_key.to_string(), json!(remote_path));
    }
}

async fn atomic_write(dst: &Path, content: &[u8]) -> Result<(), ArrtError> {
    let parent = dst.parent().ok_or_else(|| {
        ArrtError::InvalidArgument(format!(
            "download destination has no parent: {}",
            dst.display()
        ))
    })?;
    fs::create_dir_all(parent).await?;
    let file_name = dst.file_name().ok_or_else(|| {
        ArrtError::InvalidArgument(format!(
            "download destination is not a file: {}",
            dst.display()
        ))
    })?;
    let temp = parent.join(format!(
        ".{}.sshmcp-{}.tmp",
        file_name.to_string_lossy(),
        uuid::Uuid::new_v4()
    ));
    let write_result = async {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temp)
            .await?;
        file.write_all(content).await?;
        file.sync_all().await?;
        drop(file);
        atomic_replace(&temp, dst).await
    }
    .await;
    if write_result.is_err() {
        let _ = fs::remove_file(&temp).await;
    }
    write_result
}

#[cfg(not(windows))]
async fn atomic_replace(src: &Path, dst: &Path) -> Result<(), ArrtError> {
    fs::rename(src, dst).await.map_err(ArrtError::from)
}

#[cfg(windows)]
async fn atomic_replace(src: &Path, dst: &Path) -> Result<(), ArrtError> {
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::Storage::FileSystem::{
        MoveFileExW, MOVEFILE_REPLACE_EXISTING, MOVEFILE_WRITE_THROUGH,
    };

    let src_wide: Vec<u16> = src.as_os_str().encode_wide().chain(Some(0)).collect();
    let dst_wide: Vec<u16> = dst.as_os_str().encode_wide().chain(Some(0)).collect();
    let replaced = unsafe {
        MoveFileExW(
            src_wide.as_ptr(),
            dst_wide.as_ptr(),
            MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH,
        )
    };
    if replaced == 0 {
        return Err(ArrtError::Io(std::io::Error::last_os_error().to_string()));
    }
    Ok(())
}

fn classify_remote_cwd_error(result: &mut CommandResult, cwd: Option<&str>) {
    let Some(cwd) = cwd else { return };
    if result.ok {
        return;
    }
    let stderr = result.stderr.to_ascii_lowercase();
    let cwd_missing = stderr.contains("no such file or directory")
        && (stderr.contains("cd:") || stderr.contains("can't cd"));
    if cwd_missing {
        result.error = Some(ErrorPayload {
            code: "remote_cwd_not_found".to_string(),
            message: format!("remote cwd not found: {cwd}"),
        });
        let data = result.data.get_or_insert_with(|| json!({}));
        if let Some(object) = data.as_object_mut() {
            object.insert("remote_cwd".to_string(), json!(cwd));
        }
    }
}

#[cfg(test)]
#[allow(clippy::items_after_test_module)]
mod local_path_tests {
    use super::*;

    fn fake_session(namespace: &str, profile_name: &str) -> SessionInfo {
        let session_id = uuid::Uuid::new_v4().to_string();
        SessionInfo {
            session_id,
            namespace: namespace.to_string(),
            profile_name: profile_name.to_string(),
            transport: Arc::new(EmbeddedSession::test_empty()),
            delegated_target: None,
            upstream_profile: None,
            owns_transport: false,
            agent_path: None,
            agent_version: None,
            last_used: Instant::now(),
            idle_timeout: Duration::from_secs(900),
            active_operations: 0,
        }
    }

    #[test]
    fn session_views_are_namespaced() {
        let mut manager = SessionManager::new();
        let session_a = fake_session("tenant-a", "shared");
        let session_b = fake_session("tenant-b", "shared");
        let id_a = session_a.session_id.clone();
        let id_b = session_b.session_id.clone();
        manager
            .profile_index
            .insert(("tenant-a".into(), "shared".into()), id_a.clone());
        manager
            .profile_index
            .insert(("tenant-b".into(), "shared".into()), id_b.clone());
        manager.sessions.insert(id_a.clone(), session_a);
        manager.sessions.insert(id_b.clone(), session_b);

        assert!(manager.has_profile_session("tenant-a", "shared"));
        assert!(manager.session_json("tenant-a", &id_a).is_ok());
        assert!(manager.session_json("tenant-a", &id_b).is_err());
        assert_eq!(
            manager
                .sessions_json("tenant-a")
                .as_array()
                .expect("session list")
                .len(),
            1
        );
    }

    #[tokio::test]
    async fn maintenance_reaps_idle_sessions_in_every_namespace() {
        let mut manager = SessionManager::new();
        for namespace in ["tenant-a:user-a", "tenant-b:user-b"] {
            let mut session = fake_session(namespace, "shared");
            session.last_used = Instant::now() - Duration::from_secs(2);
            session.idle_timeout = Duration::from_secs(1);
            manager.sessions.insert(session.session_id.clone(), session);
        }
        manager.reap_all_idle_sessions(&AppConfig::default()).await;
        assert!(manager.sessions.is_empty());
    }

    #[tokio::test]
    async fn close_session_cannot_cross_namespace() {
        let config = AppConfig::default();
        let mut manager = SessionManager::new();
        let session = fake_session("tenant-a", "shared");
        let id = session.session_id.clone();
        manager
            .profile_index
            .insert(("tenant-a".into(), "shared".into()), id.clone());
        manager.sessions.insert(id.clone(), session);

        assert!(manager
            .close_session(&config, "tenant-b", &id)
            .await
            .is_err());
        assert!(manager.sessions.contains_key(&id));
        manager
            .close_session(&config, "tenant-a", &id)
            .await
            .unwrap();
        assert!(!manager.sessions.contains_key(&id));
    }

    #[test]
    fn daemon_rejects_relative_local_paths() {
        let error = absolute_local_path("relative/file.txt".to_string(), "upload src").unwrap_err();
        assert!(error.to_string().contains("upload src must be absolute"));
        assert_eq!(error.code(), "relative_local_path");
    }

    #[test]
    fn transfer_results_include_local_and_remote_paths() {
        let mut result = CommandResult::success();
        add_transfer_paths(
            &mut result,
            "local_src",
            r"C:\work\input.txt",
            "remote_dst",
            "/tmp/input.txt",
        );

        let data = result.data.unwrap();
        assert_eq!(data["local_src"], r"C:\work\input.txt");
        assert_eq!(data["remote_dst"], "/tmp/input.txt");
    }

    #[tokio::test]
    async fn atomic_write_overwrites_complete_file_and_creates_parents() {
        let root = std::env::temp_dir().join(format!("sshmcp-test-{}", uuid::Uuid::new_v4()));
        let dst = root.join("nested").join("download.txt");
        fs::create_dir_all(dst.parent().unwrap()).await.unwrap();
        fs::write(&dst, b"old content").await.unwrap();

        atomic_write(&dst, b"complete replacement").await.unwrap();

        assert_eq!(fs::read(&dst).await.unwrap(), b"complete replacement");
        let entries = std::fs::read_dir(dst.parent().unwrap()).unwrap().count();
        assert_eq!(entries, 1, "temporary file should be removed after rename");

        let new_dst = root.join("created").join("parents").join("download.txt");
        atomic_write(&new_dst, b"new file").await.unwrap();
        assert_eq!(fs::read(&new_dst).await.unwrap(), b"new file");
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn classifies_missing_remote_cwd() {
        let mut result = CommandResult::success();
        result.ok = false;
        result.exit_code = Some(2);
        result.stderr =
            "sh: 1: cd: can't cd to /missing/path: No such file or directory".to_string();
        result.error = Some(ErrorPayload {
            code: "remote_command_failed".to_string(),
            message: result.stderr.clone(),
        });

        classify_remote_cwd_error(&mut result, Some("/missing/path"));

        assert_eq!(result.error.unwrap().code, "remote_cwd_not_found");
        assert_eq!(result.data.unwrap()["remote_cwd"], "/missing/path");
    }

    #[test]
    fn remote_policy_exit_is_reported_as_policy_denied() {
        let output = CommandOutput {
            exit_code: 0,
            stdout: format!("77\n\n{}\n", BASE64.encode("resolved path escaped")).into_bytes(),
            stderr: Vec::new(),
        };
        let result = parse_agent_output(output).unwrap();
        assert_eq!(result.error.unwrap().code, "policy_denied");
    }
}

async fn run_remote_argv(
    transport: &EmbeddedSession,
    delegated_target: Option<&DelegatedEndpoint>,
    argv: &[String],
    input: Option<&[u8]>,
) -> Result<CommandOutput, ArrtError> {
    match delegated_target {
        Some(target) => {
            let command = ssh::shell_join(&delegate_ssh_tokens(target, argv));
            transport.run_command(&command, input).await
        }
        None => transport.run_argv(argv, input).await,
    }
}

async fn run_remote_command(
    transport: &EmbeddedSession,
    delegated_target: Option<&DelegatedEndpoint>,
    command: &str,
    input: Option<&[u8]>,
) -> Result<CommandOutput, ArrtError> {
    match delegated_target {
        Some(target) => {
            let remote = format!("sh -lc {}", ssh::shell_quote(command));
            let wrapped = format!(
                "{} {}",
                delegate_ssh_prefix(target),
                ssh::shell_quote(&remote)
            );
            transport.run_command(&wrapped, input).await
        }
        None => transport.run_command(command, input).await,
    }
}

fn delegate_ssh_tokens(target: &DelegatedEndpoint, remote_args: &[String]) -> Vec<String> {
    let mut tokens = delegate_ssh_base_tokens(target);
    tokens.extend(remote_args.iter().cloned());
    tokens
}

fn delegate_ssh_prefix(target: &DelegatedEndpoint) -> String {
    ssh::shell_join(&delegate_ssh_base_tokens(target))
}

fn delegate_ssh_base_tokens(target: &DelegatedEndpoint) -> Vec<String> {
    let mut tokens = vec![
        "ssh".to_string(),
        "-o".to_string(),
        "BatchMode=yes".to_string(),
        "-o".to_string(),
        "StrictHostKeyChecking=no".to_string(),
        "-o".to_string(),
        "UserKnownHostsFile=/dev/null".to_string(),
    ];
    if !target.user.trim().is_empty() {
        tokens.push("-l".to_string());
        tokens.push(target.user.clone());
    }
    if target.port != 22 {
        tokens.push("-p".to_string());
        tokens.push(target.port.to_string());
    }
    tokens.push(target.host.clone());
    tokens
}

fn write_mode_name(mode: WriteMode) -> &'static str {
    match mode {
        WriteMode::Create => "create",
        WriteMode::Truncate => "truncate",
        WriteMode::Append => "append",
    }
}

fn remote_parent(path: &str) -> String {
    match path.rfind('/') {
        Some(0) => "/".to_string(),
        Some(index) => path[..index].to_string(),
        None => ".".to_string(),
    }
}

fn parse_agent_output(output: CommandOutput) -> Result<CommandResult, ArrtError> {
    let stdout_text = String::from_utf8_lossy(&output.stdout);
    let mut parts = stdout_text.splitn(3, '\n');
    let exit_code = parts
        .next()
        .and_then(|value| value.trim().parse::<i32>().ok())
        .ok_or_else(|| {
            ArrtError::Agent(format!(
                "invalid agent response: stdout={}, stderr={}",
                stdout_text.trim(),
                String::from_utf8_lossy(&output.stderr).trim()
            ))
        })?;
    let stdout_b64 = parts.next().unwrap_or("").trim();
    let stderr_b64 = parts.next().unwrap_or("").trim();
    let stdout_bytes = decode_base64_field(stdout_b64)?;
    let stderr_bytes = decode_base64_field(stderr_b64)?;
    let stdout = String::from_utf8_lossy(&stdout_bytes).into_owned();
    let stderr = String::from_utf8_lossy(&stderr_bytes).into_owned();
    let mut result = CommandResult::success();
    result.ok = exit_code == 0;
    result.exit_code = Some(exit_code);
    result.stdout = stdout;
    result.stderr = stderr.clone();
    result.data = Some(json!({
        "stdout_b64": BASE64.encode(&stdout_bytes),
        "stderr_b64": BASE64.encode(&stderr_bytes),
    }));
    if !result.ok {
        result.error = Some(ErrorPayload {
            code: if exit_code == 77 {
                "policy_denied"
            } else {
                "remote_command_failed"
            }
            .to_string(),
            message: if stderr.is_empty() {
                format!("remote command exited with {}", exit_code)
            } else {
                stderr
            },
        });
    }
    Ok(result)
}

fn decode_base64_field(raw: &str) -> Result<Vec<u8>, ArrtError> {
    if raw.is_empty() {
        return Ok(Vec::new());
    }
    BASE64
        .decode(raw.as_bytes())
        .map_err(|err| ArrtError::Agent(format!("invalid base64 from remote agent: {err}")))
}
