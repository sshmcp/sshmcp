use crate::approval::request_hash;
#[cfg(test)]
use crate::approval::ApprovalService;
use crate::audit::{AuditEvent, AuditSink, AuthorizationAuditEvent, StderrAuditSink};
use crate::config::{config_path_display, AppConfig, RiskLevelConfig, RuntimeMode};
use crate::errors::ArrtError;
use crate::grant::{GrantService, PlanAuthorization};
use crate::policy::{PolicyEffect, PolicyEngine};
use crate::principal::Principal;
use crate::protocol::{CallerType, CommandResult, ErrorPayload, Request};
use crate::redaction::SecretRedactor;
use crate::session::{absolute_local_path, SessionManager};
use crate::storage::{
    ApprovalStoreFactory, CredentialStore, FileCredentialStore, FileProfileStore, ProfileStore,
    SqliteApprovalStoreFactory,
};
use serde::Serialize;
use serde_json::json;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Instant, SystemTime, UNIX_EPOCH};
use tokio::sync::{Mutex, RwLock};

#[cfg(test)]
const DEFAULT_SESSION_NAMESPACE: &str = "default";

#[derive(Debug, Serialize)]
pub struct PublicProfile {
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    pub capabilities: Vec<&'static str>,
}

pub struct GatewayService {
    sessions: Mutex<SessionManager>,
    config_access: RwLock<()>,
    maintenance_started: AtomicBool,
    audit_sink: Arc<dyn AuditSink>,
    profiles: Arc<dyn ProfileStore>,
    credentials: Arc<dyn CredentialStore>,
    approvals: Arc<dyn ApprovalStoreFactory>,
}

impl GatewayService {
    pub fn new() -> Arc<Self> {
        Self::with_providers(
            Arc::new(FileProfileStore),
            Arc::new(FileCredentialStore),
            Arc::new(SqliteApprovalStoreFactory),
            Arc::new(StderrAuditSink),
        )
    }

    pub fn with_providers(
        profiles: Arc<dyn ProfileStore>,
        credentials: Arc<dyn CredentialStore>,
        approvals: Arc<dyn ApprovalStoreFactory>,
        audit_sink: Arc<dyn AuditSink>,
    ) -> Arc<Self> {
        Arc::new(Self {
            sessions: Mutex::new(SessionManager::with_credentials(credentials.clone())),
            config_access: RwLock::new(()),
            maintenance_started: AtomicBool::new(false),
            audit_sink,
            profiles,
            credentials,
            approvals,
        })
    }

    pub fn start_maintenance(self: &Arc<Self>) {
        if self.maintenance_started.swap(true, Ordering::AcqRel) {
            return;
        }
        let service = Arc::downgrade(self);
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(60));
            loop {
                interval.tick().await;
                let Some(service) = service.upgrade() else {
                    break;
                };
                let _config_guard = service.config_access.read().await;
                if let Ok(config) = service.profiles.load().await {
                    service
                        .sessions
                        .lock()
                        .await
                        .reap_all_idle_sessions(&config)
                        .await;
                }
            }
        });
    }

    pub async fn list_hosts_for_principal(
        &self,
        request_id: &str,
        principal: &Principal,
        config: Option<&AppConfig>,
    ) -> Result<Vec<PublicProfile>, ArrtError> {
        match config {
            Some(config) => {
                self.list_hosts_with_config(request_id, principal, config, Instant::now())
                    .await
            }
            None => {
                let _guard = self.config_access.read().await;
                let config = self.profiles.load().await?;
                self.list_hosts_with_config(request_id, principal, &config, Instant::now())
                    .await
            }
        }
    }

    async fn list_hosts_with_config(
        &self,
        request_id: &str,
        principal: &Principal,
        config: &AppConfig,
        started: Instant,
    ) -> Result<Vec<PublicProfile>, ArrtError> {
        let redactor =
            SecretRedactor::from_config_with_credentials(config, self.credentials.as_ref());
        let hosts = config
            .profiles
            .iter()
            .map(|profile| {
                let caps = &profile.agent_policy.capabilities;
                let mut capabilities = Vec::new();
                for (enabled, name) in [
                    (caps.exec, "exec"),
                    (caps.read, "read"),
                    (caps.write, "write"),
                    (caps.upload, "upload"),
                    (caps.download, "download"),
                    (caps.tunnel, "tunnel"),
                ] {
                    if enabled {
                        capabilities.push(name);
                    }
                }
                PublicProfile {
                    name: profile.name.clone(),
                    description: profile
                        .description
                        .as_ref()
                        .map(|value| redactor.redact(value)),
                    capabilities,
                }
            })
            .collect();
        audit(
            self.audit_sink.as_ref(),
            config,
            request_id,
            principal,
            &Request::ProfileList,
            started,
            &CommandResult::success(),
            &redactor,
        );
        Ok(hosts)
    }

    pub async fn execute(
        &self,
        request_id: &str,
        caller: CallerType,
        task_id: Option<String>,
        request: Request,
    ) -> CommandResult {
        self.execute_principal(request_id, Principal::local(caller), task_id, request)
            .await
    }

    pub async fn execute_principal(
        &self,
        request_id: &str,
        principal: Principal,
        task_id: Option<String>,
        request: Request,
    ) -> CommandResult {
        let caller = principal.caller_type;
        let started = Instant::now();
        if let Err(err) = prevalidate(&request) {
            return error_result(err, &request);
        }
        if let Err(err) = PolicyEngine::authorize_caller(caller, &request) {
            return error_result(err, &request);
        }
        if matches!(request, Request::Ping) {
            return CommandResult::success().with_data(json!({
                "status": "ok",
                "version": env!("CARGO_PKG_VERSION"),
                "config_path": config_path_display().unwrap_or_else(|_| "unavailable".to_string()),
            }));
        }
        if matches!(request, Request::Shutdown) {
            self.shutdown().await;
            return CommandResult::success().with_data(json!({"status":"stopping"}));
        }
        let _config_guard = if matches!(
            &request,
            Request::ApprovalApprove { .. }
                | Request::ProfileCreate { .. }
                | Request::ProfileDelete { .. }
        ) {
            None
        } else {
            Some(self.config_access.read().await)
        };
        let config = self.profiles.load().await;
        self.execute_loaded(
            request_id,
            &principal,
            task_id,
            request,
            started,
            config,
            &principal.execution_namespace(),
        )
        .await
    }

    pub async fn execute_for_principal_config(
        &self,
        request_id: &str,
        principal: Principal,
        task_id: Option<String>,
        request: Request,
        config: AppConfig,
        _routing_namespace: &str,
    ) -> CommandResult {
        let caller = principal.caller_type;
        let started = Instant::now();
        if let Err(err) = prevalidate(&request) {
            return error_result(err, &request);
        }
        if let Err(err) = PolicyEngine::authorize_caller(caller, &request) {
            return error_result(err, &request);
        }
        self.execute_loaded(
            request_id,
            &principal,
            task_id,
            request,
            started,
            Ok(config),
            &principal.execution_namespace(),
        )
        .await
    }

    #[allow(clippy::too_many_arguments)]
    async fn execute_loaded(
        &self,
        request_id: &str,
        principal: &Principal,
        task_id: Option<String>,
        request: Request,
        started: Instant,
        config: Result<AppConfig, ArrtError>,
        session_namespace: &str,
    ) -> CommandResult {
        let mut result = match config {
            Ok(mut config) => {
                if principal.caller_type.enforces_agent_policy() {
                    config.authorization_namespace = Some(principal.execution_namespace());
                }
                let redactor = match &request {
                    Request::ProfileCreate { profile } => {
                        SecretRedactor::from_config_and_profile_with_credentials(
                            &config,
                            profile,
                            self.credentials.as_ref(),
                        )
                    }
                    _ => SecretRedactor::from_config_with_credentials(
                        &config,
                        self.credentials.as_ref(),
                    ),
                };
                let result = if matches!(
                    request,
                    Request::ProfileCreate { .. } | Request::ProfileDelete { .. }
                ) {
                    self.execute_mcp_profile_management(&config, principal, request.clone())
                        .await
                } else if matches!(
                    request,
                    Request::ApprovalList
                        | Request::ApprovalShow { .. }
                        | Request::ApprovalApprove { .. }
                        | Request::ApprovalReject { .. }
                        | Request::ApprovalCleanup
                        | Request::GrantList
                        | Request::GrantShow { .. }
                        | Request::GrantRevoke { .. }
                        | Request::GrantCleanup
                        | Request::PlanPropose { .. }
                        | Request::PlanList
                        | Request::PlanShow { .. }
                        | Request::PlanApprove { .. }
                        | Request::PlanReject { .. }
                ) {
                    self.execute_authorization_admin(
                        &config,
                        principal,
                        request.clone(),
                        session_namespace,
                    )
                    .await
                } else {
                    self.resolve_operation(
                        &config,
                        principal,
                        task_id.as_deref(),
                        request.clone(),
                        &redactor,
                        session_namespace,
                    )
                    .await
                };
                let mut result = result.unwrap_or_else(|err| error_result(err, &request));
                redact_result(&redactor, &mut result);
                audit(
                    self.audit_sink.as_ref(),
                    &config,
                    request_id,
                    principal,
                    &request,
                    started,
                    &result,
                    &redactor,
                );
                result
            }
            Err(err) => error_result(err, &request),
        };
        if result.duration_ms.is_none() && matches!(request, Request::Exec { .. }) {
            result.duration_ms = Some(started.elapsed().as_millis());
        }
        result
    }

    async fn execute_mcp_profile_management(
        &self,
        config: &AppConfig,
        principal: &Principal,
        request: Request,
    ) -> Result<CommandResult, ArrtError> {
        if principal.caller_type != CallerType::Mcp {
            return Err(ArrtError::PolicyDenied(
                "profile management requests are MCP-only".into(),
            ));
        }
        if !config.mcp.profile_management.enabled {
            return Err(ArrtError::ProfileManagementDisabled);
        }
        config.require_mutable_yaml()?;
        let request = match request {
            Request::ProfileCreate { profile } => {
                if config.profiles.iter().any(|item| item.name == profile.name) {
                    return Err(ArrtError::ProfileAlreadyExists(profile.name));
                }
                let mut candidate = config.clone();
                candidate.profiles.push((*profile).clone());
                candidate.validate()?;
                Request::ProfileCreate { profile }
            }
            Request::ProfileDelete { profile, .. } => {
                ensure_profile_deletable(config, &profile)?;
                if self.sessions.lock().await.has_any_profile_session(&profile) {
                    return Err(ArrtError::ProfileInUse(format!(
                        "profile {profile} has an active session"
                    )));
                }
                Request::ProfileDelete {
                    expected_profile_hash: config.profile_fingerprint(&profile)?,
                    profile,
                }
            }
            _ => {
                return Err(ArrtError::InvalidArgument(
                    "not a profile management request".into(),
                ))
            }
        };
        if matches!(
            config.runtime.mode,
            RuntimeMode::Cloud | RuntimeMode::PrivateWorker
        ) {
            let redactor = match &request {
                Request::ProfileCreate { profile } => {
                    SecretRedactor::from_config_and_profile_with_credentials(
                        config,
                        profile,
                        self.credentials.as_ref(),
                    )
                }
                _ => {
                    SecretRedactor::from_config_with_credentials(config, self.credentials.as_ref())
                }
            };
            let approval = self.approvals.open(config)?.create(
                &request,
                principal.caller_type,
                None,
                Some("Cloud profile mutation requires human approval"),
                Some(RiskLevelConfig::High),
                &redactor,
                None,
            )?;
            self.audit_approval(config, principal, "approval_created", &approval);
            return Ok(CommandResult::success()
                .with_data(json!({"status":"confirmation_required","approval":approval})));
        }
        self.execute_profile_mutation(config, request).await
    }

    async fn execute_profile_mutation(
        &self,
        config: &AppConfig,
        request: Request,
    ) -> Result<CommandResult, ArrtError> {
        let _guard = self.config_access.write().await;
        let mut config = config.reload_if_file_backed().await?;
        if !config.mcp.profile_management.enabled {
            return Err(ArrtError::ProfileManagementDisabled);
        }
        config.require_mutable_yaml()?;
        let expected_file_hash = config.file_hash().await?;
        match request {
            Request::ProfileCreate { profile } => {
                if config.profiles.iter().any(|item| item.name == profile.name) {
                    return Err(ArrtError::ProfileAlreadyExists(profile.name));
                }
                let name = profile.name.clone();
                config.profiles.push(*profile);
                config.validate()?;
                config.write_yaml_atomic(&expected_file_hash).await?;
                Ok(CommandResult::success().with_data(json!({"created":name})))
            }
            Request::ProfileDelete {
                profile,
                expected_profile_hash,
            } => {
                ensure_profile_deletable(&config, &profile)?;
                if config.profile_fingerprint(&profile)? != expected_profile_hash {
                    return Err(ArrtError::ConfigConflict(format!(
                        "profile {profile} changed while the mutation was being prepared"
                    )));
                }
                let sessions = self.sessions.lock().await;
                if sessions.has_any_profile_session(&profile) {
                    return Err(ArrtError::ProfileInUse(format!(
                        "profile {profile} has an active session"
                    )));
                }
                config.profiles.retain(|item| item.name != profile);
                config.validate()?;
                config.write_yaml_atomic(&expected_file_hash).await?;
                drop(sessions);
                Ok(CommandResult::success().with_data(json!({"deleted":profile})))
            }
            _ => Err(ArrtError::InvalidArgument(
                "not a profile management request".into(),
            )),
        }
    }

    async fn resolve_operation(
        &self,
        config: &AppConfig,
        principal: &Principal,
        task_id: Option<&str>,
        request: Request,
        redactor: &SecretRedactor,
        session_namespace: &str,
    ) -> Result<CommandResult, ArrtError> {
        let caller = principal.caller_type;
        let decision = PolicyEngine::authorize(config, caller, &request)?;
        if decision.effect == PolicyEffect::Deny {
            return Err(ArrtError::PolicyDenied(
                decision
                    .reason
                    .unwrap_or_else(|| "policy rule denied operation".into()),
            ));
        }
        if decision.effect == PolicyEffect::Allow
            && (!caller.enforces_agent_policy() || task_id.is_none() || !config.approval.enabled)
        {
            return self
                .execute_authorized(config, caller, request, session_namespace)
                .await;
        }
        let grants = GrantService::from_config(config)?;
        let profile = request_profile(&request).unwrap_or_default();
        let plan = if caller.enforces_agent_policy() {
            grants.claim_plan_action(profile, task_id, &request)?
        } else {
            None
        };
        if let Some(plan) = plan {
            return self
                .execute_enveloped(
                    config,
                    principal,
                    request,
                    Some(plan),
                    None,
                    &grants,
                    session_namespace,
                )
                .await;
        }
        if decision.effect == PolicyEffect::Allow {
            return self
                .execute_authorized(config, caller, request, session_namespace)
                .await;
        }
        let rule_id = decision
            .rule_id
            .as_deref()
            .ok_or_else(|| ArrtError::PolicyDenied("confirm decision has no rule id".into()))?;
        if let Some(grant_id) = grants.consume(profile, rule_id, task_id)? {
            return self
                .execute_enveloped(
                    config,
                    principal,
                    request,
                    None,
                    Some(grant_id),
                    &grants,
                    session_namespace,
                )
                .await;
        }
        let approval = self.approvals.open(config)?.create(
            &request,
            caller,
            decision.rule_id.as_deref(),
            decision.reason.as_deref(),
            decision.risk,
            redactor,
            task_id,
        )?;
        self.audit_approval(config, principal, "approval_created", &approval);
        Ok(CommandResult::success()
            .with_data(json!({"status":"confirmation_required","approval":approval})))
    }

    #[allow(clippy::too_many_arguments)]
    async fn execute_enveloped(
        &self,
        config: &AppConfig,
        principal: &Principal,
        request: Request,
        plan: Option<PlanAuthorization>,
        grant_id: Option<String>,
        grants: &GrantService,
        session_namespace: &str,
    ) -> Result<CommandResult, ArrtError> {
        let caller = principal.caller_type;
        let result = self
            .execute_authorized(config, caller, request, session_namespace)
            .await;
        if let Some(auth) = plan {
            let success = result.as_ref().is_ok_and(|r| r.ok);
            let event = grants.finish_plan_action(&auth, success)?;
            self.audit_approval(
                config,
                principal,
                if event["status"] == "completed" {
                    "plan_completed"
                } else {
                    "plan_action_executed"
                },
                &event,
            );
        }
        let mut result = result?;
        if let Some(id) = grant_id {
            let data = result.data.get_or_insert_with(|| json!({}));
            if let Some(object) = data.as_object_mut() {
                object.insert(
                    "authorization".into(),
                    json!({"type":"grant","grant_id":id}),
                );
            }
            self.audit_approval(config, principal, "grant_used", &json!({"grant_id":id}));
            if grants.show(&id)?["status"] == "exhausted" {
                self.audit_approval(
                    config,
                    principal,
                    "grant_exhausted",
                    &json!({"grant_id":id}),
                );
            }
        }
        Ok(result)
    }

    async fn execute_authorization_admin(
        &self,
        config: &AppConfig,
        principal: &Principal,
        request: Request,
        session_namespace: &str,
    ) -> Result<CommandResult, ArrtError> {
        let caller = principal.caller_type;
        if matches!(request, Request::PlanPropose { .. }) {
            if caller == CallerType::HumanCli {
                return Err(ArrtError::PolicyDenied(
                    "plan proposals require an agent caller".into(),
                ));
            }
            let grants = GrantService::from_config(config)?;
            let redactor =
                SecretRedactor::from_config_with_credentials(config, self.credentials.as_ref());
            if let Request::PlanPropose {
                profile,
                task_id,
                actions,
            } = request
            {
                for action in &actions {
                    let decision = PolicyEngine::authorize(config, caller, action)?;
                    if decision.effect == PolicyEffect::Deny {
                        return Err(ArrtError::PolicyDenied(
                            "plan contains a denied action".into(),
                        ));
                    }
                }
                let plan = grants.propose_plan(
                    &profile,
                    &task_id,
                    &actions,
                    config.approval.ttl_seconds,
                    &redactor,
                )?;
                self.audit_approval(config, principal, "plan_created", &plan);
                return Ok(CommandResult::success().with_data(json!({"plan":plan})));
            }
        }
        if caller != CallerType::HumanCli {
            return Err(ArrtError::PolicyDenied(
                "approval administration requires Human CLI".into(),
            ));
        }
        let approvals = self.approvals.open(config)?;
        match request {
            Request::ApprovalList => {
                Ok(CommandResult::success().with_data(json!({"approvals":approvals.list()?})))
            }
            Request::ApprovalShow { approval_id } => {let mut approval=approvals.show(&approval_id)?;add_approval_suggestions(config,&mut approval);Ok(CommandResult::success().with_data(json!({"approval":approval})))},
            Request::ApprovalReject { approval_id } => {
                let data = approvals.reject(&approval_id)?;
                self.audit_approval(config, principal, "approval_rejected", &approvals.show(&approval_id)?);
                Ok(CommandResult::success().with_data(data))
            }
            Request::ApprovalCleanup => {
                Ok(CommandResult::success().with_data(approvals.cleanup()?))
            }
            Request::ApprovalApprove { approval_id,grant_ttl_seconds,grant_task_id,max_uses } => {
                let approval_metadata = approvals.show(&approval_id)?;
                let is_profile_management = matches!(
                    approval_metadata.get("operation").and_then(|value| value.as_str()),
                    Some("profile_create" | "profile_delete")
                );
                if is_profile_management
                    && (grant_ttl_seconds.is_some() || grant_task_id.is_some() || max_uses.is_some())
                {
                    return Err(ArrtError::PolicyDenied(
                        "profile management approvals cannot create grants".into(),
                    ));
                }
                let grant_request=if grant_ttl_seconds.is_some()||grant_task_id.is_some()||max_uses.is_some(){let grants=GrantService::from_config(config)?;let ttl=grant_ttl_seconds.unwrap_or(1200);grants.validate_pending_grant(&approval_id,ttl,grant_task_id.as_deref(),max_uses)?;Some((grants,ttl))}else{None};
                let claim = approvals.claim(&approval_id)?;
                let current_hash = request_hash(&claim.request);
                if current_hash.as_ref().is_err_and(|_| true)
                    || current_hash.is_ok_and(|hash| hash != claim.request_hash)
                {
                    let failed = error_result(
                        ArrtError::Approval("request changed after approval creation".into()),
                        &claim.request,
                    );
                    approvals.finish(&claim.id, &failed)?;
                    return Ok(failed);
                }
                if matches!(&claim.request, Request::ProfileCreate { .. } | Request::ProfileDelete { .. }) {
                    self.audit_approval(config, principal, "approval_approved", &approvals.show(&claim.id)?);
                    let mut result = self
                        .execute_profile_mutation(config, claim.request.clone())
                        .await
                        .unwrap_or_else(|err| error_result(err, &claim.request));
                    let current_config = config
                        .reload_if_file_backed()
                        .await
                        .unwrap_or_else(|_| config.clone());
                    let redactor = match &claim.request {
                        Request::ProfileCreate { profile } => {
                            SecretRedactor::from_config_and_profile_with_credentials(&current_config, profile, self.credentials.as_ref())
                        }
                        _ => SecretRedactor::from_config_with_credentials(&current_config, self.credentials.as_ref()),
                    };
                    redact_result(&redactor, &mut result);
                    approvals.finish(&claim.id, &result)?;
                    self.audit_approval(config, principal,
                        if result.ok { "approval_executed" } else { "approval_failed" },
                        &approvals.show(&claim.id)?,
                    );
                    return Ok(CommandResult::success().with_data(json!({"status":if result.ok{"executed"}else{"failed"},"approval_id":claim.id,"result":result})));
                }
                let _config_guard = self.config_access.read().await;
                let current_config = config.reload_if_file_backed().await?;
                let decision = match PolicyEngine::authorize(&current_config, claim.caller, &claim.request) {
                    Ok(decision) => decision,
                    Err(err) => {
                        let failed = error_result(err, &claim.request);
                        approvals.finish(&claim.id, &failed)?;
                        return Ok(failed);
                    }
                };
                if decision.effect == PolicyEffect::Deny {
                    let failed = error_result(
                        ArrtError::PolicyDenied(
                            decision
                                .reason
                                .unwrap_or_else(|| "policy now denies operation".into()),
                        ),
                        &claim.request,
                    );
                    approvals.finish(&claim.id, &failed)?;
                    return Ok(failed);
                }
                if let Some((grants,ttl))=grant_request {
                    if decision.effect == PolicyEffect::Confirm {
                        let grant=decision.rule_id.as_deref().ok_or_else(||ArrtError::Approval("confirm decision has no rule id".into())).and_then(|rule_id|grants.create_from_claimed_approval(&claim.id,ttl,grant_task_id.as_deref(),max_uses,rule_id));
                        match grant{Ok(grant)=>self.audit_approval(config,principal,"grant_created",&grant),Err(err)=>{let failed=error_result(err,&claim.request);approvals.finish(&claim.id,&failed)?;return Ok(failed);}}
                    }
                }
                self.audit_approval(config, principal, "approval_approved", &approvals.show(&claim.id)?);
                let mut result = self
                    .execute_authorized(
                        &current_config,
                        claim.caller,
                        claim.request.clone(),
                        claim.authorization_namespace.as_deref().unwrap_or(session_namespace),
                    )
                    .await
                    .unwrap_or_else(|e| error_result(e, &claim.request));
                let redactor = SecretRedactor::from_config_with_credentials(&current_config, self.credentials.as_ref());
                redact_result(&redactor, &mut result);
                approvals.finish(&claim.id, &result)?;
                self.audit_approval(config, principal,
                    if result.ok {
                        "approval_executed"
                    } else {
                        "approval_failed"
                    },
                    &approvals.show(&claim.id)?,
                );
                Ok(CommandResult::success().with_data(json!({"status":if result.ok{"executed"}else{"failed"},"approval_id":claim.id,"result":result})))
            }
            Request::GrantList=>Ok(CommandResult::success().with_data(json!({"grants":GrantService::from_config(config)?.list()?}))),
            Request::GrantShow{grant_id}=>Ok(CommandResult::success().with_data(json!({"grant":GrantService::from_config(config)?.show(&grant_id)?}))),
            Request::GrantRevoke{grant_id}=>{let data=GrantService::from_config(config)?.revoke(&grant_id)?;self.audit_approval(config,principal,"grant_revoked",&data);Ok(CommandResult::success().with_data(data))},
            Request::GrantCleanup=>Ok(CommandResult::success().with_data(GrantService::from_config(config)?.cleanup_grants()?)),
            Request::PlanList=>Ok(CommandResult::success().with_data(json!({"plans":GrantService::from_config(config)?.list_plans()?}))),
            Request::PlanShow{plan_id}=>Ok(CommandResult::success().with_data(json!({"plan":GrantService::from_config(config)?.show_plan(&plan_id,&SecretRedactor::from_config_with_credentials(config, self.credentials.as_ref()))?}))),
            Request::PlanApprove{plan_id}=>{let data=GrantService::from_config(config)?.approve_plan(&plan_id)?;self.audit_approval(config,principal,"plan_approved",&data);Ok(CommandResult::success().with_data(data))},
            Request::PlanReject{plan_id}=>{let data=GrantService::from_config(config)?.reject_plan(&plan_id)?;self.audit_approval(config,principal,"plan_rejected",&data);Ok(CommandResult::success().with_data(data))},
            _ => Err(ArrtError::InvalidArgument("not an approval request".into())),
        }
    }

    fn audit_approval(
        &self,
        config: &AppConfig,
        principal: &Principal,
        event: &str,
        metadata: &serde_json::Value,
    ) {
        let redactor =
            SecretRedactor::from_config_with_credentials(config, self.credentials.as_ref());
        let mut safe_metadata = metadata.clone();
        redactor.redact_value(&mut safe_metadata);
        let timestamp_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| d.as_millis());
        self.audit_sink
            .emit_authorization(&AuthorizationAuditEvent {
                event,
                timestamp_ms,
                principal,
                metadata: &safe_metadata,
            });
    }

    pub async fn shutdown(&self) {
        if let Ok(config) = self.profiles.load().await {
            self.sessions.lock().await.close_all(&config).await;
        }
    }

    async fn execute_authorized(
        &self,
        config: &AppConfig,
        caller: CallerType,
        request: Request,
        session_namespace: &str,
    ) -> Result<CommandResult, ArrtError> {
        if matches!(
            config.runtime.mode,
            RuntimeMode::Cloud | RuntimeMode::PrivateWorker
        ) && matches!(
            request,
            Request::TunnelOpen { .. } | Request::TunnelClose { .. }
        ) {
            return Err(ArrtError::PolicyDenied(
                "Cloud runtime disables SSH tunnels".into(),
            ));
        }
        match request {
            Request::Ping => Ok(CommandResult::success().with_data(json!({
                "status": "ok",
                "version": env!("CARGO_PKG_VERSION"),
            }))),
            Request::Shutdown => {
                self.sessions.lock().await.close_all(config).await;
                Ok(CommandResult::success().with_data(json!({"status":"stopping"})))
            }
            Request::ProfileList => Ok(CommandResult::success().with_data(json!({
                "profiles": config.profiles.iter().map(|profile| &profile.name).collect::<Vec<_>>()
            }))),
            Request::ProfileShow { name } => {
                Ok(CommandResult::success().with_data(config.profile_summary_with_credentials(&name, self.credentials.as_ref())?))
            }
            Request::ProfileValidate { name } => {
                config.validate()?;
                if let Some(name) = name {
                    let profile = config.profile(&name)?;
                    Ok(CommandResult::success()
                        .with_data(json!({"valid": true, "profile": profile.name})))
                } else {
                    Ok(CommandResult::success()
                        .with_data(json!({"valid": true, "profiles": config.profiles.len()})))
                }
            }
            Request::ProfilePolicy { profile } => {
                let profiles = match profile {
                    Some(name) => vec![config.profile(&name)?],
                    None => config.profiles.clone(),
                };
                Ok(CommandResult::success().with_data(json!({
                    "policies": profiles.into_iter().map(|profile| json!({
                        "profile": profile.name,
                        "agent_policy": profile.agent_policy,
                    })).collect::<Vec<_>>()
                })))
            }
            Request::ProfileCreate { .. } | Request::ProfileDelete { .. } => {
                Err(ArrtError::PolicyDenied(
                    "profile management requests must use the MCP management tools".into(),
                ))
            }
            Request::Exec {
                profile,
                command,
                cwd,
                timeout_seconds,
                env,
            } => {
                let prepared = {
                    let mut sessions = self.sessions.lock().await;
                    sessions.reap_idle_sessions(config, session_namespace).await;
                    sessions
                        .prepare_exec(
                            config,
                            session_namespace,
                            &profile,
                            command,
                            cwd,
                            timeout_seconds,
                            env,
                        )
                        .await?
                };
                let session_id = prepared.session_id().to_string();
                let result = SessionManager::execute_prepared_exec(&prepared).await;
                self.sessions.lock().await.finish_exec(&session_id);
                result
            }
            Request::Read { profile, path } => {
                let roots = allowed_remote_paths(config, caller, &profile, false)?;
                let mut sessions = self.sessions.lock().await;
                sessions.reap_idle_sessions(config, session_namespace).await;
                sessions
                    .read(config, session_namespace, &profile, path, &roots)
                    .await
            }
            Request::Write {
                profile,
                path,
                mode,
                content_b64,
            } => {
                let roots = allowed_remote_paths(config, caller, &profile, true)?;
                let mut sessions = self.sessions.lock().await;
                sessions.reap_idle_sessions(config, session_namespace).await;
                sessions
                    .write(config, session_namespace, &profile, path, mode, content_b64, &roots)
                    .await
            }
            Request::Upload { profile, src, dst } => {
                absolute_local_path(src.clone(), "upload src")?;
                let roots = allowed_remote_paths(config, caller, &profile, true)?;
                let mut sessions = self.sessions.lock().await;
                sessions.reap_idle_sessions(config, session_namespace).await;
                sessions
                    .upload(config, session_namespace, &profile, src, dst, &roots)
                    .await
            }
            Request::Download { profile, src, dst } => {
                absolute_local_path(dst.clone(), "download dst")?;
                let roots = allowed_remote_paths(config, caller, &profile, false)?;
                let mut sessions = self.sessions.lock().await;
                sessions.reap_idle_sessions(config, session_namespace).await;
                sessions
                    .download(config, session_namespace, &profile, src, dst, &roots)
                    .await
            }
            Request::TunnelOpen {
                profile,
                local_port,
                remote_host,
                remote_port,
            } => {
                let mut sessions = self.sessions.lock().await;
                sessions.reap_idle_sessions(config, session_namespace).await;
                sessions
                    .tunnel_open(
                        config,
                        session_namespace,
                        &profile,
                        local_port,
                        remote_host,
                        remote_port,
                    )
                    .await
            }
            Request::TunnelClose { tunnel_id, profile } => {
                let mut sessions = self.sessions.lock().await;
                if let Some(expected_profile) = profile {
                    if sessions.tunnel_profile(session_namespace, &tunnel_id)
                        != Some(expected_profile.as_str())
                    {
                        return Err(ArrtError::PolicyDenied(
                            "tunnel does not belong to the supplied profile".to_string(),
                        ));
                    }
                }
                sessions
                    .tunnel_close(config, session_namespace, &tunnel_id)
                    .await
            }
            Request::SessionList => Ok(CommandResult::success().with_data(json!({
                "sessions": self.sessions.lock().await.sessions_json(session_namespace)
            }))),
            Request::SessionInspect { session_id } => {
                Ok(CommandResult::success().with_data(json!({
                    "session": self.sessions.lock().await.session_json(session_namespace, &session_id)?
                })))
            }
            Request::SessionClose { session_id } => {
                self.sessions
                    .lock()
                    .await
                    .close_session(config, session_namespace, &session_id)
                    .await?;
                Ok(CommandResult::success().with_data(json!({"closed": session_id})))
            }
            Request::ApprovalList
            | Request::ApprovalShow { .. }
            | Request::ApprovalApprove { .. }
            | Request::ApprovalReject { .. }
            | Request::ApprovalCleanup => Err(ArrtError::InvalidArgument(
                "approval request reached operation executor".into(),
            )),
            Request::GrantList
            | Request::GrantShow { .. }
            | Request::GrantRevoke { .. }
            | Request::GrantCleanup
            | Request::PlanPropose { .. }
            | Request::PlanList
            | Request::PlanShow { .. }
            | Request::PlanApprove { .. }
            | Request::PlanReject { .. } => Err(ArrtError::InvalidArgument(
                "authorization administration reached operation executor".into(),
            )),
        }
    }
}

fn ensure_profile_deletable(config: &AppConfig, profile: &str) -> Result<(), ArrtError> {
    config.profile(profile)?;
    if config.profiles.len() == 1 {
        return Err(ArrtError::ProfileInUse(
            "the last configured profile cannot be deleted".into(),
        ));
    }
    let dependents = config
        .profiles
        .iter()
        .filter(|item| item.via_profile.as_deref() == Some(profile))
        .map(|item| item.name.clone())
        .collect::<Vec<_>>();
    if !dependents.is_empty() {
        return Err(ArrtError::ProfileInUse(format!(
            "profile {profile} is referenced by {}",
            dependents.join(", ")
        )));
    }
    Ok(())
}

fn allowed_remote_paths(
    config: &AppConfig,
    caller: CallerType,
    profile: &str,
    write: bool,
) -> Result<Vec<String>, ArrtError> {
    if !caller.enforces_agent_policy() {
        return Ok(Vec::new());
    }
    let policy = config.profile(profile)?.agent_policy;
    Ok(if write {
        policy.allowed_write_paths
    } else {
        policy.allowed_read_paths
    })
}

fn prevalidate(request: &Request) -> Result<(), ArrtError> {
    match request {
        Request::Upload { src, .. } => absolute_local_path(src.clone(), "upload src").map(|_| ()),
        Request::Download { dst, .. } => {
            absolute_local_path(dst.clone(), "download dst").map(|_| ())
        }
        _ => Ok(()),
    }
}

fn error_result(err: ArrtError, request: &Request) -> CommandResult {
    let data = match request {
        Request::Upload { src, dst, .. } => Some(json!({"local_src": src, "remote_dst": dst})),
        Request::Download { src, dst, .. } => Some(json!({"remote_src": src, "local_dst": dst})),
        _ => None,
    };
    CommandResult {
        ok: false,
        exit_code: None,
        stdout: String::new(),
        stderr: String::new(),
        duration_ms: None,
        session_id: None,
        error: Some(ErrorPayload {
            code: err.code().to_string(),
            message: err.to_string(),
        }),
        data,
    }
}

fn redact_result(redactor: &SecretRedactor, result: &mut CommandResult) {
    result.stdout = redactor.redact(&result.stdout);
    result.stderr = redactor.redact(&result.stderr);
    if let Some(error) = &mut result.error {
        error.message = redactor.redact(&error.message);
    }
    if let Some(data) = &mut result.data {
        redactor.redact_value(data);
    }
}

#[allow(clippy::too_many_arguments)]
fn audit(
    sink: &dyn AuditSink,
    config: &AppConfig,
    request_id: &str,
    principal: &Principal,
    request: &Request,
    started: Instant,
    result: &CommandResult,
    redactor: &SecretRedactor,
) {
    let profile = request_profile(request);
    let command = match request {
        Request::Exec {
            profile, command, ..
        } if config
            .profile(profile)
            .is_ok_and(|p| p.agent_policy.audit_command) =>
        {
            Some(redactor.redact(command))
        }
        _ => None,
    };
    let timestamp_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_millis());
    sink.emit(&AuditEvent {
        event: "ssh_gateway_audit",
        timestamp_ms,
        request_id,
        principal,
        operation: request_name(request),
        profile,
        command,
        duration_ms: started.elapsed().as_millis(),
        success: result.ok,
        error_code: result.error.as_ref().map(|error| error.code.as_str()),
    });
}

fn request_profile(request: &Request) -> Option<&str> {
    match request {
        Request::Exec { profile, .. }
        | Request::Read { profile, .. }
        | Request::Write { profile, .. }
        | Request::Upload { profile, .. }
        | Request::Download { profile, .. }
        | Request::TunnelOpen { profile, .. }
        | Request::ProfileDelete { profile, .. } => Some(profile),
        Request::ProfileCreate { profile } => Some(&profile.name),
        Request::ProfilePolicy {
            profile: Some(profile),
        } => Some(profile),
        _ => None,
    }
}

fn request_name(request: &Request) -> &'static str {
    match request {
        Request::Ping => "ping",
        Request::Shutdown => "shutdown",
        Request::ProfileList => "profile_list",
        Request::ProfileShow { .. } => "profile_show",
        Request::ProfileValidate { .. } => "profile_validate",
        Request::ProfilePolicy { .. } => "profile_policy",
        Request::ProfileCreate { .. } => "profile_create",
        Request::ProfileDelete { .. } => "profile_delete",
        Request::Exec { .. } => "exec",
        Request::Read { .. } => "read",
        Request::Write { .. } => "write",
        Request::Upload { .. } => "upload",
        Request::Download { .. } => "download",
        Request::TunnelOpen { .. } => "tunnel_open",
        Request::TunnelClose { .. } => "tunnel_close",
        Request::SessionList => "session_list",
        Request::SessionInspect { .. } => "session_inspect",
        Request::SessionClose { .. } => "session_close",
        Request::ApprovalList => "approval_list",
        Request::ApprovalShow { .. } => "approval_show",
        Request::ApprovalApprove { .. } => "approval_approve",
        Request::ApprovalReject { .. } => "approval_reject",
        Request::ApprovalCleanup => "approval_cleanup",
        Request::GrantList => "grant_list",
        Request::GrantShow { .. } => "grant_show",
        Request::GrantRevoke { .. } => "grant_revoke",
        Request::GrantCleanup => "grant_cleanup",
        Request::PlanPropose { .. } => "plan_propose",
        Request::PlanList => "plan_list",
        Request::PlanShow { .. } => "plan_show",
        Request::PlanApprove { .. } => "plan_approve",
        Request::PlanReject { .. } => "plan_reject",
    }
}

fn add_approval_suggestions(config: &AppConfig, approval: &mut serde_json::Value) {
    let risk = approval["risk"].as_str().unwrap_or("low");
    let policy = match risk {
        "critical" => &config.approval.grants.critical,
        "high" => &config.approval.grants.high,
        "medium" => &config.approval.grants.medium,
        _ => &config.approval.grants.low,
    };
    let mut suggested = json!({"once":{"scope":"exact request"}});
    if let Some(object) = suggested.as_object_mut() {
        if policy.task && !approval["task_id"].is_null() {
            object.insert(
                "task".into(),
                json!({"rule_id":approval["rule_id"],"task_id":approval["task_id"],"ttl":"20m"}),
            );
        }
        if policy.time {
            object.insert(
                "temporary".into(),
                json!({"rule_id":approval["rule_id"],"ttl":"30m"}),
            );
        }
    }
    if let Some(object) = approval.as_object_mut() {
        object.insert("suggested_approvals".into(), suggested);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn cloud_and_private_worker_runtimes_reject_tunnel_before_connection() {
        for mode in [RuntimeMode::Cloud, RuntimeMode::PrivateWorker] {
            let mut config = AppConfig::default();
            config.runtime.mode = mode;
            let service = GatewayService::new();
            let result = service
                .execute_authorized(
                    &config,
                    CallerType::HumanCli,
                    Request::TunnelOpen {
                        profile: "missing".into(),
                        local_port: 1234,
                        remote_host: "example.com".into(),
                        remote_port: 80,
                    },
                    "test",
                )
                .await;
            assert!(
                matches!(result, Err(ArrtError::PolicyDenied(message)) if message.contains("disables SSH tunnels"))
            );
        }
    }

    #[tokio::test]
    async fn cloud_profile_deletion_requires_single_use_human_approval() {
        let dir =
            std::env::temp_dir().join(format!("sshmcp-cloud-profile-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("profiles.yaml");
        let db = dir.join("approvals.db");
        std::fs::write(&path, format!("runtime:\n  mode: cloud\n  host_key_mode: strict\napproval:\n  storage:\n    type: sqlite\n    path: {}\nmcp:\n  profile_management:\n    enabled: true\nprofiles:\n  - name: first\n    target:\n      host: example.com\n      user: root\n      auth: {{ type: password, password: secret-one }}\n  - name: second\n    target:\n      host: example.net\n      user: root\n      auth: {{ type: password, password: secret-two }}\n", db.display())).unwrap();
        let mut config = AppConfig::load_from_path(path.clone()).await.unwrap();
        let principal = Principal::local(CallerType::Mcp);
        config.authorization_namespace = Some(principal.execution_namespace());
        let service = GatewayService::new();
        let result = service
            .execute_mcp_profile_management(
                &config,
                &principal,
                Request::ProfileDelete {
                    profile: "second".into(),
                    expected_profile_hash: String::new(),
                },
            )
            .await
            .unwrap();
        assert_eq!(
            result.data.as_ref().unwrap()["status"],
            "confirmation_required"
        );
        assert!(std::fs::read_to_string(&path)
            .unwrap()
            .contains("name: second"));
        let approval_id = result.data.unwrap()["approval"]["id"]
            .as_str()
            .unwrap()
            .to_string();
        let human = Principal::local(CallerType::HumanCli);
        let approved = service
            .execute_authorization_admin(
                &config,
                &human,
                Request::ApprovalApprove {
                    approval_id: approval_id.clone(),
                    grant_ttl_seconds: None,
                    grant_task_id: None,
                    max_uses: None,
                },
                "human",
            )
            .await
            .unwrap();
        assert_eq!(approved.data.as_ref().unwrap()["status"], "executed");
        assert!(!std::fs::read_to_string(&path)
            .unwrap()
            .contains("name: second"));
        assert!(service
            .execute_authorization_admin(
                &config,
                &human,
                Request::ApprovalApprove {
                    approval_id,
                    grant_ttl_seconds: None,
                    grant_task_id: None,
                    max_uses: None
                },
                "human"
            )
            .await
            .is_err());
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn audit_sink_receives_redacted_command_and_principal() {
        struct Capture(std::sync::Mutex<Vec<String>>);
        impl AuditSink for Capture {
            fn emit(&self, event: &AuditEvent<'_>) {
                self.0
                    .lock()
                    .unwrap()
                    .push(serde_json::to_string(event).unwrap());
            }
            fn emit_authorization(&self, event: &AuthorizationAuditEvent<'_>) {
                self.0
                    .lock()
                    .unwrap()
                    .push(serde_json::to_string(event).unwrap());
            }
        }
        let config: AppConfig = serde_yaml::from_str("profiles:\n  - name: host\n    target:\n      host: example.com\n      user: root\n      auth:\n        type: password\n        password: secret-value\n").unwrap();
        let redactor = SecretRedactor::from_config(&config);
        let principal = Principal::local(CallerType::Mcp);
        let request = Request::Exec {
            profile: "host".into(),
            command: "echo secret-value".into(),
            cwd: None,
            timeout_seconds: None,
            env: Vec::new(),
        };
        let sink = Arc::new(Capture(std::sync::Mutex::new(Vec::new())));
        audit(
            sink.as_ref(),
            &config,
            "request",
            &principal,
            &request,
            Instant::now(),
            &CommandResult::success(),
            &redactor,
        );
        let service = GatewayService::with_providers(
            Arc::new(FileProfileStore),
            Arc::new(FileCredentialStore),
            Arc::new(SqliteApprovalStoreFactory),
            sink.clone(),
        );
        service.audit_approval(
            &config,
            &principal,
            "approval_created",
            &json!({"summary":"secret-value"}),
        );
        let events = sink.0.lock().unwrap();
        assert_eq!(events.len(), 2);
        for event in events.iter() {
            assert!(!event.contains("secret-value"));
            assert!(event.contains("local-bearer"));
        }
    }

    #[test]
    fn transfer_prevalidation_preserves_daemon_boundary() {
        let upload = Request::Upload {
            profile: "unused".to_string(),
            src: "relative/input.txt".to_string(),
            dst: "/tmp/input.txt".to_string(),
        };
        let download = Request::Download {
            profile: "unused".to_string(),
            src: "/tmp/output.txt".to_string(),
            dst: "relative/output.txt".to_string(),
        };
        assert_eq!(
            prevalidate(&upload).unwrap_err().code(),
            "relative_local_path"
        );
        assert_eq!(
            prevalidate(&download).unwrap_err().code(),
            "relative_local_path"
        );
        assert_eq!(
            error_result(ArrtError::Io("failed".into()), &upload)
                .data
                .unwrap()["local_src"],
            "relative/input.txt"
        );
    }

    #[tokio::test]
    async fn shutdown_respects_caller_policy_before_lifecycle_shortcut() {
        let service = GatewayService::new();
        let human = service
            .execute("human", CallerType::HumanCli, None, Request::Shutdown)
            .await;
        let agent = service
            .execute("agent", CallerType::AgentCli, None, Request::Shutdown)
            .await;
        let mcp = service
            .execute("mcp", CallerType::Mcp, None, Request::Shutdown)
            .await;

        assert!(human.ok);
        assert_eq!(human.data.unwrap()["status"], "stopping");
        assert_eq!(agent.error.unwrap().code, "policy_denied");
        assert_eq!(mcp.error.unwrap().code, "policy_denied");
    }

    #[tokio::test]
    async fn deny_is_checked_before_any_grant() {
        let path = std::env::temp_dir().join(format!("sshmcp-deny-{}.db", uuid::Uuid::new_v4()));
        let mut config: AppConfig = serde_yaml::from_str(
            r#"profiles:
- name: test
  target: {host: example, user: root, auth: {type: password, password: secret}}
  agent_policy:
    rules:
    - {id: deny, match: {operation: exec, commands: [reboot]}, effect: deny, risk: critical}
"#,
        )
        .unwrap();
        config.approval.storage.path = Some(path.display().to_string());
        let request = Request::Exec {
            profile: "test".into(),
            command: "reboot".into(),
            cwd: None,
            timeout_seconds: Some(1),
            env: vec![],
        };
        let result = GatewayService::new()
            .resolve_operation(
                &config,
                &Principal::local(CallerType::Mcp),
                Some("task"),
                request,
                &SecretRedactor::from_config(&config),
                DEFAULT_SESSION_NAMESPACE,
            )
            .await;
        assert!(matches!(result, Err(ArrtError::PolicyDenied(_))));
        assert!(!path.exists());
    }

    #[tokio::test]
    async fn grant_is_not_created_when_policy_changes_to_deny() {
        let path =
            std::env::temp_dir().join(format!("sshmcp-grant-deny-{}.db", uuid::Uuid::new_v4()));
        let mut config: AppConfig = serde_yaml::from_str(
            r#"profiles:
- name: test
  target: {host: example, user: root, auth: {type: password, password: secret}}
  agent_policy:
    rules:
    - {id: dangerous, match: {operation: exec, commands: [reboot]}, effect: deny, risk: critical}
"#,
        )
        .unwrap();
        config.approval.storage.path = Some(path.display().to_string());
        config.approval.grants.critical.task = true;
        let request = Request::Exec {
            profile: "test".into(),
            command: "reboot".into(),
            cwd: None,
            timeout_seconds: Some(1),
            env: vec![],
        };
        let approvals = ApprovalService::from_config(&config).unwrap();
        let approval = approvals
            .create(
                &request,
                CallerType::Mcp,
                Some("dangerous"),
                None,
                Some(crate::config::RiskLevelConfig::Critical),
                &SecretRedactor::from_config(&config),
                Some("task"),
            )
            .unwrap();
        let id = approval["id"].as_str().unwrap().to_string();
        let result = GatewayService::new()
            .execute_authorization_admin(
                &config,
                &Principal::local(CallerType::HumanCli),
                Request::ApprovalApprove {
                    approval_id: id,
                    grant_ttl_seconds: Some(60),
                    grant_task_id: Some("task".into()),
                    max_uses: Some(2),
                },
                DEFAULT_SESSION_NAMESPACE,
            )
            .await
            .unwrap();
        assert!(!result.ok);
        assert!(GrantService::from_config(&config)
            .unwrap()
            .list()
            .unwrap()
            .as_array()
            .unwrap()
            .is_empty());
        let _ = std::fs::remove_file(path);
    }

    #[tokio::test]
    async fn max_uses_only_approval_creates_grant() {
        let path =
            std::env::temp_dir().join(format!("sshmcp-grant-max-uses-{}.db", uuid::Uuid::new_v4()));
        let mut config: AppConfig = serde_yaml::from_str(
            r#"profiles:
- name: test
  target: {host: example, user: root, auth: {type: password, password: secret}}
  agent_policy:
    rules:
    - {id: restart, match: {operation: exec, commands: ["systemctl restart nginx"]}, effect: confirm, risk: medium}
"#,
        )
        .unwrap();
        config.approval.storage.path = Some(path.display().to_string());
        let request = Request::Exec {
            profile: "test".into(),
            command: "systemctl restart nginx".into(),
            cwd: None,
            timeout_seconds: Some(1),
            env: vec![],
        };
        let approvals = ApprovalService::from_config(&config).unwrap();
        let approval = approvals
            .create(
                &request,
                CallerType::Mcp,
                Some("restart"),
                None,
                Some(crate::config::RiskLevelConfig::Medium),
                &SecretRedactor::from_config(&config),
                Some("task"),
            )
            .unwrap();
        let id = approval["id"].as_str().unwrap().to_string();
        let _ = GatewayService::new()
            .execute_authorization_admin(
                &config,
                &Principal::local(CallerType::HumanCli),
                Request::ApprovalApprove {
                    approval_id: id,
                    grant_ttl_seconds: None,
                    grant_task_id: None,
                    max_uses: Some(10),
                },
                DEFAULT_SESSION_NAMESPACE,
            )
            .await
            .unwrap();
        let grants = GrantService::from_config(&config).unwrap().list().unwrap();
        assert_eq!(grants.as_array().unwrap().len(), 1);
        assert_eq!(grants[0]["max_uses"], 10);
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn delete_rejects_last_and_referenced_profiles() {
        let last: AppConfig = serde_yaml::from_str(
            "profiles:\n- name: only\n  target: {host: example, user: root, auth: {type: password, password: secret}}\n",
        )
        .unwrap();
        assert!(matches!(
            ensure_profile_deletable(&last, "only"),
            Err(ArrtError::ProfileInUse(_))
        ));
        let referenced: AppConfig = serde_yaml::from_str(
            "profiles:\n- name: upstream\n  target: {host: example, user: root, auth: {type: password, password: secret}}\n- name: child\n  via_profile: upstream\n  target: {host: child, user: root}\n",
        )
        .unwrap();
        assert!(ensure_profile_deletable(&referenced, "upstream").is_err());
        assert!(ensure_profile_deletable(&referenced, "child").is_ok());
    }

    #[tokio::test]
    async fn policy_query_returns_policy_without_credentials() {
        let config: AppConfig = serde_yaml::from_str(
            "profiles:\n- name: test\n  target: {host: example, user: root, auth: {type: password, password: secret}}\n  agent_policy:\n    allowed_commands: [hostname]\n",
        )
        .unwrap();
        let result = GatewayService::new()
            .execute_authorized(
                &config,
                CallerType::Mcp,
                Request::ProfilePolicy { profile: None },
                DEFAULT_SESSION_NAMESPACE,
            )
            .await
            .unwrap();
        let encoded = result.data.unwrap().to_string();
        assert!(encoded.contains("hostname"));
        assert!(!encoded.contains("secret"));
        assert!(!encoded.contains("example"));
    }

    #[tokio::test]
    async fn profile_management_approval_cannot_create_a_grant() {
        let path =
            std::env::temp_dir().join(format!("sshmcp-profile-admin-{}.db", uuid::Uuid::new_v4()));
        let mut config: AppConfig = serde_yaml::from_str(
            "profiles:\n- name: test\n  target: {host: example, user: root, auth: {type: password, password: secret}}\nmcp:\n  profile_management: {enabled: true}\n",
        )
        .unwrap();
        config.approval.storage.path = Some(path.display().to_string());
        let profile = serde_yaml::from_str(
            "name: new\ntarget: {host: new.example, user: ops, auth: {type: password, password: hidden}}\nagent_policy: {}\n",
        )
        .unwrap();
        let approvals = ApprovalService::from_config(&config).unwrap();
        let id = approvals
            .create(
                &Request::ProfileCreate {
                    profile: Box::new(profile),
                },
                CallerType::Mcp,
                Some("profile_admin"),
                None,
                Some(crate::config::RiskLevelConfig::Critical),
                &SecretRedactor::from_config(&config),
                None,
            )
            .unwrap()["id"]
            .as_str()
            .unwrap()
            .to_string();
        let result = GatewayService::new()
            .execute_authorization_admin(
                &config,
                &Principal::local(CallerType::HumanCli),
                Request::ApprovalApprove {
                    approval_id: id,
                    grant_ttl_seconds: Some(60),
                    grant_task_id: None,
                    max_uses: Some(2),
                },
                DEFAULT_SESSION_NAMESPACE,
            )
            .await;
        assert!(matches!(result, Err(ArrtError::PolicyDenied(_))));
        let _ = std::fs::remove_file(path);
    }
}
