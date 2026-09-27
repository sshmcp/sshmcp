use crate::config::{AgentPolicyConfig, AppConfig, PolicyEffectConfig, RiskLevelConfig};
use crate::errors::ArrtError;
use crate::protocol::{CallerType, Request};

pub struct PolicyEngine;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PolicyEffect {
    Allow,
    Confirm,
    Deny,
}

#[derive(Debug, Clone)]
pub struct PolicyDecision {
    pub effect: PolicyEffect,
    pub rule_id: Option<String>,
    pub reason: Option<String>,
    pub risk: Option<RiskLevelConfig>,
}

impl PolicyDecision {
    fn allow() -> Self {
        Self {
            effect: PolicyEffect::Allow,
            rule_id: None,
            reason: None,
            risk: None,
        }
    }
}

#[derive(Clone, Copy)]
enum Capability {
    Exec,
    Read,
    Write,
    Upload,
    Download,
    Tunnel,
}

impl PolicyEngine {
    pub fn authorize_caller(caller: CallerType, request: &Request) -> Result<(), ArrtError> {
        if caller.enforces_agent_policy() && matches!(request, Request::Shutdown) {
            return Err(ArrtError::PolicyDenied(
                "agents cannot stop the gateway daemon".to_string(),
            ));
        }
        Ok(())
    }

    pub fn authorize(
        config: &AppConfig,
        caller: CallerType,
        request: &Request,
    ) -> Result<PolicyDecision, ArrtError> {
        Self::authorize_caller(caller, request)?;
        if !caller.enforces_agent_policy() {
            return Ok(PolicyDecision::allow());
        }

        let policy = match request {
            Request::Exec {
                profile,
                command,
                cwd,
                ..
            } => {
                let profile_config = config.profile(profile)?;
                let policy = &profile_config.agent_policy;
                require_capability(policy, Capability::Exec)?;
                if policy.rules.is_empty() || !policy.allowed_commands.is_empty() {
                    require_allowed_command(policy, command)?;
                }
                if let Some(cwd) = cwd {
                    require_path(policy, cwd, false)?;
                }
                Some(profile_config.agent_policy)
            }
            Request::Read { profile, path } => {
                let policy = &config.profile(profile)?.agent_policy;
                require_capability(policy, Capability::Read)?;
                require_path(policy, path, false)?;
                Some(policy.clone())
            }
            Request::Write { profile, path, .. } => {
                let policy = &config.profile(profile)?.agent_policy;
                require_capability(policy, Capability::Write)?;
                require_path(policy, path, true)?;
                Some(policy.clone())
            }
            Request::Upload { profile, dst, .. } => {
                let policy = &config.profile(profile)?.agent_policy;
                require_capability(policy, Capability::Upload)?;
                require_path(policy, dst, true)?;
                Some(policy.clone())
            }
            Request::Download { profile, src, .. } => {
                let policy = &config.profile(profile)?.agent_policy;
                require_capability(policy, Capability::Download)?;
                require_path(policy, src, false)?;
                Some(policy.clone())
            }
            Request::TunnelOpen { profile, .. } => {
                require_capability(&config.profile(profile)?.agent_policy, Capability::Tunnel)?;
                None
            }
            Request::TunnelClose { profile, .. } => {
                let profile = profile.as_deref().ok_or_else(|| {
                    ArrtError::PolicyDenied(
                        "agent tunnel close requires --profile for policy verification".to_string(),
                    )
                })?;
                require_capability(&config.profile(profile)?.agent_policy, Capability::Tunnel)?;
                None
            }
            Request::ApprovalApprove { .. } | Request::ApprovalReject { .. } => {
                return Err(ArrtError::PolicyDenied(
                    "agents cannot approve or reject approvals".to_string(),
                ))
            }
            Request::ApprovalList | Request::ApprovalShow { .. } | Request::ApprovalCleanup => {
                return Err(ArrtError::PolicyDenied(
                    "approval administration requires Human CLI".to_string(),
                ))
            }
            Request::GrantList
            | Request::GrantShow { .. }
            | Request::GrantRevoke { .. }
            | Request::GrantCleanup
            | Request::PlanList
            | Request::PlanShow { .. }
            | Request::PlanApprove { .. }
            | Request::PlanReject { .. } => {
                return Err(ArrtError::PolicyDenied(
                    "authorization administration requires Human CLI".into(),
                ))
            }
            Request::PlanPropose { .. } => None,
            Request::SessionClose { .. } | Request::SessionInspect { .. } => None,
            Request::SessionList
            | Request::Ping
            | Request::ProfileList
            | Request::ProfileShow { .. }
            | Request::ProfileValidate { .. }
            | Request::ProfilePolicy { .. } => None,
            Request::ProfileCreate { .. } | Request::ProfileDelete { .. } => {
                return Err(ArrtError::PolicyDenied(
                    "profile management cannot be granted or included in a plan".into(),
                ))
            }
            Request::Shutdown => None,
        };
        let Some(policy) = policy else {
            return Ok(PolicyDecision::allow());
        };
        if policy.rules.is_empty() {
            return Ok(PolicyDecision::allow());
        }
        for rule in &policy.rules {
            if rule_matches(rule, request) {
                return Ok(PolicyDecision {
                    effect: match rule.effect {
                        PolicyEffectConfig::Allow => PolicyEffect::Allow,
                        PolicyEffectConfig::Confirm => PolicyEffect::Confirm,
                        PolicyEffectConfig::Deny => PolicyEffect::Deny,
                    },
                    rule_id: Some(rule.id.clone()),
                    reason: rule.reason.clone(),
                    risk: rule.risk,
                });
            }
        }
        Ok(PolicyDecision {
            effect: PolicyEffect::Deny,
            rule_id: None,
            reason: Some("no policy rule matched".into()),
            risk: None,
        })
    }
}

fn rule_matches(rule: &crate::config::PolicyRuleConfig, request: &Request) -> bool {
    let (operation, value, patterns) = match request {
        Request::Exec { command, .. } => ("exec", command.as_str(), &rule.matcher.commands),
        Request::Read { path, .. } => ("read", path.as_str(), &rule.matcher.paths),
        Request::Write { path, .. } => ("write", path.as_str(), &rule.matcher.paths),
        Request::Upload { dst, .. } => ("upload", dst.as_str(), &rule.matcher.paths),
        Request::Download { src, .. } => ("download", src.as_str(), &rule.matcher.paths),
        _ => return false,
    };
    rule.matcher.operation == operation && patterns.iter().any(|p| wildcard_match(p, value))
}

fn wildcard_match(pattern: &str, value: &str) -> bool {
    let (mut p, mut v, mut star, mut mark) = (0, 0, None, 0);
    let pb = pattern.as_bytes();
    let vb = value.as_bytes();
    while v < vb.len() {
        if p < pb.len() && pb[p] == vb[v] {
            p += 1;
            v += 1;
        } else if p < pb.len() && pb[p] == b'*' {
            star = Some(p);
            p += 1;
            mark = v;
        } else if let Some(s) = star {
            p = s + 1;
            mark += 1;
            v = mark;
        } else {
            return false;
        }
    }
    while p < pb.len() && pb[p] == b'*' {
        p += 1;
    }
    p == pb.len()
}

fn require_capability(policy: &AgentPolicyConfig, capability: Capability) -> Result<(), ArrtError> {
    let (allowed, name) = match capability {
        Capability::Exec => (policy.capabilities.exec, "exec"),
        Capability::Read => (policy.capabilities.read, "read"),
        Capability::Write => (policy.capabilities.write, "write"),
        Capability::Upload => (policy.capabilities.upload, "upload"),
        Capability::Download => (policy.capabilities.download, "download"),
        Capability::Tunnel => (policy.capabilities.tunnel, "tunnel"),
    };
    if allowed {
        Ok(())
    } else {
        Err(ArrtError::PolicyDenied(format!(
            "capability {name} is disabled"
        )))
    }
}

fn require_allowed_command(policy: &AgentPolicyConfig, command: &str) -> Result<(), ArrtError> {
    if policy
        .allowed_commands
        .iter()
        .any(|allowed| allowed == command)
    {
        Ok(())
    } else {
        Err(ArrtError::PolicyDenied(
            "command is not present in agent_policy.allowed_commands".to_string(),
        ))
    }
}

fn require_path(policy: &AgentPolicyConfig, path: &str, write: bool) -> Result<(), ArrtError> {
    let allowed = if write {
        &policy.allowed_write_paths
    } else {
        &policy.allowed_read_paths
    };
    if allowed.is_empty() {
        return Ok(());
    }
    let normalized = normalize_remote_path(path)?;
    if allowed.iter().any(|root| {
        normalize_remote_path(root).is_ok_and(|root| {
            root == "/" || normalized == root || normalized.starts_with(&(root + "/"))
        })
    }) {
        Ok(())
    } else {
        Err(ArrtError::PolicyDenied(format!(
            "{} path is outside allowed roots: {path}",
            if write { "write" } else { "read" }
        )))
    }
}

fn normalize_remote_path(path: &str) -> Result<String, ArrtError> {
    if !path.starts_with('/') {
        return Err(ArrtError::PolicyDenied(format!(
            "policy-restricted remote path must be absolute: {path}"
        )));
    }
    let mut parts = Vec::new();
    for part in path.split('/') {
        match part {
            "" | "." => {}
            ".." => {
                parts.pop();
            }
            value => parts.push(value),
        }
    }
    Ok(format!("/{}", parts.join("/")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exact_allowlist_rejects_shell_quote_and_escape_bypasses() {
        let policy = AgentPolicyConfig {
            allowed_commands: vec!["docker ps".to_string()],
            ..AgentPolicyConfig::default()
        };
        assert!(require_allowed_command(&policy, "docker ps").is_ok());
        assert!(require_allowed_command(&policy, "reboot").is_err());
        assert!(require_allowed_command(&policy, "re\"boot\"").is_err());
        assert!(require_allowed_command(&policy, "reboo\\t").is_err());
        assert!(require_allowed_command(&policy, "docker  ps").is_err());
    }

    #[test]
    fn allowed_paths_resist_parent_traversal() {
        let policy = AgentPolicyConfig {
            allowed_read_paths: vec!["/var/log".to_string()],
            ..AgentPolicyConfig::default()
        };
        assert!(require_path(&policy, "/var/log/nginx/access.log", false).is_ok());
        assert!(require_path(&policy, "/var/log/../../etc/shadow", false).is_err());
        assert!(require_path(&policy, "/var/logger", false).is_err());
    }

    #[test]
    fn agent_context_enforces_capability_while_human_cli_stays_compatible() {
        let config: AppConfig = serde_yaml::from_str(
            r#"
profiles:
  - name: readonly
    target:
      host: example
      user: root
      auth:
        type: password
        password: secret
    agent_policy:
      capabilities:
        exec: false
"#,
        )
        .unwrap();
        let request = Request::Exec {
            profile: "readonly".to_string(),
            command: "id".to_string(),
            cwd: None,
            timeout_seconds: Some(30),
            env: Vec::new(),
        };
        assert!(PolicyEngine::authorize(&config, CallerType::AgentCli, &request).is_err());
        assert!(PolicyEngine::authorize(&config, CallerType::Mcp, &request).is_err());
        assert!(PolicyEngine::authorize(&config, CallerType::HumanCli, &request).is_ok());
    }

    #[test]
    fn wildcard_is_anchored_and_does_not_unwrap_shells() {
        assert!(wildcard_match(
            "systemctl restart *",
            "systemctl restart nginx"
        ));
        assert!(!wildcard_match(
            "systemctl restart *",
            "bash -c systemctl restart nginx"
        ));
    }

    #[test]
    fn rules_return_all_three_effects() {
        let config: AppConfig = serde_yaml::from_str(r#"
profiles:
- name: test
  target: {host: example, user: root, auth: {type: password, password: secret}}
  agent_policy:
    rules:
    - {id: allow-status, match: {operation: exec, commands: ['systemctl status *']}, effect: allow, risk: low}
    - {id: confirm-restart, match: {operation: exec, commands: ['systemctl restart *']}, effect: confirm, risk: medium}
    - {id: deny-reboot, match: {operation: exec, commands: [reboot]}, effect: deny, risk: critical}
"#).unwrap();
        let make = |command: &str| Request::Exec {
            profile: "test".into(),
            command: command.into(),
            cwd: None,
            timeout_seconds: Some(30),
            env: vec![],
        };
        assert_eq!(
            PolicyEngine::authorize(&config, CallerType::Mcp, &make("systemctl status nginx"))
                .unwrap()
                .effect,
            PolicyEffect::Allow
        );
        assert_eq!(
            PolicyEngine::authorize(&config, CallerType::Mcp, &make("systemctl restart nginx"))
                .unwrap()
                .effect,
            PolicyEffect::Confirm
        );
        assert_eq!(
            PolicyEngine::authorize(&config, CallerType::Mcp, &make("reboot"))
                .unwrap()
                .effect,
            PolicyEffect::Deny
        );
        assert_eq!(
            PolicyEngine::authorize(
                &config,
                CallerType::Mcp,
                &make("bash -c 'systemctl restart nginx'")
            )
            .unwrap()
            .effect,
            PolicyEffect::Deny
        );
    }

    #[test]
    fn full_access_rules_allow_any_exec_and_read_without_command_lists() {
        let config: AppConfig = serde_yaml::from_str(
            r#"
profiles:
- name: full
  target: {host: example, user: root, auth: {type: password, password: secret}}
  agent_policy:
    capabilities: {exec: true, read: true}
    rules:
    - {id: full-exec, match: {operation: exec, commands: ['*']}, effect: allow}
    - {id: full-read, match: {operation: read, paths: ['*']}, effect: allow}
"#,
        )
        .unwrap();
        let exec = Request::Exec {
            profile: "full".into(),
            command: "apt-get update".into(),
            cwd: None,
            timeout_seconds: Some(30),
            env: vec![],
        };
        let read = Request::Read {
            profile: "full".into(),
            path: "/etc/shadow".into(),
        };
        assert_eq!(
            PolicyEngine::authorize(&config, CallerType::Mcp, &exec)
                .unwrap()
                .effect,
            PolicyEffect::Allow
        );
        assert_eq!(
            PolicyEngine::authorize(&config, CallerType::Mcp, &read)
                .unwrap()
                .effect,
            PolicyEffect::Allow
        );
    }
}
