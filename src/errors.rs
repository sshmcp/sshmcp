use thiserror::Error;

#[derive(Debug, Error)]
pub enum ArrtError {
    #[error("configuration error: {0}")]
    Config(String),
    #[error("profile not found: {0}")]
    ProfileNotFound(String),
    #[error("profile already exists: {0}")]
    ProfileAlreadyExists(String),
    #[error("profile is in use: {0}")]
    ProfileInUse(String),
    #[error("profile management is disabled")]
    ProfileManagementDisabled,
    #[error("unsupported configuration format: {0}")]
    UnsupportedConfigFormat(String),
    #[error("configuration conflict: {0}")]
    ConfigConflict(String),
    #[error("daemon unavailable: {0}")]
    DaemonUnavailable(String),
    #[error("ipc error: {0}")]
    Ipc(String),
    #[error("request timeout: {0}")]
    RequestTimeout(String),
    #[error("ssh error: {0}")]
    Ssh(String),
    #[error("SSH authentication failed")]
    AuthenticationFailed,
    #[error("jump host connection failed: {0}")]
    JumpHost(Box<ArrtError>),
    #[error("jump host could not forward to the target: {0}")]
    JumpForwarding(String),
    #[error("untrusted SSH host key for {host}: {fingerprint}")]
    HostKeyUntrusted { host: String, fingerprint: String },
    #[error("SSH host key changed for {host}: expected {expected}, received {actual}")]
    HostKeyChanged {
        host: String,
        expected: String,
        actual: String,
    },
    #[error("agent error: {0}")]
    Agent(String),
    #[error("session not found: {0}")]
    SessionNotFound(String),
    #[error("invalid argument: {0}")]
    InvalidArgument(String),
    #[error("agent policy denied: {0}")]
    PolicyDenied(String),
    #[error("relative local path: {0}")]
    RelativeLocalPath(String),
    #[error("approval error: {0}")]
    Approval(String),
    #[error("io error: {0}")]
    Io(String),
}

impl ArrtError {
    pub fn code(&self) -> &'static str {
        match self {
            Self::Config(_) => "config_error",
            Self::ProfileNotFound(_) => "profile_not_found",
            Self::ProfileAlreadyExists(_) => "profile_already_exists",
            Self::ProfileInUse(_) => "profile_in_use",
            Self::ProfileManagementDisabled => "profile_management_disabled",
            Self::UnsupportedConfigFormat(_) => "unsupported_config_format",
            Self::ConfigConflict(_) => "config_conflict",
            Self::DaemonUnavailable(_) => "daemon_unavailable",
            Self::Ipc(_) => "ipc_error",
            Self::RequestTimeout(_) => "request_timeout",
            Self::Ssh(_) => "ssh_error",
            Self::AuthenticationFailed => "authentication_failed",
            Self::JumpForwarding(_) => "jump_forwarding_failed",
            Self::JumpHost(error) => match error.as_ref() {
                Self::AuthenticationFailed => "jump_authentication_failed",
                Self::HostKeyChanged { .. } | Self::HostKeyUntrusted { .. } => {
                    "jump_host_key_mismatch"
                }
                _ => "jump_unreachable",
            },
            Self::HostKeyUntrusted { .. } => "host_key_untrusted",
            Self::HostKeyChanged { .. } => "host_key_changed",
            Self::Agent(_) => "agent_error",
            Self::SessionNotFound(_) => "session_not_found",
            Self::InvalidArgument(_) => "invalid_argument",
            Self::PolicyDenied(_) => "policy_denied",
            Self::RelativeLocalPath(_) => "relative_local_path",
            Self::Approval(_) => "approval_error",
            Self::Io(_) => "io_error",
        }
    }
}

impl From<std::io::Error> for ArrtError {
    fn from(value: std::io::Error) -> Self {
        Self::Io(value.to_string())
    }
}

impl From<russh::Error> for ArrtError {
    fn from(value: russh::Error) -> Self {
        Self::Ssh(value.to_string())
    }
}

impl From<russh::keys::Error> for ArrtError {
    fn from(value: russh::keys::Error) -> Self {
        Self::Ssh(value.to_string())
    }
}
