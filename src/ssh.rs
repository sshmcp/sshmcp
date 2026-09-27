use crate::config::{HostKeyMode, ResolvedAuthConfig, ResolvedEndpoint, ResolvedProfile};
use crate::errors::ArrtError;
use crate::target::{resolve_direct, validate_remote_hop, RuntimeTargetPolicy};
use russh::client::{self, Handle};
use russh::keys::{
    load_secret_key,
    ssh_key::{HashAlg, PublicKey},
    PrivateKeyWithHashAlg,
};
use russh::{ChannelMsg, Disconnect};
use std::path::Path;
use std::sync::Arc;
use tokio::io::{AsyncWriteExt, BufWriter};
use tokio::net::TcpStream;
use tokio::time::{timeout, Duration};

const TRANSPORT_NAME: &str = "embedded_ssh";
const HEALTHCHECK_TIMEOUT: Duration = Duration::from_secs(10);

type ClientHandle = Handle<GatewayClient>;

#[derive(Clone)]
pub struct EmbeddedSession {
    handles: Vec<Arc<ClientHandle>>,
}

#[derive(Debug)]
pub struct CommandOutput {
    pub exit_code: i32,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
}

pub trait HostKeyVerifier: Send + Sync {
    fn verify(&self, host: &str, fingerprint: &str) -> Result<(), ArrtError>;
}

#[derive(Debug, Clone)]
struct ConfiguredHostKeyVerifier {
    mode: HostKeyMode,
    pin: Option<String>,
}

impl HostKeyVerifier for ConfiguredHostKeyVerifier {
    fn verify(&self, host: &str, fingerprint: &str) -> Result<(), ArrtError> {
        match self.pin.as_deref() {
            Some(expected) if expected == fingerprint => Ok(()),
            Some(expected) => Err(ArrtError::HostKeyChanged {
                host: host.to_string(),
                expected: expected.to_string(),
                actual: fingerprint.to_string(),
            }),
            None if self.mode == HostKeyMode::InsecureCompatibility => Ok(()),
            None => Err(ArrtError::HostKeyUntrusted {
                host: host.to_string(),
                fingerprint: fingerprint.to_string(),
            }),
        }
    }
}

struct GatewayClient {
    host: String,
    verifier: Arc<dyn HostKeyVerifier>,
}

impl client::Handler for GatewayClient {
    type Error = ArrtError;

    async fn check_server_key(
        &mut self,
        server_public_key: &PublicKey,
    ) -> Result<bool, Self::Error> {
        let fingerprint = server_public_key.fingerprint(HashAlg::Sha256).to_string();
        self.verifier.verify(&self.host, &fingerprint)?;
        Ok(true)
    }
}

impl EmbeddedSession {
    #[cfg(test)]
    pub fn test_empty() -> Self {
        Self {
            handles: Vec::new(),
        }
    }

    pub async fn connect(profile: &ResolvedProfile) -> Result<Self, ArrtError> {
        let config = Arc::new(client::Config {
            nodelay: true,
            keepalive_interval: (profile.keepalive.interval_seconds > 0)
                .then(|| Duration::from_secs(profile.keepalive.interval_seconds)),
            keepalive_max: usize::try_from(profile.keepalive.count_max).unwrap_or(usize::MAX),
            ..Default::default()
        });

        let chain = profile.direct_chain().ok_or_else(|| {
            ArrtError::Ssh("embedded ssh transport requires a direct profile chain".to_string())
        })?;
        let mut handles: Vec<Arc<ClientHandle>> = Vec::with_capacity(chain.len());
        let target_policy = RuntimeTargetPolicy(profile.runtime_mode);
        if profile.runtime_mode == crate::config::RuntimeMode::Cloud {
            for endpoint in chain.iter().skip(1) {
                validate_remote_hop(&target_policy, &endpoint.host)?;
            }
        }
        for endpoint in chain {
            let result = if let Some(parent) = handles.last() {
                connect_via_channel(
                    config.clone(),
                    parent.clone(),
                    endpoint,
                    profile.host_key_mode,
                )
                .await
            } else if profile.runtime_mode == crate::config::RuntimeMode::Cloud {
                let address = resolve_direct(&target_policy, &endpoint.host, endpoint.port).await?;
                connect_direct(config.clone(), endpoint, address, profile.host_key_mode).await
            } else {
                connect_direct(
                    config.clone(),
                    endpoint,
                    (endpoint.host.as_str(), endpoint.port),
                    profile.host_key_mode,
                )
                .await
            };
            let handle = match result {
                Ok(handle) => handle,
                Err(error) => {
                    Self { handles }.disconnect().await;
                    return Err(error);
                }
            };
            handles.push(Arc::new(handle));
        }

        Ok(Self { handles })
    }

    pub fn transport_name(&self) -> &'static str {
        TRANSPORT_NAME
    }

    pub async fn is_alive(&self) -> bool {
        let Some(handle) = self.handles.last() else {
            return false;
        };
        if handle.is_closed() {
            return false;
        }
        timeout(HEALTHCHECK_TIMEOUT, handle.send_ping())
            .await
            .is_ok_and(|result| result.is_ok())
    }

    pub async fn disconnect(&self) {
        for handle in self.handles.iter().rev() {
            let _ = handle
                .disconnect(Disconnect::ByApplication, "sshmcp session closed", "en")
                .await;
        }
    }

    pub async fn run_command(
        &self,
        command: &str,
        input: Option<&[u8]>,
    ) -> Result<CommandOutput, ArrtError> {
        let mut channel = self.target_handle()?.channel_open_session().await?;
        channel.exec(true, command.as_bytes().to_vec()).await?;

        if let Some(input) = input {
            let mut writer = BufWriter::new(channel.make_writer());
            writer.write_all(input).await?;
            writer.flush().await?;
            drop(writer);
            channel.eof().await?;
        }

        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let mut exit_code = None;

        while let Some(msg) = channel.wait().await {
            match msg {
                ChannelMsg::Data { data } => stdout.extend_from_slice(&data),
                ChannelMsg::ExtendedData { data, ext } => {
                    if ext == 1 {
                        stderr.extend_from_slice(&data);
                    } else {
                        stdout.extend_from_slice(&data);
                    }
                }
                ChannelMsg::ExitStatus { exit_status } => exit_code = Some(exit_status as i32),
                ChannelMsg::Close => break,
                ChannelMsg::Eof
                | ChannelMsg::Success
                | ChannelMsg::Failure
                | ChannelMsg::WindowAdjusted { .. } => {}
                ChannelMsg::ExitSignal {
                    signal_name,
                    error_message,
                    ..
                } if stderr.is_empty() => {
                    let message = if error_message.is_empty() {
                        format!("remote command terminated by signal {:?}", signal_name)
                    } else {
                        error_message
                    };
                    stderr.extend_from_slice(message.as_bytes());
                }
                _ => {}
            }
        }

        let _ = channel.close().await;

        Ok(CommandOutput {
            exit_code: exit_code.unwrap_or(0),
            stdout,
            stderr,
        })
    }

    pub async fn run_argv(
        &self,
        argv: &[String],
        input: Option<&[u8]>,
    ) -> Result<CommandOutput, ArrtError> {
        self.run_command(&shell_join(argv), input).await
    }

    pub async fn proxy_tcp_stream(
        &self,
        mut local_stream: TcpStream,
        remote_host: &str,
        remote_port: u16,
        originator: std::net::SocketAddr,
    ) -> Result<(), ArrtError> {
        let channel = self
            .target_handle()?
            .channel_open_direct_tcpip(
                remote_host.to_string(),
                remote_port.into(),
                originator.ip().to_string(),
                originator.port().into(),
            )
            .await?;
        let mut remote_stream = channel.into_stream();
        let _ = tokio::io::copy_bidirectional(&mut local_stream, &mut remote_stream).await?;
        let _ = remote_stream.shutdown().await;
        Ok(())
    }

    fn target_handle(&self) -> Result<&Arc<ClientHandle>, ArrtError> {
        self.handles
            .last()
            .ok_or_else(|| ArrtError::Ssh("session has no active handles".to_string()))
    }
}

pub fn shell_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', r"'\''"))
}

pub fn shell_join(parts: &[String]) -> String {
    parts
        .iter()
        .map(|part| shell_quote(part))
        .collect::<Vec<_>>()
        .join(" ")
}

async fn connect_direct<A: tokio::net::ToSocketAddrs>(
    config: Arc<client::Config>,
    endpoint: &ResolvedEndpoint,
    address: A,
    mode: HostKeyMode,
) -> Result<ClientHandle, ArrtError> {
    let handler = host_key_handler(endpoint, mode);
    let mut handle = client::connect(config, address, handler).await?;
    authenticate(&mut handle, endpoint).await?;
    Ok(handle)
}

async fn connect_via_channel(
    config: Arc<client::Config>,
    upstream: Arc<ClientHandle>,
    endpoint: &ResolvedEndpoint,
    mode: HostKeyMode,
) -> Result<ClientHandle, ArrtError> {
    let channel = upstream
        .channel_open_direct_tcpip(endpoint.host.clone(), endpoint.port.into(), "127.0.0.1", 0)
        .await?;
    let mut handle = client::connect_stream(
        config,
        channel.into_stream(),
        host_key_handler(endpoint, mode),
    )
    .await?;
    authenticate(&mut handle, endpoint).await?;
    Ok(handle)
}

fn host_key_handler(endpoint: &ResolvedEndpoint, mode: HostKeyMode) -> GatewayClient {
    GatewayClient {
        host: format!("{}:{}", endpoint.host, endpoint.port),
        verifier: Arc::new(ConfiguredHostKeyVerifier {
            mode,
            pin: endpoint.host_key_sha256.clone(),
        }),
    }
}

async fn authenticate(
    handle: &mut ClientHandle,
    endpoint: &ResolvedEndpoint,
) -> Result<(), ArrtError> {
    let success = match &endpoint.auth {
        ResolvedAuthConfig::Password { password } => handle
            .authenticate_password(endpoint.user.clone(), password.clone())
            .await?
            .success(),
        ResolvedAuthConfig::Key {
            key_path,
            passphrase,
        } => {
            let key_pair = load_secret_key(Path::new(key_path), passphrase.as_deref())?;
            handle
                .authenticate_publickey(
                    endpoint.user.clone(),
                    PrivateKeyWithHashAlg::new(
                        Arc::new(key_pair),
                        handle.best_supported_rsa_hash().await?.flatten(),
                    ),
                )
                .await?
                .success()
        }
    };

    if success {
        Ok(())
    } else {
        Err(ArrtError::AuthenticationFailed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use russh::server::{self, Auth, Server as _};
    use std::fs;
    use std::process::Command;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[derive(Clone)]
    struct TestSshServer;

    impl server::Server for TestSshServer {
        type Handler = Self;

        fn new_client(&mut self, _peer: Option<std::net::SocketAddr>) -> Self {
            self.clone()
        }
    }

    impl server::Handler for TestSshServer {
        type Error = ArrtError;

        async fn auth_password(
            &mut self,
            _user: &str,
            password: &str,
        ) -> Result<Auth, Self::Error> {
            Ok(if password == "test-password" {
                Auth::Accept
            } else {
                Auth::reject()
            })
        }

        async fn channel_open_direct_tcpip(
            &mut self,
            channel: russh::Channel<server::Msg>,
            host_to_connect: &str,
            port_to_connect: u32,
            _originator_address: &str,
            _originator_port: u32,
            _session: &mut server::Session,
        ) -> Result<bool, Self::Error> {
            let port =
                u16::try_from(port_to_connect).map_err(|err| ArrtError::Ssh(err.to_string()))?;
            let mut target = TcpStream::connect((host_to_connect, port)).await?;
            let mut channel = channel.into_stream();
            tokio::spawn(async move {
                let _ = tokio::io::copy_bidirectional(&mut channel, &mut target).await;
            });
            Ok(true)
        }
    }

    #[tokio::test]
    async fn direct_ssh_checks_server_key_and_reports_changes() {
        let key =
            russh::keys::PrivateKey::random(&mut rand::rng(), russh::keys::Algorithm::Ed25519)
                .unwrap();
        let fingerprint = key.public_key().fingerprint(HashAlg::Sha256).to_string();
        let mut server_config = server::Config::default();
        server_config.keys.push(key);
        let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
            .await
            .unwrap();
        let port = listener.local_addr().unwrap().port();
        let server_task = tokio::spawn(async move {
            let mut server = TestSshServer;
            server
                .run_on_socket(Arc::new(server_config), &listener)
                .await
        });
        let make_profile = |pin: Option<&str>| {
            let host_key = pin.map_or(String::new(), |pin| {
                format!("      host_key_sha256: \"{pin}\"\n")
            });
            let yaml = format!("runtime:\n  host_key_mode: strict\nprofiles:\n  - name: test\n    target:\n      host: 127.0.0.1\n      user: test\n      port: {port}\n{host_key}      auth:\n        type: password\n        password: test-password\n");
            let config: crate::config::AppConfig = serde_yaml::from_str(&yaml).unwrap();
            config.validate().unwrap();
            config.resolved_profile("test").unwrap()
        };
        let profile = make_profile(Some(&fingerprint));
        let session =
            tokio::time::timeout(Duration::from_secs(5), EmbeddedSession::connect(&profile))
                .await
                .unwrap()
                .unwrap();
        session.disconnect().await;

        let wrong = format!("SHA256:{}", "A".repeat(43));
        let error = tokio::time::timeout(
            Duration::from_secs(5),
            EmbeddedSession::connect(&make_profile(Some(&wrong))),
        )
        .await
        .unwrap()
        .err()
        .expect("changed key must fail");
        assert_eq!(error.code(), "host_key_changed");
        let error = tokio::time::timeout(
            Duration::from_secs(5),
            EmbeddedSession::connect(&make_profile(None)),
        )
        .await
        .unwrap()
        .err()
        .expect("unknown key must fail");
        assert_eq!(error.code(), "host_key_untrusted");
        server_task.abort();
    }

    #[tokio::test]
    async fn bastion_and_target_keys_are_checked_independently() {
        async fn spawn_server() -> (u16, String, tokio::task::JoinHandle<std::io::Result<()>>) {
            let key =
                russh::keys::PrivateKey::random(&mut rand::rng(), russh::keys::Algorithm::Ed25519)
                    .unwrap();
            let fingerprint = key.public_key().fingerprint(HashAlg::Sha256).to_string();
            let mut config = server::Config::default();
            config.keys.push(key);
            let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
                .await
                .unwrap();
            let port = listener.local_addr().unwrap().port();
            let task = tokio::spawn(async move {
                let mut server = TestSshServer;
                server.run_on_socket(Arc::new(config), &listener).await
            });
            (port, fingerprint, task)
        }
        let (bastion_port, bastion_pin, bastion_task) = spawn_server().await;
        let (target_port, target_pin, target_task) = spawn_server().await;
        let make_profile = |bastion_pin: &str, target_pin: &str| {
            let yaml = format!("runtime:\n  host_key_mode: strict\nprofiles:\n  - name: test\n    target:\n      host: 127.0.0.1\n      user: test\n      port: {target_port}\n      host_key_sha256: \"{target_pin}\"\n      auth: {{ type: password, password: test-password }}\n    bastions:\n      - host: 127.0.0.1\n        user: test\n        port: {bastion_port}\n        host_key_sha256: \"{bastion_pin}\"\n        auth: {{ type: password, password: test-password }}\n");
            let config: crate::config::AppConfig = serde_yaml::from_str(&yaml).unwrap();
            config.validate().unwrap();
            config.resolved_profile("test").unwrap()
        };
        let profile = make_profile(&bastion_pin, &target_pin);
        let session =
            tokio::time::timeout(Duration::from_secs(5), EmbeddedSession::connect(&profile))
                .await
                .unwrap()
                .unwrap();
        session.disconnect().await;
        let wrong = format!("SHA256:{}", "A".repeat(43));
        let changed_bastion = tokio::time::timeout(
            Duration::from_secs(5),
            EmbeddedSession::connect(&make_profile(&wrong, &target_pin)),
        )
        .await
        .unwrap()
        .err()
        .expect("changed bastion key must fail");
        assert_eq!(changed_bastion.code(), "host_key_changed");
        let changed_target = tokio::time::timeout(
            Duration::from_secs(5),
            EmbeddedSession::connect(&make_profile(&bastion_pin, &wrong)),
        )
        .await
        .unwrap()
        .err()
        .expect("changed target key must fail");
        assert_eq!(changed_target.code(), "host_key_changed");
        bastion_task.abort();
        target_task.abort();
    }

    #[test]
    fn strict_host_keys_require_a_matching_pin() {
        let fingerprint = "SHA256:abc";
        let strict = ConfiguredHostKeyVerifier {
            mode: HostKeyMode::Strict,
            pin: None,
        };
        assert!(matches!(
            strict.verify("host:22", fingerprint),
            Err(ArrtError::HostKeyUntrusted { .. })
        ));
        let pinned = ConfiguredHostKeyVerifier {
            mode: HostKeyMode::Strict,
            pin: Some(fingerprint.into()),
        };
        assert!(pinned.verify("host:22", fingerprint).is_ok());
        assert!(matches!(
            pinned.verify("host:22", "SHA256:changed"),
            Err(ArrtError::HostKeyChanged { .. })
        ));
        let legacy = ConfiguredHostKeyVerifier {
            mode: HostKeyMode::InsecureCompatibility,
            pin: None,
        };
        assert!(legacy.verify("host:22", fingerprint).is_ok());
    }

    #[test]
    fn shell_join_quotes_arguments() {
        let command = shell_join(&[
            "/tmp/sshmcpd".to_string(),
            "exec".to_string(),
            "hello world".to_string(),
            "quote'check".to_string(),
        ]);
        assert!(command.contains("'/tmp/sshmcpd'"));
        assert!(command.contains("'hello world'"));
        assert!(command.contains("'quote'\\''check'"));
    }

    #[test]
    fn load_secret_key_supports_passphrase_protected_keys() {
        if Command::new("ssh-keygen").arg("-V").output().is_err() {
            return;
        }

        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time before epoch")
            .as_nanos();
        let key_path = std::env::temp_dir().join(format!("sshmcp-passphrase-test-{nonce}"));
        let passphrase = "test-passphrase";

        let output = Command::new("ssh-keygen")
            .args([
                "-t",
                "ed25519",
                "-N",
                passphrase,
                "-f",
                key_path.to_str().expect("temp path must be utf-8"),
                "-C",
                "sshmcp-test",
                "-q",
            ])
            .output()
            .expect("failed to run ssh-keygen");

        assert!(
            key_path.is_file(),
            "ssh-keygen should create a private key: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(
            load_secret_key(&key_path, Some(passphrase)).is_ok(),
            "encrypted private key should load with the configured passphrase"
        );
        assert!(
            load_secret_key(&key_path, Some("wrong-passphrase")).is_err(),
            "encrypted private key should reject the wrong passphrase"
        );
        assert!(
            load_secret_key(&key_path, None).is_err(),
            "encrypted private key should reject a missing passphrase"
        );

        let _ = fs::remove_file(&key_path);
        let _ = fs::remove_file(key_path.with_extension("pub"));
    }
}
