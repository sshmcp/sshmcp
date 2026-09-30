use crate::cli::{WorkerCommand, WorkerSubcommand};
use crate::errors::ArrtError;
use crate::protocol::CommandResult;
use directories::ProjectDirs;
use futures_util::{SinkExt, StreamExt};
use reqwest::header::AUTHORIZATION;
use rusqlite::{params, Connection, OptionalExtension};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tempfile::tempdir;
use tokio::process::Command;
use tokio::sync::{oneshot, Mutex, Semaphore};
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::http::HeaderValue;
use tokio_tungstenite::tungstenite::Message;
use url::Url;
use uuid::Uuid;
use zeroize::Zeroizing;

const MAX_MESSAGE_BYTES: usize = 2 * 1024 * 1024;
const MAX_RESULT_BYTES: usize = 1024 * 1024;
const HEARTBEAT_SECONDS: u64 = 15;

#[derive(Debug, Serialize, Deserialize)]
struct WorkerIdentity {
    cloud_url: String,
    worker_id: Uuid,
    location_id: Uuid,
    credential: String,
    max_concurrency: u16,
}

#[derive(Serialize)]
struct EnrollRequest<'a> {
    name: &'a str,
    version: &'static str,
    max_concurrency: u16,
}

#[derive(Deserialize)]
struct EnrollResponse {
    worker_id: Uuid,
    execution_location_id: Uuid,
    credential: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
struct JobServer {
    id: Uuid,
    tenant_id: Uuid,
    host: String,
    port: u16,
    username: String,
    host_key_sha256: String,
    agent_policy: Value,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
enum JobOperation {
    Exec { command: String },
    ReadFile { path: String },
}

#[derive(Debug, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum CloudMessage {
    Job {
        execution_id: Uuid,
        request_id: Uuid,
        runtime_mode: String,
        expires_at: i64,
        server: Box<JobServer>,
        private_key: String,
        operation: JobOperation,
    },
    StartGranted {
        execution_id: Uuid,
    },
    StartDenied {
        execution_id: Uuid,
    },
}

#[derive(Debug, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum WorkerMessage<'a> {
    Hello {
        version: &'static str,
        capacity: u16,
    },
    Heartbeat {
        active: usize,
    },
    Start {
        execution_id: Uuid,
    },
    Result {
        execution_id: Uuid,
        ok: bool,
        result: &'a Value,
        error_code: Option<&'a str>,
    },
    Uncertain {
        execution_id: Uuid,
    },
}

#[derive(Clone)]
struct Journal {
    path: PathBuf,
}

#[derive(Debug)]
enum ExistingExecution {
    New,
    Completed {
        ok: bool,
        result: Value,
        error_code: Option<String>,
    },
    Uncertain,
}

type JournalRow = (String, Option<i64>, Option<String>, Option<String>);
type CompletedExecution = (Uuid, bool, Value, Option<String>);

pub async fn dispatch(command: WorkerCommand) -> Result<CommandResult, ArrtError> {
    match command.command {
        WorkerSubcommand::Enroll {
            cloud,
            token,
            name,
            max_concurrency,
            data_dir,
        } => {
            enroll(
                &cloud,
                Zeroizing::new(token),
                &name,
                max_concurrency,
                data_dir,
            )
            .await
        }
        WorkerSubcommand::Run { data_dir } => run(data_dir).await,
        WorkerSubcommand::Status { data_dir } => status(data_dir),
    }
}

async fn enroll(
    cloud: &str,
    token: Zeroizing<String>,
    name: &str,
    max_concurrency: u16,
    data_dir: Option<PathBuf>,
) -> Result<CommandResult, ArrtError> {
    if name.trim().is_empty() || name.len() > 120 {
        return Err(ArrtError::InvalidArgument("invalid Worker name".into()));
    }
    let cloud_url = validate_cloud_url(cloud)?;
    let endpoint = cloud_url
        .join("worker/v1/enroll")
        .map_err(|_| ArrtError::InvalidArgument("invalid Cloud URL".into()))?;
    let response = reqwest::Client::builder()
        .timeout(Duration::from_secs(15))
        .build()
        .map_err(|_| ArrtError::Io("could not initialize HTTPS client".into()))?
        .post(endpoint)
        .header(AUTHORIZATION, format!("Bearer {}", token.as_str()))
        .json(&EnrollRequest {
            name: name.trim(),
            version: env!("CARGO_PKG_VERSION"),
            max_concurrency,
        })
        .send()
        .await
        .map_err(|_| ArrtError::Io("Cloud enrollment request failed".into()))?;
    if !response.status().is_success() {
        return Err(ArrtError::InvalidArgument(format!(
            "Cloud rejected Worker enrollment ({})",
            response.status()
        )));
    }
    let enrolled: EnrollResponse = response
        .json()
        .await
        .map_err(|_| ArrtError::Io("Cloud returned an invalid enrollment response".into()))?;
    let root = resolve_data_dir(data_dir)?;
    tokio::fs::create_dir_all(&root).await?;
    let identity = WorkerIdentity {
        cloud_url: cloud_url.to_string(),
        worker_id: enrolled.worker_id,
        location_id: enrolled.execution_location_id,
        credential: enrolled.credential,
        max_concurrency,
    };
    write_private(
        &root.join("worker.json"),
        &serde_json::to_vec_pretty(&identity)
            .map_err(|_| ArrtError::Io("could not serialize Worker identity".into()))?,
    )
    .await?;
    Journal::open(root.join("executions.db"))?;
    Ok(CommandResult::success().with_data(json!({
        "status":"enrolled",
        "worker_id":identity.worker_id,
        "execution_location_id":identity.location_id,
        "data_dir":root
    })))
}

async fn run(data_dir: Option<PathBuf>) -> Result<CommandResult, ArrtError> {
    let root = resolve_data_dir(data_dir)?;
    let identity: WorkerIdentity =
        serde_json::from_slice(&tokio::fs::read(root.join("worker.json")).await?)
            .map_err(|_| ArrtError::Config("invalid Worker identity file".into()))?;
    let journal = Journal::open(root.join("executions.db"))?;
    let mut backoff = 1u64;
    loop {
        let connection = connect_once(&identity, journal.clone());
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {
                return Ok(CommandResult::success().with_data(json!({"status":"stopped"})));
            }
            result = connection => {
                if result.is_ok() { backoff = 1; }
            }
        }
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {
                return Ok(CommandResult::success().with_data(json!({"status":"stopped"})));
            }
            _ = tokio::time::sleep(Duration::from_secs(backoff)) => {}
        }
        backoff = (backoff * 2).min(30);
    }
}

fn status(data_dir: Option<PathBuf>) -> Result<CommandResult, ArrtError> {
    let root = resolve_data_dir(data_dir)?;
    let bytes = std::fs::read(root.join("worker.json"))?;
    let identity: WorkerIdentity = serde_json::from_slice(&bytes)
        .map_err(|_| ArrtError::Config("invalid Worker identity file".into()))?;
    let journal = Journal::open(root.join("executions.db"))?;
    Ok(CommandResult::success().with_data(json!({
        "status":"enrolled",
        "worker_id":identity.worker_id,
        "execution_location_id":identity.location_id,
        "cloud_url":identity.cloud_url,
        "max_concurrency":identity.max_concurrency,
        "journal":journal.counts()?
    })))
}

async fn connect_once(identity: &WorkerIdentity, journal: Journal) -> Result<(), ArrtError> {
    let mut endpoint = validate_cloud_url(&identity.cloud_url)?;
    endpoint.set_path("/worker/v1/connect");
    endpoint
        .set_scheme(if endpoint.scheme() == "https" {
            "wss"
        } else {
            "ws"
        })
        .map_err(|_| ArrtError::Config("invalid Cloud Worker URL".into()))?;
    let mut request = endpoint
        .as_str()
        .into_client_request()
        .map_err(|_| ArrtError::Config("invalid Cloud Worker URL".into()))?;
    request.headers_mut().insert(
        AUTHORIZATION,
        HeaderValue::from_str(&format!("Bearer {}", identity.credential))
            .map_err(|_| ArrtError::Config("invalid Worker credential".into()))?,
    );
    let config = tokio_tungstenite::tungstenite::protocol::WebSocketConfig::default()
        .max_message_size(Some(MAX_MESSAGE_BYTES))
        .max_frame_size(Some(MAX_MESSAGE_BYTES));
    let (socket, _) = tokio_tungstenite::connect_async_with_config(request, Some(config), false)
        .await
        .map_err(|_| ArrtError::Io("Worker could not connect to Cloud".into()))?;
    let (sink, mut stream) = socket.split();
    let sink = Arc::new(Mutex::new(sink));
    send_message(
        &sink,
        &WorkerMessage::Hello {
            version: env!("CARGO_PKG_VERSION"),
            capacity: identity.max_concurrency,
        },
    )
    .await?;

    for recovered in journal.completed(100)? {
        send_message(
            &sink,
            &WorkerMessage::Result {
                execution_id: recovered.0,
                ok: recovered.1,
                result: &recovered.2,
                error_code: recovered.3.as_deref(),
            },
        )
        .await?;
    }

    let active = Arc::new(AtomicUsize::new(0));
    let semaphore = Arc::new(Semaphore::new(identity.max_concurrency.into()));
    let waiters: Arc<Mutex<HashMap<Uuid, oneshot::Sender<bool>>>> =
        Arc::new(Mutex::new(HashMap::new()));
    let heartbeat_sink = sink.clone();
    let heartbeat_active = active.clone();
    let heartbeat = tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(HEARTBEAT_SECONDS));
        loop {
            interval.tick().await;
            if send_message(
                &heartbeat_sink,
                &WorkerMessage::Heartbeat {
                    active: heartbeat_active.load(Ordering::Relaxed),
                },
            )
            .await
            .is_err()
            {
                break;
            }
        }
    });
    let mut tasks = Vec::new();
    while let Some(message) = stream.next().await {
        let message = match message {
            Ok(Message::Text(text)) if text.len() <= MAX_MESSAGE_BYTES => text,
            Ok(Message::Close(_)) | Err(_) => break,
            Ok(_) => continue,
        };
        let message: CloudMessage = serde_json::from_str(&message)
            .map_err(|_| ArrtError::Io("Cloud sent an invalid Worker message".into()))?;
        match message {
            CloudMessage::StartGranted { execution_id } => {
                if let Some(waiter) = waiters.lock().await.remove(&execution_id) {
                    let _ = waiter.send(true);
                }
            }
            CloudMessage::StartDenied { execution_id } => {
                if let Some(waiter) = waiters.lock().await.remove(&execution_id) {
                    let _ = waiter.send(false);
                }
            }
            CloudMessage::Job {
                execution_id,
                request_id,
                runtime_mode,
                expires_at,
                server,
                private_key,
                operation,
            } => {
                let permit =
                    semaphore.clone().acquire_owned().await.map_err(|_| {
                        ArrtError::Io("Worker concurrency controller stopped".into())
                    })?;
                active.fetch_add(1, Ordering::Relaxed);
                let job_sink = sink.clone();
                let job_waiters = waiters.clone();
                let job_journal = journal.clone();
                let job_active = active.clone();
                tasks.push(tokio::spawn(async move {
                    let _permit = permit;
                    let _ = handle_job(
                        &job_sink,
                        &job_waiters,
                        &job_journal,
                        execution_id,
                        request_id,
                        &runtime_mode,
                        expires_at,
                        *server,
                        Zeroizing::new(private_key),
                        operation,
                    )
                    .await;
                    job_active.fetch_sub(1, Ordering::Relaxed);
                }));
            }
        }
    }
    heartbeat.abort();
    for task in tasks {
        let _ = task.await;
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn handle_job<S>(
    sink: &Arc<Mutex<S>>,
    waiters: &Arc<Mutex<HashMap<Uuid, oneshot::Sender<bool>>>>,
    journal: &Journal,
    execution_id: Uuid,
    request_id: Uuid,
    runtime_mode: &str,
    expires_at: i64,
    server: JobServer,
    private_key: Zeroizing<String>,
    operation: JobOperation,
) -> Result<(), ArrtError>
where
    S: futures_util::Sink<Message> + Unpin,
    S::Error: std::fmt::Debug,
{
    if unix_now() >= expires_at {
        send_message(sink, &WorkerMessage::Uncertain { execution_id }).await?;
        return Ok(());
    }
    match journal.inspect(execution_id)? {
        ExistingExecution::Completed {
            ok,
            result,
            error_code,
        } => {
            return send_message(
                sink,
                &WorkerMessage::Result {
                    execution_id,
                    ok,
                    result: &result,
                    error_code: error_code.as_deref(),
                },
            )
            .await;
        }
        ExistingExecution::Uncertain => {
            return send_message(sink, &WorkerMessage::Uncertain { execution_id }).await;
        }
        ExistingExecution::New => {}
    }
    let (tx, rx) = oneshot::channel();
    waiters.lock().await.insert(execution_id, tx);
    send_message(sink, &WorkerMessage::Start { execution_id }).await?;
    let granted = tokio::time::timeout(Duration::from_secs(10), rx)
        .await
        .ok()
        .and_then(Result::ok)
        .unwrap_or(false);
    if !granted {
        waiters.lock().await.remove(&execution_id);
        return Ok(());
    }
    if !journal.begin(execution_id)? {
        send_message(sink, &WorkerMessage::Uncertain { execution_id }).await?;
        return Ok(());
    }
    let result = execute_core(
        execution_id,
        request_id,
        runtime_mode,
        &server,
        private_key,
        operation,
    )
    .await;
    let (ok, value, error_code) = match result {
        Ok(value) => {
            let ok = value.get("ok").and_then(Value::as_bool) == Some(true);
            let error = (!ok).then(|| {
                value
                    .pointer("/error/code")
                    .and_then(Value::as_str)
                    .unwrap_or("core_error")
                    .to_owned()
            });
            (ok, value, error)
        }
        Err(error) => (
            false,
            json!({"ok":false,"error":{"code":error.code(),"message":"Worker execution failed"}}),
            Some(error.code().to_owned()),
        ),
    };
    journal.finish(execution_id, ok, &value, error_code.as_deref())?;
    send_message(
        sink,
        &WorkerMessage::Result {
            execution_id,
            ok,
            result: &value,
            error_code: error_code.as_deref(),
        },
    )
    .await
}

async fn execute_core(
    execution_id: Uuid,
    request_id: Uuid,
    runtime_mode: &str,
    server: &JobServer,
    private_key: Zeroizing<String>,
    operation: JobOperation,
) -> Result<Value, ArrtError> {
    if !matches!(runtime_mode, "cloud" | "private_worker") {
        return Err(ArrtError::InvalidArgument(
            "invalid Worker runtime mode".into(),
        ));
    }
    let temp = tempdir()?;
    let key_path = temp.path().join("id_ed25519");
    let config_path = temp.path().join("profiles.yaml");
    write_private(&key_path, private_key.as_bytes()).await?;
    let profile_name = format!("{}-{}", server.tenant_id, server.id);
    let config = serde_yaml::to_string(&json!({
        "runtime":{"mode":runtime_mode,"host_key_mode":"strict"},
        "profiles":[{
            "name":profile_name,
            "target":{"host":server.host,"port":server.port,"user":server.username,
                "host_key_sha256":server.host_key_sha256,
                "auth":{"type":"key","key_path":key_path}},
            "agent":{"remote_path":format!("/tmp/sshmcpd-{}", server.id)},
            "agent_policy":server.agent_policy
        }]
    }))
    .map_err(|_| ArrtError::Config("could not prepare Worker Core profile".into()))?;
    tokio::fs::write(&config_path, config).await?;
    let executable = std::env::current_exe()?;
    let mut command = Command::new(&executable);
    command
        .env_clear()
        .env("PATH", std::env::var_os("PATH").unwrap_or_default())
        .env("HOME", temp.path())
        .env("XDG_DATA_HOME", temp.path())
        .env("SSHMCP_CONFIG_PATH", &config_path)
        .env("SSHMCP_REQUEST_ID", request_id.to_string())
        .env("SSHMCP_EXECUTION_ID", execution_id.to_string())
        .arg("--agent");
    match operation {
        JobOperation::Exec { command: text } => {
            command.args(["exec", "--profile", &profile_name, "--timeout", "20", "--"]);
            command.arg(text);
        }
        JobOperation::ReadFile { path } => {
            command.args(["read", "--profile", &profile_name, "--path"]);
            command.arg(path);
        }
    }
    command.kill_on_drop(true);
    let output = tokio::time::timeout(Duration::from_secs(30), command.output())
        .await
        .map_err(|_| ArrtError::RequestTimeout("Worker Core timed out".into()))??;
    stop_isolated_core(&executable, &config_path, temp.path()).await;
    if output.stdout.len() > MAX_RESULT_BYTES {
        return Err(ArrtError::Io("Worker Core output exceeded limit".into()));
    }
    serde_json::from_slice(&output.stdout)
        .map_err(|_| ArrtError::Io("Worker Core returned invalid JSON".into()))
}

async fn stop_isolated_core(executable: &Path, config: &Path, runtime: &Path) {
    let mut command = Command::new(executable);
    command
        .env_clear()
        .env("PATH", std::env::var_os("PATH").unwrap_or_default())
        .env("HOME", runtime)
        .env("XDG_DATA_HOME", runtime)
        .env("SSHMCP_CONFIG_PATH", config)
        .args(["daemon", "stop"])
        .kill_on_drop(true);
    let _ = tokio::time::timeout(Duration::from_secs(5), command.output()).await;
}

async fn send_message<S, T>(sink: &Arc<Mutex<S>>, message: &T) -> Result<(), ArrtError>
where
    S: futures_util::Sink<Message> + Unpin,
    S::Error: std::fmt::Debug,
    T: Serialize,
{
    let text = serde_json::to_string(message)
        .map_err(|_| ArrtError::Io("could not encode Worker message".into()))?;
    if text.len() > MAX_MESSAGE_BYTES {
        return Err(ArrtError::Io("Worker message exceeded limit".into()));
    }
    sink.lock()
        .await
        .send(Message::Text(text.into()))
        .await
        .map_err(|_| ArrtError::Io("Worker connection closed".into()))
}

fn validate_cloud_url(raw: &str) -> Result<Url, ArrtError> {
    let url =
        Url::parse(raw).map_err(|_| ArrtError::InvalidArgument("invalid Cloud URL".into()))?;
    let local = url.host_str().is_some_and(|host| {
        host == "localhost" || host.ends_with(".localhost") || host == "127.0.0.1" || host == "::1"
    });
    if url.host_str().is_none()
        || (!local && url.scheme() != "https")
        || (local && !matches!(url.scheme(), "http" | "https"))
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
        || !matches!(url.path(), "" | "/")
    {
        return Err(ArrtError::InvalidArgument(
            "Cloud URL must be an HTTPS origin (HTTP is allowed for localhost)".into(),
        ));
    }
    Ok(url)
}

fn resolve_data_dir(value: Option<PathBuf>) -> Result<PathBuf, ArrtError> {
    if let Some(path) = value {
        return Ok(path);
    }
    ProjectDirs::from("", "", "sshmcp")
        .map(|dirs| dirs.data_local_dir().join("worker"))
        .ok_or_else(|| ArrtError::Config("could not determine Worker data directory".into()))
}

async fn write_private(path: &Path, bytes: &[u8]) -> Result<(), ArrtError> {
    tokio::fs::write(path, bytes).await?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        tokio::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).await?;
    }
    Ok(())
}

fn unix_now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}

impl Journal {
    fn open(path: PathBuf) -> Result<Self, ArrtError> {
        let connection = Connection::open(&path)
            .map_err(|_| ArrtError::Io("could not open Worker journal".into()))?;
        connection
            .execute_batch(
                "PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL;
                 CREATE TABLE IF NOT EXISTS executions (
                   execution_id TEXT PRIMARY KEY,
                   state TEXT NOT NULL CHECK(state IN ('started','completed')),
                   ok INTEGER,
                   result_json TEXT,
                   error_code TEXT,
                   updated_at INTEGER NOT NULL
                 );",
            )
            .map_err(|_| ArrtError::Io("could not initialize Worker journal".into()))?;
        Ok(Self { path })
    }

    fn inspect(&self, id: Uuid) -> Result<ExistingExecution, ArrtError> {
        let connection = Connection::open(&self.path)
            .map_err(|_| ArrtError::Io("could not open Worker journal".into()))?;
        let row: Option<JournalRow> = connection
            .query_row(
                "SELECT state,ok,result_json,error_code FROM executions WHERE execution_id=?1",
                [id.to_string()],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            )
            .optional()
            .map_err(|_| ArrtError::Io("could not read Worker journal".into()))?;
        match row {
            None => Ok(ExistingExecution::New),
            Some((state, Some(ok), Some(result), error_code)) if state == "completed" => {
                let result = serde_json::from_str(&result)
                    .map_err(|_| ArrtError::Io("Worker journal contains invalid result".into()))?;
                Ok(ExistingExecution::Completed {
                    ok: ok != 0,
                    result,
                    error_code,
                })
            }
            Some(_) => Ok(ExistingExecution::Uncertain),
        }
    }

    fn begin(&self, id: Uuid) -> Result<bool, ArrtError> {
        let connection = Connection::open(&self.path)
            .map_err(|_| ArrtError::Io("could not open Worker journal".into()))?;
        let changed = connection
            .execute(
                "INSERT OR IGNORE INTO executions(execution_id,state,updated_at) VALUES(?1,'started',?2)",
                params![id.to_string(), unix_now()],
            )
            .map_err(|_| ArrtError::Io("could not persist Worker execution entry".into()))?;
        Ok(changed == 1)
    }

    fn finish(
        &self,
        id: Uuid,
        ok: bool,
        result: &Value,
        error_code: Option<&str>,
    ) -> Result<(), ArrtError> {
        let encoded = serde_json::to_string(result)
            .map_err(|_| ArrtError::Io("could not encode Worker result".into()))?;
        let connection = Connection::open(&self.path)
            .map_err(|_| ArrtError::Io("could not open Worker journal".into()))?;
        let changed = connection
            .execute(
                "UPDATE executions SET state='completed',ok=?2,result_json=?3,error_code=?4,updated_at=?5 WHERE execution_id=?1 AND state='started'",
                params![id.to_string(), ok as i64, encoded, error_code, unix_now()],
            )
            .map_err(|_| ArrtError::Io("could not persist Worker result".into()))?;
        if changed != 1 {
            return Err(ArrtError::Io(
                "Worker execution journal state changed".into(),
            ));
        }
        Ok(())
    }

    fn completed(&self, limit: usize) -> Result<Vec<CompletedExecution>, ArrtError> {
        let connection = Connection::open(&self.path)
            .map_err(|_| ArrtError::Io("could not open Worker journal".into()))?;
        let mut statement = connection
            .prepare("SELECT execution_id,ok,result_json,error_code FROM executions WHERE state='completed' ORDER BY updated_at DESC LIMIT ?1")
            .map_err(|_| ArrtError::Io("could not read Worker journal".into()))?;
        let rows = statement
            .query_map([limit as i64], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, Option<String>>(3)?,
                ))
            })
            .map_err(|_| ArrtError::Io("could not read Worker journal".into()))?;
        let mut values = Vec::new();
        for row in rows {
            let (id, ok, result, error) =
                row.map_err(|_| ArrtError::Io("could not read Worker journal".into()))?;
            values.push((
                Uuid::parse_str(&id)
                    .map_err(|_| ArrtError::Io("invalid Worker journal id".into()))?,
                ok != 0,
                serde_json::from_str(&result)
                    .map_err(|_| ArrtError::Io("invalid Worker journal result".into()))?,
                error,
            ));
        }
        Ok(values)
    }

    fn counts(&self) -> Result<Value, ArrtError> {
        let connection = Connection::open(&self.path)
            .map_err(|_| ArrtError::Io("could not open Worker journal".into()))?;
        let started: i64 = connection
            .query_row(
                "SELECT count(*) FROM executions WHERE state='started'",
                [],
                |r| r.get(0),
            )
            .map_err(|_| ArrtError::Io("could not read Worker journal".into()))?;
        let completed: i64 = connection
            .query_row(
                "SELECT count(*) FROM executions WHERE state='completed'",
                [],
                |r| r.get(0),
            )
            .map_err(|_| ArrtError::Io("could not read Worker journal".into()))?;
        Ok(json!({"uncertain":started,"completed":completed}))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn journal_never_starts_the_same_execution_twice() {
        let temp = tempdir().unwrap();
        let journal_path = temp.path().join("executions.db");
        let side_effect_path = temp.path().join("side-effects");
        let journal = Journal::open(journal_path.clone()).unwrap();
        let id = Uuid::new_v4();
        assert!(matches!(
            journal.inspect(id).unwrap(),
            ExistingExecution::New
        ));
        assert!(journal.begin(id).unwrap());
        assert!(!journal.begin(id).unwrap());
        assert!(matches!(
            journal.inspect(id).unwrap(),
            ExistingExecution::Uncertain
        ));
        journal.finish(id, true, &json!({"ok":true}), None).unwrap();
        assert!(matches!(
            journal.inspect(id).unwrap(),
            ExistingExecution::Completed { ok: true, .. }
        ));
        assert!(!journal.begin(id).unwrap());

        let interrupted_id = Uuid::new_v4();
        assert!(journal.begin(interrupted_id).unwrap());
        std::fs::write(&side_effect_path, b"started\n").unwrap();
        drop(journal);
        let reopened = Journal::open(journal_path).unwrap();
        assert!(matches!(
            reopened.inspect(interrupted_id).unwrap(),
            ExistingExecution::Uncertain
        ));
        if reopened.begin(interrupted_id).unwrap() {
            use std::io::Write;
            std::fs::OpenOptions::new()
                .append(true)
                .open(&side_effect_path)
                .unwrap()
                .write_all(b"started-again\n")
                .unwrap();
        }
        assert_eq!(
            std::fs::read_to_string(side_effect_path).unwrap(),
            "started\n"
        );
    }
}
