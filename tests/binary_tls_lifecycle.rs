#![cfg(unix)]

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::process::{Child, Command, Output, Stdio};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use rand::rngs::OsRng;
use rcgen::{
    BasicConstraints, CertificateParams, ExtendedKeyUsagePurpose, IsCa, Issuer, KeyPair,
    KeyUsagePurpose,
};
use rustls::{ClientConfig, RootCertStore};
use rustls_pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName};
use sha2::{Digest, Sha256};
use sovereign_node::identity::{NodeIdentity, key_id};
use sovereign_node::protocol::{
    ActionArguments, ActionRequestV1, ActionStatus, ActionTarget, AgentId, AuthorityKind,
    AuthorizationClaimsV1, AuthorizationId, Capability, NodeId, Nonce, PairingId, PublicKeyBytes,
    ReplayProtectionV1, RequestId, Sha256Digest, SignatureBytes, SignedActionResponseV1,
    SignedActionV1, TaskId, UnixMillis, UserAuthorityV1,
};
use sovereign_node::store::{PairingApproval, PendingPairingChallenge, StateStore, sha256};
use sovereign_node::{pairing::PairingKeyMaterialV1, protocol::MAX_WIRE_MESSAGE_BYTES};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use uuid::Uuid;

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error + Send + Sync>>;

#[derive(Debug)]
struct TestIdentity {
    certificate: CertificateDer<'static>,
    certificate_pem: String,
    private_key: Vec<u8>,
    private_key_pem: String,
}

#[derive(Debug)]
struct TestPki {
    ca: CertificateDer<'static>,
    server: TestIdentity,
    client: TestIdentity,
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn compiled_binary_tls_pair_action_duplicate_revoke_and_restart() -> TestResult {
    let temporary = tempfile::TempDir::new()?;
    let data_dir = temporary.path().join("node-state");
    let configuration = temporary.path().join("sovereign-node.toml");
    let server_certificate = temporary.path().join("server-cert.pem");
    let server_key = temporary.path().join("server-key.pem");

    let initialized = run(&[
        "init",
        "--data-dir",
        path_text(&data_dir)?,
        "--label",
        "black-box-tls-node",
    ])?;
    require_success(&initialized, "init")?;
    let init_json: serde_json::Value = serde_json::from_slice(&initialized.stdout)?;
    let node_id = NodeId(Uuid::parse_str(
        init_json["node_id"].as_str().ok_or("init omitted NodeId")?,
    )?);
    let identity = NodeIdentity::load(&data_dir)?;

    let pki = test_pki()?;
    write_private(&server_certificate, pki.server.certificate_pem.as_bytes())?;
    write_private(&server_key, pki.server.private_key_pem.as_bytes())?;
    let port = reserve_loopback_port()?;
    write_configuration(
        &configuration,
        &data_dir,
        &server_certificate,
        &server_key,
        port,
    )?;

    let owner = SigningKey::generate(&mut OsRng);
    let broker = SigningKey::generate(&mut OsRng);
    let peer_id = "black-box-control-plane";
    let pairing_id = pair_peer(&data_dir, &identity, &pki, &owner, &broker, peer_id)?;
    let client = client_connector(&pki)?;
    let address = format!("127.0.0.1:{port}");

    let mut daemon = spawn_daemon(&configuration)?;
    let mut stream = connect_with_retry(&client, &address, &mut daemon).await?;
    let issued_at = now()?;
    let action = signed_system_info_action(
        node_id,
        PairingId(pairing_id),
        &owner,
        &broker,
        issued_at,
        1,
        RequestId(Uuid::new_v4()),
    )?;
    let first = send_action(&mut stream, &action).await?;
    verify_node_response(&first, &identity.verifying_key())?;
    assert_eq!(first.response.status, ActionStatus::Succeeded);

    let duplicate = send_action(&mut stream, &action).await?;
    verify_node_response(&duplicate, &identity.verifying_key())?;
    assert_eq!(duplicate.response.status, ActionStatus::Duplicate);
    stream.shutdown().await?;

    let mut shutdown_connection = connect_with_retry(&client, &address, &mut daemon).await?;
    stop_daemon(&mut daemon)?;
    let mut closed = [0_u8; 1];
    let shutdown_read = tokio::time::timeout(
        Duration::from_secs(2),
        shutdown_connection.read(&mut closed),
    )
    .await?;
    assert!(matches!(shutdown_read, Ok(0) | Err(_)));

    let mut daemon = spawn_daemon(&configuration)?;
    let mut pre_revocation = connect_with_retry(&client, &address, &mut daemon).await?;
    let revoked = run(&[
        "pair",
        "revoke",
        "--config",
        path_text(&configuration)?,
        "--peer-id",
        peer_id,
        "--reason",
        "black-box revocation persistence test",
        "--confirm",
    ])?;
    require_success(&revoked, "pair revoke")?;
    tokio::time::sleep(Duration::from_millis(600)).await;

    let fresh_action = signed_system_info_action(
        node_id,
        PairingId(pairing_id),
        &owner,
        &broker,
        now()?,
        2,
        RequestId(Uuid::new_v4()),
    )?;
    assert!(
        send_action(&mut pre_revocation, &fresh_action)
            .await
            .is_err()
    );
    assert!(connect_once(&client, &address).await.is_err());

    stop_daemon(&mut daemon)?;
    let status = run(&["status", path_text(&configuration)?])?;
    require_success(&status, "status after revocation")?;
    let status_json: serde_json::Value = serde_json::from_slice(&status.stdout)?;
    assert_eq!(status_json["trusted_peer_count"], 0);

    let restart = run(&["serve", path_text(&configuration)?])?;
    assert!(!restart.status.success());
    assert!(
        String::from_utf8_lossy(&restart.stderr)
            .contains("at least one current, owner-approved pairing")
    );
    Ok(())
}

fn test_pki() -> TestResult<TestPki> {
    let mut ca_params = CertificateParams::new(Vec::<String>::new())?;
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ca_params.key_usages = vec![
        KeyUsagePurpose::DigitalSignature,
        KeyUsagePurpose::KeyCertSign,
        KeyUsagePurpose::CrlSign,
    ];
    let ca_key = KeyPair::generate()?;
    let ca_certificate = ca_params.self_signed(&ca_key)?;
    let issuer = Issuer::new(ca_params, ca_key);
    Ok(TestPki {
        ca: ca_certificate.der().clone(),
        server: issue_identity("localhost", ExtendedKeyUsagePurpose::ServerAuth, &issuer)?,
        client: issue_identity(
            "black-box-control-plane",
            ExtendedKeyUsagePurpose::ClientAuth,
            &issuer,
        )?,
    })
}

fn issue_identity(
    name: &str,
    extended_usage: ExtendedKeyUsagePurpose,
    issuer: &Issuer<'_, KeyPair>,
) -> TestResult<TestIdentity> {
    let mut params = CertificateParams::new(vec![name.to_owned()])?;
    params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    params.extended_key_usages = vec![extended_usage];
    params.use_authority_key_identifier_extension = true;
    let private_key = KeyPair::generate()?;
    let certificate = params.signed_by(&private_key, issuer)?;
    Ok(TestIdentity {
        certificate: certificate.der().clone(),
        certificate_pem: certificate.pem(),
        private_key: private_key.serialize_der(),
        private_key_pem: private_key.serialize_pem(),
    })
}

fn pair_peer(
    data_dir: &Path,
    identity: &NodeIdentity,
    pki: &TestPki,
    owner: &SigningKey,
    broker: &SigningKey,
    peer_id: &str,
) -> TestResult<Uuid> {
    let store = StateStore::open(data_dir.join("state.sqlite3"))?;
    let pairing_id = Uuid::new_v4();
    let challenge = [0x42_u8; 32];
    let leaf_digest = Sha256Digest(Sha256::digest(pki.client.certificate.as_ref()).into());
    let material = PairingKeyMaterialV1 {
        schema_version: 1,
        owner_id: "owner-black-box".to_owned(),
        owner_public_key: PublicKeyBytes(owner.verifying_key().to_bytes()),
        broker_public_key: PublicKeyBytes(broker.verifying_key().to_bytes()),
        client_ca_der: pki.ca.as_ref().to_vec(),
        client_certificate_sha256: leaf_digest,
        allowed_capabilities: vec![Capability::SystemInfo],
        trust_expires_at: None,
    };
    let requested_at = i64::try_from(now()?.0)?;
    store.put_pending_pairing(&PendingPairingChallenge::new(
        pairing_id,
        identity.node_id().to_string(),
        peer_id.to_owned(),
        "Black-box control plane".to_owned(),
        postcard::to_allocvec(&material)?,
        vec![pki.client.certificate.as_ref().to_vec()],
        &challenge,
        identity.key_id().0,
        leaf_digest.0,
        requested_at,
        requested_at + 60_000,
    )?)?;
    store.approve_pairing(
        &PairingApproval {
            pairing_id,
            owner_authority_digest: sha256(b"owner-black-box"),
            capability_manifest_digest: sha256(b"black-box-system-info"),
            approved_at_unix_ms: requested_at + 1,
            trust_expires_at_unix_ms: None,
        },
        &challenge,
    )?;
    Ok(pairing_id)
}

fn client_connector(pki: &TestPki) -> TestResult<TlsConnector> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let builder = ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])?;
    let mut roots = RootCertStore::empty();
    roots.add(pki.ca.clone())?;
    let config = builder
        .with_root_certificates(roots)
        .with_client_auth_cert(
            vec![pki.client.certificate.clone()],
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(pki.client.private_key.clone())),
        )?;
    Ok(TlsConnector::from(Arc::new(config)))
}

#[allow(clippy::too_many_arguments)]
fn signed_system_info_action(
    node_id: NodeId,
    pairing_id: PairingId,
    owner: &SigningKey,
    broker: &SigningKey,
    issued_at: UnixMillis,
    sequence: u64,
    request_id: RequestId,
) -> TestResult<SignedActionV1> {
    let request = ActionRequestV1::new(
        request_id,
        TaskId(Uuid::new_v4()),
        AgentId(Uuid::new_v4()),
        UserAuthorityV1 {
            authority_id: AuthorizationId(Uuid::new_v4()),
            owner_id: "owner-black-box".to_owned(),
            kind: AuthorityKind::OwnerInteractive,
            approval_reason: Some("compiled binary lifecycle".to_owned()),
        },
        node_id,
        ActionTarget::Node,
        ActionArguments::SystemInfo,
        issued_at,
        issued_at,
        UnixMillis(issued_at.0 + 30_000),
        ReplayProtectionV1 {
            nonce: Nonce(sha256(request_id.as_uuid().as_bytes())),
            sequence,
        },
        AuthorizationClaimsV1 {
            authorization_id: AuthorizationId(Uuid::new_v4()),
            pairing_id,
            trust_epoch: 1,
            policy_version: 1,
            permitted_capability: Capability::SystemInfo,
            permitted_target_digest: Sha256Digest([0; 32]),
            owner_key_id: key_id(&owner.verifying_key()),
            broker_key_id: key_id(&broker.verifying_key()),
        },
    )?;
    let owner_signature =
        SignatureBytes::from_slice(&owner.sign(&request.owner_signing_bytes()?).to_bytes())?;
    let mut action = SignedActionV1 {
        request,
        owner_signature,
        broker_signature: SignatureBytes::from_slice(&broker.sign(b"placeholder").to_bytes())?,
    };
    action.broker_signature =
        SignatureBytes::from_slice(&broker.sign(&action.broker_signing_bytes()?).to_bytes())?;
    Ok(action)
}

fn verify_node_response(
    response: &SignedActionResponseV1,
    verifying_key: &VerifyingKey,
) -> TestResult {
    response.response.validate()?;
    assert_eq!(response.response.digest()?, response.response_digest);
    let signature = ed25519_dalek::Signature::from_slice(response.node_signature.as_bytes())?;
    verifying_key.verify_strict(&response.response.signing_bytes()?, &signature)?;
    Ok(())
}

async fn connect_with_retry(
    connector: &TlsConnector,
    address: &str,
    daemon: &mut Child,
) -> TestResult<tokio_rustls::client::TlsStream<TcpStream>> {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(8);
    loop {
        if let Some(status) = daemon.try_wait()? {
            return Err(format!("daemon exited before TLS readiness: {status}").into());
        }
        if let Ok(stream) = connect_once(connector, address).await {
            return Ok(stream);
        }
        if tokio::time::Instant::now() >= deadline {
            let _ = daemon.kill();
            return Err("daemon did not accept authenticated TLS before deadline".into());
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
}

async fn connect_once(
    connector: &TlsConnector,
    address: &str,
) -> TestResult<tokio_rustls::client::TlsStream<TcpStream>> {
    let tcp = TcpStream::connect(address).await?;
    Ok(connector
        .connect(ServerName::try_from("localhost")?, tcp)
        .await?)
}

async fn send_action(
    stream: &mut tokio_rustls::client::TlsStream<TcpStream>,
    action: &SignedActionV1,
) -> TestResult<SignedActionResponseV1> {
    let encoded = postcard::to_allocvec(action)?;
    stream
        .write_all(&u32::try_from(encoded.len())?.to_be_bytes())
        .await?;
    stream.write_all(&encoded).await?;
    stream.flush().await?;
    let mut response_length = [0_u8; 4];
    stream.read_exact(&mut response_length).await?;
    let length = usize::try_from(u32::from_be_bytes(response_length))?;
    if length == 0 || length > MAX_WIRE_MESSAGE_BYTES {
        return Err("invalid response frame length".into());
    }
    let mut encoded_response = vec![0_u8; length];
    stream.read_exact(&mut encoded_response).await?;
    let (response, remainder) = postcard::take_from_bytes(&encoded_response)?;
    if !remainder.is_empty() {
        return Err("response frame has trailing bytes".into());
    }
    Ok(response)
}

fn reserve_loopback_port() -> TestResult<u16> {
    let listener = std::net::TcpListener::bind("127.0.0.1:0")?;
    Ok(listener.local_addr()?.port())
}

fn write_configuration(
    path: &Path,
    data_dir: &Path,
    certificate: &Path,
    private_key: &Path,
    port: u16,
) -> TestResult {
    let content = format!(
        "data_dir = {data:?}\npolicy_version = 1\nlisten = \"127.0.0.1:{port}\"\n\n[tls]\ncertificate_pem = {certificate:?}\nprivate_key_pem = {private_key:?}\n\n[policy]\nenabled_capabilities = [\"SystemInfo\"]\n",
        data = data_dir.display().to_string(),
        certificate = certificate.display().to_string(),
        private_key = private_key.display().to_string(),
    );
    write_private(path, content.as_bytes())
}

fn write_private(path: &Path, contents: &[u8]) -> TestResult {
    fs::write(path, contents)?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    Ok(())
}

fn spawn_daemon(configuration: &Path) -> TestResult<Child> {
    Ok(Command::new(env!("CARGO_BIN_EXE_sovereign-node"))
        .args(["serve", path_text(configuration)?])
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()?)
}

fn stop_daemon(child: &mut Child) -> TestResult {
    let signal = Command::new("/bin/kill")
        .args(["-INT", &child.id().to_string()])
        .output()?;
    require_success(&signal, "SIGINT delivery")?;
    let status = child.wait()?;
    if !status.success() {
        return Err(format!("daemon shutdown failed: {status}").into());
    }
    Ok(())
}

fn run(arguments: &[&str]) -> TestResult<Output> {
    Ok(Command::new(env!("CARGO_BIN_EXE_sovereign-node"))
        .args(arguments)
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .output()?)
}

fn require_success(output: &Output, operation: &str) -> TestResult {
    if output.status.success() {
        Ok(())
    } else {
        Err(format!(
            "{operation} failed: {}",
            String::from_utf8_lossy(&output.stderr)
        )
        .into())
    }
}

fn now() -> TestResult<UnixMillis> {
    let millis = SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis();
    Ok(UnixMillis(u64::try_from(millis)?))
}

fn path_text(path: &Path) -> TestResult<&str> {
    path.to_str().ok_or_else(|| "test path is not UTF-8".into())
}
