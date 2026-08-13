use std::collections::HashMap;
use std::io::Cursor;
use std::sync::Arc;
use std::time::Duration;

use rustls::server::WebPkiClientVerifier;
use rustls::{RootCertStore, ServerConfig};
use rustls_pki_types::pem::PemObject;
use rustls_pki_types::{CertificateDer, PrivateKeyDer};
use sha2::{Digest, Sha256};
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{Semaphore, watch};
use tokio_rustls::TlsAcceptor;

use crate::authz::TransportPeer;
use crate::config::NodeConfig;
use crate::pairing::decode_key_material;
use crate::protocol::{MAX_WIRE_MESSAGE_BYTES, SignedActionResponseV1, SignedActionV1};
use crate::runtime::{NodeRuntime, RuntimeError};
use crate::security::SecureFileError;
use crate::store::{RemoteRequestAdmission, RequestLimitScope, StateStore, StoreError};

const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
const FRAME_TIMEOUT: Duration = Duration::from_secs(30);
const TRUST_REFRESH_INTERVAL: Duration = Duration::from_millis(250);

#[derive(Debug, Error)]
pub enum TransportError {
    #[error("LAN transport is disabled in configuration")]
    Disabled,
    #[error("transport configuration is invalid: {0}")]
    Configuration(String),
    #[error("transport filesystem error: {0}")]
    Io(#[from] std::io::Error),
    #[error("transport private-key security check failed: {0}")]
    Security(#[from] SecureFileError),
    #[error("TLS configuration is invalid: {0}")]
    Tls(#[from] rustls::Error),
    #[error("trust state is unavailable: {0}")]
    Store(#[from] StoreError),
    #[error("runtime failed: {0}")]
    Runtime(#[from] RuntimeError),
    #[error("wire message is malformed or exceeds the configured limit")]
    Frame,
    #[error("authenticated TLS client is not paired")]
    UnpairedClient,
    #[error("authenticated request exceeded the {scope:?} limit; retry after {retry_after_ms} ms")]
    RateLimited {
        scope: RequestLimitScope,
        retry_after_ms: u64,
    },
    #[error("transport session trust was revoked, expired, rotated, or became unavailable")]
    SessionTrustChanged,
    #[error("runtime task ended unexpectedly")]
    RuntimeTask,
}

#[derive(Debug)]
struct TransportTrust {
    tls: Arc<ServerConfig>,
    session_by_leaf: HashMap<[u8; 32], TransportSession>,
    state_digest: [u8; 32],
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct TransportSession {
    peer: TransportPeer,
}

#[derive(Debug)]
struct ServerIdentity {
    certificate_chain: Vec<CertificateDer<'static>>,
    private_key: PrivateKeyDer<'static>,
}

#[derive(Clone, Copy, Debug)]
struct TransportRequestPolicy {
    max_frame: usize,
    peer_maximum_per_minute: u32,
    global_maximum_per_minute: u32,
    maximum_clock_rollback_ms: i64,
}

pub async fn serve(
    config: Arc<NodeConfig>,
    store: Arc<StateStore>,
    runtime: Arc<NodeRuntime>,
) -> Result<(), TransportError> {
    let address = config.listen.ok_or(TransportError::Disabled)?;
    let server_identity = Arc::new(load_server_identity(&config)?);
    let initial_trust = build_transport_trust(&server_identity, &store)?.ok_or_else(|| {
        TransportError::Configuration(
            "at least one current, owner-approved pairing is required before listening".to_owned(),
        )
    })?;
    let (trust_sender, trust_receiver) = watch::channel(Some(Arc::new(initial_trust)));
    spawn_trust_reloader(server_identity, store.clone(), trust_sender);
    let listener = TcpListener::bind(address).await?;
    let max_connections = config
        .policy
        .queue_capacity
        .saturating_mul(2)
        .clamp(1, 8_192);
    let connections = Arc::new(Semaphore::new(max_connections));

    loop {
        let (stream, _) = listener.accept().await?;
        let Some(trust) = trust_receiver.borrow().clone() else {
            continue;
        };
        let Ok(permit) = connections.clone().try_acquire_owned() else {
            continue;
        };
        let acceptor = TlsAcceptor::from(trust.tls.clone());
        let runtime = runtime.clone();
        let store = store.clone();
        let request_policy = TransportRequestPolicy {
            max_frame: config.policy.max_frame_bytes.min(MAX_WIRE_MESSAGE_BYTES),
            peer_maximum_per_minute: config.policy.max_requests_per_peer_per_minute,
            global_maximum_per_minute: config.policy.max_requests_global_per_minute,
            maximum_clock_rollback_ms: i64::try_from(config.policy.max_clock_rollback_secs)
                .map_err(|_| {
                    TransportError::Configuration("clock rollback policy overflow".to_owned())
                })?
                .saturating_mul(1_000),
        };
        tokio::spawn(async move {
            let _permit = permit;
            let accepted = tokio::time::timeout(HANDSHAKE_TIMEOUT, acceptor.accept(stream)).await;
            let Ok(Ok(tls_stream)) = accepted else {
                return;
            };
            let Some(session) = authenticated_session(&tls_stream, &trust.session_by_leaf) else {
                return;
            };
            if !session_is_current(&store, &session).unwrap_or(false) {
                return;
            }
            let _ = serve_connection(tls_stream, session, runtime, store, request_policy).await;
        });
    }
}

async fn serve_connection(
    mut stream: tokio_rustls::server::TlsStream<TcpStream>,
    session: TransportSession,
    runtime: Arc<NodeRuntime>,
    store: Arc<StateStore>,
    request_policy: TransportRequestPolicy,
) -> Result<(), TransportError> {
    loop {
        let Some(frame) = tokio::time::timeout(
            FRAME_TIMEOUT,
            read_frame_with_trust(&mut stream, &store, &session, request_policy.max_frame),
        )
        .await
        .map_err(|_| TransportError::Frame)??
        else {
            return Ok(());
        };
        let (action, remainder): (SignedActionV1, &[u8]) =
            postcard::take_from_bytes(&frame).map_err(|_| TransportError::Frame)?;
        if !remainder.is_empty() {
            return Err(TransportError::Frame);
        }
        match store.admit_remote_request_with_clock_policy(
            &session.peer.peer_id,
            request_policy.peer_maximum_per_minute,
            request_policy.global_maximum_per_minute,
            request_policy.maximum_clock_rollback_ms,
        )? {
            RemoteRequestAdmission::Admitted { .. } => {}
            RemoteRequestAdmission::Limited {
                scope,
                retry_after_ms,
            } => {
                return Err(TransportError::RateLimited {
                    scope,
                    retry_after_ms,
                });
            }
        }
        // Once dispatch begins, it is not cancelled solely because the client disconnects. The
        // durable request ID remains the source of truth on reconnect.
        let runtime_for_action = runtime.clone();
        let peer_for_action = session.peer.clone();
        let mut action_task =
            tokio::spawn(async move { runtime_for_action.handle(action, &peer_for_action).await });
        let response = wait_for_action_or_trust_change(&mut action_task, &store, &session).await?;
        let encoded = postcard::to_allocvec(&response).map_err(|_| TransportError::Frame)?;
        if encoded.len() > request_policy.max_frame || encoded.len() > u32::MAX as usize {
            return Err(TransportError::Frame);
        }
        let encoded_length = u32::try_from(encoded.len()).map_err(|_| TransportError::Frame)?;
        tokio::time::timeout(
            FRAME_TIMEOUT,
            write_response_with_trust(&mut stream, &store, &session, encoded_length, &encoded),
        )
        .await
        .map_err(|_| TransportError::Frame)??;
    }
}

async fn read_frame_with_trust<R: AsyncRead + Unpin>(
    stream: &mut R,
    store: &StateStore,
    session: &TransportSession,
    max_frame: usize,
) -> Result<Option<Vec<u8>>, TransportError> {
    let mut length_bytes = [0_u8; 4];
    if !read_exact_with_trust(stream, store, session, &mut length_bytes).await? {
        return Ok(None);
    }
    let length =
        usize::try_from(u32::from_be_bytes(length_bytes)).map_err(|_| TransportError::Frame)?;
    if length == 0 || length > max_frame {
        return Err(TransportError::Frame);
    }
    let mut frame = vec![0_u8; length];
    if !read_exact_with_trust(stream, store, session, &mut frame).await? {
        return Err(std::io::Error::from(std::io::ErrorKind::UnexpectedEof).into());
    }
    Ok(Some(frame))
}

async fn read_exact_with_trust<R: AsyncRead + Unpin>(
    stream: &mut R,
    store: &StateStore,
    session: &TransportSession,
    buffer: &mut [u8],
) -> Result<bool, TransportError> {
    ensure_session_current(store, session)?;
    let mut filled = 0;
    let mut interval = tokio::time::interval(TRUST_REFRESH_INTERVAL);
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    interval.tick().await;
    while filled < buffer.len() {
        tokio::select! {
            read = stream.read(&mut buffer[filled..]) => {
                match read? {
                    0 if filled == 0 => return Ok(false),
                    0 => return Err(std::io::Error::from(std::io::ErrorKind::UnexpectedEof).into()),
                    read => filled += read,
                }
            }
            _ = interval.tick() => ensure_session_current(store, session)?,
        }
    }
    Ok(true)
}

async fn wait_for_action_or_trust_change(
    task: &mut tokio::task::JoinHandle<Result<SignedActionResponseV1, RuntimeError>>,
    store: &StateStore,
    session: &TransportSession,
) -> Result<SignedActionResponseV1, TransportError> {
    ensure_session_current(store, session)?;
    let mut interval = tokio::time::interval(TRUST_REFRESH_INTERVAL);
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    interval.tick().await;
    loop {
        tokio::select! {
            result = &mut *task => return result
                .map_err(|_| TransportError::RuntimeTask)?
                .map_err(Into::into),
            _ = interval.tick() => ensure_session_current(store, session)?,
        }
    }
}

async fn write_response_with_trust<W: AsyncWrite + Unpin>(
    stream: &mut W,
    store: &StateStore,
    session: &TransportSession,
    encoded_length: u32,
    encoded: &[u8],
) -> Result<(), TransportError> {
    write_all_with_trust(stream, store, session, &encoded_length.to_be_bytes()).await?;
    write_all_with_trust(stream, store, session, encoded).await?;
    ensure_session_current(store, session)?;
    let mut interval = tokio::time::interval(TRUST_REFRESH_INTERVAL);
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    interval.tick().await;
    let flush = stream.flush();
    tokio::pin!(flush);
    loop {
        tokio::select! {
            result = &mut flush => return result.map_err(Into::into),
            _ = interval.tick() => ensure_session_current(store, session)?,
        }
    }
}

async fn write_all_with_trust<W: AsyncWrite + Unpin>(
    stream: &mut W,
    store: &StateStore,
    session: &TransportSession,
    buffer: &[u8],
) -> Result<(), TransportError> {
    ensure_session_current(store, session)?;
    let mut written = 0;
    let mut interval = tokio::time::interval(TRUST_REFRESH_INTERVAL);
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    interval.tick().await;
    while written < buffer.len() {
        tokio::select! {
            result = stream.write(&buffer[written..]) => {
                let count = result?;
                if count == 0 {
                    return Err(std::io::Error::from(std::io::ErrorKind::WriteZero).into());
                }
                written += count;
            }
            _ = interval.tick() => ensure_session_current(store, session)?,
        }
    }
    Ok(())
}

fn ensure_session_current(
    store: &StateStore,
    session: &TransportSession,
) -> Result<(), TransportError> {
    if session_is_current(store, session)? {
        Ok(())
    } else {
        Err(TransportError::SessionTrustChanged)
    }
}

fn spawn_trust_reloader(
    server_identity: Arc<ServerIdentity>,
    store: Arc<StateStore>,
    sender: watch::Sender<Option<Arc<TransportTrust>>>,
) {
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(TRUST_REFRESH_INTERVAL);
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        interval.tick().await;
        loop {
            interval.tick().await;
            if sender.is_closed() {
                return;
            }
            let next_digest = match current_transport_trust_digest(&store) {
                Ok(digest) => digest,
                Err(_) => {
                    if sender.borrow().is_some() {
                        sender.send_replace(None);
                    }
                    continue;
                }
            };
            let current_digest = sender.borrow().as_ref().map(|trust| trust.state_digest);
            if next_digest == current_digest {
                continue;
            }
            let refreshed = build_transport_trust(&server_identity, &store)
                .ok()
                .flatten()
                .map(Arc::new);
            sender.send_replace(refreshed);
        }
    });
}

fn load_server_identity(config: &NodeConfig) -> Result<ServerIdentity, TransportError> {
    let tls = config.tls.as_ref().ok_or_else(|| {
        TransportError::Configuration("TLS is mandatory for a LAN listener".to_owned())
    })?;
    Ok(ServerIdentity {
        certificate_chain: load_certificates(&tls.certificate_pem)?,
        private_key: load_private_key(&tls.private_key_pem)?,
    })
}

fn build_transport_trust(
    server_identity: &ServerIdentity,
    store: &StateStore,
) -> Result<Option<TransportTrust>, TransportError> {
    let now = current_time_millis()?;
    let peers = store.currently_trusted_peers(now)?;
    if peers.is_empty() {
        return Ok(None);
    }
    let state_digest = trusted_peers_digest(&peers);

    let mut roots = RootCertStore::empty();
    let mut session_by_leaf = HashMap::new();
    for peer in peers {
        let material = decode_key_material(&peer.public_key)
            .map_err(|_| TransportError::Configuration("stored pairing is invalid".to_owned()))?;
        roots.add(CertificateDer::from(material.client_ca_der))?;
        let session = TransportSession {
            peer: TransportPeer {
                peer_id: peer.peer_id,
                certificate_sha256: material.client_certificate_sha256,
                trust_epoch: peer.trust_epoch,
            },
        };
        if session_by_leaf
            .insert(material.client_certificate_sha256.0, session)
            .is_some()
        {
            return Err(TransportError::Configuration(
                "two active pairings reuse the same client certificate".to_owned(),
            ));
        }
    }
    let tls = tls13_server_config(
        server_identity.certificate_chain.clone(),
        server_identity.private_key.clone_key(),
        roots,
    )?;
    Ok(Some(TransportTrust {
        tls: Arc::new(tls),
        session_by_leaf,
        state_digest,
    }))
}

fn current_transport_trust_digest(store: &StateStore) -> Result<Option<[u8; 32]>, TransportError> {
    let peers = store.currently_trusted_peers(current_time_millis()?)?;
    if peers.is_empty() {
        Ok(None)
    } else {
        Ok(Some(trusted_peers_digest(&peers)))
    }
}

fn trusted_peers_digest(peers: &[crate::store::TrustedPeer]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"sovereign-node/transport-trust-state/v1\0");
    hasher.update((peers.len() as u64).to_be_bytes());
    for peer in peers {
        hasher.update((peer.peer_id.len() as u64).to_be_bytes());
        hasher.update(peer.peer_id.as_bytes());
        hasher.update(peer.pairing_id.as_bytes());
        hasher.update(peer.trust_epoch.to_be_bytes());
        hasher.update(Sha256::digest(&peer.public_key));
    }
    hasher.finalize().into()
}

fn tls13_server_config(
    certificate_chain: Vec<CertificateDer<'static>>,
    private_key: PrivateKeyDer<'static>,
    client_roots: RootCertStore,
) -> Result<ServerConfig, TransportError> {
    let client_verifier = WebPkiClientVerifier::builder(Arc::new(client_roots))
        .build()
        .map_err(|error| TransportError::Configuration(error.to_string()))?;
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let tls = ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .with_client_cert_verifier(client_verifier)
        .with_single_cert(certificate_chain, private_key)?;
    Ok(tls)
}

fn authenticated_session(
    stream: &tokio_rustls::server::TlsStream<TcpStream>,
    session_by_leaf: &HashMap<[u8; 32], TransportSession>,
) -> Option<TransportSession> {
    let certificates = stream.get_ref().1.peer_certificates()?;
    let leaf = certificates.first()?;
    let digest: [u8; 32] = Sha256::digest(leaf.as_ref()).into();
    session_by_leaf.get(&digest).cloned()
}

fn current_time_millis() -> Result<i64, TransportError> {
    let clock = crate::authz::SystemClock;
    let now = crate::authz::Clock::now(&clock)
        .map_err(|_| TransportError::Configuration("system clock is invalid".to_owned()))?;
    i64::try_from(now.0)
        .map_err(|_| TransportError::Configuration("system clock is invalid".to_owned()))
}

fn session_is_current(
    store: &StateStore,
    session: &TransportSession,
) -> Result<bool, TransportError> {
    let Some(peer) = store.currently_trusted_peer(&session.peer.peer_id, current_time_millis()?)?
    else {
        return Ok(false);
    };
    if peer.trust_epoch != session.peer.trust_epoch {
        return Ok(false);
    }
    let material = decode_key_material(&peer.public_key)
        .map_err(|_| TransportError::Configuration("stored pairing is invalid".to_owned()))?;
    Ok(material.client_certificate_sha256 == session.peer.certificate_sha256)
}

fn load_certificates(
    path: &std::path::Path,
) -> Result<Vec<CertificateDer<'static>>, TransportError> {
    let certificates = CertificateDer::pem_file_iter(path)
        .map_err(|error| TransportError::Configuration(error.to_string()))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| TransportError::Configuration(error.to_string()))?;
    if certificates.is_empty() {
        return Err(TransportError::Configuration(
            "server certificate file contains no certificates".to_owned(),
        ));
    }
    Ok(certificates)
}

fn load_private_key(path: &std::path::Path) -> Result<PrivateKeyDer<'static>, TransportError> {
    let bytes = crate::security::read_private_file(path)?;
    PrivateKeyDer::from_pem_reader(Cursor::new(bytes))
        .map_err(|error| TransportError::Configuration(error.to_string()))
}

#[cfg(test)]
mod tests {
    use std::error::Error;

    use ed25519_dalek::{Signer, SigningKey};
    use rand::rngs::OsRng;
    use rcgen::{
        BasicConstraints, CertificateParams, ExtendedKeyUsagePurpose, IsCa, Issuer, KeyPair,
        KeyUsagePurpose,
    };
    use rustls::{ClientConfig, ProtocolVersion};
    use rustls_pki_types::{PrivatePkcs8KeyDer, ServerName};
    use tokio_rustls::TlsConnector;
    use uuid::Uuid;

    use super::*;
    use crate::authz::{AuthorizationEngine, AuthorizationError, Clock};
    use crate::capabilities::CapabilityExecutor;
    use crate::config::{
        HealthConfig, NodeConfig, PolicyConfig, ProcessReportingConfig, RepositoryReportingConfig,
        ResourceReportingConfig, ServiceReportingConfig,
    };
    use crate::identity::{NodeIdentity, key_id};
    use crate::lifecycle::{LeaseKind, LifecycleLease};
    use crate::pairing::PairingKeyMaterialV1;
    use crate::protocol::{
        ActionArguments, ActionRequestV1, ActionStatus, ActionTarget, AgentId, AuthorityKind,
        AuthorizationClaimsV1, AuthorizationId, Capability, NodeId, Nonce, PairingId,
        PublicKeyBytes, ReplayProtectionV1, RequestId, Sha256Digest, SignatureBytes,
        SignedActionV1, TaskId, UnixMillis, UserAuthorityV1,
    };
    use crate::resources::ResourceReporter;
    use crate::runtime::{NodeRuntime, RuntimeCapacity};
    use crate::store::{
        CredentialRotationOutcome, PairingApproval, PendingPairingChallenge, RevocationOutcome,
        TerminalStatus, TrustedPeer, sha256,
    };

    type TestResult<T = ()> = Result<T, Box<dyn Error + Send + Sync>>;

    #[derive(Debug)]
    struct ManualClock(u64);

    impl ManualClock {
        fn new(now: u64) -> Self {
            Self(now)
        }
    }

    impl Clock for ManualClock {
        fn now(&self) -> Result<UnixMillis, AuthorizationError> {
            Ok(UnixMillis(self.0))
        }
    }

    #[derive(Debug)]
    struct TestIdentity {
        certificate: CertificateDer<'static>,
        private_key: Vec<u8>,
    }

    #[derive(Debug)]
    struct TestPki {
        ca: CertificateDer<'static>,
        server: TestIdentity,
        paired_client: TestIdentity,
        unpaired_client: TestIdentity,
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
            paired_client: issue_identity(
                "paired-client",
                ExtendedKeyUsagePurpose::ClientAuth,
                &issuer,
            )?,
            unpaired_client: issue_identity(
                "unpaired-client",
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
            private_key: private_key.serialize_der(),
        })
    }

    fn server_config(pki: &TestPki) -> TestResult<Arc<ServerConfig>> {
        let mut roots = RootCertStore::empty();
        roots.add(pki.ca.clone())?;
        let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(pki.server.private_key.clone()));
        Ok(Arc::new(tls13_server_config(
            vec![pki.server.certificate.clone()],
            key,
            roots,
        )?))
    }

    fn server_identity(pki: &TestPki) -> ServerIdentity {
        ServerIdentity {
            certificate_chain: vec![pki.server.certificate.clone()],
            private_key: PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
                pki.server.private_key.clone(),
            )),
        }
    }

    fn pair_transport_peer(
        store: &StateStore,
        pki: &TestPki,
        peer_id: &str,
        client: &TestIdentity,
        challenge_byte: u8,
    ) -> TestResult<TrustedPeer> {
        let owner = SigningKey::generate(&mut OsRng);
        let broker = SigningKey::generate(&mut OsRng);
        pair_transport_peer_with_keys(store, pki, peer_id, client, challenge_byte, &owner, &broker)
    }

    fn pair_transport_peer_with_keys(
        store: &StateStore,
        pki: &TestPki,
        peer_id: &str,
        client: &TestIdentity,
        challenge_byte: u8,
        owner: &SigningKey,
        broker: &SigningKey,
    ) -> TestResult<TrustedPeer> {
        let certificate_digest: [u8; 32] = Sha256::digest(client.certificate.as_ref()).into();
        let material = PairingKeyMaterialV1 {
            schema_version: 1,
            owner_id: format!("owner-{peer_id}"),
            owner_public_key: PublicKeyBytes(owner.verifying_key().to_bytes()),
            broker_public_key: PublicKeyBytes(broker.verifying_key().to_bytes()),
            client_ca_der: pki.ca.as_ref().to_vec(),
            client_certificate_sha256: Sha256Digest(certificate_digest),
            allowed_capabilities: vec![Capability::SystemInfo],
            trust_expires_at: None,
        };
        let encoded = postcard::to_allocvec(&material)?;
        let now = current_time_millis()?;
        let challenge = [challenge_byte; 32];
        let pending = PendingPairingChallenge::new(
            Uuid::new_v4(),
            "node-01".to_owned(),
            peer_id.to_owned(),
            format!("Test {peer_id}"),
            encoded,
            vec![client.certificate.as_ref().to_vec()],
            &challenge,
            sha256(b"node-identity"),
            certificate_digest,
            now,
            now + 60_000,
        )?;
        store.put_pending_pairing(&pending)?;
        let (_, trusted) = store.approve_pairing(
            &PairingApproval {
                pairing_id: pending.pairing_id,
                owner_authority_digest: sha256(b"owner"),
                capability_manifest_digest: sha256(b"manifest"),
                approved_at_unix_ms: now + 1,
                trust_expires_at_unix_ms: None,
            },
            &challenge,
        )?;
        Ok(trusted)
    }

    #[allow(clippy::too_many_arguments)]
    fn signed_system_info_action(
        node_id: NodeId,
        pairing_id: PairingId,
        owner_id: &str,
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
                owner_id: owner_id.to_owned(),
                kind: AuthorityKind::OwnerInteractive,
                approval_reason: Some("transport reconnect invariant".to_owned()),
            },
            node_id,
            ActionTarget::Node,
            ActionArguments::SystemInfo,
            issued_at,
            issued_at,
            UnixMillis(issued_at.0 + 60_000),
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

    fn client_config(
        pki: &TestPki,
        identity: Option<&TestIdentity>,
    ) -> TestResult<Arc<ClientConfig>> {
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let builder = ClientConfig::builder_with_provider(provider)
            .with_protocol_versions(&[&rustls::version::TLS13])?;
        let mut roots = RootCertStore::empty();
        roots.add(pki.ca.clone())?;
        let config = match identity {
            Some(identity) => builder
                .with_root_certificates(roots)
                .with_client_auth_cert(
                    vec![identity.certificate.clone()],
                    PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(identity.private_key.clone())),
                )?,
            None => builder.with_root_certificates(roots).with_no_client_auth(),
        };
        Ok(Arc::new(config))
    }

    async fn connect_once(
        server_config: Arc<ServerConfig>,
        client_config: Arc<ClientConfig>,
        session_by_leaf: HashMap<[u8; 32], TransportSession>,
    ) -> TestResult<(
        Result<(), std::io::Error>,
        Result<(Option<ProtocolVersion>, Option<TransportSession>), String>,
    )> {
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let address = listener.local_addr()?;
        let acceptor = TlsAcceptor::from(server_config);
        let server = tokio::spawn(async move {
            let (tcp, _) = listener.accept().await.map_err(|error| error.to_string())?;
            let tls = acceptor
                .accept(tcp)
                .await
                .map_err(|error| error.to_string())?;
            let version = tls.get_ref().1.protocol_version();
            let session = authenticated_session(&tls, &session_by_leaf);
            Ok::<_, String>((version, session))
        });

        let tcp = TcpStream::connect(address).await?;
        let connector = TlsConnector::from(client_config);
        let client = connector
            .connect(ServerName::try_from("localhost")?, tcp)
            .await
            .map(|_| ());
        let server = server.await?;
        Ok((client, server))
    }

    async fn accept_runtime_connection(
        listener: Arc<TcpListener>,
        trust: Arc<TransportTrust>,
        runtime: Arc<NodeRuntime>,
        store: Arc<StateStore>,
        request_policy: TransportRequestPolicy,
    ) -> Result<(), TransportError> {
        let (tcp, _) = listener.accept().await?;
        let acceptor = TlsAcceptor::from(trust.tls.clone());
        let tls = acceptor.accept(tcp).await.map_err(TransportError::Io)?;
        let session = authenticated_session(&tls, &trust.session_by_leaf)
            .ok_or(TransportError::UnpairedClient)?;
        ensure_session_current(&store, &session)?;
        serve_connection(tls, session, runtime, store, request_policy).await
    }

    async fn connect_test_client(
        address: std::net::SocketAddr,
        config: Arc<ClientConfig>,
    ) -> TestResult<tokio_rustls::client::TlsStream<TcpStream>> {
        let tcp = TcpStream::connect(address).await?;
        Ok(TlsConnector::from(config)
            .connect(ServerName::try_from("localhost")?, tcp)
            .await?)
    }

    async fn send_action_and_close(
        stream: &mut tokio_rustls::client::TlsStream<TcpStream>,
        action: &SignedActionV1,
    ) -> TestResult<SignedActionResponseV1> {
        let encoded = postcard::to_allocvec(action)?;
        let length = u32::try_from(encoded.len())?;
        stream.write_all(&length.to_be_bytes()).await?;
        stream.write_all(&encoded).await?;
        stream.flush().await?;

        let mut response_length = [0_u8; 4];
        stream.read_exact(&mut response_length).await?;
        let response_length = usize::try_from(u32::from_be_bytes(response_length))?;
        if response_length == 0 || response_length > MAX_WIRE_MESSAGE_BYTES {
            return Err(std::io::Error::other("invalid response frame length").into());
        }
        let mut response = vec![0_u8; response_length];
        stream.read_exact(&mut response).await?;
        stream.shutdown().await?;
        let (response, remainder) = postcard::take_from_bytes(&response)?;
        if !remainder.is_empty() {
            return Err(std::io::Error::other("non-canonical response frame").into());
        }
        Ok(response)
    }

    async fn send_action_without_reading_response(
        stream: &mut tokio_rustls::client::TlsStream<TcpStream>,
        action: &SignedActionV1,
    ) -> TestResult {
        let encoded = postcard::to_allocvec(action)?;
        stream
            .write_all(&u32::try_from(encoded.len())?.to_be_bytes())
            .await?;
        stream.write_all(&encoded).await?;
        stream.flush().await?;
        stream.shutdown().await?;
        Ok(())
    }

    async fn send_raw_frame_and_close(
        stream: &mut tokio_rustls::client::TlsStream<TcpStream>,
        declared_length: u32,
        body: &[u8],
    ) -> TestResult {
        stream.write_all(&declared_length.to_be_bytes()).await?;
        stream.write_all(body).await?;
        stream.flush().await?;
        stream.shutdown().await?;
        Ok(())
    }

    #[test]
    fn frame_size_constant_fits_u32_prefix() {
        assert!(MAX_WIRE_MESSAGE_BYTES < u32::MAX as usize);
    }

    #[tokio::test]
    async fn mutual_tls_is_tls13_only_and_requires_the_paired_leaf() -> TestResult {
        let pki = test_pki()?;
        let paired_digest: [u8; 32] = Sha256::digest(pki.paired_client.certificate.as_ref()).into();
        let session_by_leaf = HashMap::from([(
            paired_digest,
            TransportSession {
                peer: TransportPeer {
                    peer_id: "peer-01".to_owned(),
                    certificate_sha256: crate::protocol::Sha256Digest(paired_digest),
                    trust_epoch: 1,
                },
            },
        )]);

        let (client, server) = connect_once(
            server_config(&pki)?,
            client_config(&pki, Some(&pki.paired_client))?,
            session_by_leaf.clone(),
        )
        .await?;
        assert!(client.is_ok());
        let (version, session) = server.map_err(std::io::Error::other)?;
        assert_eq!(version, Some(ProtocolVersion::TLSv1_3));
        assert_eq!(
            session.map(|value| value.peer.peer_id),
            Some("peer-01".to_owned())
        );

        let (client, server) = connect_once(
            server_config(&pki)?,
            client_config(&pki, Some(&pki.unpaired_client))?,
            session_by_leaf.clone(),
        )
        .await?;
        assert!(client.is_ok());
        let (_, session) = server.map_err(std::io::Error::other)?;
        assert!(session.is_none());

        let (_client, server) = connect_once(
            server_config(&pki)?,
            client_config(&pki, None)?,
            session_by_leaf,
        )
        .await?;
        assert!(server.is_err());
        Ok(())
    }

    #[tokio::test]
    async fn trust_reloader_adds_new_pairings_and_removes_revoked_peers() -> TestResult {
        let pki = test_pki()?;
        let directory = tempfile::TempDir::new()?;
        let store = Arc::new(StateStore::open(directory.path().join("state.sqlite3"))?);
        let first = pair_transport_peer(&store, &pki, "peer-01", &pki.paired_client, 1)?;
        let identity = Arc::new(server_identity(&pki));
        let initial = build_transport_trust(&identity, &store)?
            .ok_or_else(|| std::io::Error::other("initial trust missing"))?;
        let (sender, mut receiver) = watch::channel(Some(Arc::new(initial)));
        spawn_trust_reloader(identity, store.clone(), sender);

        let second = pair_transport_peer(&store, &pki, "peer-02", &pki.unpaired_client, 2)?;
        tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                receiver.changed().await?;
                if receiver
                    .borrow()
                    .as_ref()
                    .is_some_and(|trust| trust.session_by_leaf.len() == 2)
                {
                    return Ok::<_, watch::error::RecvError>(());
                }
            }
        })
        .await??;

        let old_second_session = receiver
            .borrow()
            .as_ref()
            .and_then(|trust| {
                trust
                    .session_by_leaf
                    .values()
                    .find(|session| session.peer.peer_id == second.peer_id)
                    .cloned()
            })
            .ok_or_else(|| std::io::Error::other("second session binding missing"))?;
        let mut rotated_material = decode_key_material(&second.public_key)?;
        let rotated_broker = SigningKey::generate(&mut OsRng);
        rotated_material.broker_public_key =
            PublicKeyBytes(rotated_broker.verifying_key().to_bytes());
        assert!(matches!(
            store.rotate_peer_credential(
                &second.peer_id,
                sha256(&second.public_key),
                postcard::to_allocvec(&rotated_material)?,
                sha256(b"owner"),
                current_time_millis()?,
            )?,
            CredentialRotationOutcome::Rotated(_)
        ));
        assert!(!session_is_current(&store, &old_second_session)?);
        tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                receiver.changed().await?;
                if receiver.borrow().as_ref().is_some_and(|trust| {
                    trust.session_by_leaf.values().any(|session| {
                        session.peer.peer_id == second.peer_id && session.peer.trust_epoch == 2
                    })
                }) {
                    return Ok::<_, watch::error::RecvError>(());
                }
            }
        })
        .await??;

        assert!(matches!(
            store.revoke_peer(
                &first.peer_id,
                current_time_millis()?,
                sha256(b"owner"),
                sha256(b"revoked"),
            )?,
            RevocationOutcome::Revoked(_)
        ));
        tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                receiver.changed().await?;
                let trust = receiver.borrow().clone();
                if trust.as_ref().is_some_and(|trust| {
                    trust.session_by_leaf.len() == 1
                        && trust
                            .session_by_leaf
                            .values()
                            .any(|session| session.peer.peer_id == second.peer_id)
                }) {
                    return Ok::<_, watch::error::RecvError>(());
                }
            }
        })
        .await??;

        assert!(matches!(
            store.revoke_peer(
                &second.peer_id,
                current_time_millis()?,
                sha256(b"owner"),
                sha256(b"revoked"),
            )?,
            RevocationOutcome::Revoked(_)
        ));
        tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                receiver.changed().await?;
                if receiver.borrow().is_none() {
                    return Ok::<_, watch::error::RecvError>(());
                }
            }
        })
        .await??;
        Ok(())
    }

    #[tokio::test]
    async fn disconnects_before_and_after_reservation_never_execute_twice() -> TestResult {
        let pki = test_pki()?;
        let directory = tempfile::TempDir::new()?;
        let data_dir = directory.path().join("node");
        let now = u64::try_from(current_time_millis()?)?;
        let (identity, created) = NodeIdentity::load_or_initialize(
            &data_dir,
            "transport-reconnect-test",
            UnixMillis(now),
        )?;
        assert!(created);
        let identity = Arc::new(identity);
        let store = Arc::new(StateStore::open(data_dir.join("state.sqlite3"))?);
        let owner = SigningKey::from_bytes(&[0x41; 32]);
        let broker = SigningKey::from_bytes(&[0x42; 32]);
        let trusted = pair_transport_peer_with_keys(
            &store,
            &pki,
            "peer-reconnect",
            &pki.paired_client,
            4,
            &owner,
            &broker,
        )?;

        let policy = PolicyConfig {
            enabled_capabilities: vec![Capability::SystemInfo],
            ..PolicyConfig::default()
        };
        let config = Arc::new(NodeConfig {
            data_dir: data_dir.clone(),
            policy_version: 1,
            listen: None,
            tls: None,
            policy,
            file_roots: Default::default(),
            read_roots: Default::default(),
            approved_actions: Default::default(),
            health: HealthConfig::default(),
            resource_reporting: ResourceReportingConfig::default(),
            process_reporting: ProcessReportingConfig::default(),
            service_reporting: ServiceReportingConfig::default(),
            repository_reporting: RepositoryReportingConfig::default(),
            updates: None,
        });
        config.validate()?;
        let policy_digest = Sha256Digest(config.policy_digest()?);
        store.activate_policy(1, policy_digest.0, i64::try_from(now)?)?;
        let clock = Arc::new(ManualClock::new(now + 10));
        let authorization = AuthorizationEngine::new(
            identity.node_id(),
            store.clone(),
            clock.clone(),
            &config.policy,
            config.policy_version,
            policy_digest,
        );
        let executor = CapabilityExecutor::new(
            config.clone(),
            ResourceReporter::new(identity.node_id(), identity.device().clone()),
        );
        let runtime = Arc::new(NodeRuntime::new(
            identity.clone(),
            authorization,
            executor,
            store.clone(),
            clock,
            RuntimeCapacity {
                max_concurrent_actions: 1,
                queue_capacity: 1,
            },
            LifecycleLease::acquire(&data_dir, LeaseKind::Daemon)?,
        ));
        let trust = Arc::new(
            build_transport_trust(&server_identity(&pki), &store)?
                .ok_or_else(|| std::io::Error::other("transport trust missing"))?,
        );
        let listener = Arc::new(TcpListener::bind("127.0.0.1:0").await?);
        let address = listener.local_addr()?;
        let request_policy = TransportRequestPolicy {
            max_frame: config.policy.max_frame_bytes,
            peer_maximum_per_minute: 4,
            global_maximum_per_minute: 4,
            maximum_clock_rollback_ms: i64::try_from(config.policy.max_clock_rollback_secs)?
                .saturating_mul(1_000),
        };
        let request_id = RequestId(Uuid::new_v4());
        let action = signed_system_info_action(
            identity.node_id(),
            PairingId(trusted.pairing_id),
            "owner-peer-reconnect",
            &owner,
            &broker,
            UnixMillis(now),
            1,
            request_id,
        )?;
        let client_config = client_config(&pki, Some(&pki.paired_client))?;

        let oversized_server = tokio::spawn(accept_runtime_connection(
            listener.clone(),
            trust.clone(),
            runtime.clone(),
            store.clone(),
            request_policy,
        ));
        let mut oversized_client = connect_test_client(address, client_config.clone()).await?;
        send_raw_frame_and_close(
            &mut oversized_client,
            u32::try_from(request_policy.max_frame + 1)?,
            &[],
        )
        .await?;
        assert!(matches!(
            oversized_server.await?,
            Err(TransportError::Frame)
        ));

        let trailing_server = tokio::spawn(accept_runtime_connection(
            listener.clone(),
            trust.clone(),
            runtime.clone(),
            store.clone(),
            request_policy,
        ));
        let mut trailing_client = connect_test_client(address, client_config.clone()).await?;
        let mut noncanonical = postcard::to_allocvec(&action)?;
        noncanonical.push(0);
        send_raw_frame_and_close(
            &mut trailing_client,
            u32::try_from(noncanonical.len())?,
            &noncanonical,
        )
        .await?;
        assert!(matches!(trailing_server.await?, Err(TransportError::Frame)));
        assert!(store.action_audit_record(request_id.0)?.is_none());

        let first_server = tokio::spawn(accept_runtime_connection(
            listener.clone(),
            trust.clone(),
            runtime.clone(),
            store.clone(),
            request_policy,
        ));
        let mut interrupted = connect_test_client(address, client_config.clone()).await?;
        let encoded = postcard::to_allocvec(&action)?;
        interrupted
            .write_all(&u32::try_from(encoded.len())?.to_be_bytes())
            .await?;
        interrupted.write_all(&encoded[..encoded.len() / 2]).await?;
        interrupted.shutdown().await?;
        let interrupted_result = first_server.await?;
        assert!(matches!(interrupted_result, Err(TransportError::Io(_))));
        assert!(store.action_audit_record(request_id.0)?.is_none());

        let second_server = tokio::spawn(accept_runtime_connection(
            listener.clone(),
            trust.clone(),
            runtime.clone(),
            store.clone(),
            request_policy,
        ));
        let mut reconnected = connect_test_client(address, client_config.clone()).await?;
        let first_response = send_action_and_close(&mut reconnected, &action).await?;
        assert_eq!(first_response.response.status, ActionStatus::Succeeded);
        first_response.response.validate()?;
        assert_eq!(
            first_response.response_digest,
            first_response.response.digest()?
        );
        let first_signature =
            ed25519_dalek::Signature::from_slice(first_response.node_signature.as_bytes())?;
        identity
            .verifying_key()
            .verify_strict(&first_response.response.signing_bytes()?, &first_signature)?;
        assert!(second_server.await?.is_ok());
        assert!(store.action_audit_record(request_id.0)?.is_some());

        let third_server = tokio::spawn(accept_runtime_connection(
            listener.clone(),
            trust.clone(),
            runtime.clone(),
            store.clone(),
            request_policy,
        ));
        let mut duplicate_connection = connect_test_client(address, client_config.clone()).await?;
        let duplicate_response = send_action_and_close(&mut duplicate_connection, &action).await?;
        assert_eq!(duplicate_response.response.status, ActionStatus::Duplicate);
        duplicate_response.response.validate()?;
        assert!(third_server.await?.is_ok());

        let lost_response_request_id = RequestId(Uuid::new_v4());
        let lost_response_action = signed_system_info_action(
            identity.node_id(),
            PairingId(trusted.pairing_id),
            "owner-peer-reconnect",
            &owner,
            &broker,
            UnixMillis(now),
            2,
            lost_response_request_id,
        )?;
        let fourth_server = tokio::spawn(accept_runtime_connection(
            listener.clone(),
            trust.clone(),
            runtime.clone(),
            store.clone(),
            request_policy,
        ));
        let mut lost_response_connection =
            connect_test_client(address, client_config.clone()).await?;
        send_action_without_reading_response(&mut lost_response_connection, &lost_response_action)
            .await?;
        drop(lost_response_connection);
        let _server_write_outcome =
            tokio::time::timeout(Duration::from_secs(2), fourth_server).await??;
        let completed_record = store
            .action_audit_record(lost_response_request_id.0)?
            .ok_or_else(|| std::io::Error::other("lost-response action was not recorded"))?;
        assert!(completed_record.execution_started_at_unix_ms.is_some());
        assert!(matches!(
            completed_record.terminal.as_ref().map(|value| value.status),
            Some(TerminalStatus::Succeeded)
        ));

        let fifth_server = tokio::spawn(accept_runtime_connection(
            listener.clone(),
            trust.clone(),
            runtime.clone(),
            store.clone(),
            request_policy,
        ));
        let mut lost_response_retry = connect_test_client(address, client_config.clone()).await?;
        let lost_response_duplicate =
            send_action_and_close(&mut lost_response_retry, &lost_response_action).await?;
        assert_eq!(
            lost_response_duplicate.response.status,
            ActionStatus::Duplicate
        );
        lost_response_duplicate.response.validate()?;
        assert!(fifth_server.await?.is_ok());
        assert_eq!(
            store.action_audit_record(lost_response_request_id.0)?,
            Some(completed_record)
        );

        let limited_request_id = RequestId(Uuid::new_v4());
        let limited_action = signed_system_info_action(
            identity.node_id(),
            PairingId(trusted.pairing_id),
            "owner-peer-reconnect",
            &owner,
            &broker,
            UnixMillis(now),
            3,
            limited_request_id,
        )?;
        for _ in 0..2 {
            let limited_server = tokio::spawn(accept_runtime_connection(
                listener.clone(),
                trust.clone(),
                runtime.clone(),
                store.clone(),
                request_policy,
            ));
            let mut limited_client = connect_test_client(address, client_config.clone()).await?;
            send_action_without_reading_response(&mut limited_client, &limited_action).await?;
            assert!(matches!(
                limited_server.await?,
                Err(TransportError::RateLimited {
                    scope: RequestLimitScope::Peer,
                    ..
                })
            ));
            assert!(store.action_audit_record(limited_request_id.0)?.is_none());
        }
        Ok(())
    }

    #[tokio::test]
    async fn credential_rotation_closes_old_session_and_rebinds_exact_leaf() -> TestResult {
        let pki = test_pki()?;
        let directory = tempfile::TempDir::new()?;
        let store = Arc::new(StateStore::open(directory.path().join("state.sqlite3"))?);
        let trusted = pair_transport_peer(&store, &pki, "peer-rotate", &pki.paired_client, 5)?;
        let old_trust = Arc::new(
            build_transport_trust(&server_identity(&pki), &store)?
                .ok_or_else(|| std::io::Error::other("transport trust missing"))?,
        );
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let address = listener.local_addr()?;
        let acceptor = TlsAcceptor::from(old_trust.tls.clone());
        let server_store = store.clone();
        let (session_ready, session_established) = tokio::sync::oneshot::channel();
        let server = tokio::spawn(async move {
            let (tcp, _) = listener.accept().await.map_err(TransportError::Io)?;
            let mut tls = acceptor.accept(tcp).await.map_err(TransportError::Io)?;
            let session = authenticated_session(&tls, &old_trust.session_by_leaf)
                .ok_or(TransportError::UnpairedClient)?;
            session_ready
                .send(())
                .map_err(|()| TransportError::RuntimeTask)?;
            read_frame_with_trust(&mut tls, &server_store, &session, 1024).await
        });

        let tcp = TcpStream::connect(address).await?;
        let connector = TlsConnector::from(client_config(&pki, Some(&pki.paired_client))?);
        let mut old_client = connector
            .connect(ServerName::try_from("localhost")?, tcp)
            .await?;
        session_established.await?;

        let mut rotated_material = decode_key_material(&trusted.public_key)?;
        let rotated_broker = SigningKey::generate(&mut OsRng);
        rotated_material.broker_public_key =
            PublicKeyBytes(rotated_broker.verifying_key().to_bytes());
        rotated_material.client_certificate_sha256 =
            Sha256Digest(Sha256::digest(pki.unpaired_client.certificate.as_ref()).into());
        let rotated = match store.rotate_peer_credential(
            &trusted.peer_id,
            sha256(&trusted.public_key),
            postcard::to_allocvec(&rotated_material)?,
            sha256(b"owner-approved-rotation"),
            current_time_millis()?,
        )? {
            CredentialRotationOutcome::Rotated(peer) => peer,
            CredentialRotationOutcome::AlreadyCurrent(_) => {
                return Err(std::io::Error::other("rotation was unexpectedly idempotent").into());
            }
        };
        assert_eq!(rotated.trust_epoch, trusted.trust_epoch + 1);

        let server_result = tokio::time::timeout(Duration::from_secs(2), server).await??;
        assert!(matches!(
            server_result,
            Err(TransportError::SessionTrustChanged)
        ));
        let mut byte = [0_u8; 1];
        let old_client_read =
            tokio::time::timeout(Duration::from_secs(2), old_client.read(&mut byte)).await?;
        assert!(matches!(old_client_read, Ok(0) | Err(_)));

        let refreshed = build_transport_trust(&server_identity(&pki), &store)?
            .ok_or_else(|| std::io::Error::other("refreshed transport trust missing"))?;
        assert_eq!(refreshed.session_by_leaf.len(), 1);
        let refreshed_tls = refreshed.tls.clone();
        let refreshed_sessions = refreshed.session_by_leaf.clone();
        let (old_reconnect, old_server) = connect_once(
            refreshed_tls.clone(),
            client_config(&pki, Some(&pki.paired_client))?,
            refreshed_sessions.clone(),
        )
        .await?;
        assert!(old_reconnect.is_ok());
        let (_, old_session) = old_server.map_err(std::io::Error::other)?;
        assert!(old_session.is_none());

        let (new_reconnect, new_server) = connect_once(
            refreshed_tls,
            client_config(&pki, Some(&pki.unpaired_client))?,
            refreshed_sessions,
        )
        .await?;
        assert!(new_reconnect.is_ok());
        let (version, new_session) = new_server.map_err(std::io::Error::other)?;
        assert_eq!(version, Some(ProtocolVersion::TLSv1_3));
        let new_session =
            new_session.ok_or_else(|| std::io::Error::other("rotated leaf was not bound"))?;
        assert_eq!(new_session.peer.peer_id, trusted.peer_id);
        assert_eq!(new_session.peer.trust_epoch, rotated.trust_epoch);
        assert_eq!(
            new_session.peer.certificate_sha256,
            rotated_material.client_certificate_sha256
        );
        Ok(())
    }

    #[tokio::test]
    async fn idle_tls_session_closes_promptly_after_revocation() -> TestResult {
        let pki = test_pki()?;
        let directory = tempfile::TempDir::new()?;
        let store = Arc::new(StateStore::open(directory.path().join("state.sqlite3"))?);
        let trusted = pair_transport_peer(&store, &pki, "peer-01", &pki.paired_client, 3)?;
        let trust = Arc::new(
            build_transport_trust(&server_identity(&pki), &store)?
                .ok_or_else(|| std::io::Error::other("transport trust missing"))?,
        );
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let address = listener.local_addr()?;
        let acceptor = TlsAcceptor::from(trust.tls.clone());
        let server_store = store.clone();
        let server = tokio::spawn(async move {
            let (tcp, _) = listener.accept().await.map_err(TransportError::Io)?;
            let mut tls = acceptor.accept(tcp).await.map_err(TransportError::Io)?;
            let session = authenticated_session(&tls, &trust.session_by_leaf)
                .ok_or(TransportError::UnpairedClient)?;
            read_frame_with_trust(&mut tls, &server_store, &session, 1024).await
        });

        let tcp = TcpStream::connect(address).await?;
        let connector = TlsConnector::from(client_config(&pki, Some(&pki.paired_client))?);
        let mut client = connector
            .connect(ServerName::try_from("localhost")?, tcp)
            .await?;
        assert!(matches!(
            store.revoke_peer(
                &trusted.peer_id,
                current_time_millis()?,
                sha256(b"owner"),
                sha256(b"revoked"),
            )?,
            RevocationOutcome::Revoked(_)
        ));

        let server_result = tokio::time::timeout(Duration::from_secs(2), server).await??;
        assert!(matches!(
            server_result,
            Err(TransportError::SessionTrustChanged)
        ));
        let mut byte = [0_u8; 1];
        let client_read =
            tokio::time::timeout(Duration::from_secs(2), client.read(&mut byte)).await?;
        assert!(matches!(client_read, Ok(0) | Err(_)));
        Ok(())
    }
}
