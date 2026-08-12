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
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Semaphore;
use tokio_rustls::TlsAcceptor;

use crate::authz::TransportPeer;
use crate::config::NodeConfig;
use crate::pairing::decode_key_material;
use crate::protocol::{MAX_WIRE_MESSAGE_BYTES, Sha256Digest, SignedActionV1};
use crate::runtime::{NodeRuntime, RuntimeError};
use crate::security::SecureFileError;
use crate::store::{RemoteRequestAdmission, RequestLimitScope, StateStore, StoreError};

const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
const FRAME_TIMEOUT: Duration = Duration::from_secs(30);

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
}

#[derive(Debug)]
struct TransportTrust {
    tls: Arc<ServerConfig>,
    peer_by_leaf: HashMap<[u8; 32], String>,
}

pub async fn serve(
    config: Arc<NodeConfig>,
    store: Arc<StateStore>,
    runtime: Arc<NodeRuntime>,
) -> Result<(), TransportError> {
    let address = config.listen.ok_or(TransportError::Disabled)?;
    let trust = Arc::new(build_transport_trust(&config, &store)?);
    let acceptor = TlsAcceptor::from(trust.tls.clone());
    let listener = TcpListener::bind(address).await?;
    let max_connections = config
        .policy
        .queue_capacity
        .saturating_mul(2)
        .clamp(1, 8_192);
    let connections = Arc::new(Semaphore::new(max_connections));

    loop {
        let (stream, _) = listener.accept().await?;
        let Ok(permit) = connections.clone().try_acquire_owned() else {
            continue;
        };
        let acceptor = acceptor.clone();
        let trust = trust.clone();
        let runtime = runtime.clone();
        let store = store.clone();
        let max_frame = config.policy.max_frame_bytes.min(MAX_WIRE_MESSAGE_BYTES);
        let peer_maximum_per_minute = config.policy.max_requests_per_peer_per_minute;
        let global_maximum_per_minute = config.policy.max_requests_global_per_minute;
        tokio::spawn(async move {
            let _permit = permit;
            let accepted = tokio::time::timeout(HANDSHAKE_TIMEOUT, acceptor.accept(stream)).await;
            let Ok(Ok(tls_stream)) = accepted else {
                return;
            };
            let Some(peer) = authenticated_peer(&tls_stream, &trust.peer_by_leaf) else {
                return;
            };
            let _ = serve_connection(
                tls_stream,
                peer,
                runtime,
                store,
                max_frame,
                peer_maximum_per_minute,
                global_maximum_per_minute,
            )
            .await;
        });
    }
}

async fn serve_connection(
    mut stream: tokio_rustls::server::TlsStream<TcpStream>,
    peer: TransportPeer,
    runtime: Arc<NodeRuntime>,
    store: Arc<StateStore>,
    max_frame: usize,
    peer_maximum_per_minute: u32,
    global_maximum_per_minute: u32,
) -> Result<(), TransportError> {
    loop {
        let mut length_bytes = [0_u8; 4];
        match tokio::time::timeout(FRAME_TIMEOUT, stream.read_exact(&mut length_bytes)).await {
            Ok(Ok(_)) => {}
            Ok(Err(error))
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::UnexpectedEof
                        | std::io::ErrorKind::ConnectionReset
                        | std::io::ErrorKind::BrokenPipe
                ) =>
            {
                return Ok(());
            }
            Ok(Err(error)) => return Err(error.into()),
            Err(_) => return Err(TransportError::Frame),
        }
        let length =
            usize::try_from(u32::from_be_bytes(length_bytes)).map_err(|_| TransportError::Frame)?;
        if length == 0 || length > max_frame {
            return Err(TransportError::Frame);
        }
        let mut frame = vec![0_u8; length];
        tokio::time::timeout(FRAME_TIMEOUT, stream.read_exact(&mut frame))
            .await
            .map_err(|_| TransportError::Frame)??;
        let (action, remainder): (SignedActionV1, &[u8]) =
            postcard::take_from_bytes(&frame).map_err(|_| TransportError::Frame)?;
        if !remainder.is_empty() {
            return Err(TransportError::Frame);
        }
        match store.admit_remote_request(
            &peer.peer_id,
            peer_maximum_per_minute,
            global_maximum_per_minute,
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
        let response = runtime.handle(action, &peer).await?;
        let encoded = postcard::to_allocvec(&response).map_err(|_| TransportError::Frame)?;
        if encoded.len() > max_frame || encoded.len() > u32::MAX as usize {
            return Err(TransportError::Frame);
        }
        let encoded_length = u32::try_from(encoded.len()).map_err(|_| TransportError::Frame)?;
        tokio::time::timeout(FRAME_TIMEOUT, async {
            stream.write_all(&encoded_length.to_be_bytes()).await?;
            stream.write_all(&encoded).await?;
            stream.flush().await
        })
        .await
        .map_err(|_| TransportError::Frame)??;
    }
}

fn build_transport_trust(
    config: &NodeConfig,
    store: &StateStore,
) -> Result<TransportTrust, TransportError> {
    let tls = config.tls.as_ref().ok_or_else(|| {
        TransportError::Configuration("TLS is mandatory for a LAN listener".to_owned())
    })?;
    let certificate_chain = load_certificates(&tls.certificate_pem)?;
    let private_key = load_private_key(&tls.private_key_pem)?;

    let now = crate::authz::SystemClock;
    let now = crate::authz::Clock::now(&now)
        .map_err(|_| TransportError::Configuration("system clock is invalid".to_owned()))?;
    let now = i64::try_from(now.0)
        .map_err(|_| TransportError::Configuration("system clock is invalid".to_owned()))?;
    let peers = store.currently_trusted_peers(now)?;
    if peers.is_empty() {
        return Err(TransportError::Configuration(
            "at least one current, owner-approved pairing is required before listening".to_owned(),
        ));
    }

    let mut roots = RootCertStore::empty();
    let mut peer_by_leaf = HashMap::new();
    for peer in peers {
        let material = decode_key_material(&peer.public_key)
            .map_err(|_| TransportError::Configuration("stored pairing is invalid".to_owned()))?;
        roots.add(CertificateDer::from(material.client_ca_der))?;
        if peer_by_leaf
            .insert(material.client_certificate_sha256.0, peer.peer_id)
            .is_some()
        {
            return Err(TransportError::Configuration(
                "two active pairings reuse the same client certificate".to_owned(),
            ));
        }
    }
    let tls = tls13_server_config(certificate_chain, private_key, roots)?;
    Ok(TransportTrust {
        tls: Arc::new(tls),
        peer_by_leaf,
    })
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

fn authenticated_peer(
    stream: &tokio_rustls::server::TlsStream<TcpStream>,
    peer_by_leaf: &HashMap<[u8; 32], String>,
) -> Option<TransportPeer> {
    let certificates = stream.get_ref().1.peer_certificates()?;
    let leaf = certificates.first()?;
    let digest: [u8; 32] = Sha256::digest(leaf.as_ref()).into();
    let peer_id = peer_by_leaf.get(&digest)?.clone();
    Some(TransportPeer {
        peer_id,
        certificate_sha256: Sha256Digest(digest),
    })
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

    use rcgen::{
        BasicConstraints, CertificateParams, ExtendedKeyUsagePurpose, IsCa, Issuer, KeyPair,
        KeyUsagePurpose,
    };
    use rustls::{ClientConfig, ProtocolVersion};
    use rustls_pki_types::{PrivatePkcs8KeyDer, ServerName};
    use tokio_rustls::TlsConnector;

    use super::*;

    type TestResult<T = ()> = Result<T, Box<dyn Error + Send + Sync>>;

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
        peer_by_leaf: HashMap<[u8; 32], String>,
    ) -> TestResult<(
        Result<(), std::io::Error>,
        Result<(Option<ProtocolVersion>, Option<TransportPeer>), String>,
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
            let peer = authenticated_peer(&tls, &peer_by_leaf);
            Ok::<_, String>((version, peer))
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

    #[test]
    fn frame_size_constant_fits_u32_prefix() {
        assert!(MAX_WIRE_MESSAGE_BYTES < u32::MAX as usize);
    }

    #[tokio::test]
    async fn mutual_tls_is_tls13_only_and_requires_the_paired_leaf() -> TestResult {
        let pki = test_pki()?;
        let paired_digest: [u8; 32] = Sha256::digest(pki.paired_client.certificate.as_ref()).into();
        let peer_by_leaf = HashMap::from([(paired_digest, "peer-01".to_owned())]);

        let (client, server) = connect_once(
            server_config(&pki)?,
            client_config(&pki, Some(&pki.paired_client))?,
            peer_by_leaf.clone(),
        )
        .await?;
        assert!(client.is_ok());
        let (version, peer) = server.map_err(std::io::Error::other)?;
        assert_eq!(version, Some(ProtocolVersion::TLSv1_3));
        assert_eq!(peer.map(|value| value.peer_id), Some("peer-01".to_owned()));

        let (client, server) = connect_once(
            server_config(&pki)?,
            client_config(&pki, Some(&pki.unpaired_client))?,
            peer_by_leaf.clone(),
        )
        .await?;
        assert!(client.is_ok());
        let (_, peer) = server.map_err(std::io::Error::other)?;
        assert!(peer.is_none());

        let (_client, server) = connect_once(
            server_config(&pki)?,
            client_config(&pki, None)?,
            peer_by_leaf,
        )
        .await?;
        assert!(server.is_err());
        Ok(())
    }
}
