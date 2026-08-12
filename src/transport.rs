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
use crate::store::{StateStore, StoreError};

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
        let max_frame = config.policy.max_frame_bytes.min(MAX_WIRE_MESSAGE_BYTES);
        tokio::spawn(async move {
            let _permit = permit;
            let accepted = tokio::time::timeout(HANDSHAKE_TIMEOUT, acceptor.accept(stream)).await;
            let Ok(Ok(tls_stream)) = accepted else {
                return;
            };
            let Some(peer) = authenticated_peer(&tls_stream, &trust.peer_by_leaf) else {
                return;
            };
            let _ = serve_connection(tls_stream, peer, runtime, max_frame).await;
        });
    }
}

async fn serve_connection(
    mut stream: tokio_rustls::server::TlsStream<TcpStream>,
    peer: TransportPeer,
    runtime: Arc<NodeRuntime>,
    max_frame: usize,
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
    let client_verifier = WebPkiClientVerifier::builder(Arc::new(roots))
        .build()
        .map_err(|error| TransportError::Configuration(error.to_string()))?;
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let tls = ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .with_client_cert_verifier(client_verifier)
        .with_single_cert(certificate_chain, private_key)?;
    Ok(TransportTrust {
        tls: Arc::new(tls),
        peer_by_leaf,
    })
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
    use super::*;

    #[test]
    fn frame_size_constant_fits_u32_prefix() {
        assert!(MAX_WIRE_MESSAGE_BYTES < u32::MAX as usize);
    }
}
