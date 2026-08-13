use std::error::Error;
use std::fs;
use std::io;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use ed25519_dalek::{Signer, SigningKey};
use rcgen::{
    BasicConstraints, CertificateParams, ExtendedKeyUsagePurpose, IsCa, Issuer, KeyPair,
    KeyUsagePurpose,
};
use sovereign_node::authz::{
    AuthorizationEngine, AuthorizationError, AuthorizationOutcome, Clock, TransportPeer,
};
use sovereign_node::capabilities::{CapabilityError, CapabilityExecutor};
use sovereign_node::config::{
    HealthConfig, NodeConfig, PolicyConfig, ProcessReportingConfig, ProcessSnapshotConfig,
    ReadRootConfig, RepositoryReportingConfig, RepositorySnapshotConfig, ResourceReportingConfig,
    ServiceReportingConfig, ServiceSnapshotConfig,
};
use sovereign_node::identity::{NodeIdentity, key_id};
use sovereign_node::pairing::{
    CredentialRotationDisplay, CredentialRotationProof, CredentialRotationRequest, PairingDisplay,
    PairingError, PairingKeyMaterialV1, PairingManager, PairingProof, PairingRecoveryDisplay,
    PairingRecoveryProof, PairingRecoveryRequest, PairingRequest, TrustReceiptKind,
};
use sovereign_node::process_status::{
    ProcessStateV1, ProcessStatusEntryV1, ProcessStatusSnapshotV1, SignedProcessStatusSnapshotV1,
    process_status_snapshot_signing_bytes,
};
use sovereign_node::protocol::{
    ActionArguments, ActionErrorCode, ActionRequestV1, ActionResultV1, ActionTarget, AgentId,
    AuthorityKind, AuthorizationClaimsV1, AuthorizationId, Capability, NodeId, Nonce, PairingId,
    PublicKeyBytes, ReplayProtectionV1, RepositoryStatusV1, RequestId, Sha256Digest,
    SignatureBytes, SignedActionV1, TaskId, TrustStatus, UnixMillis, UserAuthorityV1,
    ValidationError,
};
use sovereign_node::repository_status::{
    RepositoryStatusEntryV1, RepositoryStatusSnapshotV1, SignedRepositoryStatusSnapshotV1,
    repository_status_snapshot_signing_bytes,
};
use sovereign_node::resources::{QueueSnapshot, ResourceReporter};
use sovereign_node::service_status::{
    ServiceStateV1, ServiceStatusEntryV1, ServiceStatusSnapshotV1, SignedServiceStatusSnapshotV1,
    service_status_snapshot_signing_bytes,
};
use sovereign_node::store::{RevocationOutcome, StateStore, StoreError, StoreLimits, sha256};
use tempfile::TempDir;
use uuid::Uuid;

type TestResult<T = ()> = Result<T, Box<dyn Error>>;

const NOW: u64 = 2_000_000_000_000;
const PEER_ID: &str = "owner-action-broker";
const OWNER_ID: &str = "owner-1";
const TEST_POLICY_DIGEST: Sha256Digest = Sha256Digest([0x55; 32]);

#[derive(Debug)]
struct ManualClock {
    now: AtomicU64,
}

impl ManualClock {
    fn new(now: u64) -> Self {
        Self {
            now: AtomicU64::new(now),
        }
    }

    fn set(&self, now: u64) {
        self.now.store(now, Ordering::SeqCst);
    }
}

impl Clock for ManualClock {
    fn now(&self) -> Result<UnixMillis, AuthorizationError> {
        Ok(UnixMillis(self.now.load(Ordering::SeqCst)))
    }
}

struct Harness {
    _directory: TempDir,
    identity_directory: std::path::PathBuf,
    database_path: std::path::PathBuf,
    identity: Arc<NodeIdentity>,
    store: Arc<StateStore>,
    owner_key: SigningKey,
    broker_key: SigningKey,
    material: PairingKeyMaterialV1,
    client_certificate_chain_der: Vec<Vec<u8>>,
    pairing_id: PairingId,
    clock: Arc<ManualClock>,
}

impl Harness {
    fn new() -> TestResult<Self> {
        Self::with_limits(StoreLimits::default())
    }

    fn with_limits(limits: StoreLimits) -> TestResult<Self> {
        Self::with_limits_and_capabilities(
            limits,
            &[
                Capability::SystemInfo,
                Capability::ResourceStatus,
                Capability::FileRead,
            ],
        )
    }

    fn with_capabilities(capabilities: &[Capability]) -> TestResult<Self> {
        Self::with_limits_and_capabilities(StoreLimits::default(), capabilities)
    }

    fn with_limits_and_capabilities(
        limits: StoreLimits,
        capabilities: &[Capability],
    ) -> TestResult<Self> {
        let directory = TempDir::new()?;
        let identity_directory = directory.path().join("identity");
        let database_path = directory.path().join("state.sqlite3");
        let (identity, created) = NodeIdentity::load_or_initialize(
            &identity_directory,
            "integration-test-node",
            UnixMillis(NOW),
        )?;
        assert!(created);
        let identity = Arc::new(identity);
        let store = Arc::new(StateStore::open_with_limits(&database_path, limits)?);
        store.activate_policy(1, TEST_POLICY_DIGEST.0, NOW as i64)?;
        let owner_key = SigningKey::from_bytes(&[0x11; 32]);
        let broker_key = SigningKey::from_bytes(&[0x22; 32]);
        let (mut material, client_certificate_chain_der) =
            key_material(&owner_key, &broker_key, ExtendedKeyUsagePurpose::ClientAuth)?;
        material.allowed_capabilities = capabilities.to_vec();
        let manager = PairingManager::new(
            Arc::clone(&identity),
            Arc::clone(&store),
            capabilities.iter().copied(),
        );
        let display = manager.begin(
            pairing_request(material.clone(), client_certificate_chain_der.clone()),
            UnixMillis(NOW),
        )?;
        let proof = proof_for(&display, &owner_key, &broker_key, UnixMillis(NOW + 1))?;
        let approved = manager.approve_local(&proof, true)?;
        assert_eq!(approved.trusted_peer.trust_epoch, 1);

        Ok(Self {
            _directory: directory,
            identity_directory,
            database_path,
            identity,
            store,
            owner_key,
            broker_key,
            material,
            client_certificate_chain_der,
            pairing_id: PairingId(approved.trusted_peer.pairing_id),
            clock: Arc::new(ManualClock::new(NOW + 10)),
        })
    }

    fn engine(&self) -> AuthorizationEngine {
        self.engine_for(&[
            Capability::SystemInfo,
            Capability::ResourceStatus,
            Capability::FileRead,
        ])
    }

    fn engine_for(&self, capabilities: &[Capability]) -> AuthorizationEngine {
        let policy = PolicyConfig {
            enabled_capabilities: capabilities.to_vec(),
            ..PolicyConfig::default()
        };
        AuthorizationEngine::new(
            self.identity.node_id(),
            Arc::clone(&self.store),
            self.clock.clone(),
            &policy,
            1,
            TEST_POLICY_DIGEST,
        )
    }

    fn transport_peer(&self) -> TransportPeer {
        TransportPeer {
            peer_id: PEER_ID.to_owned(),
            certificate_sha256: self.material.client_certificate_sha256,
            trust_epoch: 1,
        }
    }

    fn system_info_action(&self, request_seed: u128, sequence: u64) -> TestResult<SignedActionV1> {
        signed_action(ActionSpec {
            request_seed,
            sequence,
            node_id: self.identity.node_id(),
            pairing_id: self.pairing_id,
            trust_epoch: 1,
            owner_id: OWNER_ID,
            target: ActionTarget::Node,
            arguments: ActionArguments::SystemInfo,
            issued_at: NOW,
            not_before: NOW,
            expires_at: NOW + 60_000,
            owner_key: &self.owner_key,
            broker_key: &self.broker_key,
        })
    }
}

struct ActionSpec<'a> {
    request_seed: u128,
    sequence: u64,
    node_id: NodeId,
    pairing_id: PairingId,
    trust_epoch: u64,
    owner_id: &'a str,
    target: ActionTarget,
    arguments: ActionArguments,
    issued_at: u64,
    not_before: u64,
    expires_at: u64,
    owner_key: &'a SigningKey,
    broker_key: &'a SigningKey,
}

fn key_material(
    owner_key: &SigningKey,
    broker_key: &SigningKey,
    extended_usage: ExtendedKeyUsagePurpose,
) -> TestResult<(PairingKeyMaterialV1, Vec<Vec<u8>>)> {
    key_material_with_validity(owner_key, broker_key, extended_usage, None)
}

fn key_material_with_validity(
    owner_key: &SigningKey,
    broker_key: &SigningKey,
    extended_usage: ExtendedKeyUsagePurpose,
    leaf_validity_unix_seconds: Option<(i64, i64)>,
) -> TestResult<(PairingKeyMaterialV1, Vec<Vec<u8>>)> {
    key_material_with_options(
        owner_key,
        broker_key,
        extended_usage,
        leaf_validity_unix_seconds,
        true,
    )
}

fn key_material_with_options(
    owner_key: &SigningKey,
    broker_key: &SigningKey,
    extended_usage: ExtendedKeyUsagePurpose,
    leaf_validity_unix_seconds: Option<(i64, i64)>,
    include_leaf_key_usage: bool,
) -> TestResult<(PairingKeyMaterialV1, Vec<Vec<u8>>)> {
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
    let mut leaf_params = CertificateParams::new(vec!["paired-client".to_owned()])?;
    if let Some((not_before, not_after)) = leaf_validity_unix_seconds {
        leaf_params.not_before = time::OffsetDateTime::from_unix_timestamp(not_before)?;
        leaf_params.not_after = time::OffsetDateTime::from_unix_timestamp(not_after)?;
    }
    if include_leaf_key_usage {
        leaf_params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    }
    leaf_params.extended_key_usages = vec![extended_usage];
    leaf_params.use_authority_key_identifier_extension = true;
    let leaf_key = KeyPair::generate()?;
    let leaf_certificate = leaf_params.signed_by(&leaf_key, &issuer)?;
    let client_ca_der = ca_certificate.der().as_ref().to_vec();
    let client_leaf_der = leaf_certificate.der().as_ref().to_vec();
    let material = PairingKeyMaterialV1 {
        schema_version: 1,
        owner_id: OWNER_ID.to_owned(),
        owner_public_key: PublicKeyBytes(owner_key.verifying_key().to_bytes()),
        broker_public_key: PublicKeyBytes(broker_key.verifying_key().to_bytes()),
        client_ca_der,
        client_certificate_sha256: Sha256Digest(sha256(&client_leaf_der)),
        allowed_capabilities: vec![
            Capability::SystemInfo,
            Capability::ResourceStatus,
            Capability::FileRead,
        ],
        trust_expires_at: None,
    };
    Ok((material, vec![client_leaf_der]))
}

fn key_material_with_intermediate(
    owner_key: &SigningKey,
    broker_key: &SigningKey,
) -> TestResult<(PairingKeyMaterialV1, Vec<Vec<u8>>)> {
    let mut root_params = CertificateParams::new(Vec::<String>::new())?;
    root_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    root_params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    let root_key = KeyPair::generate()?;
    let root_certificate = root_params.self_signed(&root_key)?;
    let root_issuer = Issuer::new(root_params, root_key);

    let mut intermediate_params = CertificateParams::new(Vec::<String>::new())?;
    intermediate_params.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
    intermediate_params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    intermediate_params.use_authority_key_identifier_extension = true;
    let intermediate_key = KeyPair::generate()?;
    let intermediate_certificate =
        intermediate_params.signed_by(&intermediate_key, &root_issuer)?;
    let intermediate_issuer = Issuer::new(intermediate_params, intermediate_key);

    let mut leaf_params = CertificateParams::new(vec!["intermediate-client".to_owned()])?;
    leaf_params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    leaf_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
    leaf_params.use_authority_key_identifier_extension = true;
    let leaf_key = KeyPair::generate()?;
    let leaf_certificate = leaf_params.signed_by(&leaf_key, &intermediate_issuer)?;
    let leaf_der = leaf_certificate.der().as_ref().to_vec();
    Ok((
        PairingKeyMaterialV1 {
            schema_version: 1,
            owner_id: OWNER_ID.to_owned(),
            owner_public_key: PublicKeyBytes(owner_key.verifying_key().to_bytes()),
            broker_public_key: PublicKeyBytes(broker_key.verifying_key().to_bytes()),
            client_ca_der: root_certificate.der().as_ref().to_vec(),
            client_certificate_sha256: Sha256Digest(sha256(&leaf_der)),
            allowed_capabilities: vec![Capability::SystemInfo],
            trust_expires_at: None,
        },
        vec![leaf_der, intermediate_certificate.der().as_ref().to_vec()],
    ))
}

fn pairing_request(
    material: PairingKeyMaterialV1,
    client_certificate_chain_der: Vec<Vec<u8>>,
) -> PairingRequest {
    PairingRequest {
        peer_id: PEER_ID.to_owned(),
        device_label: "Owner Action Broker".to_owned(),
        key_material: material,
        client_certificate_chain_der,
        ttl_millis: 60_000,
    }
}

fn proof_for(
    display: &PairingDisplay,
    owner_key: &SigningKey,
    broker_key: &SigningKey,
    approved_at: UnixMillis,
) -> TestResult<PairingProof> {
    let challenge_secret = decode_fixed::<32>(&display.challenge_hex)?;
    let proof_payload = hex::decode(&display.proof_payload_hex)?;
    Ok(PairingProof {
        pairing_id: display.pairing_id,
        challenge_secret,
        owner_signature: signature_bytes(&owner_key.sign(&proof_payload))?,
        broker_signature: signature_bytes(&broker_key.sign(&proof_payload))?,
        approved_at,
    })
}

fn rotation_proof_for(
    display: &CredentialRotationDisplay,
    current_owner: &SigningKey,
    current_broker: &SigningKey,
    next_owner: &SigningKey,
    next_broker: &SigningKey,
    approved_at: UnixMillis,
) -> TestResult<CredentialRotationProof> {
    let challenge_secret = decode_fixed::<32>(&display.challenge_hex)?;
    let payload = hex::decode(&display.proof_payload_hex)?;
    Ok(CredentialRotationProof {
        rotation_id: display.rotation_id,
        challenge_secret,
        current_owner_signature: signature_bytes(&current_owner.sign(&payload))?,
        current_broker_signature: signature_bytes(&current_broker.sign(&payload))?,
        next_owner_signature: signature_bytes(&next_owner.sign(&payload))?,
        next_broker_signature: signature_bytes(&next_broker.sign(&payload))?,
        approved_at,
    })
}

fn recovery_proof_for(
    display: &PairingRecoveryDisplay,
    next_owner: &SigningKey,
    next_broker: &SigningKey,
    approved_at: UnixMillis,
) -> TestResult<PairingRecoveryProof> {
    let challenge_secret = decode_fixed::<32>(&display.challenge_hex)?;
    let payload = hex::decode(&display.proof_payload_hex)?;
    Ok(PairingRecoveryProof {
        recovery_id: display.recovery_id,
        challenge_secret,
        next_owner_signature: signature_bytes(&next_owner.sign(&payload))?,
        next_broker_signature: signature_bytes(&next_broker.sign(&payload))?,
        approved_at,
    })
}

fn signed_action(spec: ActionSpec<'_>) -> TestResult<SignedActionV1> {
    let request_id = RequestId(non_nil_uuid(spec.request_seed));
    let request = ActionRequestV1::new(
        request_id,
        TaskId(non_nil_uuid(spec.request_seed.saturating_add(1))),
        AgentId(non_nil_uuid(spec.request_seed.saturating_add(2))),
        UserAuthorityV1 {
            authority_id: AuthorizationId(non_nil_uuid(spec.request_seed.saturating_add(3))),
            owner_id: spec.owner_id.to_owned(),
            kind: AuthorityKind::OwnerInteractive,
            approval_reason: Some("owner-approved integration action".to_owned()),
        },
        spec.node_id,
        spec.target,
        spec.arguments,
        UnixMillis(spec.issued_at),
        UnixMillis(spec.not_before),
        UnixMillis(spec.expires_at),
        ReplayProtectionV1 {
            nonce: Nonce(sha256(&spec.request_seed.to_be_bytes())),
            sequence: spec.sequence,
        },
        AuthorizationClaimsV1 {
            authorization_id: AuthorizationId(non_nil_uuid(spec.request_seed.saturating_add(4))),
            pairing_id: spec.pairing_id,
            trust_epoch: spec.trust_epoch,
            policy_version: 1,
            permitted_capability: Capability::SystemInfo,
            permitted_target_digest: Sha256Digest([0; 32]),
            owner_key_id: key_id(&spec.owner_key.verifying_key()),
            broker_key_id: key_id(&spec.broker_key.verifying_key()),
        },
    )?;
    sign_request(request, spec.owner_key, spec.broker_key)
}

fn sign_request(
    request: ActionRequestV1,
    owner_key: &SigningKey,
    broker_key: &SigningKey,
) -> TestResult<SignedActionV1> {
    let owner_signature = signature_bytes(&owner_key.sign(&request.owner_signing_bytes()?))?;
    let mut signed = SignedActionV1 {
        request,
        owner_signature,
        broker_signature: signature_bytes(&broker_key.sign(b"placeholder"))?,
    };
    signed.broker_signature = signature_bytes(&broker_key.sign(&signed.broker_signing_bytes()?))?;
    Ok(signed)
}

fn signature_bytes(signature: &ed25519_dalek::Signature) -> TestResult<SignatureBytes> {
    Ok(SignatureBytes::from_slice(&signature.to_bytes())?)
}

fn decode_fixed<const SIZE: usize>(encoded: &str) -> TestResult<[u8; SIZE]> {
    let bytes = hex::decode(encoded)?;
    bytes
        .try_into()
        .map_err(|_| test_error("hex value had an unexpected length"))
}

fn non_nil_uuid(value: u128) -> Uuid {
    Uuid::from_u128(value.max(1))
}

fn test_error(message: &'static str) -> Box<dyn Error> {
    Box::new(io::Error::other(message))
}

#[test]
fn pairing_requires_local_approval_and_both_key_proofs() -> TestResult {
    let directory = TempDir::new()?;
    let (identity, _) = NodeIdentity::load_or_initialize(
        &directory.path().join("identity"),
        "pairing-test-node",
        UnixMillis(NOW),
    )?;
    let identity = Arc::new(identity);
    let store = Arc::new(StateStore::open(directory.path().join("state.sqlite3"))?);
    let owner_key = SigningKey::from_bytes(&[0x11; 32]);
    let broker_key = SigningKey::from_bytes(&[0x22; 32]);
    let attacker_key = SigningKey::from_bytes(&[0x33; 32]);
    let manager = PairingManager::new(
        Arc::clone(&identity),
        Arc::clone(&store),
        [Capability::SystemInfo],
    );
    let (mut material, client_certificate_chain_der) =
        key_material(&owner_key, &broker_key, ExtendedKeyUsagePurpose::ClientAuth)?;
    material.allowed_capabilities = vec![Capability::SystemInfo];
    let display = manager.begin(
        pairing_request(material, client_certificate_chain_der),
        UnixMillis(NOW),
    )?;
    assert_eq!(display.node_id, identity.node_id().to_string());
    assert_eq!(display.node_identity_fingerprint, identity.fingerprint());
    assert_eq!(display.peer_id, PEER_ID);
    let proof = proof_for(&display, &owner_key, &broker_key, UnixMillis(NOW + 1))?;

    assert!(matches!(
        manager.approve_local(&proof, false),
        Err(PairingError::OwnerConfirmationRequired)
    ));
    assert!(
        store
            .currently_trusted_peer(PEER_ID, NOW as i64 + 1)?
            .is_none()
    );

    let payload = hex::decode(&display.proof_payload_hex)?;
    let mut forged_owner = proof.clone();
    forged_owner.owner_signature = signature_bytes(&attacker_key.sign(&payload))?;
    assert!(matches!(
        manager.approve_local(&forged_owner, true),
        Err(PairingError::InvalidProof)
    ));

    let mut forged_broker = proof.clone();
    forged_broker.broker_signature = signature_bytes(&attacker_key.sign(&payload))?;
    assert!(matches!(
        manager.approve_local(&forged_broker, true),
        Err(PairingError::InvalidProof)
    ));
    assert!(
        store
            .currently_trusted_peer(PEER_ID, NOW as i64 + 1)?
            .is_none()
    );

    let approved = manager.approve_local(&proof, true)?;
    let trusted = &approved.trusted_peer;
    assert_eq!(trusted.peer_id, PEER_ID);
    assert_eq!(trusted.node_id, identity.node_id().to_string());
    assert_eq!(trusted.trust_epoch, 1);
    assert_eq!(
        approved.receipt.receipt.kind,
        TrustReceiptKind::InitialPairing
    );
    assert_eq!(approved.receipt.receipt.trust_epoch, 1);
    approved.receipt.verify()?;
    let node_key = PublicKeyBytes(decode_fixed::<32>(&display.node_public_key_hex)?);
    let node_signature = SignatureBytes::from_slice(&hex::decode(&display.node_signature_hex)?)?;
    sovereign_node::pairing::verify_node_proof(
        node_key,
        &hex::decode(&display.proof_payload_hex)?,
        &node_signature,
    )?;
    assert!(
        store
            .currently_trusted_peer(PEER_ID, NOW as i64 + 2)?
            .is_some()
    );
    Ok(())
}

#[test]
fn pairing_rejects_invalid_client_certificate_bindings() -> TestResult {
    let directory = TempDir::new()?;
    let (identity, _) = NodeIdentity::load_or_initialize(
        &directory.path().join("identity"),
        "certificate-validation-node",
        UnixMillis(NOW),
    )?;
    let store = Arc::new(StateStore::open(directory.path().join("state.sqlite3"))?);
    let manager = PairingManager::new(
        Arc::new(identity),
        Arc::clone(&store),
        [Capability::SystemInfo],
    );
    let owner = SigningKey::from_bytes(&[0x41; 32]);
    let broker = SigningKey::from_bytes(&[0x42; 32]);
    let (mut valid_material, valid_chain) =
        key_material(&owner, &broker, ExtendedKeyUsagePurpose::ClientAuth)?;
    valid_material.allowed_capabilities = vec![Capability::SystemInfo];

    let mut digest_mismatch = valid_chain.clone();
    digest_mismatch[0].push(0);
    assert!(matches!(
        manager.begin(
            pairing_request(valid_material.clone(), digest_mismatch),
            UnixMillis(NOW)
        ),
        Err(PairingError::Invalid(_))
    ));

    let (mut other_material, other_chain) =
        key_material(&owner, &broker, ExtendedKeyUsagePurpose::ClientAuth)?;
    other_material.allowed_capabilities = vec![Capability::SystemInfo];
    let mut wrong_issuer = valid_material.clone();
    wrong_issuer.client_certificate_sha256 = other_material.client_certificate_sha256;
    assert!(matches!(
        manager.begin(pairing_request(wrong_issuer, other_chain), UnixMillis(NOW)),
        Err(PairingError::Invalid(_))
    ));

    let (mut server_only, server_chain) =
        key_material(&owner, &broker, ExtendedKeyUsagePurpose::ServerAuth)?;
    server_only.allowed_capabilities = vec![Capability::SystemInfo];
    assert!(matches!(
        manager.begin(pairing_request(server_only, server_chain), UnixMillis(NOW)),
        Err(PairingError::Invalid(_))
    ));

    let (mut no_signing_usage, no_signing_usage_chain) = key_material_with_options(
        &owner,
        &broker,
        ExtendedKeyUsagePurpose::ClientAuth,
        None,
        false,
    )?;
    no_signing_usage.allowed_capabilities = vec![Capability::SystemInfo];
    assert!(matches!(
        manager.begin(
            pairing_request(no_signing_usage, no_signing_usage_chain),
            UnixMillis(NOW)
        ),
        Err(PairingError::Invalid(_))
    ));

    let mut non_ca = valid_material.clone();
    non_ca.client_ca_der = valid_chain[0].clone();
    assert!(matches!(
        manager.begin(
            pairing_request(non_ca, valid_chain.clone()),
            UnixMillis(NOW)
        ),
        Err(PairingError::Invalid(_))
    ));

    let mut malformed = valid_material.clone();
    malformed.client_certificate_sha256 = Sha256Digest(sha256(b"not-der"));
    assert!(matches!(
        manager.begin(
            pairing_request(malformed, vec![b"not-der".to_vec()]),
            UnixMillis(NOW)
        ),
        Err(PairingError::Invalid(_))
    ));

    let now_seconds = i64::try_from(NOW / 1_000)?;
    let (mut expired, expired_chain) = key_material_with_validity(
        &owner,
        &broker,
        ExtendedKeyUsagePurpose::ClientAuth,
        Some((now_seconds - 100, now_seconds - 1)),
    )?;
    expired.allowed_capabilities = vec![Capability::SystemInfo];
    assert!(matches!(
        manager.begin(pairing_request(expired, expired_chain), UnixMillis(NOW)),
        Err(PairingError::Invalid(_))
    ));

    let (intermediate_material, intermediate_chain) =
        key_material_with_intermediate(&owner, &broker)?;
    assert!(
        manager
            .begin(
                pairing_request(intermediate_material, intermediate_chain),
                UnixMillis(NOW)
            )
            .is_ok()
    );

    let (mut short_lived, short_lived_chain) = key_material_with_validity(
        &owner,
        &broker,
        ExtendedKeyUsagePurpose::ClientAuth,
        Some((now_seconds - 100, now_seconds + 10)),
    )?;
    short_lived.allowed_capabilities = vec![Capability::SystemInfo];
    let display = manager.begin(
        pairing_request(short_lived, short_lived_chain),
        UnixMillis(NOW),
    )?;
    let proof = proof_for(&display, &owner, &broker, UnixMillis(NOW + 11_000))?;
    assert!(matches!(
        manager.approve_local(&proof, true),
        Err(PairingError::Invalid(_))
    ));
    assert!(
        store
            .currently_trusted_peer(PEER_ID, NOW as i64 + 11_000)?
            .is_none()
    );
    Ok(())
}

#[test]
fn forged_authorizations_do_not_consume_the_request_id() -> TestResult {
    let harness = Harness::new()?;
    let engine = harness.engine();
    let transport = harness.transport_peer();
    let valid = harness.system_info_action(100, 1)?;
    let attacker_key = SigningKey::from_bytes(&[0x77; 32]);

    let mut forged_owner = valid.clone();
    forged_owner.owner_signature =
        signature_bytes(&attacker_key.sign(&forged_owner.request.owner_signing_bytes()?))?;
    assert!(matches!(
        engine.verify_and_reserve(forged_owner, &transport),
        Err(AuthorizationError::Forged)
    ));

    let mut forged_broker = valid.clone();
    forged_broker.broker_signature =
        signature_bytes(&attacker_key.sign(&forged_broker.broker_signing_bytes()?))?;
    assert!(matches!(
        engine.verify_and_reserve(forged_broker, &transport),
        Err(AuthorizationError::Forged)
    ));

    assert!(matches!(
        engine.verify_and_reserve(valid, &transport)?,
        AuthorizationOutcome::Fresh(_)
    ));
    Ok(())
}

#[test]
fn authorized_action_persists_only_redacted_audit_context() -> TestResult {
    let harness = Harness::new()?;
    let action = harness.system_info_action(101, 2)?;
    let request_id = action.request.request_id.0;
    let task_id = action.request.task_id.0;
    let agent_digest = sha256(action.request.agent_id.to_string().as_bytes());
    let authority_digest = sha256(action.request.user_authority.authority_id.0.as_bytes());
    let owner_digest = sha256(action.request.user_authority.owner_id.as_bytes());
    let raw_approval_reason = action
        .request
        .user_authority
        .approval_reason
        .clone()
        .ok_or_else(|| test_error("approval reason is missing"))?;
    assert!(matches!(
        harness
            .engine()
            .verify_and_reserve(action, &harness.transport_peer())?,
        AuthorizationOutcome::Fresh(_)
    ));

    let record = harness
        .store
        .action_audit_record(request_id)?
        .ok_or_else(|| test_error("action audit context is missing"))?;
    assert_eq!(record.context.request_id, request_id);
    assert_eq!(record.context.task_id, task_id);
    assert_eq!(record.context.agent_id_digest, agent_digest);
    assert_eq!(record.context.authority_id_digest, authority_digest);
    assert_eq!(record.context.owner_id_digest, owner_digest);
    assert_eq!(record.context.capability, "SystemInfo");
    assert_eq!(record.execution_started_at_unix_ms, None);
    assert_eq!(record.terminal, None);
    let debug = format!("{:?}", record.context);
    assert!(!debug.contains(OWNER_ID));
    assert!(!debug.contains(&raw_approval_reason));
    Ok(())
}

#[test]
fn material_clock_rollback_denies_authorization_without_consuming_request_id() -> TestResult {
    let harness = Harness::new()?;
    let engine = harness.engine();
    let transport = harness.transport_peer();
    harness.clock.set(NOW + 20_000);
    assert!(matches!(
        engine.verify_and_reserve(harness.system_info_action(150, 5)?, &transport)?,
        AuthorizationOutcome::Fresh(_)
    ));

    let retryable = harness.system_info_action(151, 6)?;
    harness.clock.set(NOW + 14_999);
    let rollback = match engine.verify_and_reserve(retryable.clone(), &transport) {
        Err(error) => error,
        Ok(_) => return Err("rollback beyond the five-second policy was accepted".into()),
    };
    assert_eq!(rollback.code(), ActionErrorCode::ClockRollback);

    harness.clock.set(NOW + 15_000);
    assert!(matches!(
        engine.verify_and_reserve(retryable, &transport)?,
        AuthorizationOutcome::Fresh(_)
    ));
    Ok(())
}

#[tokio::test]
async fn process_status_uses_signed_logical_identity_and_denies_raw_pid() -> TestResult {
    let harness = Harness::with_capabilities(&[Capability::ProcessStatus])?;
    let process_key = SigningKey::from_bytes(&[0x44; 32]);
    let snapshot = ProcessStatusSnapshotV1 {
        schema_version: 1,
        observed_at_unix_ms: NOW,
        valid_until_unix_ms: NOW + 30_000,
        processes: vec![ProcessStatusEntryV1 {
            process_id: "model-engine".to_owned(),
            state: ProcessStateV1::Running,
            detail_code: Some("ready".to_owned()),
        }],
    };
    let payload = serde_json::to_vec(&snapshot)?;
    let signature = process_key.sign(&process_status_snapshot_signing_bytes(&payload));
    let signed_snapshot = SignedProcessStatusSnapshotV1 {
        payload_hex: hex::encode(payload),
        signature_hex: hex::encode(signature.to_bytes()),
    };
    let snapshot_path = harness._directory.path().join("process-status.json");
    fs::write(&snapshot_path, serde_json::to_vec(&signed_snapshot)?)?;
    let policy = PolicyConfig {
        enabled_capabilities: vec![Capability::ProcessStatus],
        ..PolicyConfig::default()
    };
    let config = Arc::new(NodeConfig {
        data_dir: harness.identity_directory.clone(),
        policy_version: 1,
        listen: None,
        tls: None,
        policy,
        file_roots: Default::default(),
        read_roots: Default::default(),
        approved_actions: Default::default(),
        health: HealthConfig::default(),
        resource_reporting: ResourceReportingConfig::default(),
        process_reporting: ProcessReportingConfig {
            snapshot: Some(ProcessSnapshotConfig {
                snapshot_path,
                public_key_hex: hex::encode(process_key.verifying_key().to_bytes()),
                max_age_secs: 30,
            }),
        },
        service_reporting: ServiceReportingConfig::default(),
        repository_reporting: RepositoryReportingConfig::default(),
        updates: None,
    });
    config.validate()?;
    let executor = CapabilityExecutor::new(
        Arc::clone(&config),
        ResourceReporter::new(
            harness.identity.node_id(),
            harness.identity.device().clone(),
        ),
    );
    let engine = harness.engine_for(&[Capability::ProcessStatus]);
    let transport = harness.transport_peer();
    let logical = signed_action(ActionSpec {
        request_seed: 175,
        sequence: 7,
        node_id: harness.identity.node_id(),
        pairing_id: harness.pairing_id,
        trust_epoch: 1,
        owner_id: OWNER_ID,
        target: ActionTarget::ManagedProcess {
            process_id: "model-engine".to_owned(),
        },
        arguments: ActionArguments::ProcessStatus {
            include_children: false,
        },
        issued_at: NOW,
        not_before: NOW,
        expires_at: NOW + 60_000,
        owner_key: &harness.owner_key,
        broker_key: &harness.broker_key,
    })?;
    let verified = match engine.verify_and_reserve(logical, &transport)? {
        AuthorizationOutcome::Fresh(verified) => verified,
        AuthorizationOutcome::Duplicate => {
            return Err("fresh logical process request duplicated".into());
        }
    };
    let result = executor
        .execute(
            &verified,
            UnixMillis(NOW + 10),
            QueueSnapshot::default(),
            TrustStatus::Trusted,
        )
        .await?;
    let ActionResultV1::ProcessStatus(status) = result else {
        return Err("logical process request returned the wrong result type".into());
    };
    assert_eq!(status.state, "running");
    assert_eq!(status.attributes.len(), 2);

    let mut raw_pid = signed_action(ActionSpec {
        request_seed: 176,
        sequence: 8,
        node_id: harness.identity.node_id(),
        pairing_id: harness.pairing_id,
        trust_epoch: 1,
        owner_id: OWNER_ID,
        target: ActionTarget::ManagedProcess {
            process_id: "model-engine".to_owned(),
        },
        arguments: ActionArguments::ProcessStatus {
            include_children: false,
        },
        issued_at: NOW,
        not_before: NOW,
        expires_at: NOW + 60_000,
        owner_key: &harness.owner_key,
        broker_key: &harness.broker_key,
    })?;
    raw_pid.request.target = ActionTarget::Process { process_id: 42 };
    raw_pid.request.authorization.permitted_target_digest = raw_pid.request.target.digest()?;
    raw_pid = sign_request(raw_pid.request, &harness.owner_key, &harness.broker_key)?;
    assert!(matches!(
        engine.verify_and_reserve(raw_pid, &transport),
        Err(AuthorizationError::CapabilityMismatch)
    ));
    // The rejected raw-PID envelope did not consume its replay identity.
    let corrected = signed_action(ActionSpec {
        request_seed: 176,
        sequence: 8,
        node_id: harness.identity.node_id(),
        pairing_id: harness.pairing_id,
        trust_epoch: 1,
        owner_id: OWNER_ID,
        target: ActionTarget::ManagedProcess {
            process_id: "model-engine".to_owned(),
        },
        arguments: ActionArguments::ProcessStatus {
            include_children: false,
        },
        issued_at: NOW,
        not_before: NOW,
        expires_at: NOW + 60_000,
        owner_key: &harness.owner_key,
        broker_key: &harness.broker_key,
    })?;
    assert!(matches!(
        engine.verify_and_reserve(corrected, &transport)?,
        AuthorizationOutcome::Fresh(_)
    ));
    Ok(())
}

#[tokio::test]
async fn service_status_uses_signed_logical_identity_without_manager_control() -> TestResult {
    let harness = Harness::with_capabilities(&[Capability::ServiceStatus])?;
    let service_key = SigningKey::from_bytes(&[0x45; 32]);
    let snapshot = ServiceStatusSnapshotV1 {
        schema_version: 1,
        observed_at_unix_ms: NOW,
        valid_until_unix_ms: NOW + 30_000,
        services: vec![ServiceStatusEntryV1 {
            service_id: "model-engine.service".to_owned(),
            state: ServiceStateV1::Running,
            detail_code: Some("ready".to_owned()),
        }],
    };
    let payload = serde_json::to_vec(&snapshot)?;
    let signature = service_key.sign(&service_status_snapshot_signing_bytes(&payload));
    let signed_snapshot = SignedServiceStatusSnapshotV1 {
        payload_hex: hex::encode(payload),
        signature_hex: hex::encode(signature.to_bytes()),
    };
    let snapshot_path = harness._directory.path().join("service-status.json");
    fs::write(&snapshot_path, serde_json::to_vec(&signed_snapshot)?)?;
    let policy = PolicyConfig {
        enabled_capabilities: vec![Capability::ServiceStatus],
        ..PolicyConfig::default()
    };
    let config = Arc::new(NodeConfig {
        data_dir: harness.identity_directory.clone(),
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
        service_reporting: ServiceReportingConfig {
            snapshot: Some(ServiceSnapshotConfig {
                snapshot_path,
                public_key_hex: hex::encode(service_key.verifying_key().to_bytes()),
                max_age_secs: 30,
            }),
        },
        repository_reporting: RepositoryReportingConfig::default(),
        updates: None,
    });
    config.validate()?;
    let executor = CapabilityExecutor::new(
        Arc::clone(&config),
        ResourceReporter::new(
            harness.identity.node_id(),
            harness.identity.device().clone(),
        ),
    );
    let engine = harness.engine_for(&[Capability::ServiceStatus]);
    let transport = harness.transport_peer();
    let action = signed_action(ActionSpec {
        request_seed: 177,
        sequence: 9,
        node_id: harness.identity.node_id(),
        pairing_id: harness.pairing_id,
        trust_epoch: 1,
        owner_id: OWNER_ID,
        target: ActionTarget::Service {
            service_name: "model-engine.service".to_owned(),
        },
        arguments: ActionArguments::ServiceStatus,
        issued_at: NOW,
        not_before: NOW,
        expires_at: NOW + 60_000,
        owner_key: &harness.owner_key,
        broker_key: &harness.broker_key,
    })?;
    let verified = match engine.verify_and_reserve(action, &transport)? {
        AuthorizationOutcome::Fresh(verified) => verified,
        AuthorizationOutcome::Duplicate => return Err("fresh service request duplicated".into()),
    };
    let result = executor
        .execute(
            &verified,
            UnixMillis(NOW + 10),
            QueueSnapshot::default(),
            TrustStatus::Trusted,
        )
        .await?;
    let ActionResultV1::ServiceStatus(status) = result else {
        return Err("logical service request returned the wrong result type".into());
    };
    assert_eq!(status.state, "running");
    assert_eq!(status.attributes.len(), 2);
    assert_eq!(
        status
            .attributes
            .get("logical_service_id")
            .map(String::as_str),
        Some("model-engine.service")
    );

    let unknown = signed_action(ActionSpec {
        request_seed: 178,
        sequence: 10,
        node_id: harness.identity.node_id(),
        pairing_id: harness.pairing_id,
        trust_epoch: 1,
        owner_id: OWNER_ID,
        target: ActionTarget::Service {
            service_name: "unknown.service".to_owned(),
        },
        arguments: ActionArguments::ServiceStatus,
        issued_at: NOW,
        not_before: NOW,
        expires_at: NOW + 60_000,
        owner_key: &harness.owner_key,
        broker_key: &harness.broker_key,
    })?;
    let unknown = match engine.verify_and_reserve(unknown, &transport)? {
        AuthorizationOutcome::Fresh(verified) => verified,
        AuthorizationOutcome::Duplicate => return Err("fresh unknown service duplicated".into()),
    };
    assert_eq!(
        executor
            .execute(
                &unknown,
                UnixMillis(NOW + 10),
                QueueSnapshot::default(),
                TrustStatus::Trusted,
            )
            .await,
        Err(CapabilityError::TargetNotAllowed)
    );
    Ok(())
}

#[tokio::test]
async fn repository_status_uses_signed_logical_identity_without_git_access() -> TestResult {
    let harness = Harness::with_capabilities(&[Capability::RepositoryStatus])?;
    let repository_key = SigningKey::from_bytes(&[0x56; 32]);
    let snapshot = RepositoryStatusSnapshotV1 {
        schema_version: 1,
        observed_at_unix_ms: NOW,
        valid_until_unix_ms: NOW + 30_000,
        repositories: vec![RepositoryStatusEntryV1 {
            repository_id: "primary".to_owned(),
            status: RepositoryStatusV1 {
                head: Some("0123456789abcdef0123456789abcdef01234567".to_owned()),
                branch: Some("main".to_owned()),
                clean: false,
                ahead: 1,
                behind: 0,
                untracked_count: Some(3),
            },
        }],
    };
    let payload = serde_json::to_vec(&snapshot)?;
    let signature = repository_key.sign(&repository_status_snapshot_signing_bytes(&payload));
    let signed_snapshot = SignedRepositoryStatusSnapshotV1 {
        payload_hex: hex::encode(payload),
        signature_hex: hex::encode(signature.to_bytes()),
    };
    let snapshot_path = harness._directory.path().join("repository-status.json");
    fs::write(&snapshot_path, serde_json::to_vec(&signed_snapshot)?)?;
    let policy = PolicyConfig {
        enabled_capabilities: vec![Capability::RepositoryStatus],
        ..PolicyConfig::default()
    };
    let config = Arc::new(NodeConfig {
        data_dir: harness.identity_directory.clone(),
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
        repository_reporting: RepositoryReportingConfig {
            snapshot: Some(RepositorySnapshotConfig {
                snapshot_path,
                public_key_hex: hex::encode(repository_key.verifying_key().to_bytes()),
                max_age_secs: 30,
            }),
        },
        updates: None,
    });
    config.validate()?;
    let executor = CapabilityExecutor::new(
        Arc::clone(&config),
        ResourceReporter::new(
            harness.identity.node_id(),
            harness.identity.device().clone(),
        ),
    );
    let engine = harness.engine_for(&[Capability::RepositoryStatus]);
    let transport = harness.transport_peer();
    let minimized = signed_action(ActionSpec {
        request_seed: 179,
        sequence: 11,
        node_id: harness.identity.node_id(),
        pairing_id: harness.pairing_id,
        trust_epoch: 1,
        owner_id: OWNER_ID,
        target: ActionTarget::Repository {
            repository_id: "primary".to_owned(),
        },
        arguments: ActionArguments::RepositoryStatus {
            include_untracked_summary: false,
        },
        issued_at: NOW,
        not_before: NOW,
        expires_at: NOW + 60_000,
        owner_key: &harness.owner_key,
        broker_key: &harness.broker_key,
    })?;
    let minimized = match engine.verify_and_reserve(minimized, &transport)? {
        AuthorizationOutcome::Fresh(verified) => verified,
        AuthorizationOutcome::Duplicate => {
            return Err("fresh repository request duplicated".into());
        }
    };
    let result = executor
        .execute(
            &minimized,
            UnixMillis(NOW + 10),
            QueueSnapshot::default(),
            TrustStatus::Trusted,
        )
        .await?;
    let ActionResultV1::RepositoryStatus(status) = result else {
        return Err("logical repository request returned the wrong result type".into());
    };
    assert_eq!(status.branch.as_deref(), Some("main"));
    assert_eq!(status.untracked_count, None);

    let expanded = signed_action(ActionSpec {
        request_seed: 180,
        sequence: 12,
        node_id: harness.identity.node_id(),
        pairing_id: harness.pairing_id,
        trust_epoch: 1,
        owner_id: OWNER_ID,
        target: ActionTarget::Repository {
            repository_id: "primary".to_owned(),
        },
        arguments: ActionArguments::RepositoryStatus {
            include_untracked_summary: true,
        },
        issued_at: NOW,
        not_before: NOW,
        expires_at: NOW + 60_000,
        owner_key: &harness.owner_key,
        broker_key: &harness.broker_key,
    })?;
    let expanded = match engine.verify_and_reserve(expanded, &transport)? {
        AuthorizationOutcome::Fresh(verified) => verified,
        AuthorizationOutcome::Duplicate => {
            return Err("fresh expanded repository request duplicated".into());
        }
    };
    let result = executor
        .execute(
            &expanded,
            UnixMillis(NOW + 10),
            QueueSnapshot::default(),
            TrustStatus::Trusted,
        )
        .await?;
    let ActionResultV1::RepositoryStatus(status) = result else {
        return Err("expanded repository request returned the wrong result type".into());
    };
    assert_eq!(status.untracked_count, Some(3));

    let unknown = signed_action(ActionSpec {
        request_seed: 181,
        sequence: 13,
        node_id: harness.identity.node_id(),
        pairing_id: harness.pairing_id,
        trust_epoch: 1,
        owner_id: OWNER_ID,
        target: ActionTarget::Repository {
            repository_id: "unknown".to_owned(),
        },
        arguments: ActionArguments::RepositoryStatus {
            include_untracked_summary: false,
        },
        issued_at: NOW,
        not_before: NOW,
        expires_at: NOW + 60_000,
        owner_key: &harness.owner_key,
        broker_key: &harness.broker_key,
    })?;
    let unknown = match engine.verify_and_reserve(unknown, &transport)? {
        AuthorizationOutcome::Fresh(verified) => verified,
        AuthorizationOutcome::Duplicate => {
            return Err("fresh unknown repository request duplicated".into());
        }
    };
    assert_eq!(
        executor
            .execute(
                &unknown,
                UnixMillis(NOW + 10),
                QueueSnapshot::default(),
                TrustStatus::Trusted,
            )
            .await,
        Err(CapabilityError::TargetNotAllowed)
    );
    Ok(())
}

#[cfg(unix)]
#[tokio::test]
async fn file_read_uses_exact_pinned_read_only_root_without_write_authority() -> TestResult {
    let harness = Harness::with_capabilities(&[Capability::FileRead])?;
    let read_root = harness._directory.path().join("published-reports");
    fs::create_dir_all(read_root.join("daily"))?;
    let read_root = read_root.canonicalize()?;
    fs::write(read_root.join("daily/status.txt"), b"0123456789")?;
    fs::write(read_root.join("daily/private.txt"), b"private")?;
    let policy = PolicyConfig {
        enabled_capabilities: vec![Capability::FileRead],
        max_file_read_bytes: 64,
        ..PolicyConfig::default()
    };
    let config = Arc::new(NodeConfig {
        data_dir: harness.identity_directory.clone(),
        policy_version: 1,
        listen: None,
        tls: None,
        policy,
        file_roots: Default::default(),
        read_roots: std::collections::BTreeMap::from([(
            "reports".to_owned(),
            ReadRootConfig {
                path: read_root,
                allowed_files: vec!["daily/status.txt".to_owned()],
            },
        )]),
        approved_actions: Default::default(),
        health: HealthConfig::default(),
        resource_reporting: ResourceReportingConfig::default(),
        process_reporting: ProcessReportingConfig::default(),
        service_reporting: ServiceReportingConfig::default(),
        repository_reporting: RepositoryReportingConfig::default(),
        updates: None,
    });
    config.validate()?;
    let executor = CapabilityExecutor::new(
        Arc::clone(&config),
        ResourceReporter::new(
            harness.identity.node_id(),
            harness.identity.device().clone(),
        ),
    );
    let engine = harness.engine_for(&[Capability::FileRead]);
    let transport = harness.transport_peer();
    let read = signed_action(ActionSpec {
        request_seed: 182,
        sequence: 14,
        node_id: harness.identity.node_id(),
        pairing_id: harness.pairing_id,
        trust_epoch: 1,
        owner_id: OWNER_ID,
        target: ActionTarget::File {
            root_id: "reports".to_owned(),
            relative_path: "daily/status.txt".to_owned(),
        },
        arguments: ActionArguments::FileRead {
            offset: 3,
            max_bytes: 4,
        },
        issued_at: NOW,
        not_before: NOW,
        expires_at: NOW + 60_000,
        owner_key: &harness.owner_key,
        broker_key: &harness.broker_key,
    })?;
    let read = match engine.verify_and_reserve(read, &transport)? {
        AuthorizationOutcome::Fresh(verified) => verified,
        AuthorizationOutcome::Duplicate => return Err("fresh file read duplicated".into()),
    };
    let result = executor
        .execute(
            &read,
            UnixMillis(NOW + 10),
            QueueSnapshot::default(),
            TrustStatus::Trusted,
        )
        .await?;
    let ActionResultV1::FileRead(result) = result else {
        return Err("file read returned the wrong result type".into());
    };
    assert_eq!(result.contents, b"3456");
    assert!(!result.end_of_file);
    assert_eq!(result.content_digest, Sha256Digest(sha256(b"3456")));

    let denied = signed_action(ActionSpec {
        request_seed: 183,
        sequence: 15,
        node_id: harness.identity.node_id(),
        pairing_id: harness.pairing_id,
        trust_epoch: 1,
        owner_id: OWNER_ID,
        target: ActionTarget::File {
            root_id: "reports".to_owned(),
            relative_path: "daily/private.txt".to_owned(),
        },
        arguments: ActionArguments::FileRead {
            offset: 0,
            max_bytes: 4,
        },
        issued_at: NOW,
        not_before: NOW,
        expires_at: NOW + 60_000,
        owner_key: &harness.owner_key,
        broker_key: &harness.broker_key,
    })?;
    let denied = match engine.verify_and_reserve(denied, &transport)? {
        AuthorizationOutcome::Fresh(verified) => verified,
        AuthorizationOutcome::Duplicate => return Err("fresh denied file read duplicated".into()),
    };
    assert_eq!(
        executor
            .execute(
                &denied,
                UnixMillis(NOW + 10),
                QueueSnapshot::default(),
                TrustStatus::Trusted,
            )
            .await,
        Err(CapabilityError::TargetNotAllowed)
    );

    let mut write_config = (*config).clone();
    write_config
        .policy
        .enabled_capabilities
        .push(Capability::FileWrite);
    assert!(write_config.validate().is_err());
    Ok(())
}

#[test]
fn expired_wrong_node_and_capability_mismatch_fail_closed() -> TestResult {
    let harness = Harness::new()?;
    let engine = harness.engine();
    let transport = harness.transport_peer();

    let expired = signed_action(ActionSpec {
        request_seed: 200,
        sequence: 10,
        node_id: harness.identity.node_id(),
        pairing_id: harness.pairing_id,
        trust_epoch: 1,
        owner_id: OWNER_ID,
        target: ActionTarget::Node,
        arguments: ActionArguments::SystemInfo,
        issued_at: NOW,
        not_before: NOW,
        expires_at: NOW + 100,
        owner_key: &harness.owner_key,
        broker_key: &harness.broker_key,
    })?;
    harness.clock.set(NOW + 100);
    assert!(matches!(
        engine.verify_and_reserve(expired, &transport),
        Err(AuthorizationError::Expired)
    ));

    harness.clock.set(NOW + 10);
    let wrong_node = signed_action(ActionSpec {
        request_seed: 201,
        sequence: 11,
        node_id: NodeId(non_nil_uuid(9_999)),
        pairing_id: harness.pairing_id,
        trust_epoch: 1,
        owner_id: OWNER_ID,
        target: ActionTarget::Node,
        arguments: ActionArguments::SystemInfo,
        issued_at: NOW,
        not_before: NOW,
        expires_at: NOW + 60_000,
        owner_key: &harness.owner_key,
        broker_key: &harness.broker_key,
    })?;
    assert!(matches!(
        engine.verify_and_reserve(wrong_node, &transport),
        Err(AuthorizationError::WrongNode)
    ));

    let mut mismatch = harness.system_info_action(202, 12)?;
    mismatch.request.authorization.permitted_capability = Capability::ResourceStatus;
    let mismatch = sign_request(mismatch.request, &harness.owner_key, &harness.broker_key)?;
    assert!(matches!(
        engine.verify_and_reserve(mismatch, &transport),
        Err(AuthorizationError::CapabilityMismatch)
    ));

    let file_action = signed_action(ActionSpec {
        request_seed: 203,
        sequence: 13,
        node_id: harness.identity.node_id(),
        pairing_id: harness.pairing_id,
        trust_epoch: 1,
        owner_id: OWNER_ID,
        target: ActionTarget::File {
            root_id: "reports".to_owned(),
            relative_path: "daily.txt".to_owned(),
        },
        arguments: ActionArguments::FileRead {
            offset: 0,
            max_bytes: 128,
        },
        issued_at: NOW,
        not_before: NOW,
        expires_at: NOW + 60_000,
        owner_key: &harness.owner_key,
        broker_key: &harness.broker_key,
    })?;
    let system_only_engine = harness.engine_for(&[Capability::SystemInfo]);
    assert!(matches!(
        system_only_engine.verify_and_reserve(file_action, &transport),
        Err(AuthorizationError::CapabilityNotAdvertised)
    ));
    Ok(())
}

#[test]
fn duplicate_and_replay_state_survive_reconnect_and_store_reopen() -> TestResult {
    let harness = Harness::new()?;
    let transport = harness.transport_peer();
    let action = harness.system_info_action(300, 20)?;
    let engine = harness.engine();
    assert!(matches!(
        engine.verify_and_reserve(action.clone(), &transport)?,
        AuthorizationOutcome::Fresh(_)
    ));
    assert!(matches!(
        engine.verify_and_reserve(action.clone(), &transport)?,
        AuthorizationOutcome::Duplicate
    ));

    drop(engine);
    let reconnected_engine = harness.engine();
    let reconnected_transport = harness.transport_peer();
    assert!(matches!(
        reconnected_engine.verify_and_reserve(action.clone(), &reconnected_transport)?,
        AuthorizationOutcome::Duplicate
    ));

    let reopened_store = Arc::new(StateStore::open(&harness.database_path)?);
    let policy = PolicyConfig {
        enabled_capabilities: vec![Capability::SystemInfo],
        ..PolicyConfig::default()
    };
    let reopened_engine = AuthorizationEngine::new(
        harness.identity.node_id(),
        reopened_store,
        harness.clock.clone(),
        &policy,
        1,
        TEST_POLICY_DIGEST,
    );
    assert!(matches!(
        reopened_engine.verify_and_reserve(action.clone(), &reconnected_transport)?,
        AuthorizationOutcome::Duplicate
    ));

    let mut collision = action;
    collision.request.task_id = TaskId(non_nil_uuid(30_001));
    let collision = sign_request(collision.request, &harness.owner_key, &harness.broker_key)?;
    assert!(matches!(
        reopened_engine.verify_and_reserve(collision, &reconnected_transport),
        Err(AuthorizationError::ReplayCollision)
    ));
    Ok(())
}

#[test]
fn revocation_is_immediate_and_durable_across_node_restart() -> TestResult {
    let harness = Harness::new()?;
    let manager = PairingManager::new(
        Arc::clone(&harness.identity),
        Arc::clone(&harness.store),
        [Capability::SystemInfo],
    );
    let outcome = manager.revoke_local(
        PEER_ID,
        "owner revoked broker access",
        UnixMillis(NOW + 20),
        true,
    )?;
    assert!(matches!(outcome, RevocationOutcome::Revoked(_)));
    assert!(
        harness
            .store
            .currently_trusted_peer(PEER_ID, NOW as i64 + 20)?
            .is_none()
    );

    let action = harness.system_info_action(400, 30)?;
    assert!(matches!(
        harness
            .engine()
            .verify_and_reserve(action.clone(), &harness.transport_peer()),
        Err(AuthorizationError::UntrustedPeer)
    ));

    let reloaded_identity = NodeIdentity::load(&harness.identity_directory)?;
    assert_eq!(reloaded_identity.node_id(), harness.identity.node_id());
    assert_eq!(
        reloaded_identity.device().installation_id,
        harness.identity.device().installation_id
    );
    assert_eq!(
        reloaded_identity.public_key(),
        harness.identity.public_key()
    );

    let reopened_store = Arc::new(StateStore::open(&harness.database_path)?);
    assert!(reopened_store.is_peer_revoked(PEER_ID)?);
    assert!(
        reopened_store
            .currently_trusted_peer(PEER_ID, NOW as i64 + 30)?
            .is_none()
    );
    let policy = PolicyConfig {
        enabled_capabilities: vec![Capability::SystemInfo],
        ..PolicyConfig::default()
    };
    let restarted_engine = AuthorizationEngine::new(
        reloaded_identity.node_id(),
        reopened_store,
        harness.clock.clone(),
        &policy,
        1,
        TEST_POLICY_DIGEST,
    );
    assert!(matches!(
        restarted_engine.verify_and_reserve(action, &harness.transport_peer()),
        Err(AuthorizationError::UntrustedPeer)
    ));
    Ok(())
}

#[test]
fn version_mismatch_and_path_traversal_are_rejected_before_replay_reservation() -> TestResult {
    let harness = Harness::new()?;
    let engine = harness.engine();
    let transport = harness.transport_peer();

    let valid_version = harness.system_info_action(500, 40)?;
    let mut wrong_version_request = valid_version.request.clone();
    wrong_version_request.protocol_version = 2;
    let wrong_version = sign_request(
        wrong_version_request,
        &harness.owner_key,
        &harness.broker_key,
    )?;
    assert!(matches!(
        wrong_version.validate_for_node(harness.identity.node_id(), UnixMillis(NOW + 10), 1),
        Err(ValidationError::UnsupportedProtocolVersion(2))
    ));
    assert!(matches!(
        engine.verify_and_reserve(wrong_version, &transport),
        Err(AuthorizationError::Encoding)
    ));
    assert!(matches!(
        engine.verify_and_reserve(valid_version, &transport)?,
        AuthorizationOutcome::Fresh(_)
    ));

    let traversal = signed_action(ActionSpec {
        request_seed: 501,
        sequence: 41,
        node_id: harness.identity.node_id(),
        pairing_id: harness.pairing_id,
        trust_epoch: 1,
        owner_id: OWNER_ID,
        target: ActionTarget::File {
            root_id: "reports".to_owned(),
            relative_path: "../identity.json".to_owned(),
        },
        arguments: ActionArguments::FileRead {
            offset: 0,
            max_bytes: 128,
        },
        issued_at: NOW,
        not_before: NOW,
        expires_at: NOW + 60_000,
        owner_key: &harness.owner_key,
        broker_key: &harness.broker_key,
    })?;
    assert!(matches!(
        traversal.request.validate_structure(),
        Err(ValidationError::InvalidValue("relative path"))
    ));
    assert!(matches!(
        engine.verify_and_reserve(traversal, &transport),
        Err(AuthorizationError::Encoding)
    ));

    let safe_same_request = signed_action(ActionSpec {
        request_seed: 501,
        sequence: 41,
        node_id: harness.identity.node_id(),
        pairing_id: harness.pairing_id,
        trust_epoch: 1,
        owner_id: OWNER_ID,
        target: ActionTarget::File {
            root_id: "reports".to_owned(),
            relative_path: "public/status.txt".to_owned(),
        },
        arguments: ActionArguments::FileRead {
            offset: 0,
            max_bytes: 128,
        },
        issued_at: NOW,
        not_before: NOW,
        expires_at: NOW + 60_000,
        owner_key: &harness.owner_key,
        broker_key: &harness.broker_key,
    })?;
    assert!(matches!(
        engine.verify_and_reserve(safe_same_request, &transport)?,
        AuthorizationOutcome::Fresh(_)
    ));
    Ok(())
}

#[test]
fn replay_capacity_exhaustion_fails_closed_with_resource_error() -> TestResult {
    let harness = Harness::with_limits(StoreLimits {
        max_pending_pairings: 1,
        max_trusted_peers: 1,
        max_open_replays: 1,
    })?;
    let engine = harness.engine();
    let transport = harness.transport_peer();
    assert!(matches!(
        engine.verify_and_reserve(harness.system_info_action(600, 50)?, &transport)?,
        AuthorizationOutcome::Fresh(_)
    ));

    let exhausted = engine.verify_and_reserve(harness.system_info_action(601, 51)?, &transport);
    assert!(matches!(
        &exhausted,
        Err(AuthorizationError::Store(StoreError::ResourceLimit(
            "open replay reservation capacity"
        )))
    ));
    assert_eq!(
        exhausted.as_ref().err().map(|error| error.code()),
        Some(ActionErrorCode::ResourceExhausted)
    );
    Ok(())
}

#[test]
fn credential_rotation_increments_epoch_and_invalidates_old_authorizations() -> TestResult {
    let harness = Harness::new()?;
    let manager = PairingManager::new(
        Arc::clone(&harness.identity),
        Arc::clone(&harness.store),
        [
            Capability::SystemInfo,
            Capability::ResourceStatus,
            Capability::FileRead,
        ],
    );
    let new_owner_key = SigningKey::from_bytes(&[0x55; 32]);
    let new_broker_key = SigningKey::from_bytes(&[0x66; 32]);
    let (mut server_only_material, server_only_chain) = key_material(
        &new_owner_key,
        &new_broker_key,
        ExtendedKeyUsagePurpose::ServerAuth,
    )?;
    server_only_material.allowed_capabilities = harness.material.allowed_capabilities.clone();
    assert!(matches!(
        manager.begin_credential_rotation(
            CredentialRotationRequest {
                peer_id: PEER_ID.to_owned(),
                key_material: server_only_material,
                client_certificate_chain_der: server_only_chain,
                ttl_millis: 60_000,
            },
            UnixMillis(NOW + 19),
        ),
        Err(PairingError::Invalid(_))
    ));
    assert_eq!(
        harness
            .store
            .peer_record(PEER_ID)?
            .ok_or_else(|| test_error("paired peer record was missing"))?
            .trust_epoch,
        1
    );
    let mut next_material = harness.material.clone();
    next_material.owner_public_key = PublicKeyBytes(new_owner_key.verifying_key().to_bytes());
    next_material.broker_public_key = PublicKeyBytes(new_broker_key.verifying_key().to_bytes());
    let display = manager.begin_credential_rotation(
        CredentialRotationRequest {
            peer_id: PEER_ID.to_owned(),
            key_material: next_material,
            client_certificate_chain_der: harness.client_certificate_chain_der.clone(),
            ttl_millis: 60_000,
        },
        UnixMillis(NOW + 20),
    )?;
    let proof = rotation_proof_for(
        &display,
        &harness.owner_key,
        &harness.broker_key,
        &new_owner_key,
        &new_broker_key,
        UnixMillis(NOW + 21),
    )?;

    assert!(matches!(
        manager.approve_credential_rotation_local(&proof, false),
        Err(PairingError::OwnerConfirmationRequired)
    ));
    let attacker = SigningKey::from_bytes(&[0x77; 32]);
    let payload = hex::decode(&display.proof_payload_hex)?;
    let attacker_signature = signature_bytes(&attacker.sign(&payload))?;
    let mut forged_current_owner = proof.clone();
    forged_current_owner.current_owner_signature = attacker_signature.clone();
    let mut forged_current_broker = proof.clone();
    forged_current_broker.current_broker_signature = attacker_signature.clone();
    let mut forged_next_owner = proof.clone();
    forged_next_owner.next_owner_signature = attacker_signature.clone();
    let mut forged_next_broker = proof.clone();
    forged_next_broker.next_broker_signature = attacker_signature;
    for forged in [
        forged_current_owner,
        forged_current_broker,
        forged_next_owner,
        forged_next_broker,
    ] {
        assert!(matches!(
            manager.approve_credential_rotation_local(&forged, true),
            Err(PairingError::InvalidProof)
        ));
    }
    assert_eq!(
        harness
            .store
            .peer_record(PEER_ID)?
            .ok_or_else(|| test_error("paired peer record was missing"))?
            .trust_epoch,
        1
    );

    let approved = manager.approve_credential_rotation_local(&proof, true)?;
    let rotated_peer = approved.trusted_peer;
    assert_eq!(rotated_peer.trust_epoch, 2);
    assert_eq!(
        approved.receipt.receipt.kind,
        TrustReceiptKind::CredentialRotation
    );
    assert_eq!(approved.receipt.receipt.trust_epoch, 2);
    assert!(
        approved
            .receipt
            .receipt
            .previous_peer_identity_digest
            .is_some()
    );
    approved.receipt.verify()?;
    let mut tampered_receipt = approved.receipt.clone();
    tampered_receipt.receipt.trust_epoch = 3;
    assert!(matches!(
        tampered_receipt.verify(),
        Err(PairingError::InvalidProof)
    ));
    assert!(matches!(
        manager.approve_credential_rotation_local(&proof, true),
        Err(PairingError::Store(StoreError::CredentialRotationNotFound))
    ));

    let engine = harness.engine();
    let old_transport = harness.transport_peer();
    let old_epoch = harness.system_info_action(700, 60)?;
    assert!(matches!(
        engine.verify_and_reserve(old_epoch, &old_transport),
        Err(AuthorizationError::TrustEpoch)
    ));
    let mut rotated_transport = old_transport;
    rotated_transport.trust_epoch = 2;

    let old_broker_at_new_epoch = signed_action(ActionSpec {
        request_seed: 701,
        sequence: 61,
        node_id: harness.identity.node_id(),
        pairing_id: harness.pairing_id,
        trust_epoch: 2,
        owner_id: OWNER_ID,
        target: ActionTarget::Node,
        arguments: ActionArguments::SystemInfo,
        issued_at: NOW,
        not_before: NOW,
        expires_at: NOW + 60_000,
        owner_key: &new_owner_key,
        broker_key: &harness.broker_key,
    })?;
    assert!(matches!(
        engine.verify_and_reserve(old_broker_at_new_epoch, &rotated_transport),
        Err(AuthorizationError::Forged)
    ));

    let rotated_action = signed_action(ActionSpec {
        request_seed: 702,
        sequence: 62,
        node_id: harness.identity.node_id(),
        pairing_id: harness.pairing_id,
        trust_epoch: 2,
        owner_id: OWNER_ID,
        target: ActionTarget::Node,
        arguments: ActionArguments::SystemInfo,
        issued_at: NOW,
        not_before: NOW,
        expires_at: NOW + 60_000,
        owner_key: &new_owner_key,
        broker_key: &new_broker_key,
    })?;
    assert!(matches!(
        engine.verify_and_reserve(rotated_action, &rotated_transport)?,
        AuthorizationOutcome::Fresh(_)
    ));

    let reopened = StateStore::open(&harness.database_path)?;
    assert_eq!(
        reopened
            .peer_record(PEER_ID)?
            .ok_or_else(|| test_error("reopened rotated peer record was missing"))?
            .trust_epoch,
        2
    );
    Ok(())
}

#[test]
fn credential_rotation_expiry_is_consumed_without_changing_trust() -> TestResult {
    let harness = Harness::new()?;
    let manager = PairingManager::new(
        Arc::clone(&harness.identity),
        Arc::clone(&harness.store),
        [
            Capability::SystemInfo,
            Capability::ResourceStatus,
            Capability::FileRead,
        ],
    );
    let next_owner = SigningKey::from_bytes(&[0x35; 32]);
    let next_broker = SigningKey::from_bytes(&[0x36; 32]);
    let mut next_material = harness.material.clone();
    next_material.owner_public_key = PublicKeyBytes(next_owner.verifying_key().to_bytes());
    next_material.broker_public_key = PublicKeyBytes(next_broker.verifying_key().to_bytes());
    let display = manager.begin_credential_rotation(
        CredentialRotationRequest {
            peer_id: PEER_ID.to_owned(),
            key_material: next_material,
            client_certificate_chain_der: harness.client_certificate_chain_der.clone(),
            ttl_millis: 60_000,
        },
        UnixMillis(NOW + 20),
    )?;
    let proof = rotation_proof_for(
        &display,
        &harness.owner_key,
        &harness.broker_key,
        &next_owner,
        &next_broker,
        display.expires_at,
    )?;
    assert!(matches!(
        manager.approve_credential_rotation_local(&proof, true),
        Err(PairingError::Store(StoreError::CredentialRotationExpired))
    ));
    assert!(matches!(
        manager.approve_credential_rotation_local(&proof, true),
        Err(PairingError::Store(StoreError::CredentialRotationNotFound))
    ));
    assert_eq!(
        harness
            .store
            .peer_record(PEER_ID)?
            .ok_or_else(|| test_error("paired peer record was missing"))?
            .trust_epoch,
        1
    );
    Ok(())
}

#[test]
fn revoked_pairing_recovery_requires_new_proofs_and_preserves_history() -> TestResult {
    let harness = Harness::new()?;
    let manager = PairingManager::new(
        Arc::clone(&harness.identity),
        Arc::clone(&harness.store),
        [
            Capability::SystemInfo,
            Capability::ResourceStatus,
            Capability::FileRead,
        ],
    );
    let next_owner = SigningKey::from_bytes(&[0x45; 32]);
    let next_broker = SigningKey::from_bytes(&[0x46; 32]);
    let (next_material, next_chain) = key_material(
        &next_owner,
        &next_broker,
        ExtendedKeyUsagePurpose::ClientAuth,
    )?;
    let request = || PairingRecoveryRequest {
        peer_id: PEER_ID.to_owned(),
        key_material: next_material.clone(),
        client_certificate_chain_der: next_chain.clone(),
        ttl_millis: 60_000,
    };
    let old_identity_digest = harness
        .store
        .peer_record(PEER_ID)?
        .ok_or_else(|| test_error("paired peer record was missing"))?
        .identity_digest;

    assert!(matches!(
        manager.begin_pairing_recovery(request(), UnixMillis(NOW + 20)),
        Err(PairingError::Store(StoreError::PairingNotFound))
    ));
    let revocation = match manager.revoke_local(
        PEER_ID,
        "replace compromised credentials",
        UnixMillis(NOW + 21),
        true,
    )? {
        RevocationOutcome::Revoked(record) => record,
        RevocationOutcome::AlreadyRevoked(_) | RevocationOutcome::NotFound => {
            return Err(test_error("unexpected revocation outcome"));
        }
    };
    assert!(harness.store.is_peer_revoked(PEER_ID)?);

    let display = manager.begin_pairing_recovery(request(), UnixMillis(NOW + 22))?;
    assert_eq!(display.pairing_id, harness.pairing_id);
    assert_eq!(display.revoked_trust_epoch, 1);
    assert_eq!(
        display.revoked_identity_fingerprint,
        hex::encode(old_identity_digest)
    );
    sovereign_node::pairing::verify_node_proof(
        PublicKeyBytes(decode_fixed::<32>(&display.node_public_key_hex)?),
        &hex::decode(&display.proof_payload_hex)?,
        &SignatureBytes::from_slice(&hex::decode(&display.node_signature_hex)?)?,
    )?;
    let proof = recovery_proof_for(&display, &next_owner, &next_broker, UnixMillis(NOW + 23))?;
    assert!(matches!(
        manager.approve_pairing_recovery_local(&proof, false),
        Err(PairingError::OwnerConfirmationRequired)
    ));

    let attacker = SigningKey::from_bytes(&[0x47; 32]);
    let payload = hex::decode(&display.proof_payload_hex)?;
    let attacker_signature = signature_bytes(&attacker.sign(&payload))?;
    let mut forged_owner = proof.clone();
    forged_owner.next_owner_signature = attacker_signature.clone();
    assert!(matches!(
        manager.approve_pairing_recovery_local(&forged_owner, true),
        Err(PairingError::InvalidProof)
    ));
    let mut forged_broker = proof.clone();
    forged_broker.next_broker_signature = attacker_signature;
    assert!(matches!(
        manager.approve_pairing_recovery_local(&forged_broker, true),
        Err(PairingError::InvalidProof)
    ));
    assert!(harness.store.is_peer_revoked(PEER_ID)?);
    assert_eq!(
        harness
            .store
            .peer_record(PEER_ID)?
            .ok_or_else(|| test_error("revoked peer record was missing"))?
            .trust_epoch,
        1
    );

    let approved = manager.approve_pairing_recovery_local(&proof, true)?;
    assert_eq!(approved.trusted_peer.trust_epoch, 2);
    assert_eq!(
        approved.receipt.receipt.kind,
        TrustReceiptKind::RecoveryPairing
    );
    assert_eq!(approved.receipt.receipt.pairing_id, harness.pairing_id);
    assert_eq!(approved.receipt.receipt.trust_epoch, 2);
    assert_eq!(
        approved.receipt.receipt.previous_peer_identity_digest,
        Some(Sha256Digest(old_identity_digest))
    );
    approved.receipt.verify()?;
    assert!(!harness.store.is_peer_revoked(PEER_ID)?);
    assert!(matches!(
        manager.approve_pairing_recovery_local(&proof, true),
        Err(PairingError::Store(StoreError::RecoveryNotFound))
    ));

    let history = harness.store.pairing_recoveries_for_peer(PEER_ID)?;
    assert_eq!(history.len(), 1);
    assert_eq!(history[0].revocation, revocation);
    assert_eq!(history[0].previous_trust_epoch, 1);
    assert_eq!(history[0].next_trust_epoch, 2);

    harness.clock.set(NOW + 30);
    let old_action = harness.system_info_action(800, 70)?;
    assert!(
        harness
            .engine()
            .verify_and_reserve(old_action, &harness.transport_peer())
            .is_err()
    );
    let next_transport = TransportPeer {
        peer_id: PEER_ID.to_owned(),
        certificate_sha256: next_material.client_certificate_sha256,
        trust_epoch: 2,
    };
    let next_action = signed_action(ActionSpec {
        request_seed: 801,
        sequence: 71,
        node_id: harness.identity.node_id(),
        pairing_id: harness.pairing_id,
        trust_epoch: 2,
        owner_id: OWNER_ID,
        target: ActionTarget::Node,
        arguments: ActionArguments::SystemInfo,
        issued_at: NOW,
        not_before: NOW,
        expires_at: NOW + 60_000,
        owner_key: &next_owner,
        broker_key: &next_broker,
    })?;
    assert!(matches!(
        harness
            .engine()
            .verify_and_reserve(next_action, &next_transport)?,
        AuthorizationOutcome::Fresh(_)
    ));

    assert!(matches!(
        manager.revoke_local(
            PEER_ID,
            "second explicit revocation",
            UnixMillis(NOW + 31),
            true,
        )?,
        RevocationOutcome::Revoked(_)
    ));
    let reopened = StateStore::open(&harness.database_path)?;
    assert!(reopened.is_peer_revoked(PEER_ID)?);
    assert_eq!(reopened.pairing_recoveries_for_peer(PEER_ID)?, history);
    reopened.verify_audit_chain()?;
    Ok(())
}

#[test]
fn pairing_recovery_expiry_is_consumed_and_cannot_restore_trust() -> TestResult {
    let harness = Harness::new()?;
    let manager = PairingManager::new(
        Arc::clone(&harness.identity),
        Arc::clone(&harness.store),
        [
            Capability::SystemInfo,
            Capability::ResourceStatus,
            Capability::FileRead,
        ],
    );
    assert!(matches!(
        manager.revoke_local(PEER_ID, "credential loss", UnixMillis(NOW + 20), true,)?,
        RevocationOutcome::Revoked(_)
    ));
    let next_owner = SigningKey::from_bytes(&[0x48; 32]);
    let next_broker = SigningKey::from_bytes(&[0x49; 32]);
    let (next_material, next_chain) = key_material(
        &next_owner,
        &next_broker,
        ExtendedKeyUsagePurpose::ClientAuth,
    )?;
    let display = manager.begin_pairing_recovery(
        PairingRecoveryRequest {
            peer_id: PEER_ID.to_owned(),
            key_material: next_material,
            client_certificate_chain_der: next_chain,
            ttl_millis: 60_000,
        },
        UnixMillis(NOW + 21),
    )?;
    let proof = recovery_proof_for(&display, &next_owner, &next_broker, display.expires_at)?;
    assert!(matches!(
        manager.approve_pairing_recovery_local(&proof, true),
        Err(PairingError::Store(StoreError::RecoveryExpired))
    ));
    assert!(matches!(
        manager.approve_pairing_recovery_local(&proof, true),
        Err(PairingError::Store(StoreError::RecoveryNotFound))
    ));
    assert!(harness.store.is_peer_revoked(PEER_ID)?);
    assert!(
        harness
            .store
            .pairing_recoveries_for_peer(PEER_ID)?
            .is_empty()
    );
    harness.store.verify_audit_chain()?;
    Ok(())
}

#[test]
fn node_identity_rotation_requires_owner_and_remains_stable_after_restart() -> TestResult {
    let directory = TempDir::new()?;
    let identity_directory = directory.path().join("identity");
    let (identity, created) =
        NodeIdentity::load_or_initialize(&identity_directory, "stable-node", UnixMillis(NOW))?;
    assert!(created);
    let original_node_id = identity.node_id();
    let original_installation_id = identity.device().installation_id;
    let original_key_id = identity.key_id();

    assert!(
        identity
            .rotate_locally(&identity_directory, UnixMillis(NOW + 1), false)
            .is_err()
    );
    let (rotated, binding) =
        identity.rotate_locally(&identity_directory, UnixMillis(NOW + 2), true)?;
    assert_eq!(rotated.node_id(), original_node_id);
    assert_eq!(rotated.device().installation_id, original_installation_id);
    assert_ne!(rotated.key_id(), original_key_id);
    assert_eq!(rotated.cryptographic_identity().rotation_counter, 1);
    assert_eq!(binding.node_id, original_node_id);
    assert_eq!(binding.previous_key_id, original_key_id);
    assert_eq!(binding.next_key_id, rotated.key_id());
    assert_eq!(binding.rotation_counter, 1);
    assert_eq!(binding.previous_key_signature.len(), 64);
    assert_eq!(binding.next_key_signature.len(), 64);

    let reloaded = NodeIdentity::load(&identity_directory)?;
    assert_eq!(reloaded.node_id(), original_node_id);
    assert_eq!(reloaded.device().installation_id, original_installation_id);
    assert_eq!(reloaded.key_id(), rotated.key_id());
    assert_eq!(reloaded.cryptographic_identity().rotation_counter, 1);
    Ok(())
}
