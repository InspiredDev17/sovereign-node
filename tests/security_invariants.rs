use std::error::Error;
use std::io;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use ed25519_dalek::{Signer, SigningKey};
use rustls_pki_types::CertificateDer;
use rustls_pki_types::pem::PemObject;
use sovereign_node::authz::{
    AuthorizationEngine, AuthorizationError, AuthorizationOutcome, Clock, TransportPeer,
};
use sovereign_node::config::PolicyConfig;
use sovereign_node::identity::{NodeIdentity, key_id};
use sovereign_node::pairing::{
    CredentialRotationDisplay, CredentialRotationProof, CredentialRotationRequest, PairingDisplay,
    PairingError, PairingKeyMaterialV1, PairingManager, PairingProof, PairingRequest,
    TrustReceiptKind,
};
use sovereign_node::protocol::{
    ActionArguments, ActionErrorCode, ActionRequestV1, ActionTarget, AgentId, AuthorityKind,
    AuthorizationClaimsV1, AuthorizationId, Capability, NodeId, Nonce, PairingId, PublicKeyBytes,
    ReplayProtectionV1, RequestId, Sha256Digest, SignatureBytes, SignedActionV1, TaskId,
    UnixMillis, UserAuthorityV1, ValidationError,
};
use sovereign_node::store::{RevocationOutcome, StateStore, StoreError, StoreLimits, sha256};
use tempfile::TempDir;
use uuid::Uuid;

type TestResult<T = ()> = Result<T, Box<dyn Error>>;

const NOW: u64 = 2_000_000_000_000;
const PEER_ID: &str = "owner-action-broker";
const OWNER_ID: &str = "owner-1";
const CERTIFICATE_DIGEST: Sha256Digest = Sha256Digest([0x44; 32]);
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
    pairing_id: PairingId,
    clock: Arc<ManualClock>,
}

impl Harness {
    fn new() -> TestResult<Self> {
        Self::with_limits(StoreLimits::default())
    }

    fn with_limits(limits: StoreLimits) -> TestResult<Self> {
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
        let material = key_material(&owner_key, &broker_key);
        let manager = PairingManager::new(
            Arc::clone(&identity),
            Arc::clone(&store),
            [
                Capability::SystemInfo,
                Capability::ResourceStatus,
                Capability::FileRead,
            ],
        );
        let display = manager.begin(pairing_request(material.clone()), UnixMillis(NOW))?;
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
            certificate_sha256: CERTIFICATE_DIGEST,
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

fn key_material(owner_key: &SigningKey, broker_key: &SigningKey) -> PairingKeyMaterialV1 {
    let client_ca_der = CertificateDer::from_pem_slice(include_bytes!("fixtures/test-ca.pem"))
        .map_or_else(|_| Vec::new(), |certificate| certificate.as_ref().to_vec());
    PairingKeyMaterialV1 {
        schema_version: 1,
        owner_id: OWNER_ID.to_owned(),
        owner_public_key: PublicKeyBytes(owner_key.verifying_key().to_bytes()),
        broker_public_key: PublicKeyBytes(broker_key.verifying_key().to_bytes()),
        client_ca_der,
        client_certificate_sha256: CERTIFICATE_DIGEST,
        allowed_capabilities: vec![
            Capability::SystemInfo,
            Capability::ResourceStatus,
            Capability::FileRead,
        ],
        trust_expires_at: None,
    }
}

fn pairing_request(material: PairingKeyMaterialV1) -> PairingRequest {
    PairingRequest {
        peer_id: PEER_ID.to_owned(),
        device_label: "Owner Action Broker".to_owned(),
        key_material: material,
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
    let mut material = key_material(&owner_key, &broker_key);
    material.allowed_capabilities = vec![Capability::SystemInfo];
    let display = manager.begin(pairing_request(material), UnixMillis(NOW))?;
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
    let mut next_material = harness.material.clone();
    next_material.owner_public_key = PublicKeyBytes(new_owner_key.verifying_key().to_bytes());
    next_material.broker_public_key = PublicKeyBytes(new_broker_key.verifying_key().to_bytes());
    let display = manager.begin_credential_rotation(
        CredentialRotationRequest {
            peer_id: PEER_ID.to_owned(),
            key_material: next_material,
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
