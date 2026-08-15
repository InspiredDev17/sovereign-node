#![forbid(unsafe_code)]

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, anyhow, bail};
use clap::{Args, Parser, Subcommand};
use ed25519_dalek::VerifyingKey;
use rustls_pki_types::CertificateDer;
use rustls_pki_types::pem::PemObject;
use serde::Serialize;
use sha2::{Digest, Sha256};
use sovereign_node::audit::{
    MAX_AUDIT_EXPORT_EVENTS, export_local_audit, seal_eligible_audit_segment,
    verify_audit_export_file, verify_audit_segment_file, verify_complete_audit_archive,
};
use sovereign_node::authz::{AuthorizationEngine, Clock, SystemClock};
use sovereign_node::capabilities::CapabilityExecutor;
use sovereign_node::config::{
    HealthConfig, NodeConfig, PolicyConfig, ProcessReportingConfig, RepositoryReportingConfig,
    ResourceReportingConfig, ServiceReportingConfig,
};
use sovereign_node::identity::{
    IdentityProofRequest, NodeIdentity, RotationBindingV1, require_active_policy,
    verify_identity_proof_file,
};
use sovereign_node::lifecycle::{LeaseKind, LifecycleLease};
use sovereign_node::pairing::{
    CredentialRotationProof, CredentialRotationRequest, PairingKeyMaterialV1, PairingManager,
    PairingProof, PairingRecoveryProof, PairingRecoveryRequest, PairingRequest,
};
use sovereign_node::protocol::{
    Capability, CapabilityManifestV1, ComponentHealthV1, NodeId, Nonce, PairingId, PublicKeyBytes,
    Sha256Digest, SignatureBytes, SignedNodeRegistrationV1, TrustStatus, UnixMillis,
};
use sovereign_node::resources::{HealthReporter, ResourceReporter};
use sovereign_node::runtime::{NodeRuntime, RuntimeCapacity};
use sovereign_node::store::{
    PendingDeviceRotationV1, RevocationOutcome, StateStore, StoragePolicy, StoreLimits, sha256,
};
use sovereign_node::update::{LocalUpdateStageRequest, UpdatePolicy, stage_local_update};
use uuid::Uuid;

const STATE_DATABASE: &str = "state.sqlite3";

#[derive(Debug, Parser)]
#[command(name = "sovereign-node", version, about)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Create a stable local node identity and empty fail-closed state database.
    Init(InitArgs),
    /// Print an example conservative configuration without writing it.
    ConfigExample {
        #[arg(long)]
        data_dir: PathBuf,
    },
    /// Print a node-signed public registration (never private key material).
    Identity { config: PathBuf },
    /// Emit a short-lived node identity proof bound to a requester challenge.
    IdentityProof(IdentityProofArgs),
    /// Verify a short-lived identity proof against owner-retained pins.
    IdentityVerify(IdentityVerifyArgs),
    /// Inspect local trust/audit state without starting a listener.
    Status { config: PathBuf },
    /// Export a bounded, redacted, node-signed page of the local audit journal.
    #[command(subcommand)]
    Audit(AuditCommand),
    /// Owner-local pairing and revocation ceremony.
    #[command(subcommand)]
    Pair(PairCommand),
    /// Rotate the node device identity key after explicit local confirmation.
    RotateIdentity {
        config: PathBuf,
        #[arg(long)]
        confirm: bool,
    },
    /// Verify and stage an owner-supplied offline update; never installs it.
    #[command(subcommand)]
    Update(UpdateCommand),
    /// Inspect or explicitly acknowledge the durable authorization clock checkpoint.
    #[command(subcommand)]
    Clock(ClockCommand),
    /// Run the unprivileged daemon. No listener is opened unless configured.
    Serve { config: PathBuf },
}

#[derive(Debug, Subcommand)]
enum UpdateCommand {
    /// Verify pinned release/owner signatures and copy an artifact into private staging.
    Stage(UpdateStageArgs),
}

#[derive(Debug, Subcommand)]
enum ClockCommand {
    /// Compare local wall-clock time with the durable remote-authorization checkpoint.
    Status { config: PathBuf },
    /// Replace the checkpoint after explicit local confirmation while the daemon is stopped.
    Acknowledge {
        config: PathBuf,
        #[arg(long)]
        confirm: bool,
    },
}

#[derive(Debug, Subcommand)]
enum AuditCommand {
    /// Inspect active database, WAL, free-space, and sealed-chain pressure state.
    Status { config: PathBuf },
    /// Seal and prune one replay-safe audit prefix into the fixed owner-private archive.
    Archive {
        config: PathBuf,
        #[arg(long)]
        confirm: bool,
    },
    /// Verify one signed archive segment without mutating state.
    VerifySegment { input: PathBuf },
    /// Verify every sealed segment against the durable local archive manifest.
    VerifyArchive { config: PathBuf },
    /// Verify the full chain and print one local-only signed JSON page.
    Export(AuditExportArgs),
    /// Verify one untrusted export against owner-retained identity and chain pins.
    Verify(AuditVerifyArgs),
}

#[derive(Debug, Args)]
struct AuditExportArgs {
    #[arg(long)]
    config: PathBuf,
    /// Return events strictly after this durable sequence number.
    #[arg(long, default_value_t = 0)]
    after_sequence: u64,
    /// Maximum events in this page. Hard limited to 1000.
    #[arg(long, default_value_t = 100, value_parser = clap::value_parser!(u32).range(1..=i64::from(MAX_AUDIT_EXPORT_EVENTS)))]
    limit: u32,
}

#[derive(Debug, Args)]
struct AuditVerifyArgs {
    /// Strict JSON audit export already present on this machine.
    #[arg(long)]
    input: PathBuf,
    /// Owner-retained stable NodeId expected in the signed export.
    #[arg(long)]
    expected_node_id: Uuid,
    /// Owner-retained SHA-256 of the expected node device public key.
    #[arg(long)]
    expected_node_key_id_sha256: String,
    /// Exact exclusive cursor used when requesting this page.
    #[arg(long)]
    expected_after_sequence: u64,
    /// Previous page's final event hash, or 64 zeroes for the genesis page.
    #[arg(long)]
    expected_anchor_sha256: String,
}

#[derive(Debug, Args)]
struct IdentityProofArgs {
    #[arg(long)]
    config: PathBuf,
    /// Requester-generated 32-byte random challenge in hexadecimal.
    #[arg(long)]
    challenge_hex: String,
    /// Proof lifetime in seconds, hard limited to five minutes.
    #[arg(long, default_value_t = 60, value_parser = clap::value_parser!(u64).range(1..=300))]
    ttl_seconds: u64,
}

#[derive(Debug, Args)]
struct IdentityVerifyArgs {
    /// Strict JSON identity proof already present on this machine.
    #[arg(long)]
    input: PathBuf,
    /// Owner-retained stable NodeId expected in the signed proof.
    #[arg(long)]
    expected_node_id: Uuid,
    /// Owner-retained SHA-256 of the expected node device public key.
    #[arg(long)]
    expected_node_key_id_sha256: String,
    /// The exact 32-byte requester challenge originally sent to the node.
    #[arg(long)]
    expected_challenge_hex: String,
}

#[derive(Debug, Args)]
struct UpdateStageArgs {
    #[arg(long)]
    config: PathBuf,
    /// Strict JSON SignedUpdateV1 bundle already present on this machine.
    #[arg(long)]
    bundle_json: PathBuf,
    /// Local artifact whose SHA-256 digest is signed by the bundle.
    #[arg(long)]
    artifact: PathBuf,
    /// Confirms local owner intent to stage this exact signed version transition.
    #[arg(long)]
    confirm: bool,
}

#[derive(Debug, Args)]
struct InitArgs {
    #[arg(long)]
    data_dir: PathBuf,
    #[arg(long)]
    label: String,
}

#[derive(Debug, Subcommand)]
enum PairCommand {
    /// Create and display a short-lived transcript requiring proof of both keys.
    Request(PairRequestArgs),
    /// Verify both transcript signatures and commit trust after local confirmation.
    Approve(PairApproveArgs),
    /// Create and display a short-lived, node-bound peer credential rotation transcript.
    RotationRequest(PairRotationRequestArgs),
    /// Verify current/new role proofs and atomically rotate after local confirmation.
    RotationApprove(PairRotationApproveArgs),
    /// Start local recovery for an explicitly revoked peer using replacement credentials.
    RecoveryRequest(PairRecoveryRequestArgs),
    /// Verify replacement role proofs and atomically recover after local confirmation.
    RecoveryApprove(PairRecoveryApproveArgs),
    /// Durably revoke a peer after local confirmation.
    Revoke(PairRevokeArgs),
}

#[derive(Debug, Args)]
struct PairRequestArgs {
    #[arg(long)]
    config: PathBuf,
    #[arg(long)]
    peer_id: String,
    #[arg(long)]
    label: String,
    #[arg(long)]
    owner_id: String,
    #[arg(long)]
    owner_public_key_hex: String,
    #[arg(long)]
    broker_public_key_hex: String,
    #[arg(long)]
    client_ca_pem: PathBuf,
    /// PEM chain with the client leaf first, followed by intermediates.
    #[arg(long)]
    client_certificate_pem: PathBuf,
    #[arg(long = "capability", required = true)]
    capabilities: Vec<String>,
    #[arg(long, default_value_t = 300)]
    ttl_seconds: u64,
    /// Optional signed duration for cached offline trust.
    #[arg(long)]
    trust_ttl_seconds: Option<u64>,
}

#[derive(Debug, Args)]
struct PairApproveArgs {
    #[arg(long)]
    config: PathBuf,
    #[arg(long)]
    pairing_id: Uuid,
    #[arg(long)]
    challenge_hex: String,
    #[arg(long)]
    owner_signature_hex: String,
    #[arg(long)]
    broker_signature_hex: String,
    #[arg(long)]
    confirm: bool,
}

#[derive(Debug, Args)]
struct PairRevokeArgs {
    #[arg(long)]
    config: PathBuf,
    #[arg(long)]
    peer_id: String,
    #[arg(long)]
    reason: String,
    #[arg(long)]
    confirm: bool,
}

#[derive(Debug, Args)]
struct PairRotationRequestArgs {
    #[arg(long)]
    config: PathBuf,
    #[arg(long)]
    peer_id: String,
    #[arg(long)]
    owner_id: String,
    #[arg(long)]
    owner_public_key_hex: String,
    #[arg(long)]
    broker_public_key_hex: String,
    #[arg(long)]
    client_ca_pem: PathBuf,
    /// PEM chain with the replacement client leaf first, followed by intermediates.
    #[arg(long)]
    client_certificate_pem: PathBuf,
    #[arg(long = "capability", required = true)]
    capabilities: Vec<String>,
    #[arg(long, default_value_t = 300)]
    ttl_seconds: u64,
    #[arg(long)]
    trust_ttl_seconds: Option<u64>,
}

#[derive(Debug, Args)]
struct PairRotationApproveArgs {
    #[arg(long)]
    config: PathBuf,
    #[arg(long)]
    rotation_id: Uuid,
    #[arg(long)]
    challenge_hex: String,
    #[arg(long)]
    current_owner_signature_hex: String,
    #[arg(long)]
    current_broker_signature_hex: String,
    #[arg(long)]
    next_owner_signature_hex: String,
    #[arg(long)]
    next_broker_signature_hex: String,
    #[arg(long)]
    confirm: bool,
}

#[derive(Debug, Args)]
struct PairRecoveryRequestArgs {
    #[arg(long)]
    config: PathBuf,
    /// Existing peer ID whose durable state is already revoked.
    #[arg(long)]
    peer_id: String,
    #[arg(long)]
    owner_id: String,
    #[arg(long)]
    owner_public_key_hex: String,
    #[arg(long)]
    broker_public_key_hex: String,
    #[arg(long)]
    client_ca_pem: PathBuf,
    /// PEM chain with the replacement client leaf first, followed by intermediates.
    #[arg(long)]
    client_certificate_pem: PathBuf,
    #[arg(long = "capability", required = true)]
    capabilities: Vec<String>,
    #[arg(long, default_value_t = 300)]
    ttl_seconds: u64,
    #[arg(long)]
    trust_ttl_seconds: Option<u64>,
}

#[derive(Debug, Args)]
struct PairRecoveryApproveArgs {
    #[arg(long)]
    config: PathBuf,
    #[arg(long)]
    recovery_id: Uuid,
    #[arg(long)]
    challenge_hex: String,
    #[arg(long)]
    next_owner_signature_hex: String,
    #[arg(long)]
    next_broker_signature_hex: String,
    /// Confirms local physical owner approval; this command is not exposed over LAN transport.
    #[arg(long)]
    confirm: bool,
}

#[derive(Debug, Serialize)]
struct InitOutput {
    created: bool,
    node_id: String,
    display_name: String,
    identity_fingerprint_sha256: String,
    data_dir: String,
    listener_enabled: bool,
}

#[derive(Debug, Serialize)]
struct StatusOutput {
    node_id: String,
    identity_fingerprint_sha256: String,
    trusted_peer_count: usize,
    audit_event_count: u64,
    audit_tail_sha256: String,
    listener: Option<String>,
    default_remote_execution: &'static str,
    agent_green_health: ComponentHealthV1,
    action_broker_health: ComponentHealthV1,
    staged_update_version: Option<String>,
    staged_update_release_counter: Option<u64>,
    update_installation: &'static str,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    if !sovereign_node::security_platform_supported()
        && !matches!(&cli.command, Command::ConfigExample { .. })
    {
        bail!("stateful v0.1 commands require Unix owner and mode security primitives");
    }
    match cli.command {
        Command::Init(args) => init(args),
        Command::ConfigExample { data_dir } => config_example(&data_dir),
        Command::Identity { config } => identity(&config),
        Command::IdentityProof(args) => identity_proof(args),
        Command::IdentityVerify(args) => identity_verify(args),
        Command::Status { config } => status(&config),
        Command::Audit(command) => audit(command),
        Command::Pair(command) => pair(command),
        Command::RotateIdentity { config, confirm } => rotate_identity(&config, confirm),
        Command::Update(command) => update(command),
        Command::Clock(command) => clock(command),
        Command::Serve { config } => serve(&config).await,
    }
}

fn audit(command: AuditCommand) -> Result<()> {
    match command {
        AuditCommand::Status { config } => audit_storage_status(&config),
        AuditCommand::Archive { config, confirm } => audit_archive(&config, confirm),
        AuditCommand::VerifySegment { input } => {
            let segment = verify_audit_segment_file(&input)?;
            print_json(&serde_json::json!({
                "verification": "verified",
                "node_id": segment.segment.node_id.to_string(),
                "segment_sequence": segment.segment.candidate.segment_sequence,
                "first_audit_sequence": segment.segment.candidate.first_audit_sequence,
                "last_audit_sequence": segment.segment.candidate.last_audit_sequence,
                "segment_digest_sha256": hex::encode(segment.digest()?.0),
            }))
        }
        AuditCommand::VerifyArchive { config } => {
            let config = NodeConfig::load(&config)?;
            let store = open_store(&config)?;
            let verification =
                verify_complete_audit_archive(&store, &config.data_dir.join("audit/archive"))?;
            print_json(&verification)
        }
        AuditCommand::Export(args) => audit_export(args),
        AuditCommand::Verify(args) => audit_verify(args),
    }
}

fn audit_storage_status(config_path: &Path) -> Result<()> {
    let config = NodeConfig::load(config_path)?;
    let store = open_store(&config)?;
    let observation = store.storage_observation()?;
    let checkpoint = store.audit_archive_checkpoint()?;
    print_json(&serde_json::json!({
        "pressure": store.assess_storage(observation),
        "observation": observation,
        "archived_audit_sequence": checkpoint.archived_sequence,
        "archive_segment_sequence": checkpoint.segment_sequence,
        "archive_segment_digest_sha256": hex::encode(checkpoint.segment_digest),
        "archive_root": "audit/archive",
    }))
}

fn audit_archive(config_path: &Path, confirm: bool) -> Result<()> {
    if !confirm {
        bail!("explicit local confirmation is required to archive audit history");
    }
    let config = NodeConfig::load(config_path)?;
    let _lease = LifecycleLease::acquire(&config.data_dir, LeaseKind::AdminMutation)?;
    let identity = NodeIdentity::load(&config.data_dir)?;
    let store = open_store(&config)?;
    store.verify_audit_chain()?;
    let observed = now()?;
    let retention_ms = config.storage.replay_retention_secs.saturating_mul(1_000);
    let eligible_before = observed.0.saturating_sub(retention_ms);
    let eligible_before = i64::try_from(eligible_before)?;
    let archive_root = config.data_dir.join("audit/archive");
    let result = seal_eligible_audit_segment(
        &store,
        &identity,
        &archive_root,
        eligible_before,
        config.storage.archive_max_events,
        observed,
    )?;
    store.checkpoint_wal_passive()?;
    print_json(&serde_json::json!({
        "result": result,
        "pressure": store.storage_pressure()?,
        "archive_root": "audit/archive",
    }))
}

fn audit_export(args: AuditExportArgs) -> Result<()> {
    let config = NodeConfig::load(&args.config)?;
    let identity = NodeIdentity::load(&config.data_dir)?;
    let store = open_store(&config)?;
    let export = export_local_audit(&store, &identity, args.after_sequence, args.limit, now()?)?;
    print_json(&export)
}

fn audit_verify(args: AuditVerifyArgs) -> Result<()> {
    let receipt = verify_audit_export_file(
        &args.input,
        sovereign_node::protocol::NodeId::from_uuid(args.expected_node_id),
        Sha256Digest(fixed_bytes::<32>(
            &args.expected_node_key_id_sha256,
            "expected node key SHA-256",
        )?),
        args.expected_after_sequence,
        Sha256Digest(fixed_bytes::<32>(
            &args.expected_anchor_sha256,
            "expected audit anchor SHA-256",
        )?),
    )?;
    print_json(&receipt)
}

fn update(command: UpdateCommand) -> Result<()> {
    match command {
        UpdateCommand::Stage(args) => update_stage(args),
    }
}

fn clock(command: ClockCommand) -> Result<()> {
    match command {
        ClockCommand::Status { config } => clock_status(&config),
        ClockCommand::Acknowledge { config, confirm } => clock_acknowledge(&config, confirm),
    }
}

fn clock_status(config_path: &Path) -> Result<()> {
    let config = NodeConfig::load(config_path)?;
    let store = open_store(&config)?;
    store.verify_audit_chain()?;
    let observed = to_i64(now()?)?;
    let high_water = store.trusted_clock_high_water()?;
    let tolerance_ms = i64::try_from(config.policy.max_clock_rollback_secs)?.saturating_mul(1_000);
    let rollback_detected =
        high_water.is_some_and(|checkpoint| observed < checkpoint.saturating_sub(tolerance_ms));
    let authorization_state = match (high_water, rollback_detected) {
        (None, _) => "uninitialized-until-listener-start",
        (Some(_), true) => "blocked-clock-rollback",
        (Some(_), false) => "available",
    };
    print_json(&serde_json::json!({
        "observed_at_unix_ms": observed,
        "trusted_high_water_unix_ms": high_water,
        "maximum_rollback_ms": tolerance_ms,
        "remote_authorization_state": authorization_state,
    }))
}

fn clock_acknowledge(config_path: &Path, confirm: bool) -> Result<()> {
    if !confirm {
        bail!("clock acknowledgement requires explicit local --confirm");
    }
    let config = NodeConfig::load(config_path)?;
    let admin_lease = LifecycleLease::acquire(&config.data_dir, LeaseKind::AdminMutation)?;
    let daemon_lease = LifecycleLease::acquire(&config.data_dir, LeaseKind::Daemon)
        .context("clock acknowledgement requires the daemon to be stopped")?;
    let store = open_store(&config)?;
    store.verify_audit_chain()?;
    let observed = to_i64(now()?)?;
    let previous = store.acknowledge_trusted_clock(&admin_lease, &daemon_lease, observed)?;
    print_json(&serde_json::json!({
        "previous_high_water_unix_ms": previous,
        "acknowledged_high_water_unix_ms": observed,
        "daemon_restart_required": true,
        "audit_recorded": true,
    }))
}

fn update_stage(args: UpdateStageArgs) -> Result<()> {
    let config = NodeConfig::load(&args.config)?;
    let update_config = config.updates.as_ref().ok_or_else(|| {
        anyhow!("offline update staging is disabled; configure pinned update keys")
    })?;
    let _admin_lease = LifecycleLease::acquire(&config.data_dir, LeaseKind::AdminMutation)?;
    let store = open_store(&config)?;
    store.verify_audit_chain()?;
    let release_key = verifying_key_hex(
        &update_config.release_public_key_hex,
        "update release public key",
    )?;
    let owner_key = verifying_key_hex(
        &update_config.owner_approval_public_key_hex,
        "update owner-approval public key",
    )?;
    let current_release_counter = store
        .latest_staged_update()?
        .map_or(0, |record| record.release_counter);
    let result = stage_local_update(&LocalUpdateStageRequest {
        bundle_json_path: &args.bundle_json,
        artifact_path: &args.artifact,
        data_dir: &config.data_dir,
        store: &store,
        policy: UpdatePolicy {
            current_version: env!("CARGO_PKG_VERSION").to_owned(),
            current_release_counter,
            target_os: std::env::consts::OS.to_owned(),
            target_arch: std::env::consts::ARCH.to_owned(),
        },
        release_key: &release_key,
        owner_key: &owner_key,
        max_artifact_bytes: update_config.max_artifact_bytes,
        owner_confirmed: args.confirm,
        staged_at_unix_ms: to_i64(now()?)?,
    })?;
    print_json(&result)
}

fn init(args: InitArgs) -> Result<()> {
    require_absolute(&args.data_dir, "data directory")?;
    let now = now()?;
    let (identity, created) = NodeIdentity::load_or_initialize(&args.data_dir, &args.label, now)?;
    let store = StateStore::open(args.data_dir.join(STATE_DATABASE))?;
    store.verify_audit_chain()?;
    print_json(&InitOutput {
        created,
        node_id: identity.node_id().to_string(),
        display_name: identity.device().display_name.clone(),
        identity_fingerprint_sha256: identity.fingerprint(),
        data_dir: args.data_dir.display().to_string(),
        listener_enabled: false,
    })
}

fn config_example(data_dir: &Path) -> Result<()> {
    require_absolute(data_dir, "data directory")?;
    let config = NodeConfig {
        data_dir: data_dir.to_path_buf(),
        policy_version: 1,
        listen: None,
        tls: None,
        policy: PolicyConfig::default(),
        storage: Default::default(),
        file_roots: Default::default(),
        read_roots: Default::default(),
        approved_actions: Default::default(),
        health: HealthConfig::default(),
        resource_reporting: ResourceReportingConfig::default(),
        process_reporting: ProcessReportingConfig::default(),
        service_reporting: ServiceReportingConfig::default(),
        repository_reporting: RepositoryReportingConfig::default(),
        updates: None,
    };
    config.validate()?;
    println!("{}", toml::to_string_pretty(&config)?);
    Ok(())
}

fn identity(config_path: &Path) -> Result<()> {
    let config = NodeConfig::load(config_path)?;
    let identity = NodeIdentity::load(&config.data_dir)?;
    let store = open_store(&config)?;
    let now = now()?;
    let peers = store.currently_trusted_peers(to_i64(now)?)?;
    let trust = if peers.is_empty() {
        TrustStatus::Unpaired
    } else {
        TrustStatus::Trusted
    };
    let registration = identity.registration(
        CapabilityManifestV1 {
            manifest_version: config.policy_version,
            capabilities: config.policy.enabled_capabilities,
            generated_at: now,
        },
        trust,
        now,
    );
    registration.validate()?;
    let node_signature = identity.sign(&registration.signing_bytes()?)?;
    print_json(&SignedNodeRegistrationV1 {
        registration,
        node_signature,
    })
}

fn identity_proof(args: IdentityProofArgs) -> Result<()> {
    let config = NodeConfig::load(&args.config)?;
    let _admin_lease = LifecycleLease::acquire(&config.data_dir, LeaseKind::AdminMutation)?;
    let identity = NodeIdentity::load(&config.data_dir)?;
    let store = open_store(&config)?;
    let issued_at = now()?;
    let snapshot = store.identity_proof_state_snapshot(to_i64(issued_at)?)?;
    let configured_policy_digest = Sha256Digest(config.policy_digest()?);
    require_active_policy(
        snapshot.active_policy,
        config.policy_version,
        configured_policy_digest,
    )?;
    let expires_at = UnixMillis(
        issued_at
            .0
            .checked_add(args.ttl_seconds.saturating_mul(1_000))
            .context("identity proof expiry overflow")?,
    );
    let manifest = CapabilityManifestV1 {
        manifest_version: config.policy_version,
        capabilities: config.policy.enabled_capabilities.clone(),
        generated_at: issued_at,
    };
    let proof = identity.fresh_identity_proof(IdentityProofRequest {
        manifest,
        local_policy_digest: configured_policy_digest,
        active_peers: &snapshot.trusted_peers,
        trust_observed_at_unix_ms: to_i64(issued_at)?,
        requester_challenge: Nonce(fixed_bytes::<32>(
            &args.challenge_hex,
            "requester challenge",
        )?),
        issued_at,
        expires_at,
    })?;
    print_json(&proof)
}

fn identity_verify(args: IdentityVerifyArgs) -> Result<()> {
    let receipt = verify_identity_proof_file(
        &args.input,
        NodeId::from_uuid(args.expected_node_id),
        Sha256Digest(fixed_bytes::<32>(
            &args.expected_node_key_id_sha256,
            "expected node key SHA-256",
        )?),
        Nonce(fixed_bytes::<32>(
            &args.expected_challenge_hex,
            "expected requester challenge",
        )?),
        now()?,
    )?;
    print_json(&receipt)
}

fn status(config_path: &Path) -> Result<()> {
    let config = NodeConfig::load(config_path)?;
    let identity = NodeIdentity::load(&config.data_dir)?;
    let store = open_store(&config)?;
    let audit = store.verify_audit_chain()?;
    let observed_at = now()?;
    let peers = store.currently_trusted_peers(to_i64(observed_at)?)?;
    let staged_update = store.latest_staged_update()?;
    let health = HealthReporter::new(&config.health);
    print_json(&StatusOutput {
        node_id: identity.node_id().to_string(),
        identity_fingerprint_sha256: identity.fingerprint(),
        trusted_peer_count: peers.len(),
        audit_event_count: audit.event_count,
        audit_tail_sha256: hex::encode(audit.tail_hash),
        listener: config.listen.map(|address| address.to_string()),
        default_remote_execution: "deny unless exact owner+broker authorization verifies",
        agent_green_health: health.agent_green(observed_at),
        action_broker_health: health.action_broker(observed_at),
        staged_update_version: staged_update
            .as_ref()
            .map(|record| record.software_version.clone()),
        staged_update_release_counter: staged_update.map(|record| record.release_counter),
        update_installation: "never automatic; staging does not install or execute",
    })
}

fn pair(command: PairCommand) -> Result<()> {
    match command {
        PairCommand::Request(args) => pair_request(args),
        PairCommand::Approve(args) => pair_approve(args),
        PairCommand::RotationRequest(args) => pair_rotation_request(args),
        PairCommand::RotationApprove(args) => pair_rotation_approve(args),
        PairCommand::RecoveryRequest(args) => pair_recovery_request(args),
        PairCommand::RecoveryApprove(args) => pair_recovery_approve(args),
        PairCommand::Revoke(args) => pair_revoke(args),
    }
}

fn pair_request(args: PairRequestArgs) -> Result<()> {
    let (config, identity, store, _admin_lease) = pairing_context(&args.config)?;
    let owner_public_key = public_key(&args.owner_public_key_hex)?;
    let broker_public_key = public_key(&args.broker_public_key_hex)?;
    let client_ca_der = first_pem_certificate(&args.client_ca_pem)?;
    let client_certificate_chain_der = pem_certificate_chain(&args.client_certificate_pem)?;
    let certificate_digest = Sha256Digest(Sha256::digest(&client_certificate_chain_der[0]).into());
    let capabilities = args
        .capabilities
        .iter()
        .map(|value| parse_capability(value))
        .collect::<Result<Vec<_>>>()?;
    let manager = PairingManager::new(
        identity,
        store,
        config.policy.enabled_capabilities.iter().copied(),
    );
    let now = now()?;
    let trust_expires_at = args
        .trust_ttl_seconds
        .map(|seconds| {
            seconds
                .checked_mul(1_000)
                .and_then(|millis| now.0.checked_add(millis))
                .map(UnixMillis)
                .ok_or_else(|| anyhow!("trust TTL is too large"))
        })
        .transpose()?;
    let display = manager.begin(
        PairingRequest {
            peer_id: args.peer_id,
            device_label: args.label,
            key_material: PairingKeyMaterialV1 {
                schema_version: 1,
                owner_id: args.owner_id,
                owner_public_key,
                broker_public_key,
                client_ca_der,
                client_certificate_sha256: certificate_digest,
                allowed_capabilities: capabilities,
                trust_expires_at,
            },
            client_certificate_chain_der,
            ttl_millis: args
                .ttl_seconds
                .checked_mul(1_000)
                .ok_or_else(|| anyhow!("pairing TTL is too large"))?,
        },
        now,
    )?;
    print_json(&display)
}

fn pair_approve(args: PairApproveArgs) -> Result<()> {
    let (config, identity, store, _admin_lease) = pairing_context(&args.config)?;
    let manager = PairingManager::new(
        identity,
        store,
        config.policy.enabled_capabilities.iter().copied(),
    );
    let now = now()?;
    let trusted = manager.approve_local(
        &PairingProof {
            pairing_id: PairingId(args.pairing_id),
            challenge_secret: fixed_bytes::<32>(&args.challenge_hex, "challenge")?,
            owner_signature: signature(&args.owner_signature_hex)?,
            broker_signature: signature(&args.broker_signature_hex)?,
            approved_at: now,
        },
        args.confirm,
    )?;
    print_json(&trusted)
}

fn pair_rotation_request(args: PairRotationRequestArgs) -> Result<()> {
    let (config, identity, store, _admin_lease) = pairing_context(&args.config)?;
    let now = now()?;
    let trust_expires_at = args
        .trust_ttl_seconds
        .map(|seconds| {
            seconds
                .checked_mul(1_000)
                .and_then(|millis| now.0.checked_add(millis))
                .map(UnixMillis)
                .ok_or_else(|| anyhow!("trust TTL is too large"))
        })
        .transpose()?;
    let client_certificate_chain_der = pem_certificate_chain(&args.client_certificate_pem)?;
    let key_material = PairingKeyMaterialV1 {
        schema_version: 1,
        owner_id: args.owner_id,
        owner_public_key: public_key(&args.owner_public_key_hex)?,
        broker_public_key: public_key(&args.broker_public_key_hex)?,
        client_ca_der: first_pem_certificate(&args.client_ca_pem)?,
        client_certificate_sha256: Sha256Digest(
            Sha256::digest(&client_certificate_chain_der[0]).into(),
        ),
        allowed_capabilities: args
            .capabilities
            .iter()
            .map(|value| parse_capability(value))
            .collect::<Result<Vec<_>>>()?,
        trust_expires_at,
    };
    let manager = PairingManager::new(
        identity,
        store,
        config.policy.enabled_capabilities.iter().copied(),
    );
    let display = manager.begin_credential_rotation(
        CredentialRotationRequest {
            peer_id: args.peer_id,
            key_material,
            client_certificate_chain_der,
            ttl_millis: args
                .ttl_seconds
                .checked_mul(1_000)
                .ok_or_else(|| anyhow!("rotation TTL is too large"))?,
        },
        now,
    )?;
    print_json(&display)
}

fn pair_rotation_approve(args: PairRotationApproveArgs) -> Result<()> {
    let (config, identity, store, _admin_lease) = pairing_context(&args.config)?;
    let manager = PairingManager::new(
        identity,
        store,
        config.policy.enabled_capabilities.iter().copied(),
    );
    let result = manager.approve_credential_rotation_local(
        &CredentialRotationProof {
            rotation_id: args.rotation_id,
            challenge_secret: fixed_bytes::<32>(&args.challenge_hex, "challenge")?,
            current_owner_signature: signature(&args.current_owner_signature_hex)?,
            current_broker_signature: signature(&args.current_broker_signature_hex)?,
            next_owner_signature: signature(&args.next_owner_signature_hex)?,
            next_broker_signature: signature(&args.next_broker_signature_hex)?,
            approved_at: now()?,
        },
        args.confirm,
    )?;
    print_json(&result)
}

fn pair_recovery_request(args: PairRecoveryRequestArgs) -> Result<()> {
    let (config, identity, store, _admin_lease) = pairing_context(&args.config)?;
    let now = now()?;
    let trust_expires_at = args
        .trust_ttl_seconds
        .map(|seconds| {
            seconds
                .checked_mul(1_000)
                .and_then(|millis| now.0.checked_add(millis))
                .map(UnixMillis)
                .ok_or_else(|| anyhow!("trust TTL is too large"))
        })
        .transpose()?;
    let client_certificate_chain_der = pem_certificate_chain(&args.client_certificate_pem)?;
    let key_material = PairingKeyMaterialV1 {
        schema_version: 1,
        owner_id: args.owner_id,
        owner_public_key: public_key(&args.owner_public_key_hex)?,
        broker_public_key: public_key(&args.broker_public_key_hex)?,
        client_ca_der: first_pem_certificate(&args.client_ca_pem)?,
        client_certificate_sha256: Sha256Digest(
            Sha256::digest(&client_certificate_chain_der[0]).into(),
        ),
        allowed_capabilities: args
            .capabilities
            .iter()
            .map(|value| parse_capability(value))
            .collect::<Result<Vec<_>>>()?,
        trust_expires_at,
    };
    let manager = PairingManager::new(
        identity,
        store,
        config.policy.enabled_capabilities.iter().copied(),
    );
    let display = manager.begin_pairing_recovery(
        PairingRecoveryRequest {
            peer_id: args.peer_id,
            key_material,
            client_certificate_chain_der,
            ttl_millis: args
                .ttl_seconds
                .checked_mul(1_000)
                .ok_or_else(|| anyhow!("recovery TTL is too large"))?,
        },
        now,
    )?;
    print_json(&display)
}

fn pair_recovery_approve(args: PairRecoveryApproveArgs) -> Result<()> {
    let (config, identity, store, _admin_lease) = pairing_context(&args.config)?;
    let manager = PairingManager::new(
        identity,
        store,
        config.policy.enabled_capabilities.iter().copied(),
    );
    let result = manager.approve_pairing_recovery_local(
        &PairingRecoveryProof {
            recovery_id: args.recovery_id,
            challenge_secret: fixed_bytes::<32>(&args.challenge_hex, "challenge")?,
            next_owner_signature: signature(&args.next_owner_signature_hex)?,
            next_broker_signature: signature(&args.next_broker_signature_hex)?,
            approved_at: now()?,
        },
        args.confirm,
    )?;
    print_json(&result)
}

fn pair_revoke(args: PairRevokeArgs) -> Result<()> {
    let (config, identity, store, _admin_lease) = pairing_context(&args.config)?;
    let manager = PairingManager::new(
        identity,
        store,
        config.policy.enabled_capabilities.iter().copied(),
    );
    let outcome = manager.revoke_local(&args.peer_id, &args.reason, now()?, args.confirm)?;
    let label = match outcome {
        RevocationOutcome::Revoked(_) => "revoked",
        RevocationOutcome::AlreadyRevoked(_) => "already-revoked",
        RevocationOutcome::NotFound => "not-found",
    };
    print_json(&serde_json::json!({ "peer_id": args.peer_id, "outcome": label }))
}

fn rotate_identity(config_path: &Path, confirm: bool) -> Result<()> {
    if !confirm {
        bail!("device identity rotation requires explicit local --confirm");
    }
    let config = NodeConfig::load(config_path)?;
    let _admin_lease = LifecycleLease::acquire(&config.data_dir, LeaseKind::AdminMutation)?;
    let _daemon_lease = LifecycleLease::acquire(&config.data_dir, LeaseKind::Daemon)
        .context("identity rotation requires the daemon to be stopped")?;
    let identity = NodeIdentity::load(&config.data_dir)?;
    let store = open_store(&config)?;
    let rotation_time = now()?;
    if !store
        .currently_trusted_peers(to_i64(rotation_time)?)?
        .is_empty()
    {
        bail!(
            "device identity rotation is refused while trusted peers exist; revoke them and restart before rotating"
        );
    }
    let local_actor = sha256(b"local-owner-confirmed-identity-rotation-v1");
    if let Some(pending) = store.pending_device_rotation()? {
        let staged = NodeIdentity::load_pending_rotation(&config.data_dir)?;
        let rotated = if identity.key_id().0 == pending.next_key_id {
            identity
        } else if identity.key_id().0 == pending.previous_key_id {
            let staged = staged.ok_or_else(|| anyhow!("pending rotation key file is missing"))?;
            if staged.key_id().0 != pending.next_key_id {
                bail!("pending rotation key does not match durable continuity record");
            }
            NodeIdentity::activate_pending_rotation(&config.data_dir)?;
            NodeIdentity::load(&config.data_dir)?
        } else {
            bail!("current identity does not match either side of pending rotation");
        };
        store.complete_device_rotation(
            pending.transaction_id,
            rotated.key_id().0,
            local_actor,
            to_i64(rotation_time)?,
        )?;
        let (binding, remainder): (RotationBindingV1, &[u8]) =
            postcard::take_from_bytes(&pending.continuity_binding)?;
        if !remainder.is_empty() {
            bail!("pending rotation continuity record contains trailing bytes");
        }
        return print_json(&serde_json::json!({
            "node_id": rotated.node_id().to_string(),
            "identity_fingerprint_sha256": rotated.fingerprint(),
            "rotation_binding": binding,
            "recovered_pending_rotation": true,
            "daemon_restart_required": true
        }));
    }
    let (rotated, binding) = identity.prepare_local_rotation(rotation_time, confirm)?;
    rotated.stage_pending_rotation(&config.data_dir)?;
    let continuity_binding = postcard::to_allocvec(&binding)?;
    let pending = PendingDeviceRotationV1 {
        schema_version: 1,
        transaction_id: Uuid::new_v4(),
        node_id: identity.node_id().to_string(),
        previous_key_id: identity.key_id().0,
        next_key_id: rotated.key_id().0,
        rotation_counter: rotated.cryptographic_identity().rotation_counter,
        continuity_digest: sha256(&continuity_binding),
        continuity_binding,
        started_at_unix_ms: to_i64(rotation_time)?,
    };
    store.begin_device_rotation(&pending, local_actor)?;
    NodeIdentity::activate_pending_rotation(&config.data_dir)?;
    let rotated = NodeIdentity::load(&config.data_dir)?;
    store.complete_device_rotation(
        pending.transaction_id,
        rotated.key_id().0,
        local_actor,
        to_i64(rotation_time)?,
    )?;
    print_json(&serde_json::json!({
        "node_id": rotated.node_id().to_string(),
        "identity_fingerprint_sha256": rotated.fingerprint(),
        "rotation_binding": binding,
        "daemon_restart_required": true
    }))
}

async fn serve(config_path: &Path) -> Result<()> {
    if !sovereign_node::security_platform_supported() {
        bail!("the hardened v0.1 daemon currently supports Unix security primitives only");
    }
    if sovereign_node::security_running_as_root() {
        bail!("the Sovereign Node daemon refuses to run as root");
    }
    let config = Arc::new(NodeConfig::load(config_path)?);
    let daemon_lease = LifecycleLease::acquire(&config.data_dir, LeaseKind::Daemon)
        .context("could not acquire the singleton daemon lease")?;
    let identity = Arc::new(NodeIdentity::load(&config.data_dir)?);
    let store = Arc::new(open_store(&config)?);
    store.verify_audit_chain()?;
    let startup_time = to_i64(now()?)?;
    if config.listen.is_some() {
        let maximum_clock_rollback_ms =
            i64::try_from(config.policy.max_clock_rollback_secs)?.saturating_mul(1_000);
        store
            .observe_trusted_clock_at(startup_time, maximum_clock_rollback_ms)
            .context(
                "remote authorization is blocked because the local clock is behind its durable checkpoint",
            )?;
    }
    let reconciled = store.reconcile_open_replays(&daemon_lease, startup_time)?;
    if reconciled > 0 {
        eprintln!(
            "reconciled {reconciled} prior open request(s) as Indeterminate; none were retried"
        );
    }

    if config.listen.is_none() {
        eprintln!(
            "Sovereign Node is running in local-only offline mode; no network listener is open"
        );
        tokio::signal::ctrl_c().await?;
        return Ok(());
    }

    let clock: Arc<dyn Clock> = Arc::new(SystemClock);
    let policy_digest = Sha256Digest(config.policy_digest()?);
    store.activate_policy(config.policy_version, policy_digest.0, to_i64(now()?)?)?;
    let authorization = AuthorizationEngine::new(
        identity.node_id(),
        store.clone(),
        clock.clone(),
        &config.policy,
        config.policy_version,
        policy_digest,
    );
    let resources = ResourceReporter::new(identity.node_id(), identity.device().clone());
    let executor = CapabilityExecutor::new(config.clone(), resources);
    let runtime = Arc::new(NodeRuntime::new(
        identity,
        authorization,
        executor,
        store.clone(),
        clock,
        RuntimeCapacity {
            max_concurrent_actions: config.policy.max_concurrent_actions,
            queue_capacity: config.policy.queue_capacity,
        },
        daemon_lease.clone(),
    ));
    sovereign_node::transport::serve_until_shutdown(
        config,
        store,
        runtime,
        tokio::signal::ctrl_c(),
    )
    .await?;
    Ok(())
}

fn pairing_context(
    config_path: &Path,
) -> Result<(
    NodeConfig,
    Arc<NodeIdentity>,
    Arc<StateStore>,
    LifecycleLease,
)> {
    let config = NodeConfig::load(config_path)?;
    let admin_lease = LifecycleLease::acquire(&config.data_dir, LeaseKind::AdminMutation)?;
    let identity = Arc::new(NodeIdentity::load(&config.data_dir)?);
    let store = Arc::new(open_store(&config)?);
    store.verify_audit_chain()?;
    Ok((config, identity, store, admin_lease))
}

fn open_store(config: &NodeConfig) -> Result<StateStore> {
    let defaults = StoreLimits::default();
    StateStore::open_with_policies(
        config.data_dir.join(STATE_DATABASE),
        StoreLimits {
            max_total_replays: config.storage.max_total_replays,
            max_active_audit_events: config.storage.max_active_audit_events,
            ..defaults
        },
        StoragePolicy {
            database_soft_bytes: config.storage.database_soft_bytes,
            database_hard_bytes: config.storage.database_hard_bytes,
            wal_hard_bytes: config.storage.wal_hard_bytes,
            minimum_free_bytes: config.storage.minimum_free_bytes,
            maintenance_reserve_bytes: config.storage.maintenance_reserve_bytes,
        },
    )
    .map_err(Into::into)
}

fn now() -> Result<UnixMillis> {
    let duration = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("system clock is before the Unix epoch")?;
    Ok(UnixMillis(u64::try_from(duration.as_millis())?))
}

fn to_i64(value: UnixMillis) -> Result<i64> {
    i64::try_from(value.0).context("system time is outside the supported range")
}

fn public_key(value: &str) -> Result<PublicKeyBytes> {
    let bytes = fixed_bytes::<32>(value, "Ed25519 public key")?;
    let key = VerifyingKey::from_bytes(&bytes).context("invalid Ed25519 public key")?;
    if key.is_weak() {
        bail!("weak Ed25519 public keys are not accepted");
    }
    Ok(PublicKeyBytes(bytes))
}

fn verifying_key_hex(value: &str, label: &str) -> Result<VerifyingKey> {
    let bytes = fixed_bytes::<32>(value, label)?;
    let key = VerifyingKey::from_bytes(&bytes).with_context(|| format!("invalid {label}"))?;
    if key.is_weak() {
        bail!("weak {label} is not accepted");
    }
    Ok(key)
}

fn signature(value: &str) -> Result<SignatureBytes> {
    let bytes = hex::decode(value).context("signature is not hexadecimal")?;
    SignatureBytes::from_slice(&bytes).map_err(Into::into)
}

fn fixed_bytes<const N: usize>(value: &str, label: &str) -> Result<[u8; N]> {
    let bytes = hex::decode(value).with_context(|| format!("{label} is not hexadecimal"))?;
    bytes
        .try_into()
        .map_err(|_| anyhow!("{label} must contain exactly {N} bytes"))
}

fn first_pem_certificate(path: &Path) -> Result<Vec<u8>> {
    let certificate = CertificateDer::from_pem_file(path)
        .with_context(|| format!("{} contains no valid certificate", path.display()))?;
    Ok(certificate.as_ref().to_vec())
}

fn pem_certificate_chain(path: &Path) -> Result<Vec<Vec<u8>>> {
    let certificates = CertificateDer::pem_file_iter(path)
        .with_context(|| format!("{} could not be opened", path.display()))?
        .map(|certificate| {
            certificate
                .map(|certificate| certificate.as_ref().to_vec())
                .with_context(|| format!("{} contains an invalid certificate", path.display()))
        })
        .collect::<Result<Vec<_>>>()?;
    if certificates.is_empty() {
        bail!("{} contains no valid certificate", path.display());
    }
    Ok(certificates)
}

fn parse_capability(value: &str) -> Result<Capability> {
    match value {
        "SystemInfo" => Ok(Capability::SystemInfo),
        "ResourceStatus" => Ok(Capability::ResourceStatus),
        "FileRead" => Ok(Capability::FileRead),
        "FileWrite" => Ok(Capability::FileWrite),
        "ProcessStatus" => Ok(Capability::ProcessStatus),
        "ServiceStatus" => Ok(Capability::ServiceStatus),
        "ExecuteApprovedAction" => Ok(Capability::ExecuteApprovedAction),
        "GPUStatus" | "GpuStatus" => Ok(Capability::GpuStatus),
        "EngineStatus" => Ok(Capability::EngineStatus),
        "ModelStatus" => Ok(Capability::ModelStatus),
        "RepositoryStatus" => Ok(Capability::RepositoryStatus),
        "AgentGreenHealth" => Ok(Capability::AgentGreenHealth),
        "ActionBrokerHealth" => Ok(Capability::ActionBrokerHealth),
        _ => bail!("unknown capability {value:?}"),
    }
}

fn require_absolute(path: &Path, label: &str) -> Result<()> {
    if path.is_absolute() {
        Ok(())
    } else {
        bail!("{label} must be an absolute path")
    }
}

fn print_json(value: &impl Serialize) -> Result<()> {
    println!("{}", serde_json::to_string_pretty(value)?);
    Ok(())
}
