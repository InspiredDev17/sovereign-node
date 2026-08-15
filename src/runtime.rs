use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};

use sha2::{Digest, Sha256};
use thiserror::Error;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

use crate::authz::{
    AuthorizationEngine, AuthorizationError, AuthorizationOutcome, Clock, TransportPeer,
};
use crate::capabilities::{CapabilityError, CapabilityExecutor};
use crate::identity::{IdentityError, NodeIdentity};
use crate::lifecycle::LifecycleLease;
use crate::protocol::{
    ActionErrorCode, ActionErrorV1, ActionResponseV1, ActionStatus, PROTOCOL_VERSION_V1, RequestId,
    SCHEMA_VERSION_V1, SignedActionResponseV1, SignedActionV1, TaskId, TrustStatus, UnixMillis,
};
use crate::resources::QueueSnapshot;
use crate::store::{
    StateStore, StoragePressure, StoreError, TerminalResponseMetadata, TerminalStatus,
};

#[derive(Debug, Error)]
pub enum RuntimeError {
    #[error("runtime clock is unavailable")]
    Clock(#[from] AuthorizationError),
    #[error("response could not be encoded")]
    Encoding,
    #[error("response could not be signed")]
    Identity(#[from] IdentityError),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RuntimeCapacity {
    pub max_concurrent_actions: usize,
    pub queue_capacity: usize,
}

#[derive(Debug)]
pub struct NodeRuntime {
    identity: Arc<NodeIdentity>,
    authorization: AuthorizationEngine,
    executor: CapabilityExecutor,
    store: Arc<StateStore>,
    clock: Arc<dyn Clock>,
    concurrency: Arc<Semaphore>,
    admitted: AtomicU32,
    running: AtomicU32,
    queue_capacity: u32,
    /// Every connection task holds the runtime, so the daemon lease outlives all dispatch work.
    _daemon_lease: LifecycleLease,
}

impl NodeRuntime {
    #[must_use]
    pub fn new(
        identity: Arc<NodeIdentity>,
        authorization: AuthorizationEngine,
        executor: CapabilityExecutor,
        store: Arc<StateStore>,
        clock: Arc<dyn Clock>,
        capacity: RuntimeCapacity,
        daemon_lease: LifecycleLease,
    ) -> Self {
        Self {
            identity,
            authorization,
            executor,
            store,
            clock,
            concurrency: Arc::new(Semaphore::new(capacity.max_concurrent_actions)),
            admitted: AtomicU32::new(0),
            running: AtomicU32::new(0),
            queue_capacity: u32::try_from(capacity.queue_capacity).unwrap_or(u32::MAX),
            _daemon_lease: daemon_lease,
        }
    }

    pub async fn handle(
        &self,
        action: SignedActionV1,
        peer: &TransportPeer,
    ) -> Result<SignedActionResponseV1, RuntimeError> {
        if let Some(response) = self.storage_pressure_response(&action)? {
            return Ok(response);
        }
        let request_id = action.request.request_id;
        let task_id = action.request.task_id;
        let Some(admission) = self.try_admit() else {
            return self.sign_response(self.rejection(
                request_id,
                task_id,
                ActionStatus::Rejected,
                ActionErrorCode::ResourceExhausted,
                "node action queue is full",
                true,
                None,
            )?);
        };

        // Admission occurs before durable replay reservation. A temporarily full queue never burns
        // a valid request ID, while all authorization failures remain side-effect free.
        let permit = self.concurrency.clone().acquire_owned().await;
        let permit = match permit {
            Ok(permit) => permit,
            Err(_) => {
                drop(admission);
                return self.sign_response(self.rejection(
                    request_id,
                    task_id,
                    ActionStatus::Failed,
                    ActionErrorCode::Internal,
                    "node runtime is shutting down",
                    true,
                    None,
                )?);
            }
        };

        let authorized = match self.authorization.verify_and_reserve(action, peer) {
            Ok(AuthorizationOutcome::Fresh(action)) => action,
            Ok(AuthorizationOutcome::Duplicate) => {
                drop(permit);
                drop(admission);
                return self.sign_response(self.rejection(
                    request_id,
                    task_id,
                    ActionStatus::Duplicate,
                    ActionErrorCode::DuplicateRequest,
                    "request was already reserved and will not be executed again",
                    false,
                    None,
                )?);
            }
            Err(error) => {
                let code = error.code();
                let retryable = matches!(
                    code,
                    ActionErrorCode::ResourceExhausted | ActionErrorCode::Internal
                );
                drop(permit);
                drop(admission);
                return self.sign_response(self.rejection(
                    request_id,
                    task_id,
                    ActionStatus::Rejected,
                    code,
                    safe_authorization_message(&error),
                    retryable,
                    None,
                )?);
            }
        };

        self.running.fetch_add(1, Ordering::AcqRel);
        let running_guard = RunningGuard {
            running: &self.running,
            _permit: permit,
        };
        let started_at = self.clock.now()?;
        if authorized
            .request()
            .validate_execution_time(started_at)
            .is_err()
        {
            let response = self.rejection(
                request_id,
                task_id,
                ActionStatus::Expired,
                ActionErrorCode::ExpiredAuthorization,
                "authorization expired while waiting for local capacity",
                false,
                Some(started_at),
            )?;
            let signed = self.sign_response(response)?;
            let terminal = TerminalResponseMetadata {
                status: TerminalStatus::Expired,
                response_digest: signed.response_digest.0,
                redacted_error_digest: signed
                    .response
                    .error
                    .as_ref()
                    .map(|error| Sha256::digest(error.message.as_bytes()).into()),
                response_size_bytes: u64::try_from(
                    postcard::to_allocvec(&signed.response)
                        .map_err(|_| RuntimeError::Encoding)?
                        .len(),
                )
                .unwrap_or(u64::MAX),
                completed_at_unix_ms: i64::try_from(started_at.0)
                    .map_err(|_| RuntimeError::Encoding)?,
            };
            self.store
                .record_terminal_response(request_id.0, authorized.replay_fingerprint(), &terminal)
                .map_err(|_| RuntimeError::Encoding)?;
            drop(running_guard);
            drop(admission);
            return Ok(signed);
        }

        let started_at_unix_ms = i64::try_from(started_at.0).map_err(|_| RuntimeError::Encoding)?;
        if self
            .store
            .record_execution_started(
                request_id.0,
                authorized.replay_fingerprint(),
                authorized.action_context_digest(),
                started_at_unix_ms,
            )
            .is_err()
        {
            // Execution-start audit persistence is a hard pre-dispatch gate. The request remains
            // spent, no capability handler is called, and terminal recording is best-effort when
            // the underlying store failure still permits it.
            let response = self.rejection(
                request_id,
                task_id,
                ActionStatus::Failed,
                ActionErrorCode::Internal,
                "execution-start audit persistence failed; action was not executed",
                false,
                None,
            )?;
            let signed = self.sign_response(response)?;
            let terminal = TerminalResponseMetadata {
                status: TerminalStatus::Failed,
                response_digest: signed.response_digest.0,
                redacted_error_digest: signed
                    .response
                    .error
                    .as_ref()
                    .map(|error| Sha256::digest(error.message.as_bytes()).into()),
                response_size_bytes: u64::try_from(
                    postcard::to_allocvec(&signed.response)
                        .map_err(|_| RuntimeError::Encoding)?
                        .len(),
                )
                .unwrap_or(u64::MAX),
                completed_at_unix_ms: started_at_unix_ms,
            };
            let _ = self.store.record_terminal_response(
                request_id.0,
                authorized.replay_fingerprint(),
                &terminal,
            );
            drop(running_guard);
            drop(admission);
            return Ok(signed);
        }
        let queue = self.queue_snapshot(true);
        let executed = self
            .executor
            .execute(&authorized, started_at, queue, TrustStatus::Trusted)
            .await;
        let finished_at = self.clock.now()?;
        let response = match executed {
            Ok(result) => ActionResponseV1 {
                schema_version: SCHEMA_VERSION_V1,
                protocol_version: PROTOCOL_VERSION_V1,
                request_id,
                task_id,
                node_id: self.identity.node_id(),
                status: ActionStatus::Succeeded,
                result: Some(result),
                error: None,
                started_at: Some(started_at),
                finished_at,
            },
            Err(error) => self.rejection(
                request_id,
                task_id,
                ActionStatus::Failed,
                error.code(),
                safe_capability_message(&error),
                false,
                Some(started_at),
            )?,
        };
        let signed = self.sign_response(response)?;

        let terminal = TerminalResponseMetadata {
            status: match signed.response.status {
                ActionStatus::Succeeded => TerminalStatus::Succeeded,
                ActionStatus::Rejected => TerminalStatus::Rejected,
                ActionStatus::Expired => TerminalStatus::Expired,
                ActionStatus::Failed => TerminalStatus::Failed,
                ActionStatus::Accepted | ActionStatus::Running | ActionStatus::Duplicate => {
                    TerminalStatus::Failed
                }
            },
            response_digest: signed.response_digest.0,
            redacted_error_digest: signed
                .response
                .error
                .as_ref()
                .map(|error| Sha256::digest(error.message.as_bytes()).into()),
            response_size_bytes: u64::try_from(
                postcard::to_allocvec(&signed.response)
                    .map_err(|_| RuntimeError::Encoding)?
                    .len(),
            )
            .unwrap_or(u64::MAX),
            completed_at_unix_ms: i64::try_from(finished_at.0)
                .map_err(|_| RuntimeError::Encoding)?,
        };
        if self
            .store
            .record_terminal_response(request_id.0, authorized.replay_fingerprint(), &terminal)
            .is_err()
        {
            // The request remains durably spent. Report indeterminate storage failure and never
            // retry automatically; a local operator must inspect the audit/state store.
            drop(running_guard);
            drop(admission);
            return self.sign_response(self.rejection(
                request_id,
                task_id,
                ActionStatus::Failed,
                ActionErrorCode::Internal,
                "action completed but terminal audit persistence failed; request remains spent",
                false,
                Some(started_at),
            )?);
        }
        drop(running_guard);
        drop(admission);
        Ok(signed)
    }

    /// Produce a bounded node-signed denial without consuming request, rate,
    /// replay, or audit capacity. Transport calls this before its durable rate
    /// counters so disk pressure cannot amplify itself through denial writes.
    pub fn storage_pressure_response(
        &self,
        action: &SignedActionV1,
    ) -> Result<Option<SignedActionResponseV1>, RuntimeError> {
        match self.store.storage_pressure() {
            Ok(StoragePressure::Healthy) => Ok(None),
            Ok(StoragePressure::Soft | StoragePressure::Hard) | Err(_) => self
                .sign_response(self.rejection(
                    action.request.request_id,
                    action.request.task_id,
                    ActionStatus::Rejected,
                    ActionErrorCode::StoragePressure,
                    "node storage maintenance is required before remote work can continue",
                    true,
                    None,
                )?)
                .map(Some),
        }
    }

    #[must_use]
    pub fn queue_snapshot(&self, accepting_remote_work: bool) -> QueueSnapshot {
        let admitted = self.admitted.load(Ordering::Acquire);
        let running = self.running.load(Ordering::Acquire);
        QueueSnapshot {
            queued: admitted.saturating_sub(running),
            running,
            capacity: self.queue_capacity,
            accepting_remote_work,
        }
    }

    fn try_admit(&self) -> Option<AdmissionGuard<'_>> {
        let mut current = self.admitted.load(Ordering::Acquire);
        loop {
            if current >= self.queue_capacity {
                return None;
            }
            match self.admitted.compare_exchange_weak(
                current,
                current.saturating_add(1),
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => {
                    return Some(AdmissionGuard {
                        admitted: &self.admitted,
                    });
                }
                Err(updated) => current = updated,
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn rejection(
        &self,
        request_id: RequestId,
        task_id: TaskId,
        status: ActionStatus,
        code: ActionErrorCode,
        message: &str,
        retryable: bool,
        started_at: Option<UnixMillis>,
    ) -> Result<ActionResponseV1, RuntimeError> {
        let response = ActionResponseV1 {
            schema_version: SCHEMA_VERSION_V1,
            protocol_version: PROTOCOL_VERSION_V1,
            request_id,
            task_id,
            node_id: self.identity.node_id(),
            status,
            result: None,
            error: Some(ActionErrorV1 {
                code,
                message: message.to_owned(),
                retryable,
            }),
            started_at,
            finished_at: self.clock.now()?,
        };
        response.validate().map_err(|_| RuntimeError::Encoding)?;
        Ok(response)
    }

    fn sign_response(
        &self,
        response: ActionResponseV1,
    ) -> Result<SignedActionResponseV1, RuntimeError> {
        response.validate().map_err(|_| RuntimeError::Encoding)?;
        let response_digest = response.digest().map_err(|_| RuntimeError::Encoding)?;
        let signature = self.identity.sign(
            &response
                .signing_bytes()
                .map_err(|_| RuntimeError::Encoding)?,
        )?;
        Ok(SignedActionResponseV1 {
            response,
            response_digest,
            node_signature: signature,
        })
    }
}

struct AdmissionGuard<'a> {
    admitted: &'a AtomicU32,
}

impl Drop for AdmissionGuard<'_> {
    fn drop(&mut self) {
        self.admitted.fetch_sub(1, Ordering::AcqRel);
    }
}

struct RunningGuard<'a> {
    running: &'a AtomicU32,
    _permit: OwnedSemaphorePermit,
}

impl Drop for RunningGuard<'_> {
    fn drop(&mut self) {
        self.running.fetch_sub(1, Ordering::AcqRel);
    }
}

fn safe_authorization_message(error: &AuthorizationError) -> &'static str {
    match error {
        AuthorizationError::WrongNode => "authorization is for a different node",
        AuthorizationError::Expired => "authorization has expired",
        AuthorizationError::NotYetValid => "authorization is not yet valid",
        AuthorizationError::Duplicate => "request is a duplicate",
        AuthorizationError::ReplayCollision => "request replay protection was triggered",
        AuthorizationError::CapabilityNotAdvertised
        | AuthorizationError::CapabilityNotPaired
        | AuthorizationError::CapabilityMismatch => "capability is not authorized locally",
        AuthorizationError::Store(StoreError::ResourceLimit(_)) => {
            "authorization state is at capacity"
        }
        AuthorizationError::Store(_) | AuthorizationError::Clock => {
            "authorization state is unavailable"
        }
        _ => "authorization could not be verified",
    }
}

fn safe_capability_message(error: &CapabilityError) -> &'static str {
    match error {
        CapabilityError::TargetNotAllowed => "target is not locally allowlisted",
        CapabilityError::UnauthorizedFileAccess => "file access is not authorized",
        CapabilityError::ArgumentMismatch => "capability arguments do not match local policy",
        CapabilityError::Unsupported => "capability adapter is not configured",
        CapabilityError::Execution => "configured local status adapter failed",
        CapabilityError::ResourceExhausted => "capability exceeded a local resource limit",
    }
}
