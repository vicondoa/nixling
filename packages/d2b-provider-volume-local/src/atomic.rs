//! Durable generation-bound state replacement over an injected filesystem.
//!
//! The sequencing retains the historical temp-write, temp-fsync, atomic
//! replace, and parent-fsync protocol. This Provider never opens a host path;
//! a core adapter implements [`AtomicFilesystem`] for an anchored Volume view.

use std::fmt;

use d2b_contracts_resource::v3::{
    MAX_STATE_DOCUMENT_BYTES, ResourceUid, StateEnvelope, VolumeStateError, canonical_json_bytes,
};
use serde::{Serialize, de::DeserializeOwned};

use crate::lock::{LockError, LockGuard};

/// One durable-write phase, in required order.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum AtomicWritePhase {
    /// No temporary object exists.
    Initial,
    /// The temporary object was created beneath the anchored parent.
    TemporaryCreated,
    /// The complete canonical document was written.
    CompleteDocumentWritten,
    /// The temporary object was durably synchronized.
    TemporarySynced,
    /// The temporary object atomically replaced the target.
    Replaced,
    /// The anchored parent directory was durably synchronized.
    ParentSynced,
}

/// A successful durable replacement receipt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AtomicWriteReceipt {
    /// The component-local state generation committed by the write.
    pub generation: u64,
    /// The terminal durable-write phase.
    pub phase: AtomicWritePhase,
    /// Number of canonical document bytes committed.
    pub encoded_bytes: usize,
}

/// Receipt for one atomically replaced raw file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RawWriteReceipt {
    /// The terminal durable-write phase.
    pub phase: AtomicWritePhase,
    /// Number of bytes committed.
    pub encoded_bytes: usize,
}

/// A closed, content-free atomic state failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AtomicWriteError {
    /// The v3 state envelope contract rejected the document.
    StateContract(VolumeStateError),
    /// The next generation was not exactly the expected successor.
    GenerationMismatch,
    /// The held lock did not protect this Volume.
    LockInvalid,
    /// The resulting document would exceed the declared soft quota.
    QuotaExceeded,
    /// The adapter failed before atomic replacement.
    EffectFailed,
    /// Replacement completed but parent synchronization failed, so the
    /// durable result is ambiguous and must be reconciled before retry.
    CommitAmbiguous,
    /// A stored document was not canonical JSON.
    NonCanonical,
}

impl AtomicWriteError {
    /// Return the stable, redacted error code.
    pub const fn code(self) -> &'static str {
        match self {
            Self::StateContract(error) => error.code(),
            Self::GenerationMismatch => "volume-state-generation-mismatch",
            Self::LockInvalid => "volume-state-lock-invalid",
            Self::QuotaExceeded => "volume-quota-exceeded",
            Self::EffectFailed => "volume-state-effect-failed",
            Self::CommitAmbiguous => "volume-state-commit-ambiguous",
            Self::NonCanonical => "volume-state-non-canonical",
        }
    }
}

impl fmt::Display for AtomicWriteError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code())
    }
}

impl std::error::Error for AtomicWriteError {}

impl From<VolumeStateError> for AtomicWriteError {
    fn from(error: VolumeStateError) -> Self {
        Self::StateContract(error)
    }
}

impl From<LockError> for AtomicWriteError {
    fn from(_error: LockError) -> Self {
        Self::LockInvalid
    }
}

/// Canonical JSON encoding with the state-document byte ceiling.
pub struct CanonicalJson;

impl CanonicalJson {
    /// Encode one value using the resource-plane canonical JSON profile.
    pub fn encode<T: Serialize>(value: &T) -> Result<Vec<u8>, AtomicWriteError> {
        let bytes = canonical_json_bytes(value).map_err(VolumeStateError::from)?;
        if bytes.is_empty() || bytes.len() > MAX_STATE_DOCUMENT_BYTES {
            return Err(AtomicWriteError::StateContract(
                VolumeStateError::DocumentTooLarge,
            ));
        }
        Ok(bytes)
    }

    /// Decode and prove exact canonical re-encoding.
    pub fn decode<T: DeserializeOwned + Serialize>(bytes: &[u8]) -> Result<T, AtomicWriteError> {
        if bytes.is_empty() || bytes.len() > MAX_STATE_DOCUMENT_BYTES {
            return Err(AtomicWriteError::StateContract(
                VolumeStateError::DocumentTooLarge,
            ));
        }
        let value = serde_json::from_slice(bytes).map_err(|_| AtomicWriteError::NonCanonical)?;
        if Self::encode(&value)? != bytes {
            return Err(AtomicWriteError::NonCanonical);
        }
        Ok(value)
    }
}

/// Filesystem operations required for one anchored durable state document.
pub trait AtomicFilesystem {
    /// Adapter-owned temporary object.
    type Temp;

    /// Borrow the Volume identity this target belongs to.
    fn resource_uid(&self) -> &ResourceUid;
    /// Read the current target, bounded by `maximum` bytes.
    fn read_target(&mut self, maximum: usize) -> Result<Vec<u8>, AtomicWriteError>;
    /// Return the installed component-local generation, if a target exists.
    fn current_generation(&mut self) -> Result<Option<u64>, AtomicWriteError>;
    /// Return current charged bytes before replacing the target.
    fn current_charged_bytes(&mut self) -> Result<u64, AtomicWriteError>;
    /// Return the target bytes currently included in that charge.
    fn current_target_bytes(&mut self) -> Result<u64, AtomicWriteError>;
    /// Create a same-parent temporary object with close-on-exec semantics.
    fn create_temp(&mut self) -> Result<Self::Temp, AtomicWriteError>;
    /// Append bytes to the temporary object.
    fn write_temp(
        &mut self,
        temp: &mut Self::Temp,
        bytes: &[u8],
    ) -> Result<usize, AtomicWriteError>;
    /// Apply exact single-inode metadata before publication.
    ///
    /// Backends that do not carry host ownership metadata may leave the
    /// default implementation unchanged; production anchored backends must
    /// apply the declared owner, group, and mode to the temporary inode.
    fn set_temp_metadata(
        &mut self,
        _temp: &mut Self::Temp,
        _owner: u32,
        _group: u32,
        _mode: u32,
    ) -> Result<(), AtomicWriteError> {
        Ok(())
    }
    /// Synchronize the complete temporary object.
    fn sync_temp(&mut self, temp: &mut Self::Temp) -> Result<(), AtomicWriteError>;
    /// Atomically replace the target from the temporary object.
    fn replace_temp(&mut self, temp: &mut Self::Temp) -> Result<(), AtomicWriteError>;
    /// Synchronize the anchored parent directory.
    fn sync_parent(&mut self) -> Result<(), AtomicWriteError>;
    /// Remove an uncommitted temporary object.
    fn remove_temp(&mut self, temp: &mut Self::Temp);
}

/// Replace one raw file using the same temp-fsync, rename, and parent-fsync
/// sequence as [`AtomicWrite`].
pub fn replace_bytes<F: AtomicFilesystem>(
    filesystem: &mut F,
    bytes: &[u8],
    owner: u32,
    group: u32,
    mode: u32,
) -> Result<RawWriteReceipt, AtomicWriteError> {
    let mut temp = filesystem.create_temp()?;
    let mut phase = AtomicWritePhase::TemporaryCreated;
    let result = (|| {
        let mut written = 0usize;
        while written < bytes.len() {
            let count = filesystem.write_temp(&mut temp, &bytes[written..])?;
            if count == 0 {
                return Err(AtomicWriteError::EffectFailed);
            }
            written = written
                .checked_add(count)
                .ok_or(AtomicWriteError::EffectFailed)?;
        }
        phase = AtomicWritePhase::CompleteDocumentWritten;
        filesystem.set_temp_metadata(&mut temp, owner, group, mode)?;
        filesystem.sync_temp(&mut temp)?;
        phase = AtomicWritePhase::TemporarySynced;
        filesystem.replace_temp(&mut temp)?;
        phase = AtomicWritePhase::Replaced;
        filesystem
            .sync_parent()
            .map_err(|_| AtomicWriteError::CommitAmbiguous)?;
        phase = AtomicWritePhase::ParentSynced;
        Ok(RawWriteReceipt {
            phase,
            encoded_bytes: bytes.len(),
        })
    })();
    if result.is_err() && phase < AtomicWritePhase::Replaced {
        filesystem.remove_temp(&mut temp);
    }
    result
}

/// Generation and quota policy for one state write.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WritePolicy {
    /// Expected installed generation, or `None` for first creation.
    pub expected_previous: Option<u64>,
    /// Optional maximum charged bytes for soft quota enforcement.
    pub quota_bytes: Option<u64>,
}

/// Atomic state access over one injected anchored filesystem.
pub struct AtomicWrite<F> {
    filesystem: F,
}

impl<F: AtomicFilesystem> AtomicWrite<F> {
    /// Build state access over an injected filesystem adapter.
    pub const fn new(filesystem: F) -> Self {
        Self { filesystem }
    }

    /// Read a canonical envelope and verify its payload before exposure.
    pub fn read<T>(&mut self) -> Result<StateEnvelope<T>, AtomicWriteError>
    where
        T: DeserializeOwned + Serialize,
    {
        let bytes = self
            .filesystem
            .read_target(MAX_STATE_DOCUMENT_BYTES.saturating_add(1))?;
        let envelope: StateEnvelope<T> = CanonicalJson::decode(&bytes)?;
        envelope.validate_digest()?;
        Ok(envelope)
    }

    /// Validate and durably replace one state envelope.
    ///
    /// Digest validation occurs before any filesystem observation or mutation.
    /// Until the shared contract freezes a Provider-state digest domain this
    /// returns `volume-state-digest-domain-unavailable` without an effect.
    pub fn write<T: Serialize>(
        &mut self,
        envelope: &StateEnvelope<T>,
        policy: WritePolicy,
        guard: &LockGuard,
    ) -> Result<AtomicWriteReceipt, AtomicWriteError> {
        envelope.validate_digest()?;
        guard.validate_resource(self.filesystem.resource_uid())?;
        validate_generation(
            self.filesystem.current_generation()?,
            policy.expected_previous,
            envelope.generation(),
        )?;
        let document = CanonicalJson::encode(envelope)?;
        if let Some(quota) = policy.quota_bytes {
            check_soft_quota(
                self.filesystem.current_charged_bytes()?,
                self.filesystem.current_target_bytes()?,
                document.len() as u64,
                quota,
            )?;
        }
        self.commit_document(envelope.generation(), &document)
    }

    /// Consume the wrapper and return the injected filesystem.
    pub fn into_inner(self) -> F {
        self.filesystem
    }

    fn commit_document(
        &mut self,
        generation: u64,
        document: &[u8],
    ) -> Result<AtomicWriteReceipt, AtomicWriteError> {
        let mut temp = self.filesystem.create_temp()?;
        let mut phase = AtomicWritePhase::TemporaryCreated;
        let result = (|| {
            let mut written = 0usize;
            while written < document.len() {
                let count = self
                    .filesystem
                    .write_temp(&mut temp, &document[written..])?;
                if count == 0 {
                    return Err(AtomicWriteError::EffectFailed);
                }
                written = written
                    .checked_add(count)
                    .ok_or(AtomicWriteError::EffectFailed)?;
            }
            phase = AtomicWritePhase::CompleteDocumentWritten;
            self.filesystem.sync_temp(&mut temp)?;
            phase = AtomicWritePhase::TemporarySynced;
            self.filesystem.replace_temp(&mut temp)?;
            phase = AtomicWritePhase::Replaced;
            self.filesystem
                .sync_parent()
                .map_err(|_| AtomicWriteError::CommitAmbiguous)?;
            phase = AtomicWritePhase::ParentSynced;
            Ok(AtomicWriteReceipt {
                generation,
                phase,
                encoded_bytes: document.len(),
            })
        })();
        if result.is_err() && phase < AtomicWritePhase::Replaced {
            self.filesystem.remove_temp(&mut temp);
        }
        result
    }
}

/// Enforce a replacement-aware soft byte quota.
pub fn check_soft_quota(
    current_charged_bytes: u64,
    replaced_target_bytes: u64,
    new_target_bytes: u64,
    quota_bytes: u64,
) -> Result<(), AtomicWriteError> {
    let projected = current_charged_bytes
        .checked_sub(replaced_target_bytes)
        .and_then(|remaining| remaining.checked_add(new_target_bytes))
        .ok_or(AtomicWriteError::QuotaExceeded)?;
    if quota_bytes == 0 || projected > quota_bytes {
        return Err(AtomicWriteError::QuotaExceeded);
    }
    Ok(())
}

fn validate_generation(
    observed: Option<u64>,
    expected_previous: Option<u64>,
    next: u64,
) -> Result<(), AtomicWriteError> {
    if observed != expected_previous
        || match expected_previous {
            Some(previous) => previous.checked_add(1) != Some(next),
            None => next != 1,
        }
    {
        return Err(AtomicWriteError::GenerationMismatch);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;

    struct ScriptedFilesystem {
        uid: ResourceUid,
        calls: Vec<&'static str>,
        writes: Vec<u8>,
        chunks: VecDeque<usize>,
        parent_fails: bool,
    }

    impl ScriptedFilesystem {
        fn new() -> Self {
            Self {
                uid: ResourceUid::parse("6f9619ff-8b86-4d01-b42d-00cf4fc964ff").unwrap(),
                calls: Vec::new(),
                writes: Vec::new(),
                chunks: VecDeque::from([2, 3, usize::MAX]),
                parent_fails: false,
            }
        }
    }

    impl AtomicFilesystem for ScriptedFilesystem {
        type Temp = ();

        fn resource_uid(&self) -> &ResourceUid {
            &self.uid
        }
        fn read_target(&mut self, _maximum: usize) -> Result<Vec<u8>, AtomicWriteError> {
            Err(AtomicWriteError::EffectFailed)
        }
        fn current_generation(&mut self) -> Result<Option<u64>, AtomicWriteError> {
            Ok(None)
        }
        fn current_charged_bytes(&mut self) -> Result<u64, AtomicWriteError> {
            Ok(0)
        }
        fn current_target_bytes(&mut self) -> Result<u64, AtomicWriteError> {
            Ok(0)
        }
        fn create_temp(&mut self) -> Result<Self::Temp, AtomicWriteError> {
            self.calls.push("create");
            Ok(())
        }
        fn write_temp(
            &mut self,
            _temp: &mut Self::Temp,
            bytes: &[u8],
        ) -> Result<usize, AtomicWriteError> {
            self.calls.push("write");
            let count = self
                .chunks
                .pop_front()
                .unwrap_or(bytes.len())
                .min(bytes.len());
            self.writes.extend_from_slice(&bytes[..count]);
            Ok(count)
        }
        fn sync_temp(&mut self, _temp: &mut Self::Temp) -> Result<(), AtomicWriteError> {
            self.calls.push("sync-temp");
            Ok(())
        }
        fn replace_temp(&mut self, _temp: &mut Self::Temp) -> Result<(), AtomicWriteError> {
            self.calls.push("replace");
            Ok(())
        }
        fn sync_parent(&mut self) -> Result<(), AtomicWriteError> {
            self.calls.push("sync-parent");
            if self.parent_fails {
                Err(AtomicWriteError::EffectFailed)
            } else {
                Ok(())
            }
        }
        fn remove_temp(&mut self, _temp: &mut Self::Temp) {
            self.calls.push("remove");
        }
    }

    #[test]
    fn durable_sequence_handles_short_writes_in_order() {
        let mut write = AtomicWrite::new(ScriptedFilesystem::new());
        let receipt = write.commit_document(1, b"abcdef").unwrap();
        assert_eq!(receipt.phase, AtomicWritePhase::ParentSynced);
        let filesystem = write.into_inner();
        assert_eq!(filesystem.writes, b"abcdef");
        assert_eq!(
            filesystem.calls,
            [
                "create",
                "write",
                "write",
                "write",
                "sync-temp",
                "replace",
                "sync-parent"
            ]
        );
    }

    #[test]
    fn parent_sync_failure_is_ambiguous_and_never_removes_the_replaced_temp() {
        let mut filesystem = ScriptedFilesystem::new();
        filesystem.parent_fails = true;
        let mut write = AtomicWrite::new(filesystem);
        assert_eq!(
            write.commit_document(1, b"state"),
            Err(AtomicWriteError::CommitAmbiguous)
        );
        assert!(!write.into_inner().calls.contains(&"remove"));
    }

    #[test]
    fn replacement_aware_quota_rejects_overage() {
        assert!(check_soft_quota(90, 20, 25, 100).is_ok());
        assert_eq!(
            check_soft_quota(90, 20, 31, 100),
            Err(AtomicWriteError::QuotaExceeded)
        );
    }
}
