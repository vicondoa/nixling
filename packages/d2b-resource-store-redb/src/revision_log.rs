//! Revision-log replay and bounded watch admission.
//!
//! The Zone resource API owns the named-stream protocol.  This module owns
//! the storage-side cursor, replay, and delivery accounting primitives that
//! protocol uses.  The writer actor calls these functions while it owns the
//! ordering boundary, so a replay can be registered before the next commit is
//! dispatched without opening a replay/live gap.

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::sync::Arc;

use d2b_contracts_resource::v3::{ResourceName, ResourceTypeName, ZoneRevision};
use d2b_resource_store::{StoreError, StoreFilter};
use redb::{Database, ReadableDatabase};
use tokio::sync::mpsc;

use crate::actor::{SharedChangeBatch, filter_batch_with};
use crate::transaction::{
    ChangeBatch, REVISION_LOG, decode, read_meta, revision_key, set_full_durability,
};
use crate::{DecodedKey, DecodedKeyComponent};

/// One global bounded admission budget for queued watch deliveries.
pub const WATCH_ADMISSION_CAPACITY: usize = 1024;
/// Maximum initial credit window accepted for one watch.
pub const MAX_INITIAL_WATCH_CREDITS: u32 = WATCH_ADMISSION_CAPACITY as u32;
/// Maximum retained resume cursors after deterministic slow-watcher eviction.
pub const MAX_RETAINED_RESUME_CURSORS: usize = WATCH_ADMISSION_CAPACITY;
/// Maximum simultaneously registered watches.
pub const MAX_WATCH_REGISTRATIONS: usize = WATCH_ADMISSION_CAPACITY;
/// Maximum revision rows removed by one compaction transaction.
pub const MAX_COMPACTION_ROWS_PER_TRANSACTION: usize = 256;
/// Maximum encoded key/value bytes removed by one compaction transaction.
pub const MAX_COMPACTION_BYTES_PER_TRANSACTION: usize = 8 * 1024 * 1024;

/// A closed selector carried by one watch registration.
#[derive(Clone, PartialEq, Eq)]
pub struct WatchSelector {
    resource_types: BTreeSet<ResourceTypeName>,
    resource_names: BTreeSet<ResourceName>,
    filters: Vec<StoreFilter>,
}

impl core::fmt::Debug for WatchSelector {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("WatchSelector")
            .field("resource_type_count", &self.resource_types.len())
            .field("resource_name_count", &self.resource_names.len())
            .field("filter_count", &self.filters.len())
            .finish()
    }
}

impl WatchSelector {
    /// Construct a selector without retaining caller-owned collection order.
    pub fn new(
        resource_types: impl IntoIterator<Item = ResourceTypeName>,
        resource_names: impl IntoIterator<Item = ResourceName>,
        filters: impl IntoIterator<Item = StoreFilter>,
    ) -> Self {
        let resource_types = resource_types.into_iter().collect::<BTreeSet<_>>();
        let resource_names = resource_names.into_iter().collect::<BTreeSet<_>>();
        let mut filters = filters.into_iter().collect::<Vec<_>>();
        filters.sort_by(|left, right| {
            left.field
                .cmp(&right.field)
                .then_with(|| left.values.cmp(&right.values))
        });
        Self {
            resource_types,
            resource_names,
            filters,
        }
    }

    /// Match one persisted change without inspecting its payload.
    pub(crate) fn matches(&self, entry: &crate::transaction::ChangeEntry) -> bool {
        if !self.resource_types.is_empty() && !self.resource_types.contains(entry.resource_type()) {
            return false;
        }
        if !self.resource_names.is_empty() && !self.resource_names.contains(entry.resource_name()) {
            return false;
        }
        self.filters
            .iter()
            .all(|filter| match filter.field.as_str() {
                "metadata.name" => filter
                    .values
                    .iter()
                    .any(|value| value == entry.resource_name().as_str()),
                "type" => filter
                    .values
                    .iter()
                    .any(|value| value == entry.resource_type().as_str()),
                "assignment.resourceUid" => filter
                    .values
                    .iter()
                    .any(|value| value == entry.resource_uid().as_str()),
                "owner.resourceUid" => filter.values.iter().any(|value| {
                    entry
                        .owner_uid()
                        .is_some_and(|owner_uid| value == owner_uid.as_str())
                }),
                "resource-or-owner.type" => filter.values.iter().any(|value| {
                    value == entry.resource_type().as_str()
                        || entry
                            .owner_ref()
                            .is_some_and(|owner| value == owner.resource_type().as_str())
                        || entry
                            .previous_owner_ref()
                            .is_some_and(|owner| value == owner.resource_type().as_str())
                }),
                _ => false,
            })
    }
}

/// Opaque identifier for a live registration.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct WatchRegistrationId(u64);

impl core::fmt::Debug for WatchRegistrationId {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("WatchRegistrationId(<opaque>)")
    }
}

impl WatchRegistrationId {
    pub(crate) const fn from_raw(value: u64) -> Self {
        Self(value)
    }

    pub const fn get(self) -> u64 {
        self.0
    }
}

/// Receiver returned by the storage-side admission helper.
pub struct WatchStream {
    id: WatchRegistrationId,
    receiver: mpsc::UnboundedReceiver<SharedChangeBatch>,
}

impl core::fmt::Debug for WatchStream {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("WatchStream")
            .field("registration", &self.id)
            .finish()
    }
}

impl WatchStream {
    pub const fn id(&self) -> WatchRegistrationId {
        self.id
    }

    pub async fn recv(&mut self) -> Option<SharedChangeBatch> {
        self.receiver.recv().await
    }
}

/// Fixed-cardinality watch saturation signals.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WatchSignals {
    pub current_registrations: u64,
    pub budget_used: u64,
    pub budget_capacity: u64,
    pub admission_rejections: u64,
    pub slow_watcher_evictions: u64,
    pub replay_work: u64,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct ReplaySignals {
    range_seeks: u64,
    rows_scanned: u64,
    rows_decoded: u64,
}

impl ReplaySignals {
    pub(crate) const fn range_seeks(self) -> u64 {
        self.range_seeks
    }

    pub(crate) const fn rows_scanned(self) -> u64 {
        self.rows_scanned
    }

    pub(crate) const fn rows_decoded(self) -> u64 {
        self.rows_decoded
    }
}

struct Registration {
    selector: WatchSelector,
    credits: usize,
    cursor: u64,
    last_delivered: u64,
    pending: VecDeque<u64>,
    sender: mpsc::UnboundedSender<SharedChangeBatch>,
}

/// Storage-side watch coordinator with one global queued-delivery budget.
#[derive(Default)]
pub struct WatchCoordinator {
    next_id: u64,
    registrations: BTreeMap<WatchRegistrationId, Registration>,
    budget_used: usize,
    admission_rejections: u64,
    slow_watcher_evictions: u64,
    replay_work: u64,
    evicted_cursors: VecDeque<(WatchRegistrationId, u64)>,
}

impl core::fmt::Debug for WatchCoordinator {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("WatchCoordinator")
            .field("registration_count", &self.registrations.len())
            .field("budget_used", &self.budget_used)
            .field("budget_capacity", &WATCH_ADMISSION_CAPACITY)
            .finish()
    }
}

impl WatchCoordinator {
    /// Admit one watch with global accounting for its queued deliveries.
    pub fn admit(
        &mut self,
        after_revision: ZoneRevision,
        selector: WatchSelector,
        initial_credits: u32,
    ) -> Result<WatchStream, StoreError> {
        if initial_credits == 0 || initial_credits > MAX_INITIAL_WATCH_CREDITS {
            self.admission_rejections = self.admission_rejections.saturating_add(1);
            return Err(crate::transaction::backpressure());
        }
        let (sender, receiver) = mpsc::unbounded_channel();
        let id = self.register(after_revision, selector, initial_credits, sender)?;
        Ok(WatchStream { id, receiver })
    }

    /// Register a caller-owned sender.  The writer uses this form when the
    /// named-stream layer owns the receiver.
    pub fn register(
        &mut self,
        after_revision: ZoneRevision,
        selector: WatchSelector,
        initial_credits: u32,
        sender: mpsc::UnboundedSender<SharedChangeBatch>,
    ) -> Result<WatchRegistrationId, StoreError> {
        if initial_credits == 0 || initial_credits > MAX_INITIAL_WATCH_CREDITS {
            self.admission_rejections = self.admission_rejections.saturating_add(1);
            return Err(crate::transaction::backpressure());
        }
        if self.registrations.len() >= MAX_WATCH_REGISTRATIONS {
            self.admission_rejections = self.admission_rejections.saturating_add(1);
            return Err(crate::transaction::backpressure());
        }
        let id = WatchRegistrationId(self.next_id);
        self.next_id = self
            .next_id
            .checked_add(1)
            .ok_or_else(|| crate::transaction::integrity("watch-registration-exhausted"))?;
        self.registrations.insert(
            id,
            Registration {
                selector,
                credits: usize::try_from(initial_credits)
                    .map_err(|_| crate::transaction::integrity("watch-credits-invalid"))?,
                cursor: after_revision.get(),
                last_delivered: after_revision.get(),
                pending: VecDeque::new(),
                sender,
            },
        );
        Ok(id)
    }

    /// Deliver one already-decoded immutable batch to matching registrations.
    ///
    /// The return value is the number of registrations that accepted a
    /// delivery.  It lets the backend account for fan-out without exposing
    /// selectors or registration identities in its bounded signal surface.
    pub fn dispatch(&mut self, batch: SharedChangeBatch) -> u64 {
        let mut delivered = 0_u64;
        let ids = self.registrations.keys().copied().collect::<Vec<_>>();
        for id in ids {
            let Some(selector) = self
                .registrations
                .get(&id)
                .map(|entry| entry.selector.clone())
            else {
                continue;
            };
            let Some(filtered) =
                filter_batch_with(batch.batch_arc(), |entry| selector.matches(entry))
            else {
                continue;
            };
            if self.enqueue(id, filtered, false).is_ok() {
                delivered = delivered.saturating_add(1);
            }
        }
        delivered
    }

    /// Deliver one replay row while retaining only the caller's cursor state.
    pub fn enqueue_replay(
        &mut self,
        id: WatchRegistrationId,
        batch: SharedChangeBatch,
    ) -> Result<(), StoreError> {
        self.replay_work = self.replay_work.saturating_add(1);
        self.enqueue(id, batch, true)
    }

    /// Acknowledge all queued rows through one revision and release budget.
    pub fn acknowledge(
        &mut self,
        id: WatchRegistrationId,
        revision: ZoneRevision,
    ) -> Result<(), StoreError> {
        let Some(registration) = self.registrations.get_mut(&id) else {
            return Err(crate::transaction::integrity("watch-registration-missing"));
        };
        let revision = revision.get();
        if revision > registration.last_delivered {
            return Err(crate::transaction::integrity("watch-ack-beyond-delivery"));
        }
        if revision <= registration.cursor {
            return Ok(());
        }
        let mut released = 0_usize;
        while registration
            .pending
            .front()
            .is_some_and(|pending| *pending <= revision)
        {
            registration.pending.pop_front();
            released += 1;
        }
        registration.cursor = revision;
        self.budget_used = self.budget_used.saturating_sub(released);
        Ok(())
    }

    /// Remove one registration without counting it as a slow watcher.
    pub fn unregister(&mut self, id: WatchRegistrationId) -> Option<ZoneRevision> {
        self.remove_registration(id, false).map(ZoneRevision::new)
    }

    /// Return the last acknowledged cursor for an active or evicted watch.
    pub fn resume_cursor(&self, id: WatchRegistrationId) -> Option<ZoneRevision> {
        self.registrations
            .get(&id)
            .map(|registration| ZoneRevision::new(registration.cursor))
            .or_else(|| {
                self.evicted_cursors
                    .iter()
                    .find(|(candidate, _)| *candidate == id)
                    .map(|(_, cursor)| ZoneRevision::new(*cursor))
            })
    }

    /// Read and remove a retained cursor after a slow-watcher eviction.
    pub fn take_resume_cursor(&mut self, id: WatchRegistrationId) -> Option<ZoneRevision> {
        let position = self
            .evicted_cursors
            .iter()
            .position(|(candidate, _)| *candidate == id)?;
        self.evicted_cursors
            .remove(position)
            .map(|(_, cursor)| ZoneRevision::new(cursor))
    }

    pub fn signals(&self) -> WatchSignals {
        WatchSignals {
            current_registrations: self.registrations.len() as u64,
            budget_used: self.budget_used as u64,
            budget_capacity: WATCH_ADMISSION_CAPACITY as u64,
            admission_rejections: self.admission_rejections,
            slow_watcher_evictions: self.slow_watcher_evictions,
            replay_work: self.replay_work,
        }
    }

    /// Delete replay rows older than `retain_from`, in bounded transactions.
    ///
    /// The caller must invoke this from the serialized writer context.  The
    /// returned revision is the durable compaction floor after this bounded
    /// step; a later call may advance it further.
    pub fn compact(
        database: &Database,
        retain_from: ZoneRevision,
        max_rows: usize,
    ) -> Result<ZoneRevision, StoreError> {
        if max_rows == 0 {
            return Err(crate::transaction::integrity("compaction-bound-invalid"));
        }
        let read = database
            .begin_read()
            .map_err(crate::transaction::integrity)?;
        let meta = read_meta(&read)?;
        let target_floor = retain_from
            .get()
            .saturating_sub(1)
            .min(meta.current_revision);
        if target_floor <= meta.compaction_floor {
            return Ok(ZoneRevision::new(meta.compaction_floor));
        }
        let table = read
            .open_table(REVISION_LOG)
            .map_err(crate::transaction::integrity)?;
        let upper = revision_key(target_floor.saturating_add(1))?;
        let mut keys = Vec::new();
        let mut last_revision = meta.compaction_floor;
        let mut removed_bytes = 0_usize;
        let row_limit = max_rows.min(MAX_COMPACTION_ROWS_PER_TRANSACTION);
        for row in table
            .range(..upper.as_slice())
            .map_err(crate::transaction::integrity)?
        {
            let (key, value) = row.map_err(crate::transaction::integrity)?;
            let decoded = DecodedKey::decode(key.value()).map_err(crate::transaction::integrity)?;
            let [DecodedKeyComponent::U64(revision)] = decoded.components() else {
                return Err(crate::transaction::integrity("revision-key-shape-invalid"));
            };
            if *revision <= meta.compaction_floor || *revision > target_floor {
                continue;
            }
            let row_bytes = key
                .value()
                .len()
                .checked_add(value.value().len())
                .ok_or_else(|| crate::transaction::integrity("compaction-size-overflow"))?;
            if !keys.is_empty()
                && removed_bytes.saturating_add(row_bytes) > MAX_COMPACTION_BYTES_PER_TRANSACTION
            {
                break;
            }
            keys.push(key.value().to_vec());
            removed_bytes = removed_bytes.saturating_add(row_bytes);
            last_revision = *revision;
            if keys.len() >= row_limit {
                break;
            }
        }
        drop(table);
        drop(read);
        if keys.is_empty() {
            return Ok(ZoneRevision::new(meta.compaction_floor));
        }

        let mut write = database
            .begin_write()
            .map_err(crate::transaction::integrity)?;
        set_full_durability(&mut write)?;
        {
            let mut revisions = write
                .open_table(REVISION_LOG)
                .map_err(crate::transaction::integrity)?;
            for key in &keys {
                revisions
                    .remove(key.as_slice())
                    .map_err(crate::transaction::integrity)?;
            }
        }
        let mut current = crate::transaction::read_meta_in_write(&write)?;
        if current.compaction_floor != meta.compaction_floor
            || current.current_revision != meta.current_revision
        {
            write.abort().map_err(crate::transaction::integrity)?;
            return Err(crate::transaction::integrity("compaction-state-changed"));
        }
        current.compaction_floor = last_revision;
        let value =
            crate::transaction::encode(crate::values::ValueKind::StoreMetaScalar, &current)?;
        write
            .open_table(crate::transaction::STORE_META)
            .map_err(crate::transaction::integrity)?
            .insert(crate::transaction::meta_key().as_slice(), value.as_slice())
            .map_err(crate::transaction::integrity)?;
        write.commit().map_err(crate::transaction::integrity)?;
        Ok(ZoneRevision::new(last_revision))
    }

    /// Register and replay under a writer-owned ordering boundary.
    ///
    /// The caller must invoke this from the same serialized writer context
    /// that commits changes.  That ordering is what makes registration plus
    /// replay a no-gap operation.
    pub fn register_and_replay(
        &mut self,
        database: &Database,
        after_revision: ZoneRevision,
        selector: WatchSelector,
        initial_credits: u32,
    ) -> Result<(WatchStream, ZoneRevision), StoreError> {
        let meta = crate::transaction::current_meta(database)?;
        if after_revision.get() < meta.compaction_floor {
            return Err(crate::transaction::revision_expired(meta.current_revision));
        }
        if initial_credits == 0 || initial_credits > MAX_INITIAL_WATCH_CREDITS {
            self.admission_rejections = self.admission_rejections.saturating_add(1);
            return Err(crate::transaction::backpressure());
        }
        let (sender, receiver) = mpsc::unbounded_channel();
        let id = self.register(after_revision, selector, initial_credits, sender)?;
        let mut replay = ReplaySignals::default();
        let replay_result = stream_after(database, after_revision.get(), &mut replay, |batch| {
            let batch = Arc::new(batch);
            let Some(selector) = self
                .registrations
                .get(&id)
                .map(|entry| entry.selector.clone())
            else {
                return Err(crate::transaction::integrity("watch-registration-missing"));
            };
            let Some(filtered) = filter_batch_with(batch, |entry| selector.matches(entry)) else {
                return Ok(());
            };
            self.enqueue_replay(id, filtered)
        });
        if let Err(error) = replay_result {
            self.unregister(id);
            return Err(error);
        }
        Ok((
            WatchStream { id, receiver },
            ZoneRevision::new(meta.current_revision),
        ))
    }

    fn enqueue(
        &mut self,
        id: WatchRegistrationId,
        batch: SharedChangeBatch,
        replay: bool,
    ) -> Result<(), StoreError> {
        let revision = batch.revision().get();
        let Some((sender, credits, pending_len)) =
            self.registrations.get(&id).map(|registration| {
                (
                    registration.sender.clone(),
                    registration.credits,
                    registration.pending.len(),
                )
            })
        else {
            return Err(crate::transaction::integrity("watch-registration-missing"));
        };

        if pending_len >= credits {
            self.remove_registration(id, true);
            return Err(crate::transaction::backpressure());
        }
        if self.budget_used >= WATCH_ADMISSION_CAPACITY {
            self.evict_slowest();
            if self.budget_used >= WATCH_ADMISSION_CAPACITY {
                if replay {
                    self.admission_rejections = self.admission_rejections.saturating_add(1);
                }
                return Err(crate::transaction::backpressure());
            }
            if !self.registrations.contains_key(&id) {
                if replay {
                    self.admission_rejections = self.admission_rejections.saturating_add(1);
                }
                return Err(crate::transaction::backpressure());
            }
        }

        match sender.send(batch) {
            Ok(()) => {
                let Some(registration) = self.registrations.get_mut(&id) else {
                    return Err(crate::transaction::integrity("watch-registration-missing"));
                };
                registration.pending.push_back(revision);
                registration.last_delivered = registration.last_delivered.max(revision);
                self.budget_used += 1;
                Ok(())
            }
            Err(_) => {
                self.remove_registration(id, false);
                Err(crate::transaction::integrity("watch-stream-closed"))
            }
        }
    }

    fn evict_slowest(&mut self) {
        let candidate = self
            .registrations
            .iter()
            .filter(|(_, registration)| !registration.pending.is_empty())
            .min_by_key(|(id, registration)| (registration.cursor, id.0))
            .map(|(id, _)| *id);
        if let Some(id) = candidate {
            self.remove_registration(id, true);
        }
    }

    fn remove_registration(&mut self, id: WatchRegistrationId, slow: bool) -> Option<u64> {
        let registration = self.registrations.remove(&id)?;
        self.budget_used = self.budget_used.saturating_sub(registration.pending.len());
        if slow {
            self.slow_watcher_evictions = self.slow_watcher_evictions.saturating_add(1);
            self.evicted_cursors.push_back((id, registration.cursor));
            while self.evicted_cursors.len() > MAX_RETAINED_RESUME_CURSORS {
                self.evicted_cursors.pop_front();
            }
        }
        Some(registration.cursor)
    }
}

/// Compact the durable revision log from a serialized writer context.
pub fn compact(
    database: &Database,
    retain_from: ZoneRevision,
    max_rows: usize,
) -> Result<ZoneRevision, StoreError> {
    WatchCoordinator::compact(database, retain_from, max_rows)
}

/// Stream only rows after `after_revision` using the ordered revision key.
///
/// The visitor receives one decoded row at a time.  Older rows are excluded
/// by the key range before their values are read or decoded.
pub(crate) fn stream_after<F>(
    database: &Database,
    after_revision: u64,
    signals: &mut ReplaySignals,
    mut visit: F,
) -> Result<(), StoreError>
where
    F: FnMut(ChangeBatch) -> Result<(), StoreError>,
{
    let Some(first) = after_revision.checked_add(1) else {
        return Ok(());
    };
    let read = database
        .begin_read()
        .map_err(crate::transaction::integrity)?;
    let table = read
        .open_table(REVISION_LOG)
        .map_err(crate::transaction::integrity)?;
    let lower = revision_key(first)?;
    signals.range_seeks = signals.range_seeks.saturating_add(1);
    for row in table
        .range(lower.as_slice()..)
        .map_err(crate::transaction::integrity)?
    {
        let (_, value) = row.map_err(crate::transaction::integrity)?;
        signals.rows_scanned = signals.rows_scanned.saturating_add(1);
        let batch = decode(crate::values::ValueKind::ChangeBatch, value.value())?;
        signals.rows_decoded = signals.rows_decoded.saturating_add(1);
        visit(batch)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use d2b_contracts_resource::v3::{ResourceGeneration, ResourceRef, ResourceUid};
    use redb::ReadableTableMetadata;
    use std::fs::OpenOptions;

    fn batch(revision: u64) -> SharedChangeBatch {
        let entry = crate::transaction::ChangeEntry::new(
            0,
            ResourceTypeName::parse("Process").unwrap(),
            ResourceName::parse("worker").unwrap(),
            ResourceUid::parse("123e4567-e89b-42d3-a456-426614174000").unwrap(),
            crate::transaction::ChangeEvent::Created,
            None,
            Some(ResourceGeneration::new(1).unwrap()),
            None,
            "sha256:0000000000000000000000000000000000000000000000000000000000000000".to_owned(),
            None,
            "operation".to_owned(),
            "correlation".to_owned(),
        )
        .unwrap();
        crate::actor::filter_batch(
            Arc::new(ChangeBatch::new(ZoneRevision::new(revision), vec![entry]).unwrap()),
            &BTreeSet::from([ResourceTypeName::parse("Process").unwrap()]),
        )
        .unwrap()
    }

    #[test]
    fn replay_selector_keeps_assignment_uid_fence() {
        let selector = WatchSelector::new(
            [ResourceTypeName::parse("Process").unwrap()],
            [],
            [StoreFilter {
                field: "assignment.resourceUid".to_owned(),
                values: vec!["123e4567-e89b-42d3-a456-426614174000".to_owned()],
            }],
        );
        let entry = crate::transaction::ChangeEntry::new(
            0,
            ResourceTypeName::parse("Process").unwrap(),
            ResourceName::parse("worker").unwrap(),
            ResourceUid::parse("123e4567-e89b-42d3-a456-426614174000").unwrap(),
            crate::transaction::ChangeEvent::StatusUpdated,
            Some(ResourceGeneration::new(1).unwrap()),
            Some(ResourceGeneration::new(1).unwrap()),
            None,
            "sha256:0000000000000000000000000000000000000000000000000000000000000000".to_owned(),
            None,
            "operation".to_owned(),
            "correlation".to_owned(),
        )
        .unwrap();
        assert!(selector.matches(&entry));
    }

    #[test]
    fn replay_selector_keeps_owner_uid_fence() {
        let owner_uid = ResourceUid::parse("223e4567-e89b-42d3-a456-426614174001").unwrap();
        let selector = WatchSelector::new(
            [ResourceTypeName::parse("Process").unwrap()],
            [],
            [StoreFilter {
                field: "owner.resourceUid".to_owned(),
                values: vec![owner_uid.as_str().to_owned()],
            }],
        );
        let entry = crate::transaction::ChangeEntry::new(
            0,
            ResourceTypeName::parse("Process").unwrap(),
            ResourceName::parse("worker").unwrap(),
            ResourceUid::parse("123e4567-e89b-42d3-a456-426614174000").unwrap(),
            crate::transaction::ChangeEvent::StatusUpdated,
            Some(ResourceGeneration::new(1).unwrap()),
            Some(ResourceGeneration::new(1).unwrap()),
            Some(owner_uid.clone()),
            "sha256:0000000000000000000000000000000000000000000000000000000000000000".to_owned(),
            None,
            "operation".to_owned(),
            "correlation".to_owned(),
        )
        .unwrap();
        assert!(selector.matches(&entry));
        let other = crate::transaction::ChangeEntry::new(
            0,
            ResourceTypeName::parse("Process").unwrap(),
            ResourceName::parse("worker").unwrap(),
            ResourceUid::parse("123e4567-e89b-42d3-a456-426614174000").unwrap(),
            crate::transaction::ChangeEvent::StatusUpdated,
            Some(ResourceGeneration::new(1).unwrap()),
            Some(ResourceGeneration::new(1).unwrap()),
            None,
            "sha256:0000000000000000000000000000000000000000000000000000000000000000".to_owned(),
            None,
            "operation".to_owned(),
            "correlation".to_owned(),
        )
        .unwrap();
        assert!(!selector.matches(&other));
    }

    #[test]
    fn replay_selector_matches_owned_children_without_widening_unrelated_types() {
        let owner_uid = ResourceUid::parse("223e4567-e89b-42d3-a456-426614174001").unwrap();
        let selector = WatchSelector::new(
            [],
            [],
            [StoreFilter {
                field: "resource-or-owner.type".to_owned(),
                values: vec!["Host".to_owned()],
            }],
        );
        let entry = crate::transaction::ChangeEntry::new(
            0,
            ResourceTypeName::parse("Process").unwrap(),
            ResourceName::parse("worker").unwrap(),
            ResourceUid::parse("123e4567-e89b-42d3-a456-426614174000").unwrap(),
            crate::transaction::ChangeEvent::Created,
            None,
            Some(ResourceGeneration::new(1).unwrap()),
            Some(owner_uid.clone()),
            "sha256:0000000000000000000000000000000000000000000000000000000000000000".to_owned(),
            None,
            "operation".to_owned(),
            "correlation".to_owned(),
        )
        .unwrap()
        .with_owners(
            Some(ResourceRef::parse("Host/owner").unwrap()),
            Some(owner_uid),
            Some(ResourceRef::parse("Host/owner").unwrap()),
        );
        assert!(selector.matches(&entry));
        let unrelated = crate::transaction::ChangeEntry::new(
            0,
            ResourceTypeName::parse("Process").unwrap(),
            ResourceName::parse("other").unwrap(),
            ResourceUid::parse("123e4567-e89b-42d3-a456-426614174002").unwrap(),
            crate::transaction::ChangeEvent::Created,
            None,
            Some(ResourceGeneration::new(1).unwrap()),
            None,
            "sha256:0000000000000000000000000000000000000000000000000000000000000000".to_owned(),
            None,
            "operation-other".to_owned(),
            "correlation-other".to_owned(),
        )
        .unwrap();
        assert!(!selector.matches(&unrelated));
    }

    #[test]
    fn budget_eviction_releases_entries_and_retains_ack_cursor() {
        let mut coordinator = WatchCoordinator::default();
        let selector = WatchSelector::new([ResourceTypeName::parse("Process").unwrap()], [], []);
        let mut stream = coordinator
            .admit(ZoneRevision::new(0), selector, 1)
            .unwrap();
        let first = batch(1);
        coordinator.dispatch(first);
        assert_eq!(coordinator.signals().budget_used, 1);
        coordinator.dispatch(batch(2));
        let signals = coordinator.signals();
        assert_eq!(signals.budget_used, 0);
        assert_eq!(signals.current_registrations, 0);
        assert_eq!(signals.slow_watcher_evictions, 1);
        assert_eq!(
            coordinator.resume_cursor(stream.id()),
            Some(ZoneRevision::new(0))
        );
        assert!(stream.receiver.try_recv().is_ok());
    }

    #[test]
    fn acknowledgement_releases_global_budget() {
        let mut coordinator = WatchCoordinator::default();
        let selector = WatchSelector::new([ResourceTypeName::parse("Process").unwrap()], [], []);
        let stream = coordinator
            .admit(ZoneRevision::new(0), selector, 2)
            .unwrap();
        coordinator.dispatch(batch(1));
        coordinator
            .acknowledge(stream.id(), ZoneRevision::new(1))
            .unwrap();
        assert_eq!(coordinator.signals().budget_used, 0);
        assert_eq!(
            coordinator.resume_cursor(stream.id()),
            Some(ZoneRevision::new(1))
        );
    }

    #[test]
    fn compaction_advances_floor_in_bounded_steps() {
        let directory = tempfile::tempdir().unwrap();
        let file = OpenOptions::new()
            .create_new(true)
            .read(true)
            .write(true)
            .open(directory.path().join("store.redb"))
            .unwrap();
        let backend = redb::backends::FileBackend::new(file).unwrap();
        let database = Database::builder().create_with_backend(backend).unwrap();
        let identity = crate::StoreIdentity::new(
            d2b_resource_store::StoreSlot::new(0).unwrap(),
            ResourceUid::parse("11111111-1111-4111-8111-111111111111").unwrap(),
            d2b_contracts_resource::v3::ZoneId::parse("work").unwrap(),
            ResourceUid::parse("22222222-2222-4222-8222-222222222222").unwrap(),
            d2b_contracts_resource::v3::Timestamp::parse("2026-07-31T00:00:00.000Z").unwrap(),
            d2b_resource_store::PolicySnapshot {
                policy_revision: 1,
                api_catalog_revision: 1,
                active_configuration_revision:
                    d2b_contracts_resource::v3::ConfigurationGeneration::new(1).unwrap(),
                controller_generation: None,
            },
        );
        crate::transaction::initialize(&database, &identity).unwrap();

        let mut meta = crate::transaction::current_meta(&database).unwrap();
        meta.current_revision = 5;
        let mut write = database.begin_write().unwrap();
        crate::transaction::set_full_durability(&mut write).unwrap();
        {
            let mut revisions = write.open_table(REVISION_LOG).unwrap();
            for revision in 1..=5 {
                let value = crate::transaction::encode(
                    crate::values::ValueKind::ChangeBatch,
                    &ChangeBatch::new(ZoneRevision::new(revision), Vec::new()).unwrap(),
                )
                .unwrap();
                revisions
                    .insert(revision_key(revision).unwrap().as_slice(), value.as_slice())
                    .unwrap();
            }
        }
        let value =
            crate::transaction::encode(crate::values::ValueKind::StoreMetaScalar, &meta).unwrap();
        write
            .open_table(crate::transaction::STORE_META)
            .unwrap()
            .insert(crate::transaction::meta_key().as_slice(), value.as_slice())
            .unwrap();
        write.commit().unwrap();

        assert_eq!(
            compact(&database, ZoneRevision::new(4), 2).unwrap(),
            ZoneRevision::new(2)
        );
        assert_eq!(
            compact(&database, ZoneRevision::new(6), 16).unwrap(),
            ZoneRevision::new(5)
        );
        crate::transaction::validate_consistency(&database).unwrap();
        assert_eq!(
            database
                .begin_read()
                .unwrap()
                .open_table(REVISION_LOG)
                .unwrap()
                .len()
                .unwrap(),
            0
        );

        let mut coordinator = WatchCoordinator::default();
        let selector = WatchSelector::new(
            [ResourceTypeName::parse("Process").unwrap()],
            [],
            [StoreFilter {
                field: "assignment.resourceUid".to_owned(),
                values: vec!["123e4567-e89b-42d3-a456-426614174000".to_owned()],
            }],
        );
        let expired = coordinator
            .register_and_replay(
                &database,
                ZoneRevision::new(0),
                selector,
                MAX_INITIAL_WATCH_CREDITS,
            )
            .unwrap_err();
        assert_eq!(
            expired.kind(),
            d2b_resource_store::StoreErrorKind::RevisionExpired
        );
        assert_eq!(coordinator.signals().current_registrations, 0);
    }
}
