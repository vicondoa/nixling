//! Bounded priority queue with per-resource single-flight admission.

use std::{
    collections::{BTreeMap, VecDeque},
    sync::Mutex,
};

use d2b_contracts_resource::v3::ZoneRevision;

use crate::{OperationContext, ResourceKey, TriggerReason, TriggerSet};

/// Queue lane. Expedited work shares the same resource single-flight.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PriorityLane {
    Ordinary,
    Expedited,
}

/// One incoming initial-list or watch hint.
#[derive(Clone, PartialEq, Eq)]
pub struct QueueHint {
    key: ResourceKey,
    high_water_revision: ZoneRevision,
    reasons: TriggerSet,
    lane: PriorityLane,
    operation: OperationContext,
}

impl QueueHint {
    /// Construct a queue hint.
    pub fn new(
        key: ResourceKey,
        high_water_revision: ZoneRevision,
        reasons: TriggerSet,
        lane: PriorityLane,
        operation: OperationContext,
    ) -> Result<Self, QueueError> {
        if high_water_revision.get() == 0 || reasons.is_empty() {
            return Err(QueueError::InvalidHint);
        }
        if (lane == PriorityLane::Expedited) != reasons.contains(TriggerReason::ExpeditedMutation) {
            return Err(QueueError::InvalidHint);
        }
        Ok(Self {
            key,
            high_water_revision,
            reasons,
            lane,
            operation,
        })
    }
}

impl core::fmt::Debug for QueueHint {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("QueueHint")
            .field("key", &self.key)
            .field("high_water_revision", &self.high_water_revision)
            .field("reasons", &self.reasons)
            .field("lane", &self.lane)
            .field("operation", &self.operation)
            .finish()
    }
}

/// Work removed from the pending lane and marked running.
pub struct QueuedWork {
    key: ResourceKey,
    high_water_revision: ZoneRevision,
    reasons: TriggerSet,
    lane: PriorityLane,
    operation: OperationContext,
    attempt: u32,
}

impl QueuedWork {
    /// Borrow the target.
    pub const fn key(&self) -> &ResourceKey {
        &self.key
    }

    /// Return the coalesced high-water revision.
    pub const fn high_water_revision(&self) -> ZoneRevision {
        self.high_water_revision
    }

    /// Borrow all coalesced reasons.
    pub const fn reasons(&self) -> &TriggerSet {
        &self.reasons
    }

    /// Return the selected lane.
    pub const fn lane(&self) -> PriorityLane {
        self.lane
    }

    /// Borrow operation correlation.
    pub const fn operation(&self) -> &OperationContext {
        &self.operation
    }

    /// Return the one-based attempt.
    pub const fn attempt(&self) -> u32 {
        self.attempt
    }
}

impl core::fmt::Debug for QueuedWork {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("QueuedWork")
            .field("key", &self.key)
            .field("high_water_revision", &self.high_water_revision)
            .field("reasons", &self.reasons)
            .field("lane", &self.lane)
            .field("operation", &self.operation)
            .field("attempt", &self.attempt)
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq)]
struct PendingWork {
    high_water_revision: ZoneRevision,
    reasons: TriggerSet,
    lane: PriorityLane,
    operation: OperationContext,
    attempt: u32,
}

impl PendingWork {
    fn from_hint(hint: &QueueHint) -> Self {
        Self {
            high_water_revision: hint.high_water_revision,
            reasons: hint.reasons.clone(),
            lane: hint.lane,
            operation: hint.operation.clone(),
            attempt: 1,
        }
    }

    fn coalesce(&mut self, hint: &QueueHint) {
        if hint.high_water_revision > self.high_water_revision {
            self.high_water_revision = hint.high_water_revision;
        }
        if hint.high_water_revision >= self.high_water_revision {
            self.operation = hint.operation.clone();
        }
        self.reasons.union_with(&hint.reasons);
    }

    fn into_running(self, key: ResourceKey) -> QueuedWork {
        QueuedWork {
            key,
            high_water_revision: self.high_water_revision,
            reasons: self.reasons,
            lane: self.lane,
            operation: self.operation,
            attempt: self.attempt,
        }
    }
}

#[derive(Default)]
struct ResourceEntry {
    running: bool,
    ready_enqueued: bool,
    ordinary: Option<PendingWork>,
    expedited: VecDeque<PendingWork>,
    expedited_streak: usize,
}

impl ResourceEntry {
    fn has_pending(&self) -> bool {
        self.ordinary.is_some() || !self.expedited.is_empty()
    }
}

#[derive(Default)]
struct QueueState {
    resources: BTreeMap<ResourceKey, ResourceEntry>,
    ready: VecDeque<ResourceKey>,
}

/// Thread-safe bounded queue. A resource remains present while running.
pub struct PendingQueue {
    max_resources: usize,
    max_expedited_per_resource: usize,
    state: Mutex<QueueState>,
}

impl PendingQueue {
    /// Construct a queue with explicit admission bounds.
    pub fn new(max_resources: usize, max_expedited_per_resource: usize) -> Self {
        Self {
            max_resources,
            max_expedited_per_resource,
            state: Mutex::new(QueueState::default()),
        }
    }

    /// Admit or coalesce one hint without evicting another resource.
    pub fn push(&self, hint: QueueHint) -> Result<QueuePushOutcome, QueueError> {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        Self::push_locked(
            &mut state,
            hint,
            self.max_resources,
            self.max_expedited_per_resource,
        )
    }

    fn push_locked(
        state: &mut QueueState,
        hint: QueueHint,
        max_resources: usize,
        max_expedited_per_resource: usize,
    ) -> Result<QueuePushOutcome, QueueError> {
        if !state.resources.contains_key(&hint.key) && state.resources.len() >= max_resources {
            return Err(QueueError::Backpressure);
        }

        let key = hint.key.clone();
        let entry = state.resources.entry(key.clone()).or_default();
        let outcome = match hint.lane {
            PriorityLane::Ordinary => {
                if let Some(pending) = &mut entry.ordinary {
                    pending.coalesce(&hint);
                    QueuePushOutcome::Coalesced
                } else {
                    entry.ordinary = Some(PendingWork::from_hint(&hint));
                    QueuePushOutcome::Admitted
                }
            }
            PriorityLane::Expedited => {
                if let Some(pending) = entry.expedited.iter_mut().find(|pending| {
                    pending.operation.operation_id() == hint.operation.operation_id()
                }) {
                    pending.coalesce(&hint);
                    QueuePushOutcome::Coalesced
                } else {
                    if entry.expedited.len() >= max_expedited_per_resource {
                        return Err(QueueError::ExpeditedBackpressure);
                    }
                    entry.expedited.push_back(PendingWork::from_hint(&hint));
                    QueuePushOutcome::Admitted
                }
            }
        };

        if !entry.running && !entry.ready_enqueued {
            entry.ready_enqueued = true;
            state.ready.push_back(key);
        }
        Ok(outcome)
    }

    /// Select one ready resource and mark it running.
    pub fn pop_ready(&self) -> Option<QueuedWork> {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        while let Some(key) = state.ready.pop_front() {
            let entry = state
                .resources
                .get_mut(&key)
                .expect("ready keys always have an entry");
            entry.ready_enqueued = false;
            if entry.running {
                continue;
            }
            let ordinary_due = entry.ordinary.is_some()
                && (entry.expedited.is_empty()
                    || entry.expedited_streak >= self.max_expedited_per_resource);
            let pending = if ordinary_due {
                entry.expedited_streak = 0;
                entry.ordinary.take()
            } else {
                let expedited = entry.expedited.pop_front();
                if expedited.is_some() {
                    entry.expedited_streak = entry.expedited_streak.saturating_add(1);
                }
                expedited.or_else(|| entry.ordinary.take())
            };
            if let Some(pending) = pending {
                entry.running = true;
                return Some(pending.into_running(key));
            }
        }
        None
    }

    /// Finish one running pass and make its coalesced successor ready.
    pub fn finish(&self, key: &ResourceKey) -> Result<(), QueueError> {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let Some(entry) = state.resources.get_mut(key) else {
            return Err(QueueError::UnknownResource);
        };
        if !entry.running {
            return Err(QueueError::NotRunning);
        }
        entry.running = false;
        if entry.has_pending() {
            if !entry.ready_enqueued {
                entry.ready_enqueued = true;
                state.ready.push_back(key.clone());
            }
        } else {
            state.resources.remove(key);
        }
        Ok(())
    }

    /// Requeue a stale/conflicted pass with an incremented attempt.
    pub fn retry(&self, work: QueuedWork, revision: ZoneRevision) -> Result<(), QueueError> {
        let key = work.key.clone();
        let operation_id = work.operation.operation_id().to_owned();
        self.finish(&key)?;
        let mut hint = QueueHint::new(
            key,
            revision.max(work.high_water_revision),
            work.reasons,
            work.lane,
            work.operation,
        )?;
        hint.reasons.insert(TriggerReason::RetryDue);
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let outcome = Self::push_locked(
            &mut state,
            hint,
            self.max_resources,
            self.max_expedited_per_resource,
        )?;
        let entry = state
            .resources
            .get_mut(&work.key)
            .expect("retried work has an entry");
        let pending = match work.lane {
            PriorityLane::Ordinary => entry.ordinary.as_mut(),
            PriorityLane::Expedited => entry
                .expedited
                .iter_mut()
                .find(|pending| pending.operation.operation_id() == operation_id),
        }
        .expect("retried work is pending");
        pending.attempt = work.attempt.saturating_add(1);
        let _ = outcome;
        Ok(())
    }

    /// Replace idle pending state after a watch relist while preserving running work.
    pub fn rebuild(&self, hints: Vec<QueueHint>) -> Result<(), QueueError> {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        state.ready.clear();
        state.resources.retain(|_, entry| {
            entry.ready_enqueued = false;
            entry.ordinary = None;
            entry.expedited.clear();
            entry.running
        });
        for hint in hints {
            Self::push_locked(
                &mut state,
                hint,
                self.max_resources,
                self.max_expedited_per_resource,
            )?;
        }
        Ok(())
    }

    /// Number of resource identities admitted or currently running.
    pub fn resource_count(&self) -> usize {
        self.state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .resources
            .len()
    }

    /// Whether no resource is queued or running.
    pub fn is_empty(&self) -> bool {
        self.resource_count() == 0
    }
}

impl core::fmt::Debug for PendingQueue {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let state = self.state.try_lock();
        let resource_count = state.as_ref().ok().map(|state| state.resources.len());
        f.debug_struct("PendingQueue")
            .field("max_resources", &self.max_resources)
            .field(
                "max_expedited_per_resource",
                &self.max_expedited_per_resource,
            )
            .field("resource_count", &resource_count)
            .finish()
    }
}

/// Queue admission result.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QueuePushOutcome {
    Admitted,
    Coalesced,
}

/// Fail-closed queue error.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QueueError {
    InvalidHint,
    Backpressure,
    ExpeditedBackpressure,
    UnknownResource,
    NotRunning,
}

impl core::fmt::Display for QueueError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            Self::InvalidHint => "queue hint is missing a revision or reason",
            Self::Backpressure => "controller pending-resource bound reached",
            Self::ExpeditedBackpressure => "expedited priority-lane quota reached",
            Self::UnknownResource => "resource is not admitted",
            Self::NotRunning => "resource has no running handler",
        })
    }
}

impl std::error::Error for QueueError {}

#[cfg(test)]
mod tests {
    use std::{
        sync::{Arc, Barrier},
        thread,
    };

    use d2b_contracts_resource::v3::{ResourceRef, ResourceUid, ZoneId};

    use super::*;

    fn key(name: &str, suffix: u8) -> ResourceKey {
        ResourceKey::new(
            ZoneId::parse("work").unwrap(),
            ResourceRef::parse(&format!("Process/{name}")).unwrap(),
            ResourceUid::parse(format!("123e4567-e89b-42d3-a456-4266141740{suffix:02}")).unwrap(),
        )
    }

    fn hint(
        key: ResourceKey,
        revision: u64,
        reason: TriggerReason,
        lane: PriorityLane,
        operation_id: &str,
    ) -> QueueHint {
        QueueHint::new(
            key,
            ZoneRevision::new(revision),
            TriggerSet::new([reason]),
            lane,
            OperationContext::new(operation_id, operation_id, operation_id, None).unwrap(),
        )
        .unwrap()
    }

    #[test]
    fn queued_hints_coalesce_high_water_and_union_reasons() {
        let queue = PendingQueue::new(4, 2);
        let target = key("app", 0);
        queue
            .push(hint(
                target.clone(),
                3,
                TriggerReason::DependencyChanged,
                PriorityLane::Ordinary,
                "ordinary",
            ))
            .unwrap();
        assert_eq!(
            queue
                .push(hint(
                    target,
                    7,
                    TriggerReason::DeletionRequested,
                    PriorityLane::Ordinary,
                    "ordinary",
                ))
                .unwrap(),
            QueuePushOutcome::Coalesced
        );

        let work = queue.pop_ready().unwrap();
        assert_eq!(work.high_water_revision(), ZoneRevision::new(7));
        assert!(work.reasons().contains(TriggerReason::DependencyChanged));
        assert!(work.reasons().contains(TriggerReason::DeletionRequested));
    }

    #[test]
    fn ordinary_coalescing_keeps_the_newest_operation_identity() {
        let queue = PendingQueue::new(2, 1);
        let target = key("app", 0);
        queue
            .push(hint(
                target.clone(),
                3,
                TriggerReason::DependencyChanged,
                PriorityLane::Ordinary,
                "old-operation",
            ))
            .unwrap();
        queue
            .push(hint(
                target.clone(),
                4,
                TriggerReason::OwnedResourceChanged,
                PriorityLane::Ordinary,
                "new-operation",
            ))
            .unwrap();
        queue
            .push(hint(
                target,
                4,
                TriggerReason::ManualReconcile,
                PriorityLane::Ordinary,
                "same-revision-operation",
            ))
            .unwrap();

        let work = queue.pop_ready().unwrap();
        assert_eq!(work.high_water_revision(), ZoneRevision::new(4));
        assert_eq!(work.operation().operation_id(), "same-revision-operation");
        assert!(work.reasons().contains(TriggerReason::OwnedResourceChanged));
    }

    #[test]
    fn expedited_reason_cannot_enter_the_ordinary_effect_lane() {
        assert_eq!(
            QueueHint::new(
                key("app", 0),
                ZoneRevision::new(2),
                TriggerSet::new([TriggerReason::ExpeditedMutation]),
                PriorityLane::Ordinary,
                OperationContext::new("fast", "fast", "fast", None).unwrap(),
            )
            .unwrap_err(),
            QueueError::InvalidHint
        );
    }

    #[test]
    fn expedited_lane_runs_first_without_dropping_ordinary_work() {
        let queue = PendingQueue::new(4, 2);
        let target = key("app", 0);
        queue
            .push(hint(
                target.clone(),
                3,
                TriggerReason::ManualReconcile,
                PriorityLane::Ordinary,
                "ordinary",
            ))
            .unwrap();
        queue
            .push(hint(
                target.clone(),
                4,
                TriggerReason::ExpeditedMutation,
                PriorityLane::Expedited,
                "expedited",
            ))
            .unwrap();

        let expedited = queue.pop_ready().unwrap();
        assert_eq!(expedited.lane(), PriorityLane::Expedited);
        assert_eq!(expedited.operation().operation_id(), "expedited");
        assert!(queue.pop_ready().is_none());
        queue.finish(&target).unwrap();
        let ordinary = queue.pop_ready().unwrap();
        assert_eq!(ordinary.lane(), PriorityLane::Ordinary);
        assert_eq!(ordinary.operation().operation_id(), "ordinary");
    }

    #[test]
    fn expedited_burst_quota_prevents_ordinary_starvation() {
        let queue = PendingQueue::new(4, 2);
        let target = key("app", 0);
        queue
            .push(hint(
                target.clone(),
                1,
                TriggerReason::ManualReconcile,
                PriorityLane::Ordinary,
                "ordinary",
            ))
            .unwrap();
        for (revision, operation) in [(2, "fast-1"), (3, "fast-2")] {
            queue
                .push(hint(
                    target.clone(),
                    revision,
                    TriggerReason::ExpeditedMutation,
                    PriorityLane::Expedited,
                    operation,
                ))
                .unwrap();
        }

        assert_eq!(
            queue.pop_ready().unwrap().operation().operation_id(),
            "fast-1"
        );
        queue
            .push(hint(
                target.clone(),
                4,
                TriggerReason::ExpeditedMutation,
                PriorityLane::Expedited,
                "fast-3",
            ))
            .unwrap();
        queue.finish(&target).unwrap();
        assert_eq!(
            queue.pop_ready().unwrap().operation().operation_id(),
            "fast-2"
        );
        queue.finish(&target).unwrap();
        assert_eq!(
            queue.pop_ready().unwrap().operation().operation_id(),
            "ordinary"
        );
    }

    #[test]
    fn resource_bound_never_evicts_an_admitted_resource() {
        let queue = PendingQueue::new(1, 1);
        let first = key("first", 0);
        queue
            .push(hint(
                first.clone(),
                2,
                TriggerReason::ManualReconcile,
                PriorityLane::Ordinary,
                "first",
            ))
            .unwrap();
        assert_eq!(
            queue
                .push(hint(
                    key("second", 1),
                    2,
                    TriggerReason::ManualReconcile,
                    PriorityLane::Ordinary,
                    "second",
                ))
                .unwrap_err(),
            QueueError::Backpressure
        );
        assert_eq!(queue.pop_ready().unwrap().key(), &first);
    }

    #[test]
    fn poisoned_queue_lock_does_not_drop_admitted_work() {
        let queue = Arc::new(PendingQueue::new(2, 1));
        let first = key("first", 0);
        queue
            .push(hint(
                first.clone(),
                2,
                TriggerReason::ManualReconcile,
                PriorityLane::Ordinary,
                "first",
            ))
            .unwrap();
        let poisoner = Arc::clone(&queue);
        assert!(
            thread::spawn(move || {
                let _guard = poisoner.state.lock().unwrap();
                panic!("poison queue lock");
            })
            .join()
            .is_err()
        );

        queue
            .push(hint(
                key("second", 1),
                2,
                TriggerReason::ManualReconcile,
                PriorityLane::Ordinary,
                "second",
            ))
            .unwrap();
        assert_eq!(queue.pop_ready().unwrap().key(), &first);
    }

    #[test]
    fn one_resource_never_has_two_running_passes_under_contention() {
        let queue = Arc::new(PendingQueue::new(4, 2));
        let target = key("app", 0);
        queue
            .push(hint(
                target.clone(),
                2,
                TriggerReason::ManualReconcile,
                PriorityLane::Ordinary,
                "initial",
            ))
            .unwrap();
        let first = queue.pop_ready().unwrap();
        assert_eq!(first.key(), &target);

        let barrier = Arc::new(Barrier::new(9));
        let mut threads = Vec::new();
        for revision in 3..=10 {
            let queue = Arc::clone(&queue);
            let target = target.clone();
            let barrier = Arc::clone(&barrier);
            threads.push(thread::spawn(move || {
                barrier.wait();
                queue
                    .push(hint(
                        target,
                        revision,
                        TriggerReason::DependencyChanged,
                        PriorityLane::Ordinary,
                        "coalesced",
                    ))
                    .unwrap();
            }));
        }
        barrier.wait();
        for thread in threads {
            thread.join().unwrap();
        }

        assert!(
            queue.pop_ready().is_none(),
            "a contended successor ran before finish"
        );
        queue.finish(&target).unwrap();
        let successor = queue.pop_ready().unwrap();
        assert_eq!(successor.high_water_revision(), ZoneRevision::new(10));
        assert_eq!(successor.attempt(), 1);
    }

    #[test]
    fn retry_increments_attempt_and_keeps_single_flight() {
        let queue = PendingQueue::new(2, 1);
        let target = key("app", 0);
        queue
            .push(hint(
                target,
                2,
                TriggerReason::ManualReconcile,
                PriorityLane::Ordinary,
                "ordinary",
            ))
            .unwrap();
        let first = queue.pop_ready().unwrap();
        queue.retry(first, ZoneRevision::new(5)).unwrap();
        let retry = queue.pop_ready().unwrap();
        assert_eq!(retry.attempt(), 2);
        assert_eq!(retry.high_water_revision(), ZoneRevision::new(5));
        assert!(retry.reasons().contains(TriggerReason::RetryDue));
    }

    #[test]
    fn expedited_retry_updates_its_matching_operation_not_a_neighbor() {
        let queue = PendingQueue::new(2, 3);
        let target = key("app", 0);
        queue
            .push(hint(
                target.clone(),
                2,
                TriggerReason::ExpeditedMutation,
                PriorityLane::Expedited,
                "retry-me",
            ))
            .unwrap();
        let running = queue.pop_ready().unwrap();
        queue
            .push(hint(
                target.clone(),
                3,
                TriggerReason::ExpeditedMutation,
                PriorityLane::Expedited,
                "retry-me",
            ))
            .unwrap();
        queue
            .push(hint(
                target.clone(),
                4,
                TriggerReason::ExpeditedMutation,
                PriorityLane::Expedited,
                "neighbor",
            ))
            .unwrap();

        queue.retry(running, ZoneRevision::new(5)).unwrap();
        let retry = queue.pop_ready().unwrap();
        assert_eq!(retry.operation().operation_id(), "retry-me");
        assert_eq!(retry.attempt(), 2);
        queue.finish(&target).unwrap();
        let neighbor = queue.pop_ready().unwrap();
        assert_eq!(neighbor.operation().operation_id(), "neighbor");
        assert_eq!(neighbor.attempt(), 1);
    }

    #[test]
    fn relist_replaces_idle_pending_work_but_preserves_running_key() {
        let queue = PendingQueue::new(4, 1);
        let running_key = key("running", 0);
        queue
            .push(hint(
                running_key.clone(),
                2,
                TriggerReason::ManualReconcile,
                PriorityLane::Ordinary,
                "running",
            ))
            .unwrap();
        let _running = queue.pop_ready().unwrap();
        queue
            .push(hint(
                key("stale", 1),
                2,
                TriggerReason::ManualReconcile,
                PriorityLane::Ordinary,
                "stale",
            ))
            .unwrap();
        let replacement = key("replacement", 2);
        queue
            .rebuild(vec![hint(
                replacement.clone(),
                8,
                TriggerReason::StartupRelist,
                PriorityLane::Ordinary,
                "replacement",
            )])
            .unwrap();

        let work = queue.pop_ready().unwrap();
        assert_eq!(work.key(), &replacement);
        assert_eq!(queue.resource_count(), 2);
        queue.finish(&running_key).unwrap();
        assert_eq!(queue.resource_count(), 1);
    }
}
