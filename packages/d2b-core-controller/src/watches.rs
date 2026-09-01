//! Revision watch registration, cursor handoff, compaction, and quotas.

use std::collections::BTreeMap;

use d2b_contracts_resource::v3::ZoneRevision;

/// Opaque process-local watch registration identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct WatchId(u64);

/// Registered watch state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WatchCursor {
    high_water: ZoneRevision,
    checkpoint: ZoneRevision,
    credits: u32,
}

impl WatchCursor {
    /// Return the durable revision handed to this watcher.
    pub const fn high_water(self) -> ZoneRevision {
        self.high_water
    }

    /// Return the watcher's acknowledged checkpoint.
    pub const fn checkpoint(self) -> ZoneRevision {
        self.checkpoint
    }

    /// Return remaining stream credits.
    pub const fn credits(self) -> u32 {
        self.credits
    }
}

/// Closed watch handler refusal reason.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WatchError {
    InvalidLimits,
    InvalidRevision,
    QuotaExceeded,
    ExpiredCursor,
    UnknownWatch,
    CheckpointAhead,
    RevisionRegression,
    CreditExhausted,
}

impl WatchError {
    /// Return a stable, cardinality-bounded reason code.
    pub const fn code(self) -> &'static str {
        match self {
            Self::InvalidLimits => "watch-limits-invalid",
            Self::InvalidRevision => "watch-revision-invalid",
            Self::QuotaExceeded => "watch-quota-exceeded",
            Self::ExpiredCursor => "watch-cursor-expired",
            Self::UnknownWatch => "watch-unknown",
            Self::CheckpointAhead => "watch-checkpoint-ahead",
            Self::RevisionRegression => "watch-revision-regression",
            Self::CreditExhausted => "watch-credit-exhausted",
        }
    }
}

impl core::fmt::Display for WatchError {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str(self.code())
    }
}

impl std::error::Error for WatchError {}

/// Pure watch policy state used by the Core watch boundary. The production
/// store adapter supplies durable post-commit revisions to this policy.
#[derive(Debug)]
pub struct WatchHandler {
    max_watches: usize,
    max_total_credits: u32,
    allocated_credits: u32,
    next_watch: u64,
    current_revision: ZoneRevision,
    compacted_through: ZoneRevision,
    watches: BTreeMap<WatchId, WatchCursor>,
}

impl WatchHandler {
    /// Construct explicit watch and stream quota bounds.
    pub fn new(max_watches: usize, max_total_credits: u32) -> Result<Self, WatchError> {
        if max_watches == 0 || max_total_credits == 0 {
            return Err(WatchError::InvalidLimits);
        }
        Ok(Self {
            max_watches,
            max_total_credits,
            allocated_credits: 0,
            next_watch: 1,
            current_revision: ZoneRevision::new(0),
            compacted_through: ZoneRevision::new(0),
            watches: BTreeMap::new(),
        })
    }

    /// Observe a durable store commit without claiming delivery to any watch.
    pub fn record_commit(&mut self, revision: ZoneRevision) -> Result<(), WatchError> {
        if revision.get() == 0 || revision <= self.current_revision {
            return Err(WatchError::RevisionRegression);
        }
        self.current_revision = revision;
        Ok(())
    }

    /// Register a watch after an exact cursor with reserved credits.
    pub fn register(
        &mut self,
        after_revision: ZoneRevision,
        credits: u32,
    ) -> Result<WatchId, WatchError> {
        if credits == 0 || after_revision > self.current_revision {
            return Err(WatchError::InvalidRevision);
        }
        if after_revision < self.compacted_through {
            return Err(WatchError::ExpiredCursor);
        }
        if self.watches.len() == self.max_watches
            || self.allocated_credits.saturating_add(credits) > self.max_total_credits
        {
            return Err(WatchError::QuotaExceeded);
        }
        let id = WatchId(self.next_watch);
        self.next_watch = self
            .next_watch
            .checked_add(1)
            .ok_or(WatchError::QuotaExceeded)?;
        self.allocated_credits += credits;
        self.watches.insert(
            id,
            WatchCursor {
                high_water: after_revision,
                checkpoint: after_revision,
                credits,
            },
        );
        Ok(id)
    }

    /// Dispatch one committed revision after enforcing reserved stream credit.
    pub fn dispatch(&mut self, id: WatchId, revision: ZoneRevision) -> Result<(), WatchError> {
        if revision.get() == 0 || revision > self.current_revision {
            return Err(WatchError::InvalidRevision);
        }
        let cursor = self.watches.get_mut(&id).ok_or(WatchError::UnknownWatch)?;
        if cursor.credits == 0 {
            return Err(WatchError::CreditExhausted);
        }
        if revision <= cursor.high_water {
            return Err(WatchError::RevisionRegression);
        }
        cursor.credits -= 1;
        cursor.high_water = revision;
        self.allocated_credits -= 1;
        Ok(())
    }

    /// Acknowledge a monotonic checkpoint no later than handed high water.
    pub fn checkpoint(&mut self, id: WatchId, revision: ZoneRevision) -> Result<(), WatchError> {
        let cursor = self.watches.get_mut(&id).ok_or(WatchError::UnknownWatch)?;
        if revision < cursor.checkpoint {
            return Err(WatchError::RevisionRegression);
        }
        if revision > cursor.high_water {
            return Err(WatchError::CheckpointAhead);
        }
        cursor.checkpoint = revision;
        Ok(())
    }

    /// Withdraw one watch and release its remaining reserved credits.
    pub fn withdraw(&mut self, id: WatchId) -> bool {
        let Some(cursor) = self.watches.remove(&id) else {
            return false;
        };
        self.allocated_credits -= cursor.credits;
        true
    }

    /// Advance the compaction floor only through every active checkpoint.
    pub fn compact_through(&mut self, requested: ZoneRevision) -> Result<ZoneRevision, WatchError> {
        if requested < self.compacted_through || requested > self.current_revision {
            return Err(WatchError::InvalidRevision);
        }
        let safe = self
            .watches
            .values()
            .map(|cursor| cursor.checkpoint)
            .min()
            .unwrap_or(self.current_revision)
            .min(requested);
        self.compacted_through = safe;
        Ok(safe)
    }

    /// Return one watch state without exposing any resource identity.
    pub fn cursor(&self, id: WatchId) -> Option<WatchCursor> {
        self.watches.get(&id).copied()
    }

    /// Return the compaction floor.
    pub const fn compacted_through(&self) -> ZoneRevision {
        self.compacted_through
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dispatch_advances_high_water_and_checkpoint_handoff_is_monotonic() {
        let mut handler = WatchHandler::new(2, 4).unwrap();
        handler.record_commit(ZoneRevision::new(1)).unwrap();
        let watch = handler.register(ZoneRevision::new(1), 2).unwrap();
        handler.record_commit(ZoneRevision::new(2)).unwrap();
        handler.dispatch(watch, ZoneRevision::new(2)).unwrap();
        handler.checkpoint(watch, ZoneRevision::new(2)).unwrap();
        assert_eq!(
            handler.cursor(watch).unwrap().high_water(),
            ZoneRevision::new(2)
        );
        assert_eq!(
            handler.cursor(watch).unwrap().checkpoint(),
            ZoneRevision::new(2)
        );
    }

    #[test]
    fn registration_starts_at_the_acknowledged_cursor_not_the_store_tip() {
        let mut handler = WatchHandler::new(1, 2).unwrap();
        handler.record_commit(ZoneRevision::new(1)).unwrap();
        handler.record_commit(ZoneRevision::new(2)).unwrap();

        let watch = handler.register(ZoneRevision::new(1), 1).unwrap();

        assert_eq!(
            handler.cursor(watch).unwrap().high_water(),
            ZoneRevision::new(1)
        );
        assert_eq!(
            handler.checkpoint(watch, ZoneRevision::new(2)),
            Err(WatchError::CheckpointAhead)
        );
    }

    #[test]
    fn expired_cursor_is_rejected_and_requires_relist() {
        let mut handler = WatchHandler::new(2, 4).unwrap();
        handler.record_commit(ZoneRevision::new(1)).unwrap();
        handler.record_commit(ZoneRevision::new(2)).unwrap();
        handler.compact_through(ZoneRevision::new(2)).unwrap();
        assert_eq!(
            handler.register(ZoneRevision::new(1), 1).unwrap_err(),
            WatchError::ExpiredCursor
        );
    }

    #[test]
    fn quotas_and_credits_fail_closed_without_eviction() {
        let mut handler = WatchHandler::new(1, 2).unwrap();
        handler.record_commit(ZoneRevision::new(1)).unwrap();
        let watch = handler.register(ZoneRevision::new(1), 2).unwrap();
        assert_eq!(
            handler.register(ZoneRevision::new(1), 1).unwrap_err(),
            WatchError::QuotaExceeded
        );
        handler.record_commit(ZoneRevision::new(2)).unwrap();
        handler.dispatch(watch, ZoneRevision::new(2)).unwrap();
        handler.record_commit(ZoneRevision::new(3)).unwrap();
        handler.dispatch(watch, ZoneRevision::new(3)).unwrap();
        handler.record_commit(ZoneRevision::new(4)).unwrap();
        assert_eq!(
            handler.dispatch(watch, ZoneRevision::new(4)),
            Err(WatchError::CreditExhausted)
        );
    }

    #[test]
    fn watcher_with_no_credit_does_not_advance_on_commit() {
        let mut handler = WatchHandler::new(1, 1).unwrap();
        handler.record_commit(ZoneRevision::new(1)).unwrap();
        handler.record_commit(ZoneRevision::new(2)).unwrap();
        let watch = handler.register(ZoneRevision::new(1), 1).unwrap();
        handler.dispatch(watch, ZoneRevision::new(2)).unwrap();
        handler.record_commit(ZoneRevision::new(3)).unwrap();

        assert_eq!(
            handler.cursor(watch).unwrap().high_water(),
            ZoneRevision::new(2)
        );
        assert_eq!(handler.cursor(watch).unwrap().credits(), 0);
        assert_eq!(
            handler.dispatch(watch, ZoneRevision::new(3)),
            Err(WatchError::CreditExhausted)
        );
    }

    #[test]
    fn dispatch_to_one_watcher_does_not_advance_another() {
        let mut handler = WatchHandler::new(2, 2).unwrap();
        handler.record_commit(ZoneRevision::new(1)).unwrap();
        let delivered = handler.register(ZoneRevision::new(1), 1).unwrap();
        let waiting = handler.register(ZoneRevision::new(1), 1).unwrap();
        handler.record_commit(ZoneRevision::new(2)).unwrap();

        assert_eq!(
            handler.cursor(waiting).unwrap().high_water(),
            ZoneRevision::new(1)
        );
        handler.dispatch(delivered, ZoneRevision::new(2)).unwrap();
        assert_eq!(
            handler.cursor(delivered).unwrap().high_water(),
            ZoneRevision::new(2)
        );
        assert_eq!(
            handler.cursor(waiting).unwrap().high_water(),
            ZoneRevision::new(1)
        );
    }

    #[test]
    fn compaction_refuses_a_revision_not_delivered_to_a_live_watcher() {
        let mut handler = WatchHandler::new(2, 2).unwrap();
        handler.record_commit(ZoneRevision::new(1)).unwrap();
        let slow = handler.register(ZoneRevision::new(1), 1).unwrap();
        handler.record_commit(ZoneRevision::new(2)).unwrap();
        let fast = handler.register(ZoneRevision::new(2), 1).unwrap();
        handler.checkpoint(fast, ZoneRevision::new(2)).unwrap();

        let slow_checkpoint = handler.checkpoint(slow, ZoneRevision::new(2));
        let compacted = handler.compact_through(ZoneRevision::new(2)).unwrap();
        assert_eq!(
            (slow_checkpoint, compacted),
            (Err(WatchError::CheckpointAhead), ZoneRevision::new(1))
        );

        handler.dispatch(slow, ZoneRevision::new(2)).unwrap();
        handler.checkpoint(slow, ZoneRevision::new(2)).unwrap();
        assert_eq!(
            handler.compact_through(ZoneRevision::new(2)).unwrap(),
            ZoneRevision::new(2)
        );
    }

    #[test]
    fn checkpoint_ahead_of_dispatched_high_water_is_rejected() {
        let mut handler = WatchHandler::new(1, 1).unwrap();
        handler.record_commit(ZoneRevision::new(1)).unwrap();
        let watch = handler.register(ZoneRevision::new(1), 1).unwrap();
        assert_eq!(
            handler.checkpoint(watch, ZoneRevision::new(2)),
            Err(WatchError::CheckpointAhead)
        );
    }
}
