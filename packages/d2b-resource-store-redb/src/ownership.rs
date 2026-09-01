//! Singular ownership resolution and reverse-index invariants.

use std::collections::{BTreeMap, BTreeSet};

use d2b_contracts_resource::v3::{ResourceRef, ResourceUid, ZoneRevision};
pub use d2b_controller_toolkit::owner_hints::OwnerChangeEvent;
use d2b_controller_toolkit::owner_hints::{MAX_OWNER_HINT_DEPTH, OwnedResourceChangedHint};

/// Maximum accepted singular owner-chain depth.
pub const MAX_OWNER_CHAIN_DEPTH: usize = MAX_OWNER_HINT_DEPTH;

/// Immutable UID binding stored alongside a child's singular ownerRef.
#[derive(Clone, PartialEq, Eq)]
pub struct OwnerBinding {
    owner_ref: ResourceRef,
    owner_uid: ResourceUid,
}

impl OwnerBinding {
    /// Borrow the human-readable owner reference.
    pub const fn owner_ref(&self) -> &ResourceRef {
        &self.owner_ref
    }

    /// Borrow the immutable owner UID resolved at binding time.
    pub const fn owner_uid(&self) -> &ResourceUid {
        &self.owner_uid
    }
}

impl core::fmt::Debug for OwnerBinding {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("OwnerBinding")
            .field("owner_kind", self.owner_ref.resource_type())
            .field("has_owner_uid", &true)
            .finish()
    }
}

/// Reverse-index value for one owned child.
#[derive(Clone, PartialEq, Eq)]
pub struct ReverseOwnerEntry {
    child_ref: ResourceRef,
    child_uid: ResourceUid,
    latest_revision: ZoneRevision,
}

impl core::fmt::Debug for ReverseOwnerEntry {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ReverseOwnerEntry")
            .field("child_kind", self.child_ref.resource_type())
            .field("has_child_uid", &true)
            .field("latest_revision", &self.latest_revision)
            .finish()
    }
}

impl ReverseOwnerEntry {
    /// Borrow the child reference.
    pub const fn child_ref(&self) -> &ResourceRef {
        &self.child_ref
    }

    /// Borrow the immutable child UID.
    pub const fn child_uid(&self) -> &ResourceUid {
        &self.child_uid
    }

    /// Return the latest child revision reflected in the index.
    pub const fn latest_revision(&self) -> ZoneRevision {
        self.latest_revision
    }
}

/// Atomic ownership-index delta persisted with a resource mutation.
///
/// Pending hints are deliberately inaccessible outside this crate until a
/// production writer can exchange a successful durable commit for a dispatch
/// capability.
///
/// ```compile_fail
/// use d2b_resource_store_redb::OwnerIndexMutation;
///
/// let _forged_dispatch = OwnerIndexMutation::dispatch;
/// ```
#[derive(Clone, PartialEq, Eq)]
pub struct OwnerIndexMutation {
    previous_owner: Option<OwnerBinding>,
    current_owner: Option<OwnerBinding>,
    hints: Vec<OwnedResourceChangedHint>,
}

impl core::fmt::Debug for OwnerIndexMutation {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let previous_owner_kind = self
            .previous_owner
            .as_ref()
            .map(|binding| binding.owner_ref.resource_type());
        let current_owner_kind = self
            .current_owner
            .as_ref()
            .map(|binding| binding.owner_ref.resource_type());
        let hint_events = self
            .hints
            .iter()
            .map(|hint| hint.event())
            .collect::<Vec<_>>();
        let hint_revisions = self
            .hints
            .iter()
            .map(|hint| hint.revision())
            .collect::<Vec<_>>();

        f.debug_struct("OwnerIndexMutation")
            .field("has_previous_owner", &self.previous_owner.is_some())
            .field("previous_owner_kind", &previous_owner_kind)
            .field("has_current_owner", &self.current_owner.is_some())
            .field("current_owner_kind", &current_owner_kind)
            .field("hint_count", &self.hints.len())
            .field("hint_events", &hint_events)
            .field("hint_revisions", &hint_revisions)
            .finish()
    }
}

impl OwnerIndexMutation {
    /// Borrow the prior binding removed by this mutation.
    pub fn previous_owner(&self) -> Option<&OwnerBinding> {
        self.previous_owner.as_ref()
    }

    /// Borrow the new binding installed by this mutation.
    pub fn current_owner(&self) -> Option<&OwnerBinding> {
        self.current_owner.as_ref()
    }
}

/// Ownership graph and reverse index used inside the store's single writer.
///
/// Methods validate all fallible graph conditions before changing any map. The
/// returned mutation contains the hint records that the enclosing redb write
/// transaction stores in its change batch before commit.
#[derive(Clone, Default, PartialEq, Eq)]
pub struct OwnerIndex {
    current_uid_by_ref: BTreeMap<ResourceRef, ResourceUid>,
    reference_by_uid: BTreeMap<ResourceUid, ResourceRef>,
    owner_by_child: BTreeMap<ResourceUid, OwnerBinding>,
    children_by_owner: BTreeMap<ResourceUid, BTreeMap<ResourceUid, ReverseOwnerEntry>>,
}

impl core::fmt::Debug for OwnerIndex {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let reverse_entry_count = self
            .children_by_owner
            .values()
            .map(BTreeMap::len)
            .sum::<usize>();

        f.debug_struct("OwnerIndex")
            .field("current_reference_count", &self.current_uid_by_ref.len())
            .field("resource_count", &self.reference_by_uid.len())
            .field("owned_child_count", &self.owner_by_child.len())
            .field("owner_count", &self.children_by_owner.len())
            .field("reverse_entry_count", &reverse_entry_count)
            .finish()
    }
}

impl OwnerIndex {
    /// Register a resource identity, replacing only the current name binding.
    ///
    /// Older UIDs remain addressable until their child-first deletion completes,
    /// so recreating a name cannot transfer ownership to the new UID.
    pub fn register_resource(
        &mut self,
        resource_ref: ResourceRef,
        uid: ResourceUid,
    ) -> Result<(), OwnershipError> {
        if self
            .reference_by_uid
            .get(&uid)
            .is_some_and(|existing| existing != &resource_ref)
        {
            return Err(OwnershipError::UidAlreadyRegistered);
        }
        self.reference_by_uid
            .insert(uid.clone(), resource_ref.clone());
        self.current_uid_by_ref.insert(resource_ref, uid);
        Ok(())
    }

    /// Resolve a current ResourceRef to its immutable UID.
    pub fn resolve(&self, resource_ref: &ResourceRef) -> Option<&ResourceUid> {
        self.current_uid_by_ref.get(resource_ref)
    }

    /// Borrow a child's singular UID-bound owner.
    pub fn owner_of(&self, child_uid: &ResourceUid) -> Option<&OwnerBinding> {
        self.owner_by_child.get(child_uid)
    }

    /// List the canonical reverse index for an owner UID.
    pub fn children_of(&self, owner_uid: &ResourceUid) -> Vec<&ReverseOwnerEntry> {
        self.children_by_owner
            .get(owner_uid)
            .into_iter()
            .flat_map(BTreeMap::values)
            .collect()
    }

    /// Resolve and atomically install or replace one singular owner binding.
    pub fn bind_owner(
        &mut self,
        child_uid: &ResourceUid,
        owner_ref: ResourceRef,
        revision: ZoneRevision,
        event: OwnerChangeEvent,
    ) -> Result<OwnerIndexMutation, OwnershipError> {
        ensure_allocated_revision(revision)?;
        let child_ref = self
            .reference_by_uid
            .get(child_uid)
            .cloned()
            .ok_or(OwnershipError::ChildNotFound)?;
        let owner_uid = self
            .current_uid_by_ref
            .get(&owner_ref)
            .cloned()
            .ok_or(OwnershipError::OwnerNotFound)?;
        if &owner_uid == child_uid {
            return Err(OwnershipError::OwnerCycle);
        }
        self.validate_chain(child_uid, &owner_uid)?;

        let current_owner = OwnerBinding {
            owner_ref: owner_ref.clone(),
            owner_uid: owner_uid.clone(),
        };
        let previous_owner = self.owner_by_child.get(child_uid).cloned();
        let mut hints = Vec::with_capacity(if previous_owner.is_some() { 2 } else { 1 });
        if let Some(previous) = &previous_owner
            && previous != &current_owner
        {
            hints.push(make_hint(
                previous,
                &child_ref,
                child_uid,
                revision,
                OwnerChangeEvent::Reparented,
            )?);
        }
        hints.push(make_hint(
            &current_owner,
            &child_ref,
            child_uid,
            revision,
            event,
        )?);

        if let Some(previous) = &previous_owner
            && previous.owner_uid != owner_uid
        {
            remove_reverse_entry(&mut self.children_by_owner, &previous.owner_uid, child_uid);
        }
        self.owner_by_child
            .insert(child_uid.clone(), current_owner.clone());
        self.children_by_owner.entry(owner_uid).or_default().insert(
            child_uid.clone(),
            ReverseOwnerEntry {
                child_ref,
                child_uid: child_uid.clone(),
                latest_revision: revision,
            },
        );
        Ok(OwnerIndexMutation {
            previous_owner,
            current_owner: Some(current_owner),
            hints,
        })
    }

    /// Remove a child's owner binding in the same mutation as its row update.
    pub fn clear_owner(
        &mut self,
        child_uid: &ResourceUid,
        revision: ZoneRevision,
        event: OwnerChangeEvent,
    ) -> Result<OwnerIndexMutation, OwnershipError> {
        ensure_allocated_revision(revision)?;
        let child_ref = self
            .reference_by_uid
            .get(child_uid)
            .cloned()
            .ok_or(OwnershipError::ChildNotFound)?;
        let previous_owner = self
            .owner_by_child
            .get(child_uid)
            .cloned()
            .ok_or(OwnershipError::OwnerBindingNotFound)?;
        let hint = make_hint(&previous_owner, &child_ref, child_uid, revision, event)?;

        self.owner_by_child.remove(child_uid);
        remove_reverse_entry(
            &mut self.children_by_owner,
            &previous_owner.owner_uid,
            child_uid,
        );
        Ok(OwnerIndexMutation {
            previous_owner: Some(previous_owner),
            current_owner: None,
            hints: vec![hint],
        })
    }

    /// Record a child mutation without re-resolving its ownerRef.
    ///
    /// This is the normal spec/status/metadata/finalizer mutation path. It
    /// deliberately follows the stored owner UID, so owner-name reuse cannot
    /// transfer a child to a replacement resource.
    pub fn record_child_mutation(
        &mut self,
        child_uid: &ResourceUid,
        revision: ZoneRevision,
        event: OwnerChangeEvent,
    ) -> Result<OwnerIndexMutation, OwnershipError> {
        ensure_allocated_revision(revision)?;
        let child_ref = self
            .reference_by_uid
            .get(child_uid)
            .cloned()
            .ok_or(OwnershipError::ChildNotFound)?;
        let owner = self
            .owner_by_child
            .get(child_uid)
            .cloned()
            .ok_or(OwnershipError::OwnerBindingNotFound)?;
        let hint = make_hint(&owner, &child_ref, child_uid, revision, event)?;
        let reverse = self
            .children_by_owner
            .get_mut(&owner.owner_uid)
            .and_then(|children| children.get_mut(child_uid))
            .ok_or(OwnershipError::ReverseIndexMissing)?;
        reverse.latest_revision = revision;
        Ok(OwnerIndexMutation {
            previous_owner: Some(owner.clone()),
            current_owner: Some(owner),
            hints: vec![hint],
        })
    }

    /// Verify that a stored owner UID still matches the original binding.
    ///
    /// A false result after name reuse is expected and must never be repaired by
    /// silently rebinding the child to the replacement UID.
    pub fn binding_matches(
        &self,
        child_uid: &ResourceUid,
        owner_ref: &ResourceRef,
        owner_uid: &ResourceUid,
    ) -> bool {
        self.owner_by_child.get(child_uid).is_some_and(|binding| {
            &binding.owner_ref == owner_ref && &binding.owner_uid == owner_uid
        })
    }

    /// Return a deterministic child-first deletion order for a subtree.
    pub fn child_first_deletion(
        &self,
        root_uid: &ResourceUid,
    ) -> Result<Vec<ResourceUid>, OwnershipError> {
        if !self.reference_by_uid.contains_key(root_uid) {
            return Err(OwnershipError::ChildNotFound);
        }
        let mut order = Vec::new();
        let mut visiting = BTreeSet::new();
        self.append_child_first(root_uid, &mut visiting, &mut order)?;
        Ok(order)
    }

    /// Remove a resource after every child has been removed.
    pub fn remove_resource(&mut self, uid: &ResourceUid) -> Result<(), OwnershipError> {
        if self
            .children_by_owner
            .get(uid)
            .is_some_and(|children| !children.is_empty())
        {
            return Err(OwnershipError::ChildrenRemain);
        }
        if let Some(binding) = self.owner_by_child.remove(uid) {
            remove_reverse_entry(&mut self.children_by_owner, &binding.owner_uid, uid);
        }
        let resource_ref = self
            .reference_by_uid
            .remove(uid)
            .ok_or(OwnershipError::ChildNotFound)?;
        if self.current_uid_by_ref.get(&resource_ref) == Some(uid) {
            self.current_uid_by_ref.remove(&resource_ref);
        }
        self.children_by_owner.remove(uid);
        Ok(())
    }

    fn validate_chain(
        &self,
        child_uid: &ResourceUid,
        owner_uid: &ResourceUid,
    ) -> Result<(), OwnershipError> {
        let mut cursor = owner_uid;
        let mut depth = 1usize;
        let mut visited = BTreeSet::new();
        visited.insert(child_uid);
        loop {
            if !visited.insert(cursor) {
                return Err(OwnershipError::OwnerCycle);
            }
            let Some(binding) = self.owner_by_child.get(cursor) else {
                return Ok(());
            };
            depth += 1;
            if depth > MAX_OWNER_CHAIN_DEPTH {
                return Err(OwnershipError::OwnerDepth);
            }
            cursor = &binding.owner_uid;
        }
    }

    fn append_child_first(
        &self,
        uid: &ResourceUid,
        visiting: &mut BTreeSet<ResourceUid>,
        order: &mut Vec<ResourceUid>,
    ) -> Result<(), OwnershipError> {
        if !visiting.insert(uid.clone()) {
            return Err(OwnershipError::OwnerCycle);
        }
        if let Some(children) = self.children_by_owner.get(uid) {
            for child_uid in children.keys() {
                self.append_child_first(child_uid, visiting, order)?;
            }
        }
        visiting.remove(uid);
        order.push(uid.clone());
        Ok(())
    }
}

fn ensure_allocated_revision(revision: ZoneRevision) -> Result<(), OwnershipError> {
    if revision.get() == 0 {
        return Err(OwnershipError::UnallocatedRevision);
    }
    Ok(())
}

fn make_hint(
    owner: &OwnerBinding,
    child_ref: &ResourceRef,
    child_uid: &ResourceUid,
    revision: ZoneRevision,
    event: OwnerChangeEvent,
) -> Result<OwnedResourceChangedHint, OwnershipError> {
    OwnedResourceChangedHint::new_pending(
        owner.owner_ref.clone(),
        owner.owner_uid.clone(),
        child_ref.clone(),
        child_uid.clone(),
        revision,
        event,
    )
    .map_err(|_| OwnershipError::InvalidHint)
}

fn remove_reverse_entry(
    index: &mut BTreeMap<ResourceUid, BTreeMap<ResourceUid, ReverseOwnerEntry>>,
    owner_uid: &ResourceUid,
    child_uid: &ResourceUid,
) {
    if let Some(children) = index.get_mut(owner_uid) {
        children.remove(child_uid);
        if children.is_empty() {
            index.remove(owner_uid);
        }
    }
}

/// Structural ownership failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OwnershipError {
    ChildNotFound,
    OwnerNotFound,
    OwnerBindingNotFound,
    UidAlreadyRegistered,
    OwnerCycle,
    OwnerDepth,
    ChildrenRemain,
    UnallocatedRevision,
    InvalidHint,
    ReverseIndexMissing,
}

impl core::fmt::Display for OwnershipError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::ChildNotFound => f.write_str("resource UID is not registered"),
            Self::OwnerNotFound => f.write_str("ownerRef does not resolve in this Zone"),
            Self::OwnerBindingNotFound => f.write_str("resource has no owner binding"),
            Self::UidAlreadyRegistered => {
                f.write_str("resource UID is already bound to a different reference")
            }
            Self::OwnerCycle => f.write_str("resource-owner-cycle"),
            Self::OwnerDepth => f.write_str("resource-owner-depth"),
            Self::ChildrenRemain => f.write_str("owned children must be deleted first"),
            Self::UnallocatedRevision => {
                f.write_str("ownership update requires a nonzero allocated revision")
            }
            Self::InvalidHint => f.write_str("ownership mutation could not create an owner hint"),
            Self::ReverseIndexMissing => {
                f.write_str("owner reverse index is inconsistent with the UID binding")
            }
        }
    }
}

impl std::error::Error for OwnershipError {}

#[cfg(test)]
mod tests {
    use super::*;

    const OWNER_NAME_SENTINEL: &str = "owner-debug-sentinel";
    const OWNER_UID_SENTINEL: &str = "deadbeef-dead-4bad-8bad-deadbeef0002";
    const CHILD_NAME_SENTINEL: &str = "child-debug-sentinel";
    const CHILD_UID_SENTINEL: &str = "feedface-feed-4ace-9ace-feedface0003";

    fn uid(index: u8) -> ResourceUid {
        ResourceUid::parse(format!("123e4567-e89b-42d3-a456-4266141740{index:02}")).unwrap()
    }

    fn resource(index: u8) -> ResourceRef {
        ResourceRef::parse(&format!("Process/node-{index}")).unwrap()
    }

    fn graph(count: u8) -> OwnerIndex {
        let mut graph = OwnerIndex::default();
        for index in 0..count {
            graph
                .register_resource(resource(index), uid(index))
                .unwrap();
        }
        graph
    }

    fn assert_protected_markers_absent(debug: &str) {
        for marker in [
            OWNER_NAME_SENTINEL,
            OWNER_UID_SENTINEL,
            CHILD_NAME_SENTINEL,
            CHILD_UID_SENTINEL,
        ] {
            assert!(!debug.contains(marker), "{debug}");
        }
    }

    #[test]
    fn ownership_debug_redacts_every_protected_field() {
        let owner_ref = ResourceRef::parse(&format!("Guest/{OWNER_NAME_SENTINEL}")).unwrap();
        let owner_uid = ResourceUid::parse(OWNER_UID_SENTINEL).unwrap();
        let child_ref = ResourceRef::parse(&format!("Process/{CHILD_NAME_SENTINEL}")).unwrap();
        let child_uid = ResourceUid::parse(CHILD_UID_SENTINEL).unwrap();

        assert!(
            owner_ref
                .to_canonical_string()
                .contains(OWNER_NAME_SENTINEL)
        );
        assert!(
            child_ref
                .to_canonical_string()
                .contains(CHILD_NAME_SENTINEL)
        );
        assert_eq!(owner_uid.as_str(), OWNER_UID_SENTINEL);
        assert_eq!(child_uid.as_str(), CHILD_UID_SENTINEL);

        let binding = OwnerBinding {
            owner_ref: owner_ref.clone(),
            owner_uid: owner_uid.clone(),
        };
        let reverse_entry = ReverseOwnerEntry {
            child_ref: child_ref.clone(),
            child_uid: child_uid.clone(),
            latest_revision: ZoneRevision::new(41),
        };
        let hint = OwnedResourceChangedHint::new_pending(
            owner_ref.clone(),
            owner_uid.clone(),
            child_ref.clone(),
            child_uid.clone(),
            ZoneRevision::new(43),
            OwnerChangeEvent::MetadataUpdated,
        )
        .unwrap();
        let mutation = OwnerIndexMutation {
            previous_owner: Some(binding.clone()),
            current_owner: Some(binding.clone()),
            hints: vec![hint],
        };

        let binding_debug = format!("{binding:?}");
        assert_protected_markers_absent(&binding_debug);
        assert!(binding_debug.contains("owner_kind"));
        assert!(binding_debug.contains("has_owner_uid: true"));

        let reverse_debug = format!("{reverse_entry:?}");
        assert_protected_markers_absent(&reverse_debug);
        assert!(reverse_debug.contains("child_kind"));
        assert!(reverse_debug.contains("latest_revision: ZoneRevision(41)"));

        let mutation_debug = format!("{mutation:?}");
        assert_protected_markers_absent(&mutation_debug);
        assert!(mutation_debug.contains("hint_count: 1"));
        assert!(mutation_debug.contains("ZoneRevision(43)"));

        let mut index = OwnerIndex::default();
        index
            .register_resource(owner_ref.clone(), owner_uid.clone())
            .unwrap();
        index
            .register_resource(child_ref, child_uid.clone())
            .unwrap();
        index
            .bind_owner(
                &child_uid,
                owner_ref,
                ZoneRevision::new(47),
                OwnerChangeEvent::Created,
            )
            .unwrap();
        let index_debug = format!("{index:?}");
        assert_protected_markers_absent(&index_debug);
        assert_eq!(
            index_debug,
            "OwnerIndex { current_reference_count: 2, resource_count: 2, \
             owned_child_count: 1, owner_count: 1, reverse_entry_count: 1 }"
        );
    }

    #[test]
    fn cycle_property_checks_every_two_node_reparent_pair() {
        for first in 0..6 {
            for second in 0..6 {
                if first == second {
                    continue;
                }
                let mut graph = graph(6);
                graph
                    .bind_owner(
                        &uid(first),
                        resource(second),
                        ZoneRevision::new(1),
                        OwnerChangeEvent::Created,
                    )
                    .unwrap();
                assert_eq!(
                    graph.bind_owner(
                        &uid(second),
                        resource(first),
                        ZoneRevision::new(2),
                        OwnerChangeEvent::Reparented,
                    ),
                    Err(OwnershipError::OwnerCycle),
                    "{first} -> {second} -> {first}"
                );
                assert_eq!(
                    graph.owner_of(&uid(first)).unwrap().owner_uid(),
                    &uid(second)
                );
                assert!(graph.owner_of(&uid(second)).is_none());
            }
        }
    }

    #[test]
    fn depth_property_accepts_eight_edges_and_rejects_nine_atomically() {
        let mut graph = graph(10);
        for child in 1..=8 {
            graph
                .bind_owner(
                    &uid(child),
                    resource(child - 1),
                    ZoneRevision::new(u64::from(child)),
                    OwnerChangeEvent::Created,
                )
                .unwrap();
        }
        assert_eq!(
            graph.bind_owner(
                &uid(9),
                resource(8),
                ZoneRevision::new(9),
                OwnerChangeEvent::Created,
            ),
            Err(OwnershipError::OwnerDepth)
        );
        assert!(graph.owner_of(&uid(9)).is_none());
        assert!(graph.children_of(&uid(8)).is_empty());
    }

    #[test]
    fn name_reuse_never_rebinds_existing_children() {
        let mut graph = graph(3);
        graph
            .bind_owner(
                &uid(1),
                resource(0),
                ZoneRevision::new(1),
                OwnerChangeEvent::Created,
            )
            .unwrap();
        let replacement_uid = ResourceUid::parse("123e4567-e89b-42d3-a456-426614174099").unwrap();
        graph
            .register_resource(resource(0), replacement_uid.clone())
            .unwrap();

        assert_eq!(graph.resolve(&resource(0)), Some(&replacement_uid));
        assert_eq!(graph.owner_of(&uid(1)).unwrap().owner_uid(), &uid(0));
        assert!(graph.binding_matches(&uid(1), &resource(0), &uid(0)));
        assert!(!graph.binding_matches(&uid(1), &resource(0), &replacement_uid));
        assert!(graph.children_of(&replacement_uid).is_empty());
        assert_eq!(graph.children_of(&uid(0)).len(), 1);
        let mutation = graph
            .record_child_mutation(
                &uid(1),
                ZoneRevision::new(2),
                OwnerChangeEvent::StatusUpdated,
            )
            .unwrap();
        assert_eq!(mutation.hints[0].owner_uid(), &uid(0));
        assert_eq!(
            graph.children_of(&uid(0))[0].latest_revision(),
            ZoneRevision::new(2)
        );
    }

    #[test]
    fn child_drift_relist_and_owner_cascade_are_child_first() {
        let mut graph = graph(5);
        for child in 1..5 {
            graph
                .bind_owner(
                    &uid(child),
                    resource(child - 1),
                    ZoneRevision::new(u64::from(child)),
                    OwnerChangeEvent::Created,
                )
                .unwrap();
        }
        assert_eq!(graph.children_of(&uid(2))[0].child_ref(), &resource(3));
        assert_eq!(
            graph.child_first_deletion(&uid(0)).unwrap(),
            vec![uid(4), uid(3), uid(2), uid(1), uid(0)]
        );
        assert_eq!(
            graph.remove_resource(&uid(0)),
            Err(OwnershipError::ChildrenRemain)
        );
        for index in (0..5).rev() {
            graph.remove_resource(&uid(index)).unwrap();
        }
    }

    #[test]
    fn reparent_updates_reverse_indexes_and_records_both_owner_hints() {
        let mut graph = graph(3);
        graph
            .bind_owner(
                &uid(2),
                resource(0),
                ZoneRevision::new(1),
                OwnerChangeEvent::Created,
            )
            .unwrap();
        let mutation = graph
            .bind_owner(
                &uid(2),
                resource(1),
                ZoneRevision::new(2),
                OwnerChangeEvent::Reparented,
            )
            .unwrap();
        assert!(graph.children_of(&uid(0)).is_empty());
        assert_eq!(graph.children_of(&uid(1)).len(), 1);
        assert_eq!(mutation.hints.len(), 2);
        assert_eq!(mutation.hints[0].owner_uid(), &uid(0));
        assert_eq!(mutation.hints[1].owner_uid(), &uid(1));
    }
}
