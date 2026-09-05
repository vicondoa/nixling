//! clipd-host service boundary and display dependency.

use crate::{
    DISPLAY_PROVIDER_REF, DependencyStatus, DisplayDependencyEvidence,
    audit::{
        ClipboardAuditEvent, ClipboardAuditQueue, ClipboardAuditSink, ClipboardReason, SizeBucket,
    },
    fd::{AttachmentClass, FdPermit, FdPermitPool, FdReadError, FdSafetyError, ReceivedFdBatch},
    history::{ClipboardEntry, ClipboardHistory},
    picker::{PickerAuthority, PickerError, PickerReceipt, PickerRequest, PickerResult},
    policy::Policy,
};
use d2b_contracts_resource::v3::{ResourceRef, ZoneId};
use d2b_provider_toolkit::{
    AuthenticatedComponentSession, AuthenticatedSessionRouteBinding,
    unix::{AcceptedAttachment, CreditBundle, VerifiedPacket},
};
use sha2::{Digest, Sha256};
use std::{collections::BTreeMap, time::Duration};

/// Authenticated clipboard service package selected by ComponentSession.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClipboardServiceRole {
    /// General clipboard management service.
    Management,
    /// Clipboard bridge service carrying host/Guest selections.
    Bridge,
    /// Picker coordination service.
    Picker,
}

/// A routing identity projected from an authenticated ComponentSession.
///
/// The only public constructor consumes the canonical session route binding,
/// whose fields are private and can only be obtained from a verified session.
#[derive(PartialEq, Eq)]
pub struct AuthenticatedClipboardSession {
    subject_ref: ResourceRef,
    zone: ZoneId,
    provider_generation: u64,
    reconnect_generation: u64,
    role: ClipboardServiceRole,
}

impl AuthenticatedClipboardSession {
    /// Derive clipboard identity from a verified ComponentSession.
    pub fn from_component_session<C>(
        session: &AuthenticatedComponentSession<C>,
    ) -> Result<Self, ClipboardServiceError> {
        Self::from_authenticated_route(session.route_binding())
    }

    /// Derive clipboard identity from a canonical authenticated route.
    pub fn from_authenticated_route(
        route: AuthenticatedSessionRouteBinding,
    ) -> Result<Self, ClipboardServiceError> {
        let provider_matches = route
            .provider_ref()
            .is_some_and(|provider| provider.to_canonical_string() == crate::PROVIDER_REF);
        let service_matches = matches!(
            route.service().as_str(),
            crate::MANAGEMENT_SERVICE | crate::BRIDGE_SERVICE | crate::PICKER_SERVICE
        );
        let provider_generation = route
            .provider_generation()
            .ok_or(ClipboardServiceError::SessionUnauthenticated)?
            .get();
        if !provider_matches
            || !service_matches
            || provider_generation == 0
            || route.reconnect_generation().get() == 0
        {
            return Err(ClipboardServiceError::SessionUnauthenticated);
        }
        let subject_type = route.subject_ref().resource_type().as_str();
        if !matches!(subject_type, "Guest" | "User" | "Provider") {
            return Err(ClipboardServiceError::SessionUnauthenticated);
        }
        let role = match route.service().as_str() {
            crate::MANAGEMENT_SERVICE => ClipboardServiceRole::Management,
            crate::BRIDGE_SERVICE => ClipboardServiceRole::Bridge,
            crate::PICKER_SERVICE => ClipboardServiceRole::Picker,
            _ => return Err(ClipboardServiceError::SessionUnauthenticated),
        };
        Ok(Self {
            subject_ref: route.subject_ref().clone(),
            zone: route.zone().clone(),
            provider_generation,
            reconnect_generation: route.reconnect_generation().get(),
            role,
        })
    }

    /// Project an authenticated Provider transport into one Guest selected
    /// from committed daemon state.
    pub fn from_authenticated_route_for_guest(
        route: AuthenticatedSessionRouteBinding,
        guest_ref: ResourceRef,
    ) -> Result<Self, ClipboardServiceError> {
        let mut session = Self::from_authenticated_route(route.clone())?;
        if guest_ref.resource_type().as_str() != "Guest"
            || route.subject_ref().resource_type().as_str() != "Provider"
            || route.evidence_class()
                != d2b_contracts_resource::v3::identity::EvidenceClass::UnixPeer
            || route.locality() != d2b_contracts_resource::v3::identity::Locality::Local
            || route.reconnect_generation().get() == 0
        {
            return Err(ClipboardServiceError::SessionUnauthenticated);
        }
        session.subject_ref = guest_ref;
        Ok(session)
    }

    /// Admit the daemon's authenticated desktop User route for host capture.
    pub fn from_display_observer_route(
        route: AuthenticatedSessionRouteBinding,
    ) -> Result<Self, ClipboardServiceError> {
        if route
            .provider_ref()
            .is_none_or(|provider| provider.to_canonical_string() != "Provider/display-wayland")
            || route.service().as_str() != "d2b.display.v3"
            || route.evidence_class()
                != d2b_contracts_resource::v3::identity::EvidenceClass::UnixPeer
            || route.locality() != d2b_contracts_resource::v3::identity::Locality::Local
            || route.subject_ref().resource_type().as_str() != "User"
            || route
                .provider_generation()
                .is_none_or(|generation| generation.get() == 0)
            || route.reconnect_generation().get() == 0
        {
            return Err(ClipboardServiceError::HostSessionInvalid);
        }
        Ok(Self {
            subject_ref: route.subject_ref().clone(),
            zone: route.zone().clone(),
            provider_generation: route
                .provider_generation()
                .expect("validated display provider generation")
                .get(),
            reconnect_generation: route.reconnect_generation().get(),
            role: ClipboardServiceRole::Bridge,
        })
    }

    /// Admit a Guest display route together with the committed host User.
    pub fn from_display_dependency_route(
        route: AuthenticatedSessionRouteBinding,
        user_ref: ResourceRef,
    ) -> Result<Self, ClipboardServiceError> {
        if route
            .provider_ref()
            .is_none_or(|provider| provider.to_canonical_string() != "Provider/display-wayland")
            || route.service().as_str() != "d2b.display.v3"
            || route.evidence_class()
                != d2b_contracts_resource::v3::identity::EvidenceClass::UnixPeer
            || route.locality() != d2b_contracts_resource::v3::identity::Locality::Local
            || route.subject_ref().resource_type().as_str() != "Guest"
            || user_ref.resource_type().as_str() != "User"
            || route
                .provider_generation()
                .is_none_or(|generation| generation.get() == 0)
            || route.reconnect_generation().get() == 0
        {
            return Err(ClipboardServiceError::HostSessionInvalid);
        }
        Ok(Self {
            subject_ref: user_ref,
            zone: route.zone().clone(),
            provider_generation: route
                .provider_generation()
                .expect("validated display provider generation")
                .get(),
            reconnect_generation: route.reconnect_generation().get(),
            role: ClipboardServiceRole::Bridge,
        })
    }

    /// Borrow the authenticated subject reference.
    pub fn subject_ref(&self) -> &ResourceRef {
        &self.subject_ref
    }

    /// Borrow the authenticated Zone.
    pub fn zone(&self) -> &str {
        self.zone.as_str()
    }

    /// Borrow the authenticated Guest/User/Provider identity.
    pub fn guest_ref(&self) -> String {
        self.subject_ref.to_canonical_string()
    }

    /// Return the reconnect generation used for replay fencing.
    pub const fn reconnect_generation(&self) -> u64 {
        self.reconnect_generation
    }

    /// Return the authenticated service role.
    pub const fn role(&self) -> ClipboardServiceRole {
        self.role
    }

    /// Whether the subject is a Guest.
    pub fn is_guest(&self) -> bool {
        self.subject_ref.resource_type().as_str() == "Guest"
    }

    fn is_user(&self) -> bool {
        self.subject_ref.resource_type().as_str() == "User"
    }
}

impl core::fmt::Debug for AuthenticatedClipboardSession {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("AuthenticatedClipboardSession(REDACTED)")
    }
}

/// A paste route bound to two authenticated session identities.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthenticatedPasteRoute {
    operation_id: String,
    source_subject: ResourceRef,
    source_zone: String,
    source_guest: Option<String>,
    source_reconnect_generation: u64,
    destination_zone: String,
    destination_guest: String,
    reconnect_generation: u64,
}

impl AuthenticatedPasteRoute {
    /// Bind a source and destination session without accepting lexical IDs.
    pub fn from_sessions(
        source: &AuthenticatedClipboardSession,
        destination: &AuthenticatedClipboardSession,
    ) -> Result<Self, ClipboardServiceError> {
        if !destination.is_guest() {
            return Err(ClipboardServiceError::SessionUnauthenticated);
        }
        if !source.is_guest() && !source.is_user() {
            return Err(ClipboardServiceError::SessionUnauthenticated);
        }
        if !matches!(
            source.role(),
            ClipboardServiceRole::Bridge | ClipboardServiceRole::Picker
        ) || destination.role() != ClipboardServiceRole::Bridge
        {
            return Err(ClipboardServiceError::SessionUnauthenticated);
        }
        Ok(Self {
            operation_id: operation_id_for_sessions(source, destination),
            source_subject: source.subject_ref.clone(),
            source_zone: source.zone().to_owned(),
            source_guest: source.is_guest().then(|| source.guest_ref()),
            source_reconnect_generation: source.reconnect_generation(),
            destination_zone: destination.zone().to_owned(),
            destination_guest: destination.subject_ref.to_canonical_string(),
            reconnect_generation: destination.reconnect_generation(),
        })
    }

    /// Borrow the operation binding minted for this authenticated route.
    pub fn operation_id(&self) -> &str {
        &self.operation_id
    }

    pub(crate) fn source_zone(&self) -> &str {
        &self.source_zone
    }

    pub(crate) fn source_subject(&self) -> &ResourceRef {
        &self.source_subject
    }

    pub(crate) fn destination_zone(&self) -> &str {
        &self.destination_zone
    }

    pub(crate) fn source_reconnect_generation(&self) -> u64 {
        self.source_reconnect_generation
    }

    pub(crate) fn source_guest(&self) -> Option<&str> {
        self.source_guest.as_deref()
    }

    pub(crate) fn destination_guest(&self) -> &str {
        &self.destination_guest
    }

    pub(crate) fn reconnect_generation(&self) -> u64 {
        self.reconnect_generation
    }
}

/// Typed display dependency observation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DisplayDependency {
    /// Whether the display Provider is absent or Ready.
    pub status: DependencyStatus,
    /// The typed service contract consumed by clipd-host.
    pub service_contract: &'static str,
    /// Authenticated display evidence, when the dependency is Ready.
    pub evidence: Option<DisplayDependencyEvidence>,
}

/// Authenticated Guest-selection metadata used to suppress a host echo.
///
/// The receipt is issued only for a live entry owned by the supplied Guest
/// session and is consumed by host capture.  Clipboard bytes never cross this
/// boundary.
pub struct GuestSelectionEvent {
    source_zone: ZoneId,
    source_guest: ResourceRef,
    source_generation: u64,
    entry_digest: String,
    expires_at: u64,
}

/// Accepted clipboard descriptors with their transport credit reservation.
///
/// The credit bundle is retained until this value is dropped, so closing the
/// returned descriptors also closes the reservation's ownership window.
pub struct VerifiedClipboardAttachments {
    descriptors: Vec<std::os::fd::OwnedFd>,
    credits: CreditBundle,
    permit: FdPermit,
    max_size_bytes: u64,
    max_total_bytes: u64,
    fd_read_timeout: Duration,
}

struct VerifiedReceivedFds<F> {
    descriptors: Vec<F>,
    permit: FdPermit,
}

impl VerifiedClipboardAttachments {
    /// Return the number of accepted descriptors.
    pub const fn len(&self) -> usize {
        self.descriptors.len()
    }

    /// Return whether no descriptors were accepted.
    pub const fn is_empty(&self) -> bool {
        self.descriptors.is_empty()
    }

    /// Consume every descriptor through the authenticated byte bound.
    pub fn read_all(self) -> Result<Vec<Vec<u8>>, FdReadError> {
        let Self {
            descriptors,
            credits: _credits,
            permit: _permit,
            max_size_bytes,
            max_total_bytes,
            fd_read_timeout,
        } = self;
        let mut total_bytes = 0_u64;
        let mut payloads = Vec::with_capacity(descriptors.len());
        for descriptor in descriptors {
            let remaining_bytes = max_total_bytes.saturating_sub(total_bytes);
            let read_limit = max_size_bytes.min(remaining_bytes);
            let payload = match crate::fd::read_owned_fd_bounded_with_timeout(
                descriptor,
                read_limit,
                fd_read_timeout,
            ) {
                Err(FdReadError::SizeExceeded { .. }) if read_limit < max_size_bytes => {
                    return Err(FdReadError::AggregateSizeExceeded {
                        limit: max_total_bytes,
                    });
                }
                result => result?,
            };
            append_bounded_payload(&mut payloads, &mut total_bytes, payload, max_total_bytes)?;
        }
        Ok(payloads)
    }
}

fn append_bounded_payload(
    payloads: &mut Vec<Vec<u8>>,
    total_bytes: &mut u64,
    payload: Vec<u8>,
    max_total_bytes: u64,
) -> Result<(), FdReadError> {
    let observed = total_bytes.saturating_add(payload.len() as u64);
    if observed > max_total_bytes {
        return Err(FdReadError::AggregateSizeExceeded {
            limit: max_total_bytes,
        });
    }
    *total_bytes = observed;
    payloads.push(payload);
    Ok(())
}

impl core::fmt::Debug for VerifiedClipboardAttachments {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("VerifiedClipboardAttachments")
            .field("descriptor_count", &self.descriptors.len())
            .finish()
    }
}

#[derive(Debug, Clone)]
struct EchoSuppression {
    guest: String,
    zone: ZoneId,
    generation: u64,
    expires_at: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
struct DisplayDependencyFence {
    controller_generation: u64,
    reconnect_generation: u64,
    provider_generation: u64,
    session_digest: [u8; 32],
}

impl DisplayDependencyFence {
    fn from_evidence(evidence: &DisplayDependencyEvidence) -> Self {
        Self {
            controller_generation: evidence.controller_generation(),
            reconnect_generation: evidence.reconnect_generation(),
            provider_generation: evidence.generation(),
            session_digest: evidence.session_digest(),
        }
    }

    fn accepts(&self, next: &Self) -> bool {
        let current_generation = (
            self.controller_generation,
            self.reconnect_generation,
            self.provider_generation,
        );
        let next_generation = (
            next.controller_generation,
            next.reconnect_generation,
            next.provider_generation,
        );
        next_generation > current_generation
            || (next_generation == current_generation && next.session_digest == self.session_digest)
    }

    fn next_is_strictly_newer(&self, next: &Self) -> bool {
        (
            next.controller_generation,
            next.reconnect_generation,
            next.provider_generation,
        ) > (
            self.controller_generation,
            self.reconnect_generation,
            self.provider_generation,
        )
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DisplayDependencyFenceState {
    NeverObserved,
    Active(DisplayDependencyFence),
    Revoked(DisplayDependencyFence),
}

impl DisplayDependencyFenceState {
    fn accepts(&self, next: &DisplayDependencyFence) -> bool {
        match self {
            Self::NeverObserved => true,
            Self::Active(current) => current.accepts(next),
            Self::Revoked(current) => current.next_is_strictly_newer(next),
        }
    }

    fn revoke(self) -> Self {
        match self {
            Self::NeverObserved => Self::NeverObserved,
            Self::Active(current) | Self::Revoked(current) => Self::Revoked(current),
        }
    }
}

impl core::fmt::Debug for GuestSelectionEvent {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("GuestSelectionEvent(REDACTED)")
    }
}

/// Bridge effect port. Clipboard payloads are represented by attachments in
/// the real adapter; this trait never accepts a path or a raw compositor
/// socket.
pub trait ClipboardBridgePort {
    /// Notify the display bridge of a Guest selection without payload bytes.
    fn notify_guest_selection(
        &mut self,
        guest: &str,
        mime: &str,
    ) -> Result<(), ClipboardServiceError>;
    /// Cancel one opaque entry.
    fn cancel_entry(&mut self, token: &str) -> Result<(), ClipboardServiceError>;
}

/// Service failures with stable content-free codes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClipboardServiceError {
    /// Display dependency is absent or not Ready.
    DependencyUnavailable,
    /// Cross-Zone transfer is denied.
    CrossZoneDenied,
    /// Guest is suspended.
    GuestSuspended,
    /// Audit queue is full.
    AuditUnavailable,
    /// History rejected the item.
    HistoryRejected,
    /// A picker is required before materialization.
    PickerRequired,
    /// The ComponentSession route was not authenticated for this Provider.
    SessionUnauthenticated,
    /// A one-use picker receipt did not match the route or entry.
    PickerReceiptInvalid,
    /// Host capture was suppressed as a recent Guest echo.
    EchoSuppressed,
    /// Host capture was supplied by a Guest session.
    HostSessionInvalid,
    /// A received attachment failed mandatory kernel metadata checks.
    AttachmentRejected,
    /// Daemon-owned workers were not drained before authority release.
    AuthorityReleaseIncomplete,
}

impl core::fmt::Display for ClipboardServiceError {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str(match self {
            Self::DependencyUnavailable => "dependency-unavailable",
            Self::CrossZoneDenied => "cross-zone-denied",
            Self::GuestSuspended => "zone-suspended",
            Self::AuditUnavailable => "audit-unavailable",
            Self::HistoryRejected => "clipboard-history-rejected",
            Self::PickerRequired => "picker-required",
            Self::SessionUnauthenticated => "session-unauthenticated",
            Self::PickerReceiptInvalid => "picker-receipt-invalid",
            Self::EchoSuppressed => "echo-suppressed",
            Self::HostSessionInvalid => "host-session-invalid",
            Self::AttachmentRejected => "attachment-rejected",
            Self::AuthorityReleaseIncomplete => "authority-release-incomplete",
        })
    }
}

impl std::error::Error for ClipboardServiceError {}

/// In-memory clipboard service.
pub struct ClipdHost {
    policy: Policy,
    history: ClipboardHistory,
    audit: ClipboardAuditQueue,
    dependency: DisplayDependency,
    echo_window: BTreeMap<String, EchoSuppression>,
    fd_permits: FdPermitPool,
    display_fence: DisplayDependencyFenceState,
}

impl ClipdHost {
    /// Construct clipd-host with an optional display dependency.
    pub fn new(
        policy: Policy,
        audit_capacity: usize,
        display: Option<DisplayDependencyEvidence>,
    ) -> Result<Self, ClipboardServiceError> {
        let history = ClipboardHistory::new(crate::ClipboardConfig::from_policy(policy.clone()))
            .map_err(|_| ClipboardServiceError::HistoryRejected)?;
        let max_concurrent_fds = policy.max_concurrent_fds();
        let mut host = Self {
            policy,
            history,
            audit: ClipboardAuditQueue::new(audit_capacity),
            dependency: DisplayDependency {
                status: DependencyStatus::Absent,
                service_contract: "d2b.display.host-clipboard.v3",
                evidence: None,
            },
            echo_window: BTreeMap::new(),
            fd_permits: FdPermitPool::new(max_concurrent_fds),
            display_fence: DisplayDependencyFenceState::NeverObserved,
        };
        host.reconcile_display_dependency(display)?;
        Ok(host)
    }

    /// Return the typed display dependency state.
    pub const fn dependency(&self) -> &DisplayDependency {
        &self.dependency
    }

    /// Reconcile the authenticated display dependency and fence stale proofs.
    ///
    /// A missing proof is a fail-closed revocation and drains echo metadata.
    /// New proofs must advance the Core controller, reconnect, or Provider
    /// generation; an older proof cannot restore clipboard authority.
    pub fn reconcile_display_dependency(
        &mut self,
        display: Option<DisplayDependencyEvidence>,
    ) -> Result<DependencyStatus, ClipboardServiceError> {
        let Some(display) = display else {
            self.dependency.status = DependencyStatus::Absent;
            self.dependency.evidence = None;
            self.echo_window.clear();
            self.display_fence = self.display_fence.revoke();
            return Ok(DependencyStatus::Absent);
        };
        if !Self::valid_display_dependency(&display) {
            return Err(ClipboardServiceError::DependencyUnavailable);
        }
        let next_fence = DisplayDependencyFence::from_evidence(&display);
        if !self.display_fence.accepts(&next_fence) {
            return Err(ClipboardServiceError::DependencyUnavailable);
        }
        self.dependency.status = DependencyStatus::Ready;
        self.dependency.evidence = Some(display);
        self.display_fence = DisplayDependencyFenceState::Active(next_fence);
        Ok(DependencyStatus::Ready)
    }

    /// Flush acknowledged audit records without exposing clipboard payloads.
    pub fn flush_audit<S: ClipboardAuditSink>(
        &mut self,
        sink: &mut S,
        limit: usize,
    ) -> Result<usize, S::Error> {
        self.audit.flush_to(sink, limit)
    }

    /// Validate all descriptors from one authenticated attachment packet.
    ///
    /// Control truncation, descriptor metadata, operation direction, and the
    /// configured concurrent-FD bound are checked before ownership escapes the
    /// receive adapter.
    fn accept_received_fds<F>(
        &self,
        session: &AuthenticatedClipboardSession,
        batch: ReceivedFdBatch<F>,
        attachment_class: AttachmentClass,
    ) -> Result<VerifiedReceivedFds<F>, ClipboardServiceError>
    where
        F: std::os::fd::AsFd,
    {
        if session.role() != ClipboardServiceRole::Bridge {
            return Err(ClipboardServiceError::SessionUnauthenticated);
        }
        if self.dependency.status != DependencyStatus::Ready
            || !self.dependency_zone_matches(session.zone())
        {
            return Err(ClipboardServiceError::DependencyUnavailable);
        }
        Self::validate_attachment_subject(session, attachment_class)?;
        if matches!(
            attachment_class,
            AttachmentClass::HostSelectionRead | AttachmentClass::HostSelectionWrite
        ) && !self.dependency_host_user_matches(session)
        {
            return Err(ClipboardServiceError::HostSessionInvalid);
        }
        let descriptors = batch
            .validate_control(attachment_class, self.policy.max_item_bytes() as u64)
            .map_err(|_: FdSafetyError| ClipboardServiceError::AttachmentRejected)?;
        let permit = self
            .fd_permits
            .acquire(descriptors.len())
            .map_err(|_| ClipboardServiceError::AttachmentRejected)?;
        Ok(VerifiedReceivedFds {
            descriptors,
            permit,
        })
    }

    fn validate_attachment_subject(
        session: &AuthenticatedClipboardSession,
        attachment_class: AttachmentClass,
    ) -> Result<(), ClipboardServiceError> {
        match attachment_class {
            AttachmentClass::GuestTransfer if !session.is_guest() => {
                Err(ClipboardServiceError::SessionUnauthenticated)
            }
            AttachmentClass::HostSelectionRead | AttachmentClass::HostSelectionWrite
                if !session.is_user() =>
            {
                Err(ClipboardServiceError::HostSessionInvalid)
            }
            _ => Ok(()),
        }
    }

    /// Admit attachments from the audited Unix session adapter.
    ///
    /// `VerifiedPacket` can only be produced after the transport has checked
    /// the authenticated packet descriptor policy.  This boundary performs
    /// the Provider-specific size, mode, link-count, CLOEXEC, and direction
    /// checks before any descriptor is returned to the service.
    pub fn accept_verified_packet(
        &self,
        session: &AuthenticatedClipboardSession,
        packet: VerifiedPacket,
        attachment_class: AttachmentClass,
    ) -> Result<VerifiedClipboardAttachments, ClipboardServiceError> {
        let (_payload, attachments, credits) = packet.into_parts();
        let descriptors = attachments
            .into_iter()
            .map(|attachment| match attachment {
                AcceptedAttachment::File(fd) => Ok(fd),
                AcceptedAttachment::Credentials(_) => {
                    Err(ClipboardServiceError::AttachmentRejected)
                }
            })
            .collect::<Result<Vec<_>, _>>()?;
        let VerifiedReceivedFds {
            descriptors,
            permit,
        } = self.accept_received_fds(
            session,
            ReceivedFdBatch::from_verified_transport(descriptors),
            attachment_class,
        )?;
        Ok(VerifiedClipboardAttachments {
            descriptors,
            credits,
            permit,
            max_size_bytes: self.policy.max_item_bytes() as u64,
            max_total_bytes: self.policy.max_total_bytes() as u64,
            fd_read_timeout: Duration::from_secs(self.policy.fd_write_timeout_seconds()),
        })
    }

    /// Capture one Guest selection after audit admission.
    pub fn capture_guest(
        &mut self,
        session: &AuthenticatedClipboardSession,
        mime: &str,
        bytes: &[u8],
        now_secs: u64,
    ) -> Result<String, ClipboardServiceError> {
        self.history.gc(now_secs);
        self.prune_echo_window(now_secs);
        if self.dependency.status != DependencyStatus::Ready {
            return Err(ClipboardServiceError::DependencyUnavailable);
        }
        if !self.dependency_zone_matches(session.zone()) {
            return Err(ClipboardServiceError::DependencyUnavailable);
        }
        if !session.is_guest() || session.role() != ClipboardServiceRole::Bridge {
            return Err(ClipboardServiceError::SessionUnauthenticated);
        }
        if !self.policy.allow_guest_capture() {
            return Err(ClipboardServiceError::HistoryRejected);
        }
        if bytes.len() > self.policy.max_item_bytes() {
            return Err(ClipboardServiceError::HistoryRejected);
        }
        let guest = session.subject_ref().to_canonical_string();
        self.history
            .check_guest_request(&guest, now_secs)
            .map_err(|_| ClipboardServiceError::HistoryRejected)?;
        let entry = ClipboardEntry::new(&guest, mime, bytes, now_secs)
            .map_err(|_| ClipboardServiceError::HistoryRejected)?;
        let token = entry.token().to_owned();
        if self.audit.is_full() {
            return Err(ClipboardServiceError::AuditUnavailable);
        }
        self.history
            .insert(entry)
            .map_err(|_| ClipboardServiceError::HistoryRejected)?;
        self.history
            .record_guest_request(&guest, now_secs)
            .map_err(|_| ClipboardServiceError::HistoryRejected)?;
        let event = ClipboardAuditEvent::new(
            "guest",
            "host",
            ClipboardReason::Allowed,
            SizeBucket::from_len(bytes.len()),
        )
        .with_event_type(crate::ClipboardEventType::GuestCapture);
        self.audit
            .push(event)
            .map_err(|_| ClipboardServiceError::AuditUnavailable)?;
        self.echo_window.insert(
            token.clone(),
            EchoSuppression {
                guest,
                zone: session.zone.clone(),
                generation: session.reconnect_generation,
                expires_at: now_secs.saturating_add(2),
            },
        );
        Ok(token)
    }

    /// Issue authenticated metadata for a Guest selection event.
    pub fn guest_selection_event(
        &mut self,
        session: &AuthenticatedClipboardSession,
        entry_digest: &str,
        now_secs: u64,
    ) -> Result<GuestSelectionEvent, ClipboardServiceError> {
        self.history.gc(now_secs);
        self.prune_echo_window(now_secs);
        if !session.is_guest()
            || session.role() != ClipboardServiceRole::Bridge
            || !self.dependency_zone_matches(session.zone())
        {
            return Err(ClipboardServiceError::SessionUnauthenticated);
        }
        let owner = entry_owner_for_session(session);
        let Some(suppression) = self.echo_window.get(entry_digest) else {
            return Err(ClipboardServiceError::HistoryRejected);
        };
        if suppression.expires_at <= now_secs
            || suppression.guest != owner
            || self.history.authorize_guest(&owner).is_err()
            || !self
                .history
                .entry_owned_and_live(entry_digest, &owner, now_secs)
        {
            return Err(ClipboardServiceError::HistoryRejected);
        }
        Ok(GuestSelectionEvent {
            source_zone: session.zone.clone(),
            source_guest: session.subject_ref.clone(),
            source_generation: session.reconnect_generation,
            entry_digest: entry_digest.to_owned(),
            expires_at: suppression.expires_at,
        })
    }

    /// Capture one host selection through an authenticated host session.
    pub fn capture_host(
        &mut self,
        session: &AuthenticatedClipboardSession,
        mime: &str,
        bytes: &[u8],
        source_event: Option<GuestSelectionEvent>,
        now_secs: u64,
    ) -> Result<String, ClipboardServiceError> {
        self.history.gc(now_secs);
        self.prune_echo_window(now_secs);
        if self.dependency.status != DependencyStatus::Ready
            || !self.dependency_zone_matches(session.zone())
        {
            return Err(ClipboardServiceError::DependencyUnavailable);
        }
        if !session.is_user() || session.role() != ClipboardServiceRole::Bridge {
            return Err(ClipboardServiceError::HostSessionInvalid);
        }
        if !self.dependency_host_user_matches(session) {
            return Err(ClipboardServiceError::HostSessionInvalid);
        }
        if !self.policy.allow_host_capture() {
            return Err(ClipboardServiceError::HistoryRejected);
        }
        if self.policy.suppress_echo()
            && source_event.as_ref().is_some_and(|event| {
                event.expires_at > now_secs
                    && event.source_zone.as_str() == session.zone()
                    && event.source_guest.resource_type().as_str() == "Guest"
                    && self
                        .echo_window
                        .get(&event.entry_digest)
                        .is_some_and(|suppression| {
                            suppression.guest == event.source_guest.to_canonical_string()
                                && suppression.zone == event.source_zone
                                && suppression.generation == event.source_generation
                        })
            })
        {
            if !self.audit.is_full() {
                let source_zone = source_event
                    .as_ref()
                    .map_or_else(|| session.zone.clone(), |event| event.source_zone.clone());
                let _ = self.audit.push(
                    ClipboardAuditEvent::new(
                        source_zone.as_str(),
                        session.zone(),
                        ClipboardReason::EchoSuppressed,
                        SizeBucket::from_len(bytes.len()),
                    )
                    .with_event_type(crate::ClipboardEventType::EchoSuppressed),
                );
            }
            return Err(ClipboardServiceError::EchoSuppressed);
        }
        if bytes.len() > self.policy.max_item_bytes() {
            return Err(ClipboardServiceError::HistoryRejected);
        }
        let owner = entry_owner_for_session(session);
        let entry = ClipboardEntry::new(owner, mime, bytes, now_secs)
            .map_err(|_| ClipboardServiceError::HistoryRejected)?;
        let token = entry.token().to_owned();
        if self.audit.is_full() {
            return Err(ClipboardServiceError::AuditUnavailable);
        }
        self.history
            .insert(entry)
            .map_err(|_| ClipboardServiceError::HistoryRejected)?;
        self.audit
            .push(
                ClipboardAuditEvent::new(
                    session.zone(),
                    session.zone(),
                    ClipboardReason::Allowed,
                    SizeBucket::from_len(bytes.len()),
                )
                .with_event_type(crate::ClipboardEventType::HostCapture),
            )
            .map_err(|_| ClipboardServiceError::AuditUnavailable)?;
        Ok(token)
    }

    /// Suspend a Guest and revoke its paste authority.
    pub fn suspend_guest(&mut self, guest: &str) {
        self.history.suspend_guest(guest);
    }

    /// Resume a Guest.
    pub fn resume_guest(&mut self, guest: &str) {
        self.history.resume_guest(guest);
    }

    /// Purge all Guest-owned entries on lifecycle destruction.
    pub fn purge_guest(&mut self, guest: &str) {
        self.history.purge_guest(guest);
        self.echo_window
            .retain(|_, suppression| suppression.guest != guest);
    }

    /// Purge every retained payload and associated authority metadata.
    pub fn purge_all(&mut self) {
        self.history.purge_all();
        self.echo_window.clear();
    }

    fn prune_echo_window(&mut self, now_secs: u64) {
        self.echo_window
            .retain(|_, suppression| suppression.expires_at > now_secs);
    }

    /// Check whether a cross-Zone route is allowed.
    pub const fn cross_zone_allowed(&self) -> bool {
        self.policy.cross_zone_enabled()
    }

    /// Check a paste route before any attachment is requested.
    pub fn authorize_paste(
        &self,
        route: &AuthenticatedPasteRoute,
    ) -> Result<(), ClipboardServiceError> {
        self.authorize_paste_inner(route, false)
    }

    /// Check a paste route after the authenticated picker completed.
    pub fn authorize_paste_after_picker(
        &self,
        route: &AuthenticatedPasteRoute,
        receipt: &PickerReceipt,
        entry_digest: &str,
        now_secs: u64,
    ) -> Result<(), ClipboardServiceError> {
        if !receipt.matches(route, entry_digest, now_secs)
            || !self
                .history
                .entry_owned_and_live(entry_digest, receipt.source_owner(), now_secs)
        {
            return Err(ClipboardServiceError::PickerReceiptInvalid);
        }

        self.authorize_paste_inner(route, true)
    }

    /// Materialize one selected entry after the one-use receipt has authorized
    /// the exact authenticated paste route.
    pub fn materialize_after_picker(
        &mut self,
        route: &AuthenticatedPasteRoute,
        receipt: PickerReceipt,
        entry_digest: &str,
        now_secs: u64,
    ) -> Result<Vec<u8>, ClipboardServiceError> {
        self.authorize_paste_after_picker(route, &receipt, entry_digest, now_secs)?;
        self.history
            .materialize(
                entry_digest,
                route.source_subject().to_canonical_string().as_str(),
                now_secs,
            )
            .map_err(|_| ClipboardServiceError::PickerReceiptInvalid)
    }

    /// Complete one authenticated picker operation and mint its one-use
    /// receipt.  The history claim is made before returning, so retrying the
    /// same completion cannot mint another receipt.
    pub fn complete_picker(
        &mut self,
        source: &AuthenticatedClipboardSession,
        destination: &AuthenticatedClipboardSession,
        request: &PickerRequest,
        result: PickerResult,
        entry_digest: impl Into<String>,
        now_secs: u64,
    ) -> Result<PickerReceipt, PickerError> {
        PickerAuthority::complete(
            source,
            destination,
            request,
            result,
            entry_digest,
            &mut self.history,
            now_secs,
        )
    }

    fn authorize_paste_inner(
        &self,
        route: &AuthenticatedPasteRoute,
        picker_completed: bool,
    ) -> Result<(), ClipboardServiceError> {
        if self.dependency.status != DependencyStatus::Ready {
            return Err(ClipboardServiceError::DependencyUnavailable);
        }
        if !self.dependency_zone_matches(route.destination_zone()) {
            return Err(ClipboardServiceError::DependencyUnavailable);
        }
        if route.source_subject().resource_type().as_str() == "User"
            && self.dependency.evidence.as_ref().is_none_or(|evidence| {
                evidence.user_ref() != route.source_subject()
                    || evidence.zone().as_str() != route.source_zone()
            })
        {
            return Err(ClipboardServiceError::HostSessionInvalid);
        }

        if route.source_zone() != route.destination_zone() && !self.policy.cross_zone_enabled() {
            return Err(ClipboardServiceError::CrossZoneDenied);
        }
        self.history
            .authorize_guest(route.destination_guest())
            .map_err(|_| ClipboardServiceError::GuestSuspended)
            .and_then(|()| {
                if let Some(source_guest) = route.source_guest() {
                    self.history
                        .authorize_guest(source_guest)
                        .map_err(|_| ClipboardServiceError::GuestSuspended)?;
                }
                if self.policy.require_picker_for_paste() && !picker_completed {
                    Err(ClipboardServiceError::PickerRequired)
                } else {
                    Ok(())
                }
            })
    }

    /// Return bounded history size.
    pub fn history_len(&self) -> usize {
        self.history.len()
    }

    fn dependency_zone_matches(&self, zone: &str) -> bool {
        self.dependency
            .evidence
            .as_ref()
            .is_some_and(|evidence| evidence.zone().as_str() == zone && evidence.generation() != 0)
    }

    fn dependency_host_user_matches(&self, session: &AuthenticatedClipboardSession) -> bool {
        self.dependency
            .evidence
            .as_ref()
            .is_some_and(|evidence| evidence.user_ref() == session.subject_ref())
    }

    fn valid_display_dependency(display: &DisplayDependencyEvidence) -> bool {
        display.provider_ref().to_canonical_string() == DISPLAY_PROVIDER_REF
            && display.host_execution_ref().resource_type().as_str() == "Host"
            && display.user_ref().resource_type().as_str() == "User"
            && display.reconnect_generation() != 0
            && display.controller_generation() != 0
            && display.generation() != 0
            && display.session_digest() != [0; 32]
    }
}

pub(crate) fn entry_owner_for_session(session: &AuthenticatedClipboardSession) -> String {
    if session.is_guest() {
        session.subject_ref().to_canonical_string()
    } else {
        format!("Host/{}", session.zone())
    }
}

pub(crate) fn operation_id_for_sessions(
    source: &AuthenticatedClipboardSession,
    destination: &AuthenticatedClipboardSession,
) -> String {
    let mut digest = Sha256::new();
    digest.update(source.subject_ref.to_canonical_string().as_bytes());
    digest.update([0]);
    digest.update(source.zone.as_str().as_bytes());
    digest.update([0]);
    digest.update(source.provider_generation.to_be_bytes());
    digest.update([0]);
    digest.update(source.reconnect_generation.to_be_bytes());
    digest.update([0]);
    digest.update(destination.subject_ref.to_canonical_string().as_bytes());
    digest.update([0]);
    digest.update(destination.zone.as_str().as_bytes());
    digest.update([0]);
    digest.update(destination.provider_generation.to_be_bytes());
    digest.update([0]);
    digest.update(destination.reconnect_generation.to_be_bytes());
    format!(
        "sha256:{}",
        digest
            .finalize()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>()
    )
}

/// Provider configuration used by history and service components.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClipboardConfig {
    policy: Policy,
    host_entry_ttl_secs: u64,
    guest_entry_ttl_secs: u64,
}

impl Default for ClipboardConfig {
    fn default() -> Self {
        Self {
            policy: Policy::default(),
            host_entry_ttl_secs: 3600,
            guest_entry_ttl_secs: 3600,
        }
    }
}

impl ClipboardConfig {
    /// Construct configuration from a policy.
    pub fn from_policy(policy: Policy) -> Self {
        Self {
            policy,
            ..Self::default()
        }
    }

    /// Return the policy.
    pub const fn policy(&self) -> &Policy {
        &self.policy
    }

    /// Return item byte limit.
    pub const fn max_item_bytes(&self) -> usize {
        self.policy.max_item_bytes()
    }

    /// Return total byte limit.
    pub const fn max_total_bytes(&self) -> usize {
        self.policy.max_total_bytes()
    }

    /// Return history entry bound.
    pub const fn max_history_entries(&self) -> usize {
        self.policy.max_history_entries()
    }

    /// Return per-Guest rate limit.
    pub const fn max_guest_rate_per_min(&self) -> u32 {
        self.policy.max_guest_rate_per_min()
    }

    /// Return Host entry TTL.
    pub const fn host_entry_ttl_secs(&self) -> u64 {
        self.host_entry_ttl_secs
    }

    /// Return Guest entry TTL.
    pub const fn guest_entry_ttl_secs(&self) -> u64 {
        self.guest_entry_ttl_secs
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::picker::{PickerAuthority, PickerRequest};

    fn display() -> DisplayDependencyEvidence {
        DisplayDependencyEvidence {
            provider_ref: ResourceRef::parse("Provider/display-wayland").unwrap(),
            zone: ZoneId::parse("zone-a").unwrap(),
            host_execution_ref: ResourceRef::parse("Host/display-wayland").unwrap(),
            user_ref: ResourceRef::parse("User/alice").unwrap(),
            provider_generation: 1,
            reconnect_generation: 7,
            controller_generation: 1,
            session_digest: [7; 32],
        }
    }

    fn guest(name: &str, zone: &str, generation: u64) -> AuthenticatedClipboardSession {
        AuthenticatedClipboardSession {
            subject_ref: ResourceRef::parse(&format!("Guest/{name}")).unwrap(),
            zone: ZoneId::parse(zone).unwrap(),
            provider_generation: 1,
            reconnect_generation: generation,
            role: ClipboardServiceRole::Bridge,
        }
    }

    fn user(zone: &str, generation: u64) -> AuthenticatedClipboardSession {
        AuthenticatedClipboardSession {
            subject_ref: ResourceRef::parse("User/alice").unwrap(),
            zone: ZoneId::parse(zone).unwrap(),
            provider_generation: 1,
            reconnect_generation: generation,
            role: ClipboardServiceRole::Bridge,
        }
    }

    #[test]
    fn paste_routes_are_bound_to_authenticated_sessions_and_one_use_picker_receipts() {
        let mut host = ClipdHost::new(Policy::default(), 4, Some(display())).unwrap();
        let source = user("zone-a", 7);
        let destination = guest("work", "zone-a", 8);
        let route = AuthenticatedPasteRoute::from_sessions(&source, &destination).unwrap();
        assert_eq!(
            host.authorize_paste(&route),
            Err(ClipboardServiceError::PickerRequired)
        );

        let request = PickerRequest::new(
            route.operation_id(),
            "zone-a",
            "Guest/work",
            vec!["text/plain".to_owned()],
        )
        .unwrap();
        let digest = host
            .capture_host(&source, "text/plain", b"hello", None, 100)
            .unwrap();
        let receipt = host
            .complete_picker(
                &source,
                &destination,
                &request,
                crate::picker::PickerResult::Selected(digest.clone()),
                digest.clone(),
                100,
            )
            .expect("picker receipt");
        assert!(
            host.authorize_paste_after_picker(&route, &receipt, &digest, 3_700)
                == Err(ClipboardServiceError::PickerReceiptInvalid)
        );
        assert_eq!(
            host.complete_picker(
                &source,
                &destination,
                &request,
                crate::picker::PickerResult::Selected(digest.clone()),
                digest.clone(),
                100,
            )
            .err(),
            Some(crate::picker::PickerError::ResultMismatch)
        );
    }

    #[test]
    fn guest_capture_requires_ready_display_and_authenticated_guest() {
        let guest = guest("work", "zone-a", 1);
        let user = user("zone-a", 1);
        let mut absent = ClipdHost::new(Policy::default(), 4, None).unwrap();
        assert_eq!(
            absent.capture_guest(&guest, "text/plain", b"hello", 100),
            Err(ClipboardServiceError::DependencyUnavailable)
        );
        let mut host = ClipdHost::new(Policy::default(), 4, Some(display())).unwrap();
        assert_eq!(
            host.capture_guest(&user, "text/plain", b"hello", 100),
            Err(ClipboardServiceError::SessionUnauthenticated)
        );
        assert!(
            host.capture_guest(&guest, "text/plain", b"hello", 100)
                .is_ok()
        );
    }

    #[test]
    fn host_capture_enforces_policy_and_audits_suppressed_echo() {
        let policy = Policy::new(true, true, true, true, true, 3, 4096, 4096, 32, 60).unwrap();
        let mut host = ClipdHost::new(policy, 4, Some(display())).unwrap();
        let guest = guest("work", "zone-a", 1);
        let token = host
            .capture_guest(&guest, "text/plain", b"hello", 100)
            .unwrap();
        let event = host.guest_selection_event(&guest, &token, 101).unwrap();
        assert_eq!(
            host.capture_host(&user("zone-a", 1), "text/plain", b"hello", Some(event), 101),
            Err(ClipboardServiceError::EchoSuppressed)
        );
        assert_eq!(host.history_len(), 1);
    }

    #[test]
    fn host_capture_requires_the_display_bound_user() {
        let mut host = ClipdHost::new(Policy::default(), 4, Some(display())).unwrap();
        let other_user = AuthenticatedClipboardSession {
            subject_ref: ResourceRef::parse("User/bob").unwrap(),
            zone: ZoneId::parse("zone-a").unwrap(),
            provider_generation: 1,
            reconnect_generation: 1,
            role: ClipboardServiceRole::Bridge,
        };
        assert_eq!(
            host.capture_host(&other_user, "text/plain", b"hello", None, 100),
            Err(ClipboardServiceError::HostSessionInvalid)
        );
    }

    #[test]
    fn echo_receipts_expire_and_purge_with_the_guest_history() {
        let mut host = ClipdHost::new(Policy::default(), 4, Some(display())).unwrap();
        let guest = guest("work", "zone-a", 1);
        let token = host
            .capture_guest(&guest, "text/plain", b"hello", 100)
            .unwrap();
        assert!(host.guest_selection_event(&guest, &token, 101).is_ok());
        assert_eq!(
            host.guest_selection_event(&guest, &token, 102).err(),
            Some(ClipboardServiceError::HistoryRejected)
        );
        let token = host
            .capture_guest(&guest, "text/plain", b"world", 200)
            .unwrap();
        host.purge_guest("Guest/work");
        assert_eq!(
            host.guest_selection_event(&guest, &token, 200).err(),
            Some(ClipboardServiceError::HistoryRejected)
        );
    }

    #[test]
    fn echo_suppression_does_not_compare_guest_and_host_generations() {
        let policy = Policy::new(true, true, true, true, true, 3, 4096, 4096, 32, 60).unwrap();
        let mut host = ClipdHost::new(policy, 4, Some(display())).unwrap();
        let guest = guest("work", "zone-a", 7);
        let token = host
            .capture_guest(&guest, "text/plain", b"hello", 100)
            .unwrap();
        let event = host.guest_selection_event(&guest, &token, 101).unwrap();
        assert_eq!(
            host.capture_host(
                &user("zone-a", 99),
                "text/plain",
                b"hello",
                Some(event),
                101
            ),
            Err(ClipboardServiceError::EchoSuppressed)
        );
    }

    #[test]
    fn host_selection_writes_are_admitted_for_authenticated_user_sessions() {
        let host = user("zone-a", 99);
        let guest = guest("work", "zone-a", 7);
        assert!(
            ClipdHost::validate_attachment_subject(&host, AttachmentClass::HostSelectionWrite)
                .is_ok()
        );
        assert_eq!(
            ClipdHost::validate_attachment_subject(&guest, AttachmentClass::HostSelectionWrite),
            Err(ClipboardServiceError::HostSessionInvalid)
        );
    }

    #[test]
    fn provider_subject_cannot_capture_or_write_host_selection() {
        let provider = AuthenticatedClipboardSession {
            subject_ref: ResourceRef::parse("Provider/display-wayland").unwrap(),
            zone: ZoneId::parse("zone-a").unwrap(),
            provider_generation: 1,
            reconnect_generation: 1,
            role: ClipboardServiceRole::Bridge,
        };
        let mut host = ClipdHost::new(Policy::default(), 4, Some(display())).unwrap();
        assert_eq!(
            host.capture_host(&provider, "text/plain", b"hello", None, 100),
            Err(ClipboardServiceError::HostSessionInvalid)
        );
        assert_eq!(
            ClipdHost::validate_attachment_subject(&provider, AttachmentClass::HostSelectionWrite),
            Err(ClipboardServiceError::HostSessionInvalid)
        );
    }

    #[test]
    fn guest_capture_prunes_expired_echo_metadata_without_host_activity() {
        let mut host = ClipdHost::new(Policy::default(), 4, Some(display())).unwrap();
        let guest = guest("work", "zone-a", 1);
        host.capture_guest(&guest, "text/plain", b"old", 100)
            .unwrap();
        host.capture_guest(&guest, "text/plain", b"new", 200)
            .unwrap();
        assert_eq!(host.echo_window.len(), 1);
    }

    #[test]
    fn host_capture_prunes_expired_echo_metadata_without_guest_activity() {
        let mut host = ClipdHost::new(Policy::default(), 4, Some(display())).unwrap();
        let guest = guest("work", "zone-a", 1);
        let user = user("zone-a", 1);
        host.capture_guest(&guest, "text/plain", b"old", 100)
            .unwrap();
        host.capture_host(&user, "text/plain", b"new", None, 200)
            .unwrap();
        assert!(host.echo_window.is_empty());
    }

    #[test]
    fn attachment_batch_enforces_the_aggregate_byte_limit() {
        let mut payloads = Vec::new();
        let mut total_bytes = 0;
        append_bounded_payload(&mut payloads, &mut total_bytes, vec![1; 5], 8).unwrap();
        assert_eq!(
            append_bounded_payload(&mut payloads, &mut total_bytes, vec![2; 4], 8),
            Err(FdReadError::AggregateSizeExceeded { limit: 8 })
        );
        assert_eq!(payloads, vec![vec![1; 5]]);
        assert_eq!(total_bytes, 5);
    }

    #[test]
    fn picker_completion_requires_a_requested_mime_type() {
        let mut host = ClipdHost::new(Policy::default(), 4, Some(display())).unwrap();
        let source = user("zone-a", 1);
        let destination = guest("work", "zone-a", 1);
        let route = AuthenticatedPasteRoute::from_sessions(&source, &destination).unwrap();
        let request = PickerRequest::new(
            route.operation_id(),
            "zone-a",
            "Guest/work",
            vec!["image/png".to_owned()],
        )
        .unwrap();
        let digest = host
            .capture_host(&source, "text/plain", b"hello", None, 100)
            .unwrap();
        assert_eq!(
            PickerAuthority::complete(
                &source,
                &destination,
                &request,
                crate::picker::PickerResult::Selected(digest.clone()),
                digest,
                &mut host.history,
                100,
            )
            .expect_err("MIME mismatch must refuse picker completion"),
            crate::picker::PickerError::ResultMismatch
        );
    }

    #[test]
    fn picker_receipt_cannot_authorize_a_purged_entry() {
        let mut host = ClipdHost::new(Policy::default(), 4, Some(display())).unwrap();
        let source = user("zone-a", 1);
        let destination = guest("work", "zone-a", 1);
        let route = AuthenticatedPasteRoute::from_sessions(&source, &destination).unwrap();
        let request = PickerRequest::new(
            route.operation_id(),
            "zone-a",
            "Guest/work",
            vec!["text/plain".to_owned()],
        )
        .unwrap();
        let digest = host
            .capture_host(&source, "text/plain", b"hello", None, 100)
            .unwrap();
        let receipt = PickerAuthority::complete(
            &source,
            &destination,
            &request,
            crate::picker::PickerResult::Selected(digest.clone()),
            digest.clone(),
            &mut host.history,
            100,
        )
        .unwrap();
        host.purge_guest("Host/zone-a");
        assert_eq!(
            host.authorize_paste_after_picker(&route, &receipt, &digest, 101),
            Err(ClipboardServiceError::PickerReceiptInvalid)
        );
    }

    #[test]
    fn suspended_guest_cannot_complete_a_history_picker() {
        let mut host = ClipdHost::new(Policy::default(), 4, Some(display())).unwrap();
        let source = guest("source", "zone-a", 1);
        let destination = guest("work", "zone-a", 1);
        let digest = host
            .capture_guest(&source, "text/plain", b"secret", 100)
            .unwrap();
        host.suspend_guest("Guest/source");
        let route = AuthenticatedPasteRoute::from_sessions(&source, &destination).unwrap();
        let request = PickerRequest::new(
            route.operation_id(),
            "zone-a",
            "Guest/work",
            vec!["text/plain".to_owned()],
        )
        .unwrap();
        assert_eq!(
            PickerAuthority::complete(
                &source,
                &destination,
                &request,
                crate::picker::PickerResult::Selected(digest.clone()),
                digest,
                &mut host.history,
                100,
            )
            .expect_err("suspended source must not mint a receipt"),
            crate::picker::PickerError::ResultMismatch
        );
    }

    #[test]
    fn display_dependency_is_bound_to_the_operation_zone() {
        let mut host = ClipdHost::new(Policy::default(), 4, Some(display())).unwrap();
        let other_zone = guest("work", "personal", 1);
        assert_eq!(
            host.capture_guest(&other_zone, "text/plain", b"hello", 100),
            Err(ClipboardServiceError::DependencyUnavailable)
        );
    }

    #[test]
    fn suspended_guest_cannot_issue_selection_event_for_live_entry() {
        let mut host = ClipdHost::new(Policy::default(), 4, Some(display())).unwrap();
        let guest = guest("work", "zone-a", 1);
        let token = host
            .capture_guest(&guest, "text/plain", b"hello", 100)
            .unwrap();
        host.suspend_guest("Guest/work");
        assert!(matches!(
            host.guest_selection_event(&guest, &token, 101),
            Err(ClipboardServiceError::HistoryRejected)
        ));
    }

    #[test]
    fn picker_cancellation_results_never_mint_receipts() {
        let mut host = ClipdHost::new(Policy::default(), 4, Some(display())).unwrap();
        let source = guest("source", "zone-a", 1);
        let destination = guest("work", "zone-a", 1);
        let route = AuthenticatedPasteRoute::from_sessions(&source, &destination).unwrap();
        let request = PickerRequest::new(
            route.operation_id(),
            "zone-a",
            "Guest/work",
            vec!["text/plain".to_owned()],
        )
        .unwrap();
        for result in [
            crate::picker::PickerResult::Cancelled,
            crate::picker::PickerResult::TimedOut,
            crate::picker::PickerResult::Failed,
        ] {
            assert!(matches!(
                PickerAuthority::complete(
                    &source,
                    &destination,
                    &request,
                    result,
                    "sha256:entry",
                    &mut host.history,
                    100,
                ),
                Err(crate::picker::PickerError::ResultMismatch)
            ));
        }
    }

    #[test]
    fn display_dependency_revocation_and_generation_fencing_are_fail_closed() {
        let current = display();
        let mut host = ClipdHost::new(Policy::default(), 4, Some(current.clone())).unwrap();
        let guest = guest("work", "zone-a", 1);
        assert!(
            host.capture_guest(&guest, "text/plain", b"hello", 100)
                .is_ok()
        );

        assert_eq!(
            host.reconcile_display_dependency(None),
            Ok(DependencyStatus::Absent)
        );
        assert_eq!(
            host.reconcile_display_dependency(Some(current.clone())),
            Err(ClipboardServiceError::DependencyUnavailable)
        );
        assert_eq!(
            host.capture_guest(&guest, "text/plain", b"world", 101),
            Err(ClipboardServiceError::DependencyUnavailable)
        );

        host.reconcile_display_dependency(Some(DisplayDependencyEvidence {
            controller_generation: 2,
            ..current.clone()
        }))
        .unwrap();
        assert_eq!(
            host.reconcile_display_dependency(Some(current)),
            Err(ClipboardServiceError::DependencyUnavailable)
        );
    }

    #[test]
    fn paste_operation_identity_includes_provider_generation() {
        let source = user("zone-a", 1);
        let destination = guest("work", "zone-a", 1);
        let mut replacement = guest("work", "zone-a", 1);
        replacement.provider_generation = 2;

        assert_ne!(
            operation_id_for_sessions(&source, &destination),
            operation_id_for_sessions(&source, &replacement)
        );
    }
}
