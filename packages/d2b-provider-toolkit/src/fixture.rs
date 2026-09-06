//! Deterministic Provider fixtures and a transport-independent fake.
//!
//! The fixture deliberately stops at the Provider contract boundary. It
//! carries a descriptor, a Zone path, and bounded canonical payloads; it does
//! not open a session, resolve a route, or perform an effect. That makes the
//! same fake useful for registry, typed service, and generated-server tests.

use std::{
    future::ready,
    sync::{
        Arc, Mutex,
        atomic::{AtomicU64, Ordering},
    },
};

use d2b_contracts_provider::v3::SpecifiedProviderMethod;
use d2b_contracts_resource::v3::identity::{
    AuthenticatedSubjectContext, BindingDigest, EvidenceClass, Locality, ReconnectGeneration,
    ServiceName, SessionBinding, SessionPurpose, TranscriptHash, TransportBinding,
};
use d2b_contracts_resource::v3::{
    CanonicalJsonObject, ConfigurationGeneration, ResourceGeneration, ResourceName, ResourceRef,
    ResourceTypeName, ResourceUid, SchemaFingerprint, execution_policy::BoundedToken,
};
use d2b_contracts_zone_session::v3::zone_routing::{ZoneLabelId, ZonePath};
use d2b_provider::{
    ProviderAgentError, ProviderAgentRequest, ProviderAgentResponse, ProviderAgentService,
    ProviderCapabilitySet, ProviderClass, ProviderDescriptor, ProviderImplementationId,
    ProviderMethodName, ProviderRuntimeError, SessionIdentity,
};

use crate::{
    ProviderService,
    error::ProviderToolkitError,
    values::{ProviderValues, ValuesError},
};

/// The fixed timestamp used by a fresh fixture.
pub const FIXTURE_NOW_UNIX_MS: u64 = 1_700_000_000_000;

const FIXTURE_ZONE_NAME: &str = "dev";
const FIXTURE_DIGEST: &str =
    "sha256:0000000000000000000000000000000000000000000000000000000000000000";

/// A clock whose value changes only when a test changes it.
#[derive(Debug, Default)]
pub struct DeterministicClock {
    now_unix_ms: AtomicU64,
}

impl DeterministicClock {
    /// Construct a clock at the supplied millisecond timestamp.
    pub fn new(now_unix_ms: u64) -> Self {
        Self {
            now_unix_ms: AtomicU64::new(now_unix_ms),
        }
    }

    /// Read the current timestamp.
    pub fn now_unix_ms(&self) -> u64 {
        self.now_unix_ms.load(Ordering::Acquire)
    }

    /// Set the timestamp exactly.
    pub fn set(&self, now_unix_ms: u64) {
        self.now_unix_ms.store(now_unix_ms, Ordering::Release);
    }

    /// Advance the timestamp without allowing integer wraparound.
    pub fn advance(&self, delta_ms: u64) {
        self.now_unix_ms
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |current| {
                Some(current.saturating_add(delta_ms))
            })
            .expect("the update closure always returns a value");
    }
}

/// The immutable inputs shared by Provider conformance tests.
#[derive(Clone)]
pub struct Fixture {
    /// The exact descriptor the fake publishes.
    pub descriptor: ProviderDescriptor,
    /// The deterministic observation timestamp.
    pub now_unix_ms: u64,
    zone: ZonePath,
}

impl std::fmt::Debug for Fixture {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("Fixture")
            .field("schema_version", &self.descriptor.schema_version())
            .field(
                "provider_generation",
                &self.descriptor.provider_generation(),
            )
            .field("now_unix_ms", &self.now_unix_ms)
            .finish_non_exhaustive()
    }
}

impl Fixture {
    /// Build a valid descriptor for one Provider family.
    pub fn new(
        class: ProviderClass,
        ordinal: usize,
    ) -> Result<Self, d2b_provider::RegistryBuildError> {
        let zone = ZonePath::new(vec![
            ZoneLabelId::parse(FIXTURE_ZONE_NAME)
                .map_err(|_| d2b_provider::RegistryBuildError::InvalidDescriptor)?,
        ])
        .map_err(|_| d2b_provider::RegistryBuildError::InvalidDescriptor)?;
        let provider_name = format!("{}-fake-{ordinal}", class.as_str());
        let provider_ref = ResourceRef::new(
            ResourceTypeName::parse("Provider")
                .map_err(|_| d2b_provider::RegistryBuildError::InvalidDescriptor)?,
            ResourceName::parse(provider_name)
                .map_err(|_| d2b_provider::RegistryBuildError::InvalidDescriptor)?,
        );
        let methods = if class == ProviderClass::Transport {
            ProviderCapabilitySet::from_specified(SpecifiedProviderMethod::TRANSPORT_CARRIAGE)
                .map_err(|_| d2b_provider::RegistryBuildError::InvalidDescriptor)?
        } else {
            let methods = fixture_methods()
                .into_iter()
                .map(Self::method)
                .chain(
                    ["health", "inspect", "observability"]
                        .into_iter()
                        .map(|method| {
                            ProviderMethodName::parse(method)
                                .expect("fixture observation methods are valid tokens")
                        }),
                )
                .collect::<Vec<_>>();
            ProviderCapabilitySet::new(methods)?
        };
        let descriptor = ProviderDescriptor::new(
            zone.clone(),
            provider_ref,
            class,
            ProviderImplementationId::parse(format!("{}-fixture", class.as_str()))
                .map_err(|_| d2b_provider::RegistryBuildError::InvalidDescriptor)?,
            ConfigurationGeneration::new(1)
                .map_err(|_| d2b_provider::RegistryBuildError::InvalidDescriptor)?,
            ResourceGeneration::new(1)
                .map_err(|_| d2b_provider::RegistryBuildError::InvalidDescriptor)?,
            ServiceName::parse("d2b.provider.v3")
                .map_err(|_| d2b_provider::RegistryBuildError::InvalidDescriptor)?,
            methods,
        )?;
        Self::from_descriptor(descriptor, FIXTURE_NOW_UNIX_MS)
    }

    /// Build a fixture around an already validated descriptor.
    pub fn from_descriptor(
        descriptor: ProviderDescriptor,
        now_unix_ms: u64,
    ) -> Result<Self, d2b_provider::RegistryBuildError> {
        descriptor.validate()?;
        if now_unix_ms == 0 {
            return Err(d2b_provider::RegistryBuildError::InvalidDescriptor);
        }
        Ok(Self {
            zone: descriptor.zone().clone(),
            descriptor,
            now_unix_ms,
        })
    }

    /// Borrow the fixture's Zone path.
    pub const fn zone(&self) -> &ZonePath {
        &self.zone
    }

    /// Return the canonical lower-kebab name for a closed v3 method.
    pub fn method(method: SpecifiedProviderMethod) -> ProviderMethodName {
        ProviderMethodName::parse(match method {
            SpecifiedProviderMethod::OpenTransport => "open-transport",
            SpecifiedProviderMethod::CloseTransport => "close-transport",
            SpecifiedProviderMethod::ObserveTransport => "observe-transport",
            SpecifiedProviderMethod::AssessUpdate => "assess-update",
            SpecifiedProviderMethod::PlanUpgrade => "plan-upgrade",
            SpecifiedProviderMethod::ExecuteUpgrade => "execute-upgrade",
            _ => unreachable!("specified Provider method is closed"),
        })
        .expect("closed Provider methods are valid bounded tokens")
    }

    /// Derive authenticated session evidence for this fixture.
    ///
    /// The helper uses only synthetic, validated resource identities and is
    /// intended for local admission tests. The returned identity is not an
    /// authorization capability.
    pub fn session_identity(&self) -> Result<SessionIdentity, ProviderRuntimeError> {
        let session = SessionBinding::new(
            SchemaFingerprint::parse(FIXTURE_DIGEST)
                .map_err(|_| ProviderRuntimeError::SessionIdentityMismatch)?,
            TransportBinding::new(
                Locality::Local,
                BindingDigest::parse(FIXTURE_DIGEST)
                    .map_err(|_| ProviderRuntimeError::SessionIdentityMismatch)?,
            ),
            ReconnectGeneration::new(1)
                .map_err(|_| ProviderRuntimeError::SessionIdentityMismatch)?,
            TranscriptHash::from_bytes([0; 32]),
        );
        let subject = AuthenticatedSubjectContext::new(
            ResourceRef::parse("Process/provider-agent")
                .map_err(|_| ProviderRuntimeError::SessionIdentityMismatch)?,
            ResourceUid::parse("123e4567-e89b-42d3-a456-426614174000")
                .map_err(|_| ProviderRuntimeError::SessionIdentityMismatch)?,
            ResourceRef::parse("Zone/dev")
                .map_err(|_| ProviderRuntimeError::SessionIdentityMismatch)?,
            EvidenceClass::UnixPeer,
            SessionPurpose::parse("provider-invoke")
                .map_err(|_| ProviderRuntimeError::SessionIdentityMismatch)?,
            self.descriptor.service().clone(),
            session,
        )
        .with_provider_ref(self.descriptor.provider_ref().clone())
        .with_provider_generation(self.descriptor.provider_generation());
        SessionIdentity::from_authenticated(self.zone.clone(), &subject)
    }
}

fn fixture_methods() -> [SpecifiedProviderMethod; 6] {
    [
        SpecifiedProviderMethod::OpenTransport,
        SpecifiedProviderMethod::CloseTransport,
        SpecifiedProviderMethod::ObserveTransport,
        SpecifiedProviderMethod::AssessUpdate,
        SpecifiedProviderMethod::PlanUpgrade,
        SpecifiedProviderMethod::ExecuteUpgrade,
    ]
}

/// A bounded, deterministic Provider implementation used by registry and
/// typed service tests.
#[derive(Clone)]
pub struct FakeProvider {
    fixture: Fixture,
    calls: Arc<Mutex<Vec<ProviderMethodName>>>,
}

impl std::fmt::Debug for FakeProvider {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("FakeProvider")
            .field("call_count", &self.call_count())
            .finish_non_exhaustive()
    }
}

impl FakeProvider {
    /// Construct a fake from a fixture.
    pub fn new(fixture: Fixture) -> Self {
        Self {
            fixture,
            calls: Arc::new(Mutex::new(Vec::new())),
        }
    }

    /// Borrow the fixture.
    pub const fn fixture(&self) -> &Fixture {
        &self.fixture
    }

    /// Borrow the published descriptor.
    pub const fn descriptor(&self) -> &ProviderDescriptor {
        &self.fixture.descriptor
    }

    /// Return the opaque runtime instance handle for this Provider.
    pub fn instance(
        &self,
    ) -> Result<d2b_provider::instance::ProviderInstance, d2b_provider::RegistryBuildError> {
        d2b_provider::instance::ProviderInstance::new(
            self.descriptor().provider_ref().clone(),
            self.descriptor().provider_generation(),
        )
    }

    /// Return the number of accepted calls.
    pub fn call_count(&self) -> usize {
        self.calls
            .lock()
            .map(|calls| calls.len())
            .unwrap_or_default()
    }

    /// Return the accepted method sequence without exposing payloads.
    pub fn calls(&self) -> Vec<ProviderMethodName> {
        self.calls
            .lock()
            .map(|calls| calls.clone())
            .unwrap_or_default()
    }

    /// Clear the accepted method sequence.
    pub fn reset_calls(&self) {
        if let Ok(mut calls) = self.calls.lock() {
            calls.clear();
        }
    }

    /// Invoke one fixture method with an empty canonical payload.
    pub fn call(
        &self,
        method: ProviderMethodName,
    ) -> Result<CanonicalJsonObject, ProviderToolkitError> {
        self.dispatch_method(&method, &CanonicalJsonObject::empty())
    }

    /// Run the canonical health, inspection, and observability sequence.
    pub fn conformance_sequence(&self) -> Result<(), ProviderToolkitError> {
        self.reset_calls();
        for method in ["health", "inspect", "observability"] {
            let method =
                ProviderMethodName::parse(method).map_err(|_| ProviderToolkitError::WireInvalid)?;
            self.dispatch_method(&method, &CanonicalJsonObject::empty())?;
        }
        let calls = self.calls();
        let expected = ["health", "inspect", "observability"]
            .into_iter()
            .map(|method| ProviderMethodName::parse(method).expect("fixture method"))
            .collect::<Vec<_>>();
        if calls == expected {
            Ok(())
        } else {
            Err(ProviderToolkitError::WireInvalid)
        }
    }

    fn dispatch_method(
        &self,
        method: &ProviderMethodName,
        _payload: &CanonicalJsonObject,
    ) -> Result<CanonicalJsonObject, ProviderToolkitError> {
        if !self
            .fixture
            .descriptor
            .capabilities()
            .contains_method(method)
        {
            return Err(ProviderToolkitError::WireInvalid);
        }
        if let Ok(mut calls) = self.calls.lock() {
            if calls.len() >= crate::fakes::MAX_RECORDED_CALLS {
                return Err(ProviderToolkitError::CapacityOutOfRange);
            }
            calls.push(method.clone());
        }
        let values = ProviderValues::new(self.descriptor(), self.fixture.now_unix_ms)
            .map_err(|_: ValuesError| ProviderToolkitError::WireInvalid)?;
        match method.as_str() {
            "health" => values.health_payload(),
            "inspect" => values.inspection_payload(),
            "observability" => values.observability_payload(),
            _ => CanonicalJsonObject::parse(br#"{"accepted":true}"#)
                .map_err(|_| ProviderToolkitError::WireInvalid),
        }
    }
}

impl ProviderService for FakeProvider {
    fn dispatch(
        &self,
        method: &BoundedToken,
        payload: &CanonicalJsonObject,
    ) -> Result<CanonicalJsonObject, ProviderToolkitError> {
        let method = ProviderMethodName::parse(method.as_str())
            .map_err(|_| ProviderToolkitError::WireInvalid)?;
        self.dispatch_method(&method, payload)
    }
}

impl ProviderAgentService for FakeProvider {
    fn dispatch(
        &self,
        request: ProviderAgentRequest,
    ) -> impl std::future::Future<Output = Result<ProviderAgentResponse, ProviderAgentError>> + Send
    {
        let method = Fixture::method(request.method());
        let result = self
            .dispatch_method(&method, request.payload())
            .map(ProviderAgentResponse::new)
            .map_err(|_| ProviderAgentError::HandlerFailed);
        ready(result)
    }
}

/// A small request shape used when a conformance case needs a lease-like
/// operation without introducing an unapproved credential wire type.
#[derive(Clone, PartialEq, Eq)]
pub struct SampleLeaseRequest {
    provider_ref: ResourceRef,
    consumer_ref: ResourceRef,
    expires_at_unix_ms: u64,
}

impl std::fmt::Debug for SampleLeaseRequest {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("SampleLeaseRequest(<redacted>)")
    }
}

impl SampleLeaseRequest {
    /// Borrow the Provider that would issue the sample lease.
    pub const fn provider_ref(&self) -> &ResourceRef {
        &self.provider_ref
    }

    /// Borrow the synthetic consumer reference.
    pub const fn consumer_ref(&self) -> &ResourceRef {
        &self.consumer_ref
    }

    /// Return the bounded expiry timestamp.
    pub const fn expires_at_unix_ms(&self) -> u64 {
        self.expires_at_unix_ms
    }
}

/// Construct a deterministic, non-secret lease request for a fixture.
pub fn sample_lease_request(fixture: &Fixture) -> SampleLeaseRequest {
    SampleLeaseRequest {
        provider_ref: fixture.descriptor.provider_ref().clone(),
        consumer_ref: ResourceRef::parse("Provider/consumer-fake")
            .expect("sample consumer reference is valid"),
        expires_at_unix_ms: fixture.now_unix_ms.saturating_add(30_000),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_fixture_publishes_a_closed_descriptor_and_deterministic_time() {
        for (ordinal, class) in ProviderClass::ALL.into_iter().enumerate() {
            let fixture = Fixture::new(class, ordinal).expect("fixture descriptor");
            assert_eq!(fixture.now_unix_ms, FIXTURE_NOW_UNIX_MS);
            assert_eq!(fixture.descriptor.class(), class);
            assert_eq!(fixture.descriptor.zone(), fixture.zone());
        }
    }

    #[test]
    fn the_fake_provider_returns_health_inspection_and_observability_in_order() {
        let fixture = Fixture::new(ProviderClass::Runtime, 0).expect("fixture");
        let provider = FakeProvider::new(fixture);
        provider
            .conformance_sequence()
            .expect("the sequence is accepted");
        assert_eq!(provider.call_count(), 3);
    }

    #[test]
    fn the_clock_is_explicit_and_never_wraps() {
        let clock = DeterministicClock::new(u64::MAX - 2);
        clock.advance(8);
        assert_eq!(clock.now_unix_ms(), u64::MAX);
        clock.set(42);
        assert_eq!(clock.now_unix_ms(), 42);
    }
}
