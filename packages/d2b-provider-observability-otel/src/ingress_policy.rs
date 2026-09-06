//! Shared structural metric admission for every telemetry ingress.

use std::{
    collections::{BTreeMap, BTreeSet},
    sync::Arc,
    time::Instant,
};
use zeroize::Zeroize;

use crate::metric_policy::{
    IdentityCanaries, MetricDescriptor, MetricPolicyError, validate_data_point,
    validate_resource_attributes,
};
use d2b_contracts_provider::v3::{TelemetryFrame, TelemetrySignal};

/// Maximum frame bytes accepted before policy evaluation.
pub const MAX_INGRESS_FRAME_BYTES: usize = d2b_contracts_provider::v3::MAX_TELEMETRY_FRAME_BYTES;
/// Maximum metric points in one admitted frame.
pub const MAX_POINTS_PER_FRAME: usize = 1024;
/// Maximum frames quarantined for one stream.
pub const MAX_QUARANTINED_CONNECTIONS: usize = 64;
/// Maximum live connection states retained for policy accounting.
pub const MAX_TRACKED_CONNECTIONS: usize = 4096;
/// Backward-compatible name for the bounded quarantine ceiling.
pub const MAX_QUARANTINED_FRAMES: usize = MAX_QUARANTINED_CONNECTIONS;
/// Number of policy violations before a stream is quarantined.
pub const QUARANTINE_VIOLATION_THRESHOLD: u8 = 3;
/// Maximum time a stream quarantine is intended to remain active.
pub const QUARANTINE_DURATION_SECONDS: u64 = 30;
/// Idle connection state is reclaimed on the same bounded horizon.
pub const CONNECTION_IDLE_SECONDS: u64 = 30;
/// Idle metric series are reclaimed on the same monotonic horizon.
pub const SERIES_IDLE_SECONDS: u64 = CONNECTION_IDLE_SECONDS;
/// Provider-wide cap on retained metric series. Existing active series are
/// never evicted to admit a new one.
pub const MAX_PROVIDER_SERIES: usize = 4096;
/// Fair quota for one identified producer's distinct metric series.
pub const MAX_SERIES_PER_PRODUCER: usize = MAX_PROVIDER_SERIES / 4;

/// Telemetry ingress adapter.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Ingress {
    /// Compact Unix datagram emitter.
    EmitterUnix,
    /// OTLP over a private Unix socket.
    OtlpUnix,
    /// OTLP over the ZoneLink vsock path.
    OtlpVsock,
    /// D096 imported named stream.
    ImportStream,
}

impl Ingress {
    /// Stable metric label.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::EmitterUnix => "emitter_unix",
            Self::OtlpUnix => "otlp_unix",
            Self::OtlpVsock => "otlp_vsock",
            Self::ImportStream => "import_stream",
        }
    }
}

/// Bounded policy outcome class.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IngressErrorClass {
    /// No error.
    None,
    /// A label key is outside the allowlist.
    KeyNotAllowlisted,
    /// A key is unconditionally forbidden.
    KeyForbidden,
    /// A key has an identity suffix.
    KeySuffixForbidden,
    /// A value carries a resource identity.
    ValueIdentity,
    /// The frame could not be decoded.
    Malformed,
    /// The frame exceeded the byte bound.
    Oversize,
}

impl IngressErrorClass {
    /// Stable metric label.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::KeyNotAllowlisted => "key_not_allowlisted",
            Self::KeyForbidden => "key_forbidden",
            Self::KeySuffixForbidden => "key_suffix_forbidden",
            Self::ValueIdentity => "value_identity",
            Self::Malformed => "malformed",
            Self::Oversize => "oversize",
        }
    }
}

/// Admission result.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IngressOutcome {
    /// The complete frame passed validation and capacity.
    Accepted,
    /// The complete frame was rejected.
    Rejected,
    /// The stream was quarantined after a policy failure.
    Quarantined,
}

/// Clock used for injected quarantine expiry tests.
pub trait IngressClock: Send + Sync {
    /// Return monotonic milliseconds for policy state.
    fn now_ms(&self) -> u64;
}

#[derive(Debug, Default)]
struct SystemIngressClock;

impl IngressClock for SystemIngressClock {
    fn now_ms(&self) -> u64 {
        static START: std::sync::OnceLock<Instant> = std::sync::OnceLock::new();
        START
            .get_or_init(Instant::now)
            .elapsed()
            .as_millis()
            .min(u128::from(u64::MAX)) as u64
    }
}

/// One metric data point in a decoded frame.
#[derive(Clone, PartialEq)]
pub struct MetricPoint {
    /// Descriptor shared by the frame.
    pub descriptor: MetricDescriptor,
    /// Data-point labels.
    pub labels: BTreeMap<String, String>,
    /// Finite metric value retained for export.
    pub value: f64,
}

impl core::fmt::Debug for MetricPoint {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("MetricPoint")
            .field("descriptor", &self.descriptor.name())
            .field("label_count", &self.labels.len())
            .finish()
    }
}

/// A bounded frame. All points are admitted or rejected together.
#[derive(Clone, PartialEq)]
pub struct MetricFrame {
    /// Approximate encoded frame size.
    pub encoded_bytes: usize,
    /// Data points.
    pub points: Vec<MetricPoint>,
    /// Trusted resource attributes stamped by the collector.
    pub resource_attributes: BTreeMap<String, String>,
}

impl core::fmt::Debug for MetricFrame {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("MetricFrame")
            .field("encoded_bytes", &self.encoded_bytes)
            .field("point_count", &self.points.len())
            .field("resource_attribute_count", &self.resource_attributes.len())
            .finish()
    }
}

impl Drop for MetricFrame {
    fn drop(&mut self) {
        for point in &mut self.points {
            for value in point.labels.values_mut() {
                value.zeroize();
            }
        }
        for value in self.resource_attributes.values_mut() {
            value.zeroize();
        }
    }
}

impl MetricFrame {
    /// Construct one frame.
    pub fn new(
        encoded_bytes: usize,
        points: impl IntoIterator<Item = MetricPoint>,
        resource_attributes: BTreeMap<String, String>,
    ) -> Self {
        Self {
            encoded_bytes,
            points: points.into_iter().collect(),
            resource_attributes,
        }
    }

    /// Measure the canonical encoded frame instead of trusting caller bytes.
    pub fn measured_encoded_bytes(&self) -> usize {
        serde_json::to_vec(&serde_json::json!({
            "points": self.points.iter().map(|point| {
                serde_json::json!({
                    "descriptor": point.descriptor.name(),
                    "labels": point.labels,
                    "value": point.value,
                })
            }).collect::<Vec<_>>(),
            "resource_attributes": self.resource_attributes,
        }))
        .map(|bytes| bytes.len())
        .unwrap_or(usize::MAX)
    }
}

/// A policy gate with bounded stream quarantine state.
pub struct IngressPolicyGate {
    connections: BTreeMap<(Ingress, u64), ConnectionState>,
    quarantined_connections: usize,
    series: BTreeMap<SeriesKey, SeriesState>,
    producer_series: BTreeMap<ProducerKey, BTreeSet<SeriesKey>>,
    max_provider_series: usize,
    max_series_per_producer: usize,
    clock: Arc<dyn IngressClock>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct SeriesKey {
    metric_name: String,
    labels: Vec<(String, String)>,
    resource_attributes: Vec<(String, String)>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
struct ProducerKey {
    ingress: Ingress,
    connection_id: u64,
}

#[derive(Debug, Default)]
struct SeriesState {
    shared_last_seen_ms: Option<u64>,
    producer_members: BTreeMap<ProducerKey, u64>,
}

#[derive(Debug, Default)]
struct ConnectionState {
    violations: u8,
    quarantined: bool,
    quarantined_until_ms: Option<u64>,
    last_seen_ms: u64,
}

impl core::fmt::Debug for IngressPolicyGate {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("IngressPolicyGate")
            .field("tracked_connections", &self.connections.len())
            .field("quarantined_connections", &self.quarantined_connections)
            .field("series", &self.series.len())
            .field("producer_series", &self.producer_series.len())
            .finish()
    }
}

impl Default for IngressPolicyGate {
    fn default() -> Self {
        Self::with_clock(Arc::new(SystemIngressClock))
    }
}

impl IngressPolicyGate {
    /// Admit one raw shared frame before any queue mutation or eviction.
    pub fn admit_raw(
        &mut self,
        ingress: Ingress,
        connection_id: u64,
        bytes: &[u8],
    ) -> (IngressOutcome, IngressErrorClass) {
        self.prune_expired();
        if bytes.len() > MAX_INGRESS_FRAME_BYTES {
            return self.reject(ingress, connection_id, IngressErrorClass::Oversize);
        }
        let frame = match d2b_contracts_provider::v3::validate_raw_frame(bytes) {
            Ok(frame) => frame,
            Err(_) => return self.reject(ingress, connection_id, IngressErrorClass::Malformed),
        };
        self.admit_parsed_inner(ingress, connection_id, &frame, bytes.len())
    }

    /// Admit one previously parsed and validated shared frame.
    pub fn admit_parsed(
        &mut self,
        ingress: Ingress,
        connection_id: u64,
        frame: &TelemetryFrame,
        encoded_bytes: usize,
    ) -> (IngressOutcome, IngressErrorClass) {
        self.prune_expired();
        self.admit_parsed_inner(ingress, connection_id, frame, encoded_bytes)
    }

    fn admit_parsed_inner(
        &mut self,
        ingress: Ingress,
        connection_id: u64,
        frame: &TelemetryFrame,
        encoded_bytes: usize,
    ) -> (IngressOutcome, IngressErrorClass) {
        if encoded_bytes > MAX_INGRESS_FRAME_BYTES {
            return self.reject(ingress, connection_id, IngressErrorClass::Oversize);
        }
        if frame.signal == TelemetrySignal::Metric {
            let Some(metric) = metric_frame_from_raw(frame, encoded_bytes) else {
                return self.reject(ingress, connection_id, IngressErrorClass::Malformed);
            };
            return self.admit_for_connection(
                ingress,
                connection_id,
                &metric,
                &IdentityCanaries::default(),
                true,
            );
        }
        (IngressOutcome::Accepted, IngressErrorClass::None)
    }

    /// Construct a policy gate with an injected clock.
    pub fn with_clock(clock: Arc<dyn IngressClock>) -> Self {
        Self::from_limits(clock, MAX_PROVIDER_SERIES, MAX_SERIES_PER_PRODUCER)
    }

    #[cfg(test)]
    fn with_clock_and_limits(
        clock: Arc<dyn IngressClock>,
        max_provider_series: usize,
        max_series_per_producer: usize,
    ) -> Self {
        Self::from_limits(clock, max_provider_series, max_series_per_producer)
    }

    fn from_limits(
        clock: Arc<dyn IngressClock>,
        max_provider_series: usize,
        max_series_per_producer: usize,
    ) -> Self {
        Self {
            connections: BTreeMap::new(),
            quarantined_connections: 0,
            series: BTreeMap::new(),
            producer_series: BTreeMap::new(),
            max_provider_series: max_provider_series.max(1),
            max_series_per_producer: max_series_per_producer.max(1),
            clock,
        }
    }

    /// Admit a complete frame before queue/capacity accounting.
    pub fn admit(
        &mut self,
        ingress: Ingress,
        frame: &MetricFrame,
        canaries: &IdentityCanaries,
        capacity_available: bool,
    ) -> (IngressOutcome, IngressErrorClass) {
        self.admit_for_connection(ingress, 0, frame, canaries, capacity_available)
    }

    /// Admit a frame for one opaque stream connection.
    ///
    /// A Unix datagram receiver is one shared socket: it has no stable
    /// per-datagram peer identity, so connection id `0` is the shared
    /// no-identity scope. Stream callers should provide their own bounded
    /// opaque connection id so one noisy producer cannot quarantine or fill
    /// the series budget of its peers.
    pub fn admit_for_connection(
        &mut self,
        ingress: Ingress,
        connection_id: u64,
        frame: &MetricFrame,
        canaries: &IdentityCanaries,
        capacity_available: bool,
    ) -> (IngressOutcome, IngressErrorClass) {
        self.prune_expired();
        if self
            .connections
            .get(&(ingress, connection_id))
            .is_some_and(|state| {
                state.quarantined
                    && state
                        .quarantined_until_ms
                        .is_some_and(|until| self.clock.now_ms() < until)
            })
        {
            return (IngressOutcome::Quarantined, IngressErrorClass::Malformed);
        }
        if frame.measured_encoded_bytes() > MAX_INGRESS_FRAME_BYTES {
            return self.reject(ingress, connection_id, IngressErrorClass::Oversize);
        }
        if !valid_resource_attributes(&frame.resource_attributes) {
            return self.reject(ingress, connection_id, IngressErrorClass::Malformed);
        }
        if frame.points.is_empty() || frame.points.len() > MAX_POINTS_PER_FRAME {
            return self.reject(ingress, connection_id, IngressErrorClass::Malformed);
        }
        for point in &frame.points {
            if !point.value.is_finite() {
                return self.reject(ingress, connection_id, IngressErrorClass::Malformed);
            }
            if let Err(error) = validate_data_point(&point.descriptor, &point.labels, canaries) {
                return self.reject(ingress, connection_id, map_policy_error(error));
            }
        }
        if !capacity_available {
            return (IngressOutcome::Rejected, IngressErrorClass::None);
        }
        let incoming = frame
            .points
            .iter()
            .map(|point| canonical_series_key(point, &frame.resource_attributes))
            .collect::<BTreeSet<_>>();
        let producer = producer_for(ingress, connection_id);
        let new_series = incoming
            .iter()
            .filter(|series| !self.series.contains_key(*series))
            .count();
        let producer_series_count = producer
            .and_then(|producer| self.producer_series.get(&producer))
            .map_or(0, BTreeSet::len);
        let producer_new_series = producer.map_or(0, |producer| {
            let known_series = self.producer_series.get(&producer);
            incoming
                .iter()
                .filter(|series| known_series.is_none_or(|known| !known.contains(*series)))
                .count()
        });
        if self.series.len().saturating_add(new_series) > self.max_provider_series
            || producer_series_count.saturating_add(producer_new_series)
                > self.max_series_per_producer
        {
            return (IngressOutcome::Rejected, IngressErrorClass::None);
        }
        let now = self.clock.now_ms();
        for series in incoming {
            let state = self.series.entry(series.clone()).or_default();
            if let Some(producer) = producer {
                state.producer_members.insert(producer, now);
                self.producer_series
                    .entry(producer)
                    .or_default()
                    .insert(series);
            } else {
                state.shared_last_seen_ms = Some(now);
            }
        }
        (IngressOutcome::Accepted, IngressErrorClass::None)
    }

    /// Number of retained provider metric series.
    pub fn series_count(&self) -> usize {
        let now = self.clock.now_ms();
        self.series
            .values()
            .filter(|state| {
                state.shared_last_seen_ms.is_some_and(|last_seen_ms| {
                    now.saturating_sub(last_seen_ms) < SERIES_IDLE_SECONDS.saturating_mul(1000)
                }) || state.producer_members.values().any(|last_seen_ms| {
                    now.saturating_sub(*last_seen_ms) < SERIES_IDLE_SECONDS.saturating_mul(1000)
                })
            })
            .count()
    }

    /// Whether a stream is quarantined.
    pub fn is_quarantined(&mut self, ingress: Ingress) -> bool {
        self.prune_expired();
        self.connections
            .iter()
            .any(|((kind, _), state)| *kind == ingress && state.quarantined)
    }

    /// Whether one opaque connection is quarantined.
    pub fn is_connection_quarantined(&mut self, ingress: Ingress, connection_id: u64) -> bool {
        self.prune_expired();
        self.connections
            .get(&(ingress, connection_id))
            .is_some_and(|state| state.quarantined)
    }

    /// Number of bounded quarantine entries retained.
    pub fn quarantined_frames(&mut self) -> usize {
        self.prune_expired();
        self.quarantined_connections
    }

    /// Credits available to a quarantined imported stream.
    pub fn available_import_credits(&mut self) -> usize {
        self.prune_expired();
        // The legacy API has no connection id. A quarantined import means no
        // anonymous import credits can be granted.
        if self.quarantined_connections == 0 {
            1
        } else {
            0
        }
    }

    /// Credits available to one imported stream connection.
    pub fn available_import_credits_for(&mut self, connection_id: u64) -> usize {
        if self.is_connection_quarantined(Ingress::ImportStream, connection_id) {
            0
        } else {
            1
        }
    }

    /// Forget a disconnected connection and release its quarantine slot.
    pub fn reset_connection(&mut self, ingress: Ingress, connection_id: u64) {
        self.prune_expired();
        self.reset_connection_inner(ingress, connection_id);
    }

    fn reset_connection_inner(&mut self, ingress: Ingress, connection_id: u64) {
        if self
            .connections
            .remove(&(ingress, connection_id))
            .is_some_and(|state| state.quarantined)
        {
            self.quarantined_connections = self.quarantined_connections.saturating_sub(1);
        }
        if let Some(producer) = producer_for(ingress, connection_id) {
            let producer_series = self.producer_series.remove(&producer).unwrap_or_default();
            for series in producer_series {
                self.remove_membership(&series, producer);
            }
        }
    }

    /// Remove expired quarantines and stale connection entries.
    pub fn prune_expired(&mut self) {
        let now = self.clock.now_ms();
        let expired = self
            .connections
            .iter()
            .filter_map(|(key, state)| {
                (state.quarantined_until_ms.is_some_and(|until| now >= until)
                    || (!state.quarantined
                        && now.saturating_sub(state.last_seen_ms)
                            >= CONNECTION_IDLE_SECONDS.saturating_mul(1000)))
                .then_some(*key)
            })
            .collect::<Vec<_>>();
        for key in expired {
            self.reset_connection_inner(key.0, key.1);
        }
        let expired_memberships = self
            .series
            .iter()
            .flat_map(|(series, state)| {
                state
                    .producer_members
                    .iter()
                    .filter_map(|(producer, last_seen_ms)| {
                        (now.saturating_sub(*last_seen_ms)
                            >= SERIES_IDLE_SECONDS.saturating_mul(1000))
                        .then_some((series.clone(), *producer))
                    })
            })
            .collect::<Vec<_>>();
        for (series, producer) in expired_memberships {
            self.remove_membership(&series, producer);
        }
        let expired_shared_series = self
            .series
            .iter()
            .filter_map(|(series, state)| {
                state
                    .shared_last_seen_ms
                    .is_some_and(|last_seen_ms| {
                        now.saturating_sub(last_seen_ms) >= SERIES_IDLE_SECONDS.saturating_mul(1000)
                    })
                    .then_some(series.clone())
            })
            .collect::<Vec<_>>();
        for series in expired_shared_series {
            if let Some(state) = self.series.get_mut(&series) {
                state.shared_last_seen_ms = None;
            }
            self.remove_if_unreferenced(&series);
        }
    }

    fn remove_membership(&mut self, series: &SeriesKey, producer: ProducerKey) {
        let removed = self
            .series
            .get_mut(series)
            .is_some_and(|state| state.producer_members.remove(&producer).is_some());
        if !removed {
            return;
        }
        if let Some(series_set) = self.producer_series.get_mut(&producer) {
            series_set.remove(series);
            if series_set.is_empty() {
                self.producer_series.remove(&producer);
            }
        }
        self.remove_if_unreferenced(series);
    }

    fn remove_if_unreferenced(&mut self, series: &SeriesKey) {
        if self.series.get(series).is_some_and(|state| {
            state.producer_members.is_empty() && state.shared_last_seen_ms.is_none()
        }) {
            self.remove_series(series);
        }
    }

    fn remove_series(&mut self, series: &SeriesKey) {
        let Some(state) = self.series.remove(series) else {
            return;
        };
        for producer in state.producer_members.keys().copied().collect::<Vec<_>>() {
            if let Some(series_set) = self.producer_series.get_mut(&producer) {
                series_set.remove(series);
                if series_set.is_empty() {
                    self.producer_series.remove(&producer);
                }
            }
        }
    }

    fn reject(
        &mut self,
        ingress: Ingress,
        connection_id: u64,
        error: IngressErrorClass,
    ) -> (IngressOutcome, IngressErrorClass) {
        let now = self.clock.now_ms();
        if matches!(ingress, Ingress::EmitterUnix) {
            return (IngressOutcome::Rejected, error);
        }
        if !self.connections.contains_key(&(ingress, connection_id))
            && self.connections.len() >= MAX_TRACKED_CONNECTIONS
        {
            return (IngressOutcome::Rejected, IngressErrorClass::Malformed);
        }
        let state = self
            .connections
            .entry((ingress, connection_id))
            .or_default();
        state.last_seen_ms = now;
        state.violations = state.violations.saturating_add(1);
        if state.violations >= QUARANTINE_VIOLATION_THRESHOLD
            && self.quarantined_connections < MAX_QUARANTINED_CONNECTIONS
        {
            state.quarantined = true;
            state.quarantined_until_ms = Some(
                self.clock
                    .now_ms()
                    .saturating_add(QUARANTINE_DURATION_SECONDS.saturating_mul(1000)),
            );
            self.quarantined_connections += 1;
            return (IngressOutcome::Quarantined, error);
        }
        (IngressOutcome::Rejected, error)
    }
}

fn valid_resource_attributes(attributes: &BTreeMap<String, String>) -> bool {
    validate_resource_attributes(attributes).is_ok()
}

fn canonical_series_key(
    point: &MetricPoint,
    resource_attributes: &BTreeMap<String, String>,
) -> SeriesKey {
    SeriesKey {
        metric_name: point.descriptor.name().to_owned(),
        labels: point
            .labels
            .iter()
            .map(|(key, value)| (key.clone(), value.clone()))
            .collect(),
        resource_attributes: resource_attributes
            .iter()
            .map(|(key, value)| (key.clone(), value.clone()))
            .collect(),
    }
}

fn metric_frame_from_raw(frame: &TelemetryFrame, encoded_bytes: usize) -> Option<MetricFrame> {
    let object = frame.value.as_object()?;
    let name = object.get("name")?.as_str()?;
    let labels = object.get("labels")?.as_object()?;
    let labels = labels
        .iter()
        .map(|(key, value)| Some((key.clone(), value.as_str()?.to_owned())))
        .collect::<Option<BTreeMap<_, _>>>()?;
    let descriptor = crate::canonical_descriptor(name)?;
    let value = object.get("value")?.as_f64()?;
    let resource_attributes = match object.get("resource_attributes") {
        Some(value) => serde_json::from_value(value.clone()).ok()?,
        None => BTreeMap::new(),
    };
    Some(MetricFrame::new(
        encoded_bytes,
        [MetricPoint {
            descriptor,
            labels,
            value,
        }],
        resource_attributes,
    ))
}

fn map_policy_error(error: MetricPolicyError) -> IngressErrorClass {
    match error {
        MetricPolicyError::KeyNotAllowlisted => IngressErrorClass::KeyNotAllowlisted,
        MetricPolicyError::KeyForbidden => IngressErrorClass::KeyForbidden,
        MetricPolicyError::KeySuffixForbidden => IngressErrorClass::KeySuffixForbidden,
        MetricPolicyError::ValueIdentity => IngressErrorClass::ValueIdentity,
        MetricPolicyError::LabelSetMismatch | MetricPolicyError::ValueNotAllowlisted => {
            IngressErrorClass::Malformed
        }
        MetricPolicyError::DescriptorMalformed | MetricPolicyError::DescriptorNotAllowlisted => {
            IngressErrorClass::Malformed
        }
    }
}

fn producer_for(ingress: Ingress, connection_id: u64) -> Option<ProducerKey> {
    // The emitter socket deliberately passes zero because SO_PEERCRED is a
    // connection property and cannot identify individual Unix datagrams.
    (connection_id != 0).then_some(ProducerKey {
        ingress,
        connection_id,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{canonical_descriptor, label};
    use d2b_contracts_provider::v3::telemetry_policy::allowed_values;
    use std::sync::atomic::{AtomicU64, Ordering};

    #[derive(Debug)]
    struct ManualClock(AtomicU64);

    impl IngressClock for ManualClock {
        fn now_ms(&self) -> u64 {
            self.0.load(Ordering::Relaxed)
        }
    }

    fn frame(key: &str, value: &str) -> MetricFrame {
        let (descriptor, labels) = if key == "outcome" {
            (
                canonical_descriptor("d2b_otel_ingress_policy_total").unwrap(),
                BTreeMap::from([
                    ("ingress".to_owned(), "emitter_unix".to_owned()),
                    ("outcome".to_owned(), value.to_owned()),
                    ("error_class".to_owned(), "none".to_owned()),
                ]),
            )
        } else {
            (
                MetricDescriptor::new("d2b_otel_ingress_policy_total", [label(key, &[value])]),
                BTreeMap::from([(key.to_owned(), value.to_owned())]),
            )
        };
        MetricFrame::new(
            64,
            [MetricPoint {
                descriptor,
                labels,
                value: 1.0,
            }],
            BTreeMap::from([(
                "d2b.zone".to_owned(),
                "sha256:0000000000000000000000000000000000000000000000000000000000000001"
                    .to_owned(),
            )]),
        )
    }

    fn frame_for_zone(zone: u64) -> MetricFrame {
        let mut frame = frame("outcome", "accepted");
        frame.resource_attributes =
            BTreeMap::from([("d2b.zone".to_owned(), format!("sha256:{zone:064x}"))]);
        frame
    }

    fn api_frame(
        verb_index: usize,
        resource_type_index: usize,
        outcome_index: usize,
    ) -> MetricFrame {
        let verbs = allowed_values("verb").expect("canonical verbs");
        let resource_types = allowed_values("resource_type").expect("canonical resource types");
        let outcomes = &[
            "ok",
            "conflict",
            "invalid",
            "denied",
            "not_found",
            "quota",
            "error",
        ];
        MetricFrame::new(
            64,
            [MetricPoint {
                descriptor: canonical_descriptor("d2b_api_request_total")
                    .expect("canonical API descriptor"),
                labels: BTreeMap::from([
                    ("verb".to_owned(), verbs[verb_index].to_owned()),
                    (
                        "resource_type".to_owned(),
                        resource_types[resource_type_index].to_owned(),
                    ),
                    ("outcome".to_owned(), outcomes[outcome_index].to_owned()),
                ]),
                value: 1.0,
            }],
            BTreeMap::from([(
                "d2b.zone".to_owned(),
                "sha256:0000000000000000000000000000000000000000000000000000000000000001"
                    .to_owned(),
            )]),
        )
    }

    #[test]
    fn policy_runs_before_capacity_and_rejects_the_whole_frame() {
        let mut gate = IngressPolicyGate::default();
        let valid = frame("outcome", "accepted");
        assert_eq!(
            gate.admit(
                Ingress::EmitterUnix,
                &valid,
                &IdentityCanaries::default(),
                false
            ),
            (IngressOutcome::Rejected, IngressErrorClass::None)
        );
        let invalid = frame("vm", "work");
        assert_eq!(
            gate.admit(
                Ingress::EmitterUnix,
                &invalid,
                &IdentityCanaries::default(),
                true
            ),
            (IngressOutcome::Rejected, IngressErrorClass::KeyForbidden)
        );
    }

    #[test]
    fn import_stream_has_no_credits_after_quarantine() {
        let mut gate = IngressPolicyGate::default();
        let invalid = frame("vm", "work");
        let outcome = (0..3)
            .map(|_| {
                gate.admit_for_connection(
                    Ingress::ImportStream,
                    7,
                    &invalid,
                    &IdentityCanaries::default(),
                    true,
                )
            })
            .last()
            .unwrap();
        assert_eq!(outcome.0, IngressOutcome::Quarantined);
        assert_eq!(gate.available_import_credits_for(7), 0);
        assert!(gate.is_connection_quarantined(Ingress::ImportStream, 7));
    }

    #[test]
    fn quarantine_expires_on_injected_clock_and_disconnect_releases_state() {
        let clock = Arc::new(ManualClock(AtomicU64::new(0)));
        let mut gate = IngressPolicyGate::with_clock(clock.clone());
        let invalid = frame("vm", "work");
        for _ in 0..QUARANTINE_VIOLATION_THRESHOLD {
            let _ = gate.admit_for_connection(
                Ingress::ImportStream,
                9,
                &invalid,
                &IdentityCanaries::default(),
                true,
            );
        }
        assert!(gate.is_connection_quarantined(Ingress::ImportStream, 9));
        clock.0.store(30_001, Ordering::Relaxed);
        gate.prune_expired();
        assert!(!gate.is_connection_quarantined(Ingress::ImportStream, 9));
        assert_eq!(gate.quarantined_frames(), 0);
        gate.reset_connection(Ingress::ImportStream, 9);
        assert_eq!(gate.available_import_credits_for(9), 1);
    }

    #[test]
    fn raw_emitter_admission_enforces_the_provider_series_cap() {
        let mut gate = IngressPolicyGate::with_clock_and_limits(
            Arc::new(ManualClock(AtomicU64::new(0))),
            2,
            2,
        );
        for (outcome, error_class) in [("accepted", "none"), ("rejected", "malformed")] {
            let bytes = serde_json::to_vec(&serde_json::json!({
                "signal": "metric",
                "value": {
                    "name": "d2b_otel_ingress_policy_total",
                    "labels": {
                        "ingress": "emitter_unix",
                        "outcome": outcome,
                        "error_class": error_class
                    },
                    "value": 1
                }
            }))
            .expect("metric frame");
            assert_eq!(
                gate.admit_raw(Ingress::EmitterUnix, 0, &bytes).0,
                IngressOutcome::Accepted
            );
        }
        let bytes = serde_json::to_vec(&serde_json::json!({
            "signal": "metric",
            "value": {
                "name": "d2b_otel_ingress_policy_total",
                "labels": {
                    "ingress": "emitter_unix",
                    "outcome": "quarantined",
                    "error_class": "oversize"
                },
                "value": 1
            }
        }))
        .expect("over-cap frame");
        assert_eq!(
            gate.admit_raw(Ingress::EmitterUnix, 0, &bytes),
            (IngressOutcome::Rejected, IngressErrorClass::None)
        );
        assert_eq!(gate.series_count(), 2);
    }

    #[test]
    fn raw_admission_counts_resource_attributes_in_series_identity() {
        let mut gate = IngressPolicyGate::with_clock_and_limits(
            Arc::new(ManualClock(AtomicU64::new(0))),
            1,
            1,
        );
        for zone in [1, 2] {
            let bytes = serde_json::to_vec(&serde_json::json!({
                "signal": "metric",
                "value": {
                    "name": "d2b_otel_ingress_policy_total",
                    "labels": {
                        "ingress": "emitter_unix",
                        "outcome": "accepted",
                        "error_class": "none"
                    },
                    "value": 1,
                    "resource_attributes": {
                        "d2b.zone": format!("sha256:{zone:064x}")
                    }
                }
            }))
            .expect("metric frame");
            let expected = if zone == 1 {
                IngressOutcome::Accepted
            } else {
                IngressOutcome::Rejected
            };
            assert_eq!(gate.admit_raw(Ingress::EmitterUnix, 0, &bytes).0, expected);
        }
        assert_eq!(gate.series_count(), 1);
    }

    #[test]
    fn raw_unknown_descriptor_is_rejected_before_series_accounting() {
        let mut gate = IngressPolicyGate::default();
        let bytes = serde_json::to_vec(&serde_json::json!({
            "signal": "metric",
            "value": {
                "name": "d2b_unregistered_total",
                "labels": {"outcome": "ok"},
                "value": 1
            }
        }))
        .expect("unknown metric frame");

        assert_eq!(
            gate.admit_raw(Ingress::EmitterUnix, 0, &bytes),
            (IngressOutcome::Rejected, IngressErrorClass::Malformed)
        );
        assert_eq!(gate.series_count(), 0);
    }

    #[test]
    fn raw_known_descriptor_requires_its_canonical_label_set() {
        let mut gate = IngressPolicyGate::default();
        let valid = serde_json::to_vec(&serde_json::json!({
            "signal": "metric",
            "value": {
                "name": "d2b_otel_ingress_policy_total",
                "labels": {
                    "ingress": "emitter_unix",
                    "outcome": "accepted",
                    "error_class": "none"
                },
                "value": 1
            }
        }))
        .expect("valid metric frame");
        assert_eq!(
            gate.admit_raw(Ingress::EmitterUnix, 0, &valid),
            (IngressOutcome::Accepted, IngressErrorClass::None)
        );

        let missing = serde_json::to_vec(&serde_json::json!({
            "signal": "metric",
            "value": {
                "name": "d2b_otel_ingress_policy_total",
                "labels": {"outcome": "accepted"},
                "value": 1
            }
        }))
        .expect("incomplete metric frame");
        assert_eq!(
            gate.admit_raw(Ingress::EmitterUnix, 0, &missing),
            (IngressOutcome::Rejected, IngressErrorClass::Malformed)
        );
        let noncanonical_value = serde_json::to_vec(&serde_json::json!({
            "signal": "metric",
            "value": {
                "name": "d2b_otel_ingress_policy_total",
                "labels": {
                    "ingress": "emitter_unix",
                    "outcome": "accepted",
                    "error_class": "transport"
                },
                "value": 1
            }
        }))
        .expect("noncanonical metric value");
        assert_eq!(
            gate.admit_raw(Ingress::EmitterUnix, 0, &noncanonical_value),
            (IngressOutcome::Rejected, IngressErrorClass::Malformed)
        );
        assert_eq!(gate.series_count(), 1);
    }

    #[test]
    fn repeated_unknown_families_cannot_bypass_the_closed_descriptor_registry() {
        let mut gate = IngressPolicyGate::default();
        for index in 0..64 {
            let bytes = serde_json::to_vec(&serde_json::json!({
                "signal": "metric",
                "value": {
                    "name": format!("d2b_unregistered_{index}"),
                    "labels": {"outcome": "ok"},
                    "value": 1
                }
            }))
            .expect("unknown metric frame");
            assert_eq!(
                gate.admit_raw(Ingress::EmitterUnix, 0, &bytes),
                (IngressOutcome::Rejected, IngressErrorClass::Malformed)
            );
        }
        assert_eq!(gate.series_count(), 0);
    }

    #[test]
    fn resource_attributes_are_part_of_provider_series_identity() {
        let mut gate = IngressPolicyGate::with_clock_and_limits(
            Arc::new(ManualClock(AtomicU64::new(0))),
            2,
            4,
        );
        for zone in [1, 2] {
            assert_eq!(
                gate.admit_for_connection(
                    Ingress::ImportStream,
                    1,
                    &frame_for_zone(zone),
                    &IdentityCanaries::default(),
                    true
                )
                .0,
                IngressOutcome::Accepted
            );
        }
        assert_eq!(gate.series_count(), 2);
        assert_eq!(
            gate.admit_for_connection(
                Ingress::ImportStream,
                2,
                &frame_for_zone(3),
                &IdentityCanaries::default(),
                true
            ),
            (IngressOutcome::Rejected, IngressErrorClass::None)
        );
        assert_eq!(gate.series_count(), 2);
    }

    #[test]
    fn resource_attributes_count_toward_the_identified_producer_quota() {
        let mut gate = IngressPolicyGate::with_clock_and_limits(
            Arc::new(ManualClock(AtomicU64::new(0))),
            4,
            1,
        );
        assert_eq!(
            gate.admit_for_connection(
                Ingress::ImportStream,
                1,
                &frame_for_zone(1),
                &IdentityCanaries::default(),
                true
            )
            .0,
            IngressOutcome::Accepted
        );
        assert_eq!(
            gate.admit_for_connection(
                Ingress::ImportStream,
                1,
                &frame_for_zone(2),
                &IdentityCanaries::default(),
                true
            ),
            (IngressOutcome::Rejected, IngressErrorClass::None)
        );
        assert_eq!(gate.series_count(), 1);
    }

    #[test]
    fn shared_series_survives_the_first_producer_disconnect() {
        let mut gate = IngressPolicyGate::with_clock_and_limits(
            Arc::new(ManualClock(AtomicU64::new(0))),
            2,
            1,
        );
        let shared = frame("outcome", "accepted");
        for connection_id in [1, 2] {
            assert_eq!(
                gate.admit_for_connection(
                    Ingress::ImportStream,
                    connection_id,
                    &shared,
                    &IdentityCanaries::default(),
                    true
                )
                .0,
                IngressOutcome::Accepted
            );
        }
        assert_eq!(gate.series_count(), 1);

        gate.reset_connection(Ingress::ImportStream, 1);
        assert_eq!(gate.series_count(), 1);
        assert_eq!(
            gate.admit_for_connection(
                Ingress::ImportStream,
                1,
                &api_frame(0, 0, 0),
                &IdentityCanaries::default(),
                true
            )
            .0,
            IngressOutcome::Accepted
        );
        assert_eq!(gate.series_count(), 2);
        gate.reset_connection(Ingress::ImportStream, 2);
        assert_eq!(gate.series_count(), 1);
        gate.reset_connection(Ingress::ImportStream, 1);
        assert_eq!(gate.series_count(), 0);
    }

    #[test]
    fn expiry_removes_only_the_expired_producer_membership() {
        let clock = Arc::new(ManualClock(AtomicU64::new(0)));
        let mut gate = IngressPolicyGate::with_clock_and_limits(clock.clone(), 2, 2);
        let shared = frame("outcome", "accepted");
        assert_eq!(
            gate.admit_for_connection(
                Ingress::ImportStream,
                1,
                &shared,
                &IdentityCanaries::default(),
                true
            )
            .0,
            IngressOutcome::Accepted
        );
        clock.0.store(1_000, Ordering::Relaxed);
        assert_eq!(
            gate.admit_for_connection(
                Ingress::ImportStream,
                2,
                &shared,
                &IdentityCanaries::default(),
                true
            )
            .0,
            IngressOutcome::Accepted
        );

        clock.0.store(
            SERIES_IDLE_SECONDS.saturating_mul(1_000) + 1,
            Ordering::Relaxed,
        );
        gate.prune_expired();
        assert_eq!(gate.series_count(), 1);
        assert!(!gate.producer_series.contains_key(&ProducerKey {
            ingress: Ingress::ImportStream,
            connection_id: 1,
        }));
        assert_eq!(
            gate.producer_series
                .get(&ProducerKey {
                    ingress: Ingress::ImportStream,
                    connection_id: 2,
                })
                .map_or(0, BTreeSet::len),
            1
        );

        gate.reset_connection(Ingress::ImportStream, 2);
        assert_eq!(gate.series_count(), 0);
    }

    #[test]
    fn shared_emitter_scope_does_not_create_a_fake_producer() {
        let mut gate = IngressPolicyGate::with_clock_and_limits(
            Arc::new(ManualClock(AtomicU64::new(0))),
            2,
            1,
        );
        for zone in [1, 2] {
            assert_eq!(
                gate.admit_for_connection(
                    Ingress::EmitterUnix,
                    0,
                    &frame_for_zone(zone),
                    &IdentityCanaries::default(),
                    true
                )
                .0,
                IngressOutcome::Accepted
            );
        }
        assert!(gate.producer_series.is_empty());
        gate.reset_connection(Ingress::EmitterUnix, 0);
        assert_eq!(gate.series_count(), 2);
    }

    #[test]
    fn series_cap_reclaims_only_after_monotonic_idle_expiry_or_connection_reset() {
        let clock = Arc::new(ManualClock(AtomicU64::new(0)));
        let mut gate = IngressPolicyGate::with_clock_and_limits(clock.clone(), 2, 2);
        let first = api_frame(0, 0, 0);
        let second = api_frame(0, 0, 1);
        let third = api_frame(0, 0, 2);

        assert_eq!(
            gate.admit_for_connection(
                Ingress::EmitterUnix,
                0,
                &first,
                &IdentityCanaries::default(),
                true
            )
            .0,
            IngressOutcome::Accepted
        );
        assert_eq!(
            gate.admit_for_connection(
                Ingress::EmitterUnix,
                0,
                &second,
                &IdentityCanaries::default(),
                true
            )
            .0,
            IngressOutcome::Accepted
        );
        assert_eq!(
            gate.admit_for_connection(
                Ingress::EmitterUnix,
                0,
                &third,
                &IdentityCanaries::default(),
                true
            ),
            (IngressOutcome::Rejected, IngressErrorClass::None)
        );
        clock.0.store(
            (SERIES_IDLE_SECONDS * 1_000).saturating_sub(1),
            Ordering::Relaxed,
        );
        assert_eq!(gate.series_count(), 2);
        assert_eq!(
            gate.admit_for_connection(
                Ingress::EmitterUnix,
                0,
                &third,
                &IdentityCanaries::default(),
                true
            ),
            (IngressOutcome::Rejected, IngressErrorClass::None)
        );

        clock
            .0
            .store((SERIES_IDLE_SECONDS * 1_000) + 1, Ordering::Relaxed);
        gate.prune_expired();
        assert_eq!(gate.series_count(), 0);
        assert_eq!(
            gate.admit_for_connection(
                Ingress::EmitterUnix,
                0,
                &third,
                &IdentityCanaries::default(),
                true
            )
            .0,
            IngressOutcome::Accepted
        );

        gate.reset_connection(Ingress::ImportStream, 7);
        assert_eq!(gate.series_count(), 1);
        assert_eq!(
            gate.admit_for_connection(
                Ingress::ImportStream,
                7,
                &first,
                &IdentityCanaries::default(),
                true
            )
            .0,
            IngressOutcome::Accepted
        );
        assert_eq!(gate.series_count(), 2);
        gate.reset_connection(Ingress::ImportStream, 7);
        assert_eq!(gate.series_count(), 1);
    }

    #[test]
    fn identified_producer_quota_leaves_capacity_for_later_valid_series() {
        let mut gate = IngressPolicyGate::default();
        let verbs = allowed_values("verb").expect("canonical verbs");
        let resource_types = allowed_values("resource_type").expect("canonical resource types");
        let outcomes = &[
            "ok",
            "conflict",
            "invalid",
            "denied",
            "not_found",
            "quota",
            "error",
        ];
        let frames = verbs
            .iter()
            .enumerate()
            .flat_map(|(verb_index, _)| {
                resource_types
                    .iter()
                    .enumerate()
                    .flat_map(move |(resource_index, _)| {
                        outcomes.iter().enumerate().map(move |(outcome_index, _)| {
                            api_frame(verb_index, resource_index, outcome_index)
                        })
                    })
            })
            .collect::<Vec<_>>();
        assert!(frames.len() > MAX_SERIES_PER_PRODUCER);

        for frame in frames.iter().take(MAX_SERIES_PER_PRODUCER) {
            assert_eq!(
                gate.admit_for_connection(
                    Ingress::ImportStream,
                    1,
                    frame,
                    &IdentityCanaries::default(),
                    true
                )
                .0,
                IngressOutcome::Accepted
            );
        }
        let starved_frame = &frames[MAX_SERIES_PER_PRODUCER];
        assert_eq!(
            gate.admit_for_connection(
                Ingress::ImportStream,
                1,
                starved_frame,
                &IdentityCanaries::default(),
                true
            ),
            (IngressOutcome::Rejected, IngressErrorClass::None)
        );
        assert_eq!(
            gate.admit_for_connection(
                Ingress::ImportStream,
                2,
                starved_frame,
                &IdentityCanaries::default(),
                true
            )
            .0,
            IngressOutcome::Accepted
        );
    }
}
