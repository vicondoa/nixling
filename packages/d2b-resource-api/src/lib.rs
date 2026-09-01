//! Asynchronous native resource API and authorization contracts.
//!
//! Transport dispatch is explicitly authenticated through the d2b-bus
//! ComponentSession boundary.

pub mod adapter;
mod admission;
pub mod authz;
pub mod client;
pub mod emergency_gate;
pub mod error;
pub mod generated;
mod identity;
pub mod metrics;
pub mod quota_gate;
pub mod service;
pub mod registered;
mod store;
pub mod watch;
pub mod zone_service;

pub use adapter::{
    AdapterBindingError, RESOURCE_API_REACHABILITY, ResourceApiReachability, ResourceBusAdapter,
    ScopedCommitFrameError, ScopedQueryFrameError, attach_scoped_commit_frame,
    attach_scoped_query_frame, decode_scoped_commit_request, reject_scoped_commit_frame,
};
pub use admission::{AdmissionError, AdmittedMutation};
pub use authz::{AuthorizationLease, StoreSealHandoffError};
pub use client::ResourceApiClient;
pub use registered::RedbRegisteredControllerApi;
pub use d2b_resource_store::PreparedStoreMutation;
pub use identity::AuthenticatedSubjectContext;
pub use service::{GuestLifecycleAdmission, ResourceService};
pub use store::{RedbBackend, ResourceStoreBackend, StoreBindingError};
pub use zone_service::{
    StrictWireMessage, ZoneCallContext, ZoneMethod, ZoneService, ZoneServiceError,
    ZoneServiceHandler,
};
