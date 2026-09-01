//! Checked resource-store backend boundary.

use std::{future::Future, sync::Arc};

use d2b_resource_store::{
    SealedMutation, StoreCommitResult, StoreError, StoreGetRequest, StoreInspectSchemaRequest,
    StoreListRequest, StoreListResult, StoreResolveRequest, StoreResolvedIdentity,
    StoreWatchReceipt, StoreWatchRequest, StoredResource, StoredSchema,
};

use crate::admission::{AdmittedMutation, StoreAdmissionBinding};

/// Trusted persistence seam reached only after instance-bound admission verification.
///
/// A correctly wired production store accepts only evidence from its paired
/// issuer. A caller can construct a locally paired seal for a store it owns,
/// but foreign locally-paired seals are inert here: this store's acceptor
/// rejects them before the evidence reaches
/// [`ResourceStoreBackend::commit_verified`]. In production, the paired issuer
/// is retained by the native authorization path, so accepted evidence follows
/// a successful native authorization evaluation and is verified against this
/// store's identity.
///
/// This seal does not constrain the backend implementation. A backend could
/// ignore a verified mutation, change storage through another path, or omit
/// required transaction checks. Implementations are therefore part of the
/// trusted computing base: they must mutate only from the supplied
/// [`SealedMutation`], recheck its captured revisions in the write
/// transaction, preserve the store's structural and atomicity invariants, and
/// expose no independent mutation path. A production backend requires security
/// review and conformance tests for these obligations before it is registered.
pub trait ResourceStoreBackend: Send + Sync {
    fn get(
        &self,
        request: StoreGetRequest,
    ) -> impl Future<Output = Result<StoredResource, StoreError>> + Send;

    fn list(
        &self,
        request: StoreListRequest,
    ) -> impl Future<Output = Result<StoreListResult, StoreError>> + Send;

    fn watch(
        &self,
        request: StoreWatchRequest,
    ) -> impl Future<Output = Result<StoreWatchReceipt, StoreError>> + Send;

    fn resolve_ref(
        &self,
        request: StoreResolveRequest,
    ) -> impl Future<Output = Result<StoreResolvedIdentity, StoreError>> + Send;

    fn inspect_schema(
        &self,
        request: StoreInspectSchemaRequest,
    ) -> impl Future<Output = Result<StoredSchema, StoreError>> + Send;

    fn commit_verified(
        &self,
        mutation: SealedMutation,
    ) -> impl Future<Output = Result<StoreCommitResult, StoreError>> + Send;
}

/// API bridge that owns the concrete mutation-seal store binding.
///
/// A caller can construct a locally paired seal, but foreign locally-paired
/// seals are inert: a correctly wired production store accepts only evidence
/// from the issuer paired with its own acceptor.
///
/// ```compile_fail
/// use d2b_resource_api::RedbBackend;
/// use d2b_resource_store::SealedMutation;
///
/// fn forge() -> SealedMutation {
///     SealedMutation {}
/// }
/// ```
pub struct RedbBackend {
    store: Arc<d2b_resource_store_redb::RedbResourceStore>,
}

impl core::fmt::Debug for RedbBackend {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("RedbBackend(<redacted>)")
    }
}

impl RedbBackend {
    pub fn new(store: d2b_resource_store_redb::RedbResourceStore) -> Self {
        Self {
            store: Arc::new(store),
        }
    }

    /// Bind the API to a store whose lifetime is owned by a Zone runtime.
    pub const fn from_arc(store: Arc<d2b_resource_store_redb::RedbResourceStore>) -> Self {
        Self { store }
    }

    pub(crate) fn store_arc(&self) -> Arc<d2b_resource_store_redb::RedbResourceStore> {
        Arc::clone(&self.store)
    }
}

impl ResourceStoreBackend for RedbBackend {
    async fn get(&self, request: StoreGetRequest) -> Result<StoredResource, StoreError> {
        self.store.get(request).await
    }

    async fn list(&self, request: StoreListRequest) -> Result<StoreListResult, StoreError> {
        self.store.list(request).await
    }

    async fn watch(&self, request: StoreWatchRequest) -> Result<StoreWatchReceipt, StoreError> {
        self.store.watch(request).await
    }

    async fn resolve_ref(
        &self,
        request: StoreResolveRequest,
    ) -> Result<StoreResolvedIdentity, StoreError> {
        self.store.resolve_ref(request).await
    }

    async fn inspect_schema(
        &self,
        request: StoreInspectSchemaRequest,
    ) -> Result<StoredSchema, StoreError> {
        self.store.inspect_schema(request).await
    }

    async fn commit_verified(
        &self,
        mutation: SealedMutation,
    ) -> Result<StoreCommitResult, StoreError> {
        self.store.commit_verified(mutation).await
    }
}

#[cfg(test)]
mod redb_tests {
    use super::*;

    #[test]
    fn concrete_redb_backend_implements_the_checked_api_seam() {
        fn assert_backend<T: ResourceStoreBackend>() {}
        assert_backend::<RedbBackend>();
    }
}

/// A native authorizer has already been bound to a store backend.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StoreBindingError;

impl core::fmt::Display for StoreBindingError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("native authorizer is already bound to a store backend")
    }
}

impl std::error::Error for StoreBindingError {}

pub(crate) struct CheckedResourceStore<S> {
    backend: Arc<S>,
    admission: StoreAdmissionBinding,
}

impl<S> Clone for CheckedResourceStore<S> {
    fn clone(&self) -> Self {
        Self {
            backend: Arc::clone(&self.backend),
            admission: self.admission.clone(),
        }
    }
}

impl<S> CheckedResourceStore<S> {
    pub(super) const fn new(backend: Arc<S>, admission: StoreAdmissionBinding) -> Self {
        Self { backend, admission }
    }

    pub(crate) fn backend(&self) -> Arc<S> {
        Arc::clone(&self.backend)
    }
}

impl<S> CheckedResourceStore<S>
where
    S: ResourceStoreBackend,
{
    pub(crate) fn get(
        &self,
        request: StoreGetRequest,
    ) -> impl Future<Output = Result<StoredResource, StoreError>> + Send {
        self.backend.get(request)
    }

    pub(crate) fn list(
        &self,
        request: StoreListRequest,
    ) -> impl Future<Output = Result<StoreListResult, StoreError>> + Send {
        self.backend.list(request)
    }

    pub(crate) fn watch(
        &self,
        request: StoreWatchRequest,
    ) -> impl Future<Output = Result<StoreWatchReceipt, StoreError>> + Send {
        self.backend.watch(request)
    }

    pub(crate) fn resolve_ref(
        &self,
        request: StoreResolveRequest,
    ) -> impl Future<Output = Result<StoreResolvedIdentity, StoreError>> + Send {
        self.backend.resolve_ref(request)
    }

    pub(crate) fn inspect_schema(
        &self,
        request: StoreInspectSchemaRequest,
    ) -> impl Future<Output = Result<StoredSchema, StoreError>> + Send {
        self.backend.inspect_schema(request)
    }

    pub(crate) fn commit(
        &self,
        mutation: AdmittedMutation,
    ) -> impl Future<Output = Result<StoreCommitResult, StoreError>> + Send {
        let sealed = self
            .admission
            .verify(mutation)
            .and_then(|body| self.admission.seal(body));
        async move { self.backend.commit_verified(sealed?).await }
    }
}
