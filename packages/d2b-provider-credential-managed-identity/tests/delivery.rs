mod common;

use d2b_contracts_provider::v3::credential::{
    CREDENTIAL_DELIVERY_NOISE_PROFILE, CredentialAuthorization, CredentialMethod,
    CredentialProvider, CredentialRequest, CredentialResponse, CredentialServiceError,
    CredentialServiceErrorCode, DeliverySessionParams, SensitiveDeliveryRecord,
};
use d2b_provider_credential_managed_identity::ManagedIdentityCredentialProvider;

use common::{
    ProviderHarness, TestAdmission, admitted, authenticated_session, delivery, request, setup,
};

#[test]
fn provider_returns_the_adapter_supplied_binding_unchanged() {
    let expected = delivery(CredentialMethod::AcquireToken, 1);
    let (provider, _) = setup();
    let server = ProviderHarness::new(provider, admitted());
    let response = server
        .call(CredentialMethod::AcquireToken, request("idem-binding"))
        .unwrap();
    let CredentialResponse::AcquireToken(response) = response else {
        panic!("acquire response");
    };
    assert_eq!(response.delivery_session_params, expected);
}

#[test]
fn refresh_response_preserves_the_authorization_owned_binding() {
    let (provider, _) = setup();
    let server = ProviderHarness::new(provider, admitted());
    server
        .call(CredentialMethod::AcquireToken, request("idem-acquire"))
        .unwrap();
    let refresh_request = request("idem-refresh");
    let response = server
        .call(CredentialMethod::RefreshToken, refresh_request)
        .unwrap();
    let CredentialResponse::RefreshToken(response) = response else {
        panic!("refresh response");
    };
    assert_eq!(
        response.delivery_session_params,
        delivery(CredentialMethod::RefreshToken, 1)
    );
}

#[test]
fn delivery_zeroizes() {
    assert_eq!(
        CREDENTIAL_DELIVERY_NOISE_PROFILE,
        "Noise_KK_25519_ChaChaPoly_SHA256"
    );
    let mut record = SensitiveDeliveryRecord::new(b"managed-token".to_vec(), 64).unwrap();
    let mut destination = [0; 13];
    record.copy_to(&mut destination).unwrap();
    destination.fill(0);
    record.clear();
    assert!(record.is_zeroized());
}

#[derive(Clone)]
struct FixedAdmission {
    authorized: DeliverySessionParams,
}

impl TestAdmission for FixedAdmission {
    fn authorize(
        &self,
        method: CredentialMethod,
        _request: &CredentialRequest,
    ) -> Result<CredentialAuthorization, CredentialServiceError> {
        CredentialAuthorization::new(method, Some(self.authorized.clone()))?
            .with_authenticated_session(authenticated_session(
                "Provider/runtime-azure-container-apps",
                "Zone/dev",
                "Guest/aca-sandbox",
                "Provider/runtime-azure-container-apps",
                1,
                1,
            ))
    }
}

struct BindingReplacingProvider {
    inner: ManagedIdentityCredentialProvider,
    replacement: DeliverySessionParams,
}

impl CredentialProvider for BindingReplacingProvider {
    fn dispatch(
        &self,
        method: CredentialMethod,
        request: &CredentialRequest,
        authorization: &CredentialAuthorization,
    ) -> Result<CredentialResponse, CredentialServiceError> {
        let mut response = self.inner.dispatch(method, request, authorization)?;
        if let CredentialResponse::AcquireToken(delivery) = &mut response {
            delivery.delivery_session_params = self.replacement.clone();
        }
        Ok(response)
    }
}

#[test]
fn adapter_refuses_a_managed_identity_provider_binding_replacement() {
    let authorized = delivery(CredentialMethod::AcquireToken, 1);
    let replacement = delivery(CredentialMethod::AcquireToken, 2);
    let (provider, _) = setup();
    let server = ProviderHarness::new(
        BindingReplacingProvider {
            inner: provider,
            replacement,
        },
        FixedAdmission { authorized },
    );
    assert_eq!(
        server
            .call(
                CredentialMethod::AcquireToken,
                request("idem-refuse-binding")
            )
            .unwrap_err()
            .code(),
        CredentialServiceErrorCode::InvariantFailure
    );
}
