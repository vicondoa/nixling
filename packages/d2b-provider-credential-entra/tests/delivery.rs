mod common;

use d2b_contracts_provider::v3::credential::{
    CREDENTIAL_DELIVERY_NOISE_PROFILE, CredentialAuthorization, CredentialMethod,
    CredentialProvider, CredentialRequest, CredentialResponse, CredentialServiceError,
    CredentialServiceErrorCode, DeliverySessionParams, SensitiveDeliveryRecord,
};
use d2b_provider_credential_entra::EntraCredentialProvider;

use common::{
    ProviderHarness, TestAdmission, admitted, delivery, request, session_binding, setup,
    subject_context,
};

#[test]
fn provider_returns_exactly_the_read_only_adapter_binding() {
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
        .call(CredentialMethod::RefreshToken, refresh_request.clone())
        .unwrap();
    let CredentialResponse::RefreshToken(response) = response else {
        panic!("refresh response");
    };
    assert_eq!(
        response.delivery_session_params,
        common::delivery_for_request(CredentialMethod::RefreshToken, &refresh_request)
    );
}

#[test]
fn delivery_records_zeroize() {
    assert_eq!(
        CREDENTIAL_DELIVERY_NOISE_PROFILE,
        "Noise_KK_25519_ChaChaPoly_SHA256"
    );
    let mut record = SensitiveDeliveryRecord::new(b"access-token".to_vec(), 64).unwrap();
    let mut destination = [0; 12];
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
        CredentialAuthorization::new_for_subject(
            method,
            Some(self.authorized.clone()),
            subject_context(),
        )
        .and_then(|authorization| authorization.with_authenticated_session(session_binding()))
    }
}

struct BindingReplacingProvider {
    inner: EntraCredentialProvider,
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
fn adapter_refuses_an_entra_provider_binding_replacement() {
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
