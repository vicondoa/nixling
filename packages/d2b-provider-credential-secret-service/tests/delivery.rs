mod common;

use d2b_contracts_provider::v3::credential::{
    CREDENTIAL_DELIVERY_NOISE_PROFILE, CredentialAuthorization, CredentialMethod,
    CredentialProvider, CredentialRequest, CredentialResponse, CredentialServiceError,
    CredentialServiceErrorCode, DeliverySessionParams, SensitiveDeliveryRecord,
};
use d2b_provider_credential_secret_service::{
    SecretServiceCredentialProvider, SecretServiceSessionCapability,
};

use common::{Admission, ProviderHarness, SessionCapabilitySource, TestAdmission, request, setup};

#[test]
fn response_uses_the_read_only_adapter_binding_and_record_zeroizes() {
    assert_eq!(
        CREDENTIAL_DELIVERY_NOISE_PROFILE,
        "Noise_KK_25519_ChaChaPoly_SHA256"
    );
    let (provider, _) = setup(64);
    let server = ProviderHarness::new(provider, Admission);
    let response = server
        .call(CredentialMethod::AcquireToken, request("idem-delivery"))
        .unwrap();
    let CredentialResponse::AcquireToken(response) = response else {
        panic!("acquire response");
    };
    assert_eq!(response.delivery_session_params.sequence(), 1);

    let mut record = SensitiveDeliveryRecord::new(b"secret".to_vec(), 64).unwrap();
    let mut destination = [0; 6];
    record.copy_to(&mut destination).unwrap();
    destination.fill(0);
    record.clear();
    assert!(record.is_zeroized());
    assert!(record.copy_to(&mut destination).is_err());
}

#[test]
fn refresh_response_preserves_the_authorization_owned_binding() {
    let (provider, _) = setup(64);
    let server = ProviderHarness::new(provider, Admission);
    server
        .call(CredentialMethod::AcquireToken, request("idem-acquire"))
        .unwrap();
    let response = server
        .call(CredentialMethod::RefreshToken, request("idem-refresh"))
        .unwrap();
    let CredentialResponse::RefreshToken(response) = response else {
        panic!("refresh response");
    };
    assert_eq!(
        response.delivery_session_params,
        common::delivery(CredentialMethod::RefreshToken, 1)
    );
}

#[derive(Clone)]
struct MismatchedAdmission {
    authorized: DeliverySessionParams,
}

impl TestAdmission for MismatchedAdmission {
    fn authorize(
        &self,
        method: CredentialMethod,
        _request: &CredentialRequest,
    ) -> Result<CredentialAuthorization, CredentialServiceError> {
        CredentialAuthorization::new(method, Some(self.authorized.clone()))
    }
}

struct BindingReplacingProvider {
    inner: SecretServiceCredentialProvider,
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

impl SessionCapabilitySource for BindingReplacingProvider {
    fn test_session_capability(&self) -> SecretServiceSessionCapability {
        self.inner
            .issue_session_capability(
                d2b_contracts_resource::v3::ResourceGeneration::new(1).unwrap(),
            )
            .expect("test provider must issue its placement-bound capability")
    }
}

#[test]
fn adapter_refuses_a_provider_response_with_a_different_binding() {
    let authorized = common::delivery(CredentialMethod::AcquireToken, 1);
    let replacement = common::delivery(CredentialMethod::AcquireToken, 2);
    let (provider, _) = setup(64);
    let server = ProviderHarness::new(
        BindingReplacingProvider {
            inner: provider,
            replacement,
        },
        MismatchedAdmission { authorized },
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

#[test]
fn provider_refuses_an_incoming_delivery_binding_for_another_credential() {
    let (provider, _) = common::setup(64);
    let wrong_binding = common::delivery_for(
        CredentialMethod::AcquireToken,
        1,
        d2b_contracts_resource::v3::ResourceRef::parse("Credential/other").unwrap(),
    );
    let server = ProviderHarness::new(
        provider,
        MismatchedAdmission {
            authorized: wrong_binding,
        },
    );
    assert_eq!(
        server
            .call(CredentialMethod::AcquireToken, request("wrong-credential"))
            .unwrap_err()
            .code(),
        CredentialServiceErrorCode::OperationDenied
    );
}
