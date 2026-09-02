use d2b_contracts_resource::v3::execution_policy::BoundedToken;
use d2b_contracts_resource::v3::{ResourceGeneration, ResourceRef, ResourceUid};
use d2b_provider_volume_local::atomic::{AtomicWriteError, check_soft_quota};
use d2b_provider_volume_local::effect_port::{ExecutionDomain, VolumeEffectError, validate_domain};
use d2b_provider_volume_local::{ContentFile, ContentProjection, ContentProvenance};

fn token(value: &str) -> BoundedToken {
    BoundedToken::parse(value).expect("valid bounded token")
}

#[test]
fn cross_domain_volume_access_is_rejected() {
    let guest = ExecutionDomain::Guest(token("work-vm"));
    assert_eq!(
        validate_domain(&guest, &ExecutionDomain::Host(token("host-system"))),
        Err(VolumeEffectError::DomainMismatch)
    );
    assert_eq!(
        validate_domain(&guest, &ExecutionDomain::Guest(token("personal-vm"))),
        Err(VolumeEffectError::DomainMismatch)
    );
}

#[test]
fn quota_soft_check_accounts_for_replaced_bytes_and_rejects_overage() {
    assert!(check_soft_quota(8192, 4096, 4096, 8192).is_ok());
    assert_eq!(
        check_soft_quota(8192, 4096, 4097, 8192),
        Err(AtomicWriteError::QuotaExceeded)
    );
    assert_eq!(
        check_soft_quota(0, 0, 1, 0),
        Err(AtomicWriteError::QuotaExceeded)
    );
}

#[test]
fn content_projection_binds_each_file_and_provenance_to_the_volume() {
    let volume_uid =
        ResourceUid::parse("6f9619ff-8b86-4d01-b42d-00cf4fc964ff").expect("volume uid");
    let projection = ContentProjection::new(
        volume_uid.clone(),
        ContentProvenance::new(
            ResourceRef::parse("Network/work").expect("network ref"),
            ResourceUid::parse("7f9619ff-8b86-4d01-b42d-00cf4fc964ff").expect("network uid"),
            ResourceGeneration::new(3).expect("generation"),
            "assignment-7",
            None,
        )
        .expect("provenance"),
        "network:config:owned",
        [ContentFile::new(
            "dnsmasq.conf",
            ResourceRef::parse("User/net-local-controller").expect("owner"),
            ResourceRef::parse("User/net-local-controller").expect("group"),
            "0640",
            b"lan=192.0.2.0/24\n".to_vec(),
        )
        .expect("file")],
    )
    .expect("projection");

    assert_eq!(projection.volume_uid(), &volume_uid);
    assert_eq!(projection.files().len(), 1);
    assert!(projection.validate().is_ok());
    assert!(!projection.content_digest().is_empty());
}
