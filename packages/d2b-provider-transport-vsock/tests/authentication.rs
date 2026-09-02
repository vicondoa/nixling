use d2b_contracts_resource::v3::{ResourceRef, ZoneId};
use d2b_provider_transport_vsock::{
    GuestIdentity, MAX_REPLAY_ENTRIES, PeerCid, SessionAuthority, SessionKey, SessionProof,
    SessionRejectReason, SessionState,
};
use ring::rand::{SystemRandom, generate};

fn nonce_for(index: u16) -> [u8; 32] {
    let mut nonce = generate::<[u8; 32]>(&SystemRandom::new()).unwrap().expose();
    nonce[..2].copy_from_slice(&index.to_be_bytes());
    nonce
}

fn identity(cid: u32) -> GuestIdentity {
    GuestIdentity::new(
        ResourceRef::parse("Guest/guest-a").unwrap(),
        ZoneId::parse("work").unwrap(),
        PeerCid::from_core(cid).unwrap(),
        "boot-a",
    )
    .unwrap()
}

#[test]
fn correct_cid_signature_guest_zone_and_session_establish_ready() {
    let key = SessionKey::from_core([7; 32]);
    let expected = identity(42);
    let mut authority = SessionAuthority::new(expected.clone(), key.clone(), 3);
    let proof = SessionProof::sign(&key, &expected, nonce_for(1), 3);

    let session = authority
        .authenticate(PeerCid::from_core(42).unwrap(), proof)
        .unwrap();
    assert_eq!(session.state(), SessionState::Ready);
    assert!(session.matches(&expected));
    assert_eq!(session.disconnect(), SessionState::Disconnected);
}

#[test]
fn cid_reuse_and_replay_are_rejected() {
    let key = SessionKey::from_core([8; 32]);
    let expected = identity(42);
    let mut authority = SessionAuthority::new(expected.clone(), key.clone(), 3);
    let proof = SessionProof::sign(&key, &expected, nonce_for(2), 3);
    authority
        .authenticate(PeerCid::from_core(42).unwrap(), proof.clone())
        .unwrap();
    assert_eq!(
        authority
            .authenticate(PeerCid::from_core(42).unwrap(), proof)
            .unwrap_err(),
        SessionRejectReason::Replay
    );

    let mut other = identity(43);
    let proof = SessionProof::sign(&key, &other, nonce_for(3), 3);
    assert_eq!(
        authority
            .authenticate(PeerCid::from_core(42).unwrap(), proof)
            .unwrap_err(),
        SessionRejectReason::CidMismatch
    );
    other = identity(42);
    let proof = SessionProof::sign(&key, &other, nonce_for(4), 2);
    assert_eq!(
        authority
            .authenticate(PeerCid::from_core(42).unwrap(), proof)
            .unwrap_err(),
        SessionRejectReason::StaleSignature
    );
}

#[test]
fn replay_cache_refuses_new_sessions_at_its_bound() {
    let key = SessionKey::from_core([3; 32]);
    let expected = identity(42);
    let mut authority = SessionAuthority::new(expected.clone(), key.clone(), 3);
    for index in 0..MAX_REPLAY_ENTRIES {
        authority
            .authenticate(
                PeerCid::from_core(42).unwrap(),
                SessionProof::sign(&key, &expected, nonce_for(index as u16), 3),
            )
            .unwrap();
    }
    assert_eq!(
        authority
            .authenticate(
                PeerCid::from_core(42).unwrap(),
                SessionProof::sign(&key, &expected, nonce_for(MAX_REPLAY_ENTRIES as u16), 3),
            )
            .unwrap_err(),
        SessionRejectReason::AuthorityUnavailable
    );
}

#[test]
fn guest_zone_and_signature_mismatches_are_refused() {
    let expected = identity(42);
    let key = SessionKey::from_core([3; 32]);
    let wrong_key = SessionKey::from_core([4; 32]);
    let mut authority = SessionAuthority::new(expected.clone(), key.clone(), 3);

    let guest = GuestIdentity::new(
        ResourceRef::parse("Guest/other").unwrap(),
        ZoneId::parse("work").unwrap(),
        PeerCid::from_core(42).unwrap(),
        "boot-a",
    )
    .unwrap();
    assert_eq!(
        authority
            .authenticate(
                PeerCid::from_core(42).unwrap(),
                SessionProof::sign(&key, &guest, nonce_for(5), 3),
            )
            .unwrap_err(),
        SessionRejectReason::GuestMismatch
    );

    let zone = GuestIdentity::new(
        ResourceRef::parse("Guest/guest-a").unwrap(),
        ZoneId::parse("personal").unwrap(),
        PeerCid::from_core(42).unwrap(),
        "boot-a",
    )
    .unwrap();
    assert_eq!(
        authority
            .authenticate(
                PeerCid::from_core(42).unwrap(),
                SessionProof::sign(&key, &zone, nonce_for(6), 3),
            )
            .unwrap_err(),
        SessionRejectReason::ZoneMismatch
    );

    assert_eq!(
        authority
            .authenticate(
                PeerCid::from_core(42).unwrap(),
                SessionProof::sign(&wrong_key, &expected, nonce_for(7), 3),
            )
            .unwrap_err(),
        SessionRejectReason::SignatureInvalid
    );
}

#[test]
fn zero_reconnect_generation_is_never_admitted() {
    let expected = identity(42);
    let key = SessionKey::from_core([9; 32]);
    let mut authority = SessionAuthority::new(expected.clone(), key.clone(), 0);
    assert_eq!(
        authority
            .authenticate(
                PeerCid::from_core(42).unwrap(),
                SessionProof::sign(&key, &expected, nonce_for(8), 0),
            )
            .unwrap_err(),
        SessionRejectReason::StaleSignature
    );
}
