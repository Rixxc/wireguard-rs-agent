use std::convert::TryInto;

use aead::{Aead, NewAead, Payload};
use blake2::Blake2s;
use chacha20poly1305::ChaCha20Poly1305;
use clear_on_drop::clear::Clear;
use clear_on_drop::clear_stack_on_return_fnonce;
use digest::consts::U32;
use generic_array::GenericArray;
use hmac::Hmac;
use rand::rngs::OsRng;
use subtle::ConstantTimeEq;
use x25519_dalek::{PublicKey, StaticSecret};
use zerocopy::AsBytes;

use crate::agent::ipc::{ConsumeInitiatorResponse, ConsumeResponse, ConsumeResponseResponse, CreateInitiationResponse, RegisterPublicKey};
use crate::agent::types::{Peer, State};
use crate::agent::types::KeyState;
use crate::wireguard::handshake::{macs, timestamp, TYPE_INITIATION};
use crate::wireguard::handshake::messages::{Initiation, NoiseInitiation};
use crate::wireguard::handshake::noise::shared_secret;
use crate::wireguard::handshake::types::HandshakeError;

// HMAC hasher (generic construction)

type HMACBlake2s = Hmac<Blake2s>;

// convenient alias to pass state temporarily into device.rs and back

pub type TemporaryState = (u32, PublicKey, GenericArray<u8, U32>, GenericArray<u8, U32>);

const SIZE_CK: usize = 32;
const SIZE_HS: usize = 32;

// number of pages to clear after sensitive call
const CLEAR_PAGES: usize = 1;

// C := Hash(Construction)
const INITIAL_CK: [u8; SIZE_CK] = [
    0x60, 0xe2, 0x6d, 0xae, 0xf3, 0x27, 0xef, 0xc0, 0x2e, 0xc3, 0x35, 0xe2, 0xa0, 0x25, 0xd2, 0xd0,
    0x16, 0xeb, 0x42, 0x06, 0xf8, 0x72, 0x77, 0xf5, 0x2d, 0x38, 0xd1, 0x98, 0x8b, 0x78, 0xcd, 0x36,
];

// H := Hash(C || Identifier)
const INITIAL_HS: [u8; SIZE_HS] = [
    0x22, 0x11, 0xb3, 0x61, 0x08, 0x1a, 0xc5, 0x66, 0x69, 0x12, 0x43, 0xdb, 0x45, 0x8a, 0xd5, 0x32,
    0x2d, 0x9c, 0x6c, 0x66, 0x22, 0x93, 0xe8, 0xb7, 0x0e, 0xe1, 0x9c, 0x65, 0xba, 0x07, 0x9e, 0xf3,
];

const ZERO_NONCE: [u8; 12] = [0u8; 12];

macro_rules! HASH {
    ( $($input:expr),* ) => {{
        use blake2::Digest;
        let mut hsh = Blake2s::new();
        $(
            hsh.update($input);
        )*
        hsh.finalize()
    }};
}

macro_rules! HMAC {
    ($key:expr, $($input:expr),*) => {{
        use hmac::{Mac, NewMac};
        let mut mac = HMACBlake2s::new_varkey($key).unwrap();
        $(
            mac.update($input);
        )*
        mac.finalize().into_bytes()
    }};
}

macro_rules! KDF1 {
    ($ck:expr, $input:expr) => {{
        let mut t0 = HMAC!($ck, $input);
        let t1 = HMAC!(&t0, &[0x1]);
        t0.clear();
        t1
    }};
}

macro_rules! KDF2 {
    ($ck:expr, $input:expr) => {{
        let mut t0 = HMAC!($ck, $input);
        let t1 = HMAC!(&t0, &[0x1]);
        let t2 = HMAC!(&t0, &t1, &[0x2]);
        t0.clear();
        (t1, t2)
    }};
}

macro_rules! KDF3 {
    ($ck:expr, $input:expr) => {{
        let mut t0 = HMAC!($ck, $input);
        let t1 = HMAC!(&t0, &[0x1]);
        let t2 = HMAC!(&t0, &t1, &[0x2]);
        let t3 = HMAC!(&t0, &t2, &[0x3]);
        t0.clear();
        (t1, t2, t3)
    }};
}

macro_rules! SEAL {
    ($key:expr, $ad:expr, $pt:expr, $ct:expr) => {
        ChaCha20Poly1305::new(GenericArray::from_slice($key))
            .encrypt(&ZERO_NONCE.into(), Payload { msg: $pt, aad: $ad })
            .map(|ct| $ct.copy_from_slice(&ct))
            .unwrap()
    };
}

macro_rules! OPEN {
    ($key:expr, $ad:expr, $pt:expr, $ct:expr) => {
        ChaCha20Poly1305::new(GenericArray::from_slice($key))
            .decrypt(&ZERO_NONCE.into(), Payload { msg: $ct, aad: $ad })
            .map_err(|_| HandshakeError::DecryptionFailure)
            .map(|pt| $pt.copy_from_slice(&pt))
    };
}

pub fn set_private_key(pk: [u8;32], state: &mut State) {
    let psk = StaticSecret::from(pk);
    let pk = PublicKey::from(&psk);
    let macs = macs::Validator::new(pk);

    state.keyst = Some(KeyState { pk, sk: psk });

    for (public_key, peer) in &mut state.pk_map {
        let pk = PublicKey::from(public_key.clone());
        peer.ss = state.keyst
            .as_ref()
            .map(|key| *key.sk.diffie_hellman(&pk).as_bytes())
            .unwrap_or([0u8; 32]);
    }
}

pub fn register_public_key(public_key: &RegisterPublicKey, state: &mut State) {
    let pk = PublicKey::from(public_key.public_key);
    state.pk_map.insert(public_key.public_key, Peer {
        psk: public_key.preshared_key,
        ss: state.keyst
            .as_ref()
            .map(|key| *key.sk.diffie_hellman(&pk).as_bytes())
            .unwrap_or([0u8; 32])
    });
}

pub fn consume_initiator(msg: &NoiseInitiation, state: &mut State) -> Result<ConsumeInitiatorResponse, HandshakeError> {
    clear_stack_on_return_fnonce(CLEAR_PAGES, move || {
        // initialize new state
        let keyst = state.keyst.as_ref().unwrap();

        let ck = INITIAL_CK;
        let hs = INITIAL_HS;
        let hs = HASH!(&hs, keyst.pk.as_bytes());

        // C := Kdf(C, E_pub)

        let ck = KDF1!(&ck, &msg.f_ephemeral);

        // H := HASH(H, msg.ephemeral)

        let hs = HASH!(&hs, &msg.f_ephemeral);

        // (C, k) := Kdf2(C, DH(E_priv, S_pub))

        let eph_r_pk = PublicKey::from(msg.f_ephemeral);
        let (ck, key) = KDF2!(&ck, shared_secret(&keyst.sk, &eph_r_pk)?.as_bytes());

        // msg.static := Aead(k, 0, S_pub, H)

        let mut pk = [0u8; 32];

        OPEN!(
            &key,
            &hs,           // ad
            &mut pk,       // pt
            &msg.f_static  // ct || tag
        )?;

        //let peer = device.lookup_pk(&PublicKey::from(pk))?;
        let peer = state.pk_map.get(&pk).ok_or(HandshakeError::UnknownPublicKey)?;

        // check for zero shared-secret (see "shared_secret" note).

        if peer.ss.ct_eq(&[0u8; 32]).into() {
            return Err(HandshakeError::InvalidSharedSecret);
        }

        // reset initiation state

        // *peer.state.lock() = crate::wireguard::handshake::peer::State::Reset;

        // H := Hash(H || msg.static)

        let hs = HASH!(&hs, &msg.f_static[..]);

        // (C, k) := Kdf2(C, DH(S_priv, S_pub))

        let (ck, key) = KDF2!(&ck, &peer.ss);

        // msg.timestamp := Aead(k, 0, Timestamp(), H)

        let mut ts = timestamp::ZERO;

        OPEN!(
            &key,
            &hs,              // ad
            &mut ts,          // pt
            &msg.f_timestamp  // ct || tag
        )?;

        // check and update timestamp

        // peer.check_replay_flood(&ts)?;

        // H := Hash(H || msg.timestamp)

        let hs = HASH!(&hs, &msg.f_timestamp);

        // return state (to create response)

        Ok(ConsumeInitiatorResponse {
            error: 0,
            receiver: msg.f_sender.get(),
            eph_r_pk: *eph_r_pk.as_bytes(),
            hs: hs.try_into().unwrap(),
            ck: ck.try_into().unwrap(),
            peer_pk: pk,
            ts: ts.try_into().unwrap()
        })
    })
}

pub fn consume_response(
    resp: &ConsumeResponse,
    state: &mut State
) -> Result<ConsumeResponseResponse, HandshakeError> {
    clear_stack_on_return_fnonce(CLEAR_PAGES, || {
        // retrieve peer and copy initiation state
        let peer = state.pk_map.get(&resp.peer_pk).ok_or(HandshakeError::UnknownPublicKey)?;
        let keyst = state.keyst.as_ref().unwrap();

        // C := Kdf1(C, E_pub)

        let ck = KDF1!(&resp.ck, &resp.response.noise.f_ephemeral);

        // H := Hash(H || msg.ephemeral)

        let hs = HASH!(resp.hs, &resp.response.noise.f_ephemeral);

        // C := Kdf1(C, DH(E_priv, E_pub))

        let eph_r_pk = PublicKey::from(resp.response.noise.f_ephemeral);
        let ck = KDF1!(&ck, shared_secret(&StaticSecret::from(resp.eph_sk), &eph_r_pk)?.as_bytes());

        // C := Kdf1(C, DH(E_priv, S_pub))

        let ck = KDF1!(&ck, shared_secret(&keyst.sk, &eph_r_pk)?.as_bytes());

        // (C, tau, k) := Kdf3(C, Q)

        let (ck, tau, key) = KDF3!(&ck, &peer.psk);

        // H := Hash(H || tau)

        let hs = HASH!(&hs, tau);

        // msg.empty := Aead(k, 0, [], H)

        OPEN!(
            &key,
            &hs,          // ad
            &mut [],      // pt
            &resp.response.noise.f_empty  // \epsilon || tag
        )?;

        // derive key-pair
        let (key_send, key_recv) = KDF2!(&ck, &[]);

        Ok(ConsumeResponseResponse {
            error: 0,
            key_send: key_send.try_into().unwrap(),
            key_recv: key_recv.try_into().unwrap()
        })
    })
}

pub(super) fn create_initiation(
    pk: [u8; 32],
    local: u32,
    state: &mut State
) -> Result<CreateInitiationResponse, HandshakeError> {
    log::debug!("create initiation");
    clear_stack_on_return_fnonce(CLEAR_PAGES, || {
        let peer = state.pk_map.get(&pk).ok_or(HandshakeError::UnknownPublicKey)?;

        // check for zero shared-secret (see "shared_secret" note).
        if peer.ss.ct_eq(&[0u8; 32]).into() {
            return Err(HandshakeError::InvalidSharedSecret);
        }

        let mut msg = Initiation::default();
        // initialize state

        let ck = INITIAL_CK;
        let hs = INITIAL_HS;
        let hs = HASH!(&hs, pk.as_bytes());

        msg.noise.f_type.set(TYPE_INITIATION as u32);
        msg.noise.f_sender.set(local); // from us

        // (E_priv, E_pub) := DH-Generate()

        let eph_sk = StaticSecret::new(OsRng);
        let eph_pk = PublicKey::from(&eph_sk);

        // C := Kdf(C, E_pub)

        let ck = KDF1!(&ck, eph_pk.as_bytes());

        // msg.ephemeral := E_pub

        msg.noise.f_ephemeral = *eph_pk.as_bytes();

        // H := HASH(H, msg.ephemeral)

        let hs = HASH!(&hs, msg.noise.f_ephemeral);

        // (C, k) := Kdf2(C, DH(E_priv, S_pub))

        let (ck, key) = KDF2!(&ck, shared_secret(&eph_sk, &PublicKey::from(pk))?.as_bytes());

        // msg.static := Aead(k, 0, S_pub, H)

        SEAL!(
            &key,
            &hs,                 // ad
            state.keyst.as_ref().ok_or(HandshakeError::InvalidSharedSecret)?.pk.as_bytes(), // pt
            &mut msg.noise.f_static    // ct || tag
        );

        // H := Hash(H || msg.static)

        let hs = HASH!(&hs, &msg.noise.f_static[..]);

        // (C, k) := Kdf2(C, DH(S_priv, S_pub))

        let (ck, key) = KDF2!(&ck, &peer.ss);

        // msg.timestamp := Aead(k, 0, Timestamp(), H)

        SEAL!(
            &key,
            &hs,                  // ad
            &timestamp::now(),    // pt
            &mut msg.noise.f_timestamp  // ct || tag
        );

        // H := Hash(H || msg.timestamp)

        let hs = HASH!(&hs, &msg.noise.f_timestamp);

        Ok(CreateInitiationResponse {
            error: 0,
            msg,
            hs: hs.into(),
            ck: ck.into(),
            eph_sk: eph_sk.to_bytes()
        })
    })
}