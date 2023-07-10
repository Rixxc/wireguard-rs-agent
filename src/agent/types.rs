use std::collections::HashMap;
use std::time::{Duration, Instant};

use spin::Mutex;
use x25519_dalek::{PublicKey, StaticSecret};

use crate::wireguard::handshake::{macs, timestamp};
use crate::wireguard::handshake::types::{HandshakeError, Psk};

const TIME_BETWEEN_INITIATIONS: Duration = Duration::from_millis(20);

#[derive(Debug)]
pub enum IPCError {
    InvalidRequest,
    AgentError
}

pub struct Peer {
    pub macs: macs::Generator,
    pub ss: [u8; 32], // precomputed DH(static, static)
    pub psk: Psk,     // psk of peer
}

pub struct KeyState {
    pub sk: StaticSecret, // static secret key
    pub pk: PublicKey,    // static public key
    pub macs: macs::Validator,       // validator for the mac fields
}

pub struct State {
    pub keyst: Option<KeyState>,
    pub pk_map: HashMap<[u8; 32], Peer>
}

impl State {
    pub(crate) fn new() -> Self {
        Self {
            keyst: None,
            pk_map: HashMap::new()
        }
    }
}