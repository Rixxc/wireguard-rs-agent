use std::collections::HashMap;
use spin::Mutex;
use std::time::{Duration, Instant};
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

pub struct State {
    pub keyst: Option<crate::wireguard::handshake::device::KeyState>,
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