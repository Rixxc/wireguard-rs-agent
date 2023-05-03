use std::collections::HashMap;
use crate::wireguard::handshake::macs;
use crate::wireguard::handshake::types::Psk;

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