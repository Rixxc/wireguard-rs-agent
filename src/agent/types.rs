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
    pub state: Mutex<crate::wireguard::handshake::peer::State>,
    pub timestamp: Mutex<Option<timestamp::TAI64N>>,
    pub last_initiation_consumption: Mutex<Option<Instant>>,
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

impl Peer {
    pub fn check_replay_flood(
        &self,
        //device: &Device<O>,
        timestamp_new: &timestamp::TAI64N,
    ) -> Result<(), HandshakeError> {
        let mut state = self.state.lock();
        let mut timestamp = self.timestamp.lock();
        let mut last_initiation_consumption = self.last_initiation_consumption.lock();

        // check replay attack
        if let Some(timestamp_old) = *timestamp {
            if !timestamp::compare(&timestamp_old, &timestamp_new) {
                return Err(HandshakeError::OldTimestamp);
            }
        };

        // check flood attack
        if let Some(last) = *last_initiation_consumption {
            if last.elapsed() < TIME_BETWEEN_INITIATIONS {
                return Err(HandshakeError::InitiationFlood);
            }
        }

        // reset state
        if let crate::wireguard::handshake::peer::State::InitiationSent { local, .. } = *state {
            // TODO
            //device.release(local)
        }

        // update replay & flood protection
        *state = crate::wireguard::handshake::peer::State::Reset;
        *timestamp = Some(*timestamp_new);
        *last_initiation_consumption = Some(Instant::now());
        Ok(())
    }
}