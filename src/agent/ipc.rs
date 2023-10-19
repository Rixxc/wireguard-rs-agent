use std::convert::TryInto;
use std::error::Error;
use std::fs::File;
use std::io::{Read, Write};
use std::ops::Deref;

use digest::consts::U32;
use generic_array::GenericArray;
use x25519_dalek::PublicKey;
use zerocopy::{AsBytes, FromBytes, LayoutVerified};

use crate::agent::actions::{consume_initiator, consume_response, create_initiation, register_public_key, set_private_key, TemporaryState};
use crate::agent::types::{IPCError, Peer, State};
use crate::wireguard::handshake::messages::{Initiation, Response};
use crate::wireguard::handshake::types::HandshakeError;

pub struct IPC {
    pub writer: File,
    pub reader: File
}

#[repr(packed)]
#[derive(FromBytes, AsBytes)]
pub struct SetPrivateKey {
    pub request_type: u8,
    pub private_key: [u8; 32]
}

#[repr(packed)]
#[derive(FromBytes, AsBytes)]
pub struct RegisterPublicKey {
    pub request_type: u8,
    pub public_key: [u8; 32],
    pub preshared_key: [u8; 32],
}

#[repr(packed)]
#[derive(FromBytes, AsBytes)]
pub struct ConsumeInitiator {
    pub request_type: u8,
    pub initiation: Initiation
}

#[repr(packed)]
#[derive(FromBytes, AsBytes)]
pub struct ConsumeInitiatorResponse {
    pub error: u8,
    pub receiver: u32,
    pub eph_r_pk: [u8; 32],
    pub hs: [u8; 32],
    pub ck: [u8; 32],
    pub peer_pk: [u8; 32],
    pub ts: [u8; 12]
}

#[repr(packed)]
#[derive(FromBytes, AsBytes)]
pub struct ConsumeResponse {
    pub request_type: u8,
    pub response: Response,
    pub hs: [u8; 32],
    pub ck: [u8; 32],
    pub eph_sk: [u8; 32],
    pub peer_pk: [u8; 32]
}

#[repr(packed)]
#[derive(FromBytes, AsBytes)]
pub struct ConsumeResponseResponse {
    pub error: u8,
    pub key_send: [u8; 32],
    pub key_recv: [u8; 32]
}

#[repr(packed)]
#[derive(FromBytes, AsBytes)]
pub struct CreateInitiation {
    pub request_type: u8,
    pub pk: [u8; 32],
    pub local: u32
}

#[repr(packed)]
#[derive(FromBytes, AsBytes)]
pub struct CreateInitiationResponse {
    pub error: u8,
    pub msg: Initiation,
    pub hs: [u8; 32],
    pub ck: [u8; 32],
    pub eph_sk: [u8; 32]
}

impl IPC {
    pub fn handle_ipc_request(self: &mut Self, state: &mut State) -> Result<(), IPCError> {
        let mut data = [0u8; 400];
        let size = self.reader.read(&mut data).unwrap();
        log::debug!("received crypto agent call: {:?} with size {}", &data[..size], size);

        match data[0] {
            0 => {
                let pk: LayoutVerified<&[u8], SetPrivateKey> = LayoutVerified::new(&data[..size]).ok_or(IPCError::InvalidRequest)?;
                set_private_key(pk.private_key, state);
            }
            1 => {
                let pk: LayoutVerified<&[u8], RegisterPublicKey> = LayoutVerified::new(&data[..size]).ok_or(IPCError::InvalidRequest)?;
                register_public_key(pk.deref(), state);
            }
            2 => {
                let initiator: LayoutVerified<&[u8], ConsumeInitiator> = LayoutVerified::new(&data[..size]).ok_or(IPCError::InvalidRequest)?;
                let resp = consume_initiator(&initiator.initiation.noise, state).unwrap_or(ConsumeInitiatorResponse {
                    error: 1,
                    receiver: 0,
                    eph_r_pk: [0u8; 32],
                    hs: [0u8; 32],
                    ck: [0u8; 32],
                    peer_pk: [0u8; 32],
                    ts: [0u8; 12]
                });

                self.writer.write(resp.as_bytes()).unwrap();
            }
            3 => {
                let response: LayoutVerified<&[u8], ConsumeResponse> = LayoutVerified::new(&data[..size]).ok_or(IPCError::InvalidRequest)?;
                let resp = consume_response(&response, state).unwrap_or(ConsumeResponseResponse {
                    error: 1,
                    key_send: [0u8; 32],
                    key_recv: [0u8; 32]
                });

                self.writer.write(resp.as_bytes()).unwrap();
            }
            4 => {
                let initiation: LayoutVerified<&[u8], CreateInitiation> = LayoutVerified::new(&data[..size]).ok_or(IPCError::InvalidRequest)?;
                let resp = create_initiation(initiation.pk, initiation.local, state).unwrap_or(CreateInitiationResponse {
                    error: 1,
                    msg: Initiation::default(),
                    eph_sk: [0u8; 32],
                    ck: [0u8; 32],
                    hs: [0u8; 32],
                });

                self.writer.write(resp.as_bytes()).unwrap();
            }
            _ => log::error!("Invalid request to crypto agent: {:?}", &data[..size])
        };

        self.writer.flush().unwrap();

        Ok(())
    }
}