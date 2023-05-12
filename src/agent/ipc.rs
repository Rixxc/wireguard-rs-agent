use std::convert::TryInto;
use std::error::Error;
use std::fs::File;
use std::io::{Read, Write};
use std::ops::Deref;
use generic_array::GenericArray;
use crate::agent::types::{IPCError, Peer, State};
use zerocopy::{AsBytes, FromBytes, LayoutVerified};
use crate::agent::actions::{consume_initiator, consume_response, register_public_key, set_private_key, TemporaryState};
use crate::wireguard::handshake::messages::{Initiation, Response};
use x25519_dalek::PublicKey;
use digest::consts::U32;
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
                let resp = consume_initiator(&initiator.initiation.noise, state);

                if let Ok(resp) = resp {
                    self.writer.write(ConsumeInitiatorResponse {
                        error: 0,
                        receiver: resp.2.0,
                        eph_r_pk: resp.2.1.to_bytes(),
                        hs: resp.2.2.try_into().unwrap(),
                        ck: resp.2.3.try_into().unwrap(),
                        peer_pk: resp.1.to_bytes(),
                        ts: resp.3.try_into().unwrap()
                    }.as_bytes()).unwrap();
                } else {
                    self.writer.write(ConsumeInitiatorResponse {
                        error: 1,
                        receiver: 0,
                        eph_r_pk: [0u8; 32],
                        hs: [0u8; 32],
                        ck: [0u8; 32],
                        peer_pk: [0u8; 32],
                        ts: [0u8; 12]
                    }.as_bytes()).unwrap();

                    self.writer.flush().unwrap();

                    return Err(IPCError::InvalidRequest)
                }
            }
            3 => {
                log::debug!("before parsing");
                let response: LayoutVerified<&[u8], ConsumeResponse> = LayoutVerified::new(&data[..size]).unwrap();
                log::debug!("after parsing");
                let resp = consume_response(&response, state);

                if let Ok(resp) = resp {
                    self.writer.write(ConsumeResponseResponse {
                        error: 0,
                        key_send: resp.0.try_into().unwrap(),
                        key_recv: resp.1.try_into().unwrap()
                    }.as_bytes()).unwrap();
                } else {
                    self.writer.write(ConsumeResponseResponse {
                        error: 1,
                        key_send: [0u8; 32],
                        key_recv: [0u8; 32]
                    }.as_bytes()).unwrap();

                    self.writer.flush().unwrap();

                    return Err(IPCError::InvalidRequest)
                }
            }
            _ => log::error!("Invalid request to crypto agent: {:?}", &data[..size])
        };

        self.writer.flush().unwrap();

        Ok(())
    }
}