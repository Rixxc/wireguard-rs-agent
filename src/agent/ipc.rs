use std::convert::TryInto;
use std::fs::File;
use std::io::{Read, Write};
use std::ops::Deref;
use generic_array::GenericArray;
use crate::agent::types::{Peer, State};
use zerocopy::{AsBytes, FromBytes, LayoutVerified};
use crate::agent::actions::{consume_initiator, register_public_key, set_private_key, TemporaryState};
use crate::wireguard::handshake::messages::Initiation;
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
    error: u8,
    receiver: u32,
    eph_r_pk: [u8; 32],
    hs: [u8; 32],
    ck: [u8; 32]
}

impl IPC {
    pub fn handle_ipc_request(self: &mut Self, state: &mut State) {
        let mut data = [0u8; 200];
        let size = self.reader.read(&mut data).unwrap();
        log::debug!("received crypto agent call: {:?}", &data[..size]);

        match data[0] {
            0 => {
                let pk: LayoutVerified<&[u8], SetPrivateKey> = LayoutVerified::new(&data[..size]).unwrap();
                set_private_key(pk.private_key, state);
            }
            1 => {
                let pk: LayoutVerified<&[u8], RegisterPublicKey> = LayoutVerified::new(&data[..size]).unwrap();
                register_public_key(pk.deref(), state);
            }
            2 => {
                let initiator: LayoutVerified<&[u8], ConsumeInitiator> = LayoutVerified::new(&data[..size]).unwrap();
                let resp = consume_initiator(&initiator.initiation.noise, state);

                if let Ok(resp) = resp {
                    self.writer.write(ConsumeInitiatorResponse {
                        error: 0,
                        receiver: resp.2.0,
                        eph_r_pk: resp.2.1.to_bytes(),
                        hs: resp.2.2.try_into().unwrap(),
                        ck: resp.2.3.try_into().unwrap()
                    }.as_bytes()).unwrap();
                } else {
                    self.writer.write(ConsumeInitiatorResponse {
                        error: 1,
                        receiver: 0,
                        eph_r_pk: [0u8; 32],
                        hs: [0u8; 32],
                        ck: [0u8; 32]
                    }.as_bytes()).unwrap();

                    self.writer.flush().unwrap();
                }
            }
            _ => log::error!("Invalid request to crypto agent: {:?}", &data[..size])
        }
    }
}