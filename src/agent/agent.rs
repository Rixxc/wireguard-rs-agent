use std::convert::TryInto;
use std::fs;
use std::io::Write;

use x25519_dalek::{PublicKey, StaticSecret};

use crate::agent::ipc::IPC;
use crate::agent::types::{KeyState, State};
use crate::wireguard::handshake::macs;

pub fn agent_worker(mut ipc: IPC) {
    // start logging
    env_logger::builder()
        .try_init()
        .expect("Failed to initialize event logger");

    log::debug!("crypto agent worker, started");

    let private_key: [u8; 32] = fs::read("/tmp/private_key").unwrap().try_into().unwrap();
    let private_key = Some(StaticSecret::from(private_key));

    let mut state: State = State::new();
    state.keyst = private_key.map(|sk| {
        let pk = PublicKey::from(&sk);
        let macs = macs::Validator::new(pk);
        KeyState { pk, sk, macs }
    });

    ipc.writer.write(state.keyst.as_ref().unwrap().pk.as_bytes()).unwrap();
    ipc.writer.flush().unwrap();

    loop {
        match ipc.handle_ipc_request(&mut state) {
            Ok(()) => {},
            Err(e) => log::error!("{:?}", e)
        };
    }
}