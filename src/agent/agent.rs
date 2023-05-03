use crate::agent::ipc::IPC;
use crate::agent::types::State;

pub fn agent_worker(mut ipc: IPC) {
    // start logging
    env_logger::builder()
        .try_init()
        .expect("Failed to initialize event logger");

    log::debug!("crypto agent worker, started");

    let mut state: State = State::new();

    loop {
        ipc.handle_ipc_request(&mut state);
    }
}