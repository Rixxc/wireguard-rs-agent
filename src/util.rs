use std::cmp::Ordering;
use std::{fmt, ptr};
use std::fs::File;
use std::os::fd::FromRawFd;
use std::process::{exit, Stdio};
use std::sync::Arc;
use std::process::Command;
use std::os::unix::process::CommandExt;
use arraydeque::Array;

use libc::{c_char, chdir, chroot, fork, getpwnam, getuid, setgid, setsid, setuid, umask, pipe2, c_int, O_DIRECT, close, prctl, PR_SET_PDEATHSIG, SIGHUP, SIGTERM, execve, getpid, perror};
use spin::Mutex;
use crate::agent::agent::agent_worker;
use crate::agent::ipc::IPC;

#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Clone)]
pub enum DaemonizeError {
    Fork,
    SetSession,
    SetGroup,
    SetUser,
    Chroot,
    Chdir,
    Pipe,
}

impl fmt::Display for DaemonizeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            DaemonizeError::Fork => "unable to fork",
            DaemonizeError::SetSession => "unable to create new process session",
            DaemonizeError::SetGroup => "unable to set group (drop privileges)",
            DaemonizeError::SetUser => "unable to set user (drop privileges)",
            DaemonizeError::Chroot => "unable to enter chroot jail",
            DaemonizeError::Chdir => "failed to change directory",
            DaemonizeError::Pipe => "failed to create pipe",
        }
        .fmt(f)
    }
}

fn fork_and_exit() -> Result<(), DaemonizeError> {
    let pid = unsafe { fork() };
    match pid.cmp(&0) {
        Ordering::Less => Err(DaemonizeError::Fork),
        Ordering::Equal => Ok(()),
        Ordering::Greater => exit(0),
    }
}

pub fn daemonize() -> Result<(), DaemonizeError> {
    // fork from the original parent
    fork_and_exit()?;

    // avoid killing the child when this parent dies
    if unsafe { setsid() } < 0 {
        return Err(DaemonizeError::SetSession);
    }

    // fork again to create orphan
    fork_and_exit()
}

pub fn drop_privileges() -> Result<(), DaemonizeError> {
    // retrieve nobody's uid & gid
    let usr = unsafe { getpwnam("nobody\x00".as_ptr() as *const c_char) };
    if usr.is_null() {
        return Err(DaemonizeError::SetGroup);
    }

    // change root directory
    let uid = unsafe { getuid() };
    if uid == 0 && unsafe { chroot("/tmp\x00".as_ptr() as *const c_char) } != 0 {
        return Err(DaemonizeError::Chroot);
    }

    // set umask for files
    unsafe { umask(0) };

    // change directory
    if unsafe { chdir("/\x00".as_ptr() as *const c_char) } != 0 {
        return Err(DaemonizeError::Chdir);
    }

    // set group id to nobody
    if unsafe { setgid((*usr).pw_gid) } != 0 {
        return Err(DaemonizeError::SetGroup);
    }

    // set user id to nobody
    if unsafe { setuid((*usr).pw_uid) } != 0 {
        Err(DaemonizeError::SetUser)
    } else {
        Ok(())
    }
}

pub fn start_crypto_agent<>() -> Result<Arc<Mutex<IPC>>, DaemonizeError> {
    // read / write fd
    let client_to_agent: [c_int; 2] = [0; 2];
    let agent_to_client: [c_int; 2] = [0; 2];

    unsafe {
        let mut pipe = pipe2(client_to_agent.as_ptr() as *mut c_int, O_DIRECT);
        pipe |= pipe2(agent_to_client.as_ptr() as *mut c_int, O_DIRECT);

        if pipe != 0 {
            return Err(DaemonizeError::Pipe);
        }
    }

    let pid = unsafe { fork() };
    match pid.cmp(&0) {
        Ordering::Less => Err(DaemonizeError::Fork),
        Ordering::Equal => {
            // client
            unsafe {
                close(client_to_agent[0]);
                close(agent_to_client[1]);

                prctl(PR_SET_PDEATHSIG, SIGHUP);

                Ok(Arc::new(Mutex::new(IPC {
                    writer: File::from_raw_fd(client_to_agent[1]),
                    reader: File::from_raw_fd(agent_to_client[0])
                })))
            }
        },
        Ordering::Greater => {
            // agent
            unsafe {
                close(client_to_agent[1]);
                close(agent_to_client[0]);

                println!("PID: {}", getpid());
                println!("writer: {} reader: {}", agent_to_client[1], client_to_agent[0]);
                assert_eq!(agent_to_client[1], 6);
                assert_eq!(client_to_agent[0], 3);

                let err = Command::new("/home/rixxc/Projekte/MPI/Wireguard/jasmin-agent/agent")
                    .current_dir("/home/rixxc/Projekte/MPI/Wireguard/jasmin-agent")
                    .stdout(Stdio::inherit())
                    .exec();
                println!("Error: {}", err);

                exit(1);

                agent_worker(IPC {
                    writer: File::from_raw_fd(agent_to_client[1]),
                    reader: File::from_raw_fd(client_to_agent[0])
                }); // should never return

                Ok(Arc::new(Mutex::new(IPC {
                    writer: File::from_raw_fd(agent_to_client[1]),
                    reader: File::from_raw_fd(client_to_agent[0])
                })))
            }
        },
    }
}

