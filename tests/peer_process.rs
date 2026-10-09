#[path = "../src/peer.rs"]
mod peer;

use ed25519_dalek::SigningKey;
use iroh::{EndpointId, SecretKey};
use std::{
    io::{BufRead, BufReader, Write},
    process::{Command, Stdio},
    sync::mpsc,
    thread,
    time::Duration,
};

const LISTENER_SEED: [u8; 32] = [0x11; 32];
const SENDER_SEED: [u8; 32] = [0x22; 32];
const OTHER_SEED: [u8; 32] = [0x33; 32];
const TEXT: &str = "message sent by a second OS process";

#[test]
fn peer_process_worker() {
    let Ok(role) = std::env::var("SLOUCHING_PEER_WORKER") else {
        return;
    };
    let rejecting = std::env::var_os("SLOUCHING_PEER_REJECT").is_some();
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("worker runtime should start");
    if role == "listen" {
        let listener_key = SecretKey::from_bytes(&LISTENER_SEED);
        let listener_public = SigningKey::from_bytes(&LISTENER_SEED)
            .verifying_key()
            .to_bytes();
        assert_eq!(listener_key.public().as_bytes(), &listener_public);
        let expected_seed = if rejecting { OTHER_SEED } else { SENDER_SEED };
        let expected_peer = endpoint_id_for_seed(expected_seed);
        let listener = runtime
            .block_on(peer::bind_listener(
                listener_key,
                "127.0.0.1:0".parse().expect("valid loopback bind"),
                expected_peer,
            ))
            .expect("listener should bind a direct-only Iroh endpoint");
        assert_eq!(listener.id().as_bytes(), &listener_public);
        let address = listener
            .direct_addresses()
            .into_iter()
            .find(|address| address.ip().is_loopback())
            .expect("listener should expose its loopback test address");
        println!("READY {address}");
        std::io::stdout().flush().expect("ready line should flush");
        let result = runtime
            .block_on(async {
                tokio::time::timeout(Duration::from_secs(20), listener.receive_once()).await
            })
            .expect("listener worker should finish within 20 seconds");
        if rejecting {
            assert!(result.unwrap_err().contains("pinned device identity"));
            println!("REJECTED");
        } else {
            assert_eq!(result.expect("pinned peer payload should arrive"), TEXT);
            println!("RECEIVED");
        }
    } else if role == "send" {
        let address = std::env::var("SLOUCHING_PEER_ADDRESS")
            .expect("parent supplies direct address")
            .parse()
            .expect("parent supplies valid socket address");
        let sender_key = SecretKey::from_bytes(&SENDER_SEED);
        assert_eq!(
            sender_key.public().as_bytes(),
            SigningKey::from_bytes(&SENDER_SEED)
                .verifying_key()
                .as_bytes()
        );
        let result = runtime
            .block_on(async {
                tokio::time::timeout(
                    Duration::from_secs(30),
                    peer::send_once(
                        sender_key,
                        endpoint_id_for_seed(LISTENER_SEED),
                        address,
                        TEXT,
                    ),
                )
                .await
            })
            .expect("sender worker should finish within 30 seconds");
        if rejecting {
            assert!(result.is_err(), "wrong pinned device must fail the sender");
            println!("SEND_REJECTED");
        } else {
            assert_eq!(
                result.expect("listener acknowledgement should arrive"),
                "received 35 bytes"
            );
            println!("SENT");
        }
    } else {
        panic!("unknown peer worker role: {role}");
    }
}

#[test]
fn separate_processes_exchange_and_reject_unpinned_identity() {
    run_two_processes(false);
    run_two_processes(true);
}

fn run_two_processes(rejecting: bool) {
    let executable = std::env::current_exe().expect("test binary path should be available");
    let mut listener_command = Command::new(&executable);
    listener_command
        .args(["--exact", "peer_process_worker", "--nocapture"])
        .env("SLOUCHING_PEER_WORKER", "listen")
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit());
    if rejecting {
        listener_command.env("SLOUCHING_PEER_REJECT", "1");
    }
    let mut listener = listener_command
        .spawn()
        .expect("listener child process should start");
    let stdout = listener
        .stdout
        .take()
        .expect("listener stdout should be piped");
    let (ready_tx, ready_rx) = mpsc::channel();
    thread::spawn(move || {
        let mut reader = BufReader::new(stdout);
        let mut prior_output = String::new();
        loop {
            let mut line = String::new();
            match reader.read_line(&mut line) {
                Ok(0) => {
                    let _ = ready_tx.send(prior_output);
                    return;
                }
                Ok(_) if line.starts_with("READY ") => {
                    let _ = ready_tx.send(line);
                    let mut discard = String::new();
                    while reader.read_line(&mut discard).unwrap_or(0) > 0 {
                        discard.clear();
                    }
                    return;
                }
                Ok(_) => prior_output.push_str(&line),
                Err(error) => {
                    prior_output.push_str(&format!("stdout read error: {error}"));
                    let _ = ready_tx.send(prior_output);
                    return;
                }
            }
        }
    });
    let ready = match ready_rx.recv_timeout(Duration::from_secs(20)) {
        Ok(ready) => ready,
        Err(error) => {
            let _ = listener.kill();
            let _ = listener.wait();
            panic!("listener should report ready within 20 seconds: {error}");
        }
    };
    let address = ready
        .strip_prefix("READY ")
        .unwrap_or_else(|| panic!("listener did not emit a ready address: {ready}"))
        .trim()
        .to_owned();

    let mut sender_command = Command::new(&executable);
    sender_command
        .args(["--exact", "peer_process_worker", "--nocapture"])
        .env("SLOUCHING_PEER_WORKER", "send")
        .env("SLOUCHING_PEER_ADDRESS", address)
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit());
    if rejecting {
        sender_command.env("SLOUCHING_PEER_REJECT", "1");
    }
    let sender = sender_command
        .spawn()
        .expect("sender child process should start");
    let sender_output = sender
        .wait_with_output()
        .expect("sender process should exit");
    if !sender_output.status.success() {
        let _ = listener.kill();
    }
    let listener_status = listener.wait().expect("listener process should exit");
    assert!(sender_output.status.success(), "sender process failed");
    assert!(listener_status.success(), "listener process failed");
}

fn endpoint_id_for_seed(seed: [u8; 32]) -> EndpointId {
    let signing_key = SigningKey::from_bytes(&seed);
    EndpointId::from_bytes(&signing_key.verifying_key().to_bytes())
        .expect("test Ed25519 public key should be a valid iroh endpoint ID")
}
