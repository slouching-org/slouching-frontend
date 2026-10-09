#[path = "../src/peer.rs"]
mod peer;

use ed25519_dalek::SigningKey;
use futures_util::StreamExt;
use iroh::{EndpointId, SecretKey};
use std::{
    collections::HashSet,
    io::{BufRead, BufReader, Write},
    process::{Command, Stdio},
    sync::mpsc as std_mpsc,
    thread,
    time::Duration,
};
use tokio::sync::mpsc;

const LISTENER_SEED: [u8; 32] = [0x11; 32];
const SENDER_SEED: [u8; 32] = [0x22; 32];
const OTHER_SEED: [u8; 32] = [0x33; 32];
const MESSAGE_COUNT: u64 = 3;
const UNACKNOWLEDGED_TEXT: &str = "disconnect with pending delivery";

#[test]
fn peer_process_worker() {
    let Ok(role) = std::env::var("SLOUCHING_PEER_WORKER") else {
        return;
    };
    let mode = std::env::var("SLOUCHING_PEER_MODE").unwrap_or_else(|_| "session".to_owned());
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("worker runtime should start");
    if role == "listen" {
        runtime.block_on(async move {
            run_listener(&mode).await;
        });
    } else if role == "send" {
        runtime.block_on(async move {
            run_sender(&mode).await;
        });
    } else {
        panic!("unknown peer worker role: {role}");
    }
}

#[test]
fn separate_processes_exchange_multiple_messages_both_ways_and_close_with_pending_send() {
    run_two_processes("session");
}

#[test]
fn separate_processes_reject_wrong_pinned_device_before_session_stream() {
    run_two_processes("reject");
}

async fn run_listener(mode: &str) {
    let listener_key = SecretKey::from_bytes(&LISTENER_SEED);
    let listener_public = SigningKey::from_bytes(&LISTENER_SEED)
        .verifying_key()
        .to_bytes();
    assert_eq!(listener_key.public().as_bytes(), &listener_public);
    let expected_seed = if mode == "reject" {
        OTHER_SEED
    } else {
        SENDER_SEED
    };
    let listener = peer::bind_listener(
        listener_key,
        "127.0.0.1:0".parse().expect("valid loopback bind"),
        endpoint_id_for_seed(expected_seed),
    )
    .await
    .expect("listener should bind direct-only Iroh endpoint");
    assert_eq!(listener.id().as_bytes(), &listener_public);
    let address = listener
        .direct_addresses()
        .into_iter()
        .find(|address| address.ip().is_loopback())
        .expect("listener should expose a loopback test address");
    println!("READY {address}");
    std::io::stdout().flush().expect("ready line should flush");

    if mode == "reject" {
        for _ in 0..2 {
            let result = tokio::time::timeout(Duration::from_secs(12), listener.accept_session())
                .await
                .expect("listener should report a wrong pin promptly");
            assert!(matches!(
                result,
                Err(peer::PeerAcceptError::Unauthorized(_))
            ));
            assert!(
                !listener.is_closed(),
                "listener should remain available after a wrong pin"
            );
        }
        listener.close().await;
        assert!(listener.is_closed(), "listener close should finish cleanly");
        println!("REJECTED_TWICE");
        return;
    }

    let session = tokio::time::timeout(Duration::from_secs(12), listener.accept_session())
        .await
        .expect("listener should accept a pinned session")
        .expect("pinned peer should be accepted");
    run_session_script(session, "listener").await;
}

async fn run_sender(mode: &str) {
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

    if mode == "reject" {
        for _ in 0..2 {
            let session = tokio::time::timeout(
                Duration::from_secs(12),
                peer::connect_peer(
                    sender_key.clone(),
                    endpoint_id_for_seed(LISTENER_SEED),
                    address,
                ),
            )
            .await
            .expect("attempt to a live listener should resolve")
            .expect("transport may connect before the listener rejects the device pin");
            assert_no_application_session(session).await;
        }
        println!("UNAUTHORIZED_PEER_REJECTED");
        return;
    }

    let session = tokio::time::timeout(
        Duration::from_secs(12),
        peer::connect_peer(sender_key, endpoint_id_for_seed(LISTENER_SEED), address),
    )
    .await
    .expect("sender should connect within 12 seconds")
    .expect("pinned listener should accept the QUIC connection");
    run_session_script(session, "sender").await;
}

async fn run_session_script(session: peer::DirectPeerSession, role: &str) {
    let (command_tx, command_rx) = mpsc::channel(64);
    let (event_tx, mut event_rx) = mpsc::channel(64);
    let ack_commands = command_tx.clone();
    let mut events = Box::pin(session.run(command_rx));
    let event_pump = tokio::spawn(async move {
        while let Some(event) = events.next().await {
            if let peer::PeerEvent::Received { sequence, text } = &event
                && text != UNACKNOWLEDGED_TEXT
            {
                ack_commands
                    .send(peer::PeerCommand::AcceptInbound {
                        sequence: *sequence,
                    })
                    .await
                    .expect("session command receiver should remain open");
            }
            if event_tx.send(event).await.is_err() {
                return;
            }
        }
    });

    for request_id in 1..=MESSAGE_COUNT {
        command_tx
            .send(peer::PeerCommand::Send {
                request_id,
                text: format!("from-{role}-{request_id}"),
            })
            .await
            .expect("session should accept outgoing messages");
    }
    let mut acknowledged = HashSet::new();
    let mut received = HashSet::new();
    while acknowledged.len() < MESSAGE_COUNT as usize || received.len() < MESSAGE_COUNT as usize {
        let event = tokio::time::timeout(Duration::from_secs(15), event_rx.recv())
            .await
            .expect("session should exchange messages and ACKs")
            .expect("session event stream should remain open");
        match event {
            peer::PeerEvent::Connected { .. } => {}
            peer::PeerEvent::Acknowledged { request_id, text } => {
                assert_eq!(text, format!("from-{role}-{request_id}"));
                assert!(acknowledged.insert(request_id), "duplicate ACK");
            }
            peer::PeerEvent::Received { sequence, text } => {
                let expected_role = if role == "listener" {
                    "sender"
                } else {
                    "listener"
                };
                assert!(
                    (1..=MESSAGE_COUNT).any(|id| text == format!("from-{expected_role}-{id}")),
                    "unexpected text received: {text}"
                );
                assert!(received.insert(sequence), "duplicate receive sequence");
            }
            peer::PeerEvent::Rejected { reason, .. } => {
                panic!("message was unexpectedly rejected: {reason}")
            }
            peer::PeerEvent::DeliveryUnknown { .. } | peer::PeerEvent::Unauthorized { .. } => {
                panic!("session failed before completing the expected messages")
            }
            peer::PeerEvent::Disconnected { reason } => {
                panic!("session disconnected before exchange completed: {reason}")
            }
        }
    }

    if role == "sender" {
        command_tx
            .send(peer::PeerCommand::Send {
                request_id: 99,
                text: UNACKNOWLEDGED_TEXT.to_owned(),
            })
            .await
            .expect("session should accept the pending message");
        command_tx
            .send(peer::PeerCommand::Disconnect)
            .await
            .expect("session should accept explicit disconnect");
        let mut got_unknown = false;
        let mut got_disconnected = false;
        while !got_unknown || !got_disconnected {
            match tokio::time::timeout(Duration::from_secs(12), event_rx.recv())
                .await
                .expect("disconnect should resolve")
                .expect("disconnect event should arrive")
            {
                peer::PeerEvent::DeliveryUnknown { request_id, text } => {
                    assert_eq!(request_id, 99);
                    assert_eq!(text, UNACKNOWLEDGED_TEXT);
                    got_unknown = true;
                }
                peer::PeerEvent::Disconnected { .. } => got_disconnected = true,
                peer::PeerEvent::Received { text, .. } => {
                    assert_ne!(text, UNACKNOWLEDGED_TEXT);
                }
                peer::PeerEvent::Connected { .. } | peer::PeerEvent::Acknowledged { .. } => {}
                peer::PeerEvent::Rejected { reason, .. } => {
                    panic!("unexpected rejection: {reason}")
                }
                peer::PeerEvent::Unauthorized { .. } => panic!("unexpected authorization event"),
            }
        }
    } else {
        let mut got_unacknowledged = false;
        let mut got_disconnected = false;
        while !got_unacknowledged || !got_disconnected {
            match tokio::time::timeout(Duration::from_secs(12), event_rx.recv())
                .await
                .expect("peer disconnect should resolve")
                .expect("disconnect event should arrive")
            {
                peer::PeerEvent::Received { text, .. } if text == UNACKNOWLEDGED_TEXT => {
                    got_unacknowledged = true;
                }
                peer::PeerEvent::Disconnected { .. } => got_disconnected = true,
                peer::PeerEvent::Connected { .. }
                | peer::PeerEvent::Received { .. }
                | peer::PeerEvent::Acknowledged { .. } => {}
                peer::PeerEvent::DeliveryUnknown { .. }
                | peer::PeerEvent::Rejected { .. }
                | peer::PeerEvent::Unauthorized { .. } => panic!("unexpected listener event"),
            }
        }
    }
    drop(command_tx);
    event_pump
        .await
        .expect("session event pump should shut down after endpoint close");
    println!("SESSION_COMPLETE {role}");
}

async fn assert_no_application_session(session: peer::DirectPeerSession) {
    let (command_tx, command_rx) = mpsc::channel(4);
    let mut events = Box::pin(session.run(command_rx));
    assert!(matches!(
        events.next().await,
        Some(peer::PeerEvent::Connected { .. })
    ));
    command_tx
        .send(peer::PeerCommand::Send {
            request_id: 1,
            text: "must not reach application stream".to_owned(),
        })
        .await
        .expect("session should accept test command before remote rejection arrives");
    let mut rejected = false;
    while let Some(event) = tokio::time::timeout(Duration::from_secs(8), events.next())
        .await
        .expect("unauthorized session should close promptly")
    {
        match event {
            peer::PeerEvent::DeliveryUnknown { request_id: 1, .. } => rejected = true,
            peer::PeerEvent::Acknowledged { .. } | peer::PeerEvent::Received { .. } => {
                panic!("wrong pinned device exchanged an application message")
            }
            peer::PeerEvent::Disconnected { .. } => break,
            peer::PeerEvent::Connected { .. }
            | peer::PeerEvent::Rejected { .. }
            | peer::PeerEvent::Unauthorized { .. }
            | peer::PeerEvent::DeliveryUnknown { .. } => {}
        }
    }
    assert!(
        rejected,
        "unauthorized pending message must not be marked delivered"
    );
}

fn run_two_processes(mode: &str) {
    let executable = std::env::current_exe().expect("test binary path should be available");
    let mut listener_command = Command::new(&executable);
    listener_command
        .args(["--exact", "peer_process_worker", "--nocapture"])
        .env("SLOUCHING_PEER_WORKER", "listen")
        .env("SLOUCHING_PEER_MODE", mode)
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit());
    let mut listener = listener_command
        .spawn()
        .expect("listener child process should start");
    let stdout = listener
        .stdout
        .take()
        .expect("listener stdout should be piped");
    let (ready_tx, ready_rx) = std_mpsc::channel();
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
        .env("SLOUCHING_PEER_MODE", mode)
        .env("SLOUCHING_PEER_ADDRESS", address)
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit());
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
