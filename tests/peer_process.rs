#[path = "../src/blob_store.rs"]
mod blob_store;
#[path = "../src/file_transfer.rs"]
mod file_transfer;
#[path = "../src/identity.rs"]
mod identity;
#[allow(dead_code)]
#[path = "../src/peer.rs"]
mod peer;
#[allow(dead_code)]
#[path = "../src/storage.rs"]
mod storage;

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
    let peer_role = role.to_owned();
    let mut events = Box::pin(session.run(command_rx));
    let event_pump = tokio::spawn(async move {
        while let Some(event) = events.next().await {
            if peer_role == "listener"
                && matches!(&event, peer::PeerEvent::MlsCommitRequested { .. })
            {
                ack_commands
                    .send(peer::PeerCommand::SendMlsCommit {
                        request_id: 104,
                        commit: mls_commit_for("listener", 104),
                    })
                    .await
                    .expect("committer response should enter the active session");
            }
            let inbound_action = match &event {
                peer::PeerEvent::Received { sequence, text } if text != UNACKNOWLEDGED_TEXT => {
                    Some((*sequence, None))
                }
                peer::PeerEvent::MlsEventReceived { sequence, event }
                    if event.event_id[0] != 0xfe =>
                {
                    Some((*sequence, None))
                }
                peer::PeerEvent::MlsCommitReceived { sequence, commit }
                    if commit.event_id[0] == 103 =>
                {
                    Some((*sequence, Some("rejected by process test")))
                }
                peer::PeerEvent::MlsCommitReceived { sequence, commit }
                    if commit.event_id[0] != 0xfe =>
                {
                    Some((*sequence, None))
                }
                peer::PeerEvent::MlsProposalReceived {
                    sequence, proposal, ..
                } if proposal.event_id[0] != 0xfe => Some((*sequence, None)),
                peer::PeerEvent::MlsKeyPackageReceived {
                    sequence,
                    key_package,
                    ..
                } if key_package.event_id[0] != 0xfe => Some((*sequence, None)),
                peer::PeerEvent::MlsWelcomeReceived {
                    sequence, welcome, ..
                } if welcome.event_id[0] != 0xfe => Some((*sequence, None)),
                _ => None,
            };
            if let Some((sequence, rejection)) = inbound_action {
                let command = match rejection {
                    Some(reason) => peer::PeerCommand::RejectInbound {
                        sequence,
                        reason: reason.to_owned(),
                    },
                    None => peer::PeerCommand::AcceptInbound { sequence },
                };
                ack_commands
                    .send(command)
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
    command_tx
        .send(peer::PeerCommand::SendMlsEvent {
            request_id: 100,
            event: mls_event_for(role, 100),
        })
        .await
        .expect("session should accept an opaque MLS event");
    command_tx
        .send(peer::PeerCommand::SendMlsCommit {
            request_id: 102,
            commit: mls_commit_for(role, 102),
        })
        .await
        .expect("session should accept an MLS Commit");
    command_tx
        .send(peer::PeerCommand::SendMlsCommit {
            request_id: 103,
            commit: mls_commit_for(role, 103),
        })
        .await
        .expect("session should accept a Commit the remote side rejects");
    command_tx
        .send(peer::PeerCommand::SendMlsProposal {
            request_id: 105,
            proposal: mls_proposal_for(role, 105),
        })
        .await
        .expect("session should accept an MLS proposal");
    command_tx
        .send(peer::PeerCommand::SendMlsKeyPackage {
            request_id: 107,
            key_package: mls_key_package_for(role, 107),
        })
        .await
        .expect("session should accept an MLS KeyPackage");
    command_tx
        .send(peer::PeerCommand::SendMlsWelcome {
            request_id: 108,
            welcome: mls_welcome_for(role, 108),
        })
        .await
        .expect("session should accept an MLS Welcome");
    if role == "sender" {
        command_tx
            .send(peer::PeerCommand::RequestMlsCommit {
                group_id: vec![0x91; 16],
                predecessor_epoch: 7,
            })
            .await
            .expect("session should accept a predecessor request");
    }
    let mut acknowledged = HashSet::new();
    let mut received = HashSet::new();
    let mut event_acknowledged = false;
    let mut event_received = false;
    let mut commit_acknowledged = false;
    let mut commit_received = false;
    let mut commit_rejected = false;
    let mut proposal_acknowledged = false;
    let mut proposal_received = false;
    let mut key_package_acknowledged = false;
    let mut key_package_received = false;
    let mut welcome_acknowledged = false;
    let mut welcome_received = false;
    let mut commit_request_received = role != "listener";
    let mut recovered_commit_received = role == "listener";
    let mut recovered_commit_acknowledged = role == "sender";
    while acknowledged.len() < MESSAGE_COUNT as usize
        || received.len() < MESSAGE_COUNT as usize
        || !event_acknowledged
        || !event_received
        || !commit_acknowledged
        || !commit_received
        || !commit_rejected
        || !proposal_acknowledged
        || !proposal_received
        || !key_package_acknowledged
        || !key_package_received
        || !welcome_acknowledged
        || !welcome_received
        || !commit_request_received
        || !recovered_commit_received
        || !recovered_commit_acknowledged
    {
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
            peer::PeerEvent::MlsEventAcknowledged { request_id } => {
                assert_eq!(request_id, 100);
                assert!(!event_acknowledged, "duplicate MLS event ACK");
                event_acknowledged = true;
            }
            peer::PeerEvent::MlsCommitAcknowledged { request_id } => {
                if request_id == 104 {
                    assert_eq!(role, "listener");
                    recovered_commit_acknowledged = true;
                } else {
                    assert_eq!(request_id, 102);
                    assert!(!commit_acknowledged, "duplicate MLS Commit ACK");
                    commit_acknowledged = true;
                }
            }
            peer::PeerEvent::MlsCommitRejected { request_id, reason } => {
                assert_eq!(request_id, 103);
                assert_eq!(reason, "rejected by process test");
                assert!(!commit_rejected, "duplicate MLS Commit rejection");
                commit_rejected = true;
            }
            peer::PeerEvent::MlsProposalAcknowledged { request_id } => {
                assert_eq!(request_id, 105);
                assert!(!proposal_acknowledged, "duplicate MLS proposal ACK");
                proposal_acknowledged = true;
            }
            peer::PeerEvent::MlsKeyPackageAcknowledged { request_id } => {
                assert_eq!(request_id, 107);
                assert!(!key_package_acknowledged, "duplicate MLS KeyPackage ACK");
                key_package_acknowledged = true;
            }
            peer::PeerEvent::MlsWelcomeAcknowledged { request_id } => {
                assert_eq!(request_id, 108);
                assert!(!welcome_acknowledged, "duplicate MLS Welcome ACK");
                welcome_acknowledged = true;
            }
            peer::PeerEvent::DelegatedMlsCopyAcknowledged { .. }
            | peer::PeerEvent::DelegatedMlsCopyRejected { .. }
            | peer::PeerEvent::DelegatedMlsCopyDeliveryUnknown { .. }
            | peer::PeerEvent::DelegatedMlsCopyReceived { .. }
            | peer::PeerEvent::DelegatedMlsCopiesRequested { .. }
            | peer::PeerEvent::AttachmentBlobSent { .. }
            | peer::PeerEvent::AttachmentBlobReceived { .. } => {}
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
            peer::PeerEvent::MlsEventReceived { sequence, event } => {
                let expected_role = if role == "listener" {
                    "sender"
                } else {
                    "listener"
                };
                assert_eq!(event, mls_event_for(expected_role, 100));
                assert!(received.insert(sequence), "duplicate receive sequence");
                event_received = true;
            }
            peer::PeerEvent::MlsCommitReceived { sequence, commit } => {
                let expected_role = if role == "listener" {
                    "sender"
                } else {
                    "listener"
                };
                if commit.event_id[0] == 103 {
                    assert_eq!(commit, mls_commit_for(expected_role, 103));
                    assert!(received.insert(sequence), "duplicate receive sequence");
                    continue;
                }
                if commit.event_id[0] == 104 {
                    assert_eq!(role, "sender");
                    assert_eq!(commit, mls_commit_for("listener", 104));
                    assert!(received.insert(sequence), "duplicate recovered Commit");
                    recovered_commit_received = true;
                    continue;
                }
                assert_eq!(commit, mls_commit_for(expected_role, 102));
                assert!(received.insert(sequence), "duplicate receive sequence");
                commit_received = true;
            }
            peer::PeerEvent::MlsProposalReceived {
                sequence, proposal, ..
            } => {
                let expected_role = if role == "listener" {
                    "sender"
                } else {
                    "listener"
                };
                assert_eq!(proposal, mls_proposal_for(expected_role, 105));
                assert!(
                    received.insert(sequence),
                    "duplicate proposal receive sequence"
                );
                proposal_received = true;
            }
            peer::PeerEvent::MlsKeyPackageReceived {
                sequence,
                key_package,
                ..
            } => {
                let expected_role = if role == "listener" {
                    "sender"
                } else {
                    "listener"
                };
                assert_eq!(key_package, mls_key_package_for(expected_role, 107));
                assert!(
                    received.insert(sequence),
                    "duplicate KeyPackage receive sequence"
                );
                key_package_received = true;
            }
            peer::PeerEvent::MlsWelcomeReceived {
                sequence,
                peer_id,
                welcome,
            } => {
                let expected_role = if role == "listener" {
                    "sender"
                } else {
                    "listener"
                };
                assert_eq!(welcome, mls_welcome_for(expected_role, 108));
                assert_eq!(
                    *peer_id.as_bytes(),
                    SigningKey::from_bytes(if expected_role == "sender" {
                        &SENDER_SEED
                    } else {
                        &LISTENER_SEED
                    })
                    .verifying_key()
                    .to_bytes()
                );
                assert!(
                    received.insert(sequence),
                    "duplicate Welcome receive sequence"
                );
                welcome_received = true;
            }
            peer::PeerEvent::MlsKeyPackageRejected { request_id, reason } => {
                panic!("KeyPackage {request_id} was unexpectedly rejected: {reason}")
            }
            peer::PeerEvent::MlsKeyPackageDeliveryUnknown { request_id } => {
                panic!("KeyPackage {request_id} unexpectedly became unknown before disconnect")
            }
            peer::PeerEvent::MlsWelcomeRejected { request_id, reason } => {
                panic!("Welcome {request_id} was unexpectedly rejected: {reason}")
            }
            peer::PeerEvent::MlsWelcomeDeliveryUnknown { request_id } => {
                panic!("Welcome {request_id} unexpectedly became unknown before disconnect")
            }
            peer::PeerEvent::MlsProposalRejected { request_id, reason } => {
                panic!("proposal {request_id} was unexpectedly rejected: {reason}")
            }
            peer::PeerEvent::MlsProposalDeliveryUnknown { request_id } => {
                panic!("proposal {request_id} unexpectedly became unknown before disconnect")
            }
            peer::PeerEvent::MlsCommitRequested {
                group_id,
                predecessor_epoch,
                ..
            } => {
                assert_eq!(role, "listener");
                assert_eq!(group_id, vec![0x91; 16]);
                assert_eq!(predecessor_epoch, 7);
                assert!(!commit_request_received, "duplicate predecessor request");
                commit_request_received = true;
            }
            peer::PeerEvent::Rejected { reason, .. } => {
                panic!("message was unexpectedly rejected: {reason}")
            }
            peer::PeerEvent::MlsEventRejected { reason, .. } => {
                panic!("MLS event was unexpectedly rejected: {reason}")
            }
            peer::PeerEvent::DeliveryUnknown { .. } | peer::PeerEvent::Unauthorized { .. } => {
                panic!("session failed before completing the expected messages")
            }
            peer::PeerEvent::MlsEventDeliveryUnknown { .. } => {
                panic!("MLS event delivery unexpectedly became unknown")
            }
            peer::PeerEvent::MlsCommitDeliveryUnknown { .. } => {
                panic!("MLS Commit delivery unexpectedly became unknown")
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
            .send(peer::PeerCommand::SendMlsEvent {
                request_id: 101,
                event: mls_event_for(role, 101),
            })
            .await
            .expect("session should accept a pending MLS event");
        command_tx
            .send(peer::PeerCommand::SendMlsCommit {
                request_id: 103,
                commit: mls_commit_for(role, 0xfe),
            })
            .await
            .expect("session should accept a pending MLS Commit");
        command_tx
            .send(peer::PeerCommand::SendMlsProposal {
                request_id: 106,
                proposal: mls_proposal_for(role, 0xfe),
            })
            .await
            .expect("session should accept a pending MLS proposal");
        command_tx
            .send(peer::PeerCommand::Disconnect)
            .await
            .expect("session should accept explicit disconnect");
        let mut got_unknown = false;
        let mut got_mls_unknown = false;
        let mut got_mls_commit_unknown = false;
        let mut got_mls_proposal_unknown = false;
        let mut got_disconnected = false;
        while !got_unknown
            || !got_mls_unknown
            || !got_mls_commit_unknown
            || !got_mls_proposal_unknown
            || !got_disconnected
        {
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
                peer::PeerEvent::MlsEventDeliveryUnknown { request_id } => {
                    assert_eq!(request_id, 101);
                    got_mls_unknown = true;
                }
                peer::PeerEvent::MlsCommitDeliveryUnknown { request_id } => {
                    assert_eq!(request_id, 103);
                    got_mls_commit_unknown = true;
                }
                peer::PeerEvent::MlsProposalDeliveryUnknown { request_id } => {
                    assert_eq!(request_id, 106);
                    got_mls_proposal_unknown = true;
                }
                peer::PeerEvent::Received { text, .. } => {
                    assert_ne!(text, UNACKNOWLEDGED_TEXT);
                }
                peer::PeerEvent::Connected { .. }
                | peer::PeerEvent::Acknowledged { .. }
                | peer::PeerEvent::MlsEventAcknowledged { .. }
                | peer::PeerEvent::MlsEventRejected { .. }
                | peer::PeerEvent::MlsEventReceived { .. }
                | peer::PeerEvent::MlsCommitAcknowledged { .. }
                | peer::PeerEvent::MlsCommitRejected { .. }
                | peer::PeerEvent::MlsCommitReceived { .. }
                | peer::PeerEvent::MlsCommitRequested { .. }
                | peer::PeerEvent::MlsProposalReceived { .. }
                | peer::PeerEvent::MlsProposalAcknowledged { .. }
                | peer::PeerEvent::MlsProposalRejected { .. }
                | peer::PeerEvent::MlsKeyPackageReceived { .. }
                | peer::PeerEvent::MlsKeyPackageAcknowledged { .. }
                | peer::PeerEvent::MlsKeyPackageRejected { .. }
                | peer::PeerEvent::MlsKeyPackageDeliveryUnknown { .. }
                | peer::PeerEvent::MlsWelcomeReceived { .. }
                | peer::PeerEvent::MlsWelcomeAcknowledged { .. }
                | peer::PeerEvent::MlsWelcomeRejected { .. }
                | peer::PeerEvent::MlsWelcomeDeliveryUnknown { .. }
                | peer::PeerEvent::DelegatedMlsCopyAcknowledged { .. }
                | peer::PeerEvent::DelegatedMlsCopyRejected { .. }
                | peer::PeerEvent::DelegatedMlsCopyDeliveryUnknown { .. }
                | peer::PeerEvent::DelegatedMlsCopyReceived { .. }
                | peer::PeerEvent::DelegatedMlsCopiesRequested { .. }
                | peer::PeerEvent::AttachmentBlobSent { .. }
                | peer::PeerEvent::AttachmentBlobReceived { .. } => {}
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
                | peer::PeerEvent::Acknowledged { .. }
                | peer::PeerEvent::MlsEventAcknowledged { .. }
                | peer::PeerEvent::MlsCommitRequested { .. }
                | peer::PeerEvent::MlsProposalAcknowledged { .. }
                | peer::PeerEvent::MlsKeyPackageReceived { .. }
                | peer::PeerEvent::MlsKeyPackageAcknowledged { .. }
                | peer::PeerEvent::MlsKeyPackageRejected { .. }
                | peer::PeerEvent::MlsKeyPackageDeliveryUnknown { .. }
                | peer::PeerEvent::MlsWelcomeReceived { .. }
                | peer::PeerEvent::MlsWelcomeAcknowledged { .. }
                | peer::PeerEvent::MlsWelcomeRejected { .. }
                | peer::PeerEvent::MlsWelcomeDeliveryUnknown { .. }
                | peer::PeerEvent::DelegatedMlsCopyAcknowledged { .. }
                | peer::PeerEvent::DelegatedMlsCopyRejected { .. }
                | peer::PeerEvent::DelegatedMlsCopyDeliveryUnknown { .. }
                | peer::PeerEvent::DelegatedMlsCopyReceived { .. }
                | peer::PeerEvent::DelegatedMlsCopiesRequested { .. }
                | peer::PeerEvent::AttachmentBlobSent { .. }
                | peer::PeerEvent::AttachmentBlobReceived { .. } => {}
                peer::PeerEvent::MlsEventReceived { event, .. } if event.event_id[0] == 0xfe => {
                    got_unacknowledged = true;
                }
                peer::PeerEvent::MlsEventReceived { .. } => {}
                peer::PeerEvent::MlsCommitReceived { commit, .. } if commit.event_id[0] == 0xfe => {
                    got_unacknowledged = true;
                }
                peer::PeerEvent::MlsCommitReceived { .. } => {}
                peer::PeerEvent::MlsProposalReceived { .. }
                | peer::PeerEvent::MlsProposalRejected { .. }
                | peer::PeerEvent::MlsProposalDeliveryUnknown { .. } => {}
                peer::PeerEvent::DeliveryUnknown { .. }
                | peer::PeerEvent::MlsEventDeliveryUnknown { .. }
                | peer::PeerEvent::MlsCommitDeliveryUnknown { .. }
                | peer::PeerEvent::Rejected { .. }
                | peer::PeerEvent::MlsEventRejected { .. }
                | peer::PeerEvent::MlsCommitRejected { .. }
                | peer::PeerEvent::MlsCommitAcknowledged { .. }
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

fn mls_event_for(role: &str, id: u8) -> peer::MlsEventEnvelope {
    let seed = if role == "sender" {
        SENDER_SEED
    } else {
        LISTENER_SEED
    };
    let event_id = if id == 101 { [0xfe; 16] } else { [id; 16] };
    peer::MlsEventEnvelope {
        event_id,
        author_device: SigningKey::from_bytes(&seed).verifying_key().to_bytes(),
        group_id: [0x44; 16].to_vec(),
        epoch: 3,
        checkpoint: Some(vec![0x45, id]),
        expires_at_unix: 2_000_000_000,
        ciphertext: format!("opaque MLS bytes {role} {id}").into_bytes(),
    }
}

fn mls_commit_for(role: &str, id: u8) -> peer::MlsCommitEnvelope {
    let author_device = if role == "sender" {
        [0x31; 32]
    } else {
        [0x32; 32]
    };
    peer::MlsCommitEnvelope {
        event_id: [id; 16],
        author_device,
        group_id: [0x33; 16].to_vec(),
        predecessor_epoch: 0,
        epoch: 1,
        commit: vec![id; 48],
    }
}

fn mls_proposal_for(role: &str, id: u8) -> peer::MlsProposalEnvelope {
    let seed = if role == "sender" {
        SENDER_SEED
    } else {
        LISTENER_SEED
    };
    let proposal = format!("signed MLS proposal bytes {role} {id}").into_bytes();
    let digest = blake3::hash(&proposal);
    let mut event_id = [0; 16];
    event_id.copy_from_slice(&digest.as_bytes()[..16]);
    if id == 0xfe {
        event_id[0] = 0xfe;
        let mut proposal = proposal;
        // Keep the transport's content-derived event ID valid for the pending case.
        loop {
            let digest = blake3::hash(&proposal);
            event_id.copy_from_slice(&digest.as_bytes()[..16]);
            if event_id[0] == 0xfe {
                break;
            }
            proposal.push(0);
        }
        return peer::MlsProposalEnvelope {
            event_id,
            author_device: SigningKey::from_bytes(&seed).verifying_key().to_bytes(),
            group_id: [0x34; 16].to_vec(),
            epoch: 4,
            proposal,
        };
    }
    peer::MlsProposalEnvelope {
        event_id,
        author_device: SigningKey::from_bytes(&seed).verifying_key().to_bytes(),
        group_id: [0x34; 16].to_vec(),
        epoch: 4,
        proposal,
    }
}

fn mls_key_package_for(role: &str, id: u8) -> peer::MlsKeyPackageEnvelope {
    let seed = if role == "sender" {
        SENDER_SEED
    } else {
        LISTENER_SEED
    };
    let key_package = format!("public MLS KeyPackage bytes {role} {id}").into_bytes();
    let digest = blake3::hash(&key_package);
    let mut event_id = [0; 16];
    event_id.copy_from_slice(&digest.as_bytes()[..16]);
    peer::MlsKeyPackageEnvelope {
        event_id,
        invitee_device: SigningKey::from_bytes(&seed).verifying_key().to_bytes(),
        group_id: [0x35; 16].to_vec(),
        key_package,
    }
}

fn mls_welcome_for(role: &str, id: u8) -> peer::MlsWelcomeEnvelope {
    let seed = if role == "sender" {
        SENDER_SEED
    } else {
        LISTENER_SEED
    };
    let welcome = format!("serialized MLS Welcome {role} {id}").into_bytes();
    let ratchet_tree = format!("serialized MLS tree {role} {id}").into_bytes();
    let mut digest = blake3::Hasher::new();
    digest.update(&(welcome.len() as u32).to_be_bytes());
    digest.update(&welcome);
    digest.update(&(ratchet_tree.len() as u32).to_be_bytes());
    digest.update(&ratchet_tree);
    let mut event_id = [0; 16];
    event_id.copy_from_slice(&digest.finalize().as_bytes()[..16]);
    peer::MlsWelcomeEnvelope {
        event_id,
        invitee_device: SigningKey::from_bytes(&seed).verifying_key().to_bytes(),
        group_id: [0x36; 16].to_vec(),
        welcome,
        ratchet_tree,
    }
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
            peer::PeerEvent::MlsEventReceived { .. }
            | peer::PeerEvent::MlsEventAcknowledged { .. }
            | peer::PeerEvent::MlsCommitReceived { .. }
            | peer::PeerEvent::MlsCommitAcknowledged { .. }
            | peer::PeerEvent::MlsProposalReceived { .. }
            | peer::PeerEvent::MlsProposalAcknowledged { .. }
            | peer::PeerEvent::MlsKeyPackageReceived { .. }
            | peer::PeerEvent::MlsKeyPackageAcknowledged { .. }
            | peer::PeerEvent::MlsWelcomeReceived { .. }
            | peer::PeerEvent::MlsWelcomeAcknowledged { .. } => {
                panic!("wrong pinned device exchanged an MLS event")
            }
            peer::PeerEvent::DelegatedMlsCopyReceived { .. }
            | peer::PeerEvent::DelegatedMlsCopiesRequested { .. }
            | peer::PeerEvent::DelegatedMlsCopyAcknowledged { .. }
            | peer::PeerEvent::DelegatedMlsCopyRejected { .. }
            | peer::PeerEvent::DelegatedMlsCopyDeliveryUnknown { .. } => {
                panic!("wrong pinned device exchanged a delegated MLS copy")
            }
            peer::PeerEvent::MlsEventRejected { .. }
            | peer::PeerEvent::MlsCommitRejected { .. }
            | peer::PeerEvent::MlsProposalRejected { .. }
            | peer::PeerEvent::MlsKeyPackageRejected { .. } => {
                panic!("wrong pinned device exchanged an MLS event")
            }
            peer::PeerEvent::Disconnected { .. } => break,
            peer::PeerEvent::Connected { .. }
            | peer::PeerEvent::Rejected { .. }
            | peer::PeerEvent::Unauthorized { .. }
            | peer::PeerEvent::DeliveryUnknown { .. }
            | peer::PeerEvent::AttachmentBlobSent { .. }
            | peer::PeerEvent::AttachmentBlobReceived { .. } => {}
            peer::PeerEvent::MlsEventDeliveryUnknown { .. } => {}
            peer::PeerEvent::MlsCommitDeliveryUnknown { .. } => {}
            peer::PeerEvent::MlsProposalDeliveryUnknown { .. } => {}
            peer::PeerEvent::MlsKeyPackageDeliveryUnknown { .. } => {}
            peer::PeerEvent::MlsWelcomeRejected { .. }
            | peer::PeerEvent::MlsWelcomeDeliveryUnknown { .. } => {}
            peer::PeerEvent::MlsCommitRequested { .. } => {}
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
