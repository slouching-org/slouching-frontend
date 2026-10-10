//! HTTP client for the optional Elixir SPAKE2 rendezvous helper.

use crate::{
    pairing_spake2::{ContactIdentityProof, PairingCode, PairingExchange},
    storage,
};
use base64::{Engine, engine::general_purpose::STANDARD as BASE64};
use serde::Deserialize;
use std::{net::IpAddr, time::Duration};
use tokio::time::{Instant, sleep};

const SESSION_TTL: Duration = Duration::from_secs(120);
const SESSION_DEADLINE: Duration = Duration::from_secs(110);
const POLL_INTERVAL: Duration = Duration::from_millis(300);
const MAX_RESPONSE_BYTES: usize = 2048;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PairingRole {
    Inviter,
    Invitee,
}

impl PairingRole {
    fn as_str(self) -> &'static str {
        match self {
            Self::Inviter => "inviter",
            Self::Invitee => "invitee",
        }
    }
}

#[derive(Debug, Deserialize)]
struct CreatedSession {
    session_id: String,
    expires_in_seconds: u64,
    attempts_per_session: u8,
}

#[derive(Debug, Deserialize)]
struct EncodedMessage {
    message: String,
}

pub async fn create_session(helper_url: &str) -> Result<String, String> {
    let base = helper_base(helper_url)?;
    let response = client()?
        .post(format!("{base}/api/pairing-sessions"))
        .send()
        .await
        .map_err(|error| format!("could not create pairing session: {error}"))?;
    let bytes = response_bytes(response, "could not create pairing session").await?;
    let created: CreatedSession = serde_json::from_slice(&bytes)
        .map_err(|_| "pairing helper returned an invalid session response".to_owned())?;
    if created.session_id.len() != 64
        || !created
            .session_id
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
        || created.expires_in_seconds == 0
        || created.expires_in_seconds > SESSION_TTL.as_secs()
        || created.attempts_per_session != 1
    {
        return Err("pairing helper returned an unsupported session contract".to_owned());
    }
    Ok(created.session_id)
}

pub async fn delete_session(helper_url: &str, session_id: &str) -> Result<(), String> {
    let base = helper_base(helper_url)?;
    validate_session_id(session_id)?;
    let response = client()?
        .delete(format!("{base}/api/pairing-sessions"))
        .bearer_auth(session_id)
        .send()
        .await
        .map_err(|error| format!("could not cancel pairing session: {error}"))?;
    if response.status().as_u16() != 204 {
        return Err(response_error(response, "could not cancel pairing session").await);
    }
    Ok(())
}

pub async fn run_pairing(
    helper_url: &str,
    session_id: &str,
    code_text: &str,
    role: PairingRole,
    local_device_key: [u8; 32],
) -> Result<[u8; 32], String> {
    let base = helper_base(helper_url)?;
    validate_session_id(session_id)?;
    let code = PairingCode::parse(code_text)?;
    let client = client()?;
    let deadline = Instant::now() + SESSION_DEADLINE;

    let exchange = PairingExchange::start(&code);
    post_message(
        &client,
        &base,
        session_id,
        role,
        "spake2",
        exchange.outbound_message(),
    )
    .await?;
    let remote_spake =
        wait_for_message(&client, &base, session_id, role, "spake2", deadline).await?;
    let pending = exchange.finish(&remote_spake)?;

    let local_confirmation = pending.confirmation_tag();
    post_message(
        &client,
        &base,
        session_id,
        role,
        "confirm",
        &local_confirmation,
    )
    .await?;
    let remote_confirmation =
        wait_for_message(&client, &base, session_id, role, "confirm", deadline).await?;
    let confirmed = pending.confirm(&remote_confirmation)?;

    let transcript_hash = confirmed.transcript_hash();
    let (proof_key, proof_signature) =
        tokio::task::spawn_blocking(move || storage::sign_contact_identity_proof(&transcript_hash))
            .await
            .map_err(|error| format!("device identity signing task failed: {error}"))??;
    if proof_key != local_device_key {
        return Err("saved device identity changed during pairing".to_owned());
    }
    let proof = ContactIdentityProof {
        device_key: proof_key,
        signature: proof_signature,
    };
    let encrypted_identity = confirmed.seal_identity_proof(&proof)?;
    post_message(
        &client,
        &base,
        session_id,
        role,
        "identity",
        &encrypted_identity,
    )
    .await?;
    let remote_identity =
        wait_for_message(&client, &base, session_id, role, "identity", deadline).await?;
    let remote_proof = confirmed.open_identity_proof(&remote_identity)?;
    if remote_proof.device_key == local_device_key {
        return Err("cannot pair this device with itself".to_owned());
    }
    Ok(remote_proof.device_key)
}

fn client() -> Result<reqwest::Client, String> {
    reqwest::Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
        .map_err(|error| format!("could not configure pairing HTTP client: {error}"))
}

fn helper_base(value: &str) -> Result<String, String> {
    let parsed = reqwest::Url::parse(value.trim())
        .map_err(|_| "enter a valid pairing helper URL".to_owned())?;
    if !matches!(parsed.scheme(), "http" | "https")
        || parsed.host_str().is_none()
        || parsed.username() != ""
        || parsed.password().is_some()
        || parsed.query().is_some()
        || parsed.fragment().is_some()
        || !matches!(parsed.path(), "" | "/")
    {
        return Err(
            "pairing helper URL must be an HTTP(S) origin without credentials or path".to_owned(),
        );
    }
    if parsed.scheme() == "http" && !is_loopback_host(parsed.host_str().unwrap_or_default()) {
        return Err("remote pairing helpers must use HTTPS".to_owned());
    }
    Ok(parsed.as_str().trim_end_matches('/').to_owned())
}

fn is_loopback_host(host: &str) -> bool {
    if host.eq_ignore_ascii_case("localhost") {
        return true;
    }
    host.trim_start_matches('[')
        .trim_end_matches(']')
        .parse::<IpAddr>()
        .is_ok_and(|address| address.is_loopback())
}

fn validate_session_id(session_id: &str) -> Result<(), String> {
    if session_id.len() == 64
        && session_id
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        Ok(())
    } else {
        Err("pairing session ID must be 64 lowercase hexadecimal characters".to_owned())
    }
}

async fn post_message(
    client: &reqwest::Client,
    base: &str,
    session_id: &str,
    role: PairingRole,
    stage: &str,
    message: &[u8],
) -> Result<(), String> {
    let response = client
        .post(format!(
            "{base}/api/pairing-sessions/{}/{stage}",
            role.as_str()
        ))
        .bearer_auth(session_id)
        .json(&serde_json::json!({ "message": BASE64.encode(message) }))
        .send()
        .await
        .map_err(|error| format!("could not send pairing {stage} message: {error}"))?;
    if response.status().as_u16() != 204 {
        return Err(
            response_error(response, &format!("pairing {stage} message was rejected")).await,
        );
    }
    Ok(())
}

async fn wait_for_message(
    client: &reqwest::Client,
    base: &str,
    session_id: &str,
    role: PairingRole,
    stage: &str,
    deadline: Instant,
) -> Result<Vec<u8>, String> {
    let local_role = role.as_str();
    loop {
        if Instant::now() >= deadline {
            return Err("pairing session expired while waiting for the other device".to_owned());
        }
        let response = client
            .get(format!("{base}/api/pairing-sessions/{local_role}/{stage}"))
            .bearer_auth(session_id)
            .send()
            .await
            .map_err(|error| format!("could not poll pairing {stage} message: {error}"))?;
        match response.status().as_u16() {
            202 => {
                let _ =
                    response_bytes(response, "pairing helper returned an invalid response").await?;
                sleep(POLL_INTERVAL).await;
            }
            200 => {
                let bytes =
                    response_bytes(response, "pairing helper returned an invalid response").await?;
                let encoded: EncodedMessage = serde_json::from_slice(&bytes)
                    .map_err(|_| "pairing helper returned an invalid message".to_owned())?;
                return BASE64
                    .decode(encoded.message)
                    .map_err(|_| "pairing helper returned malformed message encoding".to_owned());
            }
            _ => {
                return Err(
                    response_error(response, "pairing helper session is unavailable").await,
                );
            }
        }
    }
}

async fn response_bytes(response: reqwest::Response, context: &str) -> Result<Vec<u8>, String> {
    if response
        .content_length()
        .is_some_and(|length| length > MAX_RESPONSE_BYTES as u64)
    {
        return Err(format!("{context}: response exceeds the size limit"));
    }
    let bytes = response
        .bytes()
        .await
        .map_err(|error| format!("{context}: {error}"))?;
    if bytes.len() > MAX_RESPONSE_BYTES {
        return Err(format!("{context}: response exceeds the size limit"));
    }
    Ok(bytes.to_vec())
}

async fn response_error(response: reqwest::Response, context: &str) -> String {
    let status = response.status();
    let message = response_bytes(response, context)
        .await
        .ok()
        .and_then(|bytes| serde_json::from_slice::<serde_json::Value>(&bytes).ok())
        .and_then(|json| json.get("message")?.as_str().map(str::to_owned));
    message.unwrap_or_else(|| format!("{context} (HTTP {status})"))
}
