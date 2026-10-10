//! Client for the optional Elixir HTTP ciphertext mailbox.

use base64::Engine as _;
use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};
use url::Url;

const MAX_COPY_BYTES: usize = 96 * 1024;
const MAX_PAGE_SIZE: usize = 16;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MailboxCopy {
    pub event_id: [u8; 16],
    pub expires_at_unix: i64,
    pub payload: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MailboxPage {
    pub copies: Vec<MailboxCopy>,
    pub next_after_id: Option<i64>,
}

#[derive(Serialize)]
struct UploadBody {
    copy: String,
}

#[derive(Deserialize)]
struct UploadResponse {
    status: String,
}

#[derive(Deserialize)]
struct ListResponse {
    copies: Vec<ListCopy>,
    next_after_id: Option<i64>,
}

#[derive(Deserialize)]
struct ListCopy {
    event_id: String,
    expires_at_unix: i64,
    copy: String,
}

pub fn validate_helper_url(value: &str) -> Result<Url, String> {
    let url = Url::parse(value.trim()).map_err(|error| format!("invalid mailbox URL: {error}"))?;
    if !matches!(url.scheme(), "https" | "http")
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
        || url.path() != "/"
    {
        return Err(
            "mailbox URL must be an HTTPS (or loopback HTTP) origin without credentials or path"
                .into(),
        );
    }
    if url.scheme() == "http" {
        let local = match url.host() {
            Some(url::Host::Ipv4(address)) => address.is_loopback(),
            Some(url::Host::Ipv6(address)) => address.is_loopback(),
            Some(url::Host::Domain(host)) => host == "localhost",
            None => false,
        };
        if !local {
            return Err("remote mailbox URLs must use HTTPS".into());
        }
    }
    Ok(url)
}

pub fn encode_copy(
    grant: &crate::storage::DelegatedMlsCopyGrant,
    event: &crate::storage::EncryptedEvent,
) -> Result<Vec<u8>, String> {
    let peer_grant = crate::peer::DelegatedMlsCopyGrant {
        event_id: grant.event_id,
        author_device: grant.author_device,
        recipient_device: grant.recipient_device,
        group_id: grant.group_id,
        epoch: grant.epoch,
        expires_at_unix: grant.expires_at_unix,
        checkpoint: grant.checkpoint.clone(),
        ciphertext_digest: grant.ciphertext_digest,
        signature: grant.signature,
    };
    let peer_event = crate::peer::MlsEventEnvelope {
        event_id: event.event_id,
        author_device: event.author_device,
        group_id: event.group_id.clone(),
        epoch: event.epoch,
        checkpoint: event.checkpoint.clone(),
        expires_at_unix: event.expires_at_unix,
        ciphertext: event.ciphertext.clone(),
    };
    crate::peer::encode_delegated_mls_copy(&peer_grant, &peer_event)
}

pub fn decode_copy(
    payload: &[u8],
) -> Result<
    (
        crate::storage::DelegatedMlsCopyGrant,
        crate::storage::EncryptedEvent,
    ),
    String,
> {
    let (grant, event) = crate::peer::decode_delegated_mls_copy(payload)?;
    Ok((
        crate::storage::DelegatedMlsCopyGrant {
            event_id: grant.event_id,
            author_device: grant.author_device,
            recipient_device: grant.recipient_device,
            group_id: grant.group_id,
            epoch: grant.epoch,
            expires_at_unix: grant.expires_at_unix,
            checkpoint: grant.checkpoint,
            ciphertext_digest: grant.ciphertext_digest,
            signature: grant.signature,
        },
        crate::storage::EncryptedEvent {
            event_id: event.event_id,
            author_device: event.author_device,
            group_id: event.group_id,
            epoch: event.epoch,
            checkpoint: event.checkpoint,
            expires_at_unix: event.expires_at_unix,
            ciphertext: event.ciphertext,
        },
    ))
}

pub async fn upload_copy(helper_url: &str, payload: &[u8]) -> Result<bool, String> {
    if payload.is_empty() || payload.len() > MAX_COPY_BYTES {
        return Err("mailbox copy is empty or exceeds 96 KiB".into());
    }
    let endpoint = endpoint(helper_url, "/api/delivery/copies")?;
    let client = client()?;
    let body = UploadBody {
        copy: base64::engine::general_purpose::STANDARD.encode(payload),
    };
    let response = client
        .post(endpoint)
        .json(&body)
        .send()
        .await
        .map_err(|error| format!("mailbox upload failed: {error}"))?;
    if response.status() == reqwest::StatusCode::CREATED {
        let result: UploadResponse = response
            .json()
            .await
            .map_err(|error| format!("mailbox upload response was invalid: {error}"))?;
        return match result.status.as_str() {
            "stored" => Ok(false),
            "already_stored" => Ok(true),
            _ => Err("mailbox returned an unknown upload result".into()),
        };
    }
    Err(read_api_error(response, "mailbox upload").await)
}

pub async fn list_copies(
    helper_url: &str,
    after_id: i64,
    limit: usize,
) -> Result<MailboxPage, String> {
    list_copies_with_signer(
        helper_url,
        after_id,
        limit,
        crate::storage::sign_delivery_http_request,
    )
    .await
}

async fn list_copies_with_signer<F>(
    helper_url: &str,
    after_id: i64,
    limit: usize,
    signer: F,
) -> Result<MailboxPage, String>
where
    F: FnOnce(&str, &str, &str, &[u8; 32], &[u8]) -> Result<([u8; 32], [u8; 64]), String>,
{
    if after_id < 0 || limit == 0 {
        return Err("mailbox cursor or page size is invalid".into());
    }
    let limit = limit.min(MAX_PAGE_SIZE);
    let query = format!("after_id={after_id}&limit={limit}");
    let path = format!("/api/delivery/copies?{query}");
    let endpoint = endpoint(helper_url, &path)?;
    let request = signed_request_with(
        client()?,
        reqwest::Method::GET,
        &endpoint,
        &path,
        &[],
        signer,
    )?;
    let response = request
        .send()
        .await
        .map_err(|error| format!("mailbox list request failed: {error}"))?;
    if !response.status().is_success() {
        return Err(read_api_error(response, "mailbox list").await);
    }
    let result: ListResponse = response
        .json()
        .await
        .map_err(|error| format!("mailbox list response was invalid: {error}"))?;
    if result.copies.len() > limit {
        return Err("mailbox returned more copies than requested".into());
    }
    let copies = result
        .copies
        .into_iter()
        .map(|copy| {
            let event_id = hex::decode(&copy.event_id)
                .map_err(|_| "mailbox returned an invalid event ID".to_owned())?
                .try_into()
                .map_err(|_| "mailbox returned an invalid event ID length".to_owned())?;
            let payload = base64::engine::general_purpose::STANDARD
                .decode(copy.copy)
                .map_err(|_| "mailbox returned invalid base64 ciphertext".to_owned())?;
            if payload.is_empty() || payload.len() > MAX_COPY_BYTES {
                return Err("mailbox returned an empty or oversized copy".into());
            }
            Ok(MailboxCopy {
                event_id,
                expires_at_unix: copy.expires_at_unix,
                payload,
            })
        })
        .collect::<Result<Vec<_>, String>>()?;
    Ok(MailboxPage {
        copies,
        next_after_id: result.next_after_id,
    })
}

pub async fn acknowledge_copy(helper_url: &str, event_id: &[u8; 16]) -> Result<(), String> {
    acknowledge_copy_with_signer(
        helper_url,
        event_id,
        crate::storage::sign_delivery_http_request,
    )
    .await
}

async fn acknowledge_copy_with_signer<F>(
    helper_url: &str,
    event_id: &[u8; 16],
    signer: F,
) -> Result<(), String>
where
    F: FnOnce(&str, &str, &str, &[u8; 32], &[u8]) -> Result<([u8; 32], [u8; 64]), String>,
{
    let path = format!("/api/delivery/copies/{}/ack", hex::encode(event_id));
    let endpoint = endpoint(helper_url, &path)?;
    let request = signed_request_with(
        client()?,
        reqwest::Method::POST,
        &endpoint,
        &path,
        &[],
        signer,
    )?;
    let response = request
        .send()
        .await
        .map_err(|error| format!("mailbox ACK request failed: {error}"))?;
    if response.status() == reqwest::StatusCode::NO_CONTENT {
        Ok(())
    } else {
        Err(read_api_error(response, "mailbox ACK").await)
    }
}

fn endpoint(base: &str, path: &str) -> Result<Url, String> {
    let base = validate_helper_url(base)?;
    base.join(path)
        .map_err(|error| format!("invalid mailbox endpoint: {error}"))
}

fn client() -> Result<reqwest::Client, String> {
    reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(15))
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .map_err(|error| format!("could not create mailbox HTTP client: {error}"))
}

fn signed_request_with<F>(
    client: reqwest::Client,
    method: reqwest::Method,
    endpoint: &Url,
    path: &str,
    body: &[u8],
    signer: F,
) -> Result<reqwest::RequestBuilder, String>
where
    F: FnOnce(&str, &str, &str, &[u8; 32], &[u8]) -> Result<([u8; 32], [u8; 64]), String>,
{
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|error| format!("system clock is before Unix epoch: {error}"))?
        .as_secs()
        .to_string();
    let mut nonce = [0u8; 32];
    getrandom::fill(&mut nonce)
        .map_err(|error| format!("could not create request nonce: {error}"))?;
    let (device, signature) = signer(method.as_str(), path, &timestamp, &nonce, body)?;
    Ok(client
        .request(method, endpoint.clone())
        .header("x-slouching-device", hex::encode(device))
        .header("x-slouching-timestamp", timestamp)
        .header("x-slouching-nonce", hex::encode(nonce))
        .header("x-slouching-signature", hex::encode(signature)))
}

async fn read_api_error(response: reqwest::Response, operation: &str) -> String {
    let status = response.status();
    let body = response.text().await.unwrap_or_default();
    let detail = if body.len() > 2048 {
        "response body exceeded the diagnostic limit"
    } else {
        body.trim()
    };
    format!("{operation} failed with HTTP {status}: {detail}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;

    #[test]
    fn remote_mailbox_requires_https_but_loopback_http_is_available_for_development() {
        assert!(validate_helper_url("https://mailbox.crew.example").is_ok());
        assert!(validate_helper_url("http://127.0.0.1:3707").is_ok());
        assert!(validate_helper_url("http://localhost:3707").is_ok());
        assert!(validate_helper_url("http://mailbox.crew.example").is_err());
        assert!(validate_helper_url("https://user:pass@mailbox.crew.example").is_err());
        assert!(validate_helper_url("https://mailbox.crew.example/nested").is_err());
    }

    #[tokio::test]
    #[ignore = "requires a live Elixir mailbox; run scripts/smoke-delivery-mailbox-e2e.sh"]
    async fn signed_mailbox_client_round_trips_against_live_helper() {
        let helper_url = std::env::var("SLOUCHING_DELIVERY_MAILBOX_URL")
            .expect("the mailbox smoke script should provide the helper URL");
        let author = SigningKey::from_bytes(&[0x61; 32]);
        let recipient = SigningKey::from_bytes(&[0x62; 32]);
        let expires_at_unix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time should be after Unix epoch")
            .as_secs() as i64
            + 3_600;
        let event = crate::storage::EncryptedEvent {
            event_id: [0x63; 16],
            author_device: author.verifying_key().to_bytes(),
            group_id: vec![0x64; 16],
            epoch: 7,
            checkpoint: Some(vec![0x65; 8]),
            expires_at_unix,
            ciphertext: b"mailbox cross-repository ciphertext".to_vec(),
        };
        let grant = crate::storage::sign_delegated_mls_copy_grant_with_identity(
            &event,
            recipient.verifying_key().to_bytes(),
            &author,
        )
        .expect("the author should sign the recipient-bound event copy");
        let payload = encode_copy(&grant, &event).expect("copy envelope should encode");

        let mut tampered = payload.clone();
        let signature_offset = 154;
        tampered[signature_offset] ^= 1;
        assert!(upload_copy(&helper_url, &tampered).await.is_err());
        assert!(
            !upload_copy(&helper_url, &payload)
                .await
                .expect("Elixir should accept the signed copy")
        );
        assert!(
            upload_copy(&helper_url, &payload)
                .await
                .expect("identical upload should be idempotent")
        );

        let recipient_seed = [0x62; 32];
        let page = list_copies_with_signer(
            &helper_url,
            0,
            16,
            move |method, path, timestamp, nonce, body| {
                let identity = SigningKey::from_bytes(&recipient_seed);
                crate::storage::sign_delivery_http_request_with_identity(
                    &identity, method, path, timestamp, nonce, body,
                )
            },
        )
        .await
        .expect("the helper should authenticate and return a recipient page");
        assert_eq!(page.copies.len(), 1);
        assert_eq!(page.next_after_id, None);
        assert_eq!(page.copies[0].event_id, grant.event_id);
        assert_eq!(page.copies[0].expires_at_unix, grant.expires_at_unix);
        assert_eq!(
            decode_copy(&page.copies[0].payload).unwrap(),
            (grant.clone(), event)
        );

        let recipient_seed = [0x62; 32];
        acknowledge_copy_with_signer(
            &helper_url,
            &grant.event_id,
            move |method, path, timestamp, nonce, body| {
                let identity = SigningKey::from_bytes(&recipient_seed);
                crate::storage::sign_delivery_http_request_with_identity(
                    &identity, method, path, timestamp, nonce, body,
                )
            },
        )
        .await
        .expect("the authenticated helper ACK should remove the retained copy");

        let recipient_seed = [0x62; 32];
        let empty = list_copies_with_signer(
            &helper_url,
            0,
            16,
            move |method, path, timestamp, nonce, body| {
                let identity = SigningKey::from_bytes(&recipient_seed);
                crate::storage::sign_delivery_http_request_with_identity(
                    &identity, method, path, timestamp, nonce, body,
                )
            },
        )
        .await
        .expect("the helper should allow a fresh authenticated list request");
        assert!(empty.copies.is_empty());
    }
}
