use iroh::{Endpoint, EndpointAddr, EndpointId, RelayMode, SecretKey, endpoint::presets};
use std::{net::SocketAddr, time::Duration};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

pub const PEER_ALPN: &[u8] = b"org.slouching.text/1";
const FRAME_MAGIC: &[u8; 4] = b"SLTX";
const ACK_MAGIC: &[u8; 4] = b"SLAR";
const FINAL_MAGIC: &[u8; 4] = b"SLAF";
const FRAME_VERSION: u16 = 1;
const MAX_TEXT_BYTES: usize = 16 * 1024;

pub struct DirectPeerListener {
    endpoint: Endpoint,
    expected_peer: EndpointId,
}

impl DirectPeerListener {
    pub fn id(&self) -> EndpointId {
        self.endpoint.id()
    }

    pub fn direct_addresses(&self) -> Vec<SocketAddr> {
        self.endpoint.addr().ip_addrs().copied().collect()
    }

    pub async fn receive_once(self) -> Result<String, String> {
        let connecting = self
            .endpoint
            .accept()
            .await
            .ok_or_else(|| "peer endpoint closed before a connection arrived".to_owned())?;
        let connection = connecting
            .await
            .map_err(|error| format!("could not accept authenticated QUIC peer: {error}"))?;
        if connection.remote_id() != self.expected_peer {
            connection.close(1_u32.into(), b"unexpected device identity");
            return Err("incoming peer does not match the pinned device identity".to_owned());
        }
        let (mut send, mut receive) = connection
            .accept_bi()
            .await
            .map_err(|error| format!("could not accept peer text stream: {error}"))?;
        let text = read_text_frame(&mut receive).await?;
        write_text_frame(&mut send, &format!("received {} bytes", text.len())).await?;
        send.finish()
            .map_err(|error| format!("could not finish peer acknowledgement: {error}"))?;
        let mut receipt = tokio::time::timeout(Duration::from_secs(8), connection.accept_uni())
            .await
            .map_err(|_| "timed out waiting for sender to confirm the acknowledgement".to_owned())?
            .map_err(|error| format!("could not accept acknowledgement receipt: {error}"))?;
        read_ack_receipt(&mut receipt).await?;
        let mut final_ack = connection
            .open_uni()
            .await
            .map_err(|error| format!("could not open final acknowledgement stream: {error}"))?;
        final_ack
            .write_all(FINAL_MAGIC)
            .await
            .map_err(|error| format!("could not write final acknowledgement: {error}"))?;
        final_ack
            .write_all(&FRAME_VERSION.to_be_bytes())
            .await
            .map_err(|error| format!("could not write final acknowledgement version: {error}"))?;
        final_ack
            .finish()
            .map_err(|error| format!("could not finish final acknowledgement: {error}"))?;
        let stop_code = tokio::time::timeout(Duration::from_secs(8), final_ack.stopped())
            .await
            .map_err(|_| {
                "timed out waiting for sender to receive the final acknowledgement".to_owned()
            })?
            .map_err(|error| format!("sender stopped the final acknowledgement: {error}"))?;
        if let Some(code) = stop_code {
            return Err(format!(
                "sender stopped the final acknowledgement with code {code}"
            ));
        }
        Ok(text)
    }
}

pub async fn bind_listener(
    local_identity: SecretKey,
    bind_address: SocketAddr,
    expected_peer: EndpointId,
) -> Result<DirectPeerListener, String> {
    let endpoint = bind_endpoint(local_identity, bind_address).await?;
    Ok(DirectPeerListener {
        endpoint,
        expected_peer,
    })
}

pub async fn send_once(
    local_identity: SecretKey,
    expected_peer: EndpointId,
    peer_address: SocketAddr,
    text: &str,
) -> Result<String, String> {
    let endpoint = bind_endpoint(
        local_identity,
        "0.0.0.0:0".parse().expect("valid bind addr"),
    )
    .await?;
    let remote = EndpointAddr::new(expected_peer).with_ip_addr(peer_address);
    let connection = endpoint.connect(remote, PEER_ALPN);
    let connection = tokio::time::timeout(Duration::from_secs(8), connection)
        .await
        .map_err(|_| "timed out connecting to direct LAN peer".to_owned())?
        .map_err(|error| format!("could not connect to pinned LAN peer: {error}"))?;
    if connection.remote_id() != expected_peer {
        connection.close(1_u32.into(), b"unexpected device identity");
        return Err("connected peer does not match the pinned device identity".to_owned());
    }
    let (mut send, mut receive) = connection
        .open_bi()
        .await
        .map_err(|error| format!("could not open peer text stream: {error}"))?;
    write_text_frame(&mut send, text).await?;
    send.finish()
        .map_err(|error| format!("could not finish peer text stream: {error}"))?;
    let acknowledgement =
        tokio::time::timeout(Duration::from_secs(8), read_text_frame(&mut receive))
            .await
            .map_err(|_| "timed out waiting for peer acknowledgement".to_owned())??;
    let mut receipt = connection
        .open_uni()
        .await
        .map_err(|error| format!("could not open acknowledgement receipt stream: {error}"))?;
    receipt
        .write_all(ACK_MAGIC)
        .await
        .map_err(|error| format!("could not write acknowledgement receipt: {error}"))?;
    receipt
        .write_all(&FRAME_VERSION.to_be_bytes())
        .await
        .map_err(|error| format!("could not write acknowledgement receipt version: {error}"))?;
    receipt
        .finish()
        .map_err(|error| format!("could not finish acknowledgement receipt: {error}"))?;
    let stop_code = tokio::time::timeout(Duration::from_secs(8), receipt.stopped())
        .await
        .map_err(|_| {
            "timed out waiting for listener to receive the acknowledgement receipt".to_owned()
        })?
        .map_err(|error| format!("listener stopped the acknowledgement receipt: {error}"))?;
    if let Some(code) = stop_code {
        return Err(format!(
            "listener stopped the acknowledgement receipt with code {code}"
        ));
    }
    let mut final_ack = tokio::time::timeout(Duration::from_secs(8), connection.accept_uni())
        .await
        .map_err(|_| "timed out waiting for the final acknowledgement".to_owned())?
        .map_err(|error| format!("could not accept final acknowledgement: {error}"))?;
    read_control_frame(&mut final_ack, FINAL_MAGIC, "final acknowledgement").await?;
    connection.close(0_u32.into(), b"peer acknowledgement received");
    Ok(acknowledgement)
}

async fn bind_endpoint(
    local_identity: SecretKey,
    bind_address: SocketAddr,
) -> Result<Endpoint, String> {
    Endpoint::builder(presets::Minimal)
        .secret_key(local_identity)
        .alpns(vec![PEER_ALPN.to_vec()])
        .relay_mode(RelayMode::Disabled)
        .bind_addr(bind_address)
        .map_err(|error| format!("invalid direct peer bind address: {error}"))?
        .bind()
        .await
        .map_err(|error| format!("could not start direct peer endpoint: {error}"))
}

async fn write_text_frame<W>(writer: &mut W, text: &str) -> Result<(), String>
where
    W: AsyncWrite + Unpin,
{
    let bytes = text.as_bytes();
    if bytes.is_empty() || bytes.len() > MAX_TEXT_BYTES {
        return Err(format!(
            "peer text must contain between 1 and {MAX_TEXT_BYTES} UTF-8 bytes"
        ));
    }
    writer
        .write_all(FRAME_MAGIC)
        .await
        .map_err(|error| format!("could not write peer frame header: {error}"))?;
    writer
        .write_all(&FRAME_VERSION.to_be_bytes())
        .await
        .map_err(|error| format!("could not write peer frame version: {error}"))?;
    writer
        .write_all(&(bytes.len() as u32).to_be_bytes())
        .await
        .map_err(|error| format!("could not write peer frame length: {error}"))?;
    writer
        .write_all(bytes)
        .await
        .map_err(|error| format!("could not write peer text: {error}"))
}

async fn read_text_frame<R>(reader: &mut R) -> Result<String, String>
where
    R: AsyncRead + Unpin,
{
    let mut header = [0_u8; 10];
    reader
        .read_exact(&mut header)
        .await
        .map_err(|error| format!("could not read peer frame header: {error}"))?;
    if &header[..4] != FRAME_MAGIC {
        return Err("peer sent an invalid text frame marker".to_owned());
    }
    let version = u16::from_be_bytes([header[4], header[5]]);
    if version != FRAME_VERSION {
        return Err(format!("unsupported peer text frame version: {version}"));
    }
    let length = u32::from_be_bytes(header[6..10].try_into().expect("four bytes")) as usize;
    if length == 0 || length > MAX_TEXT_BYTES {
        return Err(format!(
            "peer text length must be between 1 and {MAX_TEXT_BYTES}"
        ));
    }
    let mut bytes = vec![0_u8; length];
    reader
        .read_exact(&mut bytes)
        .await
        .map_err(|error| format!("could not read peer text: {error}"))?;
    String::from_utf8(bytes).map_err(|error| format!("peer text is not valid UTF-8: {error}"))
}

async fn read_ack_receipt<R>(reader: &mut R) -> Result<(), String>
where
    R: AsyncRead + Unpin,
{
    read_control_frame(reader, ACK_MAGIC, "acknowledgement receipt").await
}

async fn read_control_frame<R>(reader: &mut R, magic: &[u8; 4], label: &str) -> Result<(), String>
where
    R: AsyncRead + Unpin,
{
    let mut receipt = [0_u8; 6];
    tokio::time::timeout(Duration::from_secs(8), reader.read_exact(&mut receipt))
        .await
        .map_err(|_| format!("timed out reading {label}"))?
        .map_err(|error| format!("could not read {label}: {error}"))?;
    if &receipt[..4] != magic || u16::from_be_bytes([receipt[4], receipt[5]]) != FRAME_VERSION {
        return Err(format!("peer sent an invalid {label}"));
    }
    Ok(())
}
