use image_codec::{GenericImageView, ImageReader, Limits};
use std::io::Cursor;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};
use std::time::{SystemTime, UNIX_EPOCH};

const PREFIX: &str = "slouching-invite-v1:";
const MAGIC: &[u8; 8] = b"SLOUCH01";
const MAX_ADDRESSES: usize = 8;
const MAX_TEXT_LEN: usize = 2048;
const MAX_IMAGE_BYTES: usize = 8 * 1024 * 1024;
const MAX_IMAGE_DIMENSION: u32 = 4096;
const INVITE_TTL_SECONDS: u64 = 10 * 60;
const FUTURE_SKEW_SECONDS: u64 = 60;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerInvite {
    pub device_key: [u8; 32],
    pub addresses: Vec<SocketAddr>,
    pub issued_at: u64,
}

pub fn create(
    secret: &iroh::SecretKey,
    addresses: &[SocketAddr],
    now: u64,
) -> Result<String, String> {
    let addresses = normalize_addresses(addresses)?;
    let device_key = *secret.public().as_bytes();
    let mut payload = signing_payload(&device_key, &addresses, now)?;
    let signature = secret.sign(&payload);
    payload.extend_from_slice(&signature.to_bytes());
    Ok(format!("{PREFIX}{}", encode_hex(&payload)))
}

pub fn decode(text: &str, now: u64) -> Result<PeerInvite, String> {
    let encoded = text
        .strip_prefix(PREFIX)
        .ok_or_else(|| "QR não é um convite Slouching v1".to_owned())?;
    if encoded.is_empty() || encoded.len() > MAX_TEXT_LEN || encoded.len() % 2 != 0 {
        return Err("Convite QR vazio ou acima do limite permitido".to_owned());
    }
    let bytes = decode_hex(encoded)?;
    let signature_len = iroh::Signature::LENGTH;
    if bytes.len() < MAGIC.len() + 8 + 32 + 1 + signature_len {
        return Err("Convite QR incompleto".to_owned());
    }
    let signed_len = bytes.len() - signature_len;
    let (signed, signature_bytes) = bytes.split_at(signed_len);
    if &signed[..MAGIC.len()] != MAGIC {
        return Err("Versão ou formato de convite desconhecido".to_owned());
    }
    let mut cursor = MAGIC.len();
    let issued_at = take_u64(signed, &mut cursor)?;
    if issued_at > now.saturating_add(FUTURE_SKEW_SECONDS)
        || now.saturating_sub(issued_at) > INVITE_TTL_SECONDS
    {
        return Err("Convite expirado ou com horário inválido; gere um novo QR".to_owned());
    }
    let device_key: [u8; 32] = take(signed, &mut cursor, 32)?
        .try_into()
        .map_err(|_| "Chave de dispositivo inválida".to_owned())?;
    let address_count = take(signed, &mut cursor, 1)?[0] as usize;
    if address_count > MAX_ADDRESSES {
        return Err("Convite contém endereços demais".to_owned());
    }
    let mut addresses = Vec::with_capacity(address_count);
    for _ in 0..address_count {
        addresses.push(decode_address(signed, &mut cursor)?);
    }
    if cursor != signed.len() {
        return Err("Convite contém bytes extras".to_owned());
    }
    let public_key = iroh::PublicKey::from_bytes(&device_key)
        .map_err(|_| "Chave pública inválida no convite".to_owned())?;
    iroh::EndpointId::from_bytes(&device_key)
        .map_err(|_| "Identidade Iroh inválida no convite".to_owned())?;
    let signature_bytes: [u8; iroh::Signature::LENGTH] = signature_bytes
        .try_into()
        .map_err(|_| "Assinatura inválida no convite".to_owned())?;
    public_key
        .verify(signed, &iroh::Signature::from_bytes(&signature_bytes))
        .map_err(|_| "Assinatura do convite não confere".to_owned())?;
    Ok(PeerInvite {
        device_key,
        addresses,
        issued_at,
    })
}

pub fn qr_rgba(text: &str) -> Result<(u32, Vec<u8>), String> {
    let qr = qrcodegen::QrCode::encode_text(text, qrcodegen::QrCodeEcc::Quartile)
        .map_err(|error| format!("não foi possível gerar QR: {error}"))?;
    let quiet_zone = 4_u32;
    let scale = 5_u32;
    let size = (qr.size() as u32 + quiet_zone * 2) * scale;
    let mut rgba = vec![255_u8; (size * size * 4) as usize];
    for y in 0..size {
        for x in 0..size {
            let module_x = (x / scale) as i32 - quiet_zone as i32;
            let module_y = (y / scale) as i32 - quiet_zone as i32;
            if module_x >= 0
                && module_y >= 0
                && module_x < qr.size()
                && module_y < qr.size()
                && qr.get_module(module_x, module_y)
            {
                let offset = ((y * size + x) * 4) as usize;
                rgba[offset..offset + 3].fill(0);
            }
        }
    }
    Ok((size, rgba))
}

pub fn decode_png(bytes: &[u8], now: u64) -> Result<PeerInvite, String> {
    if bytes.is_empty() || bytes.len() > MAX_IMAGE_BYTES {
        return Err("Imagem vazia ou acima de 8 MiB".to_owned());
    }
    let mut reader = ImageReader::with_format(Cursor::new(bytes), image_codec::ImageFormat::Png);
    let mut limits = Limits::default();
    limits.max_image_width = Some(MAX_IMAGE_DIMENSION);
    limits.max_image_height = Some(MAX_IMAGE_DIMENSION);
    limits.max_alloc = Some(64 * 1024 * 1024);
    reader.limits(limits);
    let image = reader
        .decode()
        .map_err(|error| format!("não foi possível abrir a imagem PNG: {error}"))?;
    let (width, height) = image.dimensions();
    if width == 0 || height == 0 || width > MAX_IMAGE_DIMENSION || height > MAX_IMAGE_DIMENSION {
        return Err("Imagem excede o limite de 4096 × 4096 pixels".to_owned());
    }
    let mut prepared = rqrr::PreparedImage::prepare(image.to_luma8());
    let grids = prepared.detect_grids();
    if grids.len() != 1 {
        return Err(if grids.is_empty() {
            "Nenhum QR encontrado na imagem".to_owned()
        } else {
            "A imagem deve conter exatamente um QR".to_owned()
        });
    }
    let (_, text) = grids[0]
        .decode()
        .map_err(|error| format!("não foi possível ler o QR: {error}"))?;
    decode(&text, now)
}

fn normalize_addresses(addresses: &[SocketAddr]) -> Result<Vec<SocketAddr>, String> {
    let mut normalized = Vec::with_capacity(addresses.len().min(MAX_ADDRESSES));
    for address in addresses {
        if validate_address(address).is_ok() && !normalized.contains(address) {
            normalized.push(*address);
            if normalized.len() == MAX_ADDRESSES {
                break;
            }
        }
    }
    Ok(normalized)
}

fn validate_address(address: &SocketAddr) -> Result<(), String> {
    let valid_ip = match address.ip() {
        IpAddr::V4(ip) => !ip.is_unspecified() && !ip.is_loopback() && !ip.is_multicast(),
        IpAddr::V6(ip) => {
            !ip.is_unspecified()
                && !ip.is_loopback()
                && !ip.is_multicast()
                && !ip.is_unicast_link_local()
        }
    };
    if !valid_ip || address.port() == 0 {
        return Err(
            "Convites aceitam apenas IPs alcançáveis e portas UDP entre 1 e 65535".to_owned(),
        );
    }
    if matches!(address, SocketAddr::V6(address) if address.scope_id() != 0) {
        return Err(
            "Endereços IPv6 com escopo local não podem ser compartilhados por convite".to_owned(),
        );
    }
    Ok(())
}

fn signing_payload(
    device_key: &[u8; 32],
    addresses: &[SocketAddr],
    issued_at: u64,
) -> Result<Vec<u8>, String> {
    if addresses.len() > MAX_ADDRESSES {
        return Err("No máximo 8 endereços podem entrar no convite".to_owned());
    }
    let mut payload = Vec::with_capacity(64 + addresses.len() * 19);
    payload.extend_from_slice(MAGIC);
    payload.extend_from_slice(&issued_at.to_be_bytes());
    payload.extend_from_slice(device_key);
    payload.push(addresses.len() as u8);
    for address in addresses {
        validate_address(address)?;
        match address {
            SocketAddr::V4(address) => {
                payload.push(4);
                payload.extend_from_slice(&address.ip().octets());
                payload.extend_from_slice(&address.port().to_be_bytes());
            }
            SocketAddr::V6(address) => {
                payload.push(6);
                payload.extend_from_slice(&address.ip().octets());
                payload.extend_from_slice(&address.port().to_be_bytes());
            }
        }
    }
    Ok(payload)
}

fn decode_address(bytes: &[u8], cursor: &mut usize) -> Result<SocketAddr, String> {
    let family = take(bytes, cursor, 1)?[0];
    let address = match family {
        4 => {
            let octets: [u8; 4] = take(bytes, cursor, 4)?
                .try_into()
                .map_err(|_| "IPv4 inválido no convite".to_owned())?;
            let port = u16::from_be_bytes(
                take(bytes, cursor, 2)?
                    .try_into()
                    .map_err(|_| "Porta inválida no convite".to_owned())?,
            );
            SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::from(octets), port))
        }
        6 => {
            let octets: [u8; 16] = take(bytes, cursor, 16)?
                .try_into()
                .map_err(|_| "IPv6 inválido no convite".to_owned())?;
            let port = u16::from_be_bytes(
                take(bytes, cursor, 2)?
                    .try_into()
                    .map_err(|_| "Porta inválida no convite".to_owned())?,
            );
            SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::from(octets), port, 0, 0))
        }
        _ => return Err("Família IP desconhecida no convite".to_owned()),
    };
    validate_address(&address)?;
    Ok(address)
}

fn take<'a>(bytes: &'a [u8], cursor: &mut usize, length: usize) -> Result<&'a [u8], String> {
    let end = cursor
        .checked_add(length)
        .ok_or_else(|| "Convite excede os limites".to_owned())?;
    let slice = bytes
        .get(*cursor..end)
        .ok_or_else(|| "Convite truncado".to_owned())?;
    *cursor = end;
    Ok(slice)
}

fn take_u64(bytes: &[u8], cursor: &mut usize) -> Result<u64, String> {
    Ok(u64::from_be_bytes(
        take(bytes, cursor, 8)?
            .try_into()
            .map_err(|_| "Horário inválido no convite".to_owned())?,
    ))
}

fn encode_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        encoded.push(HEX[(byte >> 4) as usize] as char);
        encoded.push(HEX[(byte & 0x0f) as usize] as char);
    }
    encoded
}

fn decode_hex(value: &str) -> Result<Vec<u8>, String> {
    let bytes = value.as_bytes();
    let mut decoded = Vec::with_capacity(bytes.len() / 2);
    for pair in bytes.chunks_exact(2) {
        let digit = |byte: u8| match byte {
            b'0'..=b'9' => Some(byte - b'0'),
            b'a'..=b'f' => Some(byte - b'a' + 10),
            b'A'..=b'F' => Some(byte - b'A' + 10),
            _ => None,
        };
        let high = digit(pair[0]).ok_or_else(|| "Convite tem caracteres inválidos".to_owned())?;
        let low = digit(pair[1]).ok_or_else(|| "Convite tem caracteres inválidos".to_owned())?;
        decoded.push((high << 4) | low);
    }
    Ok(decoded)
}

pub fn unix_time_seconds() -> Result<u64, String> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|elapsed| elapsed.as_secs())
        .map_err(|error| format!("relógio do sistema inválido: {error}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(seed: u8) -> iroh::SecretKey {
        iroh::SecretKey::from_bytes(&[seed; 32])
    }

    fn addr(value: &str) -> SocketAddr {
        value.parse().unwrap()
    }

    #[test]
    fn signed_invite_round_trips_multiple_lan_and_vpn_addresses() {
        let signer = key(7);
        let addresses = [addr("192.168.1.4:45873"), addr("100.64.0.4:45873")];
        let encoded = create(&signer, &addresses, 1_800_000_000).unwrap();
        let invite = decode(&encoded, 1_800_000_010).unwrap();

        assert_eq!(invite.device_key, *signer.public().as_bytes());
        assert_eq!(invite.addresses, addresses);
    }

    #[test]
    fn signed_invite_bounds_the_announced_route_list() {
        let signer = key(8);
        let addresses = (1..=10)
            .map(|octet| addr(&format!("192.168.1.{octet}:45873")))
            .collect::<Vec<_>>();
        let encoded = create(&signer, &addresses, 1_800_000_000).unwrap();
        assert_eq!(decode(&encoded, 1_800_000_001).unwrap().addresses.len(), 8);
    }

    #[test]
    fn signed_invite_rejects_tampering_expiry_and_invalid_address() {
        let signer = key(9);
        let address = addr("192.168.1.8:45873");
        let encoded = create(&signer, &[address], 1_800_000_000).unwrap();
        assert!(decode(&encoded, 1_800_000_601).is_err());
        assert!(decode(&encoded, 1_799_999_939).is_err());

        let mut tampered = encoded.into_bytes();
        let last = tampered.last_mut().unwrap();
        *last = if *last == b'0' { b'1' } else { b'0' };
        assert!(decode(std::str::from_utf8(&tampered).unwrap(), 1_800_000_001).is_err());

        let no_addresses = create(
            &signer,
            &[
                addr("0.0.0.0:45873"),
                addr("127.0.0.1:45873"),
                addr("192.168.1.8:0"),
            ],
            1_800_000_000,
        )
        .unwrap();
        assert!(
            decode(&no_addresses, 1_800_000_001)
                .unwrap()
                .addresses
                .is_empty()
        );
    }

    #[test]
    fn qr_renders_and_decodes_through_png() {
        let signer = key(11);
        let encoded = create(&signer, &[addr("100.64.0.8:45873")], 1_800_000_000).unwrap();
        let (size, rgba) = qr_rgba(&encoded).unwrap();
        let image = image_codec::RgbaImage::from_raw(size, size, rgba).unwrap();
        let mut png = std::io::Cursor::new(Vec::new());
        image_codec::DynamicImage::ImageRgba8(image)
            .write_to(&mut png, image_codec::ImageFormat::Png)
            .unwrap();
        let invite = decode_png(png.get_ref(), 1_800_000_001).unwrap();
        assert_eq!(invite.device_key, *signer.public().as_bytes());
        assert_eq!(invite.addresses, [addr("100.64.0.8:45873")]);
    }

    #[test]
    fn png_import_rejects_dimensions_over_limit() {
        let image = image_codec::RgbaImage::new(MAX_IMAGE_DIMENSION + 1, 1);
        let mut png = Cursor::new(Vec::new());
        image_codec::DynamicImage::ImageRgba8(image)
            .write_to(&mut png, image_codec::ImageFormat::Png)
            .unwrap();

        assert!(decode_png(png.get_ref(), 1_800_000_001).is_err());
    }
}
