//! Local mDNS discovery for active Slouching QUIC listeners.
//!
//! Advertisements expose an ephemeral service name, UDP port, and the
//! addresses supplied by the listener. They deliberately do not expose a
//! device key or contact name. Discovery is an untrusted route hint; peers
//! still authenticate with their pinned device key after connecting.

use mdns_sd::{ResolvedService, ScopedIp, ServiceDaemon, ServiceEvent, ServiceInfo};
use std::{
    collections::BTreeSet,
    net::{IpAddr, SocketAddr},
    time::Duration,
};

pub const SERVICE_TYPE: &str = "_slouching._udp.local.";
const PROTOCOL_VERSION: &str = "1";
const DISCOVERY_ID_BYTES: usize = 8;
const MAX_DISCOVERED_PEERS: usize = 64;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct LanPeer {
    /// Random for this listener process. It is not a durable identity.
    pub discovery_id: String,
    pub service_name: String,
    pub addresses: Vec<SocketAddr>,
}

pub struct LanAdvertiser {
    daemon: ServiceDaemon,
    fullname: String,
}

impl LanAdvertiser {
    pub fn start(addresses: &[SocketAddr]) -> Result<Self, String> {
        let port = addresses
            .iter()
            .map(SocketAddr::port)
            .find(|port| *port != 0)
            .ok_or_else(|| "listener has no usable port for LAN discovery".to_owned())?;
        let ips = addresses
            .iter()
            .map(SocketAddr::ip)
            .filter(|ip| !ip.is_unspecified() && !ip.is_loopback() && !ip.is_multicast())
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect::<Vec<_>>();
        if ips.is_empty() {
            return Err("listener has no LAN/VPN address to advertise".to_owned());
        }

        let discovery_id = random_discovery_id()?;
        let instance = format!("sl-{}", &discovery_id[..12]);
        let hostname = format!("sl-{}.local.", &discovery_id[..12]);
        let properties = [("v", PROTOCOL_VERSION), ("id", discovery_id.as_str())];
        let service = ServiceInfo::new(
            SERVICE_TYPE,
            &instance,
            &hostname,
            ips.as_slice(),
            port,
            &properties[..],
        )
        .map_err(|error| format!("could not create LAN advertisement: {error}"))?;
        let fullname = service.get_fullname().to_owned();
        let daemon = ServiceDaemon::new()
            .map_err(|error| format!("could not start mDNS responder: {error}"))?;
        daemon
            .register(service)
            .map_err(|error| format!("could not advertise Slouching listener: {error}"))?;
        Ok(Self { daemon, fullname })
    }
}

impl Drop for LanAdvertiser {
    fn drop(&mut self) {
        let _ = self.daemon.unregister(&self.fullname);
        let _ = self.daemon.shutdown();
    }
}

/// Browse local Slouching listeners for a bounded interval. The caller passes
/// its current listener addresses so its own advertisement is omitted.
pub async fn discover(
    duration: Duration,
    own_addresses: Vec<SocketAddr>,
) -> Result<Vec<LanPeer>, String> {
    let daemon =
        ServiceDaemon::new().map_err(|error| format!("could not start mDNS browser: {error}"))?;
    let receiver = daemon
        .browse(SERVICE_TYPE)
        .map_err(|error| format!("could not browse Slouching listeners: {error}"))?;
    let deadline = tokio::time::Instant::now() + duration;
    let own_addresses = own_addresses.into_iter().collect::<BTreeSet<_>>();
    let mut peers = BTreeSet::new();

    loop {
        let event = match tokio::time::timeout_at(deadline, receiver.recv_async()).await {
            Ok(Ok(event)) => event,
            Ok(Err(_)) | Err(_) => break,
        };
        if let ServiceEvent::ServiceResolved(service) = event
            && let Some(peer) = parse_service(&service, &own_addresses)
        {
            peers.insert(peer);
            if peers.len() >= MAX_DISCOVERED_PEERS {
                break;
            }
        }
    }

    let _ = daemon.stop_browse(SERVICE_TYPE);
    let _ = daemon.shutdown();
    Ok(peers.into_iter().collect())
}

fn parse_service(
    service: &ResolvedService,
    own_addresses: &BTreeSet<SocketAddr>,
) -> Option<LanPeer> {
    if service.ty_domain != SERVICE_TYPE || service.port == 0 {
        return None;
    }
    let properties = &service.txt_properties;
    if properties.get_property_val_str("v") != Some(PROTOCOL_VERSION) {
        return None;
    }
    let discovery_id = properties.get_property_val_str("id")?;
    if discovery_id.len() != DISCOVERY_ID_BYTES * 2
        || !discovery_id.bytes().all(|byte| byte.is_ascii_hexdigit())
    {
        return None;
    }

    let addresses = service
        .addresses
        .iter()
        .filter_map(|scoped| socket_addr(scoped, service.port))
        .filter(|address| !own_addresses.contains(address))
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();
    if addresses.is_empty() {
        return None;
    }

    Some(LanPeer {
        discovery_id: discovery_id.to_ascii_lowercase(),
        service_name: service.fullname.clone(),
        addresses,
    })
}

fn socket_addr(scoped: &ScopedIp, port: u16) -> Option<SocketAddr> {
    match scoped {
        ScopedIp::V4(address) => {
            let ip = IpAddr::V4(*address.addr());
            valid_unicast_address(ip).then(|| SocketAddr::new(ip, port))
        }
        ScopedIp::V6(address) => {
            let ip = *address.addr();
            valid_unicast_address(IpAddr::V6(ip)).then(|| {
                SocketAddr::V6(std::net::SocketAddrV6::new(
                    ip,
                    port,
                    0,
                    address.scope_id().index,
                ))
            })
        }
        _ => None,
    }
}

fn valid_unicast_address(ip: IpAddr) -> bool {
    !ip.is_unspecified() && !ip.is_loopback() && !ip.is_multicast()
}

fn random_discovery_id() -> Result<String, String> {
    let mut bytes = [0u8; DISCOVERY_ID_BYTES];
    getrandom::fill(&mut bytes)
        .map_err(|error| format!("could not create discovery ID: {error}"))?;
    Ok(hex::encode(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    fn sample_service() -> ResolvedService {
        ServiceInfo::new(
            SERVICE_TYPE,
            "sl-0123456789ab",
            "sl-0123456789ab.local.",
            &[
                IpAddr::V4(Ipv4Addr::new(192, 168, 1, 20)),
                IpAddr::V6(Ipv6Addr::LOCALHOST),
            ][..],
            45873,
            &[("v", "1"), ("id", "0123456789abcdef")][..],
        )
        .unwrap()
        .as_resolved_service()
    }

    #[test]
    fn discovery_resolves_only_untrusted_routes_and_filters_loopback_and_self() {
        let service = sample_service();
        let local = BTreeSet::from(["192.168.1.20:45873".parse().unwrap()]);
        assert_eq!(parse_service(&service, &local), None);

        let peer = parse_service(&service, &BTreeSet::new()).unwrap();
        assert_eq!(peer.discovery_id, "0123456789abcdef");
        assert_eq!(
            peer.addresses,
            vec!["192.168.1.20:45873".parse::<SocketAddr>().unwrap()]
        );
    }

    #[test]
    fn discovery_rejects_unknown_protocol_and_malformed_ids() {
        for (version, id) in [("2", "0123456789abcdef"), ("1", "not-hex")] {
            let service = ServiceInfo::new(
                SERVICE_TYPE,
                "sl-aabbccddeeff",
                "sl-aabbccddeeff.local.",
                "192.168.1.21",
                45873,
                &[("v", version), ("id", id)][..],
            )
            .unwrap()
            .as_resolved_service();
            assert_eq!(parse_service(&service, &BTreeSet::new()), None);
        }
    }
}
