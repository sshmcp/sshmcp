use crate::config::RuntimeMode;
use crate::errors::ArrtError;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};

pub trait TargetPolicy: Send + Sync {
    fn validate(&self, host: &str, address: IpAddr) -> Result<(), ArrtError>;
}

pub struct RuntimeTargetPolicy(pub RuntimeMode);

impl TargetPolicy for RuntimeTargetPolicy {
    fn validate(&self, host: &str, address: IpAddr) -> Result<(), ArrtError> {
        if self.0 == RuntimeMode::Cloud && !is_public(address) {
            return Err(ArrtError::PolicyDenied(format!(
                "Cloud target policy rejects {host} resolved to {address}"
            )));
        }
        Ok(())
    }
}

/// Resolve once and connect to the validated socket address to avoid a second DNS lookup.
pub async fn resolve_direct(
    policy: &dyn TargetPolicy,
    host: &str,
    port: u16,
) -> Result<SocketAddr, ArrtError> {
    let addresses = tokio::net::lookup_host((host, port))
        .await?
        .collect::<Vec<_>>();
    if addresses.is_empty() {
        return Err(ArrtError::Ssh(format!("no address found for {host}")));
    }
    for address in &addresses {
        policy.validate(host, address.ip())?;
    }
    Ok(addresses[0])
}

/// A bastion resolves the next hop remotely. Cloud therefore requires a literal IP,
/// which can be checked before the bastion is asked to open the channel.
pub fn validate_remote_hop(policy: &dyn TargetPolicy, host: &str) -> Result<(), ArrtError> {
    let address: IpAddr = host.parse().map_err(|_| {
        ArrtError::PolicyDenied(format!(
            "Cloud target policy requires a literal IP for bastion hop {host}"
        ))
    })?;
    policy.validate(host, address)
}

fn is_public(address: IpAddr) -> bool {
    match address {
        IpAddr::V4(ip) => public_v4(ip),
        IpAddr::V6(ip) => {
            if let Some(mapped) = ip.to_ipv4_mapped() {
                return public_v4(mapped);
            }
            !(ip.is_unspecified()
                || ip.is_loopback()
                || ip.is_multicast()
                || ip.is_unique_local()
                || ip.is_unicast_link_local()
                || (ip.segments()[0] & 0xffc0) == 0xfe80)
        }
    }
}

fn public_v4(ip: Ipv4Addr) -> bool {
    let [a, b, c, _] = ip.octets();
    !(a == 0
        || a == 10
        || a == 127
        || a >= 224
        || (a == 100 && (64..=127).contains(&b))
        || (a == 169 && b == 254)
        || (a == 172 && (16..=31).contains(&b))
        || (a == 192 && (b == 0 || b == 168 || (b == 88 && c == 99)))
        || (a == 198 && (b == 18 || b == 19 || (b == 51 && c == 100)))
        || (a == 203 && b == 0 && c == 113))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cloud_rejects_unsafe_destinations() {
        let policy = RuntimeTargetPolicy(RuntimeMode::Cloud);
        for ip in [
            "127.0.0.1",
            "10.1.2.3",
            "169.254.169.254",
            "100.64.1.2",
            "::1",
            "fd00::1",
        ] {
            assert!(
                policy.validate("target", ip.parse().unwrap()).is_err(),
                "{ip}"
            );
        }
        assert!(policy
            .validate("target", "8.8.8.8".parse().unwrap())
            .is_ok());
        assert!(RuntimeTargetPolicy(RuntimeMode::SelfHosted)
            .validate("target", "127.0.0.1".parse().unwrap())
            .is_ok());
        assert!(RuntimeTargetPolicy(RuntimeMode::PrivateWorker)
            .validate("private-target", "10.1.2.3".parse().unwrap())
            .is_ok());
    }

    #[tokio::test]
    async fn cloud_checks_dns_answers_before_connecting() {
        let error = resolve_direct(&RuntimeTargetPolicy(RuntimeMode::Cloud), "localhost", 22)
            .await
            .unwrap_err();
        assert_eq!(error.code(), "policy_denied");
    }
}
