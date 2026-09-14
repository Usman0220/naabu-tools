use rand::Rng;
use std::net::Ipv4Addr;

pub struct IpGenerator;

#[derive(Debug, Clone)]
pub struct IpRange {
    pub start: Ipv4Addr,
    pub end: Ipv4Addr,
    pub label: String,
}

impl IpRange {
    pub fn contains(&self, ip: Ipv4Addr) -> bool {
        u32::from(ip) >= u32::from(self.start) && u32::from(ip) <= u32::from(self.end)
    }
}

fn reserved_ranges() -> Vec<IpRange> {
    vec![
        IpRange {
            start: "0.0.0.0".parse().unwrap(),
            end: "0.255.255.255".parse().unwrap(),
            label: "Current Network".into(),
        },
        IpRange {
            start: "10.0.0.0".parse().unwrap(),
            end: "10.255.255.255".parse().unwrap(),
            label: "Private Class A".into(),
        },
        IpRange {
            start: "100.64.0.0".parse().unwrap(),
            end: "100.127.255.255".parse().unwrap(),
            label: "Carrier-Grade NAT".into(),
        },
        IpRange {
            start: "127.0.0.0".parse().unwrap(),
            end: "127.255.255.255".parse().unwrap(),
            label: "Loopback".into(),
        },
        IpRange {
            start: "169.254.0.0".parse().unwrap(),
            end: "169.254.255.255".parse().unwrap(),
            label: "Link-Local".into(),
        },
        IpRange {
            start: "172.16.0.0".parse().unwrap(),
            end: "172.31.255.255".parse().unwrap(),
            label: "Private Class B".into(),
        },
        IpRange {
            start: "192.0.0.0".parse().unwrap(),
            end: "192.0.0.255".parse().unwrap(),
            label: "IETF Protocol".into(),
        },
        IpRange {
            start: "192.0.2.0".parse().unwrap(),
            end: "192.0.2.255".parse().unwrap(),
            label: "TEST-NET-1".into(),
        },
        IpRange {
            start: "192.88.99.0".parse().unwrap(),
            end: "192.88.99.255".parse().unwrap(),
            label: "IPv6 Transition".into(),
        },
        IpRange {
            start: "192.168.0.0".parse().unwrap(),
            end: "192.168.255.255".parse().unwrap(),
            label: "Private Class C".into(),
        },
        IpRange {
            start: "198.18.0.0".parse().unwrap(),
            end: "198.19.255.255".parse().unwrap(),
            label: "Benchmarking".into(),
        },
        IpRange {
            start: "198.51.100.0".parse().unwrap(),
            end: "198.51.100.255".parse().unwrap(),
            label: "TEST-NET-2".into(),
        },
        IpRange {
            start: "203.0.113.0".parse().unwrap(),
            end: "203.0.113.255".parse().unwrap(),
            label: "TEST-NET-3".into(),
        },
        IpRange {
            start: "224.0.0.0".parse().unwrap(),
            end: "239.255.255.255".parse().unwrap(),
            label: "Multicast".into(),
        },
        IpRange {
            start: "240.0.0.0".parse().unwrap(),
            end: "255.255.255.254".parse().unwrap(),
            label: "Reserved".into(),
        },
        IpRange {
            start: "255.255.255.255".parse().unwrap(),
            end: "255.255.255.255".parse().unwrap(),
            label: "Broadcast".into(),
        },
    ]
}

impl IpGenerator {
    pub fn random_public_ip() -> Ipv4Addr {
        let mut rng = rand::thread_rng();
        loop {
            let a = rng.gen_range(1..=223);
            let b = rng.gen::<u8>();
            let c = rng.gen::<u8>();
            let d = rng.gen_range(1..=254);

            let ip = Ipv4Addr::new(a, b, c, d);
            if !Self::is_reserved(ip) {
                return ip;
            }
        }
    }

    pub fn is_reserved(ip: Ipv4Addr) -> bool {
        let ranges = reserved_ranges();
        for range in &ranges {
            if range.contains(ip) {
                return true;
            }
        }
        false
    }

    pub fn generate_batch(count: usize) -> Vec<String> {
        let mut ips = Vec::with_capacity(count);
        let mut seen = std::collections::HashSet::new();

        while ips.len() < count {
            let ip = Self::random_public_ip();
            let ip_str = ip.to_string();
            if seen.insert(ip_str.clone()) {
                ips.push(ip_str);
            }
        }
        ips
    }

    pub fn generate_from_cidr(cidr: &str) -> Result<Vec<String>, String> {
        let parts: Vec<&str> = cidr.split('/').collect();
        if parts.len() != 2 {
            return Err("Invalid CIDR format. Use x.x.x.x/n".into());
        }

        let base: Ipv4Addr = parts[0]
            .parse()
            .map_err(|_| format!("Invalid IP: {}", parts[0]))?;
        let prefix: u32 = parts[1]
            .parse()
            .map_err(|_| format!("Invalid prefix: {}", parts[1]))?;

        if prefix > 32 {
            return Err("Prefix must be <= 32".into());
        }

        if prefix < 8 {
            return Err("Prefix too small (min /8) — would generate too many IPs".into());
        }

        let base_u32 = u32::from(base);
        let mask = if prefix == 0 {
            0u32
        } else {
            !0u32 << (32 - prefix)
        };
        let network = base_u32 & mask;
        let host_bits = 32 - prefix;
        let host_count = 1u32 << host_bits;

        if host_count > 65536 {
            return Err("Too many IPs (>64k). Use a larger prefix.".into());
        }

        let mut ips = Vec::new();
        for i in 1..host_count - 1 {
            let ip = Ipv4Addr::from(network | i);
            if !Self::is_reserved(ip) {
                ips.push(ip.to_string());
            }
        }

        Ok(ips)
    }

    pub fn parse_ip_list(input: &str) -> Vec<String> {
        let mut ips = Vec::new();
        for line in input.lines() {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }
            if line.contains('/') {
                if let Ok(cidr_ips) = Self::generate_from_cidr(line) {
                    ips.extend(cidr_ips);
                }
            } else if line.parse::<Ipv4Addr>().is_ok() {
                ips.push(line.to_string());
            }
        }
        ips
    }

    pub fn reserved_ranges_display() -> Vec<(String, String)> {
        reserved_ranges()
            .into_iter()
            .map(|r| (format!("{} - {}", r.start, r.end), r.label))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_random_ip_not_reserved() {
        for _ in 0..1000 {
            let ip = IpGenerator::random_public_ip();
            assert!(!IpGenerator::is_reserved(ip), "Got reserved: {}", ip);
        }
    }

    #[test]
    fn test_generate_batch_unique() {
        let ips = IpGenerator::generate_batch(100);
        let unique: std::collections::HashSet<_> = ips.iter().collect();
        assert_eq!(unique.len(), 100);
    }
}
