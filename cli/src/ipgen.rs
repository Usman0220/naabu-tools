use std::collections::HashSet;
use std::net::Ipv4Addr;
use rand::Rng;

pub struct IpGenerator;

#[derive(Clone)]
struct IpRange {
    start: Ipv4Addr,
    end: Ipv4Addr,
}

impl IpRange {
    fn contains(&self, ip: Ipv4Addr) -> bool {
        u32::from(ip) >= u32::from(self.start) && u32::from(ip) <= u32::from(self.end)
    }
}

fn range(a: &str, b: &str) -> IpRange {
    IpRange {
        start: a.parse().unwrap(),
        end: b.parse().unwrap(),
    }
}

fn reserved_ranges() -> Vec<IpRange> {
    vec![
        range("0.0.0.0", "0.255.255.255"),
        range("10.0.0.0", "10.255.255.255"),
        range("100.64.0.0", "100.127.255.255"),
        range("127.0.0.0", "127.255.255.255"),
        range("169.254.0.0", "169.254.255.255"),
        range("172.16.0.0", "172.31.255.255"),
        range("192.0.0.0", "192.0.0.255"),
        range("192.0.2.0", "192.0.2.255"),
        range("192.88.99.0", "192.88.99.255"),
        range("192.168.0.0", "192.168.255.255"),
        range("198.18.0.0", "198.19.255.255"),
        range("198.51.100.0", "198.51.100.255"),
        range("203.0.113.0", "203.0.113.255"),
        range("224.0.0.0", "239.255.255.255"),
        range("240.0.0.0", "255.255.255.254"),
        range("255.255.255.255", "255.255.255.255"),
    ]
}

impl IpGenerator {
    pub fn is_reserved(ip: Ipv4Addr) -> bool {
        reserved_ranges().iter().any(|r| r.contains(ip))
    }

    pub fn random_public_ip() -> Option<Ipv4Addr> {
        let mut rng = rand::thread_rng();
        for _ in 0..1000 {
            let a = rng.gen_range(1..=223);
            let b = rng.gen::<u8>();
            let c = rng.gen::<u8>();
            let d = rng.gen_range(1..=254);
            let ip = Ipv4Addr::new(a, b, c, d);
            if !Self::is_reserved(ip) {
                return Some(ip);
            }
        }
        None
    }

    pub fn generate_batch(count: usize) -> Vec<String> {
        let mut seen: HashSet<String> = HashSet::with_capacity(count);
        while seen.len() < count {
            if let Some(ip) = Self::random_public_ip() {
                seen.insert(ip.to_string());
            } else {
                break;
            }
        }
        seen.into_iter().collect()
    }

    pub fn from_cidr(cidr: &str) -> Result<Vec<String>, String> {
        let parts: Vec<&str> = cidr.split('/').collect();
        if parts.len() != 2 {
            return Err(format!("Invalid CIDR: {cidr}"));
        }
        let base: Ipv4Addr = parts[0].parse().map_err(|_| format!("Invalid IP: {}", parts[0]))?;
        let prefix: u32 = parts[1].parse().map_err(|_| format!("Invalid prefix: {}", parts[1]))?;
        if prefix > 32 {
            return Err("Prefix must be <= 32".into());
        }
        if prefix < 8 {
            return Err("Prefix too small (min /8)".into());
        }
        let mask = if prefix == 0 {
            0u32
        } else {
            !0u32 << (32 - prefix)
        };
        let network = u32::from(base) & mask;
        let host_count = 1u32 << (32 - prefix);
        if host_count > 65536 {
            return Err("Too many IPs (>64k). Use a larger prefix.".into());
        }
        let mut ips = Vec::new();
        for i in 1..host_count.saturating_sub(1) {
            let ip = Ipv4Addr::from(network | i);
            if !Self::is_reserved(ip) {
                ips.push(ip.to_string());
            }
        }
        Ok(ips)
    }

    pub fn parse_list(input: &str) -> Vec<String> {
        let mut ips: Vec<String> = Vec::new();
        for line in input.lines() {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }
            if line.contains('/') {
                if let Ok(cidr_ips) = Self::from_cidr(line) {
                    ips.extend(cidr_ips);
                }
            } else if line.parse::<Ipv4Addr>().is_ok() {
                ips.push(line.to_string());
            }
        }
        ips
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_batch() {
        let ips = IpGenerator::generate_batch(50);
        let unique: HashSet<_> = ips.iter().collect();
        assert_eq!(unique.len(), 50);
    }

    #[test]
    fn test_cidr() {
        let ips = IpGenerator::from_cidr("8.8.8.0/30").unwrap();
        assert_eq!(ips.len(), 2);
    }
}