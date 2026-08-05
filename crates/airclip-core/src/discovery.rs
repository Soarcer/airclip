//! Discovery per PROTOCOL.md §4 and ADR-4.
//!
//! mDNS data is an **unauthenticated hint**. A spoofed record can make us dial an
//! attacker, but cannot survive the handshake (PROTOCOL §6.1, §10). Nothing here may
//! be treated as proof of identity.
//!
//! The `mdns` feature carries the `mdns-sd` implementation used by the Windows agent.
//! iOS uses `NWBrowser` natively and feeds hints in over FFI, so the trait exists to
//! keep both paths interchangeable.

use std::net::SocketAddr;

use crate::error::{Error, Result};
use crate::{DeviceId, MDNS_SERVICE};

/// Display names are capped so the TXT record stays inside one MTU (PROTOCOL §4).
pub const MAX_NAME_BYTES: usize = 32;

const TXT_VERSION: &str = "v";
const TXT_ID: &str = "id";
const TXT_NAME: &str = "nm";

/// A discovered candidate. Ordered addresses; the caller races them (PROTOCOL §4).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerHint {
    pub device_id: DeviceId,
    pub name: String,
    pub addrs: Vec<SocketAddr>,
}

/// The `v`/`id`/`nm` TXT triple advertised alongside the service.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TxtRecord {
    pub version: u8,
    pub device_id: DeviceId,
    pub name: String,
}

impl TxtRecord {
    pub fn new(device_id: DeviceId, name: &str) -> Self {
        Self {
            version: crate::PROTOCOL_VERSION,
            device_id,
            name: truncate_name(name),
        }
    }

    pub fn to_pairs(&self) -> Vec<(String, String)> {
        vec![
            (TXT_VERSION.into(), self.version.to_string()),
            (TXT_ID.into(), self.device_id.hex()),
            (TXT_NAME.into(), self.name.clone()),
        ]
    }

    /// Parse from key/value pairs. Unknown keys are ignored so a future version can add
    /// fields without breaking this parser.
    pub fn parse<'a, I>(pairs: I) -> Result<Self>
    where
        I: IntoIterator<Item = (&'a str, &'a str)>,
    {
        let mut version = None;
        let mut device_id = None;
        let mut name = String::new();

        for (k, v) in pairs {
            match k {
                TXT_VERSION => version = v.parse::<u8>().ok(),
                TXT_ID => {
                    let raw =
                        hex::decode(v).map_err(|_| Error::Cbor("TXT id is not hex".into()))?;
                    let arr: [u8; 16] = raw
                        .try_into()
                        .map_err(|_| Error::Cbor("TXT id must be 16 bytes".into()))?;
                    device_id = Some(DeviceId(arr));
                }
                TXT_NAME => name = v.to_owned(),
                _ => {}
            }
        }

        let version = version.ok_or_else(|| Error::Cbor("TXT missing v".into()))?;
        if version != crate::PROTOCOL_VERSION {
            return Err(Error::Cbor(format!("TXT unsupported version {version}")));
        }
        let device_id = device_id.ok_or_else(|| Error::Cbor("TXT missing id".into()))?;
        Ok(Self {
            version,
            device_id,
            name,
        })
    }
}

/// Truncate to `MAX_NAME_BYTES` on a char boundary.
///
/// Byte-slicing a UTF-8 name would panic on a multi-byte boundary — and machine names
/// like "Bernhard's PC (Büro)" hit exactly that.
pub fn truncate_name(name: &str) -> String {
    if name.len() <= MAX_NAME_BYTES {
        return name.to_owned();
    }
    let mut end = MAX_NAME_BYTES;
    while end > 0 && !name.is_char_boundary(end) {
        end -= 1;
    }
    name[..end].to_owned()
}

/// The mDNS instance name for a device (PROTOCOL §4).
pub fn instance_name(device_id: &DeviceId) -> String {
    device_id.hex()
}

/// Advertise and browse. Implemented by `mdns-sd` on Windows, by `NWBrowser` on iOS.
pub trait Discovery {
    /// Publish `<device_id>._airclip._tcp.local.` on `port`.
    fn advertise(&mut self, device_id: &DeviceId, name: &str, port: u16) -> Result<()>;
    /// Stop publishing.
    fn stop_advertising(&mut self) -> Result<()>;
}

#[cfg(feature = "mdns")]
pub use mdns_impl::MdnsDiscovery;

#[cfg(feature = "mdns")]
mod mdns_impl {
    use super::*;
    use mdns_sd::{ServiceDaemon, ServiceEvent, ServiceInfo};

    /// `mdns-sd`-backed discovery for the Windows agent.
    pub struct MdnsDiscovery {
        daemon: ServiceDaemon,
        registered_fullname: Option<String>,
    }

    impl MdnsDiscovery {
        pub fn new() -> Result<Self> {
            let daemon =
                ServiceDaemon::new().map_err(|e| Error::Cbor(format!("mdns daemon: {e}")))?;
            Ok(Self {
                daemon,
                registered_fullname: None,
            })
        }

        /// Browse for peers. Returns a channel of hints; the caller decides which to dial.
        ///
        /// Runs until the returned receiver is dropped. Per PROTOCOL §4 the phone browses
        /// only when it needs a connection — never continuously.
        pub fn browse(&self) -> Result<std::sync::mpsc::Receiver<PeerHint>> {
            let rx = self
                .daemon
                .browse(MDNS_SERVICE)
                .map_err(|e| Error::Cbor(format!("mdns browse: {e}")))?;
            let (tx, out) = std::sync::mpsc::channel();

            std::thread::spawn(move || {
                while let Ok(event) = rx.recv() {
                    let ServiceEvent::ServiceResolved(info) = event else {
                        continue;
                    };
                    let Some(hint) = hint_from_resolved(&info) else {
                        continue;
                    };
                    if tx.send(hint).is_err() {
                        break; // receiver dropped — stop browsing
                    }
                }
            });
            Ok(out)
        }

        pub fn shutdown(&mut self) -> Result<()> {
            let _ = self.stop_advertising();
            self.daemon
                .shutdown()
                .map_err(|e| Error::Cbor(format!("mdns shutdown: {e}")))?;
            Ok(())
        }
    }

    fn hint_from_resolved(info: &mdns_sd::ResolvedService) -> Option<PeerHint> {
        let props: Vec<(String, String)> = info
            .txt_properties
            .iter()
            .map(|p| (p.key().to_owned(), p.val_str().to_owned()))
            .collect();
        let borrowed: Vec<(&str, &str)> = props
            .iter()
            .map(|(k, v)| (k.as_str(), v.as_str()))
            .collect();

        // A malformed or wrong-version TXT is just an uninteresting peer, not an error.
        let txt = TxtRecord::parse(borrowed).ok()?;
        let addrs: Vec<SocketAddr> = info
            .addresses
            .iter()
            .map(|a| SocketAddr::new(a.to_ip_addr(), info.port))
            .collect();
        if addrs.is_empty() {
            return None;
        }
        Some(PeerHint {
            device_id: txt.device_id,
            name: txt.name,
            addrs,
        })
    }

    impl Discovery for MdnsDiscovery {
        fn advertise(&mut self, device_id: &DeviceId, name: &str, port: u16) -> Result<()> {
            self.stop_advertising()?;

            let txt = TxtRecord::new(*device_id, name);
            let props: Vec<(String, String)> = txt.to_pairs();
            let instance = instance_name(device_id);
            // Empty address list + enable_addr_auto: mdns-sd tracks interface changes
            // for us, which PROTOCOL §4 wants on a laptop moving between networks.
            let info = ServiceInfo::new(
                MDNS_SERVICE,
                &instance,
                &format!("{instance}.local."),
                "",
                port,
                &props[..],
            )
            .map_err(|e| Error::Cbor(format!("mdns service info: {e}")))?
            .enable_addr_auto();

            let fullname = info.get_fullname().to_owned();
            self.daemon
                .register(info)
                .map_err(|e| Error::Cbor(format!("mdns register: {e}")))?;
            self.registered_fullname = Some(fullname);
            Ok(())
        }

        fn stop_advertising(&mut self) -> Result<()> {
            if let Some(full) = self.registered_fullname.take() {
                self.daemon
                    .unregister(&full)
                    .map_err(|e| Error::Cbor(format!("mdns unregister: {e}")))?;
            }
            Ok(())
        }
    }

    impl Drop for MdnsDiscovery {
        fn drop(&mut self) {
            let _ = self.stop_advertising();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn id() -> DeviceId {
        DeviceId([0xAB; 16])
    }

    #[test]
    fn txt_round_trips() {
        let t = TxtRecord::new(id(), "SAMMAMISH-PC");
        let pairs = t.to_pairs();
        let borrowed: Vec<(&str, &str)> = pairs
            .iter()
            .map(|(k, v)| (k.as_str(), v.as_str()))
            .collect();
        assert_eq!(TxtRecord::parse(borrowed).unwrap(), t);
    }

    #[test]
    fn txt_pairs_match_protocol_keys() {
        let pairs = TxtRecord::new(id(), "PC").to_pairs();
        let keys: Vec<&str> = pairs.iter().map(|(k, _)| k.as_str()).collect();
        assert_eq!(keys, vec!["v", "id", "nm"]);
        assert_eq!(pairs[0].1, "1");
        assert_eq!(pairs[1].1, id().hex());
    }

    #[test]
    fn txt_rejects_missing_or_bad_fields() {
        assert!(
            TxtRecord::parse(vec![("id", &*id().hex())]).is_err(),
            "missing v"
        );
        assert!(TxtRecord::parse(vec![("v", "1")]).is_err(), "missing id");
        assert!(
            TxtRecord::parse(vec![("v", "1"), ("id", "zzzz")]).is_err(),
            "non-hex id"
        );
        assert!(
            TxtRecord::parse(vec![("v", "1"), ("id", "aabb")]).is_err(),
            "short id"
        );
    }

    #[test]
    fn txt_rejects_other_protocol_versions() {
        let hex = id().hex();
        assert!(TxtRecord::parse(vec![("v", "2"), ("id", &*hex)]).is_err());
    }

    #[test]
    fn txt_ignores_unknown_keys() {
        let hex = id().hex();
        let t = TxtRecord::parse(vec![
            ("v", "1"),
            ("id", &*hex),
            ("nm", "PC"),
            ("future", "whatever"),
        ])
        .unwrap();
        assert_eq!(t.name, "PC");
    }

    #[test]
    fn txt_tolerates_missing_name() {
        // nm is display-only; a peer without one is still dialable.
        let hex = id().hex();
        let t = TxtRecord::parse(vec![("v", "1"), ("id", &*hex)]).unwrap();
        assert_eq!(t.name, "");
    }

    #[test]
    fn name_is_capped_at_32_bytes() {
        let long = "A".repeat(100);
        let t = TxtRecord::new(id(), &long);
        assert_eq!(t.name.len(), MAX_NAME_BYTES);
    }

    #[test]
    fn name_truncation_respects_char_boundaries() {
        // 20 × 2-byte chars = 40 bytes; the cut lands mid-character if done by bytes.
        let name = "ü".repeat(20);
        let t = TxtRecord::new(id(), &name);
        assert!(t.name.len() <= MAX_NAME_BYTES);
        assert!(std::str::from_utf8(t.name.as_bytes()).is_ok());
        assert!(t.name.chars().all(|c| c == 'ü'));

        // 4-byte emoji: 32 is not a multiple of 4 boundary-wise past 8 chars.
        let emoji = "🚀".repeat(20);
        let t = TxtRecord::new(id(), &emoji);
        assert_eq!(t.name.chars().count(), 8, "8 × 4 bytes = 32");
    }

    #[test]
    fn short_name_is_untouched() {
        assert_eq!(truncate_name("PC"), "PC");
    }

    #[test]
    fn instance_name_is_the_device_id_hex() {
        assert_eq!(instance_name(&id()), id().hex());
        assert_eq!(MDNS_SERVICE, "_airclip._tcp.local.");
    }

    /// Two in-process daemons discovering each other (T-05 acceptance).
    ///
    /// Needs working multicast, which many CI sandboxes and Windows firewall profiles
    /// deny — so a failure to bind is a skip, not a test failure. Set
    /// `AIRCLIP_REQUIRE_MDNS=1` to make the skip fatal (used by the Linux CI job).
    #[cfg(feature = "mdns")]
    #[test]
    fn two_instances_discover_each_other() {
        use std::time::{Duration, Instant};

        let require = std::env::var("AIRCLIP_REQUIRE_MDNS").is_ok();

        let (mut advertiser, browser) = match (MdnsDiscovery::new(), MdnsDiscovery::new()) {
            (Ok(a), Ok(b)) => (a, b),
            _ => {
                assert!(!require, "mDNS required but the daemon would not start");
                eprintln!("skipping: no multicast available");
                return;
            }
        };

        let device = DeviceId([0x11; 16]);
        if advertiser.advertise(&device, "TEST-PC", 49517).is_err() {
            assert!(!require, "mDNS required but advertise failed");
            eprintln!("skipping: advertise failed");
            return;
        }

        let rx = match browser.browse() {
            Ok(rx) => rx,
            Err(_) => {
                assert!(!require, "mDNS required but browse failed");
                eprintln!("skipping: browse failed");
                return;
            }
        };

        let deadline = Instant::now() + Duration::from_secs(10);
        let mut found = None;
        while Instant::now() < deadline {
            match rx.recv_timeout(Duration::from_millis(500)) {
                Ok(hint) if hint.device_id == device => {
                    found = Some(hint);
                    break;
                }
                Ok(_) => continue,
                Err(std::sync::mpsc::RecvTimeoutError::Timeout) => continue,
                Err(_) => break,
            }
        }

        match found {
            Some(hint) => {
                assert_eq!(hint.name, "TEST-PC");
                assert!(!hint.addrs.is_empty());
                assert!(hint.addrs.iter().all(|a| a.port() == 49517));
            }
            None => {
                assert!(!require, "mDNS required but no peer was discovered");
                eprintln!("skipping: no peer discovered (multicast likely blocked)");
            }
        }
    }
}
