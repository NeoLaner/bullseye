//! Country address ranges, read out of the `geoip.dat` an xray or v2ray install
//! already ships.
//!
//! This is what "allow every .ir domain" has to become. A ruleset holds addresses
//! and not names, so a domain suffix cannot be a hole at all — the country a ccTLD
//! names can be, and the file that says where a country is happens to be sitting on
//! the disk already, put there by the VPN client whose own routing uses it to
//! decide what goes direct. Reading the same file is what stops the kill switch and
//! the VPN disagreeing about where Iran is.
//!
//! The format is protocol buffers, and the reader below is the whole of it that
//! matters: it walks a message looking for a country code and reads the CIDRs under
//! it. Nothing here writes one, so a build-time dependency to skip four fields would
//! cost more than it saves.

use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};

/// Where an xray or v2ray install leaves the database, searched in order. A client
/// that unpacks itself somewhere else is the normal case rather than a broken
/// install, which is what `[bypass] geoip` in the config is for.
const KNOWN: [&str; 6] = [
    "/usr/share/xray/geoip.dat",
    "/usr/share/v2ray/geoip.dat",
    "/usr/local/share/xray/geoip.dat",
    "/opt/v2rayn-bin/bin/xray/geoip.dat",
    "/opt/v2rayn-bin/bin/geoip.dat",
    "/opt/v2ray/geoip.dat",
];

/// A configured path is returned whether or not it exists, so that a path the user
/// got wrong fails saying so instead of quietly reading a different database.
pub fn database(configured: Option<&Path>) -> Option<PathBuf> {
    match configured {
        Some(path) => Some(path.to_owned()),
        None => KNOWN
            .iter()
            .map(Path::new)
            .find(|known| known.exists())
            .map(Path::to_owned),
    }
}

/// Every IPv4 range a country covers. IPv6 is ADR-0001's wholesale case, so the v6
/// half of the database is dropped like every other v6 hole in v0.1.
pub fn ranges(code: &str, path: &Path) -> Result<Vec<String>, String> {
    let database = std::fs::read(path).map_err(|e| format!("{}: {e}", path.display()))?;
    find(code, &database).ok_or_else(|| {
        format!(
            "{} has no country {code:?} in it — the code is the two letters of a \
             ccTLD, as in geoip:ir",
            path.display()
        )
    })
}

/// `GeoIPList { repeated GeoIP entry = 1 }`, and the first entry whose country
/// matches. Every other country is stepped over rather than parsed: the file is
/// seventeen megabytes and two hundred and seventy-eight countries, and this runs
/// on every arm and every daemon tick.
fn find(code: &str, database: &[u8]) -> Option<Vec<String>> {
    let mut at = 0;
    while let Some((number, payload, next)) = field(database, at) {
        at = next;
        if let (1, Payload::Block(entry)) = (number, payload)
            && country_of(entry).is_some_and(|found| found.eq_ignore_ascii_case(code))
        {
            return Some(cidrs(entry));
        }
    }
    None
}

/// `GeoIP { string country_code = 1; repeated CIDR cidr = 2; ... }` — the two
/// fields this cares about, found by number rather than by position.
fn country_of(entry: &[u8]) -> Option<&str> {
    let mut at = 0;
    while let Some((number, payload, next)) = field(entry, at) {
        at = next;
        if let (1, Payload::Block(code)) = (number, payload) {
            return std::str::from_utf8(code).ok();
        }
    }
    None
}

fn cidrs(entry: &[u8]) -> Vec<String> {
    let mut ranges = Vec::new();
    let mut at = 0;
    while let Some((number, payload, next)) = field(entry, at) {
        at = next;
        if let (2, Payload::Block(cidr)) = (number, payload) {
            ranges.extend(range(cidr));
        }
    }
    ranges
}

/// `CIDR { bytes ip = 1; uint32 prefix = 2 }`. Two shapes are dropped rather than
/// returned: a sixteen-byte address, which is IPv6, and a prefix of zero, which
/// protobuf also spells by leaving the field out — a `/0` matches every destination
/// and would turn the kill switch off rather than open a hole in it.
fn range(cidr: &[u8]) -> Option<String> {
    let mut address = None;
    let mut prefix = 0;
    let mut at = 0;
    while let Some((number, payload, next)) = field(cidr, at) {
        at = next;
        match (number, payload) {
            (1, Payload::Block(ip)) => address = <[u8; 4]>::try_from(ip).ok().map(Ipv4Addr::from),
            (2, Payload::Number(bits)) => prefix = bits,
            _ => {}
        }
    }
    let address = address?;
    (1..=32).contains(&prefix).then(|| format!("{address}/{prefix}"))
}

/// What a protobuf field carries — only the two wire types this file uses.
enum Payload<'a> {
    Number(u64),
    Block(&'a [u8]),
}

/// The field at `at`: its number, its payload, and where the next one starts. None
/// at the end of a message and on anything malformed, so a truncated or unexpected
/// file reads as "no such country" rather than as a hole.
fn field(bytes: &[u8], at: usize) -> Option<(u64, Payload<'_>, usize)> {
    let (tag, at) = varint(bytes, at)?;
    match tag & 7 {
        0 => {
            let (value, next) = varint(bytes, at)?;
            Some((tag >> 3, Payload::Number(value), next))
        }
        2 => {
            let (length, at) = varint(bytes, at)?;
            let end = at.checked_add(usize::try_from(length).ok()?)?;
            Some((tag >> 3, Payload::Block(bytes.get(at..end)?), end))
        }
        _ => None,
    }
}

/// Seven bits a byte, low group first, until a byte with the top bit clear. Ten
/// groups is the whole of a u64; an eleventh means the file is not one.
fn varint(bytes: &[u8], mut at: usize) -> Option<(u64, usize)> {
    let mut value = 0;
    for shift in (0..64).step_by(7) {
        let byte = *bytes.get(at)?;
        at += 1;
        value |= u64::from(byte & 0x7f) << shift;
        if byte & 0x80 == 0 {
            return Some((value, at));
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    /// One length-delimited field: tag, length, bytes. Everything built here is well
    /// under 128 bytes, so a one-byte length is the whole encoder the tests need.
    fn block(number: u8, bytes: &[u8]) -> Vec<u8> {
        let mut out = vec![number << 3 | 2, bytes.len() as u8];
        out.extend(bytes);
        out
    }

    /// A one-country database, so the reader is tested against the shape it claims
    /// to read rather than against whichever geoip.dat this machine happens to have.
    fn database_of(code: &str, cidrs: &[(&[u8], u8)]) -> Vec<u8> {
        let mut entry = block(1, code.as_bytes());
        for (ip, prefix) in cidrs {
            let mut cidr = block(1, ip);
            cidr.extend([2 << 3, *prefix]); // field 2, a varint prefix
            entry.extend(block(2, &cidr));
        }
        block(1, &entry)
    }

    #[test]
    fn a_country_reads_back_as_its_ipv4_ranges_and_nothing_else() {
        let database = database_of(
            "IR",
            &[
                (&[2, 144, 0, 0], 14),
                (&[0x24, 0x8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0], 32), // v6
                (&[178, 216, 248, 0], 21),
            ],
        );
        assert_eq!(
            find("ir", &database),
            Some(vec!["2.144.0.0/14".to_owned(), "178.216.248.0/21".to_owned()])
        );
        assert!(find("us", &database).is_none());
    }

    /// Every range becomes an `accept` in a root ruleset, so nothing that would
    /// widen one past the country may come out of here: a `/0` is the kill switch's
    /// off switch, and a truncated file must read as no country rather than as one
    /// with a hole in it.
    #[test]
    fn nothing_the_reader_returns_can_widen_past_the_country() {
        let wide = database_of("IR", &[(&[0, 0, 0, 0], 0), (&[10, 0, 0, 0], 8)]);
        assert_eq!(find("ir", &wide), Some(vec!["10.0.0.0/8".to_owned()]));

        let whole = database_of("IR", &[(&[10, 0, 0, 0], 8)]);
        for cut in 1..whole.len() {
            let ranges = find("ir", &whole[..cut]).unwrap_or_default();
            assert!(
                ranges.iter().all(|range| crate::rules::address(range).is_ok()),
                "{cut}: {ranges:?}"
            );
        }
    }
}
