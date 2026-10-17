//! Minimal DNS forwarder for the private kernel.
//!
//! The kernel has to resolve a hostname before it can dial a node, and on poisoned networks
//! the OS resolver answers with dead addresses. Mihomo exposes no way to send a DNS query
//! through a proxy, and its DNS client dials resolvers itself, so a DoH endpoint has to be
//! reachable from this machine - which rules out any overseas resolver - while resolvers
//! that *are* reachable from here (mainland public DNS) answer with poisoned records of
//! their own. Measured: every mainland DoH endpoint returned a dead address for
//! `api.openai.com`, while Cloudflare returned the real one once the query travelled
//! through the node.
//!
//! This module closes that gap with a loopback resolver whose upstream is Cloudflare DoH
//! dialled **through the private kernel**. Because the upstream is written as an address
//! literal, the kernel never needs to resolve anything to reach its own resolver, so the
//! forwarder cannot deadlock against it.
//!
//! Scope, deliberately narrow:
//! * binds `127.0.0.1` on an ephemeral port - never port 53, never a wildcard address;
//! * performs no system DNS, proxy or route changes of any kind;
//! * carries no credentials and holds no state beyond an in-memory failure counter.
//!
//! It does not authenticate callers: any process running as this user could reach it over
//! loopback. That is why it is documented as "serves the kernel", not "private to the
//! kernel" - see the module notes in the analysis folder.

use anyhow::{Context, Result, bail};
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::sync::Semaphore;
use tokio::task::JoinHandle;

/// Cloudflare's resolver, addressed literally. An address literal keeps this forwarder free
/// of bootstrap resolution and therefore free of a cycle through the kernel.
const DOH_ENDPOINT: &str = "https://1.1.1.1/dns-query";

/// Receive buffer. Larger than [`MAX_DATAGRAM`] so an oversized datagram is reported by the
/// OS instead of being silently truncated into something that looks valid.
const RECEIVE_BUFFER: usize = 1232;

/// Largest datagram accepted. Standard DNS over UDP is 512 bytes; anything larger is
/// dropped rather than parsed.
const MAX_DATAGRAM: usize = 512;

/// Longest name accepted, matching the RFC 1035 wire limit.
const MAX_NAME: usize = 255;

/// Cap on answers returned in one datagram, so the response stays within [`MAX_DATAGRAM`].
const MAX_ANSWERS: usize = 12;

/// Concurrent upstream lookups. Beyond this a query fails fast instead of piling up.
const MAX_IN_FLIGHT: usize = 32;

/// Consecutive upstream failures after which the caller should stop using this resolver.
pub const FAILURE_LIMIT: usize = 8;

/// TTL handed back with each answer. Short enough that a recovering node is picked up
/// quickly, long enough that the kernel does not re-query per connection.
const ANSWER_TTL: u32 = 60;

/// A running forwarder. Dropping it stops the resolver task.
pub struct Forwarder {
    address: SocketAddr,
    failures: Arc<AtomicUsize>,
    task: JoinHandle<()>,
}

impl Forwarder {
    /// Loopback address the kernel should use as its resolver.
    pub fn address(&self) -> SocketAddr {
        self.address
    }

    /// Handle on the consecutive-failure counter. The caller watches it so it can fall back
    /// before the kernel spends its whole timeout on a resolver that stopped answering.
    pub fn failures_counter(&self) -> Arc<AtomicUsize> {
        Arc::clone(&self.failures)
    }
}

impl Drop for Forwarder {
    fn drop(&mut self) {
        self.task.abort();
    }
}

/// Starts a forwarder whose upstream DoH traffic leaves through the private kernel on
/// `proxy_port`.
pub async fn start(proxy_port: u16, password: &str) -> Result<Forwarder> {
    let socket = Arc::new(
        UdpSocket::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
            .await
            .context("cannot bind the dedicated resolver port")?,
    );
    let address = socket
        .local_addr()
        .context("cannot read the dedicated resolver port")?;
    let client = client(proxy_port, password)?;
    let failures = Arc::new(AtomicUsize::new(0));
    let in_flight = Arc::new(Semaphore::new(MAX_IN_FLIGHT));
    let counter = Arc::clone(&failures);
    let task = tokio::spawn(async move {
        // This task must never exit: losing it would leave the kernel without a resolver.
        // Every failure below is contained to a single query.
        loop {
            let mut buffer = [0u8; RECEIVE_BUFFER];
            let (length, peer) = match socket.recv_from(&mut buffer).await {
                Ok(value) => value,
                Err(_) => {
                    // A persistent error must not turn this into a busy loop.
                    tokio::time::sleep(Duration::from_millis(50)).await;
                    continue;
                }
            };
            if length > MAX_DATAGRAM {
                continue;
            }
            let query = buffer[..length].to_vec();
            let socket = Arc::clone(&socket);
            let client = client.clone();
            let counter = Arc::clone(&counter);
            let in_flight = Arc::clone(&in_flight);
            tokio::spawn(async move {
                // Bound concurrent upstream work. Without this, a burst of names would open
                // a matching burst of TLS connections through the kernel.
                let response = match in_flight.try_acquire_owned() {
                    Ok(_permit) => answer(&client, &query, &counter).await,
                    Err(_) => {
                        if query.len() >= 12 {
                            refuse(u16::from_be_bytes([query[0], query[1]]), 2)
                        } else {
                            Vec::new()
                        }
                    }
                };
                if !response.is_empty() {
                    let _ = socket.send_to(&response, peer).await;
                }
            });
        }
    });
    Ok(Forwarder {
        address,
        failures,
        task,
    })
}

/// Builds a client whose only route out is the private kernel.
fn client(proxy_port: u16, password: &str) -> Result<reqwest::Client> {
    let mut proxy = reqwest::Proxy::https(format!("http://127.0.0.1:{proxy_port}"))
        .map_err(|_| anyhow::anyhow!("cannot address the dedicated resolver proxy"))?;
    if !password.is_empty() {
        proxy = proxy.basic_auth("codex", password);
    }
    reqwest::Client::builder()
        .proxy(proxy)
        // A redirect to a plain http URL would fall outside `Proxy::https` and leave this
        // machine directly, which is exactly what this forwarder exists to avoid.
        .redirect(reqwest::redirect::Policy::none())
        .https_only(true)
        .timeout(Duration::from_secs(10))
        .build()
        .context("cannot build the dedicated resolver client")
}

/// Answers one query, returning the wire response (empty when the query is unusable).
async fn answer(client: &reqwest::Client, query: &[u8], counter: &AtomicUsize) -> Vec<u8> {
    let Some(parsed) = parse(query) else {
        // Unparseable datagrams still get a FORMERR so the caller fails fast instead of
        // waiting for its own timeout.
        return if query.len() >= 12 {
            refuse(u16::from_be_bytes([query[0], query[1]]), 1)
        } else {
            Vec::new()
        };
    };
    // Only A queries are forwarded. Anything else is answered "no records" so the kernel
    // moves on instead of waiting on a lookup this forwarder does not implement, and so an
    // AAAA question can never be answered with addresses of the wrong family.
    if parsed.qtype != 1 {
        return respond(query, &parsed, &[], 0);
    }
    match lookup(client, &parsed.name).await {
        Ok((addresses, rcode)) => {
            counter.store(0, Ordering::Relaxed);
            respond(query, &parsed, &addresses, rcode)
        }
        Err(_) => {
            // Count only real upstream/transport failures, so a name that genuinely does
            // not exist never trips the fallback.
            let _ = counter.fetch_add(1, Ordering::Relaxed);
            respond(query, &parsed, &[], 2) // SERVFAIL -> kernel tries the next source
        }
    }
}

struct Query {
    id: u16,
    flags: u16,
    name: String,
    qtype: u16,
    /// End of the question section, so the response can echo it byte for byte.
    question_end: usize,
}

/// Parses the header and the single question of a query.
fn parse(query: &[u8]) -> Option<Query> {
    if query.len() < 12 {
        return None;
    }
    let id = u16::from_be_bytes([query[0], query[1]]);
    let flags = u16::from_be_bytes([query[2], query[3]]);
    if flags & 0x8000 != 0 {
        return None; // a response, not a query
    }
    if u16::from_be_bytes([query[4], query[5]]) != 1 {
        return None; // exactly one question, or we do not answer it
    }
    let mut offset = 12usize;
    let mut labels: Vec<String> = Vec::new();
    loop {
        if offset >= query.len() {
            return None;
        }
        let length = query[offset] as usize;
        if length == 0 {
            offset += 1;
            break;
        }
        // RFC 1035: the two top bits mark a compression pointer, which has no meaning in a
        // question, and a label is at most 63 bytes.
        if length & 0b1100_0000 != 0 || length > 63 {
            return None;
        }
        let start = offset + 1;
        let end = start.checked_add(length)?;
        if end > query.len() || end > 12 + MAX_NAME {
            return None;
        }
        let label = std::str::from_utf8(&query[start..end]).ok()?;
        // Defence in depth: keep the alphabet that can reach the upstream URL predictable.
        if !label
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
        {
            return None;
        }
        labels.push(label.to_ascii_lowercase());
        offset = end;
    }
    if labels.is_empty() || offset + 4 > query.len() {
        return None;
    }
    let qtype = u16::from_be_bytes([query[offset], query[offset + 1]]);
    let qclass = u16::from_be_bytes([query[offset + 2], query[offset + 3]]);
    if qclass != 1 {
        return None; // only the IN class is forwarded
    }
    Some(Query {
        id,
        flags,
        name: labels.join("."),
        qtype,
        question_end: offset + 4,
    })
}

/// Looks a name up over DoH through the private kernel, returning the addresses and the
/// upstream response code so NXDOMAIN is not reported as a server failure.
async fn lookup(client: &reqwest::Client, name: &str) -> Result<(Vec<Ipv4Addr>, u8)> {
    let response = client
        .get(DOH_ENDPOINT)
        .header("accept", "application/dns-json")
        .query(&[("name", name), ("type", "1")])
        .send()
        .await
        .context("dedicated resolver request failed")?;
    if !response.status().is_success() {
        bail!(
            "dedicated resolver answered HTTP {}",
            response.status().as_u16()
        );
    }
    let body: serde_json::Value = response
        .json()
        .await
        .context("dedicated resolver body unreadable")?;
    // RFC 8484: `Status` is the authoritative response code.
    let rcode = u8::try_from(body.get("Status").and_then(|value| value.as_u64()).unwrap_or(2))
        .unwrap_or(2);
    let mut addresses = Vec::new();
    if let Some(answers) = body.get("Answer").and_then(|value| value.as_array()) {
        for answer in answers {
            let is_a_record = answer.get("type").and_then(|value| value.as_u64()) == Some(1);
            if !is_a_record {
                continue;
            }
            if let Some(data) = answer.get("data").and_then(|value| value.as_str())
                && let Ok(address) = data.parse::<Ipv4Addr>()
            {
                addresses.push(address);
            }
        }
    }
    // No addresses with a success code is a legitimate NODATA answer, not a failure.
    if addresses.is_empty() && rcode != 0 {
        bail!("dedicated resolver returned rcode {rcode} for {name}");
    }
    Ok((addresses, rcode))
}

/// Header-only response, used when the query itself could not be parsed.
fn refuse(id: u16, rcode: u8) -> Vec<u8> {
    let mut out = Vec::with_capacity(12);
    out.extend_from_slice(&id.to_be_bytes());
    let flags = 0x8000 | 0x0080 | u16::from(rcode & 0x0F);
    out.extend_from_slice(&flags.to_be_bytes());
    out.extend_from_slice(&0u16.to_be_bytes()); // QDCOUNT
    out.extend_from_slice(&0u16.to_be_bytes()); // ANCOUNT
    out.extend_from_slice(&0u16.to_be_bytes()); // NSCOUNT
    out.extend_from_slice(&0u16.to_be_bytes()); // ARCOUNT
    out
}

/// Builds the response datagram: header, the question echoed verbatim, then the answers.
fn respond(query: &[u8], parsed: &Query, addresses: &[Ipv4Addr], rcode: u8) -> Vec<u8> {
    let keep = addresses.len().min(MAX_ANSWERS);
    let truncated = keep < addresses.len();
    let mut out = Vec::with_capacity(parsed.question_end + 16 * keep);
    out.extend_from_slice(&parsed.id.to_be_bytes());
    // QR + RA, keep RD, drop AA, then the response code; TC marks a truncated answer.
    let mut flags = 0x8000 | 0x0080 | (parsed.flags & 0x0100) | u16::from(rcode & 0x0F);
    if truncated {
        flags |= 0x0200;
    }
    out.extend_from_slice(&flags.to_be_bytes());
    out.extend_from_slice(&1u16.to_be_bytes());
    out.extend_from_slice(&(u16::try_from(keep).unwrap_or(0)).to_be_bytes());
    out.extend_from_slice(&0u16.to_be_bytes()); // NSCOUNT
    out.extend_from_slice(&0u16.to_be_bytes()); // ARCOUNT
    out.extend_from_slice(&query[12..parsed.question_end]);
    for address in &addresses[..keep] {
        out.extend_from_slice(&[0xC0, 0x0C]); // pointer to the name in the question
        out.extend_from_slice(&1u16.to_be_bytes()); // TYPE  = A
        out.extend_from_slice(&1u16.to_be_bytes()); // CLASS = IN
        out.extend_from_slice(&ANSWER_TTL.to_be_bytes());
        out.extend_from_slice(&4u16.to_be_bytes()); // RDLENGTH
        out.extend_from_slice(&address.octets());
    }
    if out.len() > MAX_DATAGRAM {
        out.truncate(MAX_DATAGRAM);
        out[2] |= 0x02; // TC: the caller should retry over TCP
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn query(name: &str) -> Vec<u8> {
        let mut out = vec![0xAB, 0xCD, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0];
        for label in name.split('.') {
            out.push(label.len() as u8);
            out.extend_from_slice(label.as_bytes());
        }
        out.push(0);
        out.extend_from_slice(&1u16.to_be_bytes()); // QTYPE  = A
        out.extend_from_slice(&1u16.to_be_bytes()); // QCLASS = IN
        out
    }

    #[test]
    fn parses_a_well_formed_question() {
        let parsed = parse(&query("chatgpt.com")).expect("should parse");
        assert_eq!(parsed.name, "chatgpt.com");
        assert_eq!(parsed.qtype, 1);
        assert_eq!(parsed.id, 0xABCD);
        assert_eq!(parsed.question_end, query("chatgpt.com").len());
    }

    #[test]
    fn rejects_oversized_labels_and_pointers() {
        let mut malformed = vec![0xAB, 0xCD, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0];
        malformed.push(0x41); // 65 bytes: above the 63-byte label limit
        malformed.extend_from_slice(&[b'a'; 65]);
        malformed.push(0);
        malformed.extend_from_slice(&1u16.to_be_bytes());
        malformed.extend_from_slice(&1u16.to_be_bytes());
        assert!(parse(&malformed).is_none());

        let mut pointer = query("chatgpt.com");
        pointer[13] = 0xC0; // compression pointer where a length is expected
        assert!(parse(&pointer).is_none());
    }

    #[test]
    fn rejects_responses_and_truncated_datagrams() {
        let mut response = query("chatgpt.com");
        response[2] = 0x81; // QR bit set
        assert!(parse(&response).is_none());
        assert!(parse(&query("chatgpt.com")[..11]).is_none());

        let mut cut = query("chatgpt.com");
        cut.truncate(18); // question section runs past the end
        assert!(parse(&cut).is_none());
    }

    #[test]
    fn answer_stays_within_the_udp_limit() {
        let query = query("chatgpt.com");
        let parsed = parse(&query).expect("should parse");
        let many: Vec<Ipv4Addr> = (0..40)
            .map(|index| Ipv4Addr::new(104, 18, 32, index))
            .collect();
        let out = respond(&query, &parsed, &many, 0);
        assert!(out.len() <= MAX_DATAGRAM);
        assert_ne!(out[2] & 0x02, 0, "truncated answers must set TC");
        let answers = u16::from_be_bytes([out[6], out[7]]);
        assert_eq!(usize::from(answers), MAX_ANSWERS);
    }

    #[test]
    fn servfail_and_formerr_are_well_formed() {
        let query = query("chatgpt.com");
        let parsed = parse(&query).expect("should parse");
        let out = respond(&query, &parsed, &[], 2);
        assert_eq!(out[3] & 0x0F, 2);
        let refused = refuse(0xABCD, 1);
        assert_eq!(refused.len(), 12);
        assert_eq!(refused[3] & 0x0F, 1);
    }
}
