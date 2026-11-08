//! pkt-line framing, protocol version negotiation and protocol v2 requests.
//!
//! Framing follows `Documentation/gitprotocol-common.txt`: a four-byte hex
//! length counts itself, `0000` is a flush, `0001` a delimiter (v2 argument
//! sections) and `0002` a response-end. Data packets may not exceed 65520
//! bytes in total. Decoding is total: malformed input yields a typed
//! [`GitError::Protocol`], never a panic.

use bytes::Bytes;

use crate::config::ObjectFormat;
use crate::error::GitError;
use crate::git::is_full_sha;

/// Largest legal pkt-line, length header included.
pub const MAX_PKT_LEN: usize = 65_520;

/// The smart-HTTP service named in the request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Service {
    UploadPack,
    ReceivePack,
}

impl Service {
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "git-upload-pack" => Some(Self::UploadPack),
            "git-receive-pack" => Some(Self::ReceivePack),
            _ => None,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::UploadPack => "git-upload-pack",
            Self::ReceivePack => "git-receive-pack",
        }
    }

    pub fn program(self) -> &'static str {
        match self {
            Self::UploadPack => "upload-pack",
            Self::ReceivePack => "receive-pack",
        }
    }
}

/// Wire protocol version negotiated through `Git-Protocol`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Protocol {
    #[default]
    V0,
    V2,
}

impl Protocol {
    /// Read the `Git-Protocol` header (`version=2`, optionally with more
    /// colon-separated parameters).
    pub fn from_header(value: Option<&str>) -> Self {
        match value {
            Some(header) if header.split(':').any(|part| part.trim() == "version=2") => Self::V2,
            _ => Self::V0,
        }
    }

    /// The `GIT_PROTOCOL` environment pair to pass to git, if any.
    pub fn git_protocol_env(self) -> Option<(&'static str, &'static str)> {
        match self {
            Self::V0 => None,
            Self::V2 => Some(("GIT_PROTOCOL", "version=2")),
        }
    }

    /// Value for the `Git-Protocol` response header (always the maximum the
    /// client asked for).
    pub fn as_str(self) -> &'static str {
        match self {
            Self::V0 => "version=0",
            Self::V2 => "version=2",
        }
    }
}

/// Convenience for callers that only need the environment pair.
pub fn git_protocol_env(protocol: Protocol) -> Option<(&'static str, &'static str)> {
    protocol.git_protocol_env()
}

/// One parsed pkt-line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PktLine {
    Data(Bytes),
    Flush,
    Delim,
    ResponseEnd,
}

/// Read the next pkt-line from `body`, returning it and the bytes consumed.
///
/// Fewer than four bytes left is not an error: callers loop until a flush and
/// then use the reported offset as the start of raw payload (a packfile).
pub fn read_pkt(body: &[u8]) -> Result<Option<(PktLine, usize)>, GitError> {
    if body.len() < 4 {
        return Ok(None);
    }
    if !body[..4].iter().all(u8::is_ascii_hexdigit) {
        return Err(GitError::Protocol(format!(
            "pkt length is not four hex digits: {:?}",
            String::from_utf8_lossy(&body[..4])
        )));
    }
    let len_hex = std::str::from_utf8(&body[..4])
        .map_err(|_| GitError::Protocol("pkt length is not UTF-8".into()))?;
    let len = usize::from_str_radix(len_hex, 16)
        .map_err(|_| GitError::Protocol(format!("bad pkt length {len_hex:?}")))?;
    match len {
        0 => Ok(Some((PktLine::Flush, 4))),
        1 => Ok(Some((PktLine::Delim, 4))),
        2 => Ok(Some((PktLine::ResponseEnd, 4))),
        3 => Err(GitError::Protocol("reserved pkt length 3".into())),
        _ if len > MAX_PKT_LEN => Err(GitError::Protocol(format!(
            "pkt length {len} exceeds the {MAX_PKT_LEN}-byte maximum"
        ))),
        _ if len > body.len() => Err(GitError::Protocol(format!(
            "pkt length {len} exceeds the {} remaining bytes",
            body.len()
        ))),
        _ => Ok(Some((
            PktLine::Data(Bytes::copy_from_slice(&body[4..len])),
            len,
        ))),
    }
}

/// Iterate every pkt-line until a flush, returning the data lines and the
/// bytes consumed (flush included).
pub fn read_until_flush(body: &[u8]) -> Result<(Vec<Bytes>, usize), GitError> {
    let mut items = Vec::new();
    let mut offset = 0;
    loop {
        let Some((line, used)) = read_pkt(&body[offset..])? else {
            return Err(GitError::Protocol(
                "pkt-line stream ended before its flush".into(),
            ));
        };
        offset += used;
        match line {
            PktLine::Data(data) => items.push(data),
            PktLine::Flush => return Ok((items, offset)),
            PktLine::Delim => {
                return Err(GitError::Protocol(
                    "unexpected delimiter in a pkt-line stream".into(),
                ));
            }
            PktLine::ResponseEnd => {
                return Err(GitError::Protocol(
                    "unexpected response-end in a pkt-line stream".into(),
                ));
            }
        }
    }
}

/// Encode one data pkt-line, failing when the payload cannot fit.
pub fn try_pkt_line(payload: &[u8]) -> Result<Vec<u8>, GitError> {
    let total = payload.len() + 4;
    if total > MAX_PKT_LEN {
        return Err(GitError::Protocol(format!(
            "pkt-line payload of {} bytes exceeds the {MAX_PKT_LEN}-byte maximum",
            payload.len()
        )));
    }
    let mut out = format!("{total:04x}").into_bytes();
    out.extend_from_slice(payload);
    Ok(out)
}

/// Encode one data pkt-line.
///
/// # Panics
///
/// Panics when the payload cannot fit a pkt-line. Internal callers frame small
/// status lines; bulk payloads go through [`try_pkt_line`] or sideband
/// chunking.
pub fn pkt_line(payload: &[u8]) -> Vec<u8> {
    try_pkt_line(payload).expect("pkt-line payload exceeds 65516 bytes")
}

/// Encode a string pkt-line, adding the trailing newline.
pub fn pkt_line_str(payload: &str) -> Vec<u8> {
    let mut line = payload.as_bytes().to_vec();
    line.push(b'\n');
    pkt_line(&line)
}

/// [`pkt_line_str`] without panicking on oversized payloads.
pub fn try_pkt_line_str(payload: &str) -> Result<Vec<u8>, GitError> {
    let mut line = payload.as_bytes().to_vec();
    line.push(b'\n');
    try_pkt_line(&line)
}

pub fn flush_pkt() -> &'static [u8] {
    b"0000"
}

pub fn delim_pkt() -> &'static [u8] {
    b"0001"
}

pub fn response_end_pkt() -> &'static [u8] {
    b"0002"
}

/// v2 capability advertisement with the default SHA-1 object format.
pub fn v2_capabilities(server_option: bool) -> Vec<u8> {
    v2_capabilities_for(ObjectFormat::Sha1, server_option)
}

/// v2 capability advertisement body (without the `# service` wrapper).
///
/// `object-format` must name the repository's hash; clients validate every
/// object id against it.
pub fn v2_capabilities_for(format: ObjectFormat, server_option: bool) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&pkt_line_str("version 2"));
    out.extend_from_slice(&pkt_line_str(&format!(
        "agent=ryuz_git/{}",
        env!("CARGO_PKG_VERSION")
    )));
    out.extend_from_slice(&pkt_line_str("ls-refs=unborn"));
    out.extend_from_slice(&pkt_line_str(
        "fetch=shallow wait-for-done filter ref-in-want sideband-all",
    ));
    out.extend_from_slice(&pkt_line_str(&format!("object-format={format}")));
    if server_option {
        out.extend_from_slice(&pkt_line_str("server-option"));
    }
    out.extend_from_slice(flush_pkt());
    out
}

/// v0 advertisement wrapper: `# service=<name>` then a flush, then the
/// advertisement proper (the `http-backend` framing).
pub fn wrap_advertise(service: Service, refs: &[u8]) -> Vec<u8> {
    let mut out = pkt_line_str(&format!("# service={}", service.as_str()));
    out.extend_from_slice(flush_pkt());
    out.extend_from_slice(refs);
    out
}

/// A parsed protocol v2 command request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct V2Request {
    pub command: V2Command,
    pub agent: Option<String>,
    pub object_format: ObjectFormat,
    pub server_options: Vec<String>,
}

/// The v2 command and its arguments.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum V2Command {
    LsRefs(LsRefsArgs),
    Fetch(FetchArgs),
}

/// Arguments of `command=ls-refs`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct LsRefsArgs {
    pub peel: bool,
    pub symrefs: bool,
    pub unborn: bool,
    pub ref_prefixes: Vec<String>,
}

/// Arguments of `command=fetch`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct FetchArgs {
    pub wants: Vec<String>,
    pub haves: Vec<String>,
    pub done: bool,
    pub thin: bool,
    pub no_progress: bool,
    pub include_tag: bool,
    pub ofs_delta: bool,
    pub filter: Option<String>,
    pub shallow: Vec<String>,
    pub deepen: Option<u32>,
    pub deepen_relative: bool,
    pub deepen_since: Option<i64>,
    pub deepen_not: Vec<String>,
    pub sideband_all: bool,
    pub want_refs: Vec<String>,
    pub wait_for_done: bool,
}

/// Parse a protocol v2 request body.
///
/// The capability section is `key=value` lines ending in a delimiter; the
/// command argument section ends in a flush. The object format declared by
/// the client (SHA-1 when absent) decides how wants, haves and shallow lines
/// are validated.
pub fn parse_v2_request(body: &[u8]) -> Result<V2Request, GitError> {
    let mut offset = 0;
    let mut command: Option<String> = None;
    let mut agent = None;
    let mut object_format = ObjectFormat::Sha1;
    let mut server_options = Vec::new();
    loop {
        let Some((line, used)) = read_pkt(&body[offset..])? else {
            return Err(GitError::Protocol(
                "v2 request ended before the capability delimiter".into(),
            ));
        };
        offset += used;
        match line {
            PktLine::Data(data) => {
                let text = pkt_text(&data, "v2 capability")?;
                let (key, value) = text.split_once('=').ok_or_else(|| {
                    GitError::Protocol(format!("v2 capability line without '=': {text:?}"))
                })?;
                match key {
                    "command" => {
                        if command.is_some() {
                            return Err(GitError::Protocol(
                                "v2 request names more than one command".into(),
                            ));
                        }
                        command = Some(value.to_string());
                    }
                    "agent" => agent = Some(validate_agent(value)?),
                    "object-format" => {
                        object_format = ObjectFormat::parse(value).ok_or_else(|| {
                            GitError::Protocol(format!("unknown object format {value:?}"))
                        })?;
                    }
                    "server-option" => {
                        validate_server_option(value)?;
                        server_options.push(value.to_string());
                    }
                    other => {
                        return Err(GitError::Protocol(format!(
                            "unknown v2 capability {other:?}"
                        )));
                    }
                }
            }
            PktLine::Delim => break,
            PktLine::Flush | PktLine::ResponseEnd => {
                return Err(GitError::Protocol(
                    "v2 capability section did not end with a delimiter".into(),
                ));
            }
        }
    }
    let command = command.ok_or_else(|| GitError::Protocol("v2 request has no command".into()))?;

    let mut args = Vec::new();
    loop {
        let Some((line, used)) = read_pkt(&body[offset..])? else {
            return Err(GitError::Protocol(
                "v2 argument section ended before its flush".into(),
            ));
        };
        offset += used;
        match line {
            PktLine::Data(data) => {
                args.push(pkt_text(&data, "v2 argument")?.to_string());
            }
            PktLine::Flush => break,
            PktLine::Delim | PktLine::ResponseEnd => {
                return Err(GitError::Protocol(
                    "unexpected delimiter in the v2 argument section".into(),
                ));
            }
        }
    }

    let command = match command.as_str() {
        "ls-refs" => V2Command::LsRefs(parse_ls_refs_args(&args)?),
        "fetch" => V2Command::Fetch(parse_fetch_args(&args, object_format)?),
        other => {
            return Err(GitError::Protocol(format!("unknown v2 command {other:?}")));
        }
    };
    Ok(V2Request {
        command,
        agent,
        object_format,
        server_options,
    })
}

fn pkt_text<'a>(data: &'a [u8], what: &str) -> Result<&'a str, GitError> {
    let data = data.strip_suffix(b"\n").unwrap_or(data);
    std::str::from_utf8(data).map_err(|_| GitError::Protocol(format!("{what} is not UTF-8")))
}

fn parse_ls_refs_args(args: &[String]) -> Result<LsRefsArgs, GitError> {
    let mut out = LsRefsArgs::default();
    for line in args {
        match line.as_str() {
            "peel" => out.peel = true,
            "symrefs" => out.symrefs = true,
            "unborn" => out.unborn = true,
            other => match split_arg(other, "ref-prefix")? {
                Arg::Value(prefix) => {
                    validate_ref_prefix(prefix)?;
                    out.ref_prefixes.push(prefix.to_string());
                }
                Arg::Wrong(arg) => {
                    return Err(GitError::Protocol(format!(
                        "unknown ls-refs argument {arg:?}"
                    )));
                }
            },
        }
    }
    Ok(out)
}

fn parse_fetch_args(args: &[String], format: ObjectFormat) -> Result<FetchArgs, GitError> {
    let mut out = FetchArgs::default();
    for line in args {
        match line.as_str() {
            "done" => out.done = true,
            "thin-pack" => out.thin = true,
            "no-progress" => out.no_progress = true,
            "include-tag" => out.include_tag = true,
            "ofs-delta" => out.ofs_delta = true,
            "deepen-relative" => out.deepen_relative = true,
            "sideband-all" => out.sideband_all = true,
            "wait-for-done" => out.wait_for_done = true,
            other => {
                if let Some(value) = one_value(other, "want")? {
                    validate_oid(value, format, "want")?;
                    out.wants.push(value.to_string());
                } else if let Some(value) = one_value(other, "have")? {
                    validate_oid(value, format, "have")?;
                    out.haves.push(value.to_string());
                } else if let Some(value) = one_value(other, "shallow")? {
                    validate_oid(value, format, "shallow")?;
                    out.shallow.push(value.to_string());
                } else if let Some(value) = one_value(other, "want-ref")? {
                    crate::git::validate_refname(value)?;
                    if !value.starts_with("refs/") {
                        return Err(GitError::Protocol(format!(
                            "want-ref must name a full ref: {value:?}"
                        )));
                    }
                    out.want_refs.push(value.to_string());
                } else if let Some(value) = one_value(other, "deepen-not")? {
                    crate::git::validate_refname(value)?;
                    out.deepen_not.push(value.to_string());
                } else if let Some(value) = one_value(other, "filter")? {
                    if out.filter.is_some() {
                        return Err(GitError::Protocol("duplicate filter argument".into()));
                    }
                    validate_token(value, 256, "filter")?;
                    out.filter = Some(value.to_string());
                } else if let Some(value) = one_value(other, "deepen")? {
                    if out.deepen.is_some() {
                        return Err(GitError::Protocol("duplicate deepen argument".into()));
                    }
                    let depth = value.parse::<u32>().map_err(|_| {
                        GitError::Protocol(format!("invalid deepen depth {value:?}"))
                    })?;
                    if depth == 0 {
                        return Err(GitError::Protocol("deepen depth must be positive".into()));
                    }
                    out.deepen = Some(depth);
                } else if let Some(value) = one_value(other, "deepen-since")? {
                    if out.deepen_since.is_some() {
                        return Err(GitError::Protocol("duplicate deepen-since argument".into()));
                    }
                    out.deepen_since = Some(value.parse::<i64>().map_err(|_| {
                        GitError::Protocol(format!("invalid deepen-since timestamp {value:?}"))
                    })?);
                } else {
                    return Err(GitError::Protocol(format!(
                        "unknown fetch argument {other:?}"
                    )));
                }
            }
        }
    }
    Ok(out)
}

enum Arg<'a> {
    Value(&'a str),
    Wrong(&'a str),
}

fn split_arg<'a>(line: &'a str, expected: &str) -> Result<Arg<'a>, GitError> {
    match one_value(line, expected)? {
        Some(value) => Ok(Arg::Value(value)),
        None => Ok(Arg::Wrong(line)),
    }
}

/// `Some(value)` when `line` is `<name> <value>`; `None` when it is not that
/// argument; an error when it is `<name>` without a value.
fn one_value<'a>(line: &'a str, name: &str) -> Result<Option<&'a str>, GitError> {
    let Some(rest) = line.strip_prefix(name) else {
        return Ok(None);
    };
    if rest.is_empty() {
        return Ok(None);
    }
    let Some(value) = rest.strip_prefix(' ') else {
        return Ok(None);
    };
    if value.is_empty() || value.contains(' ') {
        return Err(GitError::Protocol(format!(
            "malformed {name} argument {line:?}"
        )));
    }
    Ok(Some(value))
}

fn validate_oid(value: &str, format: ObjectFormat, what: &str) -> Result<(), GitError> {
    if is_full_sha(value, format) {
        Ok(())
    } else {
        Err(GitError::Protocol(format!(
            "{what} is not a full {} object id: {value:?}",
            format
        )))
    }
}

fn validate_agent(value: &str) -> Result<String, GitError> {
    validate_token(value, 256, "agent")?;
    Ok(value.to_string())
}

/// Server options are opaque strings; only framing-breaking bytes are
/// refused. Spaces are legal inside a single option value.
fn validate_server_option(value: &str) -> Result<(), GitError> {
    if value.is_empty()
        || value.len() > 1024
        || value.contains('\0')
        || value.contains(char::is_control)
    {
        return Err(GitError::Protocol(format!(
            "invalid server option {value:?}"
        )));
    }
    Ok(())
}

fn validate_token(value: &str, max: usize, what: &str) -> Result<(), GitError> {
    if value.is_empty()
        || value.len() > max
        || value.contains('\0')
        || value.contains(char::is_control)
        || value.contains(char::is_whitespace)
    {
        return Err(GitError::Protocol(format!(
            "invalid {what} value {value:?}"
        )));
    }
    Ok(())
}

fn validate_ref_prefix(prefix: &str) -> Result<(), GitError> {
    if prefix.is_empty()
        || prefix.len() > 1024
        || prefix.contains('\0')
        || prefix.contains(char::is_control)
    {
        return Err(GitError::Protocol(format!("invalid ref-prefix {prefix:?}")));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request(header: &[&str], args: &[&str]) -> Vec<u8> {
        let mut out = Vec::new();
        for line in header {
            out.extend_from_slice(&pkt_line_str(line));
        }
        out.extend_from_slice(delim_pkt());
        for line in args {
            out.extend_from_slice(&pkt_line_str(line));
        }
        out.extend_from_slice(flush_pkt());
        out
    }

    #[test]
    fn pkt_roundtrip() {
        let encoded = pkt_line_str("hello");
        let (line, used) = read_pkt(&encoded).unwrap().unwrap();
        assert_eq!(used, encoded.len());
        assert_eq!(line, PktLine::Data(Bytes::from_static(b"hello\n")));
        assert_eq!(read_pkt(b"0000").unwrap().unwrap().0, PktLine::Flush);
        assert_eq!(read_pkt(b"0001").unwrap().unwrap().0, PktLine::Delim);
        assert_eq!(read_pkt(b"0002").unwrap().unwrap().0, PktLine::ResponseEnd);
        assert_eq!(read_pkt(b"000").unwrap(), None);
        assert_eq!(read_pkt(b"").unwrap(), None);
    }

    #[test]
    fn malformed_lengths_are_refused() {
        assert!(read_pkt(b"zzzz").is_err());
        assert!(read_pkt(b"9999").is_err());
        assert!(read_pkt(b"0003").is_err());
        assert!(read_pkt(b"+001").is_err());
        assert!(read_pkt(b" 001").is_err());
        assert!(read_pkt(b"00ff").is_err());
    }

    #[test]
    fn maximum_packet_length_is_enforced() {
        let just_fits = vec![b'a'; MAX_PKT_LEN - 4];
        let encoded = try_pkt_line(&just_fits).expect("fits");
        assert_eq!(encoded.len(), MAX_PKT_LEN);
        let (line, used) = read_pkt(&encoded).unwrap().unwrap();
        assert_eq!(used, MAX_PKT_LEN);
        assert_eq!(line, PktLine::Data(Bytes::from(just_fits)));

        assert!(try_pkt_line(&vec![b'a'; MAX_PKT_LEN - 3]).is_err());
        let mut too_long = format!("{:04x}", MAX_PKT_LEN + 1).into_bytes();
        too_long.extend(std::iter::repeat_n(b'a', MAX_PKT_LEN + 1 - 4));
        assert!(read_pkt(&too_long).is_err());
    }

    #[test]
    fn read_until_flush_handles_streams_and_refuses_junk() {
        let mut stream = pkt_line_str("one");
        stream.extend_from_slice(&pkt_line_str("two"));
        stream.extend_from_slice(flush_pkt());
        stream.extend_from_slice(b"PACK");
        let (lines, used) = read_until_flush(&stream).unwrap();
        assert_eq!(lines.len(), 2);
        assert_eq!(&stream[used..], b"PACK");

        assert!(read_until_flush(b"0000junk").is_ok());
        assert!(read_until_flush(b"").is_err());
        assert!(read_until_flush(b"0001").is_err());
        assert!(read_until_flush(b"0002").is_err());
        let mut unterminated = pkt_line_str("x");
        unterminated.extend_from_slice(b"00");
        assert!(read_until_flush(&unterminated).is_err());
    }

    #[test]
    fn arbitrary_bytes_never_panic() {
        // Deterministic xorshift; every prefix of a valid stream too.
        let mut state = 0x9e37_79b9_7f4a_7c15u64;
        let mut next = || {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state
        };
        for _ in 0..2_000 {
            let len = (next() % 96) as usize;
            let mut body = Vec::with_capacity(len);
            for _ in 0..len {
                body.push((next() & 0xff) as u8);
            }
            let _ = read_pkt(&body);
            let _ = read_until_flush(&body);
            let _ = parse_v2_request(&body);
        }
        let mut valid = request(
            &["command=ls-refs", "object-format=sha1"],
            &["peel", "ref-prefix refs/"],
        );
        while let Some(byte) = valid.pop() {
            let _ = read_pkt(&valid);
            let _ = parse_v2_request(&valid);
            let _ = byte;
        }
    }

    #[test]
    fn protocol_header_parsing() {
        assert_eq!(Protocol::from_header(None), Protocol::V0);
        assert_eq!(Protocol::from_header(Some("version=2")), Protocol::V2);
        assert_eq!(
            Protocol::from_header(Some("agent=x:version=2")),
            Protocol::V2
        );
        assert_eq!(Protocol::from_header(Some("version=1")), Protocol::V0);
        assert_eq!(Protocol::from_header(Some("version=20")), Protocol::V0);
        assert_eq!(Protocol::V0.git_protocol_env(), None);
        assert_eq!(
            git_protocol_env(Protocol::V2),
            Some(("GIT_PROTOCOL", "version=2"))
        );
    }

    #[test]
    fn v2_advertisement_names_the_object_format() {
        let body = v2_capabilities_for(ObjectFormat::Sha256, true);
        let (lines, used) = read_until_flush(&body).unwrap();
        assert_eq!(used, body.len());
        let text: Vec<String> = lines
            .iter()
            .map(|line| String::from_utf8_lossy(line).trim_end().to_string())
            .collect();
        assert_eq!(text[0], "version 2");
        assert!(text.iter().any(|line| line == "object-format=sha256"));
        assert!(text.iter().any(|line| line == "ls-refs=unborn"));
        assert!(text
            .iter()
            .any(|line| line.starts_with("fetch=") && line.contains("shallow")));
        assert!(text.iter().any(|line| line == "server-option"));
        // Default keeps the historical SHA-1 advertisement.
        let plain = v2_capabilities(false);
        let text = String::from_utf8(plain).unwrap();
        assert!(text.contains("object-format=sha1"));
        assert!(!text.contains("server-option"));
    }

    #[test]
    fn v0_wrapper_frames_the_service_line() {
        let wrapped = wrap_advertise(Service::UploadPack, b"0000");
        assert!(wrapped.starts_with(b"001e# service=git-upload-pack\n0000"));
        assert!(wrapped.ends_with(b"0000"));
        assert_eq!(
            Service::parse("git-receive-pack"),
            Some(Service::ReceivePack)
        );
        assert_eq!(Service::ReceivePack.program(), "receive-pack");
        assert_eq!(Service::parse("git-archive"), None);
    }

    #[test]
    fn parses_ls_refs() {
        let body = request(
            &[
                "command=ls-refs",
                "agent=git/2.56.0",
                "object-format=sha1",
                "server-option=trace=1",
            ],
            &[
                "peel",
                "symrefs",
                "unborn",
                "ref-prefix refs/heads/",
                "ref-prefix HEAD",
            ],
        );
        let parsed = parse_v2_request(&body).expect("parse");
        assert_eq!(parsed.agent.as_deref(), Some("git/2.56.0"));
        assert_eq!(parsed.object_format, ObjectFormat::Sha1);
        assert_eq!(parsed.server_options, vec!["trace=1"]);
        let V2Command::LsRefs(args) = parsed.command else {
            panic!("expected ls-refs");
        };
        assert!(args.peel && args.symrefs && args.unborn);
        assert_eq!(args.ref_prefixes, vec!["refs/heads/", "HEAD"]);
    }

    #[test]
    fn parses_every_fetch_argument() {
        let want = "a".repeat(40);
        let have = "b".repeat(40);
        let body = request(
            &["command=fetch", "object-format=sha1"],
            &[
                &format!("want {want}"),
                &format!("want {}", "c".repeat(40)),
                &format!("have {have}"),
                "done",
                "thin-pack",
                "no-progress",
                "include-tag",
                "ofs-delta",
                "filter blob:none",
                &format!("shallow {have}"),
                "deepen 5",
                "deepen-relative",
                "deepen-since 1700000000",
                "deepen-not refs/heads/main",
                "sideband-all",
                "want-ref refs/heads/feat",
                "wait-for-done",
            ],
        );
        let request = parse_v2_request(&body).expect("parse");
        let V2Command::Fetch(args) = request.command else {
            panic!("expected fetch");
        };
        assert_eq!(args.wants.len(), 2);
        assert_eq!(args.wants[0], want);
        assert_eq!(args.haves, vec![have.clone()]);
        assert!(args.done && args.thin && args.no_progress && args.include_tag);
        assert!(args.ofs_delta && args.deepen_relative && args.sideband_all);
        assert!(args.wait_for_done);
        assert_eq!(args.filter.as_deref(), Some("blob:none"));
        assert_eq!(args.shallow, vec![have]);
        assert_eq!(args.deepen, Some(5));
        assert_eq!(args.deepen_since, Some(1_700_000_000));
        assert_eq!(args.deepen_not, vec!["refs/heads/main"]);
        assert_eq!(args.want_refs, vec!["refs/heads/feat"]);
    }

    #[test]
    fn sha256_requests_validate_sha256_object_ids() {
        let want = "d".repeat(64);
        let body = request(
            &["command=fetch", "object-format=sha256"],
            &[&format!("want {want}")],
        );
        let parsed = parse_v2_request(&body).expect("parse");
        assert_eq!(parsed.object_format, ObjectFormat::Sha256);
        let V2Command::Fetch(args) = parsed.command else {
            panic!("expected fetch");
        };
        assert_eq!(args.wants, vec![want]);

        let bad = request(
            &["command=fetch", "object-format=sha256"],
            &[&format!("want {}", "a".repeat(40))],
        );
        assert!(parse_v2_request(&bad).is_err());
    }

    #[test]
    fn bad_v2_requests_are_refused() {
        // Missing delimiter.
        let mut no_delim = pkt_line_str("command=ls-refs");
        no_delim.extend_from_slice(flush_pkt());
        assert!(parse_v2_request(&no_delim).is_err());
        // No command.
        assert!(parse_v2_request(&request(&["agent=x"], &[])).is_err());
        // Unknown command / capability / argument.
        assert!(parse_v2_request(&request(&["command=object-info"], &[])).is_err());
        assert!(parse_v2_request(&request(&["command=ls-refs", "unknown=1"], &[])).is_err());
        assert!(parse_v2_request(&request(&["command=fetch"], &["bogus"])).is_err());
        // Duplicate command and single-valued arguments.
        assert!(parse_v2_request(&request(&["command=ls-refs", "command=fetch"], &[])).is_err());
        assert!(parse_v2_request(&request(
            &["command=fetch"],
            &["filter blob:none", "filter blob:limit=1"]
        ))
        .is_err());
        assert!(parse_v2_request(&request(&["command=fetch"], &["deepen 1", "deepen 2"])).is_err());
        assert!(parse_v2_request(&request(&["command=fetch"], &["deepen 0"])).is_err());
        assert!(parse_v2_request(&request(&["command=fetch"], &["deepen x"])).is_err());
        // Missing values and malformed flags.
        assert!(parse_v2_request(&request(&["command=fetch"], &["want"])).is_err());
        assert!(parse_v2_request(&request(&["command=fetch"], &["want a b"])).is_err());
        assert!(parse_v2_request(&request(&["command=fetch"], &["done now"])).is_err());
        assert!(parse_v2_request(&request(&["command=fetch"], &["want not-a-sha"])).is_err());
        assert!(parse_v2_request(&request(&["command=fetch"], &["want-ref HEAD"])).is_err());
        assert!(parse_v2_request(&request(&["command=ls-refs"], &["ref-prefix a b"])).is_err());
        assert!(parse_v2_request(&request(&["command=ls-refs"], &["peel=1"])).is_err());
        // Non-UTF-8 capability and argument payloads.
        let mut binary = pkt_line(&[0xff, 0xfe, b'=']);
        binary.extend_from_slice(delim_pkt());
        binary.extend_from_slice(flush_pkt());
        assert!(parse_v2_request(&binary).is_err());
    }
}
