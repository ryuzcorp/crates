//! receive-pack request parsing and report-status framing.
//!
//! A push request is a command section (optionally preceded by `shallow`
//! lines) carrying the capability list on its first command, an optional
//! `push-options` section, and then the packfile as raw bytes. The parser is
//! deliberately strict: anything it cannot account for is refused before the
//! body is handed to git, because the parsed head is also the policy input.

use crate::config::ObjectFormat;
use crate::error::{GitError, RefError};
use crate::git::is_full_sha;
use crate::git::protocol::{pkt_line, read_pkt, PktLine, MAX_PKT_LEN};
use crate::git::validate_refname;

/// Most commands accepted in one push.
pub const MAX_COMMANDS: usize = 10_000;
/// Most push options accepted in one push.
pub const MAX_PUSH_OPTIONS: usize = 256;
/// Longest accepted single push option.
pub const MAX_PUSH_OPTION_LEN: usize = 1024;
/// Most `shallow` lines accepted in one push.
pub const MAX_SHALLOW: usize = 10_000;

/// One `<old> <new> <ref>` command.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PushCommand {
    pub old: String,
    pub new: String,
    pub refname: String,
}

impl PushCommand {
    /// `new` is the zero object id: the ref is deleted.
    pub fn is_delete(&self) -> bool {
        is_zero(&self.new)
    }

    /// `old` is the zero object id: the ref is created.
    pub fn is_create(&self) -> bool {
        is_zero(&self.old)
    }

    /// Neither a create nor a delete.
    pub fn is_update(&self) -> bool {
        !self.is_delete() && !self.is_create()
    }
}

fn is_zero(oid: &str) -> bool {
    !oid.is_empty() && oid.bytes().all(|byte| byte == b'0')
}

/// Capabilities negotiated by the client.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ReceiveCaps {
    pub report_status: bool,
    pub report_status_v2: bool,
    pub side_band_64k: bool,
    pub atomic: bool,
    pub quiet: bool,
    pub push_options: bool,
    pub ofs_delta: bool,
    pub agent: Option<String>,
    pub object_format: Option<String>,
}

/// A parsed receive-pack request head.
#[derive(Debug, Clone)]
pub struct ReceiveRequest {
    pub commands: Vec<PushCommand>,
    pub caps: ReceiveCaps,
    pub push_options: Vec<String>,
    pub shallow: Vec<String>,
    /// Byte offset where the packfile starts.
    pub pack_offset: usize,
}

impl ReceiveRequest {
    pub fn wants_sideband(&self) -> bool {
        self.caps.side_band_64k
    }

    pub fn wants_report_status(&self) -> bool {
        self.caps.report_status || self.caps.report_status_v2
    }

    /// The raw pack bytes that follow the parsed head.
    pub fn pack_bytes<'a>(&self, body: &'a [u8]) -> &'a [u8] {
        body.get(self.pack_offset..).unwrap_or_default()
    }
}

/// Parse the request head. An unreadable head is an error: the caller must
/// refuse rather than hand the body to git with every check skipped.
pub fn parse_receive(body: &[u8]) -> Result<ReceiveRequest, GitError> {
    let mut offset = 0;
    let mut shallow = Vec::new();
    let mut commands = Vec::new();
    let mut caps = ReceiveCaps::default();
    let mut seen_caps = false;
    let mut seen_command = false;
    loop {
        let Some((line, used)) = read_pkt(&body[offset..])? else {
            return Err(GitError::Protocol(
                "receive-pack: body ended before the command flush".into(),
            ));
        };
        offset += used;
        let data = match line {
            PktLine::Data(data) => data,
            PktLine::Flush => break,
            PktLine::Delim | PktLine::ResponseEnd => {
                return Err(GitError::Protocol(
                    "receive-pack: unexpected pkt in the command section".into(),
                ));
            }
        };
        let data = strip_newline(&data);
        if let Some(rest) = data.strip_prefix(b"shallow") {
            if seen_command {
                return Err(GitError::Protocol(
                    "receive-pack: shallow line after a command".into(),
                ));
            }
            let Some(rest) = rest.strip_prefix(b" ") else {
                return Err(GitError::Protocol(
                    "receive-pack: malformed shallow line".into(),
                ));
            };
            let oid = utf8(rest, "shallow object id")?;
            if oid.is_empty() || oid.contains(' ') {
                return Err(GitError::Protocol(
                    "receive-pack: malformed shallow object id".into(),
                ));
            }
            if shallow.len() >= MAX_SHALLOW {
                return Err(GitError::Protocol(format!(
                    "receive-pack: more than {MAX_SHALLOW} shallow lines"
                )));
            }
            shallow.push(oid.to_string());
            continue;
        }

        let (command, caps_part) = match data.iter().position(|&byte| byte == 0) {
            Some(nul) => (&data[..nul], Some(&data[nul + 1..])),
            None => (data, None),
        };
        let text = utf8(command, "receive-pack command")?;
        if caps_part.is_some() && seen_caps {
            return Err(GitError::Protocol(
                "receive-pack: capabilities are only allowed on the first command".into(),
            ));
        }
        let mut parts = text.splitn(3, ' ');
        let (Some(old), Some(new), Some(refname)) = (parts.next(), parts.next(), parts.next())
        else {
            return Err(GitError::Protocol(
                "receive-pack: malformed command line".into(),
            ));
        };
        if refname.is_empty() || refname.contains(' ') {
            return Err(GitError::Protocol(format!(
                "receive-pack: malformed refname {refname:?}"
            )));
        }
        validate_refname(refname)?;
        if commands.len() >= MAX_COMMANDS {
            return Err(GitError::Protocol(format!(
                "receive-pack: more than {MAX_COMMANDS} commands"
            )));
        }
        commands.push(PushCommand {
            old: old.to_string(),
            new: new.to_string(),
            refname: refname.to_string(),
        });
        seen_command = true;
        if let Some(caps_part) = caps_part {
            parse_caps(caps_part, &mut caps)?;
            seen_caps = true;
        }
    }
    if commands.is_empty() {
        return Err(GitError::Protocol("receive-pack: no commands".into()));
    }
    if !seen_caps {
        // Without capabilities there is no report-status and no push-options
        // section; that is legal but rare. Nothing to do here.
    }
    let mut seen_refs = std::collections::BTreeSet::new();
    for command in &commands {
        if !seen_refs.insert(command.refname.as_str()) {
            return Err(GitError::Protocol(format!(
                "receive-pack: duplicate refname {:?}",
                command.refname
            )));
        }
    }

    let mut push_options = Vec::new();
    if caps.push_options {
        loop {
            let Some((line, used)) = read_pkt(&body[offset..])? else {
                return Err(GitError::Protocol(
                    "receive-pack: body ended inside push-options".into(),
                ));
            };
            offset += used;
            match line {
                PktLine::Flush => break,
                PktLine::Data(data) => {
                    let data = strip_newline(&data);
                    let option = utf8(data, "push option")?;
                    if option.len() > MAX_PUSH_OPTION_LEN {
                        return Err(GitError::Protocol(format!(
                            "receive-pack: push option exceeds {MAX_PUSH_OPTION_LEN} bytes"
                        )));
                    }
                    if push_options.len() >= MAX_PUSH_OPTIONS {
                        return Err(GitError::Protocol(format!(
                            "receive-pack: more than {MAX_PUSH_OPTIONS} push options"
                        )));
                    }
                    push_options.push(option.to_string());
                }
                PktLine::Delim | PktLine::ResponseEnd => {
                    return Err(GitError::Protocol(
                        "receive-pack: unexpected pkt in push-options".into(),
                    ));
                }
            }
        }
    }

    let format = effective_format(&caps, &commands, &shallow)?;
    for oid in &shallow {
        if !is_full_sha(oid, format) {
            return Err(GitError::Protocol(format!(
                "receive-pack: shallow {oid:?} is not a full {format} object id"
            )));
        }
    }
    for command in &commands {
        for oid in [&command.old, &command.new] {
            if !is_full_sha(oid, format) {
                return Err(GitError::Protocol(format!(
                    "receive-pack: {} has an invalid {format} object id {oid:?}",
                    command.refname
                )));
            }
        }
    }

    let remainder = &body[offset..];
    if !remainder.is_empty() && !remainder.starts_with(b"PACK") {
        return Err(GitError::Protocol(format!(
            "receive-pack: {} trailing bytes are not a packfile",
            remainder.len()
        )));
    }

    Ok(ReceiveRequest {
        commands,
        caps,
        push_options,
        shallow,
        pack_offset: offset,
    })
}

fn strip_newline(data: &[u8]) -> &[u8] {
    data.strip_suffix(b"\n").unwrap_or(data)
}

fn utf8<'a>(data: &'a [u8], what: &str) -> Result<&'a str, GitError> {
    std::str::from_utf8(data)
        .map_err(|_| GitError::Protocol(format!("receive-pack: {what} is not UTF-8")))
}

/// Object format declared by the client, else inferred from the object ids.
fn effective_format(
    caps: &ReceiveCaps,
    commands: &[PushCommand],
    shallow: &[String],
) -> Result<ObjectFormat, GitError> {
    if let Some(value) = &caps.object_format {
        return ObjectFormat::parse(value).ok_or_else(|| {
            GitError::Protocol(format!("receive-pack: unknown object format {value:?}"))
        });
    }
    let mut seen: Option<usize> = None;
    for oid in commands
        .iter()
        .flat_map(|command| [&command.old, &command.new])
        .chain(shallow.iter())
    {
        if is_zero(oid) {
            continue;
        }
        let len = oid.len();
        if len != 40 && len != 64 {
            return Err(GitError::Protocol(format!(
                "receive-pack: object id {oid:?} is neither SHA-1 nor SHA-256"
            )));
        }
        match seen {
            Some(existing) if existing != len => {
                return Err(GitError::Protocol(
                    "receive-pack: mixed SHA-1 and SHA-256 object ids".into(),
                ));
            }
            None => seen = Some(len),
            Some(_) => {}
        }
    }
    Ok(match seen {
        Some(64) => ObjectFormat::Sha256,
        _ => ObjectFormat::Sha1,
    })
}

fn parse_caps(caps: &[u8], out: &mut ReceiveCaps) -> Result<(), GitError> {
    let text = utf8(caps, "capability list")?;
    for cap in text.split(' ').filter(|cap| !cap.is_empty()) {
        match cap {
            "report-status" => out.report_status = true,
            "report-status-v2" => out.report_status_v2 = true,
            "side-band-64k" => out.side_band_64k = true,
            "atomic" => out.atomic = true,
            "quiet" => out.quiet = true,
            "push-options" => out.push_options = true,
            "ofs-delta" => out.ofs_delta = true,
            other if other.starts_with("agent=") => {
                let agent = &other["agent=".len()..];
                if agent.is_empty()
                    || agent.len() > 256
                    || agent.contains('\0')
                    || agent.contains(char::is_control)
                {
                    return Err(GitError::Protocol(format!(
                        "receive-pack: invalid agent {agent:?}"
                    )));
                }
                out.agent = Some(agent.to_string());
            }
            other if other.starts_with("object-format=") => {
                let format = &other["object-format=".len()..];
                if ObjectFormat::parse(format).is_none() {
                    return Err(GitError::Protocol(format!(
                        "receive-pack: unknown object format {format:?}"
                    )));
                }
                out.object_format = Some(format.to_string());
            }
            // Unknown capabilities are ignored, as the protocol requires.
            _ => {}
        }
    }
    Ok(())
}

/// The command bytes as `PushCommand`s (policy view).
pub fn commands(request: &ReceiveRequest) -> &[PushCommand] {
    &request.commands
}

/// One `unpack` status line.
pub fn unpack_line(unpack: Result<(), &str>) -> String {
    match unpack {
        Ok(()) => "unpack ok\n".to_string(),
        Err(reason) => format!("unpack {}\n", sanitize_reason(reason)),
    }
}

/// One `ok`/`ng` status line built from a [`RefError`].
pub fn ref_status_line(refname: &str, result: &Result<(), RefError>) -> String {
    match result {
        Ok(()) => format!("ok {refname}\n"),
        Err(error) => format!("ng {refname} {}\n", sanitize_reason(&error.to_string())),
    }
}

/// Report-status body for one unpack result and per-ref [`RefError`]s.
///
/// Returns an empty body when the client did not request report-status.
pub fn report_status_refs(
    caps: &ReceiveCaps,
    unpack: Result<(), &str>,
    per_ref: &[(String, Result<(), RefError>)],
) -> Vec<u8> {
    if !caps.report_status && !caps.report_status_v2 {
        return Vec::new();
    }
    let mut lines = vec![unpack_line(unpack)];
    for (refname, result) in per_ref {
        lines.push(ref_status_line(refname, result));
    }
    frame_report(caps, &lines)
}

/// Report-status body for one unpack result and plain string reasons.
pub fn report_status(
    caps: &ReceiveCaps,
    unpack_ok: bool,
    per_ref: &[(String, Result<(), String>)],
) -> Vec<u8> {
    if !caps.report_status && !caps.report_status_v2 {
        return Vec::new();
    }
    let mut lines = vec![if unpack_ok {
        "unpack ok\n".to_string()
    } else {
        "unpack failed\n".to_string()
    }];
    for (refname, result) in per_ref {
        let line = match result {
            Ok(()) => format!("ok {refname}\n"),
            Err(reason) => format!("ng {refname} {}\n", sanitize_reason(reason)),
        };
        lines.push(line);
    }
    frame_report(caps, &lines)
}

/// Frame status lines as pkt-lines, optionally wrapped in sideband band 1.
///
/// The inner pkt-line stream (terminating flush included) is what git's
/// receive-pack writes; with `side-band-64k` that whole stream is carried in
/// band-1 packets and the outer stream ends with a flush.
fn frame_report(caps: &ReceiveCaps, lines: &[String]) -> Vec<u8> {
    let mut inner = Vec::new();
    for line in lines {
        inner.extend_from_slice(&pkt_line(line.as_bytes()));
    }
    inner.extend_from_slice(b"0000");
    if !caps.side_band_64k {
        return inner;
    }
    let mut framed = Vec::new();
    for chunk in inner.chunks(MAX_PKT_LEN - 5) {
        let mut payload = Vec::with_capacity(chunk.len() + 1);
        payload.push(1);
        payload.extend_from_slice(chunk);
        framed.extend_from_slice(&pkt_line(&payload));
    }
    framed.extend_from_slice(b"0000");
    framed
}

/// Reasons go on a single status line: fold control characters and cap the
/// length so a policy message cannot break the framing.
fn sanitize_reason(reason: &str) -> String {
    const MAX: usize = 512;
    let mut out = String::with_capacity(reason.len().min(MAX));
    for ch in reason.chars() {
        if out.len() >= MAX {
            break;
        }
        if ch == '\n' || ch == '\r' || ch == '\0' || ch.is_control() {
            out.push(' ');
        } else {
            out.push(ch);
        }
    }
    let trimmed = out.trim_end();
    if trimmed.is_empty() {
        "rejected".to_string()
    } else {
        trimmed.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::git::protocol::read_until_flush;

    fn pkt(payload: &[u8]) -> Vec<u8> {
        pkt_line(payload)
    }

    fn command(old: &str, new: &str, refname: &str, caps: Option<&str>) -> Vec<u8> {
        let mut line = format!("{old} {new} {refname}");
        if let Some(caps) = caps {
            line.push('\0');
            line.push_str(caps);
        }
        line.push('\n');
        pkt(line.as_bytes())
    }

    fn push(
        caps: Option<&str>,
        commands: &[(&str, &str, &str)],
        options: &[&str],
        pack: &[u8],
    ) -> Vec<u8> {
        let old = "0".repeat(40);
        let mut body = Vec::new();
        for (index, (c_old, c_new, c_ref)) in commands.iter().enumerate() {
            let caps = if index == 0 { caps } else { None };
            let c_old = if *c_old == "0" { old.as_str() } else { c_old };
            let c_new = if *c_new == "0" { old.as_str() } else { c_new };
            body.extend_from_slice(&command(c_old, c_new, c_ref, caps));
        }
        body.extend_from_slice(b"0000");
        if let Some(caps) = caps {
            if caps.split(' ').any(|cap| cap == "push-options") && !options.is_empty() {
                for option in options {
                    body.extend_from_slice(&pkt(format!("{option}\n").as_bytes()));
                }
                body.extend_from_slice(b"0000");
            } else if caps.split(' ').any(|cap| cap == "push-options") {
                body.extend_from_slice(b"0000");
            }
        }
        body.extend_from_slice(pack);
        body
    }

    #[test]
    fn parses_commands_caps_and_push_options() {
        let old = "a".repeat(40);
        let new = "b".repeat(40);
        let mut body = pkt(
            format!("{old} {new} refs/heads/main\0report-status-v2 side-band-64k push-options agent=git/2.47\n")
                .as_bytes(),
        );
        body.extend_from_slice(&pkt(format!(
            "{} {} refs/heads/feat\n",
            "0".repeat(40),
            new
        )
        .as_bytes()));
        body.extend_from_slice(b"0000");
        body.extend_from_slice(&pkt(b"ci.skip=true\n"));
        body.extend_from_slice(b"0000");
        body.extend_from_slice(b"PACKDATA");
        let request = parse_receive(&body).unwrap();
        assert_eq!(request.commands.len(), 2);
        assert!(request.caps.report_status_v2);
        assert!(request.caps.side_band_64k);
        assert!(request.caps.push_options);
        assert_eq!(request.caps.agent.as_deref(), Some("git/2.47"));
        assert_eq!(request.push_options, vec!["ci.skip=true"]);
        assert_eq!(request.pack_bytes(&body), b"PACKDATA");
        assert!(request.commands[0].is_update());
        assert!(request.commands[1].is_create());
        assert!(request.wants_report_status());
        assert!(request.wants_sideband());
    }

    #[test]
    fn shallow_lines_are_parsed() {
        let oid = "a".repeat(40);
        let mut body = pkt(format!("shallow {oid}\n").as_bytes());
        body.extend_from_slice(&pkt(format!(
            "{} {} refs/heads/main\0report-status\n",
            "0".repeat(40),
            "b".repeat(40)
        )
        .as_bytes()));
        body.extend_from_slice(b"0000");
        let request = parse_receive(&body).unwrap();
        assert_eq!(request.shallow, vec![oid]);
        assert_eq!(request.commands.len(), 1);
        assert_eq!(request.pack_bytes(&body), b"");
    }

    #[test]
    fn sha256_object_ids_select_sha256() {
        let oid = "c".repeat(64);
        let mut body = pkt(format!(
            "{} {oid} refs/heads/main\0report-status object-format=sha256\n",
            "0".repeat(64)
        )
        .as_bytes());
        body.extend_from_slice(b"0000PACK");
        let request = parse_receive(&body).unwrap();
        assert_eq!(request.caps.object_format.as_deref(), Some("sha256"));
        assert!(request.commands[0].is_create());
        assert_eq!(request.pack_bytes(&body), b"PACK");
    }

    #[test]
    fn malformed_requests_are_refused() {
        assert!(parse_receive(b"not a pkt line").is_err());
        assert!(parse_receive(b"0000").is_err());
        let mut binary = pkt(&[0xff, 0xfe, 0x00, b'a']);
        binary.extend_from_slice(b"0000");
        assert!(parse_receive(&binary).is_err());
        // Non-UTF-8 capabilities.
        let mut bad_caps = {
            let mut line =
                format!("{} {} refs/heads/main", "0".repeat(40), "a".repeat(40)).into_bytes();
            line.push(0);
            line.extend_from_slice(&[0xff, 0xfe]);
            line.push(b'\n');
            pkt(&line)
        };
        bad_caps.extend_from_slice(b"0000");
        assert!(parse_receive(&bad_caps).is_err());
    }

    #[test]
    fn invalid_commands_are_refused() {
        let zero = "0".repeat(40);
        let oid = "a".repeat(40);
        // Bad refnames.
        for refname in ["main", "refs/../x", "refs/heads/x.lock", "/refs/heads/x"] {
            let mut body = command(&zero, &oid, refname, Some("report-status"));
            body.extend_from_slice(b"0000");
            assert!(parse_receive(&body).is_err(), "{refname}");
        }
        // Bad object ids (short, non-hex, mixed lengths).
        for bad in ["deadbeef".to_string(), "z".repeat(40)] {
            let mut body = command(&bad, &oid, "refs/heads/main", Some("report-status"));
            body.extend_from_slice(b"0000");
            assert!(parse_receive(&body).is_err(), "{bad}");
        }
        let mut mixed = command(
            &zero,
            &"b".repeat(64),
            "refs/heads/main",
            Some("report-status"),
        );
        mixed.extend_from_slice(b"0000");
        assert!(parse_receive(&mixed).is_err());
        // Duplicate refnames.
        let mut duplicate = command(&zero, &oid, "refs/heads/main", Some("report-status"));
        duplicate.extend_from_slice(&command(&zero, &oid, "refs/heads/main", None));
        duplicate.extend_from_slice(b"0000");
        assert!(parse_receive(&duplicate).is_err());
        // Capabilities on a later command.
        let mut late_caps = command(&zero, &oid, "refs/heads/main", Some("report-status"));
        late_caps.extend_from_slice(&command(&zero, &oid, "refs/heads/two", Some("quiet")));
        late_caps.extend_from_slice(b"0000");
        assert!(parse_receive(&late_caps).is_err());
        // Shallow lines after a command.
        let mut late_shallow = command(&zero, &oid, "refs/heads/main", Some("report-status"));
        late_shallow.extend_from_slice(&pkt(format!("shallow {}\n", "a".repeat(40)).as_bytes()));
        late_shallow.extend_from_slice(b"0000");
        assert!(parse_receive(&late_shallow).is_err());
        // Invalid shallow object id.
        let mut bad_shallow = pkt(b"shallow nope\n");
        bad_shallow.extend_from_slice(&command(
            &zero,
            &oid,
            "refs/heads/main",
            Some("report-status"),
        ));
        bad_shallow.extend_from_slice(b"0000");
        assert!(parse_receive(&bad_shallow).is_err());
        // Unknown object format.
        let mut bad_format = command(
            &zero,
            &oid,
            "refs/heads/main",
            Some("report-status object-format=md5"),
        );
        bad_format.extend_from_slice(b"0000");
        assert!(parse_receive(&bad_format).is_err());
        // Trailing bytes that are not a pack.
        let mut junk = command(&zero, &oid, "refs/heads/main", Some("report-status"));
        junk.extend_from_slice(b"0000not-a-pack");
        assert!(parse_receive(&junk).is_err());
    }

    #[test]
    fn push_option_limits_are_enforced() {
        let caps = Some("report-status push-options");
        let too_long = "x".repeat(MAX_PUSH_OPTION_LEN + 1);
        let body = push(caps, &[("0", "a", "refs/heads/main")], &[&too_long], b"");
        assert!(parse_receive(&body).is_err());

        let many: Vec<String> = (0..=MAX_PUSH_OPTIONS).map(|i| format!("o{i}")).collect();
        let many: Vec<&str> = many.iter().map(String::as_str).collect();
        let body = push(caps, &[("0", "a", "refs/heads/main")], &many, b"");
        assert!(parse_receive(&body).is_err());

        // A push-options section without the capability is trailing garbage.
        let body = {
            let mut body = command(
                &"0".repeat(40),
                &"a".repeat(40),
                "refs/heads/main",
                Some("report-status"),
            );
            body.extend_from_slice(b"0000");
            body.extend_from_slice(&pkt(b"ci.skip=true\n"));
            body.extend_from_slice(b"0000");
            body
        };
        assert!(parse_receive(&body).is_err());
    }

    #[test]
    fn unknown_capabilities_are_ignored() {
        let mut body = command(
            &"0".repeat(40),
            &"a".repeat(40),
            "refs/heads/main",
            Some("report-status future-cap=1 quiet"),
        );
        body.extend_from_slice(b"0000");
        let request = parse_receive(&body).unwrap();
        assert!(request.caps.report_status);
        assert!(request.caps.quiet);
    }

    #[test]
    fn report_status_without_sideband_is_plain_pkt_lines() {
        let caps = ReceiveCaps {
            report_status: true,
            ..ReceiveCaps::default()
        };
        let body = report_status(
            &caps,
            true,
            &[
                ("refs/heads/main".into(), Ok(())),
                ("refs/tags/x".into(), Err("nope".into())),
            ],
        );
        let mut expected = pkt(b"unpack ok\n");
        expected.extend_from_slice(&pkt(b"ok refs/heads/main\n"));
        expected.extend_from_slice(&pkt(b"ng refs/tags/x nope\n"));
        expected.extend_from_slice(b"0000");
        assert_eq!(body, expected);
        let (lines, used) = read_until_flush(&body).unwrap();
        assert_eq!(used, body.len());
        assert_eq!(lines.len(), 3);
    }

    #[test]
    fn report_status_sideband_wraps_the_inner_stream() {
        let plain_caps = ReceiveCaps {
            report_status: true,
            ..ReceiveCaps::default()
        };
        let band_caps = ReceiveCaps {
            report_status: true,
            side_band_64k: true,
            ..ReceiveCaps::default()
        };
        let per_ref = [("refs/heads/main".to_string(), Ok(()))];
        let inner = report_status(&plain_caps, true, &per_ref);
        let framed = report_status(&band_caps, true, &per_ref);

        let mut offset = 0;
        let mut rebuilt = Vec::new();
        let mut saw_flush = false;
        while let Some((line, used)) = read_pkt(&framed[offset..]).unwrap() {
            offset += used;
            match line {
                PktLine::Data(data) => {
                    assert_eq!(data.first(), Some(&1), "only band 1 carries the report");
                    rebuilt.extend_from_slice(&data[1..]);
                }
                PktLine::Flush => {
                    saw_flush = true;
                    break;
                }
                PktLine::Delim | PktLine::ResponseEnd => panic!("unexpected pkt"),
            }
        }
        assert!(saw_flush);
        assert_eq!(offset, framed.len());
        assert_eq!(rebuilt, inner);
    }

    #[test]
    fn report_status_is_empty_without_negotiation() {
        let caps = ReceiveCaps::default();
        assert!(report_status(&caps, true, &[]).is_empty());
        assert!(report_status_refs(&caps, Ok(()), &[]).is_empty());
    }

    #[test]
    fn ref_errors_become_ng_lines() {
        let caps = ReceiveCaps {
            report_status_v2: true,
            ..ReceiveCaps::default()
        };
        let per_ref = [
            ("refs/heads/ff".to_string(), Err(RefError::NonFastForward)),
            (
                "refs/heads/conflict".to_string(),
                Err(RefError::Conflict {
                    expected: Some("a".repeat(40)),
                    actual: None,
                }),
            ),
            (
                "refs/heads/protected".to_string(),
                Err(RefError::Rejected("protected branch\nsecond line".into())),
            ),
            ("refs/heads/gone".to_string(), Err(RefError::Missing)),
            ("refs/heads/ok".to_string(), Ok(())),
        ];
        let body = report_status_refs(&caps, Err("bad pack\nreason"), &per_ref);
        let (lines, _) = read_until_flush(&body).unwrap();
        let text: Vec<String> = lines
            .iter()
            .map(|line| String::from_utf8_lossy(line).into_owned())
            .collect();
        assert_eq!(text[0], "unpack bad pack reason\n");
        assert_eq!(text[1], "ng refs/heads/ff non-fast-forward\n");
        assert!(text[2].starts_with("ng refs/heads/conflict conflict:"));
        assert_eq!(
            text[3],
            "ng refs/heads/protected protected branch second line\n"
        );
        assert_eq!(text[4], "ng refs/heads/gone missing\n");
        assert_eq!(text[5], "ok refs/heads/ok\n");
        assert_eq!(
            ref_status_line("refs/heads/x", &Ok(())),
            "ok refs/heads/x\n"
        );
        assert_eq!(unpack_line(Ok(())), "unpack ok\n");
    }

    #[test]
    fn reasons_cannot_break_framing() {
        let long = "x".repeat(1000);
        let reason = format!("first\nsecond\r{}{long}", '\u{0}');
        let status = sanitize_reason(&reason);
        assert!(!status.contains('\n'));
        assert!(!status.contains('\r'));
        assert!(!status.contains('\0'));
        assert!(status.len() <= 512);
        assert_eq!(sanitize_reason(" \n"), "rejected");
    }

    #[test]
    fn empty_pack_after_commands_is_allowed() {
        let mut body = command(
            &"a".repeat(40),
            &"0".repeat(40),
            "refs/heads/main",
            Some("report-status"),
        );
        body.extend_from_slice(b"0000");
        let request = parse_receive(&body).unwrap();
        assert_eq!(request.pack_offset, body.len());
        assert!(request.pack_bytes(&body).is_empty());
        assert!(request.commands[0].is_delete());
    }
}
