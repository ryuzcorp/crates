//! Push-request parsing and the structural push policy.
//!
//! The server shells out to `git receive-pack` for the pack work, but it parses
//! the request head first so policy can refuse a push before git mutates
//! anything:
//!
//! - [`Role::Admin`] may do anything (force-push, delete, move tags).
//! - [`Role::Push`] may create refs and fast-forward-update them; deletes are
//!   denied here and non-fast-forward updates are denied by the caller after
//!   [`updates_needing_ff`] (both also enforced by git itself in the HTTP
//!   adapter).
//! - [`Role::View`] may not push.
//!
//! A body the parser cannot read is an error; the caller must refuse the push
//! rather than hand it to git with every check skipped.

/// One `<old> <new> <ref>` command from a receive-pack request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PushCommand {
    pub old: String,
    pub new: String,
    pub refname: String,
}

/// What a caller may do with a repository.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    View,
    Push,
    Admin,
}

impl Role {
    /// Parse the role names git-auth answers carry. Anything else is `None`.
    pub fn parse(role: &str) -> Option<Role> {
        match role {
            "view" => Some(Role::View),
            "push" => Some(Role::Push),
            "admin" => Some(Role::Admin),
            _ => None,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Role::View => "view",
            Role::Push => "push",
            Role::Admin => "admin",
        }
    }

    /// Admin and push may write; view may only read.
    pub fn can_push(self) -> bool {
        !matches!(self, Role::View)
    }
}

/// All-zero OID: ref deletion (`new`) or ref creation (`old`).
pub fn is_zero_oid(oid: &str) -> bool {
    !oid.is_empty() && oid.bytes().all(|b| b == b'0')
}

/// Parse receive-pack command pkt-lines from a stateless-rpc body.
///
/// Reads `<old> <new> <ref>[\0caps]` lines until the flush packet; the pack
/// bytes that follow are left untouched.
pub fn parse_receive_commands(body: &[u8]) -> anyhow::Result<Vec<PushCommand>> {
    let mut cmds = Vec::new();
    let mut i = 0;
    while i + 4 <= body.len() {
        let len_hex = std::str::from_utf8(&body[i..i + 4])
            .map_err(|_| anyhow::anyhow!("receive-pack: pkt length not utf8"))?;
        let len = usize::from_str_radix(len_hex.trim(), 16)
            .map_err(|_| anyhow::anyhow!("receive-pack: bad pkt length {len_hex:?}"))?;
        if len == 0 {
            break; // flush: commands done, pack bytes follow
        }
        if len < 4 || i + len > body.len() {
            anyhow::bail!("receive-pack: pkt length {len} out of bounds");
        }
        let payload = &body[i + 4..i + len];
        i += len;
        let line = payload.strip_suffix(b"\n").unwrap_or(payload);
        let cmd_part = match line.iter().position(|&c| c == 0) {
            Some(nul) => &line[..nul], // first line carries NUL + caps
            None => line,
        };
        let text = std::str::from_utf8(cmd_part)
            .map_err(|_| anyhow::anyhow!("receive-pack: command not utf8"))?;
        let mut parts = text.splitn(3, ' ');
        match (parts.next(), parts.next(), parts.next()) {
            (Some(old), Some(new), Some(name)) if !name.is_empty() => {
                cmds.push(PushCommand {
                    old: old.to_string(),
                    new: new.to_string(),
                    refname: name.to_string(),
                });
            }
            _ => anyhow::bail!("receive-pack: malformed command line"),
        }
    }
    Ok(cmds)
}

/// The outcome of a structural policy rule.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PolicyDecision {
    Allow,
    Deny(String),
}

/// Structural policy: deletes need `admin`; `view` may not push at all.
/// Fast-forward checks need the repository and run separately through
/// [`updates_needing_ff`].
pub fn check_push_policy(role: Role, cmds: &[PushCommand]) -> PolicyDecision {
    if role == Role::Admin {
        return PolicyDecision::Allow;
    }
    if role != Role::Push {
        return PolicyDecision::Deny(format!(
            "rule push-policy: role {:?} may not push (need push or admin)",
            role.as_str()
        ));
    }
    for cmd in cmds {
        if is_zero_oid(&cmd.new) {
            return PolicyDecision::Deny(format!(
                "rule push-policy: 'push' may not delete {} (admin only)",
                cmd.refname
            ));
        }
    }
    PolicyDecision::Allow
}

/// Non-create, non-delete updates: (refname, old, new). Callers verify `old`
/// is an ancestor of `new` for non-admin roles before running git.
pub fn updates_needing_ff(cmds: &[PushCommand]) -> Vec<(&str, &str, &str)> {
    cmds.iter()
        .filter(|c| !is_zero_oid(&c.old) && !is_zero_oid(&c.new))
        .map(|c| (c.refname.as_str(), c.old.as_str(), c.new.as_str()))
        .collect()
}

/// Branch protection: with `require_pr` on, only `admin` may move
/// `protected` (usually `refs/heads/main`); a `push` caller must open a pull
/// request instead. Off by default, and admins always bypass.
pub fn check_branch_protection(
    role: Role,
    cmds: &[PushCommand],
    require_pr: bool,
    protected: &str,
) -> PolicyDecision {
    if !require_pr || role == Role::Admin {
        return PolicyDecision::Allow;
    }
    for cmd in cmds {
        if cmd.refname == protected {
            return PolicyDecision::Deny(format!(
                "rule branch-protection: {protected} is protected; open a pull request instead of pushing directly"
            ));
        }
    }
    PolicyDecision::Allow
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pkt(payload: &[u8]) -> Vec<u8> {
        let total = payload.len() + 4;
        let mut out = format!("{total:04x}").into_bytes();
        out.extend_from_slice(payload);
        out
    }

    fn cmd(old: &str, new: &str, refname: &str) -> PushCommand {
        PushCommand {
            old: old.to_string(),
            new: new.to_string(),
            refname: refname.to_string(),
        }
    }

    #[test]
    fn parses_commands_with_caps_and_flush() {
        let old = "a".repeat(40);
        let new = "b".repeat(40);
        let mut body =
            pkt(format!("{old} {new} refs/heads/main\0report-status side-band-64k\n").as_bytes());
        body.extend_from_slice(&pkt(format!(
            "{} {} refs/heads/other\n",
            "c".repeat(40),
            "d".repeat(40)
        )
        .as_bytes()));
        body.extend_from_slice(b"0000");
        body.extend_from_slice(b"PACKExtraBytesIgnored");
        let cmds = parse_receive_commands(&body).unwrap();
        assert_eq!(cmds.len(), 2);
        assert_eq!(cmds[0].refname, "refs/heads/main");
        assert_eq!(cmds[1].refname, "refs/heads/other");
    }

    #[test]
    fn rejects_malformed_input() {
        assert!(parse_receive_commands(b"not a pkt line").is_err());
        assert!(parse_receive_commands(b"0000").unwrap().is_empty());
        let mut weird = pkt(&[0xff, 0xfe, 0xfd, 0x00, b'a']);
        weird.extend_from_slice(b"0000");
        assert!(parse_receive_commands(&weird).is_err());
    }

    #[test]
    fn push_may_create_and_ff_admin_may_delete() {
        let cmds = vec![
            cmd(&"a".repeat(40), &"b".repeat(40), "refs/heads/main"),
            cmd(&"0".repeat(40), &"b".repeat(40), "refs/heads/feat"),
        ];
        assert_eq!(check_push_policy(Role::Push, &cmds), PolicyDecision::Allow);
        assert_eq!(check_push_policy(Role::Admin, &cmds), PolicyDecision::Allow);
    }

    #[test]
    fn deletes_and_view_are_denied_for_push() {
        let delete = vec![cmd(&"a".repeat(40), &"0".repeat(40), "refs/heads/main")];
        match check_push_policy(Role::Push, &delete) {
            PolicyDecision::Deny(msg) => assert!(msg.contains("may not delete")),
            PolicyDecision::Allow => panic!("delete allowed for push"),
        }
        assert_eq!(
            check_push_policy(Role::Admin, &delete),
            PolicyDecision::Allow
        );
        assert!(matches!(
            check_push_policy(Role::View, &[]),
            PolicyDecision::Deny(_)
        ));
    }

    #[test]
    fn ff_filter_skips_creates_and_deletes() {
        let cmds = vec![
            cmd(&"a".repeat(40), &"b".repeat(40), "refs/heads/main"),
            cmd(&"0".repeat(40), &"b".repeat(40), "refs/heads/new"),
            cmd(&"b".repeat(40), &"0".repeat(40), "refs/heads/gone"),
        ];
        let ff = updates_needing_ff(&cmds);
        assert_eq!(ff.len(), 1);
        assert_eq!(ff[0].0, "refs/heads/main");
    }

    #[test]
    fn branch_protection_blocks_push_but_not_admin() {
        let cmds = vec![cmd(&"a".repeat(40), &"b".repeat(40), "refs/heads/main")];
        assert!(matches!(
            check_branch_protection(Role::Push, &cmds, true, "refs/heads/main"),
            PolicyDecision::Deny(_)
        ));
        assert_eq!(
            check_branch_protection(Role::Admin, &cmds, true, "refs/heads/main"),
            PolicyDecision::Allow
        );
        assert_eq!(
            check_branch_protection(Role::Push, &cmds, false, "refs/heads/main"),
            PolicyDecision::Allow
        );
    }

    #[test]
    fn roles_parse_exactly() {
        for role in [Role::View, Role::Push, Role::Admin] {
            assert_eq!(Role::parse(role.as_str()), Some(role));
        }
        for role in ["", "owner", "PUSH", "create"] {
            assert_eq!(Role::parse(role), None, "{role}");
        }
    }
}
