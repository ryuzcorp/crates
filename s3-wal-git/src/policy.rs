//! Per-repository push policy.
//!
//! A small rule language, not a JSON bag: named groups, ordered named rules,
//! one doublestar glob dialect, and an effect union whose combination law is
//! fixed by the effect type. Missing policy or empty `rules` is allow-all.
//!
//! ```json
//! {"version":1,
//!  "groups":[{"name":"admins","members":["alice@example.com"]}],
//!  "rules":[{"name":"lock-main","match":{"refs":["refs/heads/main"]},
//!            "effect":{"protect":{"restricts":["update","delete","force-push"],
//!                                 "bypass":["group:admins"]}}}]}
//! ```
//!
//! Combination law:
//! - `protect` — every matching rule applies; a rule's `bypass` only bypasses
//!   that rule. Effective protection is the union of restricted operations
//!   (AND across rules). `^` exclusions are allowed.
//! - `history` / `size` — structural only. The first matching rule that sets a
//!   field wins for that field; [`Policy::evaluate`] exposes the resolved
//!   limits so the caller can enforce them. `^` exclusions are refused at load
//!   because first-match is union-like and a carve-out would be a no-op.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use serde::de::{self, Deserializer};
use serde::ser::SerializeMap;
use serde::{Deserialize, Serialize};

use crate::error::PolicyError;

/// Policy document version this module reads and writes.
pub const POLICY_VERSION: u32 = 1;

fn default_version() -> u32 {
    POLICY_VERSION
}

/// The rule document.
///
/// Unknown keys beside `version`/`groups`/`rules` are ignored so a fleet can
/// roll a new parser past an old one. Unknown keys inside a rule, match or
/// effect are parse errors.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Policy {
    #[serde(default = "default_version")]
    pub version: u32,
    #[serde(default)]
    pub groups: Vec<Group>,
    #[serde(default)]
    pub rules: Vec<Rule>,
}

impl Default for Policy {
    fn default() -> Self {
        Self::allow_all()
    }
}

/// One named roster. Names are exact lookups resolved at eval time.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Group {
    pub name: String,
    #[serde(default)]
    pub members: Vec<String>,
    #[serde(default, rename = "_comment", skip_serializing_if = "Option::is_none")]
    pub comment: Option<String>,
}

/// One ordered, named decision.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Rule {
    pub name: String,
    #[serde(default, rename = "match")]
    pub r#match: Match,
    pub effect: Effect,
    /// Optional. Only narrows a process umbrella; stored and ignored here.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mode: Option<RuleMode>,
    #[serde(default, rename = "_comment", skip_serializing_if = "Option::is_none")]
    pub comment: Option<String>,
}

/// Who a rule applies to. Keys AND, values OR; an absent key matches all.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Match {
    #[serde(default)]
    pub refs: Vec<String>,
    #[serde(default)]
    pub principals: Vec<String>,
    /// Reserved for `size`; ignored by `protect` and `history`.
    #[serde(default)]
    pub paths: Vec<String>,
    #[serde(default, rename = "_comment", skip_serializing_if = "Option::is_none")]
    pub comment: Option<String>,
}

/// The rule type. Exactly one `effect` key is required in JSON.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Effect {
    Protect {
        /// Absent in JSON means all four operations.
        restricts: Vec<Restrict>,
        bypass: Vec<String>,
    },
    History {
        allowed_forwards: Option<u64>,
        allow_unrelated: Option<bool>,
    },
    Size {
        blob_bytes: Option<u64>,
        push_bytes: Option<u64>,
    },
}

impl Effect {
    pub fn protect(restricts: Vec<Restrict>, bypass: Vec<String>) -> Self {
        Self::Protect { restricts, bypass }
    }

    pub fn history(allowed_forwards: Option<u64>, allow_unrelated: Option<bool>) -> Self {
        Self::History {
            allowed_forwards,
            allow_unrelated,
        }
    }

    pub fn size(blob_bytes: Option<u64>, push_bytes: Option<u64>) -> Self {
        Self::Size {
            blob_bytes,
            push_bytes,
        }
    }

    /// The effect's tag, for diagnostics and metrics.
    pub fn kind(&self) -> &'static str {
        match self {
            Self::Protect { .. } => "protect",
            Self::History { .. } => "history",
            Self::Size { .. } => "size",
        }
    }
}

/// Closed set of protected operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Restrict {
    Create,
    Update,
    Delete,
    ForcePush,
}

impl Restrict {
    pub const ALL: [Self; 4] = [Self::Create, Self::Update, Self::Delete, Self::ForcePush];

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Create => "create",
            Self::Update => "update",
            Self::Delete => "delete",
            Self::ForcePush => "force-push",
        }
    }
}

/// Rule enforcement mode. Stored and ignored: a file may narrow a process
/// umbrella, never widen it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RuleMode {
    Enforce,
    Audit,
}

impl RuleMode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Enforce => "enforce",
            Self::Audit => "audit",
        }
    }
}

fn all_restricts() -> Vec<Restrict> {
    Restrict::ALL.to_vec()
}

/// One ref update as policy sees it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Update {
    pub refname: String,
    /// `None` means the ref did not exist (create).
    pub old: Option<String>,
    /// `None` means the ref is deleted.
    pub new: Option<String>,
    /// `true` when `new` is not a descendant of `old`. Ignored for create,
    /// delete and tag retargets (tags are never fast-forward).
    pub force: bool,
    /// Changed paths, used only by `size` rules.
    pub paths: Vec<String>,
}

impl Update {
    pub fn new(
        refname: impl Into<String>,
        old: Option<String>,
        new: Option<String>,
        force: bool,
    ) -> Self {
        Self {
            refname: refname.into(),
            old,
            new,
            force,
            paths: Vec::new(),
        }
    }

    /// Build from wire OIDs. An empty or all-zero OID is absent.
    pub fn from_oids(refname: impl Into<String>, old: &str, new: &str) -> Self {
        Self {
            refname: refname.into(),
            old: oid(old),
            new: oid(new),
            force: false,
            paths: Vec::new(),
        }
    }

    #[must_use]
    pub fn forced(mut self) -> Self {
        self.force = true;
        self
    }

    #[must_use]
    pub fn with_paths<I, S>(mut self, paths: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.paths = paths.into_iter().map(Into::into).collect();
        self
    }
}

fn oid(value: &str) -> Option<String> {
    let value = value.trim();
    if value.is_empty() || value.bytes().all(|b| b == b'0') {
        None
    } else {
        Some(value.to_string())
    }
}

/// Everything a push policy needs to know about one push.
#[derive(Debug, Clone, Copy)]
pub struct PushContext<'a> {
    /// Authenticated principal (the same string auth resolved).
    pub principal: &'a str,
    /// Tags the edge already bound to the principal (`okta:sre`, `ci`, ...).
    /// A match entry `@tag` consults this list.
    pub tags: &'a [String],
    pub updates: &'a [Update],
}

/// A named denial. `rule` is the rule that fired; `reason` says why.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Denied {
    pub rule: String,
    pub reason: String,
}

impl Denied {
    pub fn new(rule: impl Into<String>, reason: impl Into<String>) -> Self {
        Self {
            rule: rule.into(),
            reason: reason.into(),
        }
    }
}

impl fmt::Display for Denied {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "rejected by rule '{}': {}", self.rule, self.reason)
    }
}

impl std::error::Error for Denied {}

impl From<Denied> for PolicyError {
    fn from(denied: Denied) -> Self {
        Self::Invalid(denied.to_string())
    }
}

/// A denial-free evaluation may still expose structural limits.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Evaluation {
    /// One entry per denied update, in push order. Empty means allowed.
    pub denials: Vec<Denied>,
    /// Resolved `history` limits per update (first match per field).
    pub history: Vec<RefLimits<HistoryLimits>>,
    /// Resolved `size` ceilings per update (first match per field).
    pub size: Vec<RefLimits<SizeLimits>>,
}

impl Evaluation {
    pub fn is_allowed(&self) -> bool {
        self.denials.is_empty()
    }

    pub fn first_denial(&self) -> Option<&Denied> {
        self.denials.first()
    }
}

/// Limits resolved for one ref.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RefLimits<T> {
    pub refname: String,
    pub limits: T,
}

/// `history` limits; `None` means no matching rule set the field.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct HistoryLimits {
    pub allowed_forwards: Option<u64>,
    pub allow_unrelated: Option<bool>,
}

impl HistoryLimits {
    fn is_complete(self) -> bool {
        self.allowed_forwards.is_some() && self.allow_unrelated.is_some()
    }
}

/// `size` ceilings; `None` means no matching rule set the field.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SizeLimits {
    pub blob_bytes: Option<u64>,
    pub push_bytes: Option<u64>,
}

impl SizeLimits {
    fn is_complete(self) -> bool {
        self.blob_bytes.is_some() && self.push_bytes.is_some()
    }
}

impl Policy {
    /// Allow every push. This is the default and the missing-file value.
    pub fn allow_all() -> Self {
        Self {
            version: POLICY_VERSION,
            groups: Vec::new(),
            rules: Vec::new(),
        }
    }

    /// Alias for [`Policy::allow_all`].
    pub fn empty() -> Self {
        Self::allow_all()
    }

    /// Parse and validate a document. A missing object is represented by
    /// [`Policy::load`] with `None`; bytes that do not parse fail closed.
    pub fn parse(bytes: &[u8]) -> Result<Self, PolicyError> {
        let policy: Policy = serde_json::from_slice(bytes)?;
        policy.validate()?;
        Ok(policy)
    }

    /// Parse an optional document. `None` (a missing object) is allow-all.
    pub fn load(bytes: Option<&[u8]>) -> Result<Self, PolicyError> {
        match bytes {
            None => Ok(Self::allow_all()),
            Some(bytes) => Self::parse(bytes),
        }
    }

    /// Validate without parsing.
    pub fn validate(&self) -> Result<(), PolicyError> {
        if self.version != POLICY_VERSION {
            return Err(PolicyError::Invalid(format!(
                "unsupported policy version {}",
                self.version
            )));
        }

        let mut group_names = BTreeSet::new();
        for group in &self.groups {
            validate_name("group", &group.name)?;
            if !group_names.insert(group.name.as_str()) {
                return Err(PolicyError::Invalid(format!(
                    "duplicate group name {:?}",
                    group.name
                )));
            }
            for member in &group.members {
                if member.trim().is_empty() {
                    return Err(PolicyError::Invalid(format!(
                        "group {:?} has an empty member",
                        group.name
                    )));
                }
            }
        }

        let mut rule_names = BTreeSet::new();
        for rule in &self.rules {
            validate_name("rule", &rule.name)?;
            if !rule_names.insert(rule.name.as_str()) {
                return Err(PolicyError::Invalid(format!(
                    "duplicate rule name {:?}",
                    rule.name
                )));
            }
            validate_patterns(rule)?;
            match &rule.effect {
                Effect::Protect { restricts, bypass } => {
                    if restricts.is_empty() {
                        return Err(PolicyError::Invalid(format!(
                            "rule {:?}: restricts must name at least one operation",
                            rule.name
                        )));
                    }
                    if bypass.iter().any(|entry| entry.trim().is_empty()) {
                        return Err(PolicyError::Invalid(format!(
                            "rule {:?}: bypass contains an empty principal",
                            rule.name
                        )));
                    }
                }
                Effect::History { .. } | Effect::Size { .. } => {}
            }
        }

        check_overlap_bypass(self)
    }

    /// Serialize. Kept for the CLI; does not validate.
    pub fn to_json(&self) -> serde_json::Result<Vec<u8>> {
        serde_json::to_vec(self)
    }

    /// Validate, then serialize as pretty JSON.
    pub fn to_json_vec(&self) -> Result<Vec<u8>, PolicyError> {
        self.validate()?;
        Ok(serde_json::to_vec_pretty(self)?)
    }

    /// Validate, then serialize as pretty JSON text.
    pub fn to_json_string(&self) -> Result<String, PolicyError> {
        self.validate()?;
        Ok(serde_json::to_string_pretty(self)?)
    }

    /// Evaluate every update: named protect denials plus structural
    /// `history`/`size` limits.
    pub fn evaluate(&self, context: &PushContext<'_>) -> Evaluation {
        let compiled = CompiledPolicy::new(self);
        let denials = context
            .updates
            .iter()
            .filter_map(|update| compiled.deny(context, update))
            .collect();
        Evaluation {
            denials,
            history: check_history_with(&compiled, context),
            size: check_size_with(&compiled, context),
        }
    }

    /// Resolved `history` limits, one entry per update.
    pub fn check_history(&self, context: &PushContext<'_>) -> Vec<RefLimits<HistoryLimits>> {
        check_history(self, context)
    }

    /// Resolved `size` ceilings, one entry per update.
    pub fn check_size(&self, context: &PushContext<'_>) -> Vec<RefLimits<SizeLimits>> {
        check_size(self, context)
    }

    fn compile(&self) -> CompiledPolicy<'_> {
        CompiledPolicy::new(self)
    }
}

fn validate_name(kind: &str, name: &str) -> Result<(), PolicyError> {
    let bytes = name.as_bytes();
    let valid = (1..=63).contains(&bytes.len())
        && bytes[0].is_ascii_lowercase()
        && bytes
            .iter()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || *byte == b'-');
    if valid {
        Ok(())
    } else {
        Err(PolicyError::Invalid(format!(
            "{kind}: bad name {name:?} (want ^[a-z][a-z0-9-]{{0,62}}$)"
        )))
    }
}

fn validate_patterns(rule: &Rule) -> Result<(), PolicyError> {
    let lists = [
        ("refs", &rule.r#match.refs),
        ("principals", &rule.r#match.principals),
        ("paths", &rule.r#match.paths),
    ];
    for (field, patterns) in lists {
        for pattern in patterns {
            let glob = pattern.strip_prefix('^').unwrap_or(pattern);
            if glob.is_empty() {
                return Err(PolicyError::Invalid(format!(
                    "rule {:?}: empty {field} pattern",
                    rule.name
                )));
            }
        }
    }
    if !matches!(rule.effect, Effect::Protect { .. }) {
        for (field, patterns) in [
            ("refs", &rule.r#match.refs),
            ("principals", &rule.r#match.principals),
            ("paths", &rule.r#match.paths),
        ] {
            if patterns.iter().any(|pattern| pattern.starts_with('^')) {
                return Err(PolicyError::Invalid(format!(
                    "rule {:?}: ^ exclusions are illegal on {} {field} (first-match family)",
                    rule.name,
                    rule.effect.kind()
                )));
            }
        }
    }
    Ok(())
}

/// Two overlapping `protect` rules with non-empty, disjoint bypass lists
/// cannot both be satisfied: AND would lock out the intended bot.
fn check_overlap_bypass(policy: &Policy) -> Result<(), PolicyError> {
    let protect: Vec<&Rule> = policy
        .rules
        .iter()
        .filter(|rule| matches!(rule.effect, Effect::Protect { .. }))
        .collect();
    for (index, first) in protect.iter().enumerate() {
        let (first_restricts, first_bypass) = protect_parts(first);
        for second in &protect[index + 1..] {
            if !ref_patterns_may_overlap(&first.r#match.refs, &second.r#match.refs) {
                continue;
            }
            let (second_restricts, second_bypass) = protect_parts(second);
            if restrict_set(first_restricts).is_disjoint(&restrict_set(second_restricts)) {
                continue;
            }
            if first_bypass.is_empty() || second_bypass.is_empty() {
                continue;
            }
            let a: BTreeSet<&str> = first_bypass.iter().map(String::as_str).collect();
            let b: BTreeSet<&str> = second_bypass.iter().map(String::as_str).collect();
            if a.is_disjoint(&b) {
                return Err(PolicyError::Invalid(format!(
                    "protect rules {:?} and {:?} overlap with disjoint bypass lists",
                    first.name, second.name
                )));
            }
        }
    }
    Ok(())
}

fn protect_parts(rule: &Rule) -> (&[Restrict], &[String]) {
    match &rule.effect {
        Effect::Protect { restricts, bypass } => (restricts, bypass),
        _ => (&[], &[]),
    }
}

fn restrict_set(restricts: &[Restrict]) -> BTreeSet<Restrict> {
    if restricts.is_empty() {
        Restrict::ALL.into_iter().collect()
    } else {
        restricts.iter().copied().collect()
    }
}

/// Conservative: empty (match-all) overlaps everything; otherwise any pair of
/// non-exclusion patterns that share a prefix might overlap.
fn ref_patterns_may_overlap(a: &[String], b: &[String]) -> bool {
    if a.is_empty() || b.is_empty() {
        return true;
    }
    let a = included_patterns(a);
    let b = included_patterns(b);
    if a.is_empty() || b.is_empty() {
        return true;
    }
    a.iter()
        .any(|first| b.iter().any(|second| glob_may_overlap(first, second)))
}

fn included_patterns(patterns: &[String]) -> Vec<&str> {
    patterns
        .iter()
        .filter(|pattern| !pattern.starts_with('^'))
        .map(String::as_str)
        .collect()
}

fn glob_may_overlap(a: &str, b: &str) -> bool {
    if a == b {
        return true;
    }
    glob_match(a, b.trim_end_matches('*').trim_end_matches('/'))
        || glob_match(b, a.trim_end_matches('*').trim_end_matches('/'))
        || a.contains("**")
        || b.contains("**")
}

// ---------------------------------------------------------------------------
// Globs
// ---------------------------------------------------------------------------

/// One compiled doublestar pattern.
///
/// Grammar: `*` and `?` stop at `/`; `**` crosses `/`; every other byte is
/// literal. A leading `^` is an exclusion and is stripped by [`PatternSet`],
/// not here.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Glob {
    pattern: String,
}

impl Glob {
    pub fn new(pattern: impl Into<String>) -> Self {
        Self {
            pattern: pattern.into(),
        }
    }

    pub fn pattern(&self) -> &str {
        &self.pattern
    }

    pub fn is_match(&self, text: &str) -> bool {
        glob_bytes(self.pattern.as_bytes(), text.as_bytes(), false)
    }

    /// Match without ASCII case (principals and tags are case-insensitive).
    pub fn is_match_ignore_ascii_case(&self, text: &str) -> bool {
        glob_bytes(self.pattern.as_bytes(), text.as_bytes(), true)
    }
}

/// Match `text` against `pattern` with the doublestar dialect.
pub fn glob_match(pattern: &str, text: &str) -> bool {
    glob_bytes(pattern.as_bytes(), text.as_bytes(), false)
}

fn glob_bytes(pattern: &[u8], text: &[u8], ignore_case: bool) -> bool {
    let mut pi = 0;
    let mut ti = 0;
    while pi < pattern.len() {
        match pattern[pi] {
            b'*' if pattern.get(pi + 1) == Some(&b'*') => {
                let mut rest = &pattern[pi + 2..];
                if rest.first() == Some(&b'/') {
                    rest = &rest[1..];
                }
                if rest.is_empty() {
                    return true;
                }
                let mut index = ti;
                loop {
                    if glob_bytes(rest, &text[index..], ignore_case) {
                        return true;
                    }
                    if index >= text.len() {
                        return false;
                    }
                    index += 1;
                }
            }
            b'*' => {
                let rest = &pattern[pi + 1..];
                if glob_bytes(rest, &text[ti..], ignore_case) {
                    return true;
                }
                while ti < text.len() && text[ti] != b'/' {
                    ti += 1;
                    if glob_bytes(rest, &text[ti..], ignore_case) {
                        return true;
                    }
                }
                return false;
            }
            b'?' => {
                if ti >= text.len() || text[ti] == b'/' {
                    return false;
                }
                ti += 1;
                pi += 1;
            }
            byte => {
                if ti >= text.len() || !byte_eq(byte, text[ti], ignore_case) {
                    return false;
                }
                ti += 1;
                pi += 1;
            }
        }
    }
    ti == text.len()
}

fn byte_eq(a: u8, b: u8, ignore_case: bool) -> bool {
    if ignore_case {
        a.eq_ignore_ascii_case(&b)
    } else {
        a == b
    }
}

/// A compiled ref/path pattern list.
///
/// Entries are evaluated in order; each matching entry sets the verdict
/// (inclusion when it has no `^`, exclusion when it does), so the last match
/// wins. With no inclusion entry the starting verdict is "match", which makes
/// an exclusion-only list a carve-out from everything.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PatternSet {
    entries: Vec<(bool, Glob)>,
    has_inclusion: bool,
}

impl PatternSet {
    pub fn compile(patterns: &[String]) -> Self {
        let mut entries = Vec::with_capacity(patterns.len());
        let mut has_inclusion = false;
        for pattern in patterns {
            match pattern.strip_prefix('^') {
                Some(rest) => entries.push((true, Glob::new(rest))),
                None => {
                    has_inclusion = true;
                    entries.push((false, Glob::new(pattern)));
                }
            }
        }
        Self {
            entries,
            has_inclusion,
        }
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn is_match(&self, text: &str) -> bool {
        let mut verdict = !self.has_inclusion;
        for (negated, glob) in &self.entries {
            if glob.is_match(text) {
                verdict = !negated;
            }
        }
        verdict
    }
}

// ---------------------------------------------------------------------------
// Actors / groups
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
enum ActorSpec {
    Group(String),
    Tag(Glob),
    Name(Glob),
}

fn parse_actor(spec: &str) -> ActorSpec {
    if let Some(name) = spec.strip_prefix("group:") {
        ActorSpec::Group(name.to_string())
    } else if let Some(tag) = spec.strip_prefix('@') {
        ActorSpec::Tag(Glob::new(tag))
    } else {
        ActorSpec::Name(Glob::new(spec))
    }
}

/// A compiled principal list with last-match-wins exclusions.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct ActorSet {
    entries: Vec<(bool, ActorSpec)>,
    has_inclusion: bool,
}

impl ActorSet {
    fn compile(specs: &[String]) -> Self {
        let mut entries = Vec::with_capacity(specs.len());
        let mut has_inclusion = false;
        for spec in specs {
            match spec.strip_prefix('^') {
                Some(rest) => entries.push((true, parse_actor(rest))),
                None => {
                    has_inclusion = true;
                    entries.push((false, parse_actor(spec)));
                }
            }
        }
        Self {
            entries,
            has_inclusion,
        }
    }

    fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    fn is_match(&self, principal: &str, tags: &[String], groups: &GroupTable<'_>) -> bool {
        let mut verdict = !self.has_inclusion;
        for (negated, spec) in &self.entries {
            let hit = match spec {
                // An unresolvable exclude still excludes; an unresolvable
                // include does not admit.
                ActorSpec::Group(name) if *negated && groups.get(name).is_none() => true,
                spec => actor_hit(spec, principal, tags, groups),
            };
            if hit {
                verdict = !negated;
            }
        }
        verdict
    }
}

fn actor_hit(spec: &ActorSpec, principal: &str, tags: &[String], groups: &GroupTable<'_>) -> bool {
    let mut stack = Vec::new();
    actor_hit_inner(spec, principal, tags, groups, &mut stack)
}

fn actor_hit_inner(
    spec: &ActorSpec,
    principal: &str,
    tags: &[String],
    groups: &GroupTable<'_>,
    stack: &mut Vec<String>,
) -> bool {
    match spec {
        ActorSpec::Group(name) => {
            if stack.iter().any(|seen| seen == name) {
                return false; // cycle: never admits
            }
            let Some(members) = groups.get(name) else {
                return false;
            };
            stack.push(name.clone());
            let hit = members.iter().any(|member| {
                let spec = parse_actor(member);
                actor_hit_inner(&spec, principal, tags, groups, stack)
            });
            stack.pop();
            hit
        }
        ActorSpec::Tag(glob) => tags.iter().any(|tag| {
            let tag = tag.strip_prefix('@').unwrap_or(tag);
            glob.is_match_ignore_ascii_case(tag)
        }),
        ActorSpec::Name(glob) => glob.is_match_ignore_ascii_case(principal),
    }
}

#[derive(Debug, Clone)]
struct GroupTable<'a> {
    map: BTreeMap<&'a str, &'a [String]>,
}

impl<'a> GroupTable<'a> {
    fn new(policy: &'a Policy) -> Self {
        let mut map = BTreeMap::new();
        for group in &policy.groups {
            // First definition wins; `validate` rejects duplicates anyway.
            map.entry(group.name.as_str())
                .or_insert(group.members.as_slice());
        }
        Self { map }
    }

    fn get(&self, name: &str) -> Option<&'a [String]> {
        self.map.get(name).copied()
    }
}

// ---------------------------------------------------------------------------
// Compiled evaluation
// ---------------------------------------------------------------------------

#[derive(Debug)]
struct CompiledPolicy<'a> {
    groups: GroupTable<'a>,
    rules: Vec<CompiledRule<'a>>,
}

impl<'a> CompiledPolicy<'a> {
    fn new(policy: &'a Policy) -> Self {
        Self {
            groups: GroupTable::new(policy),
            rules: policy.rules.iter().map(CompiledRule::new).collect(),
        }
    }

    fn deny(&self, context: &PushContext<'_>, update: &Update) -> Option<Denied> {
        let op = classify(update)?;
        for rule in &self.rules {
            let Effect::Protect { restricts, .. } = &rule.rule.effect else {
                continue;
            };
            if !rule.matches_identity(update.refname.as_str(), context, &self.groups) {
                continue;
            }
            let Some(kind) = restricts_operation(restricts, op) else {
                continue;
            };
            if !rule.bypass.is_empty()
                && rule
                    .bypass
                    .is_match(context.principal, context.tags, &self.groups)
            {
                continue;
            }
            return Some(Denied::new(
                rule.rule.name.clone(),
                format!("{} {} is restricted", kind.as_str(), update.refname),
            ));
        }
        None
    }
}

#[derive(Debug)]
struct CompiledRule<'a> {
    rule: &'a Rule,
    refs: PatternSet,
    principals: ActorSet,
    paths: PatternSet,
    bypass: ActorSet,
}

impl<'a> CompiledRule<'a> {
    fn new(rule: &'a Rule) -> Self {
        let bypass = match &rule.effect {
            Effect::Protect { bypass, .. } => ActorSet::compile(bypass),
            _ => ActorSet::default(),
        };
        Self {
            rule,
            refs: PatternSet::compile(&rule.r#match.refs),
            principals: ActorSet::compile(&rule.r#match.principals),
            paths: PatternSet::compile(&rule.r#match.paths),
            bypass,
        }
    }

    /// Refs and principals; `paths` is ignored (protect/history rule).
    fn matches_identity(
        &self,
        refname: &str,
        context: &PushContext<'_>,
        groups: &GroupTable<'_>,
    ) -> bool {
        self.refs.is_match(refname)
            && self
                .principals
                .is_match(context.principal, context.tags, groups)
    }

    /// `size` also ANDs the paths key: any changed path may match.
    fn matches_paths(&self, paths: &[String]) -> bool {
        self.paths.is_empty() || paths.iter().any(|path| self.paths.is_match(path))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Op {
    Create,
    Update,
    ForcePush,
    Delete,
}

impl Op {
    fn as_str(self) -> &'static str {
        match self {
            Self::Create => "create",
            Self::Update => "update",
            Self::ForcePush => "force-push",
            Self::Delete => "delete",
        }
    }
}

fn classify(update: &Update) -> Option<Op> {
    match (&update.old, &update.new) {
        (None, None) => None,
        (None, Some(_)) => Some(Op::Create),
        (Some(_), None) => Some(Op::Delete),
        (Some(old), Some(new)) => {
            if old.eq_ignore_ascii_case(new) {
                None
            } else if update.force || update.refname.starts_with("refs/tags/") {
                // Tags are never fast-forward in any useful sense.
                Some(Op::ForcePush)
            } else {
                Some(Op::Update)
            }
        }
    }
}

fn restricts_operation(restricts: &[Restrict], op: Op) -> Option<Op> {
    let hit = match op {
        Op::Create => restricts.contains(&Restrict::Create),
        Op::Update => restricts.contains(&Restrict::Update),
        // A force-push is still an update; either restriction blocks it.
        Op::ForcePush => {
            restricts.contains(&Restrict::ForcePush) || restricts.contains(&Restrict::Update)
        }
        Op::Delete => restricts.contains(&Restrict::Delete),
    };
    hit.then_some(op)
}

/// Resolved `history` limits for every update (first matching rule per field).
///
/// Structural only: the caller enforces. Never silently ignored.
pub fn check_history(policy: &Policy, context: &PushContext<'_>) -> Vec<RefLimits<HistoryLimits>> {
    check_history_with(&policy.compile(), context)
}

fn check_history_with(
    compiled: &CompiledPolicy<'_>,
    context: &PushContext<'_>,
) -> Vec<RefLimits<HistoryLimits>> {
    context
        .updates
        .iter()
        .map(|update| {
            let mut limits = HistoryLimits::default();
            for rule in &compiled.rules {
                let Effect::History {
                    allowed_forwards,
                    allow_unrelated,
                } = &rule.rule.effect
                else {
                    continue;
                };
                if !rule.matches_identity(update.refname.as_str(), context, &compiled.groups) {
                    continue;
                }
                if limits.allowed_forwards.is_none() {
                    limits.allowed_forwards = *allowed_forwards;
                }
                if limits.allow_unrelated.is_none() {
                    limits.allow_unrelated = *allow_unrelated;
                }
                if limits.is_complete() {
                    break;
                }
            }
            RefLimits {
                refname: update.refname.clone(),
                limits,
            }
        })
        .collect()
}

/// Resolved `size` ceilings for every update (first matching rule per field).
///
/// Structural only: the caller enforces against the bytes it ingests.
pub fn check_size(policy: &Policy, context: &PushContext<'_>) -> Vec<RefLimits<SizeLimits>> {
    check_size_with(&policy.compile(), context)
}

fn check_size_with(
    compiled: &CompiledPolicy<'_>,
    context: &PushContext<'_>,
) -> Vec<RefLimits<SizeLimits>> {
    context
        .updates
        .iter()
        .map(|update| {
            let mut limits = SizeLimits::default();
            for rule in &compiled.rules {
                let Effect::Size {
                    blob_bytes,
                    push_bytes,
                } = &rule.rule.effect
                else {
                    continue;
                };
                if !rule.matches_identity(update.refname.as_str(), context, &compiled.groups) {
                    continue;
                }
                if !rule.matches_paths(&update.paths) {
                    continue;
                }
                if limits.blob_bytes.is_none() {
                    limits.blob_bytes = *blob_bytes;
                }
                if limits.push_bytes.is_none() {
                    limits.push_bytes = *push_bytes;
                }
                if limits.is_complete() {
                    break;
                }
            }
            RefLimits {
                refname: update.refname.clone(),
                limits,
            }
        })
        .collect()
}

/// Evaluate the push; the first named denial becomes the error.
pub fn evaluate_push(policy: &Policy, context: &PushContext<'_>) -> Result<(), PolicyError> {
    match policy.evaluate(context).denials.into_iter().next() {
        Some(denied) => Err(denied.into()),
        None => Ok(()),
    }
}

// ---------------------------------------------------------------------------
// Effect parsing
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct EffectRepr {
    #[serde(default)]
    protect: Option<ProtectRepr>,
    #[serde(default)]
    history: Option<HistoryRepr>,
    #[serde(default)]
    size: Option<SizeRepr>,
    #[serde(default)]
    _comment: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ProtectRepr {
    #[serde(default, deserialize_with = "deserialize_restricts")]
    restricts: Option<Vec<Restrict>>,
    #[serde(default)]
    bypass: Vec<String>,
    #[serde(default)]
    _comment: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct HistoryRepr {
    #[serde(default)]
    allowed_forwards: Option<u64>,
    #[serde(default)]
    allow_unrelated: Option<bool>,
    #[serde(default)]
    _comment: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct SizeRepr {
    #[serde(default)]
    blob_bytes: Option<u64>,
    #[serde(default)]
    push_bytes: Option<u64>,
    #[serde(default)]
    _comment: Option<String>,
}

fn deserialize_restricts<'de, D>(deserializer: D) -> Result<Option<Vec<Restrict>>, D::Error>
where
    D: Deserializer<'de>,
{
    match Option::<Vec<Restrict>>::deserialize(deserializer)? {
        None => Err(de::Error::custom(
            "restricts: null is a parse error (omit the key to restrict all four operations)",
        )),
        Some(list) if list.is_empty() => Err(de::Error::custom(
            "restricts: [] is a parse error (omit the key to restrict all four operations)",
        )),
        Some(list) => Ok(Some(list)),
    }
}

impl<'de> Deserialize<'de> for Effect {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let repr = EffectRepr::deserialize(deserializer)?;
        let EffectRepr {
            protect,
            history,
            size,
            _comment: _,
        } = repr;
        let count = usize::from(protect.is_some())
            + usize::from(history.is_some())
            + usize::from(size.is_some());
        if count != 1 {
            return Err(de::Error::custom(
                "effect: exactly one of protect, history, size is required",
            ));
        }
        match (protect, history, size) {
            (Some(protect), None, None) => {
                let ProtectRepr {
                    restricts,
                    bypass,
                    _comment: _,
                } = protect;
                Ok(Effect::Protect {
                    restricts: restricts.unwrap_or_else(all_restricts),
                    bypass,
                })
            }
            (None, Some(history), None) => {
                let HistoryRepr {
                    allowed_forwards,
                    allow_unrelated,
                    _comment: _,
                } = history;
                Ok(Effect::History {
                    allowed_forwards,
                    allow_unrelated,
                })
            }
            (None, None, Some(size)) => {
                let SizeRepr {
                    blob_bytes,
                    push_bytes,
                    _comment: _,
                } = size;
                Ok(Effect::Size {
                    blob_bytes,
                    push_bytes,
                })
            }
            _ => Err(de::Error::custom(
                "effect: exactly one of protect, history, size is required",
            )),
        }
    }
}

impl Serialize for Effect {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        #[derive(Serialize)]
        struct ProtectBody<'a> {
            restricts: &'a [Restrict],
            bypass: &'a [String],
        }

        #[derive(Serialize)]
        struct HistoryBody {
            #[serde(skip_serializing_if = "Option::is_none")]
            allowed_forwards: Option<u64>,
            #[serde(skip_serializing_if = "Option::is_none")]
            allow_unrelated: Option<bool>,
        }

        #[derive(Serialize)]
        struct SizeBody {
            #[serde(skip_serializing_if = "Option::is_none")]
            blob_bytes: Option<u64>,
            #[serde(skip_serializing_if = "Option::is_none")]
            push_bytes: Option<u64>,
        }

        let mut map = serializer.serialize_map(Some(1))?;
        match self {
            Self::Protect { restricts, bypass } => {
                map.serialize_entry("protect", &ProtectBody { restricts, bypass })?;
            }
            Self::History {
                allowed_forwards,
                allow_unrelated,
            } => {
                map.serialize_entry(
                    "history",
                    &HistoryBody {
                        allowed_forwards: *allowed_forwards,
                        allow_unrelated: *allow_unrelated,
                    },
                )?;
            }
            Self::Size {
                blob_bytes,
                push_bytes,
            } => {
                map.serialize_entry(
                    "size",
                    &SizeBody {
                        blob_bytes: *blob_bytes,
                        push_bytes: *push_bytes,
                    },
                )?;
            }
        }
        map.end()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(json: &str) -> Policy {
        Policy::parse(json.as_bytes()).unwrap()
    }

    fn parse_err(json: &str) -> String {
        Policy::parse(json.as_bytes()).unwrap_err().to_string()
    }

    fn upd(refname: &str, old: &str, new: &str, force: bool) -> Update {
        let mut update = Update::from_oids(refname, old, new);
        update.force = force;
        update
    }

    fn ctx<'a>(principal: &'a str, tags: &'a [String], updates: &'a [Update]) -> PushContext<'a> {
        PushContext {
            principal,
            tags,
            updates,
        }
    }

    fn tags(values: &[&str]) -> Vec<String> {
        values.iter().map(|value| (*value).to_string()).collect()
    }

    const A: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const B: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

    #[test]
    fn missing_or_empty_policy_is_allow_all() {
        assert_eq!(Policy::load(None).unwrap(), Policy::allow_all());
        // A half-wired object fails closed; only a missing object is allow-all.
        assert!(Policy::parse(b"").is_err());
        assert!(Policy::parse(b"  \n\t").is_err());
        let updates = [
            upd("refs/heads/main", A, B, true),
            upd("refs/heads/gone", A, "", false),
        ];
        let evaluation = Policy::load(None)
            .unwrap()
            .evaluate(&ctx("anyone", &[], &updates));
        assert!(evaluation.is_allowed());
        assert!(evaluation
            .history
            .iter()
            .all(|limits| limits.limits == HistoryLimits::default()));
        assert!(evaluation
            .size
            .iter()
            .all(|limits| limits.limits == SizeLimits::default()));
        assert!(evaluate_push(&Policy::default(), &ctx("anyone", &[], &updates)).is_ok());
        let parsed = parse(r#"{"version":1,"rules":[]}"#);
        assert_eq!(parsed, Policy::allow_all());
        assert!(evaluate_push(&parsed, &ctx("anyone", &[], &updates)).is_ok());
    }

    #[test]
    fn envelope_errors_are_table_driven() {
        let bad = [
            r#"{"version":2,"rules":[]}"#,
            r#"{"version":0,"rules":[]}"#,
            r#"{"version":"1","rules":[]}"#,
            r#"{"version":1,"rules":{}}"#,
            r#"{"version":1,"groups":{}}"#,
            r#"{"version":1,"rules":null}"#,
            r#"{"version":1,"rules":[{"name":"x"}]}"#,
            r#"{"version":1,"rules":[{"name":"x","effect":{"protect":{}},"name":"y"}]}"#,
        ];
        for json in bad {
            assert!(Policy::parse(json.as_bytes()).is_err(), "{json}");
        }

        let good = [
            r#"{"version":1,"future_knob":true,"rules":[]}"#,
            r#"{"_comment":"envelope","version":1,"rules":[]}"#,
            r#"{"rules":[{"name":"x","effect":{"protect":{}}}]}"#,
        ];
        for json in good {
            assert!(Policy::parse(json.as_bytes()).is_ok(), "{json}");
        }
    }

    #[test]
    fn unknown_rule_and_effect_keys_are_parse_errors() {
        let bad = [
            r#"{"version":1,"rules":[{"name":"x","match":{},"effect":{"protect":{}},"typo":1}]}"#,
            r#"{"version":1,"rules":[{"name":"x","match":{"ref":[]},"effect":{"protect":{}}}]}"#,
            r#"{"version":1,"rules":[{"name":"x","match":{},"effect":{"protect":{"bypass_actrs":[]}}}]}"#,
            r#"{"version":1,"rules":[{"name":"x","match":{},"effect":{"history":{"max":1}}}]}"#,
            r#"{"version":1,"rules":[{"name":"x","match":{},"effect":{"size":{"max":1}}}]}"#,
            r#"{"version":1,"rules":[{"name":"x","match":{},"effect":{"protext":{}}}]}"#,
            r#"{"version":1,"rules":[{"name":"x","match":{},"effect":{"protect":{},"history":{}}}]}"#,
            r#"{"version":1,"rules":[{"name":"x","match":{},"effect":{}}]}"#,
            r#"{"version":1,"rules":[{"name":"x","match":{},"effect":{"protect":{"restricts":null}}}]}"#,
            r#"{"version":1,"rules":[{"name":"x","match":{},"effect":{"protect":{"restricts":[]}}}]}"#,
        ];
        for json in bad {
            assert!(Policy::parse(json.as_bytes()).is_err(), "{json}");
        }

        let good = r#"{
          "version": 1,
          "groups": [{"name":"g","_comment":"roster","members":[]}],
          "rules": [{
            "name": "x",
            "_comment": "rule",
            "match": {"_comment": "match"},
            "effect": {"_comment": "effect", "protect": {"_comment": "body"}}
          }]
        }"#;
        let policy = parse(good);
        assert_eq!(
            policy.rules[0].effect,
            Effect::Protect {
                restricts: all_restricts(),
                bypass: Vec::new()
            }
        );
    }

    #[test]
    fn names_are_validated_and_unique() {
        let valid = ["a", "a0", "release-tags", &"a".repeat(63)];
        for name in valid {
            let json = format!(
                r#"{{"version":1,"rules":[{{"name":"{name}","match":{{}},"effect":{{"protect":{{}}}}}}]}}"#
            );
            assert!(Policy::parse(json.as_bytes()).is_ok(), "{name}");
        }
        let invalid = ["", "A", "0a", "a_b", "a b", &"a".repeat(64), "a."];
        for name in invalid {
            let json = format!(
                r#"{{"version":1,"rules":[{{"name":"{name}","match":{{}},"effect":{{"protect":{{}}}}}}]}}"#
            );
            assert!(Policy::parse(json.as_bytes()).is_err(), "{name:?}");
        }
        let duplicate_rules = r#"{"version":1,"rules":[
            {"name":"x","match":{},"effect":{"protect":{}}},
            {"name":"x","match":{},"effect":{"protect":{}}}]}"#;
        assert!(parse_err(duplicate_rules).contains("duplicate rule name"));
        let duplicate_groups = r#"{"version":1,"groups":[
            {"name":"g","members":[]},{"name":"g","members":[]}],"rules":[]}"#;
        assert!(parse_err(duplicate_groups).contains("duplicate group name"));
        let group_typo = r#"{"version":1,"groups":[{"name":"g","member":[]}],"rules":[]}"#;
        assert!(Policy::parse(group_typo.as_bytes()).is_err());
    }

    #[test]
    fn mode_is_typed_and_invalid_values_are_parse_errors() {
        let enforce = r#"{"version":1,"rules":[
            {"name":"x","match":{},"mode":"enforce","effect":{"protect":{}}},
            {"name":"y","match":{},"mode":"audit","effect":{"protect":{}}}]}"#;
        let policy = parse(enforce);
        assert_eq!(policy.rules[0].mode, Some(RuleMode::Enforce));
        assert_eq!(policy.rules[1].mode, Some(RuleMode::Audit));
        assert_eq!(RuleMode::Enforce.as_str(), "enforce");
        assert_eq!(RuleMode::Audit.as_str(), "audit");

        let bad = r#"{"version":1,"rules":[
            {"name":"x","match":{},"mode":"warn","effect":{"protect":{}}}]}"#;
        assert!(Policy::parse(bad.as_bytes()).is_err());
    }

    #[test]
    fn doublestar_globs() {
        let cases = [
            ("refs/heads/main", "refs/heads/main", true),
            ("refs/heads/*", "refs/heads/main", true),
            ("refs/heads/*", "refs/heads/foo/bar", false),
            ("refs/heads/**", "refs/heads/foo/bar", true),
            ("refs/**/main", "refs/heads/main", true),
            ("refs/**/main", "refs/main", true),
            ("refs/tags/v?", "refs/tags/v1", true),
            ("refs/tags/v?", "refs/tags/v12", false),
            ("refs/tags/v?", "refs/tags/v/", false),
            ("**", "", true),
            ("*", "", true),
            ("refs/heads/main", "refs/heads/Main", false),
            ("refs/heads/ma*", "refs/heads/main", true),
            ("a?c", "abc", true),
            ("a?c", "a/c", false),
        ];
        for (pattern, text, expected) in cases {
            assert_eq!(glob_match(pattern, text), expected, "{pattern} vs {text}");
        }
        assert!(Glob::new("ALICE@EXAMPLE.COM").is_match_ignore_ascii_case("alice@example.com"));
    }

    #[test]
    fn pattern_lists_use_last_match_wins() {
        let cases = [
            (
                vec!["refs/heads/**", "^refs/heads/tmp/**"],
                "refs/heads/tmp/x",
                false,
            ),
            (
                vec!["^refs/heads/tmp/**", "refs/heads/**"],
                "refs/heads/tmp/x",
                true,
            ),
            (
                vec!["refs/heads/**", "^refs/heads/tmp/**"],
                "refs/heads/main",
                true,
            ),
            (vec!["^refs/heads/tmp/**"], "refs/heads/main", true),
            (vec!["^refs/heads/tmp/**"], "refs/heads/tmp/x", false),
            (vec!["refs/heads/main"], "refs/heads/dev", false),
            (vec![], "anything", true),
        ];
        for (patterns, text, expected) in cases {
            let patterns: Vec<String> = patterns.into_iter().map(str::to_string).collect();
            assert_eq!(
                PatternSet::compile(&patterns).is_match(text),
                expected,
                "{patterns:?} vs {text}"
            );
        }
    }

    #[test]
    fn exclusions_are_refused_on_history_and_size() {
        for effect in [r#"{"history":{}}"#, r#"{"size":{}}"#] {
            let json = format!(
                r#"{{"version":1,"rules":[{{"name":"x","match":{{"refs":["refs/**","^refs/notes/**"]}},"effect":{effect}}}]}}"#
            );
            assert!(Policy::parse(json.as_bytes()).is_err(), "{json}");
        }
        // Protect may carve out.
        let ok = parse(
            r#"{"version":1,"rules":[{"name":"x",
                "match":{"refs":["refs/**","^refs/notes/**"]},
                "effect":{"protect":{"restricts":["delete"]}}}]}"#,
        );
        assert_eq!(ok.rules.len(), 1);
    }

    #[test]
    fn match_keys_and_or_values() {
        let policy = parse(
            r#"{"version":1,"rules":[{
                "name":"guarded",
                "match":{"refs":["refs/heads/main","refs/tags/**"],
                         "principals":["alice@example.com","group:team"]},
                "effect":{"protect":{"restricts":["create"]}}}]}"#,
        );
        // In JSON the group is unknown, so only alice matches.
        let cases = [
            ("alice@example.com", "refs/heads/main", false),
            ("alice@example.com", "refs/tags/v1", false),
            ("alice@example.com", "refs/heads/dev", true),
            ("bob@example.com", "refs/heads/main", true),
        ];
        for (principal, refname, allowed) in cases {
            let updates = [upd(refname, "", A, false)];
            assert_eq!(
                evaluate_push(&policy, &ctx(principal, &[], &updates)).is_ok(),
                allowed,
                "{principal} {refname}"
            );
        }
    }

    #[test]
    fn groups_resolve_at_eval_and_unresolvable_never_admits() {
        let policy = parse(
            r#"{"version":1,
                "groups":[
                  {"name":"sre","members":["alice@example.com"]},
                  {"name":"admins","members":["group:sre","svc:queue"]}],
                "rules":[{
                  "name":"lock",
                  "match":{"refs":["refs/heads/main"]},
                  "effect":{"protect":{"restricts":["update"],
                                        "bypass":["group:admins"]}}}]}"#,
        );
        let updates = [upd("refs/heads/main", A, B, false)];
        assert!(evaluate_push(&policy, &ctx("alice@example.com", &[], &updates)).is_ok());
        assert!(evaluate_push(&policy, &ctx("svc:queue", &[], &updates)).is_ok());
        assert!(evaluate_push(&policy, &ctx("bob@example.com", &[], &updates)).is_err());

        // A bypass naming a missing roster never admits.
        let missing = parse(
            r#"{"version":1,"rules":[{"name":"lock",
                "match":{"refs":["refs/heads/main"]},
                "effect":{"protect":{"restricts":["update"],
                                     "bypass":["group:missing"]}}}]}"#,
        );
        assert!(evaluate_push(&missing, &ctx("alice@example.com", &[], &updates)).is_err());

        // An unresolvable include in `match` simply does not match.
        let inert = parse(
            r#"{"version":1,"rules":[{"name":"lock",
                "match":{"refs":["refs/heads/main"],"principals":["group:missing"]},
                "effect":{"protect":{"restricts":["update"]}}}]}"#,
        );
        assert!(evaluate_push(&inert, &ctx("alice@example.com", &[], &updates)).is_ok());

        // An unresolvable exclusion still excludes.
        let exclude = parse(
            r#"{"version":1,"rules":[{"name":"lock",
                "match":{"refs":["refs/heads/main"],"principals":["*","^group:missing"]},
                "effect":{"protect":{"restricts":["update"]}}}]}"#,
        );
        assert!(evaluate_push(&exclude, &ctx("alice@example.com", &[], &updates)).is_ok());
    }

    #[test]
    fn group_cycles_terminate_without_admitting() {
        let policy = parse(
            r#"{"version":1,
                "groups":[
                  {"name":"a","members":["group:b"]},
                  {"name":"b","members":["group:a"]}],
                "rules":[{"name":"lock",
                  "match":{"refs":["refs/heads/main"]},
                  "effect":{"protect":{"restricts":["update"],
                                       "bypass":["group:a"]}}}]}"#,
        );
        let updates = [upd("refs/heads/main", A, B, false)];
        assert!(evaluate_push(&policy, &ctx("alice@example.com", &[], &updates)).is_err());
    }

    #[test]
    fn tags_match_actor_specs_at_eval() {
        let policy = parse(
            r#"{"version":1,"rules":[{"name":"bots",
                "match":{"refs":["refs/heads/**"],"principals":["@ci","^intern"]},
                "effect":{"protect":{"restricts":["create"]}}}]}"#,
        );
        let create = [upd("refs/heads/x", "", A, false)];
        assert!(evaluate_push(&policy, &ctx("robot", &tags(&["ci"]), &create)).is_err());
        assert!(evaluate_push(&policy, &ctx("intern", &tags(&["ci"]), &create)).is_ok());
        assert!(evaluate_push(&policy, &ctx("robot", &[], &create)).is_ok());
        // The leading @ on stored tags is optional and case is ignored.
        assert!(evaluate_push(&policy, &ctx("robot", &tags(&["@CI"]), &create)).is_err());
    }

    #[test]
    fn a_bypass_only_bypasses_its_own_rule() {
        let policy = parse(
            r#"{"version":1,"rules":[
              {"name":"a","match":{"refs":["refs/heads/main"]},
               "effect":{"protect":{"restricts":["update"],
                                    "bypass":["alice@example.com"]}}},
              {"name":"b","match":{"refs":["refs/heads/main"]},
               "effect":{"protect":{"restricts":["update"]}}}]}"#,
        );
        let updates = [upd("refs/heads/main", A, B, false)];
        let denied = policy.evaluate(&ctx("alice@example.com", &[], &updates));
        assert_eq!(denied.denials.len(), 1);
        assert_eq!(denied.denials[0].rule, "b");
        assert!(evaluate_push(&policy, &ctx("bob@example.com", &[], &updates)).is_err());
        // Same bypass on both rules is loadable and admits.
        let both = parse(
            r#"{"version":1,"rules":[
              {"name":"a","match":{"refs":["refs/heads/main"]},
               "effect":{"protect":{"restricts":["update"],
                                    "bypass":["alice@example.com"]}}},
              {"name":"b","match":{"refs":["refs/heads/main"]},
               "effect":{"protect":{"restricts":["update"],
                                    "bypass":["alice@example.com"]}}}]}"#,
        );
        assert!(evaluate_push(&both, &ctx("alice@example.com", &[], &updates)).is_ok());
        assert!(evaluate_push(&both, &ctx("bob@example.com", &[], &updates)).is_err());
    }

    #[test]
    fn overlapping_disjoint_bypass_lists_are_rejected() {
        let json = r#"{"version":1,"rules":[
          {"name":"a","match":{"refs":["refs/heads/main"]},
           "effect":{"protect":{"bypass":["alice@example.com"]}}},
          {"name":"b","match":{"refs":["refs/heads/main"]},
           "effect":{"protect":{"bypass":["bob@example.com"]}}}]}"#;
        assert!(parse_err(json).contains("disjoint bypass"));
        // Disjoint restricted operations cannot lock anybody out.
        let ok = r#"{"version":1,"rules":[
          {"name":"a","match":{"refs":["refs/heads/main"]},
           "effect":{"protect":{"restricts":["create"],"bypass":["alice@example.com"]}}},
          {"name":"b","match":{"refs":["refs/heads/main"]},
           "effect":{"protect":{"restricts":["delete"],"bypass":["bob@example.com"]}}}]}"#;
        assert!(Policy::parse(ok.as_bytes()).is_ok());
    }

    #[test]
    fn create_update_force_and_delete_are_distinct() {
        let create = [upd("refs/heads/main", "", A, false)];
        let fast_forward = [upd("refs/heads/main", A, B, false)];
        let force = [upd("refs/heads/main", A, B, true)];
        let delete = [upd("refs/heads/main", A, "", false)];
        let no_op = [upd("refs/heads/main", A, A, false)];

        let protects = |operations: &str| {
            parse(&format!(
                r#"{{"version":1,"rules":[{{"name":"r",
                    "match":{{"refs":["refs/heads/main"]}},
                    "effect":{{"protect":{{"restricts":[{operations}]}}}}}}]}}"#
            ))
        };

        let restrict_create = protects(r#""create""#);
        assert!(evaluate_push(&restrict_create, &ctx("x", &[], &create)).is_err());
        assert!(evaluate_push(&restrict_create, &ctx("x", &[], &fast_forward)).is_ok());
        assert!(evaluate_push(&restrict_create, &ctx("x", &[], &force)).is_ok());
        assert!(evaluate_push(&restrict_create, &ctx("x", &[], &delete)).is_ok());

        let restrict_update = protects(r#""update""#);
        assert!(evaluate_push(&restrict_update, &ctx("x", &[], &fast_forward)).is_err());
        // A force-push is still an update.
        assert!(evaluate_push(&restrict_update, &ctx("x", &[], &force)).is_err());
        assert!(evaluate_push(&restrict_update, &ctx("x", &[], &create)).is_ok());

        let restrict_force = protects(r#""force-push""#);
        assert!(evaluate_push(&restrict_force, &ctx("x", &[], &fast_forward)).is_ok());
        assert!(evaluate_push(&restrict_force, &ctx("x", &[], &force)).is_err());

        let restrict_delete = protects(r#""delete""#);
        assert!(evaluate_push(&restrict_delete, &ctx("x", &[], &delete)).is_err());
        assert!(evaluate_push(&restrict_delete, &ctx("x", &[], &fast_forward)).is_ok());

        for policy in [
            &restrict_create,
            &restrict_update,
            &restrict_force,
            &restrict_delete,
        ] {
            assert!(evaluate_push(policy, &ctx("x", &[], &no_op)).is_ok());
        }
    }

    #[test]
    fn tag_retarget_is_force_even_without_the_flag() {
        let policy = parse(
            r#"{"version":1,"rules":[{"name":"tags-immutable",
                "match":{"refs":["refs/tags/**"]},
                "effect":{"protect":{"restricts":["force-push"]}}}]}"#,
        );
        let retarget = [upd("refs/tags/v1", A, B, false)];
        assert!(evaluate_push(&policy, &ctx("x", &[], &retarget)).is_err());
        // First tag creation is not a retarget.
        let create = [upd("refs/tags/v1", "", B, false)];
        assert!(evaluate_push(&policy, &ctx("x", &[], &create)).is_ok());
        // Moving to the same object is a no-op.
        let same = [upd("refs/tags/v1", A, A, false)];
        assert!(evaluate_push(&policy, &ctx("x", &[], &same)).is_ok());
    }

    #[test]
    fn admins_have_no_implicit_bypass() {
        let policy = parse(
            r#"{"version":1,"rules":[{"name":"lock",
                "match":{"refs":["refs/heads/main"]},
                "effect":{"protect":{"restricts":["update"]}}}]}"#,
        );
        let updates = [upd("refs/heads/main", A, B, false)];
        for principal in ["admin", "root@example.com", "svc:root"] {
            assert!(
                evaluate_push(&policy, &ctx(principal, &[], &updates)).is_err(),
                "{principal}"
            );
        }
    }

    #[test]
    fn denial_is_named_and_evaluate_push_reports_it() {
        let policy = parse(
            r#"{"version":1,"rules":[{"name":"lock-main",
                "match":{"refs":["refs/heads/main"]},
                "effect":{"protect":{"restricts":["force-push"]}}}]}"#,
        );
        let updates = [
            upd("refs/heads/dev", A, B, true),
            upd("refs/heads/main", A, B, true),
        ];
        let evaluation = policy.evaluate(&ctx("bob", &[], &updates));
        assert!(!evaluation.is_allowed());
        assert_eq!(evaluation.denials.len(), 1);
        assert_eq!(
            evaluation.denials[0],
            Denied {
                rule: "lock-main".into(),
                reason: "force-push refs/heads/main is restricted".into()
            }
        );
        assert_eq!(
            evaluation.denials[0].to_string(),
            "rejected by rule 'lock-main': force-push refs/heads/main is restricted"
        );
        let error = evaluate_push(&policy, &ctx("bob", &[], &updates)).unwrap_err();
        assert!(error.to_string().contains("lock-main"), "{error}");
    }

    #[test]
    fn history_is_structural_and_first_match_per_field() {
        let policy = parse(
            r#"{"version":1,"rules":[
              {"name":"main","match":{"refs":["refs/heads/main"]},
               "effect":{"history":{"allowed_forwards":5}}},
              {"name":"wide","match":{"refs":["refs/heads/**"]},
               "effect":{"history":{"allowed_forwards":9,"allow_unrelated":true}}}]}"#,
        );
        let main = [upd("refs/heads/main", A, B, true)];
        let dev = [upd("refs/heads/dev", A, B, false)];
        let main_limits = policy.check_history(&ctx("x", &[], &main));
        assert_eq!(main_limits[0].refname, "refs/heads/main");
        assert_eq!(
            main_limits[0].limits,
            HistoryLimits {
                allowed_forwards: Some(5),
                allow_unrelated: Some(true),
            }
        );
        let dev_limits = policy.check_history(&ctx("x", &[], &dev));
        assert_eq!(
            dev_limits[0].limits,
            HistoryLimits {
                allowed_forwards: Some(9),
                allow_unrelated: Some(true),
            }
        );
        // Parsed and exposed, never silently enforced or ignored.
        assert!(policy.evaluate(&ctx("x", &[], &main)).is_allowed());
        assert_eq!(policy.evaluate(&ctx("x", &[], &main)).history, main_limits);
    }

    #[test]
    fn size_is_first_match_per_field_and_uses_paths() {
        let policy = parse(
            r#"{"version":1,"rules":[
              {"name":"vendor","match":{"paths":["vendor/**"]},
               "effect":{"size":{"blob_bytes":10}}},
              {"name":"main","match":{"refs":["refs/heads/main"]},
               "effect":{"size":{"push_bytes":100}}},
              {"name":"wide","match":{"refs":["refs/heads/**"]},
               "effect":{"size":{"blob_bytes":999,"push_bytes":999}}}]}"#,
        );
        let main = [upd("refs/heads/main", A, B, false).with_paths(["src/lib.rs"])];
        let limits = policy.check_size(&ctx("x", &[], &main));
        assert_eq!(
            limits[0].limits,
            SizeLimits {
                blob_bytes: Some(999),
                push_bytes: Some(100),
            }
        );
        let vendor = [upd("refs/heads/main", A, B, false).with_paths(["vendor/a.js"])];
        let limits = policy.check_size(&ctx("x", &[], &vendor));
        assert_eq!(
            limits[0].limits,
            SizeLimits {
                blob_bytes: Some(10),
                push_bytes: Some(100),
            }
        );
        // A size rule that asks about paths cannot match a push whose paths
        // are unknown.
        let unknown = [upd("refs/heads/main", A, B, false)];
        let limits = policy.check_size(&ctx("x", &[], &unknown));
        assert_eq!(limits[0].limits.blob_bytes, Some(999));
        assert_eq!(limits[0].limits.push_bytes, Some(100));
    }

    #[test]
    fn paths_are_ignored_by_protect_and_history() {
        let policy = parse(
            r#"{"version":1,"rules":[{"name":"p",
                "match":{"refs":["refs/heads/main"],"paths":["vendor/**"]},
                "effect":{"protect":{"restricts":["create"]}}}]}"#,
        );
        let create = [upd("refs/heads/main", "", A, false)];
        assert!(evaluate_push(&policy, &ctx("x", &[], &create)).is_err());
    }

    #[test]
    fn real_world_document_drives_the_matcher() {
        let policy = parse(
            r#"{
              "version": 1,
              "groups": [
                {"name": "admins", "members": ["@okta:sre"]},
                {"name": "queue",  "members": ["svc:merge-queue"]}
              ],
              "rules": [
                {"name": "lock-main", "match": {"refs": ["refs/heads/main"]},
                 "effect": {"protect": {"restricts": ["create","delete","update"],
                                        "bypass": ["group:admins","group:queue"]}}},
                {"name": "tags-immutable",
                 "match": {"refs": ["refs/tags/**","^refs/tags/tmp/**"]},
                 "effect": {"protect": {"restricts": ["update","delete"],
                                        "bypass": ["group:admins"]}}},
                {"name": "reserve-queue-ns",
                 "match": {"refs": ["refs/heads/mq/**"]},
                 "effect": {"protect": {"bypass": ["group:queue","group:admins"]}}}
              ]
            }"#,
        );
        let sre = tags(&["okta:sre"]);
        let main_update = [upd("refs/heads/main", A, B, false)];
        let main_delete = [upd("refs/heads/main", A, "", false)];
        let tag_move = [upd("refs/tags/v1", A, B, false)];
        let tag_tmp = [upd("refs/tags/tmp/x", A, B, false)];
        let mq = [upd("refs/heads/mq/x", A, B, false)];

        assert!(evaluate_push(&policy, &ctx("bob", &[], &main_update)).is_err());
        assert!(evaluate_push(&policy, &ctx("alice", &sre, &main_update)).is_ok());
        assert!(evaluate_push(&policy, &ctx("alice", &sre, &main_delete)).is_ok());
        assert!(evaluate_push(&policy, &ctx("svc:merge-queue", &[], &mq)).is_ok());
        assert!(evaluate_push(&policy, &ctx("bob", &[], &mq)).is_err());
        assert!(evaluate_push(&policy, &ctx("alice", &sre, &tag_move)).is_ok());
        assert!(evaluate_push(&policy, &ctx("bob", &[], &tag_move)).is_err());
        assert!(evaluate_push(&policy, &ctx("bob", &[], &tag_tmp)).is_ok());
    }

    #[test]
    fn json_round_trip_preserves_semantics() {
        let policy = parse(
            r#"{"version":1,
                "groups":[{"name":"admins","members":["alice@example.com"]}],
                "rules":[
                  {"name":"lock","match":{"refs":["refs/heads/main"]},
                   "effect":{"protect":{"restricts":["delete"],
                                        "bypass":["group:admins"]}}},
                  {"name":"hist","match":{"refs":["refs/heads/**"]},
                   "effect":{"history":{"allowed_forwards":4}}},
                  {"name":"big","match":{"paths":["**"]},
                   "effect":{"size":{"push_bytes":1024}}}]}"#,
        );
        let encoded = policy.to_json_vec().unwrap();
        let decoded = Policy::parse(&encoded).unwrap();
        assert_eq!(decoded, policy);
        assert!(decoded
            .to_json_string()
            .unwrap()
            .contains("refs/heads/main"));
    }

    #[test]
    fn update_constructors_normalize_oids() {
        let zeros = "0".repeat(40);
        let create = Update::from_oids("refs/heads/x", &zeros, A);
        assert_eq!(create.old, None);
        assert_eq!(create.new.as_deref(), Some(A));
        let delete = Update::from_oids("refs/heads/x", A, &zeros);
        assert_eq!(delete.old.as_deref(), Some(A));
        assert_eq!(delete.new, None);
        let forced = Update::from_oids("refs/heads/x", A, B).forced();
        assert!(forced.force);
        let paths = Update::from_oids("refs/heads/x", A, B).with_paths(["a", "b"]);
        assert_eq!(paths.paths, vec!["a".to_string(), "b".to_string()]);
    }
}
