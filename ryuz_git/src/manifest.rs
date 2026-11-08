//! Manifest formats.
//!
//! A manifest is the only source of truth for a repository's refs (and, in
//! pack mode, its live pack set and log window). Every publish writes a
//! complete new one after the immutable objects land, using a conditional
//! write so two writers cannot both win.
//!
//! [`RefsManifest`] is the generic format. Applications with an existing
//! on-disk shape implement [`ManifestCodec`] for their own type; the WAL never
//! assumes the JSON field names.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::config::Layout;

/// Manifest format this crate writes. Readers accept older versions.
pub const MANIFEST_VERSION: u8 = 2;
/// Oldest manifest version still readable.
pub const MIN_MANIFEST_VERSION: u8 = 1;

/// One live ref tip: the commit and, in bundle mode, its immutable bundle.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ManifestRef {
    pub sha: String,
    /// Bundle key in bundle mode. Pack-mode manifests may omit it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bundle: Option<String>,
}

impl ManifestRef {
    pub fn bundle(sha: impl Into<String>, bundle: impl Into<String>) -> Self {
        Self {
            sha: sha.into(),
            bundle: Some(bundle.into()),
        }
    }

    pub fn pack(sha: impl Into<String>) -> Self {
        Self {
            sha: sha.into(),
            bundle: None,
        }
    }
}

/// What kind of objects a pack holds. Labels never authorize access.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum PackKind {
    #[default]
    Objects,
    History,
    Blobs,
}

/// One immutable pack in the live (or retired) set.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PackRef {
    pub checksum: String,
    pub pack_size: u64,
    pub idx_size: u64,
    pub object_count: u64,
    /// WAL sequence that introduced the pack.
    pub seq: u64,
    /// 0 = push, 1 = compacted, 2 = base.
    #[serde(default)]
    pub tier: u32,
    #[serde(default)]
    pub has_rev: bool,
    #[serde(default)]
    pub has_bitmap: bool,
    #[serde(default)]
    pub has_commit_graph: bool,
    #[serde(default)]
    pub kind: PackKind,
}

impl PackRef {
    pub fn pack_key(&self, layout: &Layout, slug: &str) -> String {
        layout.pack_key(slug, &self.checksum, "pack")
    }

    pub fn idx_key(&self, layout: &Layout, slug: &str) -> String {
        layout.pack_key(slug, &self.checksum, "idx")
    }

    pub fn rev_key(&self, layout: &Layout, slug: &str) -> String {
        layout.pack_key(slug, &self.checksum, "rev")
    }
}

/// A retired pack: its bytes stay downloadable; it is no longer live.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RetiredPack {
    pub checksum: String,
    pub retired_at: String,
    pub retired_seq: u64,
}

/// One immutable log segment.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LogSegmentRef {
    pub key: String,
    pub first_seq: u64,
    pub last_seq: u64,
    pub size: u64,
    #[serde(default)]
    pub sealed: bool,
}

/// Folded state pointer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CheckpointRef {
    pub seq: u64,
    pub key: String,
    pub refs_key: String,
}

/// Versioned per-repository settings.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RepoSetting {
    pub toml: String,
    pub revision: u64,
    pub author: String,
    pub updated_at: String,
    #[serde(default)]
    pub message: String,
}

/// The generic WAL manifest.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RefsManifest {
    pub version: u8,
    /// Logical publish counter.
    pub seq: u64,
    /// Monotonic manifest writes (diagnostics).
    #[serde(default)]
    pub revision: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub writer: Option<String>,
    #[serde(default)]
    pub refs: BTreeMap<String, ManifestRef>,
    /// Symbolic `HEAD` target, e.g. `refs/heads/main`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub head: Option<String>,
    /// Peeled tag targets (`^{}`) so replicas advertise without objects.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub peeled: BTreeMap<String, String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub packs: Vec<PackRef>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub retired_packs: Vec<RetiredPack>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub log: Vec<LogSegmentRef>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub checkpoint: Option<CheckpointRef>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub settings: Option<RepoSetting>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub updated_at: Option<String>,
}

/// The complete state a publish writes.
#[derive(Debug, Clone, Default)]
pub struct ManifestState {
    pub seq: u64,
    pub revision: u64,
    pub writer: Option<String>,
    pub refs: BTreeMap<String, ManifestRef>,
    pub head: Option<String>,
    pub peeled: BTreeMap<String, String>,
    pub packs: Vec<PackRef>,
    pub retired_packs: Vec<RetiredPack>,
    pub log: Vec<LogSegmentRef>,
    pub checkpoint: Option<CheckpointRef>,
    pub settings: Option<RepoSetting>,
    pub updated_at: Option<String>,
}

impl ManifestState {
    /// Whether this state carries anything beyond refs and seq.
    fn has_extended(&self) -> bool {
        self.revision != 0
            || self.writer.is_some()
            || self.head.is_some()
            || !self.peeled.is_empty()
            || !self.packs.is_empty()
            || !self.retired_packs.is_empty()
            || !self.log.is_empty()
            || self.checkpoint.is_some()
            || self.settings.is_some()
            || self.updated_at.is_some()
    }
}

/// Application-owned manifest shape.
pub trait ManifestCodec: Send + Sync {
    type Manifest: Send + Sync;

    fn encode(&self, manifest: &Self::Manifest) -> anyhow::Result<Vec<u8>>;
    fn decode(&self, bytes: &[u8]) -> anyhow::Result<Self::Manifest>;
    fn seq(&self, manifest: &Self::Manifest) -> u64;
    fn refs(&self, manifest: &Self::Manifest) -> Vec<(String, ManifestRef)>;
    fn build(&self, seq: u64, refs: Vec<(String, ManifestRef)>) -> anyhow::Result<Self::Manifest>;

    /// Full state view. Codecs that only model refs keep the default.
    fn state(&self, manifest: &Self::Manifest) -> ManifestState {
        ManifestState {
            seq: self.seq(manifest),
            refs: self.refs(manifest).into_iter().collect(),
            ..ManifestState::default()
        }
    }

    /// Build from a full state. The default refuses to silently drop data.
    #[allow(clippy::wrong_self_convention)]
    fn from_state(&self, state: ManifestState) -> anyhow::Result<Self::Manifest> {
        if state.has_extended() {
            anyhow::bail!(
                "manifest codec does not model packs/log/head/settings; use RefsCodec or override from_state"
            );
        }
        self.build(state.seq, state.refs.into_iter().collect())
    }

    fn refs_map(&self, manifest: &Self::Manifest) -> BTreeMap<String, ManifestRef> {
        self.refs(manifest).into_iter().collect()
    }
}

/// [`ManifestCodec`] for [`RefsManifest`]. Accepts v1 manifests (refs only)
/// and writes v2.
#[derive(Debug, Clone, Copy, Default)]
pub struct RefsCodec;

impl RefsCodec {
    fn decode_v1(bytes: &[u8]) -> anyhow::Result<RefsManifest> {
        let old: RefsManifest = serde_json::from_slice(bytes)?;
        let mut manifest = old;
        manifest.version = MANIFEST_VERSION;
        Ok(manifest)
    }
}

impl ManifestCodec for RefsCodec {
    type Manifest = RefsManifest;

    fn encode(&self, manifest: &RefsManifest) -> anyhow::Result<Vec<u8>> {
        Ok(serde_json::to_vec(manifest)?)
    }

    fn decode(&self, bytes: &[u8]) -> anyhow::Result<RefsManifest> {
        let probe: serde_json::Value = serde_json::from_slice(bytes)?;
        let version = probe
            .get("version")
            .and_then(serde_json::Value::as_u64)
            .unwrap_or(1) as u8;
        if !(MIN_MANIFEST_VERSION..=MANIFEST_VERSION).contains(&version) {
            anyhow::bail!("manifest version {version} unsupported");
        }
        if version == 1 {
            return Self::decode_v1(bytes);
        }
        let manifest: RefsManifest = serde_json::from_slice(bytes)?;
        Ok(manifest)
    }

    fn seq(&self, manifest: &RefsManifest) -> u64 {
        manifest.seq
    }

    fn refs(&self, manifest: &RefsManifest) -> Vec<(String, ManifestRef)> {
        manifest
            .refs
            .iter()
            .map(|(name, entry)| (name.clone(), entry.clone()))
            .collect()
    }

    fn build(&self, seq: u64, refs: Vec<(String, ManifestRef)>) -> anyhow::Result<RefsManifest> {
        Ok(RefsManifest {
            version: MANIFEST_VERSION,
            seq,
            refs: refs.into_iter().collect(),
            ..RefsManifest::default()
        })
    }

    fn state(&self, manifest: &RefsManifest) -> ManifestState {
        ManifestState {
            seq: manifest.seq,
            revision: manifest.revision,
            writer: manifest.writer.clone(),
            refs: manifest.refs.clone(),
            head: manifest.head.clone(),
            peeled: manifest.peeled.clone(),
            packs: manifest.packs.clone(),
            retired_packs: manifest.retired_packs.clone(),
            log: manifest.log.clone(),
            checkpoint: manifest.checkpoint.clone(),
            settings: manifest.settings.clone(),
            updated_at: manifest.updated_at.clone(),
        }
    }

    fn from_state(&self, state: ManifestState) -> anyhow::Result<RefsManifest> {
        Ok(RefsManifest {
            version: MANIFEST_VERSION,
            seq: state.seq,
            revision: state.revision,
            writer: state.writer,
            refs: state.refs,
            head: state.head,
            peeled: state.peeled,
            packs: state.packs,
            retired_packs: state.retired_packs,
            log: state.log,
            checkpoint: state.checkpoint,
            settings: state.settings,
            updated_at: state.updated_at,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn v1_manifest_reads_as_v2() {
        let v1 = br#"{"version":1,"seq":3,"refs":{"refs/heads/main":{"sha":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","bundle":"git/a/main/a.bundle"}}}"#;
        let manifest = RefsCodec.decode(v1).unwrap();
        assert_eq!(manifest.version, MANIFEST_VERSION);
        assert_eq!(manifest.seq, 3);
        assert_eq!(
            manifest.refs["refs/heads/main"].bundle.as_deref(),
            Some("git/a/main/a.bundle")
        );
        assert!(manifest.packs.is_empty());
    }

    #[test]
    fn v2_roundtrip_keeps_every_field() {
        let state = ManifestState {
            seq: 9,
            revision: 4,
            writer: Some("host-1".into()),
            refs: BTreeMap::from([(
                "refs/heads/main".to_string(),
                ManifestRef::bundle("a".repeat(40), "git/a/main/a.bundle"),
            )]),
            head: Some("refs/heads/main".into()),
            peeled: BTreeMap::from([("refs/tags/v1".to_string(), "b".repeat(40))]),
            packs: vec![PackRef {
                checksum: "c".repeat(40),
                pack_size: 10,
                idx_size: 2,
                object_count: 3,
                seq: 9,
                tier: 0,
                has_rev: true,
                has_bitmap: false,
                has_commit_graph: false,
                kind: PackKind::Objects,
            }],
            retired_packs: vec![RetiredPack {
                checksum: "d".repeat(40),
                retired_at: "2026-01-01T00:00:00Z".into(),
                retired_seq: 8,
            }],
            log: vec![LogSegmentRef {
                key: "log/0000000000000009.pb".into(),
                first_seq: 9,
                last_seq: 9,
                size: 42,
                sealed: true,
            }],
            checkpoint: Some(CheckpointRef {
                seq: 4,
                key: "checkpoints/4/checkpoint.json".into(),
                refs_key: "checkpoints/4/refs.json".into(),
            }),
            settings: Some(RepoSetting {
                toml: "[maintenance]\n".into(),
                revision: 1,
                author: "me".into(),
                updated_at: "2026-01-01T00:00:00Z".into(),
                message: "init".into(),
            }),
            updated_at: Some("2026-01-01T00:00:00Z".into()),
        };
        let manifest = RefsCodec.from_state(state.clone()).unwrap();
        let bytes = RefsCodec.encode(&manifest).unwrap();
        let back = RefsCodec.decode(&bytes).unwrap();
        let state_back = RefsCodec.state(&back);
        assert_eq!(state_back.seq, state.seq);
        assert_eq!(state_back.packs, state.packs);
        assert_eq!(state_back.log, state.log);
        assert_eq!(state_back.head, state.head);
        assert_eq!(state_back.settings, state.settings);
    }

    #[test]
    fn unknown_versions_are_refused() {
        assert!(RefsCodec
            .decode(br#"{"version":99,"seq":1,"refs":{}}"#)
            .is_err());
    }
}
