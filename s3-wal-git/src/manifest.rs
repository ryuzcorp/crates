//! Manifest formats.
//!
//! A manifest is the only source of truth for a repository's refs. Every
//! publish writes a complete new one after its tip bundles land; readers never
//! see a ref whose bundle is missing.
//!
//! [`RefsManifest`] is the generic format:
//!
//! ```json
//! {"version": 1, "seq": 7, "refs": {"refs/heads/main": {"sha": "…", "bundle": "git/app/refs/heads/main/….bundle"}}}
//! ```
//!
//! Applications with an existing on-disk format implement [`ManifestCodec`]
//! for their own type instead; the WAL never assumes the JSON shape.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

/// Manifest format version this crate writes and reads.
pub const MANIFEST_VERSION: u8 = 1;

/// One live ref tip: the commit and the immutable bundle holding it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ManifestRef {
    pub sha: String,
    pub bundle: String,
}

/// The WAL format shared by generic multi-ref repositories.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RefsManifest {
    pub version: u8,
    pub seq: u64,
    pub refs: BTreeMap<String, ManifestRef>,
}

/// Application-owned manifest shape.
///
/// `decode` must reject formats it does not understand; `build` must be able
/// to represent every ref the repository tracks. [`Self::refs`] is the
/// normalized view the WAL operates on (full ref names such as
/// `refs/heads/main`), independent of the on-disk field names.
pub trait ManifestCodec: Send + Sync {
    type Manifest: Send + Sync;

    fn encode(&self, manifest: &Self::Manifest) -> anyhow::Result<Vec<u8>>;
    fn decode(&self, bytes: &[u8]) -> anyhow::Result<Self::Manifest>;
    fn seq(&self, manifest: &Self::Manifest) -> u64;
    fn refs(&self, manifest: &Self::Manifest) -> Vec<(String, ManifestRef)>;
    fn build(&self, seq: u64, refs: Vec<(String, ManifestRef)>) -> anyhow::Result<Self::Manifest>;

    /// [`Self::refs`] as a map (last duplicate wins).
    fn refs_map(&self, manifest: &Self::Manifest) -> BTreeMap<String, ManifestRef> {
        self.refs(manifest).into_iter().collect()
    }
}

/// [`ManifestCodec`] for [`RefsManifest`].
#[derive(Debug, Clone, Copy, Default)]
pub struct RefsCodec;

impl ManifestCodec for RefsCodec {
    type Manifest = RefsManifest;

    fn encode(&self, manifest: &RefsManifest) -> anyhow::Result<Vec<u8>> {
        Ok(serde_json::to_vec(manifest)?)
    }

    fn decode(&self, bytes: &[u8]) -> anyhow::Result<RefsManifest> {
        let manifest: RefsManifest = serde_json::from_slice(bytes)?;
        if manifest.version != MANIFEST_VERSION {
            anyhow::bail!("manifest version {} unsupported", manifest.version);
        }
        Ok(manifest)
    }

    fn seq(&self, manifest: &RefsManifest) -> u64 {
        manifest.seq
    }

    fn refs(&self, manifest: &RefsManifest) -> Vec<(String, ManifestRef)> {
        manifest
            .refs
            .iter()
            .map(|(refname, entry)| (refname.clone(), entry.clone()))
            .collect()
    }

    fn build(&self, seq: u64, refs: Vec<(String, ManifestRef)>) -> anyhow::Result<RefsManifest> {
        Ok(RefsManifest {
            version: MANIFEST_VERSION,
            seq,
            refs: refs.into_iter().collect(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn refs_manifest_roundtrips_and_rejects_unknown_versions() {
        let manifest = RefsManifest {
            version: MANIFEST_VERSION,
            seq: 7,
            refs: BTreeMap::from([(
                "refs/heads/main".to_string(),
                ManifestRef {
                    sha: "a".repeat(40),
                    bundle: "git/demo/refs/heads/main/aaa.bundle".to_string(),
                },
            )]),
        };
        let bytes = RefsCodec.encode(&manifest).unwrap();
        let back = RefsCodec.decode(&bytes).unwrap();
        assert_eq!(back.seq, 7);
        assert_eq!(back.refs["refs/heads/main"].sha, "a".repeat(40));
        assert_eq!(RefsCodec.seq(&back), 7);
        assert_eq!(RefsCodec.refs(&back).len(), 1);

        let mut newer = manifest;
        newer.version = 2;
        assert!(RefsCodec
            .decode(&serde_json::to_vec(&newer).unwrap())
            .is_err());
    }

    #[test]
    fn build_preserves_seq_and_refs() {
        let built = RefsCodec
            .build(
                4,
                vec![(
                    "refs/heads/main".to_string(),
                    ManifestRef {
                        sha: "b".repeat(40),
                        bundle: "k".to_string(),
                    },
                )],
            )
            .unwrap();
        assert_eq!(built.seq, 4);
        assert_eq!(built.version, MANIFEST_VERSION);
        assert_eq!(built.refs.len(), 1);
    }
}
