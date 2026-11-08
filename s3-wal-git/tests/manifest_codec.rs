use std::collections::BTreeMap;

use s3_wal_git::manifest::{
    ManifestCodec, ManifestRef, ManifestState, RefsManifest, MANIFEST_VERSION,
};
use serde::{Deserialize, Serialize};

/// An application-owned single-ref format, like a forge with `main` and
/// `preview` fields instead of a refs map.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct LegacyManifest {
    version: u8,
    seq: u64,
    main: Option<ManifestRef>,
    #[serde(default)]
    preview: Option<ManifestRef>,
}

struct LegacyCodec;

impl ManifestCodec for LegacyCodec {
    type Manifest = LegacyManifest;

    fn encode(&self, manifest: &LegacyManifest) -> anyhow::Result<Vec<u8>> {
        Ok(serde_json::to_vec(manifest)?)
    }

    fn decode(&self, bytes: &[u8]) -> anyhow::Result<LegacyManifest> {
        let manifest: LegacyManifest = serde_json::from_slice(bytes)?;
        anyhow::ensure!(
            manifest.version == MANIFEST_VERSION,
            "unsupported manifest version {}",
            manifest.version
        );
        Ok(manifest)
    }

    fn seq(&self, manifest: &LegacyManifest) -> u64 {
        manifest.seq
    }

    fn refs(&self, manifest: &LegacyManifest) -> Vec<(String, ManifestRef)> {
        let mut refs = Vec::new();
        if let Some(main) = &manifest.main {
            refs.push(("refs/heads/main".to_string(), main.clone()));
        }
        if let Some(preview) = &manifest.preview {
            refs.push(("refs/heads/preview".to_string(), preview.clone()));
        }
        refs
    }

    fn build(&self, seq: u64, refs: Vec<(String, ManifestRef)>) -> anyhow::Result<LegacyManifest> {
        let mut manifest = LegacyManifest {
            version: MANIFEST_VERSION,
            seq,
            main: None,
            preview: None,
        };
        for (name, entry) in refs {
            match name.as_str() {
                "refs/heads/main" => manifest.main = Some(entry),
                "refs/heads/preview" => manifest.preview = Some(entry),
                other => anyhow::bail!("legacy format does not model {other}"),
            }
        }
        Ok(manifest)
    }

    fn state(&self, manifest: &LegacyManifest) -> ManifestState {
        ManifestState {
            seq: manifest.seq,
            refs: self.refs(manifest).into_iter().collect(),
            ..ManifestState::default()
        }
    }

    fn from_state(&self, state: ManifestState) -> anyhow::Result<LegacyManifest> {
        self.build(state.seq, state.refs.into_iter().collect())
    }
}

#[test]
fn an_app_owned_format_shares_the_wal_and_keeps_its_json_shape() {
    let codec = LegacyCodec;
    let main = ManifestRef::bundle("a".repeat(40), "git/app/main/a.bundle");
    let preview = ManifestRef::bundle("b".repeat(40), "git/app/preview/b.bundle");
    let manifest = codec
        .build(
            7,
            vec![
                ("refs/heads/main".into(), main.clone()),
                ("refs/heads/preview".into(), preview.clone()),
            ],
        )
        .unwrap();
    let bytes = codec.encode(&manifest).unwrap();
    let text = String::from_utf8(bytes.clone()).unwrap();
    assert!(text.contains("\"main\""), "{text}");
    assert!(text.contains("\"preview\""), "{text}");
    assert!(!text.contains("\"refs\""), "{text}");

    let back = codec.decode(&bytes).unwrap();
    assert_eq!(codec.seq(&back), 7);
    assert_eq!(
        codec.refs(&back).into_iter().collect::<BTreeMap<_, _>>(),
        BTreeMap::from([
            ("refs/heads/main".to_string(), main),
            ("refs/heads/preview".to_string(), preview),
        ])
    );
}

#[test]
fn the_generic_format_roundtrips_extended_state() {
    let codec = s3_wal_git::RefsCodec;
    let state = ManifestState {
        seq: 2,
        refs: BTreeMap::from([(
            "refs/heads/main".to_string(),
            ManifestRef::bundle("c".repeat(40), "k"),
        )]),
        head: Some("refs/heads/main".into()),
        ..ManifestState::default()
    };
    let manifest: RefsManifest = codec.from_state(state.clone()).unwrap();
    let back = codec.decode(&codec.encode(&manifest).unwrap()).unwrap();
    assert_eq!(back.head.as_deref(), Some("refs/heads/main"));
    assert_eq!(back.seq, 2);
}
