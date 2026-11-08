//! `walgit` — operator CLI for an ryuz_git repository.
//!
//! ```text
//! walgit --config wal.toml init demo
//! walgit --config wal.toml import demo /srv/git/demo.git --force
//! walgit --config wal.toml export demo demo.bundle
//! ```
//!
//! Exit codes: `0` success, `1` runtime failure, `2` configuration/usage
//! failure, `3` verification ran and found the repository unhealthy.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use clap::{Args, CommandFactory, Parser, Subcommand, ValueEnum};
use serde::{Deserialize, Serialize};
use tracing_subscriber::EnvFilter;

use ryuz_git::config::{Layout, ObjectFormat, StorageMode, WalConfig};
use ryuz_git::error::WalError;
use ryuz_git::export::{self, ExportOptions};
use ryuz_git::import::{self, ImportOptions};
use ryuz_git::manifest::RefsCodec;
use ryuz_git::policy::Policy;
#[cfg(feature = "s3")]
use ryuz_git::store::s3::{S3Config, S3Store};
use ryuz_git::store::{DynStore, FsStore, MemoryStore};
use ryuz_git::wal::maintenance::{self as maintenance, CompactOptions, FsckReport, GcReport};
use ryuz_git::wal::Wal;

#[derive(Debug, Parser)]
#[command(
    name = "walgit",
    version,
    about = "Operate an ryuz_git repository",
    propagate_version = true
)]
struct Cli {
    /// TOML configuration with `[store]` and `[wal]` sections.
    #[arg(long, global = true, value_name = "PATH")]
    config: Option<PathBuf>,
    /// Override the configured store backend.
    #[arg(long, global = true, value_enum)]
    store: Option<StoreKind>,
    /// Root directory for the fs store (or the store's own path).
    #[arg(long, global = true, value_name = "PATH")]
    store_path: Option<PathBuf>,
    /// Override `[wal] repos_dir`.
    #[arg(long, global = true, value_name = "PATH")]
    repos_dir: Option<PathBuf>,
    /// Emit structured JSON output.
    #[arg(long, global = true)]
    json: bool,
    /// Increase log verbosity (`-v`, `-vv`).
    #[arg(long, global = true, action = clap::ArgAction::Count)]
    verbose: u8,
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
enum StoreKind {
    Memory,
    Fs,
    S3,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Create an empty repository.
    Init { slug: String },
    /// List the refs in the manifest.
    Ls { slug: String },
    /// Resolve one ref.
    Show {
        slug: String,
        #[arg(default_value = "HEAD")]
        rev: String,
    },
    /// Verify objects and repository connectivity.
    Verify { slug: String },
    /// Full connectivity report.
    Fsck { slug: String },
    /// Compact live packs.
    Compact {
        slug: String,
        /// Compact even when the live set is already at the target tier.
        #[arg(long)]
        force: bool,
    },
    /// Collect unreachable pack bytes past the retention grace.
    Gc { slug: String },
    /// Import a working repository, bare repository or bundle.
    Import(ImportArgs),
    /// Export a repository as a bundle or a refs JSON document.
    Export(ExportArgs),
    /// Read or replace the push policy.
    Policy {
        #[command(subcommand)]
        command: PolicyCommand,
    },
    /// Follow the durable WAL log.
    Events {
        #[command(subcommand)]
        command: EventsCommand,
    },
    /// Inspect the command line definition (debug builds).
    #[command(hide = true, name = "__schema")]
    Schema,
}

#[derive(Debug, Args)]
struct ImportArgs {
    slug: String,
    /// Source repository path (working tree or bare).
    #[arg(required_unless_present = "bundle", conflicts_with = "bundle")]
    path: Option<PathBuf>,
    /// Import a git bundle file instead of a repository.
    #[arg(long, value_name = "FILE")]
    bundle: Option<PathBuf>,
    /// Overwrite a moved or diverged target.
    #[arg(long)]
    force: bool,
    /// Hard cap for one uploaded object.
    #[arg(long)]
    max_bytes: Option<u64>,
    /// Skip the pre-upload connectivity walk.
    #[arg(long)]
    no_verify: bool,
    /// Recorded in the import marker.
    #[arg(long)]
    message: Option<String>,
}

#[derive(Debug, Args)]
struct ExportArgs {
    slug: String,
    /// Output bundle path (or JSON path with `--refs`).
    output: Option<PathBuf>,
    /// Export the refs JSON document instead of a bundle.
    #[arg(long)]
    refs: bool,
    /// Skip re-hashing stored packs and bundles.
    #[arg(long)]
    no_verify: bool,
}

#[derive(Debug, Subcommand)]
enum PolicyCommand {
    Get {
        slug: String,
    },
    Set {
        slug: String,
        /// JSON policy document.
        file: PathBuf,
    },
}

#[derive(Debug, Subcommand)]
enum EventsCommand {
    Tail {
        slug: String,
        /// First sequence number to show.
        #[arg(long, default_value_t = 0)]
        from: u64,
        /// Keep polling for new entries.
        #[arg(long)]
        follow: bool,
        /// Stop after this many entries.
        #[arg(long)]
        limit: Option<usize>,
    },
}

#[derive(Debug, Default, Deserialize)]
struct FileConfig {
    #[serde(default)]
    store: StoreFile,
    #[serde(default)]
    wal: WalFile,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
struct StoreFile {
    #[serde(alias = "backend")]
    kind: Option<String>,
    path: Option<PathBuf>,
    endpoint: Option<String>,
    bucket: Option<String>,
    region: Option<String>,
    access_key: Option<String>,
    secret_key: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
struct WalFile {
    repos_dir: Option<PathBuf>,
    prefix: Option<String>,
    storage: Option<String>,
    object_format: Option<String>,
    default_branch: Option<String>,
}

#[derive(Debug, thiserror::Error)]
enum CliError {
    #[error("{0}")]
    Config(String),
    #[error("{0}")]
    Usage(String),
    #[error("repository {0} not found")]
    NotFound(String),
    #[error("repository {slug} is unhealthy: {detail}")]
    Unhealthy { slug: String, detail: String },
    #[error(transparent)]
    Import(#[from] import::ImportError),
    #[error(transparent)]
    Export(#[from] export::ExportError),
    #[error(transparent)]
    Wal(#[from] WalError),
    #[error(transparent)]
    Store(#[from] ryuz_git::error::StoreError),
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    Json(#[from] serde_json::Error),
    #[error(transparent)]
    Toml(#[from] toml::de::Error),
}

impl CliError {
    fn exit_code(&self) -> u8 {
        match self {
            Self::Config(_) | Self::Usage(_) | Self::Toml(_) => 2,
            Self::Unhealthy { .. } => 3,
            _ => 1,
        }
    }
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> std::process::ExitCode {
    let cli = Cli::parse();
    init_tracing(&cli);
    let code = match run(cli).await {
        Ok(()) => 0,
        Err(error) => {
            tracing::error!(error = %error, "command failed");
            eprintln!("walgit: {error}");
            error.exit_code()
        }
    };
    std::process::ExitCode::from(code)
}

fn init_tracing(cli: &Cli) {
    let level = match cli.verbose {
        0 => "info",
        1 => "debug",
        _ => "trace",
    };
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new(format!("walgit={level},ryuz_git={level}")));
    let builder = tracing_subscriber::fmt().with_env_filter(filter);
    if cli.json {
        let _ = builder.json().try_init();
    } else {
        let _ = builder.try_init();
    }
}

async fn run(cli: Cli) -> Result<(), CliError> {
    if matches!(cli.command, Command::Schema) {
        Cli::command().debug_assert();
        return Ok(());
    }
    let file = load_config(cli.config.as_deref())?;
    let wal = build_wal(&cli, &file).await?;
    let json = cli.json;
    match cli.command {
        Command::Init { slug } => {
            wal.init_repo(&slug).await?;
            if json {
                emit_value(
                    json,
                    &serde_json::json!({"slug": slug, "initialized": true}),
                );
            } else {
                println!("initialized {slug}");
            }
            Ok(())
        }
        Command::Ls { slug } => {
            let refs = export::export_refs(&wal, &slug).await?;
            if json {
                emit_json(&refs)?;
            } else {
                for (refname, sha) in &refs.refs {
                    println!("{sha}\t{refname}");
                }
            }
            Ok(())
        }
        Command::Show { slug, rev } => {
            let sha = wal
                .head_of(&slug, &rev)
                .await?
                .ok_or_else(|| CliError::NotFound(format!("{slug} {rev}")))?;
            if json {
                emit_value(
                    json,
                    &serde_json::json!({"slug": slug, "rev": rev, "sha": sha}),
                );
            } else {
                println!("{sha}");
            }
            Ok(())
        }
        Command::Verify { slug } => fsck(json, &wal, &slug).await,
        Command::Fsck { slug } => fsck(json, &wal, &slug).await,
        Command::Compact { slug, force } => {
            let pack = maintenance::compact(
                &wal,
                &slug,
                CompactOptions {
                    target_tier: 1,
                    retain: 0,
                    force,
                },
            )
            .await?;
            match (&pack, json) {
                (Some(pack), true) => emit_json(pack)?,
                (None, true) => println!("null"),
                (Some(pack), false) => {
                    println!("compacted to {} ({} bytes)", pack.checksum, pack.pack_size)
                }
                (None, false) => println!("nothing to compact"),
            }
            Ok(())
        }
        Command::Gc { slug } => {
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
            let report: GcReport = maintenance::gc(&wal, &slug, now).await?;
            if json {
                emit_value(
                    json,
                    &serde_json::json!({
                        "scanned": report.scanned,
                        "deleted": report.deleted,
                        "young": report.young,
                        "live": report.live,
                    }),
                );
            } else {
                println!(
                    "scanned {} objects, deleted {}, kept {} live, {} young",
                    report.scanned,
                    report.deleted_count(),
                    report.live,
                    report.young
                );
            }
            Ok(())
        }
        Command::Import(args) => {
            let opts = ImportOptions {
                mode: None,
                force: args.force,
                verify: !args.no_verify,
                max_bytes: args.max_bytes,
                message: args.message.clone(),
            };
            let report = match (args.path, args.bundle) {
                (Some(path), None) => import::import_repo(&wal, &args.slug, &path, &opts).await?,
                (None, Some(bundle)) => {
                    let bytes = tokio::fs::read(&bundle).await?;
                    import::import_bundle_with_options(&wal, &args.slug, &bytes, &opts).await?
                }
                _ => {
                    return Err(CliError::Usage(
                        "import needs a repository path or --bundle FILE".into(),
                    ))
                }
            };
            if json {
                emit_json(&report)?;
            } else if report.no_op {
                println!("{} is already up to date", report.slug);
            } else {
                println!(
                    "imported {} refs into {} at seq {} ({} objects, {} bytes)",
                    report.refs.len(),
                    report.slug,
                    report.seq,
                    report.uploaded.len(),
                    report.bytes_uploaded
                );
            }
            Ok(())
        }
        Command::Export(args) => {
            let opts = ExportOptions {
                verify_checksums: !args.no_verify,
            };
            if args.refs {
                let refs = export::export_refs(&wal, &args.slug).await?;
                let bytes = serde_json::to_vec_pretty(&refs)?;
                if let Some(path) = args.output {
                    tokio::fs::write(&path, bytes).await?;
                } else {
                    println!("{}", String::from_utf8_lossy(&bytes));
                }
                return Ok(());
            }
            let output = args.output.unwrap_or_else(|| {
                PathBuf::from(format!("{}.bundle", args.slug.replace('/', "-")))
            });
            let report = export::export_to_path_with(&wal, &args.slug, &output, &opts).await?;
            if json {
                emit_json(&report)?;
            } else {
                println!(
                    "exported {} refs to {} ({} bytes, sha256 {})",
                    report.refs.len(),
                    output.display(),
                    report.bytes,
                    report.sha256
                );
            }
            Ok(())
        }
        Command::Policy { command } => match command {
            PolicyCommand::Get { slug } => {
                let policy: Policy = wal.read_policy(&slug).await?;
                let bytes = policy
                    .to_json()
                    .map_err(|error| CliError::Config(error.to_string()))?;
                print!("{}", String::from_utf8_lossy(&bytes));
                Ok(())
            }
            PolicyCommand::Set { slug, file } => {
                let bytes = tokio::fs::read(&file).await?;
                let policy = Policy::parse(&bytes).map_err(|error| {
                    CliError::Usage(format!(
                        "{} is not a valid policy JSON: {error}",
                        file.display()
                    ))
                })?;
                wal.write_policy(&slug, &policy).await?;
                if json {
                    emit_value(json, &serde_json::json!({"slug": slug, "updated": true}));
                } else {
                    println!("policy for {slug} updated");
                }
                Ok(())
            }
        },
        Command::Events { command } => match command {
            EventsCommand::Tail {
                slug,
                from,
                follow,
                limit,
            } => tail_events(&wal, &slug, from, follow, limit).await,
        },
        Command::Schema => Ok(()),
    }
}

async fn fsck(json: bool, wal: &Wal<RefsCodec>, slug: &str) -> Result<(), CliError> {
    let report: FsckReport = maintenance::fsck(wal, slug).await?;
    if json {
        emit_json(&report)?;
    } else if report.is_healthy() {
        println!(
            "{} is healthy at seq {} ({} missing, {} problems, {:.3}s)",
            slug,
            report.seq,
            report.missing.len(),
            report.problems.len(),
            report.elapsed_secs
        );
    } else {
        println!(
            "{} at seq {}: {} missing objects, {} problems",
            slug,
            report.seq,
            report.missing_total.max(report.missing.len() as u64),
            report.problems.len()
        );
        for oid in &report.missing {
            println!("missing {oid}");
        }
        for problem in &report.problems {
            println!("problem {problem}");
        }
    }
    if !report.is_healthy() {
        return Err(CliError::Unhealthy {
            slug: slug.to_string(),
            detail: format!(
                "{} missing objects, {} problems",
                report.missing_total.max(report.missing.len() as u64),
                report.problems.len()
            ),
        });
    }
    Ok(())
}

async fn tail_events(
    wal: &Wal<RefsCodec>,
    slug: &str,
    from: u64,
    follow: bool,
    limit: Option<usize>,
) -> Result<(), CliError> {
    let mut next = from;
    let mut printed = 0usize;
    loop {
        let entries = wal.read_log(slug, next, Some(u64::MAX)).await?;
        if entries.is_empty() {
            if !follow {
                return Ok(());
            }
            tokio::time::sleep(std::time::Duration::from_secs(1)).await;
            continue;
        }
        for entry in &entries {
            println!("{}", serde_json::to_string(entry)?);
            printed += 1;
            if limit.is_some_and(|limit| printed >= limit) {
                return Ok(());
            }
        }
        next = entries
            .last()
            .map(|entry| entry.seq.saturating_add(1))
            .unwrap_or(next);
        if !follow {
            return Ok(());
        }
    }
}

fn load_config(path: Option<&Path>) -> Result<FileConfig, CliError> {
    let Some(path) = path else {
        return Ok(FileConfig::default());
    };
    let text = std::fs::read_to_string(path)
        .map_err(|error| CliError::Config(format!("cannot read {}: {error}", path.display())))?;
    let config: FileConfig = toml::from_str(&text)?;
    Ok(config)
}

async fn build_wal(cli: &Cli, file: &FileConfig) -> Result<Wal<RefsCodec>, CliError> {
    let repos_dir = cli
        .repos_dir
        .clone()
        .or_else(|| file.wal.repos_dir.clone())
        .unwrap_or_else(|| PathBuf::from("wal-repos"));

    let kind = match cli.store {
        Some(kind) => kind,
        None => match file.store.kind.as_deref() {
            Some(value) => parse_store_kind(value)?,
            None => {
                if file.store.path.is_some() {
                    StoreKind::Fs
                } else {
                    StoreKind::Memory
                }
            }
        },
    };

    let store: DynStore = match kind {
        StoreKind::Memory => Arc::new(MemoryStore::new()),
        StoreKind::Fs => {
            let root = cli
                .store_path
                .clone()
                .or_else(|| file.store.path.clone())
                .ok_or_else(|| {
                    CliError::Config("fs store needs --store-path or [store].path".to_string())
                })?;
            Arc::new(FsStore::open(root).await?)
        }
        StoreKind::S3 => {
            #[cfg(feature = "s3")]
            {
                let bucket =
                    file.store.bucket.clone().ok_or_else(|| {
                        CliError::Config("s3 store needs [store].bucket".to_string())
                    })?;
                let mut cfg = S3Config::new(bucket);
                if let Some(region) = &file.store.region {
                    cfg = cfg.with_region(region.clone());
                }
                if let Some(endpoint) = &file.store.endpoint {
                    cfg = cfg.with_endpoint(endpoint.clone()).with_path_style(true);
                }
                match (&file.store.access_key, &file.store.secret_key) {
                    (Some(access), Some(secret)) => {
                        cfg = cfg.with_credentials(access.clone(), secret.clone(), None);
                    }
                    (None, None) => {}
                    _ => {
                        return Err(CliError::Config(
                            "s3 needs both [store].access_key and [store].secret_key".to_string(),
                        ))
                    }
                }
                Arc::new(S3Store::new(cfg).await?)
            }
            #[cfg(not(feature = "s3"))]
            {
                let described = format!(
                    "endpoint={:?} bucket={:?} region={:?} keys={}",
                    file.store.endpoint,
                    file.store.bucket,
                    file.store.region,
                    if file.store.access_key.is_some() || file.store.secret_key.is_some() {
                        "configured"
                    } else {
                        "absent"
                    }
                );
                return Err(CliError::Config(format!(
                    "s3 backend is not available in this binary ({described}); rebuild with `--features cli,s3`"
                )));
            }
        }
    };

    let prefix = file.wal.prefix.clone().unwrap_or_else(|| "git".to_string());
    let mut config = WalConfig::new(repos_dir, Layout::new(prefix));
    if let Some(storage) = &file.wal.storage {
        config.storage = StorageMode::parse(storage)
            .ok_or_else(|| CliError::Config(format!("unknown [wal] storage {storage:?}")))?;
    }
    if let Some(format) = &file.wal.object_format {
        config.object_format = ObjectFormat::parse(format)
            .ok_or_else(|| CliError::Config(format!("unknown [wal] object_format {format:?}")))?;
    }
    if let Some(branch) = &file.wal.default_branch {
        config.default_branch = branch.clone();
    }
    config
        .validate()
        .map_err(|error| CliError::Config(error.to_string()))?;
    tracing::debug!(
        backend = store.backend(),
        repos_dir = %config.repos_dir.display(),
        storage = ?config.storage,
        "wal configured"
    );
    Ok(Wal::new(store, Arc::new(config), Arc::new(RefsCodec)))
}

fn parse_store_kind(value: &str) -> Result<StoreKind, CliError> {
    match value {
        "memory" => Ok(StoreKind::Memory),
        "fs" | "file" => Ok(StoreKind::Fs),
        "s3" => Ok(StoreKind::S3),
        other => Err(CliError::Config(format!(
            "unknown [store] backend {other:?}"
        ))),
    }
}

fn emit_value<T: Serialize>(json: bool, value: &T) {
    if json {
        if let Ok(text) = serde_json::to_string_pretty(value) {
            println!("{text}");
        }
    }
}

fn emit_json<T: Serialize>(value: &T) -> Result<(), CliError> {
    println!("{}", serde_json::to_string_pretty(value)?);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::error::ErrorKind;

    #[test]
    fn command_definition_is_valid() {
        Cli::command().debug_assert();
    }

    #[test]
    fn help_is_available() {
        let error = Cli::try_parse_from(["walgit", "--help"]).unwrap_err();
        assert_eq!(error.kind(), ErrorKind::DisplayHelp);
    }

    #[test]
    fn import_parses_source_and_bundle() {
        let cli = Cli::try_parse_from(["walgit", "import", "demo", "/srv/demo.git"]).unwrap();
        match cli.command {
            Command::Import(args) => {
                assert_eq!(args.slug, "demo");
                assert_eq!(args.path.as_deref(), Some(Path::new("/srv/demo.git")));
                assert!(args.bundle.is_none());
            }
            other => panic!("unexpected command: {other:?}"),
        }

        let cli =
            Cli::try_parse_from(["walgit", "import", "demo", "--bundle", "in.bundle"]).unwrap();
        match cli.command {
            Command::Import(args) => {
                assert!(args.path.is_none());
                assert_eq!(args.bundle.as_deref(), Some(Path::new("in.bundle")));
            }
            other => panic!("unexpected command: {other:?}"),
        }
    }

    #[test]
    fn toml_config_parses_store_and_wal() {
        let config: FileConfig = toml::from_str(
            r#"
[store]
kind = "fs"
path = "/var/lib/wal/store"
endpoint = "http://localhost:9000"
bucket = "git"
access_key = "AK"
secret_key = "SK"

[wal]
repos_dir = "/var/lib/wal/repos"
prefix = "repos"
storage = "pack"
object_format = "sha256"
"#,
        )
        .unwrap();
        assert_eq!(config.store.kind.as_deref(), Some("fs"));
        assert_eq!(config.store.bucket.as_deref(), Some("git"));
        assert_eq!(config.wal.prefix.as_deref(), Some("repos"));
        assert_eq!(config.wal.storage.as_deref(), Some("pack"));
        assert_eq!(config.wal.object_format.as_deref(), Some("sha256"));
    }

    #[test]
    fn config_errors_exit_two() {
        assert_eq!(CliError::Config("bad".into()).exit_code(), 2);
        assert_eq!(CliError::Usage("bad".into()).exit_code(), 2);
        assert_eq!(
            CliError::Unhealthy {
                slug: "demo".into(),
                detail: "x".into()
            }
            .exit_code(),
            3
        );
    }
}
