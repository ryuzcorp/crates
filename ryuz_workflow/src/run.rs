//! The container runner: one container per job, steps in file order.
//!
//! The runner never touches a host shell. Every container CLI invocation is an
//! argv vector; only a step's script is handed to a shell, and that shell
//! lives inside the container.
//!
//! # Safety properties
//!
//! - **Argv only.** Untrusted config text never reaches a host shell.
//! - **Secrets stay off argv.** Container env is passed as `-e KEY` with the
//!   value set on the CLI child's environment, so `ps` and audit logs show
//!   names, never values. Step output is redacted for every configured value.
//! - **No capabilities for steps.** The container is created with
//!   `--cap-drop ALL`, `--cap-add CHOWN`, `--security-opt no-new-privileges`,
//!   `--init`, a pids limit and memory/CPU caps; steps exec as the configured
//!   uid/gid. `CHOWN` only serves the ownership prep that runs before any
//!   step.
//! - **No leaks.** A [`JobContainer`] removal is armed until the container is
//!   gone: an explicit `rm -f` disarms it, and dropping the run (cancellation,
//!   workflow timeout) spawns `rm -f` instead of leaving the container behind.
//!   Containers are labelled with the process id and swept at start, so a
//!   killed process cannot leave them forever.
//! - **Bounded.** Per-step, per-job and whole-run timeouts kill the container;
//!   an exit 137 is reported as out-of-memory.

use std::collections::{BTreeMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, LazyLock, Mutex};
use std::time::{Duration, Instant};

use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::process::Command;
use tokio::sync::Semaphore;

use crate::error::Error;
use crate::event::{Event, Stream};
use crate::fs_util;
use crate::outcome::{Artifact, Failure, JobOutcome, JobStatus, Outcome, StepOutcome};
use crate::workflow::{check_env_key, Job, Shell, Step, StepKind, Workflow};

/// Mount point of [`Settings::cache_volume`] inside every job container.
///
/// Steps exec as the build uid, so `HOME` points here and the persistent
/// volume (when configured) makes package-manager caches survive across runs.
pub const CACHE_DIR: &str = "/ci-home";

/// Step timeout when the step sets no `timeout-minutes`.
pub const DEFAULT_STEP_TIMEOUT: Duration = Duration::from_secs(10 * 60);

/// Cap for one logged output line; longer lines are truncated with a marker.
const MAX_LOG_LINE_BYTES: usize = 256 * 1024;

/// Cap for logged output per step; past it lines are drained, not logged.
const MAX_STEP_LOG_BYTES: u64 = 8 * 1024 * 1024;

/// Timeout for the `kill` fired on a step or job timeout.
const KILL_TIMEOUT: Duration = Duration::from_secs(30);

/// Timeout for a control-plane container CLI call (`create`, `cp`, …).
const CLI_TIMEOUT: Duration = Duration::from_secs(120);

/// Longest [`Settings::container_prefix`].
const MAX_PREFIX_BYTES: usize = 32;

/// Longest [`Settings::artifact_dir`].
const MAX_ARTIFACT_DIR_BYTES: usize = 256;

/// Label every container carries so a later run can sweep orphans.
const PID_LABEL: &str = "ryuz_workflow.pid";

/// Shortest secret value that becomes a log mask. Shorter values (a bare `1`,
/// `on`, `true`) would shred every log line without hiding anything.
const MIN_SECRET_BYTES: usize = 4;

/// How the container CLI pulls job images.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PullPolicy {
    Always,
    Missing,
    Never,
}

impl PullPolicy {
    fn as_arg(self) -> &'static str {
        match self {
            PullPolicy::Always => "always",
            PullPolicy::Missing => "missing",
            PullPolicy::Never => "never",
        }
    }
}

/// Container settings. The caller builds this from its own config/env
/// (container CLI, default image, allowlist, budgets, …).
#[derive(Debug, Clone)]
pub struct Settings {
    /// Container CLI (`docker`, `podman`, …). A seam: tests point it at a
    /// fake script.
    pub docker_bin: String,
    /// Image when the job sets none.
    pub default_image: String,
    /// Exact allowlist; a job image outside it fails before any container starts.
    pub allowed_images: Vec<String>,
    /// `create --network`.
    pub network: String,
    /// `create --memory/--memory-swap` (MiB).
    pub memory_mb: u64,
    /// `create --cpus`.
    pub cpus: f64,
    /// Owner of `/work` inside the container; steps exec as this user.
    pub uid: u32,
    /// Group of `/work` inside the container.
    pub gid: u32,
    /// Named volume mounted at [`CACHE_DIR`]. `None` mounts an ephemeral tmpfs
    /// there instead, so the container starts clean (a cache that must survive
    /// runs needs a volume).
    pub cache_volume: Option<String>,
    /// Base container env, e.g. tokens or config the build needs. Values never
    /// reach argv; they are also masked in step output.
    pub env: Vec<(String, String)>,
    /// Prefix of generated container names: `<prefix>-<pid>-<n>`.
    pub container_prefix: String,
    /// Directory copied back out of the container after a successful job,
    /// relative to the worktree (e.g. `dist`). `None` disables the copy;
    /// `uses: upload-artifact` still works.
    pub artifact_dir: Option<String>,
    /// `create --platform` (e.g. `linux/arm64`).
    pub platform: Option<String>,
    pub pull: PullPolicy,
    /// Jobs allowed to run at once; `1` keeps file order strictly sequential.
    pub max_parallel: u32,
    /// Whole-run wall-clock cap. On expiry the running jobs are cancelled (and
    /// their containers removed) and the outcome reports them as cancelled.
    pub run_timeout: Option<Duration>,
}

type Sink = Arc<dyn Fn(Event) + Send + Sync>;

fn step_timeout(step: &Step) -> Duration {
    step.timeout_minutes
        .map(|m| Duration::from_secs(m * 60))
        .unwrap_or(DEFAULT_STEP_TIMEOUT)
}

fn format_cpus(cpus: f64) -> String {
    if cpus.fract() == 0.0 {
        format!("{}", cpus as u64)
    } else {
        format!("{cpus}")
    }
}

fn validate_settings(settings: &Settings) -> Result<(), Error> {
    if settings.docker_bin.trim().is_empty() {
        return Err(Error::Config("docker binary path is empty".to_string()));
    }
    if settings.docker_bin.contains('\0') {
        return Err(Error::Config("docker binary path contains NUL".to_string()));
    }
    if settings.default_image.trim().is_empty() {
        return Err(Error::Config("default image is empty".to_string()));
    }
    if settings.network.trim().is_empty() {
        return Err(Error::Config("network is empty".to_string()));
    }
    if settings.memory_mb == 0 {
        return Err(Error::Config("memory_mb must be nonzero".to_string()));
    }
    if !settings.cpus.is_finite() || settings.cpus <= 0.0 {
        return Err(Error::Config("cpus must be a positive number".to_string()));
    }
    if let Some(volume) = &settings.cache_volume {
        if volume.trim().is_empty() {
            return Err(Error::Config("cache_volume is empty".to_string()));
        }
        if volume.contains('\0') {
            return Err(Error::Config("cache_volume contains NUL".to_string()));
        }
    }
    validate_prefix(&settings.container_prefix)?;
    if let Some(dir) = &settings.artifact_dir {
        validate_artifact_dir(dir)?;
    }
    if let Some(platform) = &settings.platform {
        if platform.trim().is_empty() {
            return Err(Error::Config("platform is empty".to_string()));
        }
        if platform.contains('\0') {
            return Err(Error::Config("platform contains NUL".to_string()));
        }
    }
    if settings.max_parallel == 0 {
        return Err(Error::Config("max_parallel must be nonzero".to_string()));
    }
    if settings.run_timeout.is_some_and(|d| d.is_zero()) {
        return Err(Error::Config("run_timeout must be nonzero".to_string()));
    }
    for (key, value) in &settings.env {
        check_env_key("settings.env", key)?;
        if value.contains('\0') {
            return Err(Error::Config(format!(
                "settings.env value for `{key}` contains NUL"
            )));
        }
        if value.len() > crate::workflow::MAX_ENV_VALUE_BYTES {
            return Err(Error::Config(format!(
                "settings.env value for `{key}` is longer than the {}-byte cap",
                crate::workflow::MAX_ENV_VALUE_BYTES
            )));
        }
    }
    Ok(())
}

/// Docker container names: `[A-Za-z0-9][A-Za-z0-9_.-]*`.
fn validate_prefix(prefix: &str) -> Result<(), Error> {
    let err = |why: &str| Error::Config(format!("container_prefix {why}"));
    if prefix.is_empty() {
        return Err(err("is empty"));
    }
    if prefix.len() > MAX_PREFIX_BYTES {
        return Err(err("is longer than the 32-byte cap"));
    }
    let mut chars = prefix.chars();
    let first_ok = chars.next().is_some_and(|c| c.is_ascii_alphanumeric());
    let rest_ok = chars.all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | '-'));
    if !first_ok || !rest_ok {
        return Err(err("must match [A-Za-z0-9][A-Za-z0-9_.-]*"));
    }
    Ok(())
}

/// The artifact directory names a path under `/work`: relative, no `..`.
fn validate_artifact_dir(dir: &str) -> Result<(), Error> {
    let err = |why: &str| Error::Config(format!("artifact_dir {why}"));
    if dir.trim().is_empty() {
        return Err(err("is empty"));
    }
    if dir.len() > MAX_ARTIFACT_DIR_BYTES {
        return Err(err("is longer than the 256-byte cap"));
    }
    if dir.contains('\0') {
        return Err(err("contains NUL"));
    }
    if dir.starts_with('/') {
        return Err(err("must be relative to /work"));
    }
    if dir.split('/').any(|part| part == "..") {
        return Err(err("escapes /work"));
    }
    Ok(())
}

/// Run the workflow, formatting [`Event`]s into plain log lines.
///
/// See [`run_with_events`] for the structured form and the error contract.
pub async fn run<F>(
    settings: &Settings,
    work_dir: &Path,
    workflow: &Workflow,
    log: F,
) -> Result<Outcome, Error>
where
    F: Fn(String) + Send + Sync + 'static,
{
    run_with_events(settings, work_dir, workflow, move |event| {
        if let Some(line) = crate::event::format_event(&event) {
            log(line);
        }
    })
    .await
}

/// Run the workflow: one container per job, matrix members expanded, up to
/// [`Settings::max_parallel`] jobs at once, failing fast within a job's matrix.
///
/// `Ok` means the workflow was attempted; per-job success is in
/// [`Outcome::success`]. `Err` is reserved for a bad config/settings, a bad
/// work dir, a disallowed image and a scheduler failure.
pub async fn run_with_events<F>(
    settings: &Settings,
    work_dir: &Path,
    workflow: &Workflow,
    events: F,
) -> Result<Outcome, Error>
where
    F: Fn(Event) + Send + Sync + 'static,
{
    validate_settings(settings)?;
    let work = work_dir
        .to_str()
        .ok_or_else(|| Error::BadWorkDir(work_dir.to_string_lossy().into_owned()))?
        .to_string();
    if !tokio::fs::metadata(work_dir)
        .await
        .is_ok_and(|m| m.is_dir())
    {
        return Err(Error::BadWorkDir(work.clone()));
    }
    // Fail fast on images before any container starts.
    for job in &workflow.jobs {
        let image = job.image.as_deref().unwrap_or(&settings.default_image);
        if !settings.allowed_images.iter().any(|a| a == image) {
            return Err(Error::ImageNotAllowed(image.to_string()));
        }
    }

    let sink: Sink = Arc::new(events);
    sweep_orphans(settings).await;
    let started = Instant::now();
    sink(Event::WorkflowStarted {
        jobs: workflow.jobs.len(),
    });

    let outcomes = schedule(settings, &work, workflow, &sink).await?;
    let jobs: Vec<JobOutcome> = outcomes
        .into_iter()
        .enumerate()
        .map(|(index, outcome)| {
            outcome.unwrap_or_else(|| cancelled_outcome(settings, &workflow.jobs[index]))
        })
        .collect();
    let mut artifacts = Vec::new();
    for job in &jobs {
        artifacts.extend(job.artifacts.iter().cloned());
    }
    // Only an install this run actually performed counts: a filesystem check
    // would follow a symlink the checkout planted at the artifact path.
    let artifact_path = settings.artifact_dir.as_ref().and_then(|dir| {
        let target = work_dir.join(dir);
        jobs.iter()
            .flat_map(|job| &job.artifacts)
            .any(|artifact| artifact.path == target)
            .then_some(target)
    });
    let success = jobs.iter().all(JobOutcome::success);
    sink(Event::WorkflowFinished {
        success,
        duration: started.elapsed(),
    });
    Ok(Outcome {
        jobs,
        artifacts,
        artifact_path,
    })
}

fn cancelled_outcome(settings: &Settings, job: &Job) -> JobOutcome {
    JobOutcome {
        name: job.name.clone(),
        base_name: job.base_name.clone(),
        matrix: job.matrix.clone(),
        image: job
            .image
            .clone()
            .unwrap_or_else(|| settings.default_image.clone()),
        status: JobStatus::Cancelled,
        steps: Vec::new(),
        artifacts: Vec::new(),
        duration: Duration::ZERO,
    }
}

/// Run every job under the global and per-matrix concurrency caps.
///
/// Results are written into a shared slot vector as they finish, so a
/// whole-run timeout can report the jobs that did not finish as cancelled.
async fn schedule(
    settings: &Settings,
    work: &str,
    workflow: &Workflow,
    sink: &Sink,
) -> Result<Vec<Option<JobOutcome>>, Error> {
    let slots: Arc<Mutex<Vec<Option<JobOutcome>>>> =
        Arc::new(Mutex::new(vec![None; workflow.jobs.len()]));
    let global = Arc::new(Semaphore::new(settings.max_parallel.max(1) as usize));
    let mut set = tokio::task::JoinSet::new();

    for group in groups(workflow) {
        let first = &workflow.jobs[group[0]];
        let cap = first
            .max_parallel
            .unwrap_or(u32::MAX)
            .min(settings.max_parallel.max(1));
        let group_sem = Arc::new(Semaphore::new(cap.max(1) as usize));
        let failed = Arc::new(AtomicBool::new(false));
        let fail_fast = first.fail_fast;
        for index in group {
            let job = workflow.jobs[index].clone();
            let base_env = Arc::new(workflow.env.clone());
            let settings = settings.clone();
            let work = work.to_string();
            let sink = sink.clone();
            let slots = slots.clone();
            let group_sem = group_sem.clone();
            let global = global.clone();
            let failed = failed.clone();
            set.spawn(async move {
                let skipped = || {
                    let mut outcome = cancelled_outcome(&settings, &job);
                    outcome.status = JobStatus::Skipped;
                    outcome
                };
                let _group = match group_sem.acquire_owned().await {
                    Ok(permit) => permit,
                    Err(_) => return,
                };
                if fail_fast && failed.load(Ordering::Relaxed) {
                    let outcome = skipped();
                    slots.lock().expect("slots lock")[index] = Some(outcome);
                    return;
                }
                let _global = match global.acquire_owned().await {
                    Ok(permit) => permit,
                    Err(_) => return,
                };
                if fail_fast && failed.load(Ordering::Relaxed) {
                    let outcome = skipped();
                    slots.lock().expect("slots lock")[index] = Some(outcome);
                    return;
                }
                let outcome = run_job(&settings, &work, &job, &base_env, &sink).await;
                if !outcome.success() && fail_fast {
                    failed.store(true, Ordering::Relaxed);
                }
                slots.lock().expect("slots lock")[index] = Some(outcome);
            });
        }
    }

    let drain = async {
        while let Some(joined) = set.join_next().await {
            joined.map_err(|error| Error::Container(format!("job task failed: {error}")))?;
        }
        Ok::<(), Error>(())
    };
    match settings.run_timeout.map(|d| Instant::now() + d) {
        Some(deadline) => {
            match tokio::time::timeout_at(tokio::time::Instant::from_std(deadline), drain).await {
                Ok(result) => result?,
                Err(_) => {
                    // Unfinished jobs stay unwritten in their slots and are
                    // reported as cancelled; aborting the tasks drops their
                    // container guards, which remove the containers.
                    set.abort_all();
                    while set.join_next().await.is_some() {}
                }
            }
        }
        None => drain.await?,
    }
    let slots = std::mem::take(&mut *slots.lock().expect("slots lock"));
    Ok(slots)
}

/// Consecutive jobs that share a declared name (their matrix members).
fn groups(workflow: &Workflow) -> Vec<Vec<usize>> {
    let mut groups: Vec<Vec<usize>> = Vec::new();
    for (index, job) in workflow.jobs.iter().enumerate() {
        match groups.last_mut() {
            Some(last) if workflow.jobs[last[0]].base_name == job.base_name => last.push(index),
            _ => groups.push(vec![index]),
        }
    }
    groups
}

async fn run_job(
    settings: &Settings,
    work: &str,
    job: &Job,
    base_env: &BTreeMap<String, String>,
    sink: &Sink,
) -> JobOutcome {
    let started = Instant::now();
    let image = job
        .image
        .clone()
        .unwrap_or_else(|| settings.default_image.clone());
    sink(Event::JobStarted {
        job: job.name.clone(),
        image: image.clone(),
    });
    let mut outcome = JobOutcome {
        name: job.name.clone(),
        base_name: job.base_name.clone(),
        matrix: job.matrix.clone(),
        image: image.clone(),
        status: JobStatus::Success,
        steps: Vec::new(),
        artifacts: Vec::new(),
        duration: Duration::ZERO,
    };
    let redactor = Redactor::new(settings, base_env, job);
    let mut container = match JobContainer::start(settings, work, &image, &job.name).await {
        Ok(container) => container,
        Err(error) => {
            outcome.status = JobStatus::Failed(Failure::Container(error.to_string()));
            outcome.duration = started.elapsed();
            sink(Event::JobFinished {
                job: job.name.clone(),
                status: outcome.status.clone(),
                duration: outcome.duration,
            });
            return outcome;
        }
    };

    let mut failure = None;
    let steps = match job.timeout_minutes.map(|m| Duration::from_secs(m * 60)) {
        Some(limit) => {
            match tokio::time::timeout(
                limit,
                run_steps(settings, job, base_env, &container, sink, &redactor),
            )
            .await
            {
                Ok(result) => result,
                Err(_) => {
                    container.kill().await;
                    let line = format!("job `{}` exceeded its timeout of {limit:?}", job.name);
                    sink(Event::Note {
                        job: job.name.clone(),
                        line,
                    });
                    failure = Some(Failure::Timeout { step: None });
                    StepRun::default()
                }
            }
        }
        None => run_steps(settings, job, base_env, &container, sink, &redactor).await,
    };
    outcome.steps = steps.steps;
    outcome.artifacts = steps.artifacts;
    if failure.is_none() {
        failure = steps.failure;
    }
    if failure.is_none() {
        if let Some(dir) = &settings.artifact_dir {
            if let Some(artifact) =
                copy_out(settings, &container, work, dir, None, &job.name, sink).await
            {
                outcome.artifacts.push(artifact);
            }
        }
    }
    outcome.status = match failure {
        None => JobStatus::Success,
        Some(failure) => JobStatus::Failed(failure),
    };
    container.remove().await;
    outcome.duration = started.elapsed();
    sink(Event::JobFinished {
        job: job.name.clone(),
        status: outcome.status.clone(),
        duration: outcome.duration,
    });
    outcome
}

#[derive(Default)]
struct StepRun {
    steps: Vec<StepOutcome>,
    artifacts: Vec<Artifact>,
    failure: Option<Failure>,
}

async fn run_steps(
    settings: &Settings,
    job: &Job,
    base_env: &BTreeMap<String, String>,
    container: &JobContainer,
    sink: &Sink,
    redactor: &Redactor,
) -> StepRun {
    let mut run = StepRun::default();
    for (index, step) in job.steps.iter().enumerate() {
        let label = step
            .name
            .clone()
            .unwrap_or_else(|| format!("step #{}", index + 1));
        sink(Event::StepStarted {
            job: job.name.clone(),
            step: label.clone(),
        });
        match &step.kind {
            StepKind::Checkout => {
                sink(Event::Note {
                    job: job.name.clone(),
                    line:
                        "uses: checkout is a no-op; the worktree is already checked out, skipping"
                            .to_string(),
                });
            }
            StepKind::Cache => {
                sink(Event::Note {
                    job: job.name.clone(),
                    line: "uses: cache is a no-op; the cache volume is always mounted".to_string(),
                });
            }
            StepKind::UploadArtifact { path, name } => {
                if let Some(artifact) = copy_out(
                    settings,
                    container,
                    &container.work,
                    path,
                    name.clone(),
                    &job.name,
                    sink,
                )
                .await
                {
                    run.artifacts.push(artifact);
                }
            }
            StepKind::Run { script, shell } => {
                let shell = shell.or(job.defaults.shell).unwrap_or(Shell::Sh);
                let env = merged_env(base_env, job, step);
                let timeout = step_timeout(step);
                let started = Instant::now();
                match exec_step(
                    settings, job, container, &label, step, script, shell, &env, timeout, sink,
                    redactor,
                )
                .await
                {
                    Ok(exit_code) => {
                        let duration = started.elapsed();
                        sink(Event::StepFinished {
                            job: job.name.clone(),
                            step: label.clone(),
                            exit_code,
                            duration,
                        });
                        run.steps.push(StepOutcome {
                            name: step.name.clone(),
                            exit_code,
                            duration,
                        });
                        if exit_code != 0 {
                            let failure = if exit_code == 137 {
                                Failure::OutOfMemory { step: label }
                            } else {
                                Failure::StepFailed {
                                    step: label,
                                    exit_code,
                                }
                            };
                            sink(Event::Note {
                                job: job.name.clone(),
                                line: failure.to_string(),
                            });
                            run.failure = Some(failure);
                            return run;
                        }
                    }
                    Err(ExecError::Timeout) => {
                        container.kill().await;
                        let failure = Failure::Timeout {
                            step: Some(label.clone()),
                        };
                        sink(Event::Note {
                            job: job.name.clone(),
                            line: failure.to_string(),
                        });
                        run.failure = Some(failure);
                        return run;
                    }
                    Err(ExecError::Container(message)) => {
                        run.failure = Some(Failure::Container(message));
                        return run;
                    }
                }
            }
        }
    }
    run
}

/// Copy `/work/<path>` out of the container to `<work>/<path>`.
///
/// Best-effort by design: a missing path is a note, not a failure (GitHub's
/// `upload-artifact` with `if-no-files-found: ignore`, and our deploy root).
/// The bytes land in a staging directory first and are installed with
/// no-follow, dirfd-relative operations, so a symlink planted in the checkout
/// (or by a parallel job) cannot redirect the host write.
#[allow(clippy::too_many_arguments)]
async fn copy_out(
    settings: &Settings,
    container: &JobContainer,
    work: &str,
    path: &str,
    name: Option<String>,
    job: &str,
    sink: &Sink,
) -> Option<Artifact> {
    let work_path = Path::new(work).to_path_buf();
    let staging = match create_staging(&work_path) {
        Ok(dir) => dir,
        Err(error) => {
            sink(Event::Note {
                job: job.to_string(),
                line: format!("artifact: cannot create a staging dir ({error})"),
            });
            return None;
        }
    };
    let payload = staging.join("payload");
    let args = vec![
        "cp".to_string(),
        format!("{}:/work/{path}", container.name),
        payload.to_string_lossy().into_owned(),
    ];
    let copied = cli(&settings.docker_bin, &args, &[]).await;
    let installed = match copied {
        Ok(_) => {
            let staged = payload.clone();
            let root = work_path.clone();
            let rel = path.to_string();
            let result = tokio::task::spawn_blocking(move || {
                // One install at a time: a parallel job's artifact must not
                // race another's path check on the same worktree.
                let _serialized = install_lock().lock().expect("install lock");
                fs_util::install_artifact(&staged, &root, &rel)
            })
            .await;
            match result {
                Ok(Ok(dest)) => Some(dest),
                Ok(Err(error)) => {
                    sink(Event::Note {
                        job: job.to_string(),
                        line: format!(
                            "artifact: refusing to install {path} ({error}); nothing was overwritten"
                        ),
                    });
                    None
                }
                Err(error) => {
                    sink(Event::Note {
                        job: job.to_string(),
                        line: format!("artifact: install task for {path} failed ({error})"),
                    });
                    None
                }
            }
        }
        Err(error) => {
            sink(Event::Note {
                job: job.to_string(),
                line: format!("artifact: no {path} in container, skipping ({error})"),
            });
            None
        }
    };
    let _ = tokio::fs::remove_dir_all(&staging).await;
    let dest = installed?;
    #[cfg(unix)]
    if !fs_util::lchown_tree(&dest, settings.uid, settings.gid) {
        sink(Event::Note {
            job: job.to_string(),
            line: format!("artifact: copied {path}/ but chown failed; continuing"),
        });
    }
    sink(Event::Artifact {
        job: job.to_string(),
        name: name.clone(),
        path: dest.clone(),
    });
    Some(Artifact { name, path: dest })
}

/// Directory outside the tenant-visible worktree namespace (a fresh, random
/// name next to it, on the same filesystem so the install is one rename).
fn create_staging(work: &Path) -> std::io::Result<PathBuf> {
    static N: AtomicU64 = AtomicU64::new(0);
    for _ in 0..32 {
        let id = N.fetch_add(1, Ordering::Relaxed);
        let dir = work.join(format!(".ryuz-workflow-stage-{}-{id}", std::process::id()));
        match std::fs::create_dir(&dir) {
            Ok(()) => return Ok(dir),
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(error) => return Err(error),
        }
    }
    Err(std::io::Error::new(
        std::io::ErrorKind::AlreadyExists,
        "no free staging directory name",
    ))
}

fn install_lock() -> &'static Mutex<()> {
    static LOCK: LazyLock<Mutex<()>> = LazyLock::new(|| Mutex::new(()));
    &LOCK
}

fn merged_env(
    base_env: &BTreeMap<String, String>,
    job: &Job,
    step: &Step,
) -> Vec<(String, String)> {
    let mut env = job.matrix_env();
    env.extend(base_env.clone());
    env.extend(job.env.clone());
    env.extend(step.env.clone());
    env.into_iter().collect()
}

enum ExecError {
    Timeout,
    Container(String),
}

#[allow(clippy::too_many_arguments)]
async fn exec_step(
    settings: &Settings,
    job: &Job,
    container: &JobContainer,
    label: &str,
    step: &Step,
    script: &str,
    shell: Shell,
    env: &[(String, String)],
    timeout: Duration,
    sink: &Sink,
    redactor: &Redactor,
) -> Result<i32, ExecError> {
    let ownership = format!("{}:{}", settings.uid, settings.gid);
    let workdir = match step
        .working_directory
        .as_deref()
        .or(job.defaults.working_directory.as_deref())
    {
        Some(wd) => format!("/work/{wd}"),
        None => "/work".to_string(),
    };
    let mut args: Vec<String> = vec![
        "exec".to_string(),
        "--user".to_string(),
        ownership,
        "-w".to_string(),
        workdir,
    ];
    for (key, _) in env {
        args.push("-e".to_string());
        args.push(key.clone());
    }
    args.push(container.name.clone());
    args.extend(shell.argv(script));

    let argv = args.join(" ");
    let mut child = spawn_piped(&settings.docker_bin, &args, env)
        .await
        .map_err(|error| ExecError::Container(format!("spawn {argv}: {error}")))?;
    let outcome = tokio::time::timeout(timeout, async {
        let stdout = child.stdout.take().expect("piped above");
        let stderr = child.stderr.take().expect("piped above");
        stream_to_log(stdout, stderr, redactor, sink, &job.name, label).await?;
        let status = child
            .wait()
            .await
            .map_err(|error| ExecError::Container(format!("wait {argv}: {error}")))?;
        Ok::<i32, ExecError>(status.code().unwrap_or(-1))
    })
    .await;
    match outcome {
        Err(_) => {
            let _ = tokio::time::timeout(
                KILL_TIMEOUT,
                cli(
                    &settings.docker_bin,
                    &["kill".to_string(), container.name.clone()],
                    &[],
                ),
            )
            .await;
            let _ = child.kill().await;
            let _ = child.wait().await;
            Err(ExecError::Timeout)
        }
        Ok(result) => result,
    }
}

/// Drain both pipes concurrently into the sink. Past the per-step log cap,
/// output is still drained (so the child never blocks) but no longer sent.
async fn stream_to_log(
    stdout: impl tokio::io::AsyncRead + Unpin,
    stderr: impl tokio::io::AsyncRead + Unpin,
    redactor: &Redactor,
    sink: &Sink,
    job: &str,
    label: &str,
) -> Result<(), ExecError> {
    let mut out_lines = BufReader::new(stdout).split(b'\n');
    let mut err_lines = BufReader::new(stderr).split(b'\n');
    let mut out_done = false;
    let mut err_done = false;
    let mut logged_bytes: u64 = 0;
    let push = |stream: Stream, line: String, logged_bytes: &mut u64| {
        if *logged_bytes >= MAX_STEP_LOG_BYTES {
            return;
        }
        let line = truncate_line(redactor.redact(&line));
        *logged_bytes += line.len() as u64;
        sink(Event::StepOutput {
            job: job.to_string(),
            step: label.to_string(),
            stream,
            line,
        });
    };
    while !out_done || !err_done {
        tokio::select! {
            line = out_lines.next_segment(), if !out_done => {
                match line {
                    Ok(Some(bytes)) => push(
                        Stream::Stdout,
                        String::from_utf8_lossy(&bytes).trim_end_matches('\r').to_string(),
                        &mut logged_bytes,
                    ),
                    _ => out_done = true,
                }
            }
            line = err_lines.next_segment(), if !err_done => {
                match line {
                    Ok(Some(bytes)) => push(
                        Stream::Stderr,
                        String::from_utf8_lossy(&bytes).trim_end_matches('\r').to_string(),
                        &mut logged_bytes,
                    ),
                    _ => err_done = true,
                }
            }
        }
    }
    Ok(())
}

/// The last `max` bytes of `text`, moved forward to a character boundary so a
/// multibyte character is never sliced.
fn last_chars(text: String, max: usize) -> String {
    if text.len() <= max {
        return text;
    }
    let mut start = text.len() - max;
    while start < text.len() && !text.is_char_boundary(start) {
        start += 1;
    }
    format!("…{}", &text[start..])
}

/// Trim one log line to [`MAX_LOG_LINE_BYTES`] without cutting a UTF-8
/// character (which would panic) and mark the loss.
fn truncate_line(line: String) -> String {
    if line.len() <= MAX_LOG_LINE_BYTES {
        return line;
    }
    let mut end = MAX_LOG_LINE_BYTES;
    while end > 0 && !line.is_char_boundary(end) {
        end -= 1;
    }
    let mut line = line;
    line.truncate(end);
    line.push_str("…[truncated]");
    line
}

/// Spawn the container CLI with piped output. A CLI replaced in place (a
/// package upgrade) returns `ETXTBSY` for a moment; retrying is correct and
/// harmless. Only that error is retried.
async fn spawn_piped(
    bin: &str,
    args: &[String],
    env: &[(String, String)],
) -> std::io::Result<tokio::process::Child> {
    let mut last = None;
    for attempt in 0..3u64 {
        let mut command = Command::new(bin);
        command
            .args(args)
            .envs(env.iter().map(|(key, value)| (key, value)))
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped());
        match command.spawn() {
            Ok(child) => return Ok(child),
            Err(error) => {
                let retry = error.kind() == std::io::ErrorKind::ExecutableFileBusy && attempt < 2;
                if !retry {
                    return Err(error);
                }
                last = Some(error);
                tokio::time::sleep(Duration::from_millis(10 * (attempt + 1))).await;
            }
        }
    }
    Err(last.expect("set when retrying"))
}

/// Run the container CLI to completion, returning stdout. Any failure (spawn,
/// timeout, nonzero exit) becomes [`Error::Container`] with the argv and
/// stderr tail. Values are passed through the child environment only.
async fn cli(bin: &str, args: &[String], env: &[(String, String)]) -> Result<String, Error> {
    let argv = args.join(" ");
    let mut command = Command::new(bin);
    command
        .args(args)
        .envs(env.iter().map(|(key, value)| (key, value)))
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped());
    let child = command
        .spawn()
        .map_err(|error| Error::Container(format!("spawn {bin} {argv}: {error}")))?;
    let output = tokio::time::timeout(CLI_TIMEOUT, child.wait_with_output())
        .await
        .map_err(|_| {
            Error::Container(format!(
                "{bin} {argv}: timed out after {}s",
                CLI_TIMEOUT.as_secs()
            ))
        })?
        .map_err(|error| Error::Container(format!("{bin} {argv}: wait: {error}")))?;
    if !output.status.success() {
        let code = output
            .status
            .code()
            .map(|c| c.to_string())
            .unwrap_or_else(|| "signal".to_string());
        let stderr = last_chars(String::from_utf8_lossy(&output.stderr).into_owned(), 2048);
        return Err(Error::Container(format!(
            "{bin} {argv}: exit {code}: {}",
            stderr.trim()
        )));
    }
    Ok(String::from_utf8_lossy(&output.stdout).into_owned())
}

/// Masks configured secret values in step output.
struct Redactor {
    secrets: Vec<String>,
}

impl Redactor {
    fn new(settings: &Settings, base_env: &BTreeMap<String, String>, job: &Job) -> Self {
        let mut secrets: Vec<String> = settings
            .env
            .iter()
            .map(|(_, value)| value.clone())
            .chain(base_env.values().cloned())
            .chain(job.env.values().cloned())
            .chain(job.steps.iter().flat_map(|step| step.env.values().cloned()))
            .flat_map(|value| {
                // Output is masked one line at a time, so a multi-line secret
                // (a PEM key, a JSON credential file) also contributes each of
                // its lines as its own mask.
                let mut parts = vec![value.clone()];
                if value.contains('\n') {
                    parts.extend(
                        value
                            .lines()
                            .map(|line| line.trim().to_string())
                            .filter(|line| !line.is_empty()),
                    );
                }
                parts
            })
            .filter(|value| value.len() >= MIN_SECRET_BYTES)
            .collect();
        secrets.sort_by_key(|value| std::cmp::Reverse(value.len()));
        secrets.dedup();
        Self { secrets }
    }

    fn redact(&self, line: &str) -> String {
        let mut line = line.to_string();
        for secret in &self.secrets {
            if line.contains(secret.as_str()) {
                line = line.replace(secret.as_str(), "***");
            }
        }
        line
    }
}

/// Registered live container names, used to keep the orphan sweep from
/// removing a container a concurrent run in this process still owns.
fn live() -> &'static Mutex<HashSet<String>> {
    static LIVE: LazyLock<Mutex<HashSet<String>>> = LazyLock::new(|| Mutex::new(HashSet::new()));
    &LIVE
}

/// Remove containers labelled with this process id that no live run owns.
///
/// Best-effort: a CLI that fails here (an old version, a stopped daemon) must
/// not stop the run; leaking is reported by the daemon anyway.
async fn sweep_orphans(settings: &Settings) {
    let filter = format!("label={PID_LABEL}={}", std::process::id());
    let args = vec![
        "ps".to_string(),
        "-a".to_string(),
        "--filter".to_string(),
        filter,
        "--format".to_string(),
        "{{.Names}}".to_string(),
    ];
    let Ok(output) = cli(&settings.docker_bin, &args, &[]).await else {
        return;
    };
    for name in output
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
    {
        if live().lock().expect("live lock").contains(name) {
            continue;
        }
        let args = vec!["rm".to_string(), "-f".to_string(), name.to_string()];
        let _ = cli(&settings.docker_bin, &args, &[]).await;
    }
}

/// One job container. Removal is armed from creation until the explicit
/// `rm -f` lands, so cancellation cannot leak it.
struct JobContainer {
    bin: String,
    name: String,
    work: String,
    armed: bool,
}

impl JobContainer {
    async fn start(
        settings: &Settings,
        work: &str,
        image: &str,
        job_name: &str,
    ) -> Result<Self, Error> {
        static CREATE_COUNTER: AtomicU64 = AtomicU64::new(0);
        let id = CREATE_COUNTER.fetch_add(1, Ordering::Relaxed);
        let name = format!("{}-{}-{id}", settings.container_prefix, std::process::id());
        let mut args: Vec<String> = vec![
            "create".to_string(),
            "--init".to_string(),
            "--cap-drop".to_string(),
            "ALL".to_string(),
            // The ownership prep runs as container root; CAP_CHOWN lets it
            // hand /work and the cache dir to the build uid. Steps run as that
            // uid with no capabilities, so this one never reaches step code.
            "--cap-add".to_string(),
            "CHOWN".to_string(),
            "--security-opt".to_string(),
            "no-new-privileges".to_string(),
            "--pids-limit".to_string(),
            "2048".to_string(),
            "--memory".to_string(),
            format!("{}m", settings.memory_mb),
            "--memory-swap".to_string(),
            format!("{}m", settings.memory_mb),
            "--cpus".to_string(),
            format_cpus(settings.cpus),
            "--network".to_string(),
            settings.network.clone(),
            "--pull".to_string(),
            settings.pull.as_arg().to_string(),
            "--label".to_string(),
            format!("{PID_LABEL}={}", std::process::id()),
            "--label".to_string(),
            format!("ryuz_workflow.job={}", sanitize_label(job_name)),
            "--user".to_string(),
            "0".to_string(),
            "--name".to_string(),
            name.clone(),
        ];
        if let Some(platform) = &settings.platform {
            args.push("--platform".to_string());
            args.push(platform.clone());
        }
        match &settings.cache_volume {
            Some(volume) => {
                args.push("-v".to_string());
                args.push(format!("{volume}:{CACHE_DIR}"));
            }
            None => {
                args.push("--tmpfs".to_string());
                args.push(format!("{CACHE_DIR}:rw,mode=1777"));
            }
        }
        for (key, _) in &settings.env {
            args.push("-e".to_string());
            args.push(key.clone());
        }
        // HOME always points at the writable cache dir.
        args.push("-e".to_string());
        args.push(format!("HOME={CACHE_DIR}"));
        args.push(image.to_string());
        args.push("sh".to_string());
        args.push("-lc".to_string());
        args.push("sleep infinity".to_string());
        cli(&settings.docker_bin, &args, &settings.env).await?;
        let container = Self {
            bin: settings.docker_bin.clone(),
            name,
            work: work.to_string(),
            armed: true,
        };
        live()
            .lock()
            .expect("live lock")
            .insert(container.name.clone());
        container.start_container().await?;
        let args = vec![
            "cp".to_string(),
            format!("{work}/."),
            format!("{}:/work", container.name),
        ];
        cli(&container.bin, &args, &[]).await?;
        let args = vec![
            "exec".to_string(),
            "-u".to_string(),
            "0".to_string(),
            container.name.clone(),
            "chown".to_string(),
            "-R".to_string(),
            format!("{}:{}", settings.uid, settings.gid),
            "/work".to_string(),
            CACHE_DIR.to_string(),
        ];
        cli(&container.bin, &args, &[]).await?;
        Ok(container)
    }

    async fn start_container(&self) -> Result<(), Error> {
        cli(&self.bin, &["start".to_string(), self.name.clone()], &[])
            .await
            .map(|_| ())
    }

    async fn kill(&self) {
        let _ = tokio::time::timeout(
            KILL_TIMEOUT,
            cli(&self.bin, &["kill".to_string(), self.name.clone()], &[]),
        )
        .await;
    }

    async fn remove(&mut self) {
        let _ = cli(
            &self.bin,
            &["rm".to_string(), "-f".to_string(), self.name.clone()],
            &[],
        )
        .await;
        self.armed = false;
        live().lock().expect("live lock").remove(&self.name);
    }
}

impl Drop for JobContainer {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        self.armed = false;
        live().lock().expect("live lock").remove(&self.name);
        let bin = self.bin.clone();
        let name = self.name.clone();
        let remove = async move {
            let _ = cli(&bin, &["rm".to_string(), "-f".to_string(), name], &[]).await;
        };
        match tokio::runtime::Handle::try_current() {
            Ok(handle) => {
                handle.spawn(remove);
            }
            Err(_) => {
                let _ = std::process::Command::new(&self.bin)
                    .args(["rm", "-f", &self.name])
                    .stdin(std::process::Stdio::null())
                    .stdout(std::process::Stdio::null())
                    .stderr(std::process::Stdio::null())
                    .spawn();
            }
        }
    }
}

/// Docker label values allow `[A-Za-z0-9_.-]`; job names can carry spaces,
/// parentheses and commas from matrix expansion.
fn sanitize_label(name: &str) -> String {
    let mut out: String = name
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | '-') {
                c
            } else {
                '_'
            }
        })
        .collect();
    out.truncate(128);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event::format_event;
    use crate::workflow::parse;
    use std::sync::atomic::AtomicU64;

    fn settings_for(script: &Path) -> Settings {
        Settings {
            docker_bin: script.to_string_lossy().into_owned(),
            default_image: "oven/bun:1.4.4".to_string(),
            allowed_images: vec!["oven/bun:1.4.4".to_string(), "oven/bun:1.4.3".to_string()],
            network: "bridge".to_string(),
            memory_mb: 512,
            cpus: 1.5,
            uid: 1000,
            gid: 1000,
            cache_volume: Some("ryuz-workflow-cache-test".to_string()),
            env: vec![],
            container_prefix: "ryuz-wf".to_string(),
            artifact_dir: Some("dist".to_string()),
            platform: None,
            pull: PullPolicy::Missing,
            max_parallel: 1,
            run_timeout: None,
        }
    }

    fn logged() -> (
        Arc<Mutex<Vec<String>>>,
        impl Fn(String) + Send + Sync + 'static,
    ) {
        let lines: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
        let sink = lines.clone();
        (lines, move |line: String| {
            sink.lock().expect("log lock").push(line);
        })
    }

    fn collected() -> (
        Arc<Mutex<Vec<Event>>>,
        impl Fn(Event) + Send + Sync + 'static,
    ) {
        let events: Arc<Mutex<Vec<Event>>> = Arc::new(Mutex::new(Vec::new()));
        let sink = events.clone();
        (events, move |event: Event| {
            sink.lock().expect("event lock").push(event);
        })
    }

    /// A fake container CLI. Behavior is driven by files next to the script (no
    /// env mutation, so tests stay parallel): `step-exit` (exit code),
    /// `step-sleep` (seconds the step sleeps), `step-stdout` (lines printed),
    /// `no-artifact` (a `cp` out of the container fails). Every invocation
    /// appends its argv, one arg per line plus a `---` separator, to `argv.log`;
    /// `create` records the CLI child's `FOO`, `exec` records `NODE_ENV`/`FOO`,
    /// and `rm` appends to `rm.log`.
    fn fake_docker() -> PathBuf {
        static N: AtomicU64 = AtomicU64::new(0);
        let dir = std::env::temp_dir().join(format!(
            "ryuz-workflow-fake-{}-{}",
            std::process::id(),
            N.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&dir).expect("temp dir");
        let script = dir.join("docker");
        std::fs::write(
            &script,
            r#"#!/bin/sh
DIR=$(dirname "$0")
block="---"
for arg in "$@"; do
  block="$block
$arg"
done
# One write per invocation: concurrent CLI calls must not interleave blocks.
printf '%s\n' "$block" >> "$DIR/argv.log"
cmd=$1
shift
case "$cmd" in
  ps) exit 0;;
  create)
    printf 'FOO=%s\n' "$FOO" >> "$DIR/create-env.log"
    echo "fake-container-id"; exit 0;;
  start|kill) exit 0;;
  rm)
    printf 'rm\n' >> "$DIR/rm.log"
    exit 0;;
  cp)
    case "$1" in
      *:/work/*)
        if [ -e "$DIR/no-artifact" ]; then echo "no such file or directory" >&2; exit 1; fi
        mkdir -p "$2" && printf 'fake\n' > "$2/from-ci.txt"
        exit 0;;
      *) exit 0;;
    esac;;
  exec)
    case "$*" in
      *"chown -R"*) exit 0;;
    esac
    printf 'NODE_ENV=%s FOO=%s MATRIX=%s\n' "$NODE_ENV" "$FOO" "$RYUZ_MATRIX_NODE" >> "$DIR/exec-env.log"
    if [ -e "$DIR/step-stdout" ]; then cat "$DIR/step-stdout"; fi
    if [ -e "$DIR/step-sleep" ]; then sleep "$(cat "$DIR/step-sleep")"; fi
    if [ -e "$DIR/step-exit" ]; then exit "$(cat "$DIR/step-exit")"; fi
    exit 0;;
  *) echo "unexpected: $cmd" >&2; exit 99;;
esac
"#,
        )
        .expect("write fake docker");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755))
                .expect("chmod");
        }
        script
    }

    fn argv_log(script: &Path) -> Vec<Vec<String>> {
        let log = script.parent().expect("parent").join("argv.log");
        let text = std::fs::read_to_string(log).unwrap_or_default();
        text.split("\n---\n")
            .filter_map(|block| {
                let args: Vec<String> = block
                    .lines()
                    .filter(|line| !line.is_empty() && *line != "---")
                    .map(str::to_string)
                    .collect();
                (!args.is_empty()).then_some(args)
            })
            .collect()
    }

    fn verbs(invocations: &[Vec<String>]) -> Vec<&str> {
        invocations.iter().map(|args| args[0].as_str()).collect()
    }

    fn write_flag(script: &Path, name: &str, contents: &str) {
        std::fs::write(script.parent().expect("parent").join(name), contents).expect("flag");
    }

    fn work_dir(tag: &str) -> PathBuf {
        static N: AtomicU64 = AtomicU64::new(0);
        let dir = std::env::temp_dir().join(format!(
            "ryuz-workflow-work-{tag}-{}-{}",
            std::process::id(),
            N.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&dir).expect("work dir");
        std::fs::write(dir.join("index.ts"), "export {};\n").expect("seed file");
        dir
    }

    fn test_workflow() -> Workflow {
        parse(
            "jobs:\n  build:\n    steps:\n      - name: Install\n        run: bun install\n        env: { NODE_ENV: production }\n        working-directory: packages/app\n      - run: bun run build\n",
        )
        .expect("test workflow parses")
    }

    #[tokio::test]
    async fn engine_builds_expected_argv_and_copies_artifact() {
        let script = fake_docker();
        let work = work_dir("argv");
        let mut settings = settings_for(&script);
        settings.env = vec![("FOO".to_string(), "bar-secret".to_string())];
        let (lines, log) = logged();
        let outcome = run(&settings, &work, &test_workflow(), log)
            .await
            .expect("fake run succeeds");

        let invocations = argv_log(&script);
        let got = verbs(&invocations);
        assert_eq!(
            got,
            vec!["ps", "create", "start", "cp", "exec", "exec", "exec", "cp", "rm"],
            "{invocations:?}"
        );
        // Sweep targets only this process's leftovers.
        assert!(invocations[0]
            .iter()
            .any(|arg| arg == &format!("label={PID_LABEL}={}", std::process::id())));

        let create = &invocations[1];
        for required in [
            "--init",
            "--cap-drop",
            "ALL",
            "--cap-add",
            "CHOWN",
            "--security-opt",
            "no-new-privileges",
            "--pids-limit",
            "2048",
            "--memory",
            "512m",
            "--memory-swap",
            "512m",
            "--cpus",
            "1.5",
            "--network",
            "bridge",
            "--pull",
            "missing",
            "--user",
            "0",
        ] {
            assert!(
                create.iter().any(|arg| arg == required),
                "{required}: {create:?}"
            );
        }
        assert!(create
            .iter()
            .any(|arg| arg == &format!("{PID_LABEL}={}", std::process::id())));
        assert!(create.windows(2).any(|pair| pair
            == [
                "-v".to_string(),
                format!("ryuz-workflow-cache-test:{CACHE_DIR}")
            ]));
        // Env is referenced by name only; the value is never argv.
        assert!(create
            .windows(2)
            .any(|pair| pair == ["-e".to_string(), "FOO".to_string()]));
        assert!(create
            .windows(2)
            .any(|pair| pair == ["-e".to_string(), format!("HOME={CACHE_DIR}")]));
        assert!(!create.iter().any(|arg| arg.contains("bar-secret")));
        assert_eq!(
            std::fs::read_to_string(script.parent().unwrap().join("create-env.log"))
                .expect("create env"),
            "FOO=bar-secret\n"
        );

        let container = create
            .iter()
            .position(|arg| arg == "--name")
            .map(|index| create[index + 1].clone())
            .expect("name");
        assert!(container.starts_with("ryuz-wf-"), "{container}");

        let chown = &invocations[4];
        assert_eq!(
            chown,
            &vec![
                "exec",
                "-u",
                "0",
                &container,
                "chown",
                "-R",
                "1000:1000",
                "/work",
                CACHE_DIR,
            ]
            .into_iter()
            .map(str::to_string)
            .collect::<Vec<_>>()
        );

        let step1 = &invocations[5];
        assert_eq!(
            &step1[0..8],
            &[
                "exec",
                "--user",
                "1000:1000",
                "-w",
                "/work/packages/app",
                "-e",
                "NODE_ENV",
                &container,
            ]
        );
        assert_eq!(&step1[8..11], &["sh", "-lc", "bun install"]);
        let step2 = &invocations[6];
        assert_eq!(step2[4], "/work");
        assert_eq!(&step2[5..8], &[&container, "sh", "-lc"]);
        assert_eq!(step2[8], "bun run build");
        // Values still reach the CLI child's environment.
        let exec_env = std::fs::read_to_string(script.parent().unwrap().join("exec-env.log"))
            .expect("exec env");
        assert!(exec_env.contains("NODE_ENV=production"), "{exec_env}");

        assert_eq!(invocations[7][0], "cp");
        assert_eq!(invocations[7][1], format!("{container}:/work/dist"));
        assert!(
            invocations[7][2].starts_with(
                work.join(".ryuz-workflow-stage-")
                    .to_string_lossy()
                    .as_ref()
            ),
            "copies out to staging first: {invocations:?}"
        );
        assert_eq!(
            invocations[8],
            vec!["rm".to_string(), "-f".to_string(), container]
        );

        assert!(outcome.success());
        assert_eq!(outcome.jobs[0].steps.len(), 2);
        assert_eq!(outcome.artifact_path, Some(work.join("dist")));
        assert_eq!(outcome.artifacts.len(), 1);
        assert!(work.join("dist/from-ci.txt").exists());

        let lines = lines.lock().expect("log lock");
        for expected in [
            "workflow: 1 jobs",
            "job: build (oven/bun:1.4.4)",
            "step: Install",
            "job: build done",
            "workflow: done",
        ] {
            assert!(
                lines.iter().any(|line| line == expected),
                "{expected}: {lines:?}"
            );
        }
    }

    #[tokio::test]
    async fn secrets_are_redacted_from_step_output() {
        let script = fake_docker();
        write_flag(&script, "step-stdout", "token=supersecret\n");
        let work = work_dir("redact");
        let mut settings = settings_for(&script);
        settings.env = vec![("SECRET".to_string(), "supersecret".to_string())];
        let workflow =
            parse("jobs:\n  build:\n    steps:\n      - run: echo hi\n").expect("parses");
        let (events, sink) = collected();
        let outcome = run_with_events(&settings, &work, &workflow, sink)
            .await
            .expect("runs");
        assert!(outcome.success());
        let events = events.lock().expect("event lock");
        assert!(
            events.iter().any(|event| matches!(
                event,
                Event::StepOutput { line, .. } if line == "token=***"
            )),
            "{events:?}"
        );
        assert!(
            !events
                .iter()
                .any(|event| format!("{event:?}").contains("supersecret")),
            "secret leaked: {events:?}"
        );
    }

    #[tokio::test]
    async fn failure_stops_the_job_and_still_cleans_up() {
        let script = fake_docker();
        write_flag(&script, "step-exit", "3");
        let work = work_dir("fail");
        let (lines, log) = logged();
        let outcome = run(&settings_for(&script), &work, &test_workflow(), log)
            .await
            .expect("attempted");
        assert!(!outcome.success());
        assert_eq!(
            outcome.jobs[0].status,
            JobStatus::Failed(Failure::StepFailed {
                step: "Install".to_string(),
                exit_code: 3,
            })
        );
        assert_eq!(outcome.jobs[0].steps.len(), 1, "second step did not run");
        let invocations = argv_log(&script);
        let got = verbs(&invocations);
        assert_eq!(
            got,
            vec!["ps", "create", "start", "cp", "exec", "exec", "rm"]
        );
        let lines = lines.lock().expect("log lock");
        assert!(
            lines
                .iter()
                .any(|line| line == "job: build step `Install` failed with exit 3"),
            "{lines:?}"
        );
        assert!(
            lines.iter().any(|line| line == "workflow: failed"),
            "{lines:?}"
        );
    }

    #[tokio::test]
    async fn exit_137_is_reported_as_out_of_memory() {
        let script = fake_docker();
        write_flag(&script, "step-exit", "137");
        let work = work_dir("oom");
        let workflow =
            parse("jobs:\n  build:\n    steps:\n      - run: eat memory\n").expect("parses");
        let (events, sink) = collected();
        let outcome = run_with_events(&settings_for(&script), &work, &workflow, sink)
            .await
            .expect("attempted");
        assert_eq!(
            outcome.jobs[0].status,
            JobStatus::Failed(Failure::OutOfMemory {
                step: "step #1".to_string()
            })
        );
        let events = events.lock().expect("event lock");
        assert!(
            events.iter().any(|event| matches!(
                event,
                Event::Note { line, .. } if line.contains("exit 137") && line.contains("out of memory")
            )),
            "{events:?}"
        );
    }

    #[tokio::test]
    async fn container_guard_removes_on_drop() {
        let script = fake_docker();
        let work = work_dir("guard");
        let settings = settings_for(&script);
        let container = JobContainer::start(
            &settings,
            work.to_str().expect("utf8"),
            "oven/bun:1.4.4",
            "probe",
        )
        .await
        .expect("starts");
        let name = container.name.clone();
        drop(container);
        tokio::time::sleep(Duration::from_millis(300)).await;
        let invocations = argv_log(&script);
        assert!(
            invocations
                .iter()
                .any(|args| args == &vec!["rm".to_string(), "-f".to_string(), name.clone()]),
            "no rm for {name}: {invocations:?}"
        );
    }

    #[tokio::test]
    async fn step_timeout_kills_the_container() {
        let script = fake_docker();
        write_flag(&script, "step-sleep", "30");
        let work = work_dir("timeout");
        let settings = settings_for(&script);
        let workflow =
            parse("jobs:\n  build:\n    steps:\n      - name: Hang\n        run: sleep\n")
                .expect("parses");
        let job = &workflow.jobs[0];
        let step = &job.steps[0];
        let container = JobContainer::start(
            &settings,
            work.to_str().expect("utf8"),
            "oven/bun:1.4.4",
            "probe",
        )
        .await
        .expect("starts");
        let (_events, sink) = collected();
        let sink: Sink = Arc::new(sink);
        let redactor = Redactor::new(&settings, &BTreeMap::new(), job);
        let error = exec_step(
            &settings,
            job,
            &container,
            "Hang",
            step,
            "sleep",
            Shell::Sh,
            &[],
            Duration::from_millis(200),
            &sink,
            &redactor,
        )
        .await
        .expect_err("times out");
        assert!(matches!(error, ExecError::Timeout));
        assert!(verbs(&argv_log(&script)).contains(&"kill"));
    }

    #[tokio::test]
    async fn disallowed_image_never_starts_a_container() {
        let script = fake_docker();
        let work = work_dir("allowlist");
        let workflow = parse(
            "jobs:\n  build:\n    image: evil/thing:latest\n    steps:\n      - run: echo hi\n",
        )
        .expect("parses");
        let (_lines, log) = logged();
        let error = run(&settings_for(&script), &work, &workflow, log)
            .await
            .expect_err("allowlist");
        assert!(matches!(error, Error::ImageNotAllowed(_)), "{error}");
        let invocations = argv_log(&script);
        assert!(
            invocations.iter().all(|args| args[0] != "create"),
            "{invocations:?}"
        );
    }

    #[tokio::test]
    async fn noop_actions_and_missing_artifacts_are_notes() {
        let script = fake_docker();
        write_flag(&script, "no-artifact", "");
        let work = work_dir("skip");
        let workflow = parse(
            "jobs:\n\
             \x20 build:\n\
             \x20\x20\x20 steps:\n\
             \x20\x20\x20\x20 - uses: checkout\n\
             \x20\x20\x20\x20 - uses: cache\n\
             \x20\x20\x20\x20\x20\x20 with: { path: ~/.cache, key: x }\n\
             \x20\x20\x20\x20 - run: echo hi\n",
        )
        .expect("parses");
        let (events, sink) = collected();
        let outcome = run_with_events(&settings_for(&script), &work, &workflow, sink)
            .await
            .expect("runs");
        assert!(outcome.success());
        assert!(outcome.artifact_path.is_none());
        assert!(outcome.artifacts.is_empty());
        let invocations = argv_log(&script);
        assert_eq!(
            verbs(&invocations),
            vec!["ps", "create", "start", "cp", "exec", "exec", "cp", "rm"]
        );
        let events = events.lock().expect("event lock");
        for needle in [
            "uses: checkout is a no-op",
            "uses: cache is a no-op",
            "no dist in container, skipping",
        ] {
            assert!(
                events.iter().any(|event| matches!(
                    event,
                    Event::Note { line, .. } if line.contains(needle)
                )),
                "{needle}: {events:?}"
            );
        }
    }

    #[tokio::test]
    async fn upload_artifact_copies_a_nested_path() {
        let script = fake_docker();
        let work = work_dir("artifact");
        let workflow = parse(
            "jobs:\n\
             \x20 build:\n\
             \x20\x20\x20 steps:\n\
             \x20\x20\x20\x20 - run: echo hi\n\
             \x20\x20\x20\x20 - uses: upload-artifact\n\
             \x20\x20\x20\x20\x20\x20 with: { path: reports/junit.xml, name: junit }\n",
        )
        .expect("parses");
        let (events, sink) = collected();
        let outcome = run_with_events(&settings_for(&script), &work, &workflow, sink)
            .await
            .expect("runs");
        assert!(outcome.success());
        let artifact = outcome.artifacts.first().expect("artifact");
        assert_eq!(artifact.name.as_deref(), Some("junit"));
        assert_eq!(artifact.path, work.join("reports/junit.xml"));
        assert!(artifact.path.join("from-ci.txt").exists());
        let events = events.lock().expect("event lock");
        assert!(events.iter().any(|event| matches!(
            event,
            Event::Artifact { name, .. } if name.as_deref() == Some("junit")
        )));
        // The automatic dist copy is still attempted after the job.
        let invocations = argv_log(&script);
        assert!(invocations
            .iter()
            .any(|args| args[0] == "cp" && args[1].ends_with(":/work/reports/junit.xml")));
    }

    #[tokio::test]
    async fn parallel_jobs_overlap_and_sequential_jobs_do_not() {
        let script = fake_docker();
        write_flag(&script, "step-sleep", "0.3");
        let workflow = parse(
            "jobs:\n\
             \x20 a:\n\
             \x20\x20\x20 steps:\n\
             \x20\x20\x20\x20 - run: echo a\n\
             \x20 b:\n\
             \x20\x20\x20 steps:\n\
             \x20\x20\x20\x20 - run: echo b\n",
        )
        .expect("parses");
        let work = work_dir("parallel");
        let mut settings = settings_for(&script);
        settings.max_parallel = 2;
        let (_lines, log) = logged();
        let outcome = run(&settings, &work, &workflow, log).await.expect("runs");

        let invocations = argv_log(&script);
        let got = verbs(&invocations);
        let first_create = got
            .iter()
            .position(|verb| *verb == "create")
            .expect("create");
        let second_create = got
            .iter()
            .enumerate()
            .filter(|(_, verb)| **verb == "create")
            .nth(1)
            .map(|(index, _)| index)
            .unwrap_or_else(|| panic!("second create: {got:?} {invocations:?} {:?}", outcome.jobs));
        let first_rm = got.iter().position(|verb| *verb == "rm").expect("rm");
        assert!(
            second_create < first_rm,
            "parallel jobs did not overlap: {got:?} {:?}",
            outcome.jobs
        );
        assert!(first_create < second_create);

        // Sequential: the first job is gone before the second starts.
        let script = fake_docker();
        write_flag(&script, "step-sleep", "0.1");
        let work = work_dir("sequential");
        let mut settings = settings_for(&script);
        settings.max_parallel = 1;
        let (_lines, log) = logged();
        let outcome = run(&settings, &work, &workflow, log).await.expect("runs");
        let invocations = argv_log(&script);
        let got = verbs(&invocations);
        let first_rm = got.iter().position(|verb| *verb == "rm").expect("rm");
        let second_create = got
            .iter()
            .enumerate()
            .filter(|(_, verb)| **verb == "create")
            .nth(1)
            .map(|(index, _)| index)
            .unwrap_or_else(|| panic!("second create: {got:?} {:?}", outcome.jobs));
        assert!(
            first_rm < second_create,
            "sequential jobs overlapped: {got:?}"
        );
    }

    #[tokio::test]
    async fn matrix_fail_fast_skips_the_rest_of_the_group() {
        let script = fake_docker();
        write_flag(&script, "step-exit", "3");
        let work = work_dir("failfast");
        let workflow = parse(
            "jobs:\n\
             \x20 build:\n\
             \x20\x20 strategy: { matrix: { node: [20, 22] } }\n\
             \x20\x20 steps:\n\
             \x20\x20\x20 - run: echo hi\n",
        )
        .expect("parses");
        let (_lines, log) = logged();
        let outcome = run(&settings_for(&script), &work, &workflow, log)
            .await
            .expect("attempted");
        let statuses: Vec<&JobStatus> = outcome.jobs.iter().map(|job| &job.status).collect();
        assert!(matches!(statuses[0], JobStatus::Failed(_)), "{statuses:?}");
        assert_eq!(statuses[1], &JobStatus::Skipped, "{statuses:?}");
        assert!(!outcome.success());
    }

    #[tokio::test]
    async fn matrix_fail_fast_false_runs_every_member() {
        let script = fake_docker();
        write_flag(&script, "step-exit", "3");
        let work = work_dir("nofailfast");
        let workflow = parse(
            "jobs:\n\
             \x20 build:\n\
             \x20\x20 strategy: { matrix: { node: [20, 22] }, fail-fast: false }\n\
             \x20\x20 steps:\n\
             \x20\x20\x20 - run: echo hi\n",
        )
        .expect("parses");
        let (_lines, log) = logged();
        let outcome = run(&settings_for(&script), &work, &workflow, log)
            .await
            .expect("attempted");
        assert!(
            outcome
                .jobs
                .iter()
                .all(|job| matches!(job.status, JobStatus::Failed(_))),
            "{:?}",
            outcome.jobs
        );
    }

    #[tokio::test]
    async fn run_timeout_cancels_unfinished_jobs() {
        let script = fake_docker();
        write_flag(&script, "step-sleep", "30");
        let work = work_dir("runtimout");
        let workflow =
            parse("jobs:\n  build:\n    steps:\n      - run: sleep 30\n").expect("parses");
        let mut settings = settings_for(&script);
        settings.run_timeout = Some(Duration::from_millis(200));
        let (_lines, log) = logged();
        let outcome = run(&settings, &work, &workflow, log)
            .await
            .expect("attempted");
        assert!(!outcome.success());
        assert!(outcome
            .jobs
            .iter()
            .all(|job| job.status == JobStatus::Cancelled));
    }

    #[tokio::test]
    async fn bash_and_job_defaults_shape_the_exec_argv() {
        let script = fake_docker();
        let work = work_dir("bash");
        let workflow = parse(
            "jobs:\n\
             \x20 build:\n\
             \x20\x20 defaults: { run: { shell: bash, working-directory: app } }\n\
             \x20\x20 steps:\n\
             \x20\x20\x20 - run: echo hi\n",
        )
        .expect("parses");
        let (_lines, log) = logged();
        run(&settings_for(&script), &work, &workflow, log)
            .await
            .expect("runs");
        let invocations = argv_log(&script);
        let exec = invocations
            .iter()
            .find(|args| args[0] == "exec" && args[1] == "--user")
            .expect("step exec");
        assert!(exec.windows(2).any(|pair| pair == ["-w", "/work/app"]));
        assert!(exec
            .windows(6)
            .any(|pair| pair == ["bash", "-e", "-o", "pipefail", "-l", "-c"]));
    }

    #[test]
    fn settings_validation_covers_every_field() {
        type Mutate = Box<dyn Fn(&mut Settings)>;
        let bad_cases: Vec<Mutate> = vec![
            Box::new(|s: &mut Settings| s.docker_bin = String::new()),
            Box::new(|s: &mut Settings| s.default_image = String::new()),
            Box::new(|s: &mut Settings| s.network = String::new()),
            Box::new(|s: &mut Settings| s.memory_mb = 0),
            Box::new(|s: &mut Settings| s.cpus = 0.0),
            Box::new(|s: &mut Settings| s.cache_volume = Some(String::new())),
            Box::new(|s: &mut Settings| s.container_prefix = String::new()),
            Box::new(|s: &mut Settings| s.container_prefix = "-bad".to_string()),
            Box::new(|s: &mut Settings| s.container_prefix = "a b".to_string()),
            Box::new(|s: &mut Settings| s.artifact_dir = Some(String::new())),
            Box::new(|s: &mut Settings| s.artifact_dir = Some("/abs".to_string())),
            Box::new(|s: &mut Settings| s.artifact_dir = Some("../e".to_string())),
            Box::new(|s: &mut Settings| s.platform = Some(String::new())),
            Box::new(|s: &mut Settings| s.max_parallel = 0),
            Box::new(|s: &mut Settings| s.run_timeout = Some(Duration::ZERO)),
        ];
        for mutate in bad_cases {
            let mut settings = settings_for(Path::new("/bin/true"));
            mutate(&mut settings);
            assert!(validate_settings(&settings).is_err(), "{settings:?}");
        }
        let mut settings = settings_for(Path::new("/bin/true"));
        settings.container_prefix = "ryuz.workflow_1".to_string();
        settings.artifact_dir = Some("build/out".to_string());
        settings.platform = Some("linux/arm64".to_string());
        settings.max_parallel = 4;
        assert!(validate_settings(&settings).is_ok());
    }

    #[test]
    fn format_event_covers_the_log_protocol() {
        assert_eq!(
            format_event(&Event::JobStarted {
                job: "build".to_string(),
                image: "img".to_string(),
            })
            .as_deref(),
            Some("job: build (img)")
        );
        assert_eq!(
            format_event(&Event::StepStarted {
                job: "build".to_string(),
                step: "Install".to_string(),
            })
            .as_deref(),
            Some("step: Install")
        );
        assert_eq!(
            format_event(&Event::StepFinished {
                job: "build".to_string(),
                step: "Install".to_string(),
                exit_code: 0,
                duration: Duration::ZERO,
            }),
            None
        );
        assert_eq!(
            format_event(&Event::JobFinished {
                job: "build".to_string(),
                status: JobStatus::Skipped,
                duration: Duration::ZERO,
            })
            .as_deref(),
            Some("job: build skipped")
        );
    }

    #[tokio::test]
    async fn real_docker_runs_two_steps_sharing_state() {
        let workflow = parse(
            "jobs:\n  build:\n    steps:\n      - name: Write\n        run: echo hello > msg.txt && mkdir -p dist && echo page > dist/index.html && echo \"home=$HOME\"\n      - name: Read\n        run: cat msg.txt && printenv GREETING\n",
        )
        .expect("parses");
        // Opt-in: the real-container path pulls an image and needs a working
        // daemon; CI stays hermetic and runs it only when asked
        // (`RYUZ_WORKFLOW_REAL_DOCKER=1` on a host with Docker, or the CLI path
        // such as `RYUZ_WORKFLOW_REAL_DOCKER=podman`).
        let Ok(runner) = std::env::var("RYUZ_WORKFLOW_REAL_DOCKER") else {
            eprintln!("skipping: set RYUZ_WORKFLOW_REAL_DOCKER=<cli> to run real containers");
            return;
        };
        let bin = if runner == "1" {
            "docker"
        } else {
            runner.as_str()
        };
        if !std::process::Command::new(bin)
            .arg("info")
            .output()
            .is_ok_and(|output| output.status.success())
        {
            eprintln!("skipping: `{bin} info` failed");
            return;
        }
        let work = work_dir("real");
        let settings = Settings {
            docker_bin: bin.to_string(),
            default_image: "oven/bun:1.4.4".to_string(),
            allowed_images: vec!["oven/bun:1.4.4".to_string()],
            network: "bridge".to_string(),
            memory_mb: 512,
            cpus: 1.0,
            uid: 1000,
            gid: 1000,
            cache_volume: Some(format!("ryuz-workflow-cache-real-{}", std::process::id())),
            env: vec![("GREETING".to_string(), "hello-real".to_string())],
            container_prefix: "ryuz-wf".to_string(),
            artifact_dir: Some("dist".to_string()),
            platform: None,
            pull: PullPolicy::Missing,
            max_parallel: 1,
            run_timeout: None,
        };
        let (lines, log) = logged();
        let outcome = run(&settings, &work, &workflow, log)
            .await
            .expect("real run succeeds");
        assert!(outcome.success(), "{:?}", outcome.jobs);
        let lines = lines.lock().expect("log lock");
        assert!(lines.iter().any(|line| line == "hello"), "{lines:?}");
        // HOME points at the cache mount, and base env reached the step through
        // `-e KEY` + the CLI child env (then got masked in the log).
        assert!(
            lines.iter().any(|line| line == "home=/ci-home"),
            "{lines:?}"
        );
        assert!(lines.iter().any(|line| line == "***"), "{lines:?}");
        assert!(
            !lines.iter().any(|line| line.contains("hello-real")),
            "{lines:?}"
        );
        let artifact = outcome.artifact_path.expect("artifact");
        assert!(artifact.join("index.html").exists());
    }

    #[test]
    fn truncation_helpers_never_split_a_character() {
        let mut line = "a".repeat(MAX_LOG_LINE_BYTES - 1);
        line.push('é');
        line.push_str("tail");
        let trimmed = truncate_line(line);
        assert!(trimmed.ends_with("…[truncated]"), "{trimmed}");
        assert_eq!(trimmed.len(), MAX_LOG_LINE_BYTES - 1 + "…[truncated]".len());

        // The tail starts inside the second byte of `é`; it must move forward.
        let text = format!("{}é{}", "a".repeat(2999), "b".repeat(2047));
        let tail = last_chars(text, 2048);
        assert!(tail.starts_with('…'), "{tail}");
    }

    #[tokio::test]
    async fn multiline_secrets_are_masked_line_by_line() {
        let script = fake_docker();
        let secret = "-----BEGIN KEY-----\nsupersecretline\n-----END KEY-----";
        write_flag(
            &script,
            "step-stdout",
            "-----BEGIN KEY-----\nsupersecretline\n-----END KEY-----\n",
        );
        let work = work_dir("multiline");
        let mut settings = settings_for(&script);
        settings.env = vec![("SECRET".to_string(), secret.to_string())];
        let workflow =
            parse("jobs:\n  build:\n    steps:\n      - run: cat key\n").expect("parses");
        let (events, sink) = collected();
        let outcome = run_with_events(&settings, &work, &workflow, sink)
            .await
            .expect("runs");
        assert!(outcome.success());
        let events = events.lock().expect("event lock");
        assert!(
            events.iter().any(|event| matches!(
                event,
                Event::StepOutput { line, .. } if line == "***"
            )),
            "{events:?}"
        );
        assert!(
            !events
                .iter()
                .any(|event| format!("{event:?}").contains("supersecretline")),
            "secret leaked: {events:?}"
        );
    }

    #[tokio::test]
    async fn invalid_utf8_output_is_lossy_and_still_drained() {
        let script = fake_docker();
        let mut bytes = vec![0xff, b'\n'];
        bytes.extend(std::iter::repeat_n(b'x', 200 * 1024));
        bytes.push(b'\n');
        std::fs::write(script.parent().expect("parent").join("step-stdout"), bytes)
            .expect("stdout");
        let work = work_dir("invalid-utf8");
        let workflow =
            parse("jobs:\n  build:\n    steps:\n      - run: cat blob\n").expect("parses");
        let (events, sink) = collected();
        let outcome = tokio::time::timeout(
            Duration::from_secs(10),
            run_with_events(&settings_for(&script), &work, &workflow, sink),
        )
        .await
        .expect("must not hang on invalid UTF-8")
        .expect("runs");
        assert!(outcome.success());
        let events = events.lock().expect("event lock");
        assert!(
            events.iter().any(|event| matches!(
                event,
                Event::StepOutput { line, .. } if line.contains('\u{FFFD}')
            )),
            "{events:?}"
        );
        assert!(
            events.iter().any(|event| matches!(
                event,
                Event::StepOutput { line, .. } if line.len() > 100_000
            )),
            "the rest of the stream was not drained"
        );
    }

    #[tokio::test]
    async fn matrix_values_reach_steps_and_explicit_env_wins() {
        let script = fake_docker();
        let work = work_dir("matrix-env");
        let workflow = parse(
            "jobs:\n  build:\n    strategy: { matrix: { node: [20, 22] } }\n    steps:\n      - run: echo hi\n",
        )
        .expect("parses");
        let (_lines, log) = logged();
        run(&settings_for(&script), &work, &workflow, log)
            .await
            .expect("runs");
        let exec_env = std::fs::read_to_string(script.parent().unwrap().join("exec-env.log"))
            .expect("exec env");
        assert!(exec_env.contains("MATRIX=20"), "{exec_env}");
        assert!(exec_env.contains("MATRIX=22"), "{exec_env}");

        let script = fake_docker();
        let work = work_dir("matrix-override");
        let workflow = parse(
            "jobs:\n  build:\n    strategy: { matrix: { node: [20] } }\n    steps:\n      - run: echo hi\n        env: { RYUZ_MATRIX_NODE: explicit }\n",
        )
        .expect("parses");
        let (_lines, log) = logged();
        run(&settings_for(&script), &work, &workflow, log)
            .await
            .expect("runs");
        let exec_env = std::fs::read_to_string(script.parent().unwrap().join("exec-env.log"))
            .expect("exec env");
        assert!(exec_env.contains("MATRIX=explicit"), "{exec_env}");
    }

    #[tokio::test]
    async fn artifact_install_replaces_a_symlinked_destination() {
        let script = fake_docker();
        let work = work_dir("artifact-symlink");
        let outside =
            std::env::temp_dir().join(format!("ryuz-workflow-outside-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&outside);
        std::fs::create_dir_all(&outside).expect("outside");
        std::os::unix::fs::symlink(&outside, work.join("dist")).expect("symlink");
        let workflow =
            parse("jobs:\n  build:\n    steps:\n      - run: echo hi\n").expect("parses");
        let (_events, sink) = collected();
        let outcome = run_with_events(&settings_for(&script), &work, &workflow, sink)
            .await
            .expect("runs");
        assert!(outcome.success());
        // The link itself is replaced; nothing is written through it.
        assert_eq!(outcome.artifact_path, Some(work.join("dist")));
        assert!(
            !outside.join("from-ci.txt").exists(),
            "wrote through symlink"
        );
        let target = std::fs::symlink_metadata(work.join("dist")).expect("installed");
        assert!(!target.file_type().is_symlink());
        assert!(work.join("dist/from-ci.txt").exists());
        let _ = std::fs::remove_dir_all(&outside);
    }
}
