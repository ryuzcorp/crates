//! GitHub-Actions-style CI workflows executed in containers.
//!
//! Three independent layers:
//!
//! - [`parse`] turns YAML into a strict, expanded [`Workflow`]. Unknown keys,
//!   oversize values, `${{ … }}` expressions and malformed shapes are rejected
//!   with their config path; nothing is silently ignored.
//! - [`run_with_events`] executes a [`Workflow`] with one container per job,
//!   up to a concurrency cap, streaming structured [`Event`]s.
//!   [`run`] is the same call formatted into plain log lines.
//! - [`Outcome`] reports one [`JobOutcome`] per expanded job, including
//!   failures, durations and artifacts.
//!
//! Integration belongs to the caller: it decides the file name, reads the
//! worktree, builds [`Settings`] and routes events wherever it wants them.
//!
//! # Config shape (GitHub Actions subset, v1)
//!
//! ```yaml
//! name: ci
//! on: [push]                 # accepted, ignored
//! env: { NODE_ENV: production }
//! jobs:
//!   build:
//!     runs-on: boat          # routing hint for the caller; not used locally
//!     image: oven/bun:1.4.4  # or `container:`; defaults to settings
//!     timeout-minutes: 30    # 1..=360, kills the container when it expires
//!     defaults: { run: { shell: bash } }
//!     strategy:
//!       matrix: { os: [linux, macos], node: [20, 22] }
//!       max-parallel: 2
//!       fail-fast: true       # default
//!     steps:
//!       - uses: checkout     # no-op: the worktree is already there
//!       - uses: cache        # no-op: the cache volume is always mounted
//!         with: { path: ~/.bun/install/cache, key: bun }
//!       - name: Install
//!         run: bun install --frozen-lockfile
//!         env: { CI: "1" }
//!         working-directory: .
//!         timeout-minutes: 10
//!       - uses: upload-artifact
//!         with: { path: reports/junit.xml, name: junit }
//! ```
//!
//! Accepted top-level keys: `name`, `on`, `env`, `jobs`. Accepted job keys:
//! `name`, `runs-on`, `image`, `container`, `env`, `defaults`, `timeout-minutes`,
//! `strategy`, `steps`. Accepted step keys: `name`, `run`, `env`,
//! `working-directory`, `timeout-minutes`, `shell`, `uses`, `with`. `needs` is
//! rejected: jobs run in file order, bounded by `max_parallel`.
//!
//! Matrix values are exposed to steps as `RYUZ_MATRIX_<KEY>` env vars (key
//! uppercased, `[^A-Z0-9_]` → `_`), unless an explicit `env` of that name
//! overrides them. `env` keys that configure the host container CLI or the
//! dynamic loader (`PATH`, `HOME`, `LD_*`, `DOCKER_*`, …) are rejected: those
//! names would leave the container with the CLI child's environment.
//!
//! # Container contract (per job)
//!
//! ```text
//! {cli} create --init --cap-drop ALL --cap-add CHOWN --security-opt no-new-privileges \
//!   --pids-limit 2048 --memory <m>m --memory-swap <m>m --cpus <c> --network <net> \
//!   --pull <policy> [--platform <p>] --label ryuz_workflow.pid=<pid> \
//!   --user 0 --name <name> -v <cache>:/ci-home -e <base key>... -e HOME=/ci-home \
//!   <image> sh -lc 'sleep infinity'
//! {cli} start <name>
//! {cli} cp <work>/. <name>:/work
//! {cli} exec -u 0 <name> chown -R <uid>:<gid> /work /ci-home
//! {cli} exec --user <uid>:<gid> -w /work/<wd> -e <key>... <name> <shell> <script>
//!   (per step; stdout/stderr streamed as Event::StepOutput)
//! {cli} cp <name>:/work/<path> <work>/.ryuz-workflow-stage-<n>/payload
//!   (then installed with openat/renameat, refusing symlinked components)
//! {cli} rm -f <name>                           # always, including on drop
//! ```
//!
//! All argv is built as vectors and passed to the container CLI directly: no
//! host shell ever interprets untrusted values. The script is the only shell
//! text, and it runs inside the container. Env values travel through the CLI
//! child's environment and are referenced as `-e KEY`, so they never appear in
//! `ps`; they are also masked in step output. [`Settings::docker_bin`] is a
//! plain path, so any Docker-compatible CLI (docker, podman, …) works.
//!
//! # Example
//!
//! ```no_run
//! use ryuz_workflow::{parse, run, Settings};
//!
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! let workflow = parse(include_str!("../tests/fixtures/ci.yaml"))?;
//! let settings = Settings {
//!     docker_bin: "docker".into(),
//!     default_image: "oven/bun:1.4.4".into(),
//!     allowed_images: vec!["oven/bun:1.4.4".into()],
//!     network: "bridge".into(),
//!     memory_mb: 1024,
//!     cpus: 2.0,
//!     uid: 1000,
//!     gid: 1000,
//!     cache_volume: Some("ci-cache".into()),
//!     env: Vec::new(),
//!     container_prefix: "ci".into(),
//!     artifact_dir: Some("dist".into()),
//!     platform: None,
//!     pull: ryuz_workflow::PullPolicy::Missing,
//!     max_parallel: 1,
//!     run_timeout: None,
//! };
//! let outcome = run(&settings, std::path::Path::new("."), &workflow, |line| {
//!     println!("{line}");
//! })
//! .await?;
//! println!("success: {}, artifact: {:?}", outcome.success(), outcome.artifact_path);
//! # Ok(())
//! # }
//! ```

mod error;
mod event;
mod outcome;
mod workflow;

#[cfg(feature = "runner")]
mod fs_util;
#[cfg(feature = "runner")]
mod run;

pub use error::Error;
pub use event::{format_event, Event, Stream};
pub use outcome::{Artifact, Failure, JobOutcome, JobStatus, Outcome, StepOutcome};
pub use workflow::{
    parse, Job, RunDefaults, Shell, Step, StepKind, Workflow, MAX_ARTIFACT_PATH_BYTES,
    MAX_CONFIG_BYTES, MAX_ENV_VALUE_BYTES, MAX_ENV_VARS, MAX_EXPANDED_JOBS, MAX_JOBS,
    MAX_JOB_TIMEOUT_MINUTES, MAX_MATRIX_KEYS, MAX_MATRIX_VALUES, MAX_NAME_BYTES, MAX_RUN_BYTES,
    MAX_STEPS_PER_JOB, MAX_TIMEOUT_MINUTES, MAX_WORKING_DIR_BYTES,
};

#[cfg(feature = "runner")]
pub use run::{run, run_with_events, PullPolicy, Settings, CACHE_DIR, DEFAULT_STEP_TIMEOUT};
