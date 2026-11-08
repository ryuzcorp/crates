//! The workflow model and its strict, GitHub-Actions-compatible parser.
//!
//! `parse` accepts a deliberately small GitHub Actions subset. Anything the
//! runner cannot honour is a config error, not a warning: a workflow that
//! silently ignores a key would report success for work it never did.
//!
//! Accepted surface:
//!
//! - top level: `name`, `on` (any shape, ignored), `env`, `jobs`;
//! - job: `name`, `runs-on`, `image`/`container`, `env`, `timeout-minutes`,
//!   `defaults.run`, `strategy` (`matrix`, `max-parallel`, `fail-fast`),
//!   `steps`;
//! - step: `name`, `run`, `env`, `working-directory`, `timeout-minutes`,
//!   `shell` (`bash`/`sh`), `uses` (`checkout`, `cache`, `upload-artifact`,
//!   with an optional `@ref`), `with`.
//!
//! `matrix` is expanded at parse time: one [`Job`] per combination, with the
//! declared order preserved and the display name carrying the values
//! (`build (linux, 20)`). `runs-on` is kept as a routing hint for callers that
//! dispatch to other runners; the container runner uses `image`/`container`.
//! `${{ … }}` expressions are rejected: the crate does not evaluate them.

use std::collections::BTreeMap;

use serde_yaml_ng::Value;

use crate::error::Error;

/// A config larger than this is refused unread.
pub const MAX_CONFIG_BYTES: usize = 64 * 1024;

/// Most jobs a workflow may declare (before `matrix` expansion).
pub const MAX_JOBS: usize = 32;

/// Most jobs after `matrix` expansion.
pub const MAX_EXPANDED_JOBS: usize = 256;

/// Most `matrix` keys one job may carry.
pub const MAX_MATRIX_KEYS: usize = 16;

/// Most values one `matrix` key may carry.
pub const MAX_MATRIX_VALUES: usize = 256;

/// Most steps one job may carry.
pub const MAX_STEPS_PER_JOB: usize = 32;

/// Longest single `run` script.
pub const MAX_RUN_BYTES: usize = 32 * 1024;

/// Longest step `name`.
pub const MAX_NAME_BYTES: usize = 512;

/// Longest `working-directory`.
pub const MAX_WORKING_DIR_BYTES: usize = 1024;

/// Longest artifact `path`.
pub const MAX_ARTIFACT_PATH_BYTES: usize = 1024;

/// Most `env` entries one mapping may carry.
pub const MAX_ENV_VARS: usize = 256;

/// Longest single `env` value.
pub const MAX_ENV_VALUE_BYTES: usize = 64 * 1024;

/// Longest per-step `timeout-minutes`.
pub const MAX_TIMEOUT_MINUTES: u64 = 120;

/// Longest per-job `timeout-minutes` (GitHub and remote runners cap at 6 h).
pub const MAX_JOB_TIMEOUT_MINUTES: u64 = 360;

/// A parsed workflow: jobs in file order, matrix members expanded in place.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Workflow {
    pub name: Option<String>,
    /// Workflow-level env; jobs and steps override it in that order.
    pub env: BTreeMap<String, String>,
    pub jobs: Vec<Job>,
}

/// One named job: one container, steps share `/work` in order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Job {
    /// Display name; matrix members carry their values in parentheses.
    pub name: String,
    /// Declared name, before expansion.
    pub base_name: String,
    /// Matrix values for this member, empty without a matrix.
    pub matrix: BTreeMap<String, String>,
    /// Routing hint from `runs-on`; the container runner does not use it.
    pub runs_on: Option<String>,
    pub image: Option<String>,
    pub env: BTreeMap<String, String>,
    pub defaults: RunDefaults,
    pub timeout_minutes: Option<u64>,
    /// `strategy.max-parallel` for this job's matrix members.
    pub max_parallel: Option<u32>,
    /// `strategy.fail-fast`; `true` when unset, as in GitHub Actions.
    pub fail_fast: bool,
    pub steps: Vec<Step>,
}

/// `defaults.run`: values a step inherits when it does not set its own.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RunDefaults {
    pub shell: Option<Shell>,
    pub working_directory: Option<String>,
}

/// The shell a `run` step executes in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Shell {
    /// `sh -lc <script>` (POSIX; works in distroless-busybox images).
    Sh,
    /// `bash -e -o pipefail -l -c <script>`, GitHub's Linux default semantics.
    Bash,
}

impl Shell {
    #[cfg(feature = "runner")]
    pub(crate) fn argv(self, script: &str) -> Vec<String> {
        match self {
            Shell::Sh => vec!["sh".into(), "-lc".into(), script.into()],
            Shell::Bash => vec![
                "bash".into(),
                "-e".into(),
                "-o".into(),
                "pipefail".into(),
                "-l".into(),
                "-c".into(),
                script.into(),
            ],
        }
    }
}

/// One step.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Step {
    pub name: Option<String>,
    pub env: BTreeMap<String, String>,
    pub working_directory: Option<String>,
    pub timeout_minutes: Option<u64>,
    pub kind: StepKind,
}

/// What a step does.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StepKind {
    Run {
        script: String,
        shell: Option<Shell>,
    },
    /// `uses: checkout` / `actions/checkout@…`: the worktree is already
    /// checked out, so this only logs a note.
    Checkout,
    /// `uses: cache` / `actions/cache@…`: the cache volume is always mounted,
    /// so this only logs a note.
    Cache,
    /// `uses: upload-artifact` / `actions/upload-artifact@…`: copy `path` out
    /// of the container into the worktree.
    UploadArtifact { path: String, name: Option<String> },
}

impl StepKind {
    /// The script for `run` steps.
    pub fn script(&self) -> Option<&str> {
        match self {
            StepKind::Run { script, .. } => Some(script),
            _ => None,
        }
    }
}

/// Parse workflow contents. `on` is accepted and ignored; `jobs` is required
/// and keeps file order. Unknown keys are rejected with their path.
pub fn parse(contents: &str) -> Result<Workflow, Error> {
    if contents.len() > MAX_CONFIG_BYTES {
        return Err(Error::TooLarge {
            bytes: contents.len(),
            max: MAX_CONFIG_BYTES,
        });
    }
    let value: Value = serde_yaml_ng::from_str(contents)
        .map_err(|e| Error::Config(format!("invalid YAML: {e}")))?;
    let top = as_mapping(&value, "config")?;
    let mut name: Option<String> = None;
    let mut env = BTreeMap::new();
    let mut jobs_value: Option<&Value> = None;
    for (key, v) in top {
        let k = as_str(key, "config key")?;
        match k {
            "on" => {}
            "name" => {
                let s = as_str(v, "config.name")?;
                if s.len() > MAX_NAME_BYTES {
                    return Err(Error::Config(format!(
                        "config.name is longer than the {MAX_NAME_BYTES}-byte cap"
                    )));
                }
                name = Some(s.to_string());
            }
            "env" => env = parse_env(v, "config.env")?,
            "jobs" => jobs_value = Some(v),
            other => {
                return Err(Error::Config(format!(
                    "unknown key `{other}` (expected `name`, `on`, `env`, `jobs`)"
                )));
            }
        }
    }
    let Some(jobs_value) = jobs_value else {
        return Err(Error::Config("missing required `jobs` mapping".to_string()));
    };
    let jobs_map = as_mapping(jobs_value, "`jobs`")?;
    if jobs_map.is_empty() {
        return Err(Error::Config("`jobs` defines no jobs".to_string()));
    }
    if jobs_map.len() > MAX_JOBS {
        return Err(Error::Config(format!(
            "`jobs` defines {} jobs, more than the {MAX_JOBS}-job cap",
            jobs_map.len()
        )));
    }
    let mut jobs = Vec::new();
    for (key, value) in jobs_map {
        let base = as_str(key, "`jobs` key")?;
        if base.trim().is_empty() {
            return Err(Error::Config("a job name is empty".to_string()));
        }
        jobs.extend(parse_job(base, value)?);
        if jobs.len() > MAX_EXPANDED_JOBS {
            return Err(Error::Config(format!(
                "`jobs` expands to more than the {MAX_EXPANDED_JOBS}-job cap"
            )));
        }
    }
    Ok(Workflow { name, env, jobs })
}

fn parse_env(value: &Value, ctx: &str) -> Result<BTreeMap<String, String>, Error> {
    let map = as_mapping(value, ctx)?;
    if map.len() > MAX_ENV_VARS {
        return Err(Error::Config(format!(
            "{ctx} defines more than the {MAX_ENV_VARS}-variable cap"
        )));
    }
    let mut env = BTreeMap::new();
    for (ek, ev) in map {
        let key = as_str(ek, &format!("{ctx} key"))?;
        check_env_key(ctx, key)?;
        let val = as_env_value(ev, &format!("{ctx}.{key}"))?;
        check_no_expression(&val, &format!("{ctx}.{key}"))?;
        env.insert(key.to_string(), val);
    }
    Ok(env)
}

fn parse_job(base: &str, value: &Value) -> Result<Vec<Job>, Error> {
    let ctx = format!("jobs.{base}");
    let map = as_mapping(value, &ctx)?;
    let mut display = base.to_string();
    let mut runs_on: Option<String> = None;
    let mut image: Option<String> = None;
    let mut container: Option<String> = None;
    let mut env = BTreeMap::new();
    let mut defaults = RunDefaults::default();
    let mut timeout_minutes: Option<u64> = None;
    let mut max_parallel: Option<u32> = None;
    let mut fail_fast = true;
    let mut matrix: Vec<(String, Vec<String>)> = Vec::new();
    let mut steps_value: Option<&Value> = None;
    for (key, v) in map {
        let k = as_str(key, &ctx)?;
        match k {
            "name" => {
                let s = as_str(v, &format!("{ctx}.name"))?;
                if s.len() > MAX_NAME_BYTES {
                    return Err(Error::Config(format!(
                        "{ctx}.name is longer than the {MAX_NAME_BYTES}-byte cap"
                    )));
                }
                display = s.to_string();
            }
            "runs-on" => {
                let s = as_str(v, &format!("{ctx}.runs-on"))?;
                if s.trim().is_empty() {
                    return Err(Error::Config(format!("{ctx}.runs-on is empty")));
                }
                runs_on = Some(s.to_string());
            }
            "image" => {
                let s = as_str(v, &format!("{ctx}.image"))?;
                if s.trim().is_empty() {
                    return Err(Error::Config(format!("{ctx}.image is empty")));
                }
                image = Some(s.to_string());
            }
            "container" => {
                let s = as_str(v, &format!("{ctx}.container"))?;
                if s.trim().is_empty() {
                    return Err(Error::Config(format!("{ctx}.container is empty")));
                }
                container = Some(s.to_string());
            }
            "env" => env = parse_env(v, &format!("{ctx}.env"))?,
            "defaults" => defaults = parse_defaults(v, &format!("{ctx}.defaults"))?,
            "timeout-minutes" => {
                timeout_minutes = Some(parse_minutes(
                    v,
                    &format!("{ctx}.timeout-minutes"),
                    MAX_JOB_TIMEOUT_MINUTES,
                )?)
            }
            "strategy" => {
                let (m, p, f) = parse_strategy(v, &format!("{ctx}.strategy"))?;
                matrix = m;
                max_parallel = p;
                fail_fast = f;
            }
            "steps" => steps_value = Some(v),
            "needs" => {
                return Err(Error::Config(format!(
                    "{ctx}: `needs` is unsupported; jobs run in file order, bounded by max_parallel"
                )));
            }
            other => {
                return Err(Error::Config(format!(
                    "{ctx}: unknown key `{other}` (expected `name`, `runs-on`, `image`, `container`, `env`, `defaults`, `timeout-minutes`, `strategy`, `steps`)"
                )));
            }
        }
    }
    if image.is_some() && container.is_some() {
        return Err(Error::Config(format!(
            "{ctx}: set either `image` or `container`, not both"
        )));
    }
    let image = image.or(container);
    let Some(steps_value) = steps_value else {
        return Err(Error::Config(format!("{ctx}: missing required `steps`")));
    };
    let steps_seq = as_sequence(steps_value, &format!("{ctx}.steps"))?;
    if steps_seq.is_empty() {
        return Err(Error::Config(format!("{ctx}.steps defines no steps")));
    }
    if steps_seq.len() > MAX_STEPS_PER_JOB {
        return Err(Error::Config(format!(
            "{ctx}.steps defines {} steps, more than the {MAX_STEPS_PER_JOB}-step cap",
            steps_seq.len()
        )));
    }
    let mut steps = Vec::with_capacity(steps_seq.len());
    for (i, step) in steps_seq.iter().enumerate() {
        steps.push(parse_step(base, i, step)?);
    }
    expand(
        base,
        display,
        runs_on,
        image,
        env,
        defaults,
        timeout_minutes,
        max_parallel,
        fail_fast,
        matrix,
        steps,
    )
}

#[allow(clippy::too_many_arguments)]
fn expand(
    base: &str,
    display: String,
    runs_on: Option<String>,
    image: Option<String>,
    env: BTreeMap<String, String>,
    defaults: RunDefaults,
    timeout_minutes: Option<u64>,
    max_parallel: Option<u32>,
    fail_fast: bool,
    matrix: Vec<(String, Vec<String>)>,
    steps: Vec<Step>,
) -> Result<Vec<Job>, Error> {
    // GitHub's order: the last declared key varies fastest.
    let mut members: Vec<BTreeMap<String, String>> = vec![BTreeMap::new()];
    for (key, values) in &matrix {
        let mut next = Vec::with_capacity(members.len() * values.len());
        for member in &members {
            for value in values {
                let mut expanded = member.clone();
                expanded.insert(key.clone(), value.clone());
                next.push(expanded);
            }
        }
        members = next;
    }
    if members.len() > MAX_EXPANDED_JOBS {
        return Err(Error::Config(format!(
            "jobs.{base}: matrix expands to {} jobs, more than the {MAX_EXPANDED_JOBS}-job cap",
            members.len()
        )));
    }
    let mut jobs = Vec::with_capacity(members.len());
    for member in members {
        let name = if member.is_empty() {
            display.clone()
        } else {
            format!(
                "{display} ({})",
                matrix
                    .iter()
                    .map(|(key, _)| member[key].clone())
                    .collect::<Vec<_>>()
                    .join(", ")
            )
        };
        jobs.push(Job {
            name,
            base_name: base.to_string(),
            matrix: member,
            runs_on: runs_on.clone(),
            image: image.clone(),
            env: env.clone(),
            defaults: defaults.clone(),
            timeout_minutes,
            max_parallel,
            fail_fast,
            steps: steps.clone(),
        });
    }
    Ok(jobs)
}

fn parse_defaults(value: &Value, ctx: &str) -> Result<RunDefaults, Error> {
    let map = as_mapping(value, ctx)?;
    let mut defaults = RunDefaults::default();
    for (key, v) in map {
        let k = as_str(key, ctx)?;
        if k != "run" {
            return Err(Error::Config(format!(
                "{ctx}: unknown key `{k}` (expected `run`)"
            )));
        }
        let run = as_mapping(v, &format!("{ctx}.run"))?;
        for (rk, rv) in run {
            let r = as_str(rk, &format!("{ctx}.run key"))?;
            match r {
                "shell" => {
                    let s = as_str(rv, &format!("{ctx}.run.shell"))?;
                    defaults.shell = Some(parse_shell(s, &format!("{ctx}.run.shell"))?);
                }
                "working-directory" => {
                    let s = as_str(rv, &format!("{ctx}.run.working-directory"))?;
                    defaults.working_directory =
                        check_relative_dir(&format!("{ctx}.run.working-directory"), s)?;
                }
                other => {
                    return Err(Error::Config(format!(
                        "{ctx}.run: unknown key `{other}` (expected `shell`, `working-directory`)"
                    )));
                }
            }
        }
    }
    Ok(defaults)
}

type Strategy = (Vec<(String, Vec<String>)>, Option<u32>, bool);

fn parse_strategy(value: &Value, ctx: &str) -> Result<Strategy, Error> {
    let map = as_mapping(value, ctx)?;
    let mut matrix = Vec::new();
    let mut max_parallel: Option<u32> = None;
    let mut fail_fast = true;
    for (key, v) in map {
        let k = as_str(key, ctx)?;
        match k {
            "matrix" => matrix = parse_matrix(v, &format!("{ctx}.matrix"))?,
            "max-parallel" => {
                let n = as_u64(v, &format!("{ctx}.max-parallel"))?;
                if !(1..=MAX_EXPANDED_JOBS as u64).contains(&n) {
                    return Err(Error::Config(format!(
                        "{ctx}.max-parallel must be 1..={MAX_EXPANDED_JOBS}"
                    )));
                }
                max_parallel = Some(n as u32);
            }
            "fail-fast" => {
                let Value::Bool(b) = v else {
                    return Err(Error::Config(format!("{ctx}.fail-fast must be a bool")));
                };
                fail_fast = *b;
            }
            other => {
                return Err(Error::Config(format!(
                    "{ctx}: unknown key `{other}` (expected `matrix`, `max-parallel`, `fail-fast`)"
                )));
            }
        }
    }
    Ok((matrix, max_parallel, fail_fast))
}

fn parse_matrix(value: &Value, ctx: &str) -> Result<Vec<(String, Vec<String>)>, Error> {
    let map = as_mapping(value, ctx)?;
    if map.is_empty() {
        return Err(Error::Config(format!("{ctx} is empty")));
    }
    if map.len() > MAX_MATRIX_KEYS {
        return Err(Error::Config(format!(
            "{ctx} defines more than the {MAX_MATRIX_KEYS}-key cap"
        )));
    }
    let mut matrix = Vec::with_capacity(map.len());
    for (key, v) in map {
        let k = as_str(key, &format!("{ctx} key"))?;
        if k == "include" || k == "exclude" {
            return Err(Error::Config(format!(
                "{ctx}.{k} is unsupported; list the values to run instead"
            )));
        }
        check_matrix_key(k, ctx)?;
        let values = as_sequence(v, &format!("{ctx}.{k}"))?;
        if values.is_empty() {
            return Err(Error::Config(format!("{ctx}.{k} lists no values")));
        }
        if values.len() > MAX_MATRIX_VALUES {
            return Err(Error::Config(format!(
                "{ctx}.{k} lists more than the {MAX_MATRIX_VALUES}-value cap"
            )));
        }
        let mut out = Vec::with_capacity(values.len());
        for item in values {
            out.push(as_scalar(item, &format!("{ctx}.{k}"))?);
        }
        matrix.push((k.to_string(), out));
    }
    Ok(matrix)
}

fn check_matrix_key(key: &str, ctx: &str) -> Result<(), Error> {
    let mut chars = key.chars();
    let first_ok = chars
        .next()
        .is_some_and(|c| c.is_ascii_alphabetic() || c == '_');
    let rest_ok = chars.all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-');
    if !first_ok || !rest_ok {
        return Err(Error::Config(format!(
            "{ctx}: matrix key `{key}` must match [A-Za-z_][A-Za-z0-9_-]*"
        )));
    }
    Ok(())
}

fn parse_step(base: &str, index: usize, value: &Value) -> Result<Step, Error> {
    let ctx = format!("jobs.{base}.steps[{index}]");
    let map = as_mapping(value, &ctx)?;
    let mut name: Option<String> = None;
    let mut run: Option<String> = None;
    let mut uses: Option<String> = None;
    let mut with: Option<BTreeMap<String, String>> = None;
    let mut env = BTreeMap::new();
    let mut working_directory: Option<String> = None;
    let mut timeout_minutes: Option<u64> = None;
    let mut shell: Option<Shell> = None;
    for (key, v) in map {
        let k = as_str(key, &ctx)?;
        match k {
            "name" => {
                let s = as_str(v, &format!("{ctx}.name"))?;
                if s.len() > MAX_NAME_BYTES {
                    return Err(Error::Config(format!(
                        "{ctx}.name is longer than the {MAX_NAME_BYTES}-byte cap"
                    )));
                }
                name = Some(s.to_string());
            }
            "run" => {
                let s = as_str(v, &format!("{ctx}.run"))?;
                if s.len() > MAX_RUN_BYTES {
                    return Err(Error::Config(format!(
                        "{ctx}.run is longer than the {MAX_RUN_BYTES}-byte cap"
                    )));
                }
                check_no_expression(s, &format!("{ctx}.run"))?;
                run = Some(s.to_string());
            }
            "uses" => {
                let s = as_str(v, &format!("{ctx}.uses"))?;
                if s.trim().is_empty() {
                    return Err(Error::Config(format!("{ctx}.uses is empty")));
                }
                uses = Some(s.to_string());
            }
            "with" => {
                let mut out = BTreeMap::new();
                for (wk, wv) in as_mapping(v, &format!("{ctx}.with"))? {
                    let wk = as_str(wk, &format!("{ctx}.with key"))?;
                    out.insert(
                        wk.to_string(),
                        as_env_value(wv, &format!("{ctx}.with.{wk}"))?,
                    );
                }
                with = Some(out);
            }
            "env" => env = parse_env(v, &format!("{ctx}.env"))?,
            "working-directory" => {
                let s = as_str(v, &format!("{ctx}.working-directory"))?;
                working_directory = check_relative_dir(&ctx, s)?;
            }
            "timeout-minutes" => {
                timeout_minutes = Some(parse_minutes(
                    v,
                    &format!("{ctx}.timeout-minutes"),
                    MAX_TIMEOUT_MINUTES,
                )?)
            }
            "shell" => {
                let s = as_str(v, &format!("{ctx}.shell"))?;
                shell = Some(parse_shell(s, &format!("{ctx}.shell"))?);
            }
            other => {
                return Err(Error::Config(format!(
                    "{ctx}: unknown key `{other}` (expected `name`, `run`, `env`, `working-directory`, `timeout-minutes`, `shell`, `uses`, `with`)"
                )));
            }
        }
    }
    let kind = match (run, uses) {
        (Some(_), Some(_)) => {
            return Err(Error::Config(format!(
                "{ctx}: a step takes either `run` or `uses`, not both"
            )));
        }
        (Some(script), None) => {
            if with.is_some() {
                return Err(Error::Config(format!(
                    "{ctx}: `with` is only valid on `uses` steps"
                )));
            }
            if script.trim().is_empty() {
                return Err(Error::Config(format!("{ctx}: `run` is empty")));
            }
            StepKind::Run { script, shell }
        }
        (None, Some(uses)) => {
            if !env.is_empty() {
                return Err(Error::Config(format!(
                    "{ctx}: `env` is only valid on `run` steps"
                )));
            }
            if timeout_minutes.is_some() {
                return Err(Error::Config(format!(
                    "{ctx}: `timeout-minutes` is only valid on `run` steps"
                )));
            }
            if shell.is_some() {
                return Err(Error::Config(format!(
                    "{ctx}: `shell` is only valid on `run` steps"
                )));
            }
            if working_directory.is_some() {
                return Err(Error::Config(format!(
                    "{ctx}: `working-directory` is only valid on `run` steps"
                )));
            }
            parse_uses(&ctx, &uses, with)?
        }
        (None, None) => {
            return Err(Error::Config(format!(
                "{ctx}: missing required `run` or `uses`"
            )));
        }
    };
    Ok(Step {
        name,
        env,
        working_directory,
        timeout_minutes,
        kind,
    })
}

const CHECKOUT_ACTIONS: [&str; 2] = ["checkout", "actions/checkout"];
const CACHE_ACTIONS: [&str; 2] = ["cache", "actions/cache"];
const UPLOAD_ACTIONS: [&str; 2] = ["upload-artifact", "actions/upload-artifact"];

fn parse_uses(
    ctx: &str,
    uses: &str,
    with: Option<BTreeMap<String, String>>,
) -> Result<StepKind, Error> {
    let action = uses.split('@').next().unwrap_or(uses).trim();
    let with = with.unwrap_or_default();
    if CHECKOUT_ACTIONS.contains(&action) {
        // Checkout inputs (fetch-depth, ref, …) are inert: the caller already
        // checked the worktree out, which is what makes `uses: checkout` a
        // no-op rather than unimplemented.
        return Ok(StepKind::Checkout);
    }
    if CACHE_ACTIONS.contains(&action) {
        for key in with.keys() {
            if key != "path" && key != "key" {
                return Err(Error::Config(format!(
                    "{ctx}: `{action}` input `{key}` is unsupported (the cache volume is always mounted)"
                )));
            }
        }
        return Ok(StepKind::Cache);
    }
    if UPLOAD_ACTIONS.contains(&action) {
        for key in with.keys() {
            if key != "path" && key != "name" {
                return Err(Error::Config(format!(
                    "{ctx}: `{action}` input `{key}` is unsupported (expected `path`, `name`)"
                )));
            }
        }
        let Some(path) = with.get("path") else {
            return Err(Error::Config(format!(
                "{ctx}: `{action}` requires a `with.path`"
            )));
        };
        let path = check_artifact_path(&format!("{ctx}.with.path"), path)?;
        return Ok(StepKind::UploadArtifact {
            path,
            name: with.get("name").cloned(),
        });
    }
    Err(Error::Config(format!(
        "{ctx}: unsupported action `{uses}` (supported: `checkout`, `cache`, `upload-artifact`, with or without an `@ref`)"
    )))
}

fn parse_shell(raw: &str, ctx: &str) -> Result<Shell, Error> {
    match raw.trim() {
        "bash" => Ok(Shell::Bash),
        "sh" => Ok(Shell::Sh),
        other => Err(Error::Config(format!(
            "{ctx}: unsupported shell `{other}` (expected `bash`, `sh`)"
        ))),
    }
}

fn parse_minutes(value: &Value, ctx: &str, max: u64) -> Result<u64, Error> {
    let err = || Error::Config(format!("{ctx} must be 1..={max}"));
    let Value::Number(n) = value else {
        return Err(err());
    };
    let Some(m) = n.as_u64() else {
        return Err(err());
    };
    if !(1..=max).contains(&m) {
        return Err(err());
    }
    Ok(m)
}

fn as_u64(value: &Value, ctx: &str) -> Result<u64, Error> {
    let Value::Number(n) = value else {
        return Err(Error::Config(format!("{ctx} must be an integer")));
    };
    n.as_u64()
        .ok_or_else(|| Error::Config(format!("{ctx} must be a positive integer")))
}

pub(crate) fn check_env_key(ctx: &str, key: &str) -> Result<(), Error> {
    let mut chars = key.chars();
    let first_ok = chars
        .next()
        .is_some_and(|c| c.is_ascii_alphabetic() || c == '_');
    let rest_ok = chars.all(|c| c.is_ascii_alphanumeric() || c == '_');
    if !first_ok || !rest_ok {
        return Err(Error::Config(format!(
            "{ctx}: env key `{key}` must match [A-Za-z_][A-Za-z0-9_]*"
        )));
    }
    Ok(())
}

fn as_env_value(value: &Value, ctx: &str) -> Result<String, Error> {
    let s = as_scalar(value, ctx)?;
    if s.len() > MAX_ENV_VALUE_BYTES {
        return Err(Error::Config(format!(
            "{ctx} is longer than the {MAX_ENV_VALUE_BYTES}-byte cap"
        )));
    }
    Ok(s)
}

/// A YAML scalar as its literal text: strings as written, numbers/booleans as
/// their YAML spelling.
fn as_scalar(value: &Value, ctx: &str) -> Result<String, Error> {
    let s = match value {
        Value::String(s) => s.clone(),
        Value::Number(n) => n.to_string(),
        Value::Bool(b) => b.to_string(),
        Value::Null => {
            return Err(Error::Config(format!("{ctx} has no value")));
        }
        _ => {
            return Err(Error::Config(format!(
                "{ctx} must be a scalar (quote it if it looks like a number or boolean)"
            )));
        }
    };
    if s.contains('\0') {
        return Err(Error::Config(format!("{ctx} contains NUL")));
    }
    Ok(s)
}

/// `${{ … }}` is GitHub expression syntax; the crate does not evaluate it, and
/// passing it through would run a literal `${{` string.
fn check_no_expression(text: &str, ctx: &str) -> Result<(), Error> {
    if text.contains("${{") {
        return Err(Error::Config(format!(
            "{ctx}: `${{{{ … }}}}` expressions are unsupported; pass the value in through `env`"
        )));
    }
    Ok(())
}

/// Normalize `working-directory`: `.`/empty means `/work` (`None`); anything
/// else must stay inside `/work` (relative, no `..`).
fn check_relative_dir(ctx: &str, raw: &str) -> Result<Option<String>, Error> {
    let err = |why: &str| Error::Config(format!("{ctx} {why}"));
    let trimmed = raw.trim();
    if trimmed.is_empty() || trimmed == "." {
        return Ok(None);
    }
    if trimmed.len() > MAX_WORKING_DIR_BYTES {
        return Err(err("is longer than the 1024-byte cap"));
    }
    if trimmed.contains('\0') {
        return Err(err("contains NUL"));
    }
    check_no_expression(trimmed, ctx)?;
    if trimmed.starts_with('/') {
        return Err(err(format!(
            "`{raw}` is absolute; it must be relative to /work"
        )
        .as_str()));
    }
    let mut parts = Vec::new();
    for part in trimmed.split('/') {
        if part.is_empty() || part == "." {
            continue;
        }
        if part == ".." {
            return Err(err(format!("`{raw}` escapes /work").as_str()));
        }
        parts.push(part);
    }
    if parts.is_empty() {
        return Ok(None);
    }
    Ok(Some(parts.join("/")))
}

/// An artifact path must name something under `/work`, and may be nested.
fn check_artifact_path(ctx: &str, raw: &str) -> Result<String, Error> {
    let err = |why: &str| Error::Config(format!("{ctx} {why}"));
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err(err("is empty"));
    }
    if trimmed.len() > MAX_ARTIFACT_PATH_BYTES {
        return Err(err("is longer than the 1024-byte cap"));
    }
    if trimmed.contains('\0') {
        return Err(err("contains NUL"));
    }
    check_no_expression(trimmed, ctx)?;
    if trimmed.starts_with('/') {
        return Err(err("must be relative to /work"));
    }
    let mut parts = Vec::new();
    for part in trimmed.split('/') {
        if part.is_empty() || part == "." {
            continue;
        }
        if part == ".." {
            return Err(err("escapes /work"));
        }
        parts.push(part);
    }
    if parts.is_empty() {
        return Err(err("is empty"));
    }
    Ok(parts.join("/"))
}

fn as_mapping<'a>(value: &'a Value, ctx: &str) -> Result<&'a serde_yaml_ng::Mapping, Error> {
    match value {
        Value::Mapping(m) => Ok(m),
        Value::Null => Err(Error::Config(format!("{ctx} is empty"))),
        _ => Err(Error::Config(format!("{ctx} must be a mapping"))),
    }
}

fn as_sequence<'a>(value: &'a Value, ctx: &str) -> Result<&'a Vec<Value>, Error> {
    match value {
        Value::Sequence(s) => Ok(s),
        _ => Err(Error::Config(format!("{ctx} must be a list"))),
    }
}

fn as_str<'a>(value: &'a Value, ctx: &str) -> Result<&'a str, Error> {
    match value {
        Value::String(s) => Ok(s),
        _ => Err(Error::Config(format!("{ctx} must be a string"))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn valid_two_step_job() {
        let workflow = parse(
            "on: [push]\n\
             jobs:\n\
             \x20 build:\n\
             \x20\x20 image: oven/bun:1.4.4\n\
             \x20\x20 steps:\n\
             \x20\x20\x20 - name: Install\n\
             \x20\x20\x20\x20\x20 run: bun install --frozen-lockfile\n\
             \x20\x20\x20 - name: Build\n\
             \x20\x20\x20\x20\x20 run: bun run build\n\
             \x20\x20\x20\x20\x20 env: { NODE_ENV: production }\n\
             \x20\x20\x20\x20\x20 working-directory: .\n\
             \x20\x20\x20\x20\x20 timeout-minutes: 10\n",
        )
        .expect("parses");
        assert_eq!(workflow.jobs.len(), 1);
        let job = &workflow.jobs[0];
        assert_eq!(job.name, "build");
        assert_eq!(job.base_name, "build");
        assert_eq!(job.image.as_deref(), Some("oven/bun:1.4.4"));
        assert_eq!(job.steps.len(), 2);
        assert_eq!(job.steps[0].name.as_deref(), Some("Install"));
        assert_eq!(
            job.steps[0].kind,
            StepKind::Run {
                script: "bun install --frozen-lockfile".to_string(),
                shell: None,
            }
        );
        let build = &job.steps[1];
        assert_eq!(
            build.env.get("NODE_ENV").map(String::as_str),
            Some("production")
        );
        assert_eq!(build.working_directory, None);
        assert_eq!(build.timeout_minutes, Some(10));
    }

    #[test]
    fn jobs_keep_file_order() {
        let workflow = parse(
            "jobs:\n\
             \x20 zebra:\n\
             \x20\x20\x20 steps:\n\
             \x20\x20\x20\x20 - run: echo z\n\
             \x20 alpha:\n\
             \x20\x20\x20 steps:\n\
             \x20\x20\x20\x20 - run: echo a\n\
             \x20 mango:\n\
             \x20\x20\x20 steps:\n\
             \x20\x20\x20\x20 - run: echo m\n",
        )
        .expect("parses");
        let names: Vec<&str> = workflow.jobs.iter().map(|j| j.name.as_str()).collect();
        assert_eq!(names, vec!["zebra", "alpha", "mango"]);
    }

    #[test]
    fn workflow_name_env_and_job_defaults() {
        let workflow = parse(
            "name: ci\n\
             env: { CI: '1', PORT: 8080 }\n\
             jobs:\n\
             \x20 build:\n\
             \x20\x20 name: Build\n\
             \x20\x20 runs-on: boat\n\
             \x20\x20 env: { NODE_ENV: production }\n\
             \x20\x20 timeout-minutes: 30\n\
             \x20\x20 defaults: { run: { shell: bash, working-directory: app } }\n\
             \x20\x20 steps:\n\
             \x20\x20\x20 - run: echo hi\n",
        )
        .expect("parses");
        assert_eq!(workflow.name.as_deref(), Some("ci"));
        assert_eq!(workflow.env.get("CI").map(String::as_str), Some("1"));
        assert_eq!(workflow.env.get("PORT").map(String::as_str), Some("8080"));
        let job = &workflow.jobs[0];
        assert_eq!(job.name, "Build");
        assert_eq!(job.runs_on.as_deref(), Some("boat"));
        assert_eq!(job.timeout_minutes, Some(30));
        assert_eq!(job.defaults.shell, Some(Shell::Bash));
        assert_eq!(job.defaults.working_directory.as_deref(), Some("app"));
        assert_eq!(
            job.env.get("NODE_ENV").map(String::as_str),
            Some("production")
        );
    }

    #[test]
    fn container_is_an_image_alias() {
        let workflow =
            parse("jobs:\n  build:\n    container: node:22\n    steps:\n      - run: echo hi\n")
                .expect("parses");
        assert_eq!(workflow.jobs[0].image.as_deref(), Some("node:22"));

        let err = parse(
            "jobs:\n  build:\n    image: node:22\n    container: node:24\n    steps:\n      - run: echo hi\n",
        )
        .expect_err("both");
        assert!(
            err.to_string().contains("either `image` or `container`"),
            "{err}"
        );
    }

    #[test]
    fn env_values_coerce_scalars() {
        let workflow = parse(
            "jobs:\n  build:\n    steps:\n      - run: echo hi\n        env:\n          PORT: 8080\n          DEBUG: true\n          RATIO: 1.5\n",
        )
        .expect("parses");
        let env = &workflow.jobs[0].steps[0].env;
        assert_eq!(env.get("PORT").map(String::as_str), Some("8080"));
        assert_eq!(env.get("DEBUG").map(String::as_str), Some("true"));
        assert_eq!(env.get("RATIO").map(String::as_str), Some("1.5"));
    }

    #[test]
    fn working_directory_forms() {
        let workflow = parse(
            "jobs:\n  build:\n    steps:\n      - run: echo a\n        working-directory: packages/app\n      - run: echo b\n        working-directory: ./nested//dir/\n",
        )
        .expect("parses");
        assert_eq!(
            workflow.jobs[0].steps[0].working_directory.as_deref(),
            Some("packages/app")
        );
        assert_eq!(
            workflow.jobs[0].steps[1].working_directory.as_deref(),
            Some("nested/dir")
        );
    }

    #[test]
    fn shells_are_bash_or_sh() {
        let workflow = parse(
            "jobs:\n  build:\n    steps:\n      - run: echo a\n        shell: bash\n      - run: echo b\n        shell: sh\n",
        )
        .expect("parses");
        assert_eq!(
            workflow.jobs[0].steps[0].kind,
            StepKind::Run {
                script: "echo a".to_string(),
                shell: Some(Shell::Bash),
            }
        );
        assert_eq!(
            workflow.jobs[0].steps[1].kind,
            StepKind::Run {
                script: "echo b".to_string(),
                shell: Some(Shell::Sh),
            }
        );
        let err = parse("jobs:\n  build:\n    steps:\n      - run: x\n        shell: pwsh\n")
            .expect_err("pwsh");
        assert!(
            err.to_string().contains("unsupported shell `pwsh`"),
            "{err}"
        );
    }

    #[test]
    fn rejects_unknown_keys_with_paths() {
        let err = parse(
            "concurrency: 1\njobs:\n\x20 a:\n\x20\x20\x20 steps:\n\x20\x20\x20\x20 - run: x\n",
        )
        .expect_err("top-level key");
        assert!(
            err.to_string().contains("unknown key `concurrency`"),
            "{err}"
        );

        let err = parse(
            "jobs:\n\x20 a:\n\x20\x20 permissions: read\n\x20\x20 steps:\n\x20\x20\x20 - run: x\n",
        )
        .expect_err("job key");
        assert!(
            err.to_string()
                .contains("jobs.a: unknown key `permissions`"),
            "{err}"
        );

        let err = parse("jobs:\n\x20 a:\n\x20\x20 steps:\n\x20\x20\x20 - if: always()\n\x20\x20\x20\x20\x20 run: x\n")
            .expect_err("step key");
        assert!(err.to_string().contains("unknown key `if`"), "{err}");
    }

    #[test]
    fn needs_is_rejected_with_a_reason() {
        let err = parse(
            "jobs:\n  a:\n    steps:\n      - run: x\n  b:\n    needs: [a]\n    steps:\n      - run: y\n",
        )
        .expect_err("needs");
        assert!(err.to_string().contains("`needs` is unsupported"), "{err}");
    }

    #[test]
    fn rejects_oversize_config() {
        let big = format!(
            "jobs:\n\x20 a:\n\x20\x20\x20 steps:\n\x20\x20\x20\x20 - run: {}\n",
            "x".repeat(70 * 1024)
        );
        let err = parse(&big).expect_err("oversize");
        assert!(matches!(err, Error::TooLarge { .. }), "{err}");
    }

    #[test]
    fn rejects_empty_shapes() {
        assert!(parse("jobs: {}\n").is_err(), "empty jobs map");
        assert!(parse("on: push\n").is_err(), "missing jobs mapping");
        let err = parse("jobs:\n\x20 a:\n\x20\x20 steps: []\n").expect_err("empty steps");
        assert!(err.to_string().contains("defines no steps"), "{err}");
        let err = parse("jobs:\n\x20 a:\n\x20\x20 steps:\n\x20\x20\x20 - name: No run\n")
            .expect_err("missing run");
        assert!(
            err.to_string().contains("missing required `run` or `uses`"),
            "{err}"
        );
        let err = parse("jobs:\n\x20 a:\n\x20\x20 steps:\n\x20\x20\x20 - run: '   '\n")
            .expect_err("blank run");
        assert!(err.to_string().contains("`run` is empty"), "{err}");
    }

    #[test]
    fn rejects_too_many_steps() {
        let mut cfg = "jobs:\n\x20 a:\n\x20\x20\x20 steps:\n".to_string();
        for i in 0..33 {
            cfg.push_str(&format!("\x20\x20\x20\x20 - run: echo {i}\n"));
        }
        let err = parse(&cfg).expect_err("33 steps");
        assert!(
            err.to_string().contains("more than the 32-step cap"),
            "{err}"
        );
    }

    #[test]
    fn uses_actions_are_recognised() {
        let workflow = parse(
            "jobs:\n\
             \x20 build:\n\
             \x20\x20\x20 steps:\n\
             \x20\x20\x20\x20 - uses: checkout\n\
             \x20\x20\x20\x20 - uses: actions/checkout@v4\n\
             \x20\x20\x20\x20\x20\x20 with: { fetch-depth: 0 }\n\
             \x20\x20\x20\x20 - uses: actions/cache@v4\n\
             \x20\x20\x20\x20\x20\x20 with: { path: ~/.cache, key: build }\n\
             \x20\x20\x20\x20 - uses: upload-artifact\n\
             \x20\x20\x20\x20\x20\x20 with: { path: reports/junit.xml, name: junit }\n\
             \x20\x20\x20\x20 - run: echo hi\n",
        )
        .expect("parses");
        let kinds: Vec<&StepKind> = workflow.jobs[0]
            .steps
            .iter()
            .map(|step| &step.kind)
            .collect();
        assert_eq!(kinds[0], &StepKind::Checkout, "checkout");
        assert_eq!(kinds[1], &StepKind::Checkout, "actions/checkout@v4");
        assert_eq!(kinds[2], &StepKind::Cache, "actions/cache@v4");
        assert_eq!(
            kinds[3],
            &StepKind::UploadArtifact {
                path: "reports/junit.xml".to_string(),
                name: Some("junit".to_string()),
            }
        );
    }

    #[test]
    fn unsupported_actions_and_bad_with_are_rejected() {
        let err = parse(
            "jobs:\n\
             \x20 build:\n\
             \x20\x20\x20 steps:\n\
             \x20\x20\x20\x20 - uses: actions/setup-node@v4\n",
        )
        .expect_err("marketplace uses");
        assert!(
            err.to_string()
                .contains("unsupported action `actions/setup-node@v4`"),
            "{err}"
        );

        let err =
            parse("jobs:\n  build:\n    steps:\n      - uses: checkout\n        run: echo hi\n")
                .expect_err("uses mixed with run");
        assert!(err.to_string().contains("either `run` or `uses`"), "{err}");

        let err = parse(
            "jobs:\n  build:\n    steps:\n      - uses: upload-artifact\n        with: { name: x }\n",
        )
        .expect_err("missing path");
        assert!(err.to_string().contains("requires a `with.path`"), "{err}");

        let err = parse(
            "jobs:\n  build:\n    steps:\n      - uses: upload-artifact\n        with: { path: ../escape }\n",
        )
        .expect_err("escaping path");
        assert!(err.to_string().contains("escapes /work"), "{err}");

        let err = parse(
            "jobs:\n  build:\n    steps:\n      - uses: cache@v4\n        with: { restore-keys: x }\n",
        )
        .expect_err("cache input");
        assert!(
            err.to_string()
                .contains("input `restore-keys` is unsupported"),
            "{err}"
        );

        let err = parse("jobs:\n  build:\n    steps:\n      - run: x\n        with: { a: b }\n")
            .expect_err("with on run");
        assert!(err.to_string().contains("only valid on `uses`"), "{err}");

        let err =
            parse("jobs:\n  build:\n    steps:\n      - uses: checkout\n        shell: bash\n")
                .expect_err("shell on uses");
        assert!(err.to_string().contains("only valid on `run`"), "{err}");
    }

    #[test]
    fn expressions_are_rejected() {
        let err = parse("jobs:\n  build:\n    steps:\n      - run: echo ${{ secrets.TOKEN }}\n")
            .expect_err("expression in run");
        assert!(
            err.to_string().contains("expressions are unsupported"),
            "{err}"
        );

        let err = parse(
            "env: { TOKEN: '${{ secrets.TOKEN }}' }\njobs:\n  build:\n    steps:\n      - run: x\n",
        )
        .expect_err("expression in env");
        assert!(
            err.to_string().contains("expressions are unsupported"),
            "{err}"
        );
    }

    #[test]
    fn rejects_bad_timeouts_env_and_dirs() {
        for bad in [
            "timeout-minutes: 0",
            "timeout-minutes: 121",
            "timeout-minutes: fast",
            "timeout-minutes: 1.5",
        ] {
            let cfg = format!("jobs:\n  a:\n    steps:\n      - run: x\n        {bad}\n");
            assert!(parse(&cfg).is_err(), "{bad}");
        }
        for bad in ["timeout-minutes: 0", "timeout-minutes: 361"] {
            let cfg = format!("jobs:\n  a:\n    {bad}\n    steps:\n      - run: x\n");
            assert!(parse(&cfg).is_err(), "job {bad}");
        }
        for bad in ["FOO-BAR: 1", "1ABC: 1", "has space: 1"] {
            let cfg =
                format!("jobs:\n  a:\n    steps:\n      - run: x\n        env:\n          {bad}\n");
            let err = parse(&cfg).expect_err(format!("env {bad}").as_str());
            assert!(err.to_string().contains("must match"), "{err}");
        }
        for bad in ["/abs", "../escape", "a/../../b"] {
            let cfg = format!(
                "jobs:\n  a:\n    steps:\n      - run: x\n        working-directory: {bad}\n"
            );
            assert!(parse(&cfg).is_err(), "{bad}");
        }
        let err = parse(
            "jobs:\n  a:\n    defaults: { run: { shell: zsh } }\n    steps:\n      - run: x\n",
        )
        .expect_err("defaults shell");
        assert!(err.to_string().contains("unsupported shell `zsh`"), "{err}");
    }

    #[test]
    fn matrix_expands_in_declared_order() {
        let workflow = parse(
            "jobs:\n\
             \x20 build:\n\
             \x20\x20 strategy:\n\
             \x20\x20\x20 matrix: { os: [linux, macos], node: [20, 22] }\n\
             \x20\x20 steps:\n\
             \x20\x20\x20 - run: echo hi\n",
        )
        .expect("parses");
        let names: Vec<&str> = workflow.jobs.iter().map(|j| j.name.as_str()).collect();
        assert_eq!(
            names,
            vec![
                "build (linux, 20)",
                "build (linux, 22)",
                "build (macos, 20)",
                "build (macos, 22)",
            ]
        );
        assert!(workflow.jobs.iter().all(|job| job.base_name == "build"));
        assert_eq!(
            workflow.jobs[0].matrix.get("os").map(String::as_str),
            Some("linux")
        );
        assert_eq!(
            workflow.jobs[0].matrix.get("node").map(String::as_str),
            Some("20")
        );
    }

    #[test]
    fn strategy_controls_are_parsed() {
        let workflow = parse(
            "jobs:\n  build:\n    strategy:\n      matrix: { node: [20, 22, 24] }\n      max-parallel: 2\n      fail-fast: false\n    steps:\n      - run: echo hi\n",
        )
        .expect("parses");
        assert_eq!(workflow.jobs.len(), 3);
        assert_eq!(workflow.jobs[0].max_parallel, Some(2));
        assert!(!workflow.jobs[0].fail_fast);

        let err = parse(
            "jobs:\n  build:\n    strategy:\n      matrix: { include: [{ node: 20 }] }\n    steps:\n      - run: x\n",
        )
        .expect_err("include");
        assert!(err.to_string().contains("include is unsupported"), "{err}");

        let err = parse(
            "jobs:\n  build:\n    strategy:\n      matrix: { node: [] }\n    steps:\n      - run: x\n",
        )
        .expect_err("empty values");
        assert!(err.to_string().contains("lists no values"), "{err}");

        let err = parse(
            "jobs:\n  build:\n    strategy:\n      matrix:\n        a: [1, 2, 3, 4, 5, 6, 7]\n        b: [1, 2, 3, 4, 5, 6, 7]\n        c: [1, 2, 3, 4, 5, 6, 7]\n    steps:\n      - run: x\n",
        )
        .expect_err("too many");
        assert!(
            err.to_string().contains("more than the 256-job cap"),
            "{err}"
        );
    }
}
