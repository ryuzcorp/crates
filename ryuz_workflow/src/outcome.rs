//! What a finished run produced.
//!
//! A run always yields one [`JobOutcome`] per expanded job (matrix members
//! included) unless the scheduler itself fails. Failures live in the outcome,
//! not in `Result`.

use std::collections::BTreeMap;
use std::fmt;
use std::path::PathBuf;
use std::time::Duration;

/// Why a job did not succeed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Failure {
    /// A step exited nonzero.
    StepFailed { step: String, exit_code: i32 },
    /// A step was killed with exit 137: almost always the kernel OOM killer.
    OutOfMemory { step: String },
    /// The step timeout or the job timeout expired; the container was killed.
    Timeout { step: Option<String> },
    /// The container could not be created, copied into or inspected.
    Container(String),
}

impl fmt::Display for Failure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Failure::StepFailed { step, exit_code } => {
                write!(f, "step `{step}` failed with exit {exit_code}")
            }
            Failure::OutOfMemory { step } => write!(
                f,
                "step `{step}` was killed with exit 137 (out of memory; raise memory_mb)"
            ),
            Failure::Timeout { step: Some(step) } => {
                write!(f, "step `{step}` timed out")
            }
            Failure::Timeout { step: None } => write!(f, "job timed out"),
            Failure::Container(message) => write!(f, "container failed: {message}"),
        }
    }
}

/// The final state of one job.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum JobStatus {
    Success,
    Failed(Failure),
    /// Fail-fast stopped a matrix member before it started.
    Skipped,
    /// A workflow timeout stopped the job while it was queued or running.
    Cancelled,
}

impl JobStatus {
    pub fn is_success(&self) -> bool {
        matches!(self, JobStatus::Success)
    }
}

/// One finished step.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StepOutcome {
    pub name: Option<String>,
    pub exit_code: i32,
    pub duration: Duration,
}

/// A file tree copied out of a job's container.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Artifact {
    /// `name:` from `uses: upload-artifact`, when the step set one.
    pub name: Option<String>,
    /// Local path the artifact was copied to.
    pub path: PathBuf,
}

/// One finished job.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JobOutcome {
    /// Display name; matrix members carry their values in parentheses.
    pub name: String,
    /// Declared job name, without the matrix suffix.
    pub base_name: String,
    /// Matrix values, empty for a job without `strategy.matrix`.
    pub matrix: BTreeMap<String, String>,
    pub image: String,
    pub status: JobStatus,
    pub steps: Vec<StepOutcome>,
    pub artifacts: Vec<Artifact>,
    pub duration: Duration,
}

impl JobOutcome {
    pub fn success(&self) -> bool {
        self.status.is_success()
    }
}

/// A finished workflow.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Outcome {
    /// One outcome per expanded job, in file order (matrix members in
    /// expansion order).
    pub jobs: Vec<JobOutcome>,
    /// Every artifact copied out by any job, in completion order.
    pub artifacts: Vec<Artifact>,
    /// The automatic `<work_dir>/<artifact_dir>` copy of the last successful
    /// job, when [`crate::Settings::artifact_dir`] produced one.
    pub artifact_path: Option<PathBuf>,
}

impl Outcome {
    pub fn success(&self) -> bool {
        self.jobs.iter().all(JobOutcome::success)
    }
}
