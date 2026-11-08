//! Structured progress events.
//!
//! [`crate::run_with_events`] hands these to the caller as they happen;
//! [`crate::run`] formats them into the plain log lines `job: …, step: …,
//! <output>` that a deploy log or terminal wants. A caller that renders a
//! table or posts to an API can keep the structure instead.

use std::path::PathBuf;
use std::time::Duration;

use crate::outcome::JobStatus;

/// Which pipe a step output line came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Stream {
    Stdout,
    Stderr,
}

/// One thing that happened during a run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Event {
    WorkflowStarted {
        jobs: usize,
    },
    JobStarted {
        job: String,
        image: String,
    },
    StepStarted {
        job: String,
        step: String,
    },
    StepOutput {
        job: String,
        step: String,
        stream: Stream,
        line: String,
    },
    StepFinished {
        job: String,
        step: String,
        exit_code: i32,
        duration: Duration,
    },
    /// A runner message (a skipped no-op action, a missing artifact, why a
    /// step was killed). Not step output.
    Note {
        job: String,
        line: String,
    },
    Artifact {
        job: String,
        name: Option<String>,
        path: PathBuf,
    },
    JobFinished {
        job: String,
        status: JobStatus,
        duration: Duration,
    },
    WorkflowFinished {
        success: bool,
        duration: Duration,
    },
}

/// Render an event as one log line, or `None` when it has no log form.
///
/// This is the format [`crate::run`] emits:
/// `workflow: N jobs`, `job: <name> (<image>)`, `step: <name>`, the step's raw
/// lines, notes, `artifact: …`, and `job: <name> done` / `job: <name> <failure>`.
pub fn format_event(event: &Event) -> Option<String> {
    match event {
        Event::WorkflowStarted { jobs } => Some(format!("workflow: {jobs} jobs")),
        Event::JobStarted { job, image } => Some(format!("job: {job} ({image})")),
        Event::StepStarted { step, .. } => Some(format!("step: {step}")),
        Event::StepOutput { line, .. } => Some(line.clone()),
        Event::StepFinished { .. } => None,
        Event::Note { line, .. } => Some(line.clone()),
        Event::Artifact { path, .. } => Some(format!("artifact: {}", path.display())),
        Event::JobFinished { job, status, .. } => Some(match status {
            JobStatus::Success => format!("job: {job} done"),
            JobStatus::Skipped => format!("job: {job} skipped"),
            JobStatus::Cancelled => format!("job: {job} cancelled"),
            JobStatus::Failed(failure) => format!("job: {job} {failure}"),
        }),
        Event::WorkflowFinished { success, .. } => Some(if *success {
            "workflow: done".to_string()
        } else {
            "workflow: failed".to_string()
        }),
    }
}
