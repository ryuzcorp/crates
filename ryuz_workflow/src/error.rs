//! Everything [`crate::parse`] and [`crate::run`] can report as an error.
//!
//! Step failures are not errors: they are [`crate::JobStatus::Failed`] in the
//! outcome, because a workflow has many jobs and one failing step must not
//! destroy the other jobs' results. `Error` is reserved for the things that
//! stop a workflow from being attempted at all (a bad config, a bad work dir,
//! a disallowed image) or for a broken scheduler.

/// Config, settings or scheduler failure.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("config is {bytes} bytes, larger than the {max}-byte cap")]
    TooLarge { bytes: usize, max: usize },
    #[error("{0}")]
    Config(String),
    #[error("job image `{0}` is not in the allowlist")]
    ImageNotAllowed(String),
    #[error("work dir {0}: not a directory")]
    BadWorkDir(String),
    #[error("{0}")]
    Container(String),
    #[error(transparent)]
    Io(#[from] std::io::Error),
}
