//! Typed errors shared by every layer.
//!
//! Store errors stay distinct because callers must branch on CAS conflicts and
//! retryability. Git failures stay distinct because a missing object is a
//! client error while a broken pipe is not. Everything that crosses the HTTP
//! boundary has an explicit status mapping in `http`.

use std::fmt;

/// Object-store failure. The variants are the contract every backend honours.
#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    #[error("object not found: {key}")]
    NotFound { key: String },
    /// A conditional write/read/delete lost against the current object.
    #[error("precondition failed on {key} (current version: {current:?})")]
    PreconditionFailed {
        key: String,
        current: Option<String>,
    },
    /// Transient: a retry may succeed.
    #[error("retryable store error: {0}")]
    Retryable(#[source] anyhow::Error),
    #[error("invalid store argument: {0}")]
    InvalidArgument(String),
    #[error(transparent)]
    Other(#[from] anyhow::Error),
}

impl From<std::io::Error> for StoreError {
    fn from(error: std::io::Error) -> Self {
        Self::Other(error.into())
    }
}

impl StoreError {
    pub fn not_found(key: impl Into<String>) -> Self {
        Self::NotFound { key: key.into() }
    }

    pub fn precondition(key: impl Into<String>, current: Option<String>) -> Self {
        Self::PreconditionFailed {
            key: key.into(),
            current,
        }
    }

    pub fn invalid(message: impl Into<String>) -> Self {
        Self::InvalidArgument(message.into())
    }

    pub fn retryable(error: impl Into<anyhow::Error>) -> Self {
        Self::Retryable(error.into())
    }

    pub fn is_not_found(&self) -> bool {
        matches!(self, Self::NotFound { .. })
    }

    pub fn is_precondition_failed(&self) -> bool {
        matches!(self, Self::PreconditionFailed { .. })
    }

    pub fn is_retryable(&self) -> bool {
        matches!(self, Self::Retryable(_))
    }
}

/// Git process or object-level failure.
#[derive(Debug, thiserror::Error)]
pub enum GitError {
    #[error("git {command} failed with {status}: {stderr}")]
    Subprocess {
        command: String,
        status: String,
        stderr: String,
    },
    #[error("git command timed out: {0}")]
    Timeout(String),
    #[error("git I/O: {0}")]
    Io(#[from] std::io::Error),
    #[error("missing object {oid}")]
    MissingObject { oid: String },
    #[error("ref conflict on {name}: expected {expected:?}, actual {actual:?}")]
    RefConflict {
        name: String,
        expected: Option<String>,
        actual: Option<String>,
    },
    #[error("invalid repository input: {0}")]
    InvalidInput(String),
    #[error("invalid repository id: {0}")]
    InvalidRepoId(String),
    #[error("protocol error: {0}")]
    Protocol(String),
    #[error("pack error: {0}")]
    Pack(String),
    #[error("fsck failed: {0}")]
    Fsck(String),
    #[error(transparent)]
    Other(#[from] anyhow::Error),
}

/// One ref's result inside a transaction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RefError {
    NonFastForward,
    Conflict {
        expected: Option<String>,
        actual: Option<String>,
    },
    Rejected(String),
    Missing,
}

impl fmt::Display for RefError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NonFastForward => f.write_str("non-fast-forward"),
            Self::Conflict { expected, actual } => {
                write!(f, "conflict: expected {expected:?}, actual {actual:?}")
            }
            Self::Rejected(reason) => f.write_str(reason),
            Self::Missing => f.write_str("missing"),
        }
    }
}

/// WAL-level failure.
#[derive(Debug, thiserror::Error)]
pub enum WalError {
    #[error("repository {0} not found")]
    NotFound(String),
    #[error("repository {0} already exists")]
    AlreadyExists(String),
    #[error("ref conflict on {name}: expected {expected:?}, actual {actual:?}")]
    RefConflict {
        name: String,
        expected: Option<String>,
        actual: Option<String>,
    },
    #[error("repository is corrupt: {0}")]
    Corrupt(String),
    #[error("legacy manifest version {0} is not supported")]
    UnsupportedVersion(u8),
    #[error("publish retries exhausted for {slug} after {attempts} attempts")]
    RetryExhausted { slug: String, attempts: u32 },
    #[error("manifest write outcome is unknown: {0}")]
    Ambiguous(String),
    #[error(transparent)]
    Store(#[from] StoreError),
    #[error(transparent)]
    Git(#[from] GitError),
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    Json(#[from] serde_json::Error),
    #[error(transparent)]
    Other(#[from] anyhow::Error),
}

/// Configuration problems, all reported at once.
#[derive(Debug, thiserror::Error)]
pub struct ConfigError {
    pub problems: Vec<String>,
}

impl ConfigError {
    pub fn new(problems: Vec<String>) -> Self {
        Self { problems }
    }

    pub fn one(problem: impl Into<String>) -> Self {
        Self {
            problems: vec![problem.into()],
        }
    }
}

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.problems.len() == 1 {
            return f.write_str(&self.problems[0]);
        }
        writeln!(f, "invalid configuration:")?;
        for problem in &self.problems {
            writeln!(f, "- {problem}")?;
        }
        Ok(())
    }
}

/// A policy file or rule failure.
#[derive(Debug, thiserror::Error)]
pub enum PolicyError {
    #[error("policy: {0}")]
    Invalid(String),
    #[error(transparent)]
    Json(#[from] serde_json::Error),
}
