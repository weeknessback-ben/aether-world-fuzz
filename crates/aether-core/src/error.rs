//! Error model.
//!
//! Every fallible operation in AETHER returns [`Error`]. The variants are
//! deliberately coarse but each carries enough context to be actionable in a
//! CLI message or an MCP structured error, because an MCP client cannot read
//! a backtrace. [`Error::kind`] gives a stable machine-readable string that
//! the MCP layer reports verbatim so callers can branch on it.

use std::fmt;
use std::path::PathBuf;

#[derive(Debug)]
pub enum Error {
    /// A configuration file or value failed validation before any work ran.
    Config { what: String, detail: String },
    /// The requested target cannot be used as described.
    Target { what: String, detail: String },
    /// The operation was refused by the authorization/scope policy. This is
    /// never downgraded to a warning: an out-of-scope target is a hard stop.
    Scope { what: String, detail: String },
    /// A capability the request needs is not present in this environment.
    /// Carries the remedy so `aether doctor` and MCP errors can relay it.
    Unsupported { capability: String, reason: String, remedy: Option<String> },
    /// Target execution failed for reasons attributable to AETHER, not to the
    /// target. A crashing target is a normal result, not this.
    Exec { what: String, detail: String },
    /// Corpus or finding storage failed.
    Storage { what: String, detail: String },
    /// An identifier did not resolve.
    NotFound { kind: &'static str, id: String },
    /// A state machine rejected a transition.
    InvalidTransition { from: String, to: String },
    /// The operation was cancelled by the user or a budget expiring.
    Cancelled { what: String },
    Io { path: Option<PathBuf>, source: std::io::Error },
    Sqlite(rusqlite::Error),
    Json(serde_json::Error),
}

impl Error {
    /// Stable machine-readable discriminant, reported through MCP so callers
    /// can branch without parsing prose.
    pub fn kind(&self) -> &'static str {
        match self {
            Error::Config { .. } => "config_invalid",
            Error::Target { .. } => "target_invalid",
            Error::Scope { .. } => "scope_denied",
            Error::Unsupported { .. } => "unsupported_capability",
            Error::Exec { .. } => "execution_failed",
            Error::Storage { .. } => "storage_failed",
            Error::NotFound { .. } => "not_found",
            Error::InvalidTransition { .. } => "invalid_transition",
            Error::Cancelled { .. } => "cancelled",
            Error::Io { .. } => "io_error",
            Error::Sqlite(_) => "database_error",
            Error::Json(_) => "serialization_error",
        }
    }

    pub fn config(what: impl Into<String>, detail: impl Into<String>) -> Self {
        Error::Config { what: what.into(), detail: detail.into() }
    }
    pub fn target(what: impl Into<String>, detail: impl Into<String>) -> Self {
        Error::Target { what: what.into(), detail: detail.into() }
    }
    pub fn scope(what: impl Into<String>, detail: impl Into<String>) -> Self {
        Error::Scope { what: what.into(), detail: detail.into() }
    }
    pub fn exec(what: impl Into<String>, detail: impl Into<String>) -> Self {
        Error::Exec { what: what.into(), detail: detail.into() }
    }
    pub fn storage(what: impl Into<String>, detail: impl Into<String>) -> Self {
        Error::Storage { what: what.into(), detail: detail.into() }
    }
    pub fn unsupported(capability: impl Into<String>, reason: impl Into<String>) -> Self {
        Error::Unsupported {
            capability: capability.into(),
            reason: reason.into(),
            remedy: None,
        }
    }
    pub fn unsupported_with_remedy(
        capability: impl Into<String>,
        reason: impl Into<String>,
        remedy: impl Into<String>,
    ) -> Self {
        Error::Unsupported {
            capability: capability.into(),
            reason: reason.into(),
            remedy: Some(remedy.into()),
        }
    }
    pub fn not_found(kind: &'static str, id: impl Into<String>) -> Self {
        Error::NotFound { kind, id: id.into() }
    }
    pub fn io(path: impl Into<PathBuf>, source: std::io::Error) -> Self {
        Error::Io { path: Some(path.into()), source }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Config { what, detail } => write!(f, "invalid configuration: {what}: {detail}"),
            Error::Target { what, detail } => write!(f, "target unusable: {what}: {detail}"),
            Error::Scope { what, detail } => {
                write!(f, "refused by scope policy: {what}: {detail}")
            }
            Error::Unsupported { capability, reason, remedy } => {
                write!(f, "capability '{capability}' unavailable: {reason}")?;
                if let Some(r) = remedy {
                    write!(f, " (remedy: {r})")?;
                }
                Ok(())
            }
            Error::Exec { what, detail } => write!(f, "execution failed: {what}: {detail}"),
            Error::Storage { what, detail } => write!(f, "storage failure: {what}: {detail}"),
            Error::NotFound { kind, id } => write!(f, "no such {kind}: {id}"),
            Error::InvalidTransition { from, to } => {
                write!(f, "invalid state transition: {from} -> {to}")
            }
            Error::Cancelled { what } => write!(f, "cancelled: {what}"),
            Error::Io { path, source } => match path {
                Some(p) => write!(f, "io error on {}: {source}", p.display()),
                None => write!(f, "io error: {source}"),
            },
            Error::Sqlite(e) => write!(f, "database error: {e}"),
            Error::Json(e) => write!(f, "serialization error: {e}"),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Error::Io { source, .. } => Some(source),
            Error::Sqlite(e) => Some(e),
            Error::Json(e) => Some(e),
            _ => None,
        }
    }
}

impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Error::Io { path: None, source: e }
    }
}
impl From<rusqlite::Error> for Error {
    fn from(e: rusqlite::Error) -> Self {
        Error::Sqlite(e)
    }
}
impl From<serde_json::Error> for Error {
    fn from(e: serde_json::Error) -> Self {
        Error::Json(e)
    }
}

pub type Result<T> = std::result::Result<T, Error>;
