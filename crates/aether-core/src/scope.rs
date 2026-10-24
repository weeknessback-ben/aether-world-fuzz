//! Authorization and target scope policy.
//!
//! AETHER runs attacker-controlled data through real programs, so "may I test
//! this?" is a question the engine answers before any execution, not a
//! documentation note. The rules here are deliberately restrictive:
//!
//! * Local executables are allowed by default, because that is the laboratory
//!   case the tool exists for.
//! * A network target is refused unless its host is explicitly authorized
//!   *and* the operator recorded an authorization note. Supplying a URL is not
//!   permission to test it.
//! * Loopback is not special-cased into "always fine": a local HTTP service
//!   still has to be listed, because `127.0.0.1:8080` may be someone's
//!   production admin panel forwarded over SSH.
//! * Scope is never widened by anything the target produces. Parsing a crash
//!   log, an HTTP response or a corpus file cannot reach this module.
//!
//! This is enforcement, not advice: [`ScopePolicy::authorize_target`] is
//! called by the campaign controller before the first execution and by every
//! executor construction path.

use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScopePolicy {
    /// Permit executing local binaries. Default true.
    #[serde(default = "default_true")]
    pub allow_local_execution: bool,

    /// Permit targets reached over the network. Default false.
    #[serde(default)]
    pub allow_network_targets: bool,

    /// Hosts a network target may address. An entry is `host` or `host:port`.
    /// An empty list with `allow_network_targets = true` still refuses every
    /// host: the operator has to name them.
    #[serde(default)]
    pub authorized_hosts: Vec<String>,

    /// Free-text record of who authorized testing. Required before any
    /// network target is accepted, so that an engagement always has a
    /// human-attributable reason attached to it.
    #[serde(default)]
    pub authorization_note: Option<String>,

    /// Rate ceiling applied to network targets. 0 means "unset", which is
    /// refused for network targets rather than treated as unlimited.
    #[serde(default)]
    pub max_requests_per_second: u32,

    /// Permit a target whose command line AETHER cannot fully validate, such
    /// as one wrapped in an interpreter. Off by default.
    #[serde(default)]
    pub allow_unvalidated_argv: bool,
}

fn default_true() -> bool {
    true
}

impl Default for ScopePolicy {
    /// The default policy is "local laboratory only".
    fn default() -> Self {
        ScopePolicy {
            allow_local_execution: true,
            allow_network_targets: false,
            authorized_hosts: Vec::new(),
            authorization_note: None,
            max_requests_per_second: 0,
            allow_unvalidated_argv: false,
        }
    }
}

/// What a target needs permission for. Derived from the target definition by
/// the caller, so this module never has to parse a URL out of free text.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ScopeRequest {
    /// Execute a local program.
    LocalExecution { binary: String },
    /// Reach a network endpoint.
    Network { host: String, port: u16 },
}

impl ScopePolicy {
    pub fn authorize_target(&self, req: &ScopeRequest) -> Result<()> {
        match req {
            ScopeRequest::LocalExecution { binary } => {
                if !self.allow_local_execution {
                    return Err(Error::scope(
                        "local execution",
                        "scope.allow_local_execution is false",
                    ));
                }
                if binary.trim().is_empty() {
                    return Err(Error::scope("local execution", "empty binary path"));
                }
                Ok(())
            }
            ScopeRequest::Network { host, port } => {
                if !self.allow_network_targets {
                    return Err(Error::scope(
                        format!("network target {host}:{port}"),
                        "scope.allow_network_targets is false; supplying an address is not \
                         authorization to test it",
                    ));
                }
                match self.authorization_note.as_deref().map(str::trim) {
                    Some(note) if !note.is_empty() => {}
                    _ => {
                        return Err(Error::scope(
                            format!("network target {host}:{port}"),
                            "scope.authorization_note is required before any network target \
                             is tested",
                        ))
                    }
                }
                if self.max_requests_per_second == 0 {
                    return Err(Error::scope(
                        format!("network target {host}:{port}"),
                        "scope.max_requests_per_second must be set for network targets",
                    ));
                }
                if !self.host_authorized(host, *port) {
                    return Err(Error::scope(
                        format!("network target {host}:{port}"),
                        format!(
                            "host is not in scope.authorized_hosts ({} entr{} listed)",
                            self.authorized_hosts.len(),
                            if self.authorized_hosts.len() == 1 { "y" } else { "ies" }
                        ),
                    ));
                }
                Ok(())
            }
        }
    }

    /// Exact host match, optionally pinned to a port. No wildcards and no
    /// subdomain matching: `example.com` does not authorize
    /// `admin.example.com`, because a scope that silently grows is the failure
    /// mode this whole module exists to prevent.
    fn host_authorized(&self, host: &str, port: u16) -> bool {
        let host = host.trim().to_ascii_lowercase();
        self.authorized_hosts.iter().any(|entry| {
            let entry = entry.trim().to_ascii_lowercase();
            match entry.rsplit_once(':') {
                Some((h, p)) if p.chars().all(|c| c.is_ascii_digit()) && !p.is_empty() => {
                    h == host && p.parse::<u16>().map(|pp| pp == port).unwrap_or(false)
                }
                _ => entry == host,
            }
        })
    }

    /// Validate the policy itself, independently of any target, so that an
    /// incoherent configuration is reported at load time.
    pub fn validate(&self) -> Result<()> {
        if self.allow_network_targets && self.authorized_hosts.is_empty() {
            return Err(Error::config(
                "scope",
                "allow_network_targets is true but authorized_hosts is empty; \
                 list the hosts explicitly",
            ));
        }
        for entry in &self.authorized_hosts {
            if entry.trim().is_empty() {
                return Err(Error::config("scope", "authorized_hosts contains an empty entry"));
            }
            if entry.contains('*') {
                return Err(Error::config(
                    "scope",
                    format!("authorized_hosts entry {entry:?} contains a wildcard; \
                             list each host explicitly"),
                ));
            }
        }
        Ok(())
    }

    /// A one-line human summary for status output and reports.
    pub fn describe(&self) -> String {
        if !self.allow_network_targets {
            return "local targets only; network targets refused".to_string();
        }
        format!(
            "local targets; network limited to {} authorized host(s) at <= {} req/s",
            self.authorized_hosts.len(),
            self.max_requests_per_second
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn net(host: &str, port: u16) -> ScopeRequest {
        ScopeRequest::Network { host: host.into(), port }
    }

    #[test]
    fn default_policy_allows_local_and_refuses_network() {
        let p = ScopePolicy::default();
        p.authorize_target(&ScopeRequest::LocalExecution { binary: "/bin/true".into() }).unwrap();
        assert!(p.authorize_target(&net("example.com", 80)).is_err());
    }

    #[test]
    fn url_alone_is_not_authorization() {
        // allow_network_targets on, but no host list, no note, no rate limit.
        let p = ScopePolicy { allow_network_targets: true, ..Default::default() };
        assert!(p.authorize_target(&net("example.com", 80)).is_err());
        assert!(p.validate().is_err(), "empty authorized_hosts must fail validation");
    }

    #[test]
    fn loopback_is_not_implicitly_authorized() {
        let p = ScopePolicy {
            allow_network_targets: true,
            authorized_hosts: vec!["example.com".into()],
            authorization_note: Some("engagement ticket SEC-1".into()),
            max_requests_per_second: 10,
            ..Default::default()
        };
        assert!(p.authorize_target(&net("127.0.0.1", 8080)).is_err());
        assert!(p.authorize_target(&net("localhost", 8080)).is_err());
    }

    #[test]
    fn fully_configured_network_scope_is_accepted() {
        let p = ScopePolicy {
            allow_network_targets: true,
            authorized_hosts: vec!["127.0.0.1:8080".into()],
            authorization_note: Some("local lab service, ticket SEC-2".into()),
            max_requests_per_second: 25,
            ..Default::default()
        };
        p.validate().unwrap();
        p.authorize_target(&net("127.0.0.1", 8080)).unwrap();
        // Same host, different port: refused, because the entry pinned a port.
        assert!(p.authorize_target(&net("127.0.0.1", 9090)).is_err());
    }

    #[test]
    fn note_and_rate_limit_are_both_required() {
        let base = ScopePolicy {
            allow_network_targets: true,
            authorized_hosts: vec!["h".into()],
            authorization_note: Some("ticket".into()),
            max_requests_per_second: 5,
            ..Default::default()
        };
        let no_note = ScopePolicy { authorization_note: None, ..base.clone() };
        assert!(no_note.authorize_target(&net("h", 1)).is_err());
        let blank_note = ScopePolicy { authorization_note: Some("   ".into()), ..base.clone() };
        assert!(blank_note.authorize_target(&net("h", 1)).is_err());
        let no_rate = ScopePolicy { max_requests_per_second: 0, ..base.clone() };
        assert!(no_rate.authorize_target(&net("h", 1)).is_err());
        base.authorize_target(&net("h", 1)).unwrap();
    }

    #[test]
    fn subdomains_do_not_inherit_authorization() {
        let p = ScopePolicy {
            allow_network_targets: true,
            authorized_hosts: vec!["example.com".into()],
            authorization_note: Some("ticket".into()),
            max_requests_per_second: 1,
            ..Default::default()
        };
        p.authorize_target(&net("example.com", 443)).unwrap();
        assert!(p.authorize_target(&net("admin.example.com", 443)).is_err());
        assert!(p.authorize_target(&net("example.com.evil.net", 443)).is_err());
    }

    #[test]
    fn wildcards_are_refused_at_validation() {
        let p = ScopePolicy {
            allow_network_targets: true,
            authorized_hosts: vec!["*.example.com".into()],
            authorization_note: Some("t".into()),
            max_requests_per_second: 1,
            ..Default::default()
        };
        assert!(p.validate().is_err());
    }

    #[test]
    fn local_execution_can_be_disabled() {
        let p = ScopePolicy { allow_local_execution: false, ..Default::default() };
        assert!(p
            .authorize_target(&ScopeRequest::LocalExecution { binary: "/bin/true".into() })
            .is_err());
    }

    #[test]
    fn host_matching_is_case_insensitive() {
        let p = ScopePolicy {
            allow_network_targets: true,
            authorized_hosts: vec!["Example.COM".into()],
            authorization_note: Some("t".into()),
            max_requests_per_second: 1,
            ..Default::default()
        };
        p.authorize_target(&net("example.com", 80)).unwrap();
    }
}
