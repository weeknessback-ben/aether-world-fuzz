//! Read-only queries over stored campaign state.
//!
//! Exists so that consumers - the CLI, the MCP server - never contain SQL.
//! Keeping the schema behind typed functions means a schema change is a
//! compile error in one crate rather than a silently wrong query in three, and
//! it keeps identifier validation in one place: every id that arrives from
//! outside is checked before it reaches a statement.

use rusqlite::OptionalExtension;
use serde::{Deserialize, Serialize};
use std::path::Path;

use crate::error::{Error, Result};
use crate::evidence::FindingStatus;
use crate::ids::{CampaignId, FindingId};
use crate::persist::Store;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CampaignRow {
    pub campaign_id: String,
    pub target: String,
    pub status: String,
    pub profile: Option<String>,
    pub seed: u64,
    pub executions: u64,
    pub edges: u64,
    pub guard_count: Option<u32>,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FindingRow {
    pub finding_id: String,
    pub campaign_id: String,
    pub status: String,
    pub signature: String,
    pub exit_class: String,
    pub fault: Option<String>,
    pub sanitizer: Option<String>,
    pub repro_attempts: u32,
    pub repro_successes: u32,
    pub trigger_hash: String,
    pub minimized_hash: Option<String>,
    pub created_at: String,
    /// Parsed evidence, when it was stored and is readable.
    pub evidence: Option<serde_json::Value>,
    pub notes: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StrategyRow {
    pub strategy_id: String,
    pub rounds: u32,
    pub executions: u64,
    pub new_edges: u64,
    pub findings: u32,
    pub value_sum: f64,
    pub cost_micros: u64,
}

/// Open the store for an output directory, with a message that says what to do
/// when there is nothing there yet.
pub fn open_store(dir: &Path) -> Result<Store> {
    let path = dir.join("aether.sqlite");
    if !path.exists() {
        return Err(Error::not_found(
            "campaign store",
            format!(
                "{} (no campaign has been run in this directory)",
                path.display()
            ),
        ));
    }
    Store::open(&path)
}

/// Most recent campaigns first.
pub fn list_campaigns(store: &Store, limit: usize) -> Result<Vec<CampaignRow>> {
    let mut stmt = store.conn().prepare(
        "SELECT id, target_name, status, profile, seed, total_execs, total_edges, \
         guard_count, created_ms, updated_ms FROM campaigns \
         ORDER BY created_ms DESC LIMIT ?1",
    )?;
    let rows = stmt.query_map([limit.min(1000) as i64], |r| {
        Ok(CampaignRow {
            campaign_id: r.get(0)?,
            target: r.get(1)?,
            status: r.get(2)?,
            profile: r.get(3)?,
            seed: r.get::<_, i64>(4)? as u64,
            executions: r.get::<_, i64>(5)? as u64,
            edges: r.get::<_, i64>(6)? as u64,
            guard_count: r.get::<_, Option<i64>>(7)?.map(|v| v as u32),
            created_at: crate::time::format_rfc3339(r.get::<_, i64>(8)? as u64),
            updated_at: crate::time::format_rfc3339(r.get::<_, i64>(9)? as u64),
        })
    })?;
    Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
}

/// The most recently created campaign, used when no id is given.
pub fn latest_campaign(store: &Store) -> Result<String> {
    let id: Option<String> = store
        .conn()
        .query_row(
            "SELECT id FROM campaigns ORDER BY created_ms DESC LIMIT 1",
            [],
            |r| r.get(0),
        )
        .optional()?;
    id.ok_or_else(|| Error::not_found("campaign", "none recorded; run `aether campaign run` first"))
}

/// Resolve an optional id to a concrete one, validating anything supplied.
pub fn resolve_campaign(store: &Store, given: Option<&str>) -> Result<String> {
    match given {
        Some(g) => {
            let id = CampaignId::from_string(g);
            id.validate()?;
            // Confirm it exists, so a typo is reported as a missing campaign
            // rather than as an empty result set.
            let found: Option<String> = store
                .conn()
                .query_row("SELECT id FROM campaigns WHERE id = ?1", [g], |r| r.get(0))
                .optional()?;
            found.ok_or_else(|| Error::not_found("campaign", g))
        }
        None => latest_campaign(store),
    }
}

pub fn list_findings(
    store: &Store,
    campaign_id: &str,
    status: Option<&str>,
    limit: usize,
) -> Result<Vec<FindingRow>> {
    CampaignId::from_string(campaign_id).validate()?;
    if let Some(s) = status {
        // Validate against the state machine rather than passing arbitrary
        // text into a query.
        if FindingStatus::parse(s).is_none() {
            return Err(Error::config(
                "status",
                format!(
                    "unknown status {s:?}; expected one of candidate, reproducing, \
                     reproducible, intermittent, unconfirmed, environmental, duplicate, closed"
                ),
            ));
        }
    }

    const COLUMNS: &str = "id, campaign_id, status, signature, exit_class, fault, \
                           sanitizer_kind, repro_attempts, repro_successes, trigger_hash, \
                           minimized_hash, created_ms, evidence, validation_notes";
    let sql = match status {
        Some(_) => format!(
            "SELECT {COLUMNS} FROM findings WHERE campaign_id = ?1 AND status = ?3 \
             ORDER BY created_ms DESC LIMIT ?2"
        ),
        None => format!(
            "SELECT {COLUMNS} FROM findings WHERE campaign_id = ?1 \
             ORDER BY created_ms DESC LIMIT ?2"
        ),
    };
    let mut stmt = store.conn().prepare(&sql)?;
    let limit = limit.min(1000) as i64;
    let rows = match status {
        Some(s) => stmt
            .query_map(rusqlite::params![campaign_id, limit, s], map_finding)?
            .collect::<rusqlite::Result<Vec<_>>>()?,
        None => stmt
            .query_map(rusqlite::params![campaign_id, limit], map_finding)?
            .collect::<rusqlite::Result<Vec<_>>>()?,
    };
    Ok(rows)
}

fn map_finding(r: &rusqlite::Row<'_>) -> rusqlite::Result<FindingRow> {
    let evidence: Option<String> = r.get(12)?;
    let notes: Option<String> = r.get(13)?;
    Ok(FindingRow {
        finding_id: r.get(0)?,
        campaign_id: r.get(1)?,
        status: r.get(2)?,
        signature: r.get(3)?,
        exit_class: r.get(4)?,
        fault: r.get(5)?,
        sanitizer: r.get(6)?,
        repro_attempts: r.get::<_, i64>(7)? as u32,
        repro_successes: r.get::<_, i64>(8)? as u32,
        trigger_hash: r.get(9)?,
        minimized_hash: r.get(10)?,
        created_at: crate::time::format_rfc3339(r.get::<_, i64>(11)? as u64),
        evidence: evidence
            .as_deref()
            .and_then(|s| serde_json::from_str(s).ok()),
        notes: notes
            .as_deref()
            .and_then(|s| serde_json::from_str::<Vec<String>>(s).ok())
            .unwrap_or_default(),
    })
}

pub fn get_finding(store: &Store, finding_id: &str) -> Result<FindingRow> {
    FindingId::from_string(finding_id).validate()?;
    let mut stmt = store.conn().prepare(
        "SELECT id, campaign_id, status, signature, exit_class, fault, sanitizer_kind, \
         repro_attempts, repro_successes, trigger_hash, minimized_hash, created_ms, \
         evidence, validation_notes FROM findings WHERE id = ?1",
    )?;
    stmt.query_row([finding_id], map_finding)
        .optional()?
        .ok_or_else(|| Error::not_found("finding", finding_id))
}

pub fn list_strategy_stats(store: &Store, campaign_id: &str) -> Result<Vec<StrategyRow>> {
    CampaignId::from_string(campaign_id).validate()?;
    let mut stmt = store.conn().prepare(
        "SELECT strategy_id, rounds, execs, new_edges, findings, value_sum, cost_micros \
         FROM strategy_stats WHERE campaign_id = ?1 ORDER BY rounds DESC",
    )?;
    let rows = stmt.query_map([campaign_id], |r| {
        Ok(StrategyRow {
            strategy_id: r.get(0)?,
            rounds: r.get::<_, i64>(1)? as u32,
            executions: r.get::<_, i64>(2)? as u64,
            new_edges: r.get::<_, i64>(3)? as u64,
            findings: r.get::<_, i64>(4)? as u32,
            value_sum: r.get(5)?,
            cost_micros: r.get::<_, i64>(6)? as u64,
        })
    })?;
    Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
}

/// Recent campaign events, newest first.
pub fn list_events(
    store: &Store,
    campaign_id: &str,
    limit: usize,
) -> Result<Vec<crate::persist::CampaignEvent>> {
    CampaignId::from_string(campaign_id).validate()?;
    store.recent_events(campaign_id, limit.min(1000))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn store_with_data() -> Store {
        let s = Store::open_in_memory().unwrap();
        s.conn()
            .execute(
                "INSERT INTO campaigns(id, target_name, profile, seed, status, config_toml, \
                 created_ms, updated_ms, total_execs, total_edges) \
                 VALUES ('cmp-0000000000000001','demo','quick-local',42,'completed','',1000,2000,500,17)",
                [],
            )
            .unwrap();
        s.conn()
            .execute(
                "INSERT INTO campaigns(id, target_name, seed, status, config_toml, \
                 created_ms, updated_ms) \
                 VALUES ('cmp-0000000000000002','other',7,'running','',3000,3000)",
                [],
            )
            .unwrap();
        s.conn()
            .execute(
                "INSERT INTO findings(id, campaign_id, status, signature, exit_class, \
                 trigger_hash, repro_attempts, repro_successes, created_ms, updated_ms, \
                 evidence, validation_notes, fault) \
                 VALUES ('fnd-0000000000000001','cmp-0000000000000001','reproducible','sig1',\
                 'crash','aa',5,5,1500,1500,'{\"trigger_size\":8}','[\"a note\"]','abort')",
                [],
            )
            .unwrap();
        s.conn()
            .execute(
                "INSERT INTO findings(id, campaign_id, status, signature, exit_class, \
                 trigger_hash, repro_attempts, repro_successes, created_ms, updated_ms) \
                 VALUES ('fnd-0000000000000002','cmp-0000000000000001','unconfirmed','sig2',\
                 'crash','bb',5,0,1600,1600)",
                [],
            )
            .unwrap();
        s.conn()
            .execute(
                "INSERT INTO strategy_stats(campaign_id, strategy_id, rounds, execs, \
                 value_sum, cost_micros, new_edges, findings) \
                 VALUES ('cmp-0000000000000001','havoc',40,2560,88.5,120000,17,1)",
                [],
            )
            .unwrap();
        s
    }

    #[test]
    fn campaigns_list_newest_first() {
        let s = store_with_data();
        let rows = list_campaigns(&s, 10).unwrap();
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].campaign_id, "cmp-0000000000000002", "newest first");
        assert_eq!(rows[1].executions, 500);
        assert_eq!(rows[1].profile.as_deref(), Some("quick-local"));
        assert!(rows[1].created_at.starts_with("1970-"));
    }

    #[test]
    fn limits_are_capped() {
        let s = store_with_data();
        // A caller asking for a huge limit must not be able to request an
        // unbounded result set.
        assert!(list_campaigns(&s, usize::MAX).unwrap().len() <= 2);
        assert!(
            list_findings(&s, "cmp-0000000000000001", None, usize::MAX)
                .unwrap()
                .len()
                <= 2
        );
    }

    #[test]
    fn latest_campaign_resolves_and_reports_when_empty() {
        let s = store_with_data();
        assert_eq!(latest_campaign(&s).unwrap(), "cmp-0000000000000002");
        let empty = Store::open_in_memory().unwrap();
        let e = latest_campaign(&empty).unwrap_err();
        assert_eq!(e.kind(), "not_found");
        assert!(
            e.to_string().contains("campaign run"),
            "should say what to do: {e}"
        );
    }

    #[test]
    fn resolve_rejects_a_malformed_id_and_a_missing_one() {
        let s = store_with_data();
        // Path traversal and shell metacharacters are refused by validation
        // before reaching a statement.
        for bad in [
            "../../etc/passwd",
            "cmp-a;DROP TABLE campaigns",
            "' OR 1=1 --",
        ] {
            assert!(resolve_campaign(&s, Some(bad)).is_err(), "accepted {bad:?}");
        }
        // Well-formed but absent.
        let e = resolve_campaign(&s, Some("cmp-0000000000009999")).unwrap_err();
        assert_eq!(e.kind(), "not_found");
        // Present.
        assert_eq!(
            resolve_campaign(&s, Some("cmp-0000000000000001")).unwrap(),
            "cmp-0000000000000001"
        );
    }

    #[test]
    fn findings_filter_by_status() {
        let s = store_with_data();
        let all = list_findings(&s, "cmp-0000000000000001", None, 50).unwrap();
        assert_eq!(all.len(), 2);
        let confirmed =
            list_findings(&s, "cmp-0000000000000001", Some("reproducible"), 50).unwrap();
        assert_eq!(confirmed.len(), 1);
        assert_eq!(confirmed[0].finding_id, "fnd-0000000000000001");
        assert_eq!(confirmed[0].repro_successes, 5);
        assert_eq!(confirmed[0].notes, vec!["a note".to_string()]);
        assert_eq!(confirmed[0].evidence.as_ref().unwrap()["trigger_size"], 8);
    }

    #[test]
    fn an_unknown_status_filter_is_refused() {
        let s = store_with_data();
        let e = list_findings(&s, "cmp-0000000000000001", Some("probably-a-bug"), 10).unwrap_err();
        assert!(e.to_string().contains("unknown status"), "{e}");
    }

    #[test]
    fn get_finding_reports_a_missing_id() {
        let s = store_with_data();
        assert_eq!(
            get_finding(&s, "fnd-0000000000000001").unwrap().status,
            "reproducible"
        );
        assert_eq!(
            get_finding(&s, "fnd-0000000000009999").unwrap_err().kind(),
            "not_found"
        );
        assert!(get_finding(&s, "../../etc/passwd").is_err());
    }

    #[test]
    fn strategy_stats_are_readable() {
        let s = store_with_data();
        let rows = list_strategy_stats(&s, "cmp-0000000000000001").unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].strategy_id, "havoc");
        assert_eq!(rows[0].rounds, 40);
        assert_eq!(rows[0].findings, 1);
    }

    #[test]
    fn missing_store_reports_what_to_do() {
        let dir = std::env::temp_dir().join(format!("aether-no-store-{}", std::process::id()));
        let e = open_store(&dir).unwrap_err();
        assert_eq!(e.kind(), "not_found");
        assert!(e.to_string().contains("no campaign has been run"), "{e}");
    }
}
