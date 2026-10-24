//! Campaign metadata persistence on SQLite.
//!
//! The database holds metadata only: corpus *content* lives in the
//! content-addressed store on disk, and rows reference it by hash. That split
//! keeps the database small enough to stay fast while a campaign accumulates
//! gigabytes of test cases.
//!
//! Schema version is stored and checked. A database from a newer AETHER is
//! refused rather than half-understood, and migrations are explicit.
//!
//! Writes that must not be seen half-applied - adding an input, recording a
//! finding transition - go through a transaction.

use rusqlite::{params, Connection, OptionalExtension};
use std::path::Path;

use crate::error::{Error, Result};

/// Schema version this build creates and reads.
pub const SCHEMA_VERSION: i64 = 1;

pub struct Store {
    conn: Connection,
}

impl Store {
    /// Open or create the database at `path`, applying migrations as needed.
    pub fn open(path: &Path) -> Result<Self> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(|e| Error::io(parent, e))?;
        }
        let conn = Connection::open(path)?;
        Self::configure(&conn)?;
        let mut s = Store { conn };
        s.migrate()?;
        Ok(s)
    }

    /// In-memory database, for tests and for a dry run.
    pub fn open_in_memory() -> Result<Self> {
        let conn = Connection::open_in_memory()?;
        Self::configure(&conn)?;
        let mut s = Store { conn };
        s.migrate()?;
        Ok(s)
    }

    fn configure(conn: &Connection) -> Result<()> {
        // WAL lets a reader (a status query, an MCP request) run while the
        // campaign is writing. NORMAL synchronous is the right trade here:
        // losing the last few metadata rows to a machine crash is acceptable,
        // and fsync-per-commit would throttle the campaign loop.
        conn.pragma_update(None, "journal_mode", "WAL")?;
        conn.pragma_update(None, "synchronous", "NORMAL")?;
        conn.pragma_update(None, "foreign_keys", "ON")?;
        conn.busy_timeout(std::time::Duration::from_secs(10))?;
        Ok(())
    }

    fn migrate(&mut self) -> Result<()> {
        let found: Option<i64> = self
            .conn
            .query_row(
                "SELECT value FROM aether_meta WHERE key = 'schema_version'",
                [],
                |r| r.get(0),
            )
            .optional()
            .unwrap_or(None);

        match found {
            Some(v) if v == SCHEMA_VERSION => Ok(()),
            Some(v) if v > SCHEMA_VERSION => Err(Error::storage(
                "database",
                format!(
                    "schema version {v} was written by a newer AETHER (this build reads \
                     {SCHEMA_VERSION}); upgrade AETHER or use a separate output directory"
                ),
            )),
            Some(v) => Err(Error::storage(
                "database",
                format!("no migration path from schema version {v} to {SCHEMA_VERSION}"),
            )),
            None => self.create_schema(),
        }
    }

    fn create_schema(&mut self) -> Result<()> {
        let tx = self.conn.transaction()?;
        tx.execute_batch(
            r#"
            CREATE TABLE IF NOT EXISTS aether_meta (
                key   TEXT PRIMARY KEY,
                value INTEGER NOT NULL
            );

            CREATE TABLE IF NOT EXISTS campaigns (
                id           TEXT PRIMARY KEY,
                target_name  TEXT NOT NULL,
                profile      TEXT,
                seed         INTEGER NOT NULL,
                status       TEXT NOT NULL,
                config_toml  TEXT NOT NULL,
                created_ms   INTEGER NOT NULL,
                updated_ms   INTEGER NOT NULL,
                finished_ms  INTEGER,
                total_execs  INTEGER NOT NULL DEFAULT 0,
                total_edges  INTEGER NOT NULL DEFAULT 0,
                guard_count  INTEGER,
                notes        TEXT
            );

            -- Corpus metadata. Content lives in the CAS, referenced by hash.
            CREATE TABLE IF NOT EXISTS inputs (
                id            TEXT PRIMARY KEY,
                content_hash  TEXT NOT NULL,
                campaign_id   TEXT NOT NULL REFERENCES campaigns(id) ON DELETE CASCADE,
                strategy_id   TEXT,
                parent_id     TEXT,
                created_ms    INTEGER NOT NULL,
                size_bytes    INTEGER NOT NULL,
                exec_count    INTEGER NOT NULL DEFAULT 0,
                exec_micros   INTEGER NOT NULL DEFAULT 0,
                new_edges     INTEGER NOT NULL DEFAULT 0,
                touched_edges INTEGER NOT NULL DEFAULT 0,
                behavior_sig  TEXT,
                score         REAL NOT NULL DEFAULT 0,
                -- Set when this input reproduces a finding. Such an input is
                -- never evicted by corpus trimming.
                finding_id    TEXT,
                provenance    TEXT
            );
            CREATE INDEX IF NOT EXISTS inputs_campaign ON inputs(campaign_id);
            CREATE INDEX IF NOT EXISTS inputs_hash     ON inputs(content_hash);
            CREATE INDEX IF NOT EXISTS inputs_score    ON inputs(campaign_id, score DESC);
            -- One row per distinct content per campaign: this is what makes
            -- duplicate detection a constraint rather than a convention.
            CREATE UNIQUE INDEX IF NOT EXISTS inputs_unique_content
                ON inputs(campaign_id, content_hash);

            CREATE TABLE IF NOT EXISTS findings (
                id                 TEXT PRIMARY KEY,
                campaign_id        TEXT NOT NULL REFERENCES campaigns(id) ON DELETE CASCADE,
                status             TEXT NOT NULL,
                signature          TEXT NOT NULL,
                exit_class         TEXT NOT NULL,
                signal             INTEGER,
                exit_code          INTEGER,
                sanitizer_kind     TEXT,
                fault              TEXT,
                frames             TEXT,
                trigger_hash       TEXT NOT NULL,
                minimized_hash     TEXT,
                repro_attempts     INTEGER NOT NULL DEFAULT 0,
                repro_successes    INTEGER NOT NULL DEFAULT 0,
                duplicate_of       TEXT,
                created_ms         INTEGER NOT NULL,
                updated_ms         INTEGER NOT NULL,
                evidence           TEXT,
                validation_notes   TEXT
            );
            CREATE INDEX IF NOT EXISTS findings_campaign ON findings(campaign_id);
            CREATE INDEX IF NOT EXISTS findings_sig      ON findings(campaign_id, signature);

            -- Per-strategy accounting: what the scheduler's decisions were
            -- based on, kept so a report can show the evidence.
            CREATE TABLE IF NOT EXISTS strategy_stats (
                campaign_id   TEXT NOT NULL REFERENCES campaigns(id) ON DELETE CASCADE,
                strategy_id   TEXT NOT NULL,
                rounds        INTEGER NOT NULL DEFAULT 0,
                execs         INTEGER NOT NULL DEFAULT 0,
                value_sum     REAL NOT NULL DEFAULT 0,
                cost_micros   INTEGER NOT NULL DEFAULT 0,
                new_edges     INTEGER NOT NULL DEFAULT 0,
                findings      INTEGER NOT NULL DEFAULT 0,
                PRIMARY KEY (campaign_id, strategy_id)
            );

            CREATE TABLE IF NOT EXISTS events (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                campaign_id TEXT NOT NULL REFERENCES campaigns(id) ON DELETE CASCADE,
                ts_ms       INTEGER NOT NULL,
                kind        TEXT NOT NULL,
                detail      TEXT
            );
            CREATE INDEX IF NOT EXISTS events_campaign ON events(campaign_id, id);

            CREATE TABLE IF NOT EXISTS checkpoints (
                campaign_id TEXT PRIMARY KEY REFERENCES campaigns(id) ON DELETE CASCADE,
                ts_ms       INTEGER NOT NULL,
                state       TEXT NOT NULL
            );
            "#,
        )?;
        tx.execute(
            "INSERT OR REPLACE INTO aether_meta(key, value) VALUES ('schema_version', ?1)",
            params![SCHEMA_VERSION],
        )?;
        tx.commit()?;
        Ok(())
    }

    pub fn conn(&self) -> &Connection {
        &self.conn
    }

    pub fn conn_mut(&mut self) -> &mut Connection {
        &mut self.conn
    }

    pub fn schema_version(&self) -> Result<i64> {
        Ok(self.conn.query_row(
            "SELECT value FROM aether_meta WHERE key = 'schema_version'",
            [],
            |r| r.get(0),
        )?)
    }

    /// Append a campaign event. Events are the audit trail a report draws on.
    pub fn record_event(&self, campaign: &str, kind: &str, detail: Option<&str>) -> Result<()> {
        self.conn.execute(
            "INSERT INTO events(campaign_id, ts_ms, kind, detail) VALUES (?1, ?2, ?3, ?4)",
            params![campaign, crate::time::now_millis() as i64, kind, detail],
        )?;
        Ok(())
    }

    /// Read back recent events, newest first, bounded.
    pub fn recent_events(&self, campaign: &str, limit: usize) -> Result<Vec<CampaignEvent>> {
        let mut stmt = self.conn.prepare(
            "SELECT ts_ms, kind, detail FROM events WHERE campaign_id = ?1 \
             ORDER BY id DESC LIMIT ?2",
        )?;
        let rows = stmt.query_map(params![campaign, limit as i64], |r| {
            Ok(CampaignEvent {
                ts_ms: r.get::<_, i64>(0)? as u64,
                kind: r.get(1)?,
                detail: r.get(2)?,
            })
        })?;
        Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
    }
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct CampaignEvent {
    pub ts_ms: u64,
    pub kind: String,
    pub detail: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn store_with_campaign() -> Store {
        let s = Store::open_in_memory().unwrap();
        s.conn()
            .execute(
                "INSERT INTO campaigns(id, target_name, seed, status, config_toml, \
                 created_ms, updated_ms) VALUES ('cmp-1','t',1,'running','',0,0)",
                [],
            )
            .unwrap();
        s
    }

    #[test]
    fn fresh_database_gets_the_current_schema() {
        let s = Store::open_in_memory().unwrap();
        assert_eq!(s.schema_version().unwrap(), SCHEMA_VERSION);
    }

    #[test]
    fn reopening_a_database_is_idempotent() {
        let dir = std::env::temp_dir().join(format!("aether-db-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("meta.sqlite");
        let _ = std::fs::remove_file(&path);

        {
            let s = Store::open(&path).unwrap();
            s.conn()
                .execute(
                    "INSERT INTO campaigns(id, target_name, seed, status, config_toml, \
                     created_ms, updated_ms) VALUES ('cmp-x','t',7,'done','',1,1)",
                    [],
                )
                .unwrap();
        }
        {
            let s = Store::open(&path).unwrap();
            assert_eq!(s.schema_version().unwrap(), SCHEMA_VERSION);
            let n: i64 = s
                .conn()
                .query_row("SELECT count(*) FROM campaigns", [], |r| r.get(0))
                .unwrap();
            assert_eq!(n, 1, "reopening must not wipe or duplicate data");
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn newer_schema_version_is_refused_with_a_remedy() {
        let s = Store::open_in_memory().unwrap();
        s.conn()
            .execute(
                "UPDATE aether_meta SET value = ?1 WHERE key = 'schema_version'",
                params![SCHEMA_VERSION + 5],
            )
            .unwrap();
        // Re-running migration against the bumped version must refuse.
        let mut s2 = Store { conn: s.conn };
        let e = s2.migrate().unwrap_err();
        assert_eq!(e.kind(), "storage_failed");
        assert!(e.to_string().contains("newer AETHER"), "{e}");
    }

    #[test]
    fn duplicate_content_in_one_campaign_is_rejected_by_the_schema() {
        // Deduplication is enforced by a unique index, not by caller
        // discipline, so a bug elsewhere cannot create a duplicate row.
        let s = store_with_campaign();
        let insert = "INSERT INTO inputs(id, content_hash, campaign_id, created_ms, size_bytes) \
                      VALUES (?1, ?2, 'cmp-1', 0, 4)";
        s.conn().execute(insert, params!["inp-1", "aa00"]).unwrap();
        let err = s.conn().execute(insert, params!["inp-2", "aa00"]).unwrap_err();
        assert!(err.to_string().contains("UNIQUE"), "{err}");

        // The same content in a *different* campaign is fine.
        s.conn()
            .execute(
                "INSERT INTO campaigns(id, target_name, seed, status, config_toml, \
                 created_ms, updated_ms) VALUES ('cmp-2','t',1,'running','',0,0)",
                [],
            )
            .unwrap();
        s.conn()
            .execute(
                "INSERT INTO inputs(id, content_hash, campaign_id, created_ms, size_bytes) \
                 VALUES ('inp-3','aa00','cmp-2',0,4)",
                [],
            )
            .unwrap();
    }

    #[test]
    fn deleting_a_campaign_cascades_to_its_rows() {
        let s = store_with_campaign();
        s.conn()
            .execute(
                "INSERT INTO inputs(id, content_hash, campaign_id, created_ms, size_bytes) \
                 VALUES ('inp-1','ab',  'cmp-1', 0, 1)",
                [],
            )
            .unwrap();
        s.record_event("cmp-1", "started", None).unwrap();
        s.conn().execute("DELETE FROM campaigns WHERE id='cmp-1'", []).unwrap();

        for table in ["inputs", "events"] {
            let n: i64 = s
                .conn()
                .query_row(&format!("SELECT count(*) FROM {table}"), [], |r| r.get(0))
                .unwrap();
            assert_eq!(n, 0, "{table} rows outlived their campaign");
        }
    }

    #[test]
    fn events_round_trip_newest_first_and_bounded() {
        let s = store_with_campaign();
        for i in 0..10 {
            s.record_event("cmp-1", "tick", Some(&format!("n={i}"))).unwrap();
        }
        let got = s.recent_events("cmp-1", 3).unwrap();
        assert_eq!(got.len(), 3, "limit must be honoured");
        assert_eq!(got[0].detail.as_deref(), Some("n=9"), "newest first");
        assert_eq!(got[0].kind, "tick");
    }

    #[test]
    fn a_row_cannot_reference_a_missing_campaign() {
        let s = Store::open_in_memory().unwrap();
        let e = s
            .conn()
            .execute(
                "INSERT INTO inputs(id, content_hash, campaign_id, created_ms, size_bytes) \
                 VALUES ('inp-1','ab','does-not-exist',0,1)",
                [],
            )
            .unwrap_err();
        assert!(e.to_string().to_lowercase().contains("foreign key"), "{e}");
    }
}
