//! Corpus management: content-addressed storage plus ranked metadata.
//!
//! The corpus is the engine's memory of what is worth mutating. It owns:
//!
//! * deduplicated storage of every kept input ([`cas`]),
//! * metadata and provenance in SQLite, so a campaign can explain where an
//!   input came from and what it achieved,
//! * a multi-objective ranking ([`score`]) that decides what gets mutated next,
//! * retention, which trims the corpus without ever discarding an input that
//!   reproduces a finding.
//!
//! That last guarantee is enforced here rather than left to callers: an input
//! with a `finding_id` is excluded from eviction by the query that chooses
//! victims, so a trimming bug cannot lose evidence.

pub mod cas;
pub mod minimize;
pub mod score;

use rusqlite::{params, OptionalExtension};
use serde::{Deserialize, Serialize};
use std::path::Path;

use crate::config::CorpusWeights;
use crate::error::{Error, Result};
use crate::hash::{content_hash, ContentHash};
use crate::ids::{CampaignId, FindingId, InputId};
use crate::persist::Store;
use cas::ContentStore;
use score::{Score, ScoreInputs, ScoreNorms};

/// One corpus entry's metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InputRecord {
    pub id: InputId,
    pub content_hash: ContentHash,
    pub campaign_id: CampaignId,
    /// Strategy that produced it, `None` for an imported seed.
    pub strategy_id: Option<String>,
    /// Input it was mutated from, giving a provenance chain back to a seed.
    pub parent_id: Option<InputId>,
    pub created_ms: u64,
    pub size_bytes: usize,
    pub exec_count: u64,
    pub exec_micros: u64,
    pub new_edges: u32,
    pub touched_edges: u32,
    /// Groups inputs that drove the target the same way.
    pub behavior_sig: Option<String>,
    pub score: f64,
    /// Set when this input reproduces a finding. Such an input is never
    /// evicted, however poorly it ranks as an exploration seed.
    pub finding_id: Option<FindingId>,
}

/// What was added, or why nothing was.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AddOutcome {
    /// Stored as a new entry.
    Added(InputId),
    /// Content already present; the existing entry's id is returned.
    Duplicate(InputId),
    /// Refused, with a reason.
    Rejected(String),
}

pub struct Corpus {
    cas: ContentStore,
    campaign_id: CampaignId,
    norms: ScoreNorms,
    weights: CorpusWeights,
    max_inputs: usize,
    max_input_bytes: usize,
}

impl Corpus {
    pub fn open(
        root: &Path,
        campaign_id: CampaignId,
        weights: CorpusWeights,
        max_inputs: usize,
        max_input_bytes: usize,
    ) -> Result<Self> {
        campaign_id.validate()?;
        let cas = ContentStore::open(&root.join("objects"))?;
        // Clear anything an interrupted run left behind before it can be
        // mistaken for a stored object.
        cas.clean_temporaries()?;
        Ok(Corpus {
            cas,
            campaign_id,
            norms: ScoreNorms::default(),
            weights,
            max_inputs: max_inputs.max(1),
            max_input_bytes,
        })
    }

    pub fn content_store(&self) -> &ContentStore {
        &self.cas
    }

    pub fn norms(&self) -> &ScoreNorms {
        &self.norms
    }

    /// Add an input, deduplicating on content.
    ///
    /// Takes the store so metadata and content land together: content is
    /// written first, then the row, inside a transaction. If the row fails the
    /// object is simply unreferenced - wasted space, cleaned by retention -
    /// whereas the reverse order would leave a row pointing at nothing.
    pub fn add(
        &mut self,
        store: &mut Store,
        bytes: &[u8],
        meta: NewInput<'_>,
    ) -> Result<AddOutcome> {
        if bytes.len() > self.max_input_bytes {
            return Ok(AddOutcome::Rejected(format!(
                "{} bytes exceeds the configured ceiling of {}",
                bytes.len(),
                self.max_input_bytes
            )));
        }

        let hash = content_hash(bytes);
        if let Some(existing) = self.lookup_by_hash(store, &hash)? {
            return Ok(AddOutcome::Duplicate(existing));
        }

        self.cas.put(bytes)?;

        let inputs = ScoreInputs {
            new_edges: meta.new_edges,
            touched_edges: meta.touched_edges,
            novelty: meta.novelty,
            exec_micros: meta.exec_micros,
            size_bytes: bytes.len(),
            productive_children: 0,
            total_children: 0,
            signature_siblings: self.count_signature_siblings(store, meta.behavior_sig)?,
            state_transitions: meta.state_transitions,
        };
        let norms_moved = self.norms.observe(&inputs);
        let s = score::score(&inputs, &self.norms, &self.weights);

        let id = InputId::new();
        let tx = store.conn_mut().transaction()?;
        let affected = tx.execute(
            "INSERT OR IGNORE INTO inputs(id, content_hash, campaign_id, strategy_id, \
             parent_id, created_ms, size_bytes, exec_count, exec_micros, new_edges, \
             touched_edges, behavior_sig, score, finding_id, provenance) \
             VALUES (?1,?2,?3,?4,?5,?6,?7,1,?8,?9,?10,?11,?12,?13,?14)",
            params![
                id.as_str(),
                &hash,
                self.campaign_id.as_str(),
                meta.strategy_id,
                meta.parent_id.map(|p| p.as_str().to_string()),
                crate::time::now_millis() as i64,
                bytes.len() as i64,
                meta.exec_micros as i64,
                meta.new_edges as i64,
                meta.touched_edges as i64,
                meta.behavior_sig,
                s.total,
                meta.finding_id.map(|f| f.as_str().to_string()),
                serde_json::to_string(&s).unwrap_or_default(),
            ],
        )?;
        tx.commit()?;

        if affected == 0 {
            // Lost a race with another worker on the same content.
            if let Some(existing) = self.lookup_by_hash(store, &hash)? {
                return Ok(AddOutcome::Duplicate(existing));
            }
            return Ok(AddOutcome::Rejected("concurrent insert conflict".into()));
        }

        // A moved maximum makes every previously stored score relative to a
        // stale baseline, so refresh them. Maxima settle quickly, so this
        // runs a handful of times over a campaign rather than per insert.
        if norms_moved {
            self.rescore_all(store)?;
        }

        // Record the mutation as attempted against its parent, so mutation
        // productivity has a denominator.
        if let Some(parent) = meta.parent_id {
            store.conn().execute(
                "UPDATE inputs SET exec_count = exec_count + 1 WHERE id = ?1",
                params![parent.as_str()],
            )?;
        }

        Ok(AddOutcome::Added(id))
    }

    /// Recompute every stored score for this campaign against current norms.
    ///
    /// Scores are relative to corpus-wide maxima, so they are only comparable
    /// when they were all computed against the same ones. This is what keeps
    /// `ORDER BY score` meaningful.
    pub fn rescore_all(&self, store: &mut Store) -> Result<u64> {
        // (id, new_edges, touched_edges, exec_micros, size_bytes, exec_count, behavior_sig)
        type ScoreRow = (String, u32, u32, u64, usize, u64, Option<String>);
        let rows: Vec<ScoreRow> = {
            let mut stmt = store.conn().prepare(
                "SELECT id, new_edges, touched_edges, exec_micros, size_bytes, exec_count, \
                 behavior_sig FROM inputs WHERE campaign_id = ?1",
            )?;
            let it = stmt.query_map(params![self.campaign_id.as_str()], |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, i64>(1)? as u32,
                    r.get::<_, i64>(2)? as u32,
                    r.get::<_, i64>(3)? as u64,
                    r.get::<_, i64>(4)? as usize,
                    r.get::<_, i64>(5)? as u64,
                    r.get::<_, Option<String>>(6)?,
                ))
            })?;
            it.collect::<rusqlite::Result<Vec<_>>>()?
        };

        // Sibling counts per behaviour signature, computed once rather than
        // with a correlated subquery per row.
        let mut sibling_counts: std::collections::HashMap<String, u32> =
            std::collections::HashMap::new();
        for (_, _, _, _, _, _, sig) in &rows {
            if let Some(sig) = sig {
                *sibling_counts.entry(sig.clone()).or_insert(0) += 1;
            }
        }

        let tx = store.conn_mut().transaction()?;
        let mut n = 0u64;
        {
            let mut up = tx.prepare("UPDATE inputs SET score = ?2 WHERE id = ?1")?;
            for (id, new_edges, touched, micros, size, children, sig) in &rows {
                let siblings = sig
                    .as_ref()
                    .and_then(|s| sibling_counts.get(s))
                    .copied()
                    .unwrap_or(0)
                    .saturating_sub(1);
                let s = score::score(
                    &ScoreInputs {
                        new_edges: *new_edges,
                        touched_edges: *touched,
                        novelty: 0.0,
                        exec_micros: *micros,
                        size_bytes: *size,
                        productive_children: 0,
                        total_children: *children as u32,
                        signature_siblings: siblings,
                        state_transitions: 0,
                    },
                    &self.norms,
                    &self.weights,
                );
                up.execute(params![id, s.total])?;
                n += 1;
            }
        }
        tx.commit()?;
        Ok(n)
    }

    fn lookup_by_hash(&self, store: &Store, hash: &str) -> Result<Option<InputId>> {
        let got: Option<String> = store
            .conn()
            .query_row(
                "SELECT id FROM inputs WHERE campaign_id = ?1 AND content_hash = ?2",
                params![self.campaign_id.as_str(), hash],
                |r| r.get(0),
            )
            .optional()?;
        Ok(got.map(InputId::from_string))
    }

    fn count_signature_siblings(&self, store: &Store, sig: Option<&str>) -> Result<u32> {
        let Some(sig) = sig else { return Ok(0) };
        let n: i64 = store.conn().query_row(
            "SELECT count(*) FROM inputs WHERE campaign_id = ?1 AND behavior_sig = ?2",
            params![self.campaign_id.as_str(), sig],
            |r| r.get(0),
        )?;
        Ok(n as u32)
    }

    pub fn get_bytes(&self, hash: &str) -> Result<Vec<u8>> {
        self.cas.get(hash)
    }

    pub fn len(&self, store: &Store) -> Result<u64> {
        let n: i64 = store.conn().query_row(
            "SELECT count(*) FROM inputs WHERE campaign_id = ?1",
            params![self.campaign_id.as_str()],
            |r| r.get(0),
        )?;
        Ok(n as u64)
    }

    pub fn is_empty(&self, store: &Store) -> Result<bool> {
        Ok(self.len(store)? == 0)
    }

    /// Highest-ranked entries, for a strategy to draw mutation bases from.
    pub fn top(&self, store: &Store, limit: usize) -> Result<Vec<InputRecord>> {
        let mut stmt = store.conn().prepare(
            "SELECT id, content_hash, strategy_id, parent_id, created_ms, size_bytes, \
             exec_count, exec_micros, new_edges, touched_edges, behavior_sig, score, finding_id \
             FROM inputs WHERE campaign_id = ?1 ORDER BY score DESC, id ASC LIMIT ?2",
        )?;
        let rows = stmt.query_map(params![self.campaign_id.as_str(), limit as i64], |r| {
            Ok(self.row_to_record(r))
        })?;
        Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
    }

    fn row_to_record(&self, r: &rusqlite::Row<'_>) -> InputRecord {
        InputRecord {
            id: InputId::from_string(r.get::<_, String>(0).unwrap_or_default()),
            content_hash: r.get(1).unwrap_or_default(),
            campaign_id: self.campaign_id.clone(),
            strategy_id: r.get(2).ok(),
            parent_id: r
                .get::<_, Option<String>>(3)
                .ok()
                .flatten()
                .map(InputId::from_string),
            created_ms: r.get::<_, i64>(4).unwrap_or(0) as u64,
            size_bytes: r.get::<_, i64>(5).unwrap_or(0) as usize,
            exec_count: r.get::<_, i64>(6).unwrap_or(0) as u64,
            exec_micros: r.get::<_, i64>(7).unwrap_or(0) as u64,
            new_edges: r.get::<_, i64>(8).unwrap_or(0) as u32,
            touched_edges: r.get::<_, i64>(9).unwrap_or(0) as u32,
            behavior_sig: r.get::<_, Option<String>>(10).ok().flatten(),
            score: r.get::<_, f64>(11).unwrap_or(0.0),
            finding_id: r
                .get::<_, Option<String>>(12)
                .ok()
                .flatten()
                .map(FindingId::from_string),
        }
    }

    /// Sample an entry weighted by score, for a strategy picking a base.
    ///
    /// Weighted rather than always taking the best: a corpus that only ever
    /// mutates its top entry stops exploring.
    pub fn sample(
        &self,
        store: &Store,
        rng: &mut crate::rng::Rng,
        pool: usize,
    ) -> Result<Option<InputRecord>> {
        let candidates = self.top(store, pool.max(1))?;
        if candidates.is_empty() {
            return Ok(None);
        }
        // Floor each weight so even a zero-scored entry can be drawn.
        let weights: Vec<f64> = candidates.iter().map(|c| c.score.max(0.0) + 0.01).collect();
        Ok(rng.weighted_index(&weights).map(|i| candidates[i].clone()))
    }

    /// Mark that mutating `parent` produced something worthwhile, which feeds
    /// the mutation-productivity term of its score.
    pub fn record_productive_child(&self, store: &Store, parent: &InputId) -> Result<()> {
        store.conn().execute(
            "UPDATE inputs SET new_edges = new_edges WHERE id = ?1",
            params![parent.as_str()],
        )?;
        store.conn().execute(
            "UPDATE inputs SET score = MIN(1.0, score + 0.01) WHERE id = ?1",
            params![parent.as_str()],
        )?;
        Ok(())
    }

    /// Attach a finding to the input that triggered it, which also makes the
    /// input permanently exempt from eviction.
    pub fn mark_finding_input(
        &self,
        store: &Store,
        input: &InputId,
        finding: &FindingId,
    ) -> Result<()> {
        store.conn().execute(
            "UPDATE inputs SET finding_id = ?2 WHERE id = ?1",
            params![input.as_str(), finding.as_str()],
        )?;
        Ok(())
    }

    /// Trim the corpus to its configured ceiling, lowest-scoring first.
    ///
    /// Returns how many entries were removed. Inputs tied to a finding are
    /// excluded by the selection query itself, so no caller can trim away
    /// evidence by mistake.
    pub fn enforce_retention(&self, store: &mut Store) -> Result<u64> {
        let total = self.len(store)?;
        if total as usize <= self.max_inputs {
            return Ok(0);
        }
        let excess = total as usize - self.max_inputs;

        let victims: Vec<(String, String)> = {
            let mut stmt = store.conn().prepare(
                "SELECT id, content_hash FROM inputs \
                 WHERE campaign_id = ?1 AND finding_id IS NULL \
                 ORDER BY score ASC, id ASC LIMIT ?2",
            )?;
            let rows = stmt.query_map(params![self.campaign_id.as_str(), excess as i64], |r| {
                Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?))
            })?;
            rows.collect::<rusqlite::Result<Vec<_>>>()?
        };

        let mut removed = 0u64;
        let tx = store.conn_mut().transaction()?;
        for (id, _) in &victims {
            tx.execute("DELETE FROM inputs WHERE id = ?1", params![id])?;
            removed += 1;
        }
        tx.commit()?;

        // Remove content only once no row references it, in this campaign or
        // any other.
        for (_, hash) in &victims {
            let refs: i64 = store.conn().query_row(
                "SELECT count(*) FROM inputs WHERE content_hash = ?1",
                params![hash],
                |r| r.get(0),
            )?;
            if refs == 0 {
                self.cas.remove(hash)?;
            }
        }
        Ok(removed)
    }

    /// Export every entry as files in `dir`, named by content hash.
    pub fn export(&self, store: &Store, dir: &Path) -> Result<u64> {
        std::fs::create_dir_all(dir).map_err(|e| Error::io(dir, e))?;
        let mut stmt = store
            .conn()
            .prepare("SELECT content_hash FROM inputs WHERE campaign_id = ?1")?;
        let rows = stmt.query_map(params![self.campaign_id.as_str()], |r| {
            r.get::<_, String>(0)
        })?;
        let mut n = 0;
        for hash in rows {
            let hash = hash?;
            let bytes = self.cas.get(&hash)?;
            let out = dir.join(&hash);
            std::fs::write(&out, &bytes).map_err(|e| Error::io(&out, e))?;
            n += 1;
        }
        Ok(n)
    }

    /// Import seed files from `dir`. Returns (added, duplicates, rejected).
    pub fn import_seeds(&mut self, store: &mut Store, dir: &Path) -> Result<(u64, u64, u64)> {
        let entries = std::fs::read_dir(dir).map_err(|e| Error::io(dir, e))?;
        let (mut added, mut dup, mut rejected) = (0, 0, 0);
        for e in entries.flatten() {
            let p = e.path();
            // Only regular files, and never through a symlink: a seed
            // directory is attacker-adjacent input.
            let Ok(meta) = std::fs::symlink_metadata(&p) else {
                continue;
            };
            if !meta.is_file() {
                continue;
            }
            let Ok(bytes) = std::fs::read(&p) else {
                rejected += 1;
                continue;
            };
            match self.add(
                store,
                &bytes,
                NewInput {
                    strategy_id: Some("imported-seed"),
                    ..Default::default()
                },
            )? {
                AddOutcome::Added(_) => added += 1,
                AddOutcome::Duplicate(_) => dup += 1,
                AddOutcome::Rejected(_) => rejected += 1,
            }
        }
        Ok((added, dup, rejected))
    }

    /// Per-campaign corpus statistics for status output and reports.
    pub fn stats(&self, store: &Store) -> Result<CorpusStats> {
        let (bytes, objects) = self.cas.usage()?;
        let row: (i64, Option<f64>, Option<i64>, Option<i64>) = store.conn().query_row(
            "SELECT count(*), avg(score), sum(size_bytes), count(DISTINCT behavior_sig) \
             FROM inputs WHERE campaign_id = ?1",
            params![self.campaign_id.as_str()],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
        )?;
        let with_findings: i64 = store.conn().query_row(
            "SELECT count(*) FROM inputs WHERE campaign_id = ?1 AND finding_id IS NOT NULL",
            params![self.campaign_id.as_str()],
            |r| r.get(0),
        )?;
        Ok(CorpusStats {
            entries: row.0 as u64,
            mean_score: row.1.unwrap_or(0.0),
            total_input_bytes: row.2.unwrap_or(0) as u64,
            distinct_behaviors: row.3.unwrap_or(0) as u64,
            finding_inputs: with_findings as u64,
            store_bytes: bytes,
            store_objects: objects,
        })
    }
}

/// Metadata supplied when adding an input.
#[derive(Debug, Clone, Default)]
pub struct NewInput<'a> {
    pub strategy_id: Option<&'a str>,
    pub parent_id: Option<&'a InputId>,
    pub new_edges: u32,
    pub touched_edges: u32,
    pub novelty: f64,
    pub exec_micros: u64,
    pub behavior_sig: Option<&'a str>,
    pub state_transitions: u32,
    pub finding_id: Option<&'a FindingId>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CorpusStats {
    pub entries: u64,
    pub mean_score: f64,
    pub total_input_bytes: u64,
    pub distinct_behaviors: u64,
    /// Entries that reproduce a finding, and so are retention-exempt.
    pub finding_inputs: u64,
    pub store_bytes: u64,
    pub store_objects: u64,
}

/// Score components for one input, recomputed from current norms.
pub fn rescore(record: &InputRecord, norms: &ScoreNorms, weights: &CorpusWeights) -> Score {
    score::score(
        &ScoreInputs {
            new_edges: record.new_edges,
            touched_edges: record.touched_edges,
            novelty: 0.0,
            exec_micros: record.exec_micros,
            size_bytes: record.size_bytes,
            productive_children: 0,
            total_children: record.exec_count as u32,
            signature_siblings: 0,
            state_transitions: 0,
        },
        norms,
        weights,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Fixture {
        _dir: std::path::PathBuf,
        corpus: Corpus,
        store: Store,
    }

    impl Fixture {
        fn new(max_inputs: usize) -> Self {
            let dir = std::env::temp_dir().join(format!(
                "aether-corpus-{}-{}",
                std::process::id(),
                InputId::new()
            ));
            std::fs::create_dir_all(&dir).unwrap();
            let mut store = Store::open_in_memory().unwrap();
            let cid = CampaignId::new();
            store
                .conn_mut()
                .execute(
                    "INSERT INTO campaigns(id, target_name, seed, status, config_toml, \
                     created_ms, updated_ms) VALUES (?1,'t',1,'running','',0,0)",
                    params![cid.as_str()],
                )
                .unwrap();
            let corpus =
                Corpus::open(&dir, cid, CorpusWeights::default(), max_inputs, 1 << 20).unwrap();
            Fixture {
                _dir: dir,
                corpus,
                store,
            }
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self._dir);
        }
    }

    #[test]
    fn adds_and_deduplicates() {
        let mut f = Fixture::new(100);
        let a = f
            .corpus
            .add(&mut f.store, b"hello", NewInput::default())
            .unwrap();
        assert!(matches!(a, AddOutcome::Added(_)));

        let b = f
            .corpus
            .add(&mut f.store, b"hello", NewInput::default())
            .unwrap();
        match (a, b) {
            (AddOutcome::Added(id1), AddOutcome::Duplicate(id2)) => assert_eq!(id1, id2),
            other => panic!("expected a duplicate pointing at the original: {other:?}"),
        }
        assert_eq!(f.corpus.len(&f.store).unwrap(), 1);
    }

    #[test]
    fn oversized_inputs_are_rejected_with_a_reason() {
        let dir = std::env::temp_dir().join(format!("aether-corpus-big-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let mut store = Store::open_in_memory().unwrap();
        let cid = CampaignId::new();
        store
            .conn_mut()
            .execute(
                "INSERT INTO campaigns(id, target_name, seed, status, config_toml, \
                 created_ms, updated_ms) VALUES (?1,'t',1,'running','',0,0)",
                params![cid.as_str()],
            )
            .unwrap();
        let mut c = Corpus::open(&dir, cid, CorpusWeights::default(), 10, 16).unwrap();
        match c.add(&mut store, &[0u8; 64], NewInput::default()).unwrap() {
            AddOutcome::Rejected(r) => assert!(r.contains("exceeds"), "{r}"),
            other => panic!("expected rejection, got {other:?}"),
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn higher_coverage_ranks_higher_whatever_the_insert_order() {
        // Scores are relative to corpus-wide maxima, so an input added when
        // the maximum was lower must not keep an inflated score. Both orders
        // are checked because the failure only showed up in one of them.
        for ascending in [true, false] {
            let mut f = Fixture::new(100);
            let pairs: Vec<(&[u8], u32)> = if ascending {
                vec![(b"low", 1), (b"high", 50)]
            } else {
                vec![(b"high", 50), (b"low", 1)]
            };
            for (data, edges) in pairs {
                f.corpus
                    .add(
                        &mut f.store,
                        data,
                        NewInput {
                            new_edges: edges,
                            ..Default::default()
                        },
                    )
                    .unwrap();
            }
            let top = f.corpus.top(&f.store, 10).unwrap();
            assert_eq!(top.len(), 2);
            assert_eq!(
                f.corpus.get_bytes(&top[0].content_hash).unwrap(),
                b"high",
                "ranking depended on insert order (ascending = {ascending})"
            );
        }
    }

    #[test]
    fn scores_are_refreshed_when_a_maximum_moves() {
        let mut f = Fixture::new(100);
        f.corpus
            .add(
                &mut f.store,
                b"first",
                NewInput {
                    new_edges: 2,
                    ..Default::default()
                },
            )
            .unwrap();
        let before = f.corpus.top(&f.store, 1).unwrap()[0].score;

        // A far better input raises the coverage maximum, which must deflate
        // the first input's relative score.
        f.corpus
            .add(
                &mut f.store,
                b"better",
                NewInput {
                    new_edges: 200,
                    ..Default::default()
                },
            )
            .unwrap();
        let first_after = f
            .corpus
            .top(&f.store, 10)
            .unwrap()
            .into_iter()
            .find(|r| f.corpus.get_bytes(&r.content_hash).unwrap() == b"first")
            .unwrap();
        assert!(
            first_after.score < before,
            "stale score kept: {} then {}",
            before,
            first_after.score
        );
    }

    #[test]
    fn retention_trims_lowest_scoring_entries_first() {
        let mut f = Fixture::new(3);
        for i in 0..6u32 {
            let data = format!("input-{i}");
            f.corpus
                .add(
                    &mut f.store,
                    data.as_bytes(),
                    NewInput {
                        new_edges: i,
                        ..Default::default()
                    },
                )
                .unwrap();
        }
        assert_eq!(f.corpus.len(&f.store).unwrap(), 6);
        let removed = f.corpus.enforce_retention(&mut f.store).unwrap();
        assert_eq!(removed, 3);
        assert_eq!(f.corpus.len(&f.store).unwrap(), 3);

        // The survivors must be the highest-coverage ones.
        let survivors = f.corpus.top(&f.store, 10).unwrap();
        let kept: Vec<u32> = survivors.iter().map(|s| s.new_edges).collect();
        assert!(kept.contains(&5), "the best entry was evicted: {kept:?}");
        assert!(!kept.contains(&0), "the worst entry survived: {kept:?}");
    }

    #[test]
    fn retention_never_evicts_an_input_that_reproduces_a_finding() {
        // The guarantee that makes trimming safe: evidence is not exploration
        // material and must not be lost when the corpus is trimmed.
        let mut f = Fixture::new(1);
        let finding = FindingId::new();

        // A poorly-ranked input that reproduces a finding.
        let evidence = match f
            .corpus
            .add(
                &mut f.store,
                b"crasher",
                NewInput {
                    new_edges: 0,
                    ..Default::default()
                },
            )
            .unwrap()
        {
            AddOutcome::Added(id) => id,
            other => panic!("{other:?}"),
        };
        f.corpus
            .mark_finding_input(&f.store, &evidence, &finding)
            .unwrap();

        // Several better-ranked ordinary inputs.
        for i in 1..5u32 {
            let d = format!("ordinary-{i}");
            f.corpus
                .add(
                    &mut f.store,
                    d.as_bytes(),
                    NewInput {
                        new_edges: i * 10,
                        ..Default::default()
                    },
                )
                .unwrap();
        }

        f.corpus.enforce_retention(&mut f.store).unwrap();
        let remaining = f.corpus.top(&f.store, 100).unwrap();
        assert!(
            remaining.iter().any(|r| r.id == evidence),
            "the finding's input was evicted by retention"
        );
        // And its content is still readable.
        assert_eq!(
            f.corpus
                .get_bytes(
                    &remaining
                        .iter()
                        .find(|r| r.id == evidence)
                        .unwrap()
                        .content_hash
                )
                .unwrap(),
            b"crasher"
        );
    }

    #[test]
    fn provenance_chain_is_recorded() {
        let mut f = Fixture::new(100);
        let parent = match f
            .corpus
            .add(
                &mut f.store,
                b"seed",
                NewInput {
                    strategy_id: Some("imported-seed"),
                    ..Default::default()
                },
            )
            .unwrap()
        {
            AddOutcome::Added(id) => id,
            o => panic!("{o:?}"),
        };
        let child = match f
            .corpus
            .add(
                &mut f.store,
                b"mutated",
                NewInput {
                    strategy_id: Some("havoc"),
                    parent_id: Some(&parent),
                    ..Default::default()
                },
            )
            .unwrap()
        {
            AddOutcome::Added(id) => id,
            o => panic!("{o:?}"),
        };
        let all = f.corpus.top(&f.store, 10).unwrap();
        let c = all.iter().find(|r| r.id == child).unwrap();
        assert_eq!(c.parent_id.as_ref(), Some(&parent));
        assert_eq!(c.strategy_id.as_deref(), Some("havoc"));
    }

    #[test]
    fn sampling_is_reproducible_for_a_fixed_seed() {
        let mut f = Fixture::new(100);
        for i in 0..20u32 {
            let d = format!("i{i}");
            f.corpus
                .add(
                    &mut f.store,
                    d.as_bytes(),
                    NewInput {
                        new_edges: i,
                        ..Default::default()
                    },
                )
                .unwrap();
        }
        let draw = |seed: u64| {
            let mut rng = crate::rng::Rng::from_seed(seed);
            (0..10)
                .map(|_| {
                    f.corpus
                        .sample(&f.store, &mut rng, 20)
                        .unwrap()
                        .map(|r| r.id.as_str().to_string())
                })
                .collect::<Vec<_>>()
        };
        assert_eq!(draw(7), draw(7), "a fixed seed must replay the same draws");
        assert_ne!(draw(7), draw(8));
    }

    #[test]
    fn sampling_an_empty_corpus_yields_none() {
        let f = Fixture::new(10);
        let mut rng = crate::rng::Rng::from_seed(1);
        assert!(f.corpus.sample(&f.store, &mut rng, 8).unwrap().is_none());
        assert!(f.corpus.is_empty(&f.store).unwrap());
    }

    #[test]
    fn export_and_import_round_trip() {
        let mut f = Fixture::new(100);
        for i in 0..5u32 {
            let d = format!("payload-{i}");
            f.corpus
                .add(&mut f.store, d.as_bytes(), NewInput::default())
                .unwrap();
        }
        let out = f._dir.join("exported");
        assert_eq!(f.corpus.export(&f.store, &out).unwrap(), 5);

        // Import into a fresh corpus: everything should arrive, and a second
        // import of the same directory should be all duplicates.
        let mut f2 = Fixture::new(100);
        let (added, dup, rejected) = f2.corpus.import_seeds(&mut f2.store, &out).unwrap();
        assert_eq!((added, dup, rejected), (5, 0, 0));
        let (added2, dup2, _) = f2.corpus.import_seeds(&mut f2.store, &out).unwrap();
        assert_eq!((added2, dup2), (0, 5), "re-import must deduplicate");
    }

    #[test]
    fn stats_report_the_corpus_shape() {
        let mut f = Fixture::new(100);
        f.corpus
            .add(
                &mut f.store,
                b"a",
                NewInput {
                    behavior_sig: Some("sig-1"),
                    ..Default::default()
                },
            )
            .unwrap();
        f.corpus
            .add(
                &mut f.store,
                b"bb",
                NewInput {
                    behavior_sig: Some("sig-1"),
                    ..Default::default()
                },
            )
            .unwrap();
        f.corpus
            .add(
                &mut f.store,
                b"ccc",
                NewInput {
                    behavior_sig: Some("sig-2"),
                    ..Default::default()
                },
            )
            .unwrap();
        let s = f.corpus.stats(&f.store).unwrap();
        assert_eq!(s.entries, 3);
        assert_eq!(s.total_input_bytes, 6);
        assert_eq!(s.distinct_behaviors, 2);
        assert_eq!(s.finding_inputs, 0);
        assert_eq!(s.store_objects, 3);
    }
}
