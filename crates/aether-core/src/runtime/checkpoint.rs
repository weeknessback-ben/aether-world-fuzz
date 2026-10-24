//! Campaign checkpoints, so an interrupted campaign can resume instead of
//! starting over.
//!
//! A checkpoint holds the state that cannot be recomputed: the coverage map
//! (which decides what counts as novel), the scheduler's learned estimates,
//! and each strategy's internal state. The corpus itself is already durable -
//! content in the store, metadata in SQLite - so it is referenced rather than
//! copied.
//!
//! The coverage map is the one bulky item, at 64 KiB. It is run-length encoded
//! before serialisation because a real map is overwhelmingly zero, which takes
//! it to a few hundred bytes in practice.

use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};
use crate::exec::shm::MAP_SIZE;
use crate::persist::Store;

/// Format version. A checkpoint from a newer build is refused rather than
/// half-read, since a misread coverage map would silently corrupt novelty
/// detection for the whole resumed campaign.
pub const CHECKPOINT_VERSION: u32 = 1;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Checkpoint {
    pub version: u32,
    pub campaign_id: String,
    pub saved_at_ms: u64,
    pub total_executions: u64,
    pub elapsed_ms: u64,
    /// Run-length encoded coverage map: `(value, run_length)` pairs.
    pub coverage_rle: Vec<(u8, u32)>,
    pub guard_count: Option<u32>,
    /// Scheduler state, as exported by the bandit.
    pub scheduler: serde_json::Value,
    /// Per-strategy state, keyed by strategy id.
    pub strategies: Vec<(String, serde_json::Value)>,
    /// Comparison constants learned so far, so a resumed campaign does not
    /// have to rediscover the gates it already walked.
    pub cmp_tokens: Vec<(u64, u8)>,
}

/// Run-length encode a coverage map.
pub fn encode_map(map: &[u8; MAP_SIZE]) -> Vec<(u8, u32)> {
    let mut out: Vec<(u8, u32)> = Vec::new();
    let mut current = map[0];
    let mut run = 1u32;
    for &b in &map[1..] {
        if b == current && run < u32::MAX {
            run += 1;
        } else {
            out.push((current, run));
            current = b;
            run = 1;
        }
    }
    out.push((current, run));
    out
}

/// Decode a run-length encoded map.
///
/// Refuses an encoding whose runs do not sum to exactly the map size: a short
/// or long encoding would leave part of the map at whatever the buffer held,
/// which would corrupt novelty detection in a way that is very hard to notice.
pub fn decode_map(rle: &[(u8, u32)]) -> Result<Box<[u8; MAP_SIZE]>> {
    let total: u64 = rle.iter().map(|(_, n)| *n as u64).sum();
    if total != MAP_SIZE as u64 {
        return Err(Error::storage(
            "checkpoint",
            format!("coverage encoding covers {total} bytes, expected {MAP_SIZE}"),
        ));
    }
    let mut map = Box::new([0u8; MAP_SIZE]);
    let mut i = 0usize;
    for (value, run) in rle {
        for _ in 0..*run {
            map[i] = *value;
            i += 1;
        }
    }
    Ok(map)
}

impl Checkpoint {
    /// Persist, replacing any previous checkpoint for this campaign.
    pub fn save(&self, store: &Store) -> Result<()> {
        let json = serde_json::to_string(self)?;
        store.conn().execute(
            "INSERT INTO checkpoints(campaign_id, ts_ms, state) VALUES (?1, ?2, ?3) \
             ON CONFLICT(campaign_id) DO UPDATE SET ts_ms = ?2, state = ?3",
            rusqlite::params![&self.campaign_id, self.saved_at_ms as i64, json],
        )?;
        Ok(())
    }

    pub fn load(store: &Store, campaign_id: &str) -> Result<Option<Self>> {
        use rusqlite::OptionalExtension;
        let json: Option<String> = store
            .conn()
            .query_row(
                "SELECT state FROM checkpoints WHERE campaign_id = ?1",
                rusqlite::params![campaign_id],
                |r| r.get(0),
            )
            .optional()?;
        let Some(json) = json else { return Ok(None) };
        let cp: Checkpoint = serde_json::from_str(&json)?;
        if cp.version > CHECKPOINT_VERSION {
            return Err(Error::storage(
                "checkpoint",
                format!(
                    "checkpoint version {} was written by a newer AETHER (this build reads \
                     {CHECKPOINT_VERSION}); start a fresh campaign instead of resuming",
                    cp.version
                ),
            ));
        }
        Ok(Some(cp))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn map_with(slots: &[(usize, u8)]) -> Box<[u8; MAP_SIZE]> {
        let mut m = Box::new([0u8; MAP_SIZE]);
        for (i, v) in slots {
            m[*i] = *v;
        }
        m
    }

    fn checkpoint(map: &[u8; MAP_SIZE]) -> Checkpoint {
        Checkpoint {
            version: CHECKPOINT_VERSION,
            campaign_id: "cmp-0000000000000001".into(),
            saved_at_ms: 1_700_000_000_000,
            total_executions: 12_345,
            elapsed_ms: 60_000,
            coverage_rle: encode_map(map),
            guard_count: Some(190),
            scheduler: serde_json::json!({ "round": 40 }),
            strategies: vec![("havoc".into(), serde_json::json!({ "stack_floor": 3 }))],
            cmp_tokens: vec![(0xDEAD_BEEF, 4)],
        }
    }

    #[test]
    fn map_encoding_round_trips() {
        let m = map_with(&[(0, 1), (100, 8), (65_535, 2)]);
        let decoded = decode_map(&encode_map(&m)).unwrap();
        assert_eq!(&decoded[..], &m[..]);
    }

    #[test]
    fn a_sparse_map_encodes_compactly() {
        // The reason for encoding at all: a real map is almost entirely zero.
        let m = map_with(&[(10, 1), (20, 2), (30, 4)]);
        let rle = encode_map(&m);
        assert!(rle.len() < 16, "sparse map produced {} runs", rle.len());
        let bytes = serde_json::to_string(&rle).unwrap().len();
        assert!(bytes < 1024, "sparse map serialised to {bytes} bytes");
    }

    #[test]
    fn an_empty_map_round_trips() {
        let m = Box::new([0u8; MAP_SIZE]);
        let rle = encode_map(&m);
        assert_eq!(rle.len(), 1, "an all-zero map is one run");
        assert_eq!(&decode_map(&rle).unwrap()[..], &m[..]);
    }

    #[test]
    fn a_full_map_round_trips() {
        let m = Box::new([0xAAu8; MAP_SIZE]);
        assert_eq!(&decode_map(&encode_map(&m)).unwrap()[..], &m[..]);
    }

    #[test]
    fn a_truncated_encoding_is_refused() {
        // Decoding a short encoding would leave the rest of the map at
        // whatever the buffer held, quietly corrupting novelty detection.
        let short = vec![(1u8, 10u32)];
        let e = decode_map(&short).unwrap_err();
        assert!(e.to_string().contains("expected"), "{e}");

        let long = vec![(1u8, MAP_SIZE as u32 + 5)];
        assert!(decode_map(&long).is_err());
        assert!(decode_map(&[]).is_err());
    }

    #[test]
    fn checkpoint_saves_and_loads() {
        let mut store = Store::open_in_memory().unwrap();
        store
            .conn_mut()
            .execute(
                "INSERT INTO campaigns(id, target_name, seed, status, config_toml, \
                 created_ms, updated_ms) VALUES ('cmp-0000000000000001','t',1,'running','',0,0)",
                [],
            )
            .unwrap();

        let m = map_with(&[(5, 1), (9, 8)]);
        let cp = checkpoint(&m);
        cp.save(&store).unwrap();

        let back = Checkpoint::load(&store, "cmp-0000000000000001")
            .unwrap()
            .unwrap();
        assert_eq!(back.total_executions, 12_345);
        assert_eq!(back.guard_count, Some(190));
        assert_eq!(back.scheduler["round"], 40);
        assert_eq!(back.strategies[0].0, "havoc");
        assert_eq!(back.cmp_tokens, vec![(0xDEAD_BEEF, 4)]);
        assert_eq!(&decode_map(&back.coverage_rle).unwrap()[..], &m[..]);
    }

    #[test]
    fn saving_twice_replaces_rather_than_duplicating() {
        let mut store = Store::open_in_memory().unwrap();
        store
            .conn_mut()
            .execute(
                "INSERT INTO campaigns(id, target_name, seed, status, config_toml, \
                 created_ms, updated_ms) VALUES ('cmp-0000000000000001','t',1,'running','',0,0)",
                [],
            )
            .unwrap();
        let m = Box::new([0u8; MAP_SIZE]);
        let mut cp = checkpoint(&m);
        cp.save(&store).unwrap();
        cp.total_executions = 99_999;
        cp.save(&store).unwrap();

        let n: i64 = store
            .conn()
            .query_row("SELECT count(*) FROM checkpoints", [], |r| r.get(0))
            .unwrap();
        assert_eq!(n, 1, "checkpoints must be replaced, not accumulated");
        let back = Checkpoint::load(&store, "cmp-0000000000000001")
            .unwrap()
            .unwrap();
        assert_eq!(back.total_executions, 99_999);
    }

    #[test]
    fn missing_checkpoint_is_none_not_an_error() {
        let store = Store::open_in_memory().unwrap();
        assert!(Checkpoint::load(&store, "cmp-does-not-exist")
            .unwrap()
            .is_none());
    }

    #[test]
    fn a_newer_checkpoint_version_is_refused_with_a_remedy() {
        let mut store = Store::open_in_memory().unwrap();
        store
            .conn_mut()
            .execute(
                "INSERT INTO campaigns(id, target_name, seed, status, config_toml, \
                 created_ms, updated_ms) VALUES ('cmp-0000000000000001','t',1,'running','',0,0)",
                [],
            )
            .unwrap();
        let m = Box::new([0u8; MAP_SIZE]);
        let mut cp = checkpoint(&m);
        cp.version = CHECKPOINT_VERSION + 3;
        cp.save(&store).unwrap();

        let e = Checkpoint::load(&store, "cmp-0000000000000001").unwrap_err();
        assert!(e.to_string().contains("newer AETHER"), "{e}");
        assert!(
            e.to_string().contains("fresh campaign"),
            "should say what to do: {e}"
        );
    }
}
