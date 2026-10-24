//! AETHER - Adaptive Evolutionary Testing & Hybrid Exploration Runtime.
//!
//! A fuzzing platform built around three engines sharing one campaign runtime:
//!
//! * **Exploration** ([`exec`], [`strategy`], [`feedback`]) runs candidates
//!   against a target and observes what they did.
//! * **Intelligence** ([`intel`], [`corpus`]) decides what to try next and
//!   which inputs are worth keeping, from measurements rather than fixed rules.
//! * **Evidence** ([`evidence`]) turns a suspected failure into a reproduced,
//!   minimised, deduplicated finding, or explicitly declines to.
//!
//! The modules below have deliberately narrow interfaces so a strategy, a
//! feedback provider or an execution backend can be added without touching
//! the campaign loop.

pub mod bench;
pub mod config;
pub mod corpus;
pub mod error;
pub mod evidence;
pub mod exec;
pub mod feedback;
pub mod hash;
pub mod ids;
pub mod intel;
pub mod oracle;
pub mod persist;
pub mod query;
pub mod rng;
pub mod runtime;
pub mod scope;
pub mod strategy;
pub mod time;

pub use error::{Error, Result};
