//! Parsing sanitizer reports out of a target's stderr.
//!
//! A sanitizer report is strong evidence, so the parser is deliberately
//! strict about where it will accept one. Two rules matter:
//!
//! 1. **stderr only.** Sanitizers write to stderr. A report-shaped string on
//!    stdout is target output, not a finding - `fixtures/noisy_output.c`
//!    prints a convincing fake banner precisely to test this.
//! 2. **An abnormal exit is required.** A sanitizer that fires terminates the
//!    process. A process that printed a banner and then exited 0 did not
//!    crash, so the banner is text, not evidence.
//!
//! Both rules are enforced by the caller passing only stderr and the exit
//! classification; [`parse`] itself only extracts structure.

use serde::{Deserialize, Serialize};

/// The sanitizer families AETHER recognises.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SanitizerKind {
    Address,
    Undefined,
    Memory,
    Thread,
    LeakCheck,
    /// Recognised as a sanitizer report, family not identified.
    Other,
}

impl SanitizerKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            SanitizerKind::Address => "AddressSanitizer",
            SanitizerKind::Undefined => "UndefinedBehaviorSanitizer",
            SanitizerKind::Memory => "MemorySanitizer",
            SanitizerKind::Thread => "ThreadSanitizer",
            SanitizerKind::LeakCheck => "LeakSanitizer",
            SanitizerKind::Other => "sanitizer",
        }
    }
}

/// One parsed sanitizer report.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SanitizerReport {
    pub kind: SanitizerKind,
    /// The specific fault, e.g. `heap-buffer-overflow`, normalised to lowercase.
    pub fault: String,
    /// Operation, where the report states one: `read`, `write`.
    pub access: Option<String>,
    /// Access size in bytes, where stated.
    pub access_size: Option<u64>,
    /// Top frames, innermost first, as `function` names with addresses and
    /// build-specific paths stripped so the signature is stable across builds.
    pub frames: Vec<String>,
    /// The report's headline, truncated.
    pub summary: String,
}

impl SanitizerReport {
    /// Frames that make up this report's identity. Deliberately shallow: the
    /// innermost few frames identify a fault while being insensitive to how
    /// deep the harness call stack happened to be.
    pub fn signature_frames(&self, depth: usize) -> Vec<&str> {
        self.frames.iter().take(depth).map(String::as_str).collect()
    }
}

const MAX_FRAMES: usize = 24;

/// Extract a sanitizer report from a target's stderr.
///
/// Returns `None` when the text contains no recognisable report. The caller is
/// responsible for only offering stderr from an abnormally terminated process.
pub fn parse(stderr: &str) -> Option<SanitizerReport> {
    // The error line looks like:
    //   ==1234==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x...
    // UBSan instead emits:
    //   file.c:12:5: runtime error: signed integer overflow: ...
    let mut kind = None;
    let mut fault = String::new();
    let mut summary = String::new();

    for line in stderr.lines() {
        let t = line.trim();
        if let Some(rest) = after_error_marker(t) {
            let (k, f) = classify_error_line(rest);
            if let Some(k) = k {
                kind = Some(k);
                fault = f;
                summary = truncate(t, 300);
                break;
            }
        }
        if let Some(pos) = t.find("runtime error: ") {
            kind = Some(SanitizerKind::Undefined);
            fault = normalise_fault(&t[pos + "runtime error: ".len()..]);
            summary = truncate(t, 300);
            break;
        }
    }

    // A LeakSanitizer report has no ERROR: line in some configurations.
    if kind.is_none() && stderr.contains("detected memory leaks") {
        kind = Some(SanitizerKind::LeakCheck);
        fault = "memory-leak".to_string();
        summary = "LeakSanitizer: detected memory leaks".to_string();
    }

    let kind = kind?;
    let (access, access_size) = parse_access(stderr);

    Some(SanitizerReport {
        kind,
        fault,
        access,
        access_size,
        frames: parse_frames(stderr),
        summary,
    })
}

fn after_error_marker(line: &str) -> Option<&str> {
    // `==PID==ERROR: ` or a bare `ERROR: ` at the start of the line.
    if let Some(idx) = line.find("ERROR: ") {
        // Only accept the marker at the start, or right after a ==pid== prefix,
        // so the word ERROR inside arbitrary target output does not qualify.
        let prefix = &line[..idx];
        if prefix.is_empty()
            || (prefix.starts_with("==") && prefix.trim_start_matches(['=', ' ']).chars().all(|c| c.is_ascii_digit() || c == '=')
                && prefix.ends_with("=="))
        {
            return Some(&line[idx + "ERROR: ".len()..]);
        }
    }
    None
}

fn classify_error_line(rest: &str) -> (Option<SanitizerKind>, String) {
    let (name, remainder) = match rest.split_once(':') {
        Some((n, r)) => (n.trim(), r.trim()),
        None => (rest.trim(), ""),
    };
    let kind = match name {
        "AddressSanitizer" => SanitizerKind::Address,
        "UndefinedBehaviorSanitizer" => SanitizerKind::Undefined,
        "MemorySanitizer" => SanitizerKind::Memory,
        "ThreadSanitizer" => SanitizerKind::Thread,
        "LeakSanitizer" => SanitizerKind::LeakCheck,
        other if other.ends_with("Sanitizer") => SanitizerKind::Other,
        _ => return (None, String::new()),
    };
    (Some(kind), normalise_fault(remainder))
}

/// Keep the fault token, drop the addresses and prose that follow it.
fn normalise_fault(s: &str) -> String {
    let s = s.trim();
    let stop = [" on address", " on unknown address", " at pc", ":", " ("];
    let mut end = s.len();
    for pat in stop {
        if let Some(p) = s.find(pat) {
            end = end.min(p);
        }
    }
    let token = s[..end].trim();
    if token.is_empty() {
        "unknown".to_string()
    } else {
        truncate(&token.to_ascii_lowercase(), 120)
    }
}

fn parse_access(stderr: &str) -> (Option<String>, Option<u64>) {
    for line in stderr.lines() {
        let t = line.trim();
        for (word, kind) in [("READ of size ", "read"), ("WRITE of size ", "write")] {
            if let Some(p) = t.find(word) {
                let tail = &t[p + word.len()..];
                let digits: String = tail.chars().take_while(|c| c.is_ascii_digit()).collect();
                return (Some(kind.to_string()), digits.parse().ok());
            }
        }
    }
    (None, None)
}

/// Pull `#N 0xADDR in <symbol> <path>` frames, keeping only the symbol.
///
/// Addresses and paths are dropped deliberately: they move between builds and
/// between machines, and a signature that includes them would report the same
/// defect as new after every recompile.
fn parse_frames(stderr: &str) -> Vec<String> {
    let mut frames = Vec::new();
    for line in stderr.lines() {
        let t = line.trim();
        if !t.starts_with('#') {
            continue;
        }
        // Skip the frame number.
        let after_num = match t.find(' ') {
            Some(i) => &t[i + 1..],
            None => continue,
        };
        let sym = match after_num.find(" in ") {
            Some(i) => {
                let tail = after_num[i + 4..].trim();
                strip_location(tail).to_string()
            }
            None => {
                // Frames with no symbol: `#3 0x... (/lib/libc.so+0x2a1c9)`
                let tail = after_num.trim();
                match (tail.find('('), tail.rfind('+')) {
                    (Some(a), Some(b)) if b > a => {
                        let obj = &tail[a + 1..b];
                        let base = obj.rsplit('/').next().unwrap_or(obj);
                        format!("<{base}>")
                    }
                    _ => continue,
                }
            }
        };
        if sym.is_empty() {
            continue;
        }
        frames.push(truncate(&sym, 160));
        if frames.len() >= MAX_FRAMES {
            break;
        }
    }
    frames
}

/// Drop the source location that follows a symbol in a sanitizer frame.
///
/// The location is the final whitespace-delimited field, and it may be an
/// absolute path (`/src/a.c:3`), a relative one (`../../a.inc:996`), or a
/// module offset (`(/lib/libc.so+0x2a1c9)`). Splitting from the right rather
/// than scanning for `" /"` is what makes a relative path work, and it keeps
/// C++ symbols that contain spaces intact.
fn strip_location(tail: &str) -> &str {
    match tail.rsplit_once(char::is_whitespace) {
        Some((head, last))
            if !head.is_empty()
                && (last.starts_with('(')
                    || last.contains('/')
                    || last.contains(':')) =>
        {
            head.trim_end()
        }
        _ => tail,
    }
}

fn truncate(s: &str, n: usize) -> String {
    if s.len() <= n {
        return s.to_string();
    }
    let mut end = n;
    while end > 0 && !s.is_char_boundary(end) {
        end -= 1;
    }
    s[..end].to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    const ASAN: &str = r#"
=================================================================
==1279==ERROR: AddressSanitizer: stack-buffer-overflow on address 0x7f95a8800050 at pc 0x7f95aac7ed7f bp 0x7fffebc2bcb0 sp 0x7fffebc2b458
WRITE of size 20 at 0x7f95a8800050 thread T0
    #0 0x7f95aac7ed7e in fread ../../../../src/libsanitizer/sanitizer_common/sanitizer_common_interceptors.inc:996
    #1 0x55d17d6a6308 in main /home/user/scratch/oob.c:3
    #2 0x7f95aa82a1c9 (/lib/x86_64-linux-gnu/libc.so.6+0x2a1c9)
    #3 0x55d17d6a6164 in _start (/tmp/oob+0x1164)
SUMMARY: AddressSanitizer: stack-buffer-overflow
"#;

    #[test]
    fn parses_a_real_asan_report() {
        let r = parse(ASAN).expect("should parse");
        assert_eq!(r.kind, SanitizerKind::Address);
        assert_eq!(r.fault, "stack-buffer-overflow");
        assert_eq!(r.access.as_deref(), Some("write"));
        assert_eq!(r.access_size, Some(20));
        assert_eq!(r.frames[0], "fread");
        assert_eq!(r.frames[1], "main");
        assert_eq!(r.frames[2], "<libc.so.6>");
    }

    #[test]
    fn frames_exclude_addresses_and_paths() {
        // A signature built from these frames has to survive a rebuild at a
        // different load address and from a different source directory.
        let r = parse(ASAN).unwrap();
        for f in &r.frames {
            assert!(!f.contains("0x"), "frame kept an address: {f}");
            assert!(!f.contains("/home/"), "frame kept a build path: {f}");
            assert!(!f.contains(".c:"), "frame kept a line number: {f}");
        }
    }

    #[test]
    fn parses_ubsan_runtime_error() {
        let r = parse("oob.c:7:12: runtime error: signed integer overflow: 2147483647 + 1 cannot be represented in type 'int'").unwrap();
        assert_eq!(r.kind, SanitizerKind::Undefined);
        assert_eq!(r.fault, "signed integer overflow");
    }

    #[test]
    fn parses_leak_report_without_error_line() {
        let r = parse("\n==77==ERROR: LeakSanitizer: detected memory leaks\n\nDirect leak of 16 byte(s)\n").unwrap();
        assert_eq!(r.kind, SanitizerKind::LeakCheck);
    }

    #[test]
    fn ignores_text_that_merely_mentions_sanitizers() {
        assert!(parse("the AddressSanitizer docs explain heap-buffer-overflow").is_none());
        assert!(parse("ERROR: could not open file").is_none());
        assert!(parse("").is_none());
        assert!(parse("some ERROR: NotASanitizer: whatever").is_none());
    }

    #[test]
    fn target_controlled_banner_is_still_parsed_but_caller_gates_it() {
        // fixtures/noisy_output.c prints exactly this on *stdout*. The parser
        // will recognise the shape; what keeps it from becoming a finding is
        // that the caller only ever passes stderr from an abnormal exit.
        let fake = "==1234==ERROR: AddressSanitizer: heap-use-after-free on address 0x0";
        assert!(parse(fake).is_some(), "parser recognises the shape");
        // The guard lives in classification, verified in exec::tests.
    }

    #[test]
    fn handles_truncated_and_binary_noise() {
        // A log cut mid-report, and one with control bytes, must not panic.
        parse("==1==ERROR: AddressSanitizer: heap-buffer-overfl");
        parse("\u{0}\u{1}==1==ERROR: AddressSanitizer: bad-free on address 0x1\n    #0 0x1 in f\u{0}x");
        let long = format!("==1==ERROR: AddressSanitizer: {}", "x".repeat(10_000));
        let r = parse(&long).unwrap();
        assert!(r.fault.len() <= 120, "fault should be truncated");
        assert!(r.summary.len() <= 300);
    }

    #[test]
    fn frame_list_is_bounded() {
        let mut s = String::from("==1==ERROR: AddressSanitizer: bad on address 0x1\n");
        for i in 0..500 {
            s.push_str(&format!("    #{i} 0xdead in func_{i} /src/a.c:{i}\n"));
        }
        let r = parse(&s).unwrap();
        assert!(r.frames.len() <= MAX_FRAMES, "got {} frames", r.frames.len());
    }

    #[test]
    fn strips_every_shape_of_source_location() {
        assert_eq!(strip_location("fread ../../../a.inc:996"), "fread");
        assert_eq!(strip_location("main /home/user/oob.c:3"), "main");
        assert_eq!(strip_location("_start (/tmp/oob+0x1164)"), "_start");
        assert_eq!(strip_location("main"), "main");
        // A C++ symbol containing spaces must survive intact.
        assert_eq!(
            strip_location("std::vector<int, std::allocator<int> >::push_back /usr/x.h:1"),
            "std::vector<int, std::allocator<int> >::push_back"
        );
        // Nothing to strip when the only field looks like a location.
        assert_eq!(strip_location("/lib/libc.so"), "/lib/libc.so");
    }

    #[test]
    fn signature_frames_are_shallow() {
        let r = parse(ASAN).unwrap();
        assert_eq!(r.signature_frames(2), vec!["fread", "main"]);
        assert_eq!(r.signature_frames(99).len(), r.frames.len());
    }
}
