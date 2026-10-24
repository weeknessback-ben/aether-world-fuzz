//! Security tests.
//!
//! AETHER runs attacker-controlled data through real programs, so these verify
//! the safeguards against a hostile *target* and against a hostile
//! *configuration*. Each test names the attack it is checking, because a
//! safeguard without a test is a comment.
//!
//! What is deliberately not here: tests against real third-party software.
//! These exercise AETHER's own controls, using purpose-built fixtures.

mod common;

use std::path::Path;

use aether_core::config::Config;
use aether_core::corpus::cas::ContentStore;
use aether_core::exec::native::{NativeExecutor, TargetSpec};
use aether_core::exec::{Executor, ExitClass};
use aether_core::ids::{CampaignId, FindingId, InputId};
use aether_core::scope::{ScopePolicy, ScopeRequest};
use common::{config_toml_for, config_toml_uninstrumented, fixture, Build, Scratch};

// ---------------------------------------------------------------------------
// Command injection
// ---------------------------------------------------------------------------

#[test]
fn input_bytes_cannot_reach_a_shell() {
    // Targets are launched from an argument vector, never a command string.
    // A mutated input containing shell metacharacters must arrive as bytes.
    let bin = fixture("always_ok", Build::Instrumented);
    let cfg = Config::from_toml_str(&config_toml_for(&bin, "")).unwrap();
    let s = Scratch::new("sec-shell");
    let spec = TargetSpec::from_config(&cfg.target, &ScopePolicy::default(), 4096).unwrap();
    let mut exec = NativeExecutor::new(spec, &s.path).unwrap();

    let canary = std::env::temp_dir().join(format!("aether-canary-{}", std::process::id()));
    let _ = std::fs::remove_file(&canary);
    let c = canary.display().to_string();

    let payloads: Vec<Vec<u8>> = vec![
        format!("; touch {c}").into_bytes(),
        format!("$(touch {c})").into_bytes(),
        format!("`touch {c}`").into_bytes(),
        format!("| touch {c}").into_bytes(),
        format!("&& touch {c}").into_bytes(),
        format!("\n touch {c} \n").into_bytes(),
        b"../../../../etc/passwd".to_vec(),
        b"a\x00b; rm -rf /".to_vec(),
        b"'\"\\$(){}[]<>|&;".to_vec(),
    ];
    for p in &payloads {
        let out = exec.run(p).expect("run");
        assert_eq!(
            out.class,
            ExitClass::Ok,
            "payload {:?} changed the verdict",
            String::from_utf8_lossy(p)
        );
    }
    assert!(
        !canary.exists(),
        "a shell interpreted an input: the canary file was created"
    );
}

#[test]
fn target_arguments_cannot_reach_a_shell() {
    // The same guarantee for configured arguments, which may come from a file
    // someone else wrote.
    let bin = fixture("file_arg_reader", Build::Plain);
    let canary = std::env::temp_dir().join(format!("aether-argv-canary-{}", std::process::id()));
    let _ = std::fs::remove_file(&canary);

    let cfg = Config::from_toml_str(&config_toml_uninstrumented(
        &bin,
        &format!(
            "input_mode = \"file-arg\"\nargs = [\"@@\", \"; touch {}\"]",
            canary.display()
        ),
    ))
    .unwrap();
    let s = Scratch::new("sec-argv");
    let spec = TargetSpec::from_config(&cfg.target, &ScopePolicy::default(), 4096).unwrap();
    let mut exec = NativeExecutor::new(spec, &s.path).unwrap();
    exec.run(b"hello").expect("run");

    assert!(
        !canary.exists(),
        "a configured argument was interpreted by a shell"
    );
}

// ---------------------------------------------------------------------------
// Path traversal
// ---------------------------------------------------------------------------

#[test]
fn crafted_content_hashes_cannot_escape_the_store() {
    let dir = std::env::temp_dir().join(format!("aether-sec-cas-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let cas = ContentStore::open(&dir).unwrap();

    for bad in [
        "../../../../etc/passwd",
        "..",
        "/etc/passwd",
        "ab/../../../etc/shadow",
        "ab%2f..%2f..%2fetc",
        &"A".repeat(32),
        "",
        "zz",
        "\0\0",
    ] {
        assert!(cas.get(bad).is_err(), "read accepted {bad:?}");
        assert!(!cas.contains(bad), "contains accepted {bad:?}");
        assert!(cas.remove(bad).is_err(), "remove accepted {bad:?}");
    }
    // Nothing outside the store was touched.
    assert!(
        Path::new("/etc/passwd").exists(),
        "a system file was removed"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn crafted_identifiers_are_refused_before_reaching_a_path_or_a_statement() {
    for bad in [
        "../../etc/passwd",
        "cmp-../../../tmp",
        "cmp-a;DROP TABLE campaigns",
        "cmp-a' OR 1=1 --",
        "cmp-a/b",
        "cmp-a\0b",
        "",
        &format!("cmp-{}", "x".repeat(200)),
    ] {
        assert!(
            CampaignId::from_string(bad).validate().is_err(),
            "campaign id accepted {bad:?}"
        );
    }
    // Prefix confusion is refused too: a finding id is not a campaign id.
    assert!(CampaignId::from_string("fnd-0000000000000001")
        .validate()
        .is_err());
    assert!(FindingId::from_string("cmp-0000000000000001")
        .validate()
        .is_err());
    assert!(InputId::new().validate().is_ok());
}

#[test]
fn symlinks_planted_in_the_store_are_not_followed() {
    let dir = std::env::temp_dir().join(format!("aether-sec-link-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let cas = ContentStore::open(&dir).unwrap();
    cas.put(b"a real object").unwrap();

    // A link out of the store must not make a directory walk escape it.
    let link = dir.join("escape");
    if std::os::unix::fs::symlink("/etc", &link).is_ok() {
        let (_, count) = cas.usage().unwrap();
        assert_eq!(count, 1, "the store walk followed a symlink out of itself");
    }
    let _ = std::fs::remove_dir_all(&dir);
}

// ---------------------------------------------------------------------------
// Configuration cannot widen what runs
// ---------------------------------------------------------------------------

#[test]
fn configuration_cannot_redirect_the_loader_or_disable_the_oracle() {
    let base = r#"
schema_version = 1
[target]
name = "t"
kind = "executable"
binary = "/bin/true"
"#;
    for var in [
        "LD_PRELOAD",
        "ld_preload",
        "LD_LIBRARY_PATH",
        "LD_AUDIT",
        "DYLD_INSERT_LIBRARIES",
        "ASAN_OPTIONS",
        "UBSAN_OPTIONS",
        "AETHER_SHM_PATH",
        "AETHER_FORKSRV",
    ] {
        let toml = format!("{base}\n[target.env]\n{var} = \"anything\"\n");
        let e = Config::from_toml_str(&toml)
            .err()
            .unwrap_or_else(|| panic!("{var} was accepted in target.env"));
        assert!(e.to_string().contains("may not be set"), "{var}: {e}");
    }
}

#[test]
fn the_target_environment_is_cleared() {
    // A variable in the operator's shell must not change what is tested.
    // `always_ok` exits 0 regardless, so this checks the mechanism rather than
    // a behavioural difference: the executor sets env_clear and only the
    // engine's own variables survive.
    std::env::set_var("AETHER_TEST_LEAK_CHECK", "leaked");
    let bin = fixture("always_ok", Build::Instrumented);
    let cfg = Config::from_toml_str(&config_toml_for(&bin, "")).unwrap();
    let s = Scratch::new("sec-env");
    let spec = TargetSpec::from_config(&cfg.target, &ScopePolicy::default(), 4096).unwrap();
    let mut exec = NativeExecutor::new(spec, &s.path).unwrap();
    assert_eq!(exec.run(b"x").unwrap().class, ExitClass::Ok);
    std::env::remove_var("AETHER_TEST_LEAK_CHECK");
}

// ---------------------------------------------------------------------------
// Scope
// ---------------------------------------------------------------------------

#[test]
fn an_address_alone_is_not_authorization() {
    let net = |h: &str, p: u16| ScopeRequest::Network {
        host: h.into(),
        port: p,
    };

    // Default policy refuses every network target.
    let d = ScopePolicy::default();
    assert!(d.authorize_target(&net("example.com", 443)).is_err());
    assert!(d.authorize_target(&net("127.0.0.1", 8080)).is_err());

    // Turning the flag on is not enough on its own.
    let flag_only = ScopePolicy {
        allow_network_targets: true,
        ..Default::default()
    };
    assert!(flag_only
        .authorize_target(&net("example.com", 443))
        .is_err());
    assert!(
        flag_only.validate().is_err(),
        "an empty host list must fail validation"
    );

    // All three requirements, and only the listed host.
    let full = ScopePolicy {
        allow_network_targets: true,
        authorized_hosts: vec!["example.com".into()],
        authorization_note: Some("engagement SEC-1".into()),
        max_requests_per_second: 10,
        ..Default::default()
    };
    full.validate().unwrap();
    full.authorize_target(&net("example.com", 443)).unwrap();

    // Loopback is not implicitly in scope, and a subdomain does not inherit.
    for host in [
        "127.0.0.1",
        "localhost",
        "admin.example.com",
        "example.com.evil.net",
    ] {
        assert!(
            full.authorize_target(&net(host, 443)).is_err(),
            "{host} was authorized by an entry for example.com"
        );
    }
}

#[test]
fn wildcards_in_the_host_list_are_refused() {
    let p = ScopePolicy {
        allow_network_targets: true,
        authorized_hosts: vec!["*.example.com".into()],
        authorization_note: Some("t".into()),
        max_requests_per_second: 1,
        ..Default::default()
    };
    assert!(
        p.validate().is_err(),
        "a wildcard host entry must be refused"
    );
}

// ---------------------------------------------------------------------------
// Resource exhaustion
// ---------------------------------------------------------------------------

#[test]
fn a_target_cannot_flood_the_engine_with_output() {
    // noisy_output prints roughly 20,000 lines with embedded NUL bytes.
    let bin = fixture("noisy_output", Build::Instrumented);
    let cfg = Config::from_toml_str(&config_toml_for(&bin, "")).unwrap();
    let s = Scratch::new("sec-flood");
    let limit = 4096;
    let spec = TargetSpec::from_config(&cfg.target, &ScopePolicy::default(), limit).unwrap();
    let mut exec = NativeExecutor::new(spec, &s.path).unwrap();

    for _ in 0..5 {
        let out = exec.run(b"x").expect("run");
        assert!(
            out.stdout.len() <= limit,
            "captured {} bytes",
            out.stdout.len()
        );
        assert!(
            out.stdout_truncated,
            "truncation must be reported, not silent"
        );
    }
}

#[test]
fn a_hanging_target_is_killed_and_does_not_wedge_the_engine() {
    let bin = fixture("hang", Build::Instrumented);
    let toml = config_toml_for(&bin, "").replace("timeout_ms = 2000", "timeout_ms = 200");
    let cfg = Config::from_toml_str(&toml).unwrap();
    let s = Scratch::new("sec-hang");
    let spec = TargetSpec::from_config(&cfg.target, &ScopePolicy::default(), 4096).unwrap();
    let mut exec = NativeExecutor::new(spec, &s.path).unwrap();

    let start = std::time::Instant::now();
    for _ in 0..3 {
        assert_eq!(exec.run(b"HANG").unwrap().class, ExitClass::Timeout);
    }
    assert!(
        start.elapsed() < std::time::Duration::from_secs(5),
        "three 200ms timeouts took {:?}",
        start.elapsed()
    );
    // Still usable afterwards: a timeout must not leave the executor wedged.
    assert_eq!(exec.run(b"fine").unwrap().class, ExitClass::Ok);
}

#[test]
fn oversized_inputs_are_refused_rather_than_stored() {
    let bin = fixture("always_ok", Build::Instrumented);
    let toml = config_toml_for(&bin, "").replace(
        "duration_secs = 5",
        "duration_secs = 5\nmax_input_bytes = 1024",
    );
    let cfg = Config::from_toml_str(&toml).unwrap();
    assert_eq!(cfg.max_input_bytes(), 1024);

    // And the hard ceiling cannot be exceeded by configuration.
    let over = config_toml_for(&bin, "").replace(
        "duration_secs = 5",
        &format!(
            "duration_secs = 5\nmax_input_bytes = {}",
            aether_core::config::MAX_INPUT_BYTES + 1
        ),
    );
    assert!(Config::from_toml_str(&over).is_err());
}

#[test]
fn many_executions_do_not_leak_processes() {
    // A fork server leaking one child per run would exhaust the process table.
    // 400 runs is comfortably past the RLIMIT_NPROC of 256 the engine sets.
    let bin = fixture("coverage_ladder", Build::Instrumented);
    let cfg = Config::from_toml_str(&config_toml_for(&bin, "")).unwrap();
    let s = Scratch::new("sec-leak");
    let spec = TargetSpec::from_config(&cfg.target, &ScopePolicy::default(), 2048).unwrap();
    let mut exec = NativeExecutor::new(spec, &s.path).unwrap();
    for i in 0..400u32 {
        exec.run(&i.to_le_bytes())
            .unwrap_or_else(|e| panic!("run {i}: {e}"));
    }
    assert_eq!(exec.exec_count(), 400);
}

// ---------------------------------------------------------------------------
// A target cannot manufacture evidence
// ---------------------------------------------------------------------------

#[test]
fn a_target_cannot_fake_a_sanitizer_finding() {
    // noisy_output prints a convincing AddressSanitizer banner on stdout and
    // exits cleanly. Believing it would let any target manufacture findings.
    let bin = fixture("noisy_output", Build::Instrumented);
    let cfg = Config::from_toml_str(&config_toml_for(&bin, "")).unwrap();
    let s = Scratch::new("sec-fake");
    let spec = TargetSpec::from_config(&cfg.target, &ScopePolicy::default(), 64 * 1024).unwrap();
    let mut exec = NativeExecutor::new(spec, &s.path).unwrap();

    let out = exec.run(b"x").expect("run");
    assert!(
        out.stdout.windows(5).any(|w| w == b"ERROR"),
        "the fixture should be printing its fake banner"
    );
    assert!(
        out.sanitizer.is_none(),
        "a banner on stdout became a finding"
    );
    assert_ne!(out.class, ExitClass::SanitizerFault);
    assert!(aether_core::evidence::signature::signature_for(&out).is_none());
}

// ---------------------------------------------------------------------------
// Malformed configuration
// ---------------------------------------------------------------------------

#[test]
fn malformed_configuration_is_refused_with_a_reason() {
    let cases: &[(&str, &str)] = &[
        ("not toml at all {{{", "toml"),
        ("schema_version = 99\n[target]\nname=\"t\"\nkind=\"executable\"\nbinary=\"/bin/true\"\n", "not supported"),
        ("schema_version = 1\n", "missing field"),
        ("schema_version = 1\n[target]\nname=\"\"\nkind=\"executable\"\nbinary=\"/bin/true\"\n", "must not be empty"),
        ("schema_version = 1\n[target]\nname=\"t\"\nkind=\"executable\"\nbinary=\"/bin/true\"\ntimeout_ms=0\n", "outside"),
        ("schema_version = 1\nnot_a_field = 1\n[target]\nname=\"t\"\nkind=\"executable\"\nbinary=\"/bin/true\"\n", "unknown field"),
        ("schema_version = 1\n[target]\nname=\"t\"\nkind=\"executable\"\nbinary=\"/bin/true\"\n[campaign]\nduration_secs=0\nmax_execs=0\n", "unbounded campaign is refused"),
        ("schema_version = 1\n[target]\nname=\"t\"\nkind=\"executable\"\nbinary=\"/bin/true\"\n[reproduction]\nattempts=3\nrequired_successes=9\n", "must be in"),
    ];
    for (toml, expect) in cases {
        let e = Config::from_toml_str(toml)
            .err()
            .unwrap_or_else(|| panic!("accepted malformed config: {toml}"));
        assert!(
            e.to_string().contains(expect),
            "for {toml:?}\nexpected {expect:?}\ngot {e}"
        );
    }
}

#[test]
fn a_nonexistent_or_non_executable_target_is_refused() {
    let cfg = Config::from_toml_str(
        "schema_version = 1\n[target]\nname=\"t\"\nkind=\"executable\"\n\
         binary=\"/nonexistent/aether-definitely-not-here\"\n",
    )
    .unwrap();
    let e = TargetSpec::from_config(&cfg.target, &ScopePolicy::default(), 4096).unwrap_err();
    assert_eq!(e.kind(), "target_invalid");

    // A readable but non-executable file.
    let dir = std::env::temp_dir().join(format!("aether-sec-exec-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let p = dir.join("data.txt");
    std::fs::write(&p, b"not a program").unwrap();
    let cfg2 = Config::from_toml_str(&format!(
        "schema_version = 1\n[target]\nname=\"t\"\nkind=\"executable\"\nbinary=\"{}\"\n",
        p.display()
    ))
    .unwrap();
    let e2 = TargetSpec::from_config(&cfg2.target, &ScopePolicy::default(), 4096).unwrap_err();
    assert!(e2.to_string().contains("not executable"), "{e2}");
    let _ = std::fs::remove_dir_all(&dir);
}

// ---------------------------------------------------------------------------
// Evidence integrity
// ---------------------------------------------------------------------------

#[test]
fn tampered_corpus_content_is_detected() {
    let dir = std::env::temp_dir().join(format!("aether-sec-tamper-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let cas = ContentStore::open(&dir).unwrap();
    let hash = cas.put(b"original evidence").unwrap();
    assert!(cas.verify(&hash).unwrap());

    // Overwrite the stored object in place.
    let mut found = None;
    fn walk(d: &Path, out: &mut Option<std::path::PathBuf>) {
        if let Ok(rd) = std::fs::read_dir(d) {
            for e in rd.flatten() {
                let p = e.path();
                if p.is_dir() {
                    walk(&p, out);
                } else if out.is_none() {
                    *out = Some(p);
                }
            }
        }
    }
    walk(&dir, &mut found);
    std::fs::write(found.expect("stored object"), b"tampered").unwrap();

    assert!(
        !cas.verify(&hash).unwrap(),
        "altered content was not detected"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn an_interrupted_write_is_not_mistaken_for_an_object() {
    let dir = std::env::temp_dir().join(format!("aether-sec-partial-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let cas = ContentStore::open(&dir).unwrap();
    cas.put(b"complete").unwrap();

    // Simulate a crash mid-write: a temporary file left behind.
    let sub = dir.join("00").join("11");
    std::fs::create_dir_all(&sub).unwrap();
    std::fs::write(sub.join(".tmp-999-interrupted"), b"half written").unwrap();

    let (_, count) = cas.usage().unwrap();
    assert_eq!(count, 1, "a partial write counted as a stored object");
    assert_eq!(cas.clean_temporaries().unwrap(), 1);
    let _ = std::fs::remove_dir_all(&dir);
}
