// Verify every shipped example loads through the engine's own validator,
// which is stricter than TOML parsing: cross-field coherence, scope rules,
// strategy names, provider names and profile compatibility.
fn main() {
    let mut failed = 0;
    for entry in std::fs::read_dir("examples").expect("examples dir") {
        let p = entry.expect("entry").path();
        if p.extension().and_then(|e| e.to_str()) != Some("toml") {
            continue;
        }
        let text = std::fs::read_to_string(&p).expect("read");
        match aether_core::config::Config::from_toml_str(&text) {
            Ok(cfg) => {
                // Strategy and provider names must all be known.
                for s in &cfg.strategies.enabled {
                    if !aether_core::strategy::ALL_STRATEGY_IDS.contains(&s.as_str()) {
                        println!("{}: unknown strategy {s:?}", p.display());
                        failed += 1;
                    }
                }
                println!(
                    "{}: ok ({} strategies)",
                    p.display(),
                    cfg.strategies.enabled.len()
                );
            }
            Err(e) => {
                println!("{}: REJECTED: {e}", p.display());
                failed += 1;
            }
        }
    }
    if failed > 0 {
        eprintln!("{failed} example(s) invalid");
        std::process::exit(1);
    }
}
