use anyhow::{Context, Result, anyhow};
use clap::{Args, Parser, Subcommand};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};
use tracing::{Level, info};
use tracing_subscriber::FmtSubscriber;

#[derive(Parser)]
#[command(name = "kestrel-lab")]
#[command(about = "Battle Lab runner for Kestrel scenarios")]
#[command(version)]
struct Cli {
    #[arg(long, default_value = "./scenarios")]
    scenarios_dir: PathBuf,

    #[arg(long, default_value = "./lab-results")]
    results_dir: PathBuf,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    List,
    Validate,
    Show {
        #[arg(long)]
        scenario: String,
    },
    Run(RunArgs),
    RunAll {
        #[command(flatten)]
        options: SharedRunOptions,
        #[arg(long, default_value_t = false)]
        json: bool,
    },
    Assert {
        #[arg(long)]
        scenario: String,
        #[arg(long)]
        alerts: PathBuf,
        #[arg(long, default_value_t = false)]
        json: bool,
    },
}

#[derive(Args, Clone)]
struct SharedRunOptions {
    #[arg(long, default_value_t = false)]
    execute: bool,
    #[arg(long, default_value_t = false)]
    allow_real_targets: bool,
    #[arg(long = "env")]
    env_vars: Vec<String>,
    #[arg(long)]
    alerts: Option<PathBuf>,
    #[arg(long)]
    replay_log: Option<PathBuf>,
    #[arg(long)]
    replay_rules: Option<PathBuf>,
    #[arg(long, default_value = "0")]
    replay_speed: f64,
}

#[derive(Args, Clone)]
struct RunArgs {
    #[arg(long)]
    scenario: String,
    #[command(flatten)]
    options: SharedRunOptions,
    #[arg(long, default_value_t = false)]
    json: bool,
}

#[derive(Debug, Deserialize)]
struct Scenario {
    id: String,
    name: String,
    category: String,
    severity: String,
    status: String,
    summary: String,
    #[serde(default)]
    recommended_rules: Vec<String>,
    execution: ExecutionConfig,
}

#[derive(Debug, Deserialize)]
struct ExecutionConfig {
    entrypoint: String,
    #[serde(default)]
    env: BTreeMap<String, String>,
}

#[derive(Debug, Deserialize)]
struct ExpectedAlerts {
    scenario_id: String,
    #[serde(default)]
    expected_rules: Vec<ExpectedRule>,
    #[serde(default)]
    unexpected_rules: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct ExpectedRule {
    rule_id: String,
    min_hits: usize,
}

#[derive(Debug)]
struct ScenarioBundle {
    dir: PathBuf,
    scenario: Scenario,
    expected: ExpectedAlerts,
}

#[derive(Debug, Deserialize)]
struct MinimalAlert {
    rule_id: String,
}

#[derive(Debug, Serialize)]
struct AssertionRuleResult {
    rule_id: String,
    observed_hits: usize,
    min_hits: usize,
    matched: bool,
}

#[derive(Debug, Serialize)]
struct AssertionSummary {
    scenario_id: String,
    passed: bool,
    checked_rules: Vec<AssertionRuleResult>,
    unexpected_hits: Vec<String>,
}

#[derive(Debug, Serialize)]
struct ReplaySummary {
    replay_log: String,
    rules_dir: String,
    events_processed: u64,
    current_ts_mono_ns: u64,
    current_ts_wall_ns: u64,
}

#[derive(Debug, Serialize)]
struct ScenarioRunSummary {
    scenario_id: String,
    exit_code: i32,
    results_dir: String,
    stdout_log: String,
    stderr_log: String,
    assertions: Option<AssertionSummary>,
    replay: Option<ReplaySummary>,
}

#[derive(Debug, Serialize)]
struct RunAllSummary {
    session_dir: String,
    scenarios: Vec<ScenarioRunSummary>,
    passed: usize,
    failed: usize,
}

fn main() -> Result<()> {
    setup_logging()?;
    let cli = Cli::parse();

    match cli.command {
        Commands::List => list_scenarios(&cli.scenarios_dir),
        Commands::Validate => validate_scenarios(&cli.scenarios_dir),
        Commands::Show { scenario } => show_scenario(&cli.scenarios_dir, &scenario),
        Commands::Run(args) => {
            let summary = run_scenario(
                &cli.scenarios_dir,
                &cli.results_dir,
                &args.scenario,
                &args.options,
                None,
            )?;
            print_run_summary(&summary, args.json)?;
            Ok(())
        },
        Commands::RunAll { options, json } => {
            let summary = run_all_scenarios(&cli.scenarios_dir, &cli.results_dir, &options)?;
            if json {
                println!("{}", serde_json::to_string_pretty(&summary)?);
            } else {
                for scenario in &summary.scenarios {
                    println!(
                        "- {} => exit_code={}{}",
                        scenario.scenario_id,
                        scenario.exit_code,
                        scenario
                            .assertions
                            .as_ref()
                            .map(|assertion| format!(", assertions_passed={}", assertion.passed))
                            .unwrap_or_default()
                    );
                }
                println!(
                    "session_dir={} passed={} failed={}",
                    summary.session_dir, summary.passed, summary.failed
                );
            }
            Ok(())
        },
        Commands::Assert {
            scenario,
            alerts,
            json,
        } => {
            let bundle = load_scenario_bundle(&cli.scenarios_dir, &scenario)?;
            let summary = evaluate_alert_expectations(&bundle, &alerts)?;
            if json {
                println!("{}", serde_json::to_string_pretty(&summary)?);
            } else {
                println!("scenario: {}", summary.scenario_id);
                println!("passed: {}", summary.passed);
                for rule in summary.checked_rules {
                    println!(
                        "- {} observed={} min_hits={} matched={}",
                        rule.rule_id, rule.observed_hits, rule.min_hits, rule.matched
                    );
                }
                if !summary.unexpected_hits.is_empty() {
                    println!("unexpected_hits: {}", summary.unexpected_hits.join(", "));
                }
            }
            Ok(())
        },
    }
}

fn setup_logging() -> Result<()> {
    let subscriber = FmtSubscriber::builder()
        .with_max_level(Level::INFO)
        .finish();
    tracing::subscriber::set_global_default(subscriber)
        .map_err(|e| anyhow!("failed to set tracing subscriber: {}", e))?;
    Ok(())
}

fn list_scenarios(scenarios_dir: &Path) -> Result<()> {
    let bundles = load_all_scenarios(scenarios_dir)?;
    for bundle in bundles {
        println!(
            "- {} [{}] ({}) - {}",
            bundle.scenario.id,
            bundle.scenario.category,
            bundle.scenario.status,
            bundle.scenario.name
        );
    }
    Ok(())
}

fn validate_scenarios(scenarios_dir: &Path) -> Result<()> {
    let bundles = load_all_scenarios(scenarios_dir)?;
    for bundle in &bundles {
        let script_path = bundle.dir.join(&bundle.scenario.execution.entrypoint);
        if !script_path.exists() {
            return Err(anyhow!(
                "scenario '{}' is missing entrypoint {}",
                bundle.scenario.id,
                script_path.display()
            ));
        }
        if bundle.expected.scenario_id != bundle.scenario.id {
            return Err(anyhow!(
                "scenario '{}' has mismatched expected_alerts scenario_id '{}'",
                bundle.scenario.id,
                bundle.expected.scenario_id
            ));
        }
        if bundle
            .expected
            .expected_rules
            .iter()
            .any(|rule| rule.min_hits == 0)
        {
            return Err(anyhow!(
                "scenario '{}' has expected rule with min_hits=0",
                bundle.scenario.id
            ));
        }
    }
    info!(count = bundles.len(), "Scenario validation completed");
    Ok(())
}

fn show_scenario(scenarios_dir: &Path, scenario_id: &str) -> Result<()> {
    let bundle = load_scenario_bundle(scenarios_dir, scenario_id)?;
    println!("id: {}", bundle.scenario.id);
    println!("name: {}", bundle.scenario.name);
    println!("category: {}", bundle.scenario.category);
    println!("severity: {}", bundle.scenario.severity);
    println!("status: {}", bundle.scenario.status);
    println!("summary: {}", bundle.scenario.summary);
    if !bundle.scenario.recommended_rules.is_empty() {
        println!("recommended_rules: {}", bundle.scenario.recommended_rules.join(", "));
    }
    if !bundle.expected.expected_rules.is_empty() {
        println!("expected_rules:");
        for rule in bundle.expected.expected_rules {
            println!("  - {} (min_hits={})", rule.rule_id, rule.min_hits);
        }
    }
    Ok(())
}

fn run_scenario(
    scenarios_dir: &Path,
    results_dir: &Path,
    scenario_id: &str,
    options: &SharedRunOptions,
    session_dir: Option<&Path>,
) -> Result<ScenarioRunSummary> {
    let bundle = load_scenario_bundle(scenarios_dir, scenario_id)?;
    let entrypoint = bundle.dir.join(&bundle.scenario.execution.entrypoint);
    if !entrypoint.exists() {
        return Err(anyhow!("scenario entrypoint does not exist: {}", entrypoint.display()));
    }

    let scenario_results_dir = prepare_results_dir(results_dir, &bundle.scenario.id, session_dir)?;
    let stdout_path = scenario_results_dir.join("stdout.log");
    let stderr_path = scenario_results_dir.join("stderr.log");
    let summary_path = scenario_results_dir.join("summary.json");

    let mut command = Command::new("bash");
    command.arg(&entrypoint).current_dir(&bundle.dir);
    command.env("KESTREL_LAB_EXECUTE", if options.execute { "1" } else { "0" });
    command.env(
        "KESTREL_LAB_ALLOW_REAL_TARGETS",
        if options.allow_real_targets { "1" } else { "0" },
    );

    for (key, value) in &bundle.scenario.execution.env {
        command.env(key, value);
    }
    for item in &options.env_vars {
        let (key, value) = item
            .split_once('=')
            .ok_or_else(|| anyhow!("invalid --env value '{}', expected KEY=VALUE", item))?;
        command.env(key, value);
    }

    info!(scenario = %bundle.scenario.id, path = %entrypoint.display(), results_dir = %scenario_results_dir.display(), "Running scenario");
    let output = command
        .output()
        .with_context(|| format!("failed to execute {}", entrypoint.display()))?;

    fs::write(&stdout_path, &output.stdout)
        .with_context(|| format!("failed to write {}", stdout_path.display()))?;
    fs::write(&stderr_path, &output.stderr)
        .with_context(|| format!("failed to write {}", stderr_path.display()))?;

    let archived_alerts_path = if let Some(alerts_path) = options.alerts.as_ref() {
        let archived = scenario_results_dir.join("alerts.json");
        fs::copy(alerts_path, &archived).with_context(|| {
            format!(
                "failed to archive alerts file from {} to {}",
                alerts_path.display(),
                archived.display()
            )
        })?;
        Some(archived)
    } else {
        None
    };

    let assertions = match archived_alerts_path.as_deref() {
        Some(path) => Some(evaluate_alert_expectations(&bundle, path)?),
        None => None,
    };

    let replay = match (&options.replay_log, &options.replay_rules) {
        (Some(log_path), Some(rules_dir)) => {
            let replay_summary = run_replay(log_path, rules_dir, options.replay_speed)?;
            let replay_summary_path = scenario_results_dir.join("replay_summary.json");
            fs::write(&replay_summary_path, serde_json::to_vec_pretty(&replay_summary)?)?;
            Some(replay_summary)
        },
        _ => None,
    };

    let summary = ScenarioRunSummary {
        scenario_id: bundle.scenario.id,
        exit_code: output.status.code().unwrap_or(-1),
        results_dir: scenario_results_dir.display().to_string(),
        stdout_log: stdout_path.display().to_string(),
        stderr_log: stderr_path.display().to_string(),
        assertions,
        replay,
    };
    fs::write(&summary_path, serde_json::to_vec_pretty(&summary)?)
        .with_context(|| format!("failed to write {}", summary_path.display()))?;

    Ok(summary)
}

fn run_all_scenarios(
    scenarios_dir: &Path,
    results_dir: &Path,
    options: &SharedRunOptions,
) -> Result<RunAllSummary> {
    let bundles = load_all_scenarios(scenarios_dir)?;
    let session_dir = create_session_dir(results_dir)?;
    let mut scenarios = Vec::new();
    let mut passed = 0;
    let mut failed = 0;

    for bundle in bundles {
        let summary = run_scenario(
            scenarios_dir,
            results_dir,
            &bundle.scenario.id,
            options,
            Some(session_dir.as_path()),
        )?;
        let scenario_passed = summary.exit_code == 0
            && summary
                .assertions
                .as_ref()
                .map(|value| value.passed)
                .unwrap_or(true);
        if scenario_passed {
            passed += 1;
        } else {
            failed += 1;
        }
        scenarios.push(summary);
    }

    let summary = RunAllSummary {
        session_dir: session_dir.display().to_string(),
        scenarios,
        passed,
        failed,
    };
    let session_summary = session_dir.join("summary.json");
    fs::write(&session_summary, serde_json::to_vec_pretty(&summary)?)?;
    Ok(summary)
}

fn evaluate_alert_expectations(
    bundle: &ScenarioBundle,
    alerts_path: &Path,
) -> Result<AssertionSummary> {
    let alerts = load_alerts(alerts_path)?;
    let mut checked_rules = Vec::new();
    for expected_rule in &bundle.expected.expected_rules {
        let observed_hits = alerts
            .iter()
            .filter(|alert| alert.rule_id == expected_rule.rule_id)
            .count();
        checked_rules.push(AssertionRuleResult {
            rule_id: expected_rule.rule_id.clone(),
            observed_hits,
            min_hits: expected_rule.min_hits,
            matched: observed_hits >= expected_rule.min_hits,
        });
    }

    let unexpected_hits = bundle
        .expected
        .unexpected_rules
        .iter()
        .filter(|rule_id| alerts.iter().any(|alert| &alert.rule_id == *rule_id))
        .cloned()
        .collect::<Vec<_>>();

    let passed = checked_rules.iter().all(|rule| rule.matched) && unexpected_hits.is_empty();
    Ok(AssertionSummary {
        scenario_id: bundle.scenario.id.clone(),
        passed,
        checked_rules,
        unexpected_hits,
    })
}

fn run_replay(log_path: &Path, rules_dir: &Path, speed: f64) -> Result<ReplaySummary> {
    let rt = tokio::runtime::Runtime::new().context("failed to create tokio runtime for replay")?;
    let mut engine = rt.block_on(async {
        kestrel_engine::DetectionEngine::new(kestrel_engine::EngineConfig {
            rules_dir: rules_dir.to_path_buf(),
            alert_output: kestrel_core::AlertOutputConfig {
                stdout: false,
                ..Default::default()
            },
            ..Default::default()
        })
        .await
    })?;

    let stats = rt.block_on(async {
        engine
            .replay_log(kestrel_core::ReplayConfig {
                log_path: log_path.to_path_buf(),
                speed_multiplier: speed,
                stop_on_error: true,
                verify_determinism: false,
                verification_runs: 1,
                ..Default::default()
            })
            .await
    })?;

    Ok(ReplaySummary {
        replay_log: log_path.display().to_string(),
        rules_dir: rules_dir.display().to_string(),
        events_processed: stats.events_processed,
        current_ts_mono_ns: stats.current_ts_mono_ns,
        current_ts_wall_ns: stats.current_ts_wall_ns,
    })
}

fn load_alerts(path: &Path) -> Result<Vec<MinimalAlert>> {
    let content = fs::read_to_string(path)
        .with_context(|| format!("failed to read alerts file {}", path.display()))?;
    let mut alerts = Vec::new();
    let stream = serde_json::Deserializer::from_str(&content).into_iter::<MinimalAlert>();
    for alert in stream {
        alerts
            .push(alert.with_context(|| format!("failed to parse alert from {}", path.display()))?);
    }
    Ok(alerts)
}

fn print_run_summary(summary: &ScenarioRunSummary, json: bool) -> Result<()> {
    if json {
        println!("{}", serde_json::to_string_pretty(summary)?);
        return Ok(());
    }

    println!("scenario: {}", summary.scenario_id);
    println!("exit_code: {}", summary.exit_code);
    println!("results_dir: {}", summary.results_dir);
    println!("stdout_log: {}", summary.stdout_log);
    println!("stderr_log: {}", summary.stderr_log);
    if let Some(assertions) = &summary.assertions {
        println!("assertions_passed: {}", assertions.passed);
        for rule in &assertions.checked_rules {
            println!(
                "- {} observed={} min_hits={} matched={}",
                rule.rule_id, rule.observed_hits, rule.min_hits, rule.matched
            );
        }
        if !assertions.unexpected_hits.is_empty() {
            println!("unexpected_hits: {}", assertions.unexpected_hits.join(", "));
        }
    }
    if let Some(replay) = &summary.replay {
        println!(
            "replay: events_processed={} current_ts_mono_ns={}",
            replay.events_processed, replay.current_ts_mono_ns
        );
    }
    Ok(())
}

fn create_session_dir(results_dir: &Path) -> Result<PathBuf> {
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("system time before UNIX_EPOCH")?
        .as_secs();
    let dir = results_dir.join(format!("session-{}", timestamp));
    fs::create_dir_all(&dir).with_context(|| format!("failed to create {}", dir.display()))?;
    Ok(dir)
}

fn prepare_results_dir(
    results_dir: &Path,
    scenario_id: &str,
    session_dir: Option<&Path>,
) -> Result<PathBuf> {
    let base_dir = match session_dir {
        Some(path) => path.to_path_buf(),
        None => create_session_dir(results_dir)?,
    };
    let scenario_dir = base_dir.join(scenario_id);
    fs::create_dir_all(&scenario_dir)
        .with_context(|| format!("failed to create {}", scenario_dir.display()))?;
    Ok(scenario_dir)
}

fn load_all_scenarios(scenarios_dir: &Path) -> Result<Vec<ScenarioBundle>> {
    let mut bundles = Vec::new();
    for entry in fs::read_dir(scenarios_dir)
        .with_context(|| format!("failed to read scenarios dir {}", scenarios_dir.display()))?
    {
        let path = entry?.path();
        if !path.is_dir() {
            continue;
        }
        bundles.push(load_scenario_bundle_from_dir(&path)?);
    }
    bundles.sort_by(|a, b| a.scenario.id.cmp(&b.scenario.id));
    Ok(bundles)
}

fn load_scenario_bundle(scenarios_dir: &Path, scenario_id: &str) -> Result<ScenarioBundle> {
    let dir = scenarios_dir.join(scenario_id);
    load_scenario_bundle_from_dir(&dir)
}

fn load_scenario_bundle_from_dir(dir: &Path) -> Result<ScenarioBundle> {
    let scenario_path = dir.join("scenario.yaml");
    let expected_path = dir.join("expected_alerts.json");

    let scenario: Scenario = serde_yaml::from_str(
        &fs::read_to_string(&scenario_path)
            .with_context(|| format!("failed to read {}", scenario_path.display()))?,
    )
    .with_context(|| format!("failed to parse {}", scenario_path.display()))?;

    let expected: ExpectedAlerts = serde_json::from_str(
        &fs::read_to_string(&expected_path)
            .with_context(|| format!("failed to read {}", expected_path.display()))?,
    )
    .with_context(|| format!("failed to parse {}", expected_path.display()))?;

    Ok(ScenarioBundle {
        dir: dir.to_path_buf(),
        scenario,
        expected,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_load_scenario_bundle_from_dir() {
        let dir = tempdir().unwrap();
        fs::write(
            dir.path().join("scenario.yaml"),
            r#"id: sample
name: Sample Scenario
category: test
severity: low
status: draft
summary: sample summary
recommended_rules: ["rule-001"]
execution:
  entrypoint: attack.sh
  env:
    DEMO: value
"#,
        )
        .unwrap();
        fs::write(
            dir.path().join("expected_alerts.json"),
            r#"{"scenario_id":"sample","expected_rules":[{"rule_id":"rule-001","min_hits":1}],"unexpected_rules":[]}"#,
        )
        .unwrap();
        fs::write(dir.path().join("attack.sh"), "#!/usr/bin/env bash\nexit 0\n").unwrap();

        let bundle = load_scenario_bundle_from_dir(dir.path()).unwrap();
        assert_eq!(bundle.scenario.id, "sample");
        assert_eq!(bundle.expected.expected_rules.len(), 1);
    }

    #[test]
    fn test_evaluate_alert_expectations() {
        let dir = tempdir().unwrap();
        fs::write(
            dir.path().join("scenario.yaml"),
            r#"id: sample
name: Sample Scenario
category: test
severity: low
status: draft
summary: sample summary
execution:
  entrypoint: attack.sh
"#,
        )
        .unwrap();
        fs::write(
            dir.path().join("expected_alerts.json"),
            r#"{"scenario_id":"sample","expected_rules":[{"rule_id":"rule-001","min_hits":1}],"unexpected_rules":["rule-999"]}"#,
        )
        .unwrap();
        fs::write(dir.path().join("attack.sh"), "#!/usr/bin/env bash\nexit 0\n").unwrap();
        let alerts_path = dir.path().join("alerts.json");
        fs::write(&alerts_path, "{\"rule_id\":\"rule-001\"}\n{\"rule_id\":\"rule-002\"}\n")
            .unwrap();

        let bundle = load_scenario_bundle_from_dir(dir.path()).unwrap();
        let summary = evaluate_alert_expectations(&bundle, &alerts_path).unwrap();
        assert!(summary.passed);
        assert_eq!(summary.checked_rules[0].observed_hits, 1);
    }

    #[test]
    fn test_prepare_results_dir() {
        let dir = tempdir().unwrap();
        let scenario_dir = prepare_results_dir(dir.path(), "sample", None).unwrap();
        assert!(scenario_dir.ends_with("sample"));
        assert!(scenario_dir.exists());
    }
}
