use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::PathBuf;
use std::process::{Command, Output};
use std::time::{SystemTime, UNIX_EPOCH};

fn fixtures() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../examples")
}

fn run(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_leak-fence"))
        .args(args)
        .output()
        .unwrap()
}

fn inspect_file(path: &str, contract: &str) -> Output {
    let root = fixtures();
    run(&[
        "inspect",
        root.join("contracts.json").to_str().unwrap(),
        contract,
        root.join("inspection/context.json").to_str().unwrap(),
        path,
    ])
}

fn scratch(content: &[u8]) -> PathBuf {
    let dir = fixtures().join("../.local/cli-tests");
    fs::create_dir_all(&dir).unwrap();
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let path = dir.join(format!("{}-{unique}.json", std::process::id()));
    OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&path)
        .unwrap()
        .write_all(content)
        .unwrap();
    path
}

#[test]
fn allowed_content_is_not_daily_quota_approval_and_body_is_not_printed() {
    let output = inspect_file(
        fixtures().join("inspection/allowed.json").to_str().unwrap(),
        "sample.customers",
    );
    assert!(output.status.success());
    let v: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(v["content_check"], "passed");
    assert_eq!(v["budget_check"], "not_performed");
    assert_eq!(v["cost"]["records"], 1);
    assert!(!String::from_utf8_lossy(&output.stdout).contains("合成データ"));
    assert!(output.stderr.is_empty());
}

#[test]
fn unauthorized_content_has_failure_exit_and_no_source_data() {
    for (file, code) in [
        ("foreign-tenant.json", "tenant_mismatch"),
        ("extra-field.json", "unapproved_field"),
    ] {
        let output = inspect_file(
            fixtures().join("inspection").join(file).to_str().unwrap(),
            "sample.customers",
        );
        assert_eq!(output.status.code(), Some(2));
        let v: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(v["error"], code);
        let text = String::from_utf8_lossy(&output.stdout);
        assert!(!text.contains("SYNTHETIC_REJECT_MARKER"));
        assert!(!text.contains("synthetic-acme"));
    }
}

#[test]
fn duplicate_keys_and_invalid_utf8_use_the_worker_inspector() {
    for body in [
        br#"{"id":"1","\u0069d":"1","tenant_id":"synthetic-acme"}"#.as_slice(),
        &[255],
    ] {
        let path = scratch(body);
        let output = inspect_file(path.to_str().unwrap(), "sample.customers");
        assert_eq!(output.status.code(), Some(2));
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&output.stdout).unwrap()["error"],
            "invalid_json"
        );
    }
}

#[test]
fn unknown_contract_and_oversized_file_fail_without_dumping_input() {
    let path = scratch(&vec![b'x'; 262_145]);
    for (contract, expected) in [
        ("unknown", "unconfigured_contract"),
        ("sample.customers", "byte_limit"),
    ] {
        let output = inspect_file(path.to_str().unwrap(), contract);
        assert_eq!(output.status.code(), Some(2));
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&output.stdout).unwrap()["error"],
            expected
        );
        assert!(output.stdout.len() < 200);
    }
}

#[test]
fn configuration_ambiguity_and_parser_errors_do_not_print_policy_values() {
    let original: serde_json::Value =
        serde_json::from_slice(&fs::read(fixtures().join("contracts.json")).unwrap()).unwrap();
    let mut other = original[0].clone();
    other["id"] = "SYNTHETIC_REJECT_MARKER".into();
    other["daily_records"] = 51.into();
    let conflicting = serde_json::to_vec(&serde_json::json!([original[0], other])).unwrap();
    for content in [
        conflicting,
        b"[SYNTHETIC_REJECT_MARKER]".to_vec(),
        vec![b'x'; 131_073],
    ] {
        let file = scratch(&content);
        let output = run(&["check", file.to_str().unwrap()]);
        assert_eq!(output.status.code(), Some(1));
        assert!(!String::from_utf8_lossy(&output.stdout).contains("SYNTHETIC_REJECT_MARKER"));
        assert!(output.stderr.is_empty());
    }
}

#[test]
fn valid_configuration_and_file_errors_have_distinct_outcomes() {
    assert!(
        run(&["check", fixtures().join("contracts.json").to_str().unwrap()])
            .status
            .success()
    );
    assert_eq!(
        run(&["check", "/not-a-real-leak-fence-file"]).status.code(),
        Some(1)
    );
    assert_eq!(run(&["inspect"]).status.code(), Some(1));
}

#[test]
fn embedded_demo_runs_from_any_directory_without_input_files() {
    let output = Command::new(env!("CARGO_BIN_EXE_leak-fence"))
        .arg("demo")
        .current_dir(std::env::temp_dir())
        .output()
        .unwrap();
    assert!(output.status.success());
    let v: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(v["demo"], "passed");
    assert_eq!(v["budget_check"], "not_performed");
    assert_eq!(v["network"], "not_used");
    assert_eq!(v["checks"].as_array().unwrap().len(), 3);
}
