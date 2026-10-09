//! Offline checks using the same validation code as the Worker. No networking,
//! persistence, quota reservation, or response-body output.
use leak_fence_core::{Context, MAX_BODY_BYTES, Policy, inspect, validate_policies};
use std::fs::File;
use std::io::{self, Read, Write};
use std::process::ExitCode;

const MAX_POLICIES_BYTES: usize = 131_072;
const MAX_CONTEXT_BYTES: usize = 1_700_000;

enum ReadFailure {
    Io,
    Limit,
}

fn bounded_file(path: &str, limit: usize) -> Result<Vec<u8>, ReadFailure> {
    if !std::fs::metadata(path)
        .map_err(|_| ReadFailure::Io)?
        .is_file()
    {
        return Err(ReadFailure::Io);
    }
    let file = File::open(path).map_err(|_| ReadFailure::Io)?;
    // Only regular files are supported; do not trust metadata length.
    if !file.metadata().map_err(|_| ReadFailure::Io)?.is_file() {
        return Err(ReadFailure::Io);
    }
    let mut bytes = Vec::new();
    file.take(limit as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| ReadFailure::Io)?;
    if bytes.len() > limit {
        return Err(ReadFailure::Limit);
    }
    Ok(bytes)
}

fn policies(path: &str) -> Result<Vec<Policy>, &'static str> {
    let bytes = bounded_file(path, MAX_POLICIES_BYTES).map_err(|_| "policy_file")?;
    let policies: Vec<Policy> = serde_json::from_slice(&bytes).map_err(|_| "policy_json")?;
    validate_policies(&policies).map_err(|_| "configuration")?;
    Ok(policies)
}

fn output(value: serde_json::Value, code: u8) -> ExitCode {
    // Serialize only fixed reason codes and counts, never parser errors or input.
    let mut stdout = io::stdout().lock();
    if writeln!(stdout, "{value}").is_err() {
        return ExitCode::FAILURE;
    }
    ExitCode::from(code)
}

fn failure(reason: &str) -> ExitCode {
    output(serde_json::json!({"error": reason}), 1)
}

fn denied(reason: &str) -> ExitCode {
    output(
        serde_json::json!({
            "content_check": "denied", "budget_check": "not_performed", "error": reason
        }),
        2,
    )
}

fn demo() -> ExitCode {
    let policies: Vec<Policy> = match serde_json::from_slice::<Vec<Policy>>(include_bytes!(
        "../../../examples/contracts.json"
    )) {
        Ok(policies) if validate_policies(&policies).is_ok() => policies,
        _ => return failure("demo_configuration"),
    };
    let context: Context =
        match serde_json::from_slice(include_bytes!("../../../examples/inspection/context.json")) {
            Ok(context) => context,
            Err(_) => return failure("demo_configuration"),
        };
    let checks: [(&str, &[u8], &str); 3] = [
        (
            "allowed",
            include_bytes!("../../../examples/inspection/allowed.json"),
            "passed",
        ),
        (
            "foreign_tenant",
            include_bytes!("../../../examples/inspection/foreign-tenant.json"),
            "tenant_mismatch",
        ),
        (
            "extra_field",
            include_bytes!("../../../examples/inspection/extra-field.json"),
            "unapproved_field",
        ),
    ];
    let mut results = Vec::new();
    for (scenario, body, expected) in checks {
        let actual = match inspect(body, &policies[0], &context) {
            Ok(_) => "passed",
            Err(reason) => reason.code(),
        };
        if actual != expected {
            return failure("demo_failed");
        }
        results.push(serde_json::json!({"scenario": scenario, "result": actual}));
    }
    output(
        serde_json::json!({
            "demo": "passed", "checks": results, "budget_check": "not_performed", "network": "not_used"
        }),
        0,
    )
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args
        .iter()
        .map(String::as_str)
        .collect::<Vec<_>>()
        .as_slice()
    {
        [] | ["help" | "--help" | "-h"] => {
            let text = "LeakFence: offline policy and response checks / ローカル設定・応答検査\n\
                leak-fence check <policies.json>\n\
                leak-fence inspect <policies.json> <contract> <context.json> <response.json>\n\
                leak-fence demo\n\
                inspect does NOT enforce or reserve daily quotas. No data is sent or saved.\n\
                inspectは内容検査のみ。日次枠は確認・消費せず、データの送信・保存もしません。\n\
                Exit: 0 passed, 2 content denied, 1 configuration/file/usage failure.\n";
            if io::stdout().write_all(text.as_bytes()).is_err() {
                ExitCode::FAILURE
            } else {
                ExitCode::SUCCESS
            }
        }
        ["demo"] => demo(),
        ["check", path] => match policies(path) {
            Ok(policies) => output(
                serde_json::json!({"configuration": "valid", "contracts": policies.len()}),
                0,
            ),
            Err(reason) => failure(reason),
        },
        ["inspect", path, contract, context_path, body_path] => {
            let policies = match policies(path) {
                Ok(policies) => policies,
                Err(reason) => return failure(reason),
            };
            let Some(policy) = policies.iter().find(|p| p.id == *contract) else {
                return denied("unconfigured_contract");
            };
            let context = match bounded_file(context_path, MAX_CONTEXT_BYTES) {
                Ok(bytes) => match serde_json::from_slice::<Context>(&bytes) {
                    Ok(context) => context,
                    Err(_) => return failure("context_json"),
                },
                Err(_) => return failure("context_file"),
            };
            let body = match bounded_file(body_path, MAX_BODY_BYTES) {
                Ok(body) => body,
                Err(ReadFailure::Limit) => return denied("byte_limit"),
                Err(ReadFailure::Io) => return failure("response_file"),
            };
            match inspect(&body, policy, &context) {
                Ok(cost) => output(
                    serde_json::json!({
                        "content_check": "passed", "budget_check": "not_performed", "cost": cost
                    }),
                    0,
                ),
                Err(reason) => denied(reason.code()),
            }
        }
        _ => failure("usage"),
    }
}
