use futures_util::StreamExt;
use leak_fence_core::{
    CHARGE_SQL, CREATE_BUDGET_SQL, Context as Authority, Cost, DAY_SECONDS, Policy, inspect,
    validate_policies,
};
use serde::{Deserialize, Serialize};
use worker::*;

const MAX_ENVELOPE: usize = 1_700_000; // bounded JSON escaping + at most 1,000 allowed IDs

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Check {
    contract: String,
    context: Authority,
    response_body: String,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Charge {
    cost: Cost,
    daily_records: u64,
    daily_bytes: u64,
}

fn reply(status: u16, body: Vec<u8>) -> Result<Response> {
    let headers = Headers::new();
    headers.set("Content-Type", "application/json")?;
    headers.set("Cache-Control", "no-store")?;
    headers.set("X-Content-Type-Options", "nosniff")?;
    Ok(Response::from_bytes(body)?
        .with_status(status)
        .with_headers(headers))
}

fn reject(status: u16, reason: &str) -> Result<Response> {
    reply(
        status,
        serde_json::to_vec(&serde_json::json!({"error":reason}))?,
    )
}

async fn bounded(req: &mut Request, limit: usize) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    let mut stream = req.stream()?;
    let mut chunks = 0usize;
    while let Some(chunk) = stream.next().await {
        let chunk = chunk?;
        chunks += 1;
        if chunk.len() > limit.saturating_sub(bytes.len()) || chunks > 16_384 {
            return Err(Error::RustError("body_limit".into()));
        }
        bytes.extend_from_slice(&chunk);
    }
    Ok(bytes)
}

#[event(fetch)]
pub async fn main(req: Request, env: Env, _ctx: Context) -> Result<Response> {
    // All unexpected runtime/configuration/storage failures stop disclosure.
    use futures_util::future::{Either, select};
    match select(
        Box::pin(handle(req, env)),
        Box::pin(Delay::from(std::time::Duration::from_secs(5))),
    )
    .await
    {
        Either::Left((Ok(response), _)) => Ok(response),
        _ => reject(503, "unavailable"),
    }
}

async fn handle(mut req: Request, env: Env) -> Result<Response> {
    if env.var("SERVICE_ENABLED")?.to_string() != "true" {
        return reject(503, "disabled");
    }
    let path = req.path();
    if req.method() != Method::Post || !matches!(path.as_str(), "/v1/protect" | "/v1/evaluate") {
        return reject(404, "not_found");
    }
    if req.headers().get("Content-Encoding")?.is_some()
        || req.headers().get("Content-Type")?.as_deref() != Some("application/json")
    {
        return reject(415, "media_type");
    }
    let bytes = match bounded(&mut req, MAX_ENVELOPE).await {
        Ok(b) => b,
        Err(_) => return reject(413, "body_limit"),
    };
    let check: Check = match serde_json::from_slice(&bytes) {
        Ok(c) => c,
        Err(_) => return reject(400, "invalid_contract_request"),
    };
    let policy_json = env.var("POLICIES_JSON")?.to_string();
    if policy_json.len() > 131_072 {
        return reject(503, "configuration");
    }
    let policies: Vec<Policy> = serde_json::from_str(&policy_json)?;
    if validate_policies(&policies).is_err() {
        return reject(503, "configuration");
    }
    let Some(policy) = policies.iter().find(|p| p.id == check.contract) else {
        return reject(403, "unconfigured_contract");
    };
    let cost = match inspect(check.response_body.as_bytes(), policy, &check.context) {
        Ok(cost) => cost,
        Err(reason) => return reject(403, reason.code()),
    };
    if path == "/v1/evaluate" {
        // Content-free evaluation only; deliberately does not reserve quota or forward data.
        return reply(
            200,
            serde_json::to_vec(
                &serde_json::json!({"content_check":"passed","budget_check":"not_performed","cost":cost}),
            )?,
        );
    }
    // JSON tuple prevents delimiter collisions. IDs must be opaque; no response data is stored.
    let key = serde_json::to_string(&(
        &check.context.tenant,
        &check.context.principal,
        &policy.budget_group,
    ))?;
    let stub = env
        .durable_object("BUDGETS")?
        .id_from_name(&key)?
        .get_stub()?;
    let charge = Charge {
        cost,
        daily_records: policy.daily_records,
        daily_bytes: policy.daily_bytes,
    };
    let headers = Headers::new();
    headers.set("Content-Type", "application/json")?;
    let mut init = RequestInit::new();
    init.with_method(Method::Post)
        .with_headers(headers)
        .with_body(Some(serde_json::to_string(&charge)?.into()));
    let result = stub
        .fetch_with_request(Request::new_with_init(
            "https://budget.internal/charge",
            &init,
        )?)
        .await?;
    match result.status_code() {
        204 => reply(200, check.response_body.into_bytes()),
        429 => reject(429, "disclosure_budget"),
        _ => reject(503, "budget_unavailable"),
    }
}

#[durable_object]
pub struct DisclosureBudget {
    state: State,
}

impl DurableObject for DisclosureBudget {
    fn new(state: State, _env: Env) -> Self {
        Self { state }
    }
    async fn fetch(&self, mut req: Request) -> Result<Response> {
        match self.charge(&mut req).await {
            Ok(response) => Ok(response),
            Err(_) => reject(503, "budget_unavailable"),
        }
    }
}

impl DisclosureBudget {
    async fn charge(&self, req: &mut Request) -> Result<Response> {
        if req.method() != Method::Post || req.path() != "/charge" {
            return reject(404, "not_found");
        }
        let bytes = bounded(req, 1_024).await?;
        let c: Charge = serde_json::from_slice(&bytes)?;
        if c.daily_records == 0
            || c.daily_records > 1_000_000_000
            || c.daily_bytes == 0
            || c.daily_bytes > 1_000_000_000_000
            || c.cost.bytes == 0
            || c.cost.bytes > 262_144
            || c.cost.records > 1_000
        {
            return reject(400, "invalid_charge");
        }
        // Required also for the first INSERT, whose conflict predicate does not run.
        if c.cost.records > c.daily_records || c.cost.bytes > c.daily_bytes {
            return reject(429, "disclosure_budget");
        }
        let day = (Date::now().as_millis() / 1_000 / DAY_SECONDS) as i64;
        let storage = self.state.storage();
        let sql = storage.sql();
        sql.exec(CREATE_BUDGET_SQL, None)?;
        let cursor = sql.exec(
            CHARGE_SQL,
            Some(vec![
                SqlStorageValue::Integer(day),
                SqlStorageValue::Integer(c.cost.records as i64),
                SqlStorageValue::Integer(c.cost.bytes as i64),
                SqlStorageValue::Integer(c.daily_records as i64),
                SqlStorageValue::Integer(c.daily_bytes as i64),
            ]),
        )?;
        #[derive(Deserialize)]
        struct Used {
            records: u64,
            bytes: u64,
        }
        let used = cursor.next::<Used>().next().transpose()?;
        // Await durability before the worker can return a protected body.
        storage.sync().await?;
        match used {
            Some(used) if used.records <= c.daily_records && used.bytes <= c.daily_bytes => {
                Response::empty().map(|r| r.with_status(204))
            }
            _ => reject(429, "disclosure_budget"),
        }
    }
}
