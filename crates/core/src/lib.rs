//! Bounded disclosure checks. Caller-provided authority must come from trusted
//! server-side authorization. This crate does not authenticate users.
use serde::de::{self, MapAccess, SeqAccess, Visitor};
use serde::{Deserialize, Deserializer, Serialize};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

pub const MAX_BODY_BYTES: usize = 262_144;
pub const MAX_RECORDS: usize = 1_000;
pub const DAY_SECONDS: u64 = 86_400;

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Context {
    pub principal: String,
    pub tenant: String,
    pub permission: String,
    pub record_ids: BTreeSet<String>,
}

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Policy {
    pub id: String,
    /// Stable across routes and deployments that share a disclosure budget.
    pub budget_group: String,
    pub permission: String,
    pub fields: BTreeSet<String>,
    pub tenant_field: String,
    pub id_field: String,
    pub max_records: usize,
    pub max_bytes: usize,
    pub daily_records: u64,
    pub daily_bytes: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Cost {
    pub records: u64,
    pub bytes: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Denied {
    Configuration,
    Unauthorized,
    ByteLimit,
    RecordLimit,
    InvalidJson,
    TenantMismatch,
    ObjectUnauthorized,
    UnapprovedField,
    NestedValue,
}

impl Denied {
    pub fn code(self) -> &'static str {
        match self {
            Self::Configuration => "configuration",
            Self::Unauthorized => "unauthorized",
            Self::ByteLimit => "byte_limit",
            Self::RecordLimit => "record_limit",
            Self::InvalidJson => "invalid_json",
            Self::TenantMismatch => "tenant_mismatch",
            Self::ObjectUnauthorized => "object_unauthorized",
            Self::UnapprovedField => "unapproved_field",
            Self::NestedValue => "nested_value",
        }
    }
}

pub fn valid_id(value: &str) -> bool {
    !value.is_empty() && value.len() <= 128 && !value.chars().any(char::is_control)
}

impl Policy {
    pub fn validate(&self) -> Result<(), Denied> {
        if ![
            &self.id,
            &self.budget_group,
            &self.permission,
            &self.tenant_field,
            &self.id_field,
        ]
        .into_iter()
        .all(|s| valid_id(s))
            || self.tenant_field == self.id_field
            || self.fields.len() > 128
            || !self.fields.iter().all(|s| valid_id(s))
            || !self.fields.contains(&self.tenant_field)
            || !self.fields.contains(&self.id_field)
            || !(1..=MAX_RECORDS).contains(&self.max_records)
            || !(1..=MAX_BODY_BYTES).contains(&self.max_bytes)
            || !(1..=1_000_000_000).contains(&self.daily_records)
            || !(1..=1_000_000_000_000).contains(&self.daily_bytes)
        {
            return Err(Denied::Configuration);
        }
        Ok(())
    }
}

/// Reject configuration ambiguity rather than selecting the first contract.
pub fn validate_policies(policies: &[Policy]) -> Result<(), Denied> {
    if policies.is_empty() || policies.len() > 128 {
        return Err(Denied::Configuration);
    }
    let mut ids = BTreeSet::new();
    let mut groups = BTreeMap::new();
    for p in policies {
        p.validate()?;
        if !ids.insert(&p.id) {
            return Err(Denied::Configuration);
        }
        let limits = (p.daily_records, p.daily_bytes);
        if groups
            .insert(&p.budget_group, limits)
            .is_some_and(|old| old != limits)
        {
            return Err(Denied::Configuration);
        }
    }
    Ok(())
}

/// Never derives permission from the data being inspected.
pub fn inspect(body: &[u8], policy: &Policy, context: &Context) -> Result<Cost, Denied> {
    policy.validate()?;
    if !valid_id(&context.principal)
        || !valid_id(&context.tenant)
        || context.permission != policy.permission
        || context.record_ids.len() > MAX_RECORDS
        || !context.record_ids.iter().all(|id| valid_id(id))
    {
        return Err(Denied::Unauthorized);
    }
    if body.len() > policy.max_bytes {
        return Err(Denied::ByteLimit);
    }
    let Document(records) = serde_json::from_slice(body).map_err(|_| Denied::InvalidJson)?;
    if records.len() > policy.max_records {
        return Err(Denied::RecordLimit);
    }
    for FlatRecord(record) in &records {
        if record.get(&policy.tenant_field).and_then(Value::as_str) != Some(&context.tenant) {
            return Err(Denied::TenantMismatch);
        }
        let id = record
            .get(&policy.id_field)
            .and_then(Value::as_str)
            .ok_or(Denied::ObjectUnauthorized)?;
        if !context.record_ids.contains(id) {
            return Err(Denied::ObjectUnauthorized);
        }
        if !record.keys().all(|key| policy.fields.contains(key)) {
            return Err(Denied::UnapprovedField);
        }
        if record.values().any(|v| v.is_array() || v.is_object()) {
            return Err(Denied::NestedValue);
        }
    }
    Ok(Cost {
        records: records.len() as u64,
        bytes: body.len() as u64,
    })
}

struct FlatRecord(BTreeMap<String, Value>);

fn read_record<'de, M: MapAccess<'de>>(mut map: M) -> Result<FlatRecord, M::Error> {
    let mut fields = BTreeMap::new();
    while let Some((key, value)) = map.next_entry::<String, Value>()? {
        if fields.insert(key, value).is_some() || fields.len() > 128 {
            return Err(de::Error::custom("duplicate or excessive keys"));
        }
    }
    Ok(FlatRecord(fields))
}

impl<'de> Deserialize<'de> for FlatRecord {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct RecordVisitor;
        impl<'de> Visitor<'de> for RecordVisitor {
            type Value = FlatRecord;
            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                f.write_str("a record")
            }
            fn visit_map<M: MapAccess<'de>>(self, map: M) -> Result<Self::Value, M::Error> {
                read_record(map)
            }
        }
        d.deserialize_map(RecordVisitor)
    }
}

struct Document(Vec<FlatRecord>);
impl<'de> Deserialize<'de> for Document {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct DocumentVisitor;
        impl<'de> Visitor<'de> for DocumentVisitor {
            type Value = Document;
            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                f.write_str("record or record array")
            }
            fn visit_map<M: MapAccess<'de>>(self, map: M) -> Result<Self::Value, M::Error> {
                Ok(Document(vec![read_record(map)?]))
            }
            fn visit_seq<S: SeqAccess<'de>>(self, mut seq: S) -> Result<Self::Value, S::Error> {
                let mut records = Vec::new();
                while let Some(record) = seq.next_element()? {
                    if records.len() == MAX_RECORDS {
                        return Err(de::Error::custom("excessive records"));
                    }
                    records.push(record);
                }
                Ok(Document(records))
            }
        }
        d.deserialize_any(DocumentVisitor)
    }
}

/// One SQLite statement charges a UTC calendar-day budget before disclosure.
/// No refund: a lost reply can overcount but must not enable an uncharged send.
/// Parameters: day, records, bytes, daily record limit, daily byte limit.
pub const CHARGE_SQL: &str = "
INSERT INTO budget (id, day, records, bytes) VALUES (1, ?1, ?2, ?3)
ON CONFLICT(id) DO UPDATE SET
  day = excluded.day,
  records = CASE WHEN budget.day < excluded.day THEN excluded.records ELSE budget.records + excluded.records END,
  bytes = CASE WHEN budget.day < excluded.day THEN excluded.bytes ELSE budget.bytes + excluded.bytes END
WHERE budget.day <= excluded.day
  AND (CASE WHEN budget.day < excluded.day THEN excluded.records ELSE budget.records + excluded.records END) <= ?4
  AND (CASE WHEN budget.day < excluded.day THEN excluded.bytes ELSE budget.bytes + excluded.bytes END) <= ?5
RETURNING records, bytes";

pub const CREATE_BUDGET_SQL: &str = "CREATE TABLE IF NOT EXISTS budget (
id INTEGER PRIMARY KEY CHECK(id = 1), day INTEGER NOT NULL,
records INTEGER NOT NULL CHECK(records >= 0), bytes INTEGER NOT NULL CHECK(bytes >= 0))";

#[cfg(test)]
mod tests {
    use super::*;
    fn policy() -> Policy {
        serde_json::from_str(r#"{"id":"customers","budget_group":"customers","permission":"read","fields":["id","tenant_id","name"],"tenant_field":"tenant_id","id_field":"id","max_records":2,"max_bytes":200,"daily_records":10,"daily_bytes":2000}"#).unwrap()
    }
    fn context() -> Context {
        serde_json::from_str(
            r#"{"principal":"alice","tenant":"acme","permission":"read","record_ids":["1","2"]}"#,
        )
        .unwrap()
    }
    #[test]
    fn intended_disclosure_and_utf8_cost() {
        let body = r#"[{"id":"1","tenant_id":"acme","name":"合成データ"}]"#.as_bytes();
        assert_eq!(
            inspect(body, &policy(), &context()),
            Ok(Cost {
                records: 1,
                bytes: body.len() as u64
            })
        );
        assert_eq!(inspect(b"[]", &policy(), &context()).unwrap().records, 0);
    }
    #[test]
    fn tenant_object_and_field_boundaries() {
        for (body, reason) in [
            (r#"{"id":"1","tenant_id":"else"}"#, Denied::TenantMismatch),
            (
                r#"{"id":"3","tenant_id":"acme"}"#,
                Denied::ObjectUnauthorized,
            ),
            (r#"{"id":1,"tenant_id":"acme"}"#, Denied::ObjectUnauthorized),
            (
                r#"{"id":"1","tenant_id":"acme","secret":"hidden"}"#,
                Denied::UnapprovedField,
            ),
            (
                r#"{"id":"1","tenant_id":"acme","name":{"x":"hidden"}}"#,
                Denied::NestedValue,
            ),
        ] {
            assert_eq!(inspect(body.as_bytes(), &policy(), &context()), Err(reason));
        }
    }
    #[test]
    fn ambiguous_and_malformed_json_denied() {
        for body in [
            r#"{"id":"1","\u0069d":"2","tenant_id":"acme"}"#,
            "NaN",
            "1e999",
            "null",
            "[1]",
            "{}{}",
            r#"{"id":"1","tenant_id":"acme","name":NaN}"#,
        ] {
            assert_eq!(
                inspect(body.as_bytes(), &policy(), &context()),
                Err(Denied::InvalidJson)
            );
        }
        assert_eq!(
            inspect(&[255], &policy(), &context()),
            Err(Denied::InvalidJson)
        );
    }
    #[test]
    fn bounds_and_authority() {
        let row = r#"{"id":"1","tenant_id":"acme"}"#;
        let body = format!("[{row},{row},{row}]");
        assert_eq!(
            inspect(body.as_bytes(), &policy(), &context()),
            Err(Denied::RecordLimit)
        );
        assert_eq!(
            inspect(&[b' '; 201], &policy(), &context()),
            Err(Denied::ByteLimit)
        );
        let mut c = context();
        c.permission = "admin".into();
        assert_eq!(inspect(b"[]", &policy(), &c), Err(Denied::Unauthorized));
        c = context();
        c.principal.clear();
        assert_eq!(inspect(b"[]", &policy(), &c), Err(Denied::Unauthorized));
    }
    #[test]
    fn ambiguous_configuration_is_rejected() {
        let p = policy();
        let mut second = policy();
        assert_eq!(
            validate_policies(&[p.clone(), second.clone()]),
            Err(Denied::Configuration)
        );
        second.id = "other_route".into();
        second.daily_records += 1;
        assert_eq!(validate_policies(&[p, second]), Err(Denied::Configuration));
        let mut p = policy();
        p.id_field = p.tenant_field.clone();
        assert_eq!(p.validate(), Err(Denied::Configuration));
    }
    #[test]
    fn permitted_value_content_is_not_an_authorization_or_pii_oracle() {
        // Explicit limitation: permitted labels cannot prove a value's origin.
        let body = br#"{"id":"1","tenant_id":"acme","name":"unrelated secret"}"#;
        assert!(inspect(body, &policy(), &context()).is_ok());
    }
}
