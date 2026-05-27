use std::sync::{Arc, Mutex};

use crate::policy::{Action, Policy, RuleData};
use chrono::{DateTime, Local};
use rusqlite::{Connection, Result as SqliteResult, params};
use tracing::info;

#[derive(Debug, Clone)]
pub struct LimitRule {
    pub id: i64,
    pub tag: String,
    pub max_duration_secs: i64,
}

#[derive(Clone)]
pub struct LimitManager {
    conn: Arc<Mutex<Connection>>,
}

impl LimitManager {
    pub fn new(conn: Arc<Mutex<Connection>>) -> SqliteResult<Self> {
        conn.lock().unwrap().execute(
            "CREATE TABLE IF NOT EXISTS limit_rules (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                tag TEXT NOT NULL UNIQUE,
                max_duration_secs INTEGER NOT NULL
            )",
            [],
        )?;

        Ok(Self { conn })
    }

    pub fn add_limit(&self, tag: &str, duration_secs: i64) -> SqliteResult<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO limit_rules (tag, max_duration_secs) VALUES (?1, ?2)
             ON CONFLICT(tag) DO UPDATE SET max_duration_secs = excluded.max_duration_secs",
            params![tag, duration_secs],
        )?;
        Ok(())
    }

    pub fn delete_limit(&self, tag: &str) -> SqliteResult<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute("DELETE FROM limit_rules WHERE tag = ?1", params![tag])?;
        Ok(())
    }

    pub fn get_all_limits(&self) -> SqliteResult<Vec<LimitRule>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare("SELECT id, tag, max_duration_secs FROM limit_rules")?;
        let rules = stmt
            .query_map([], |row| {
                Ok(LimitRule {
                    id: row.get(0)?,
                    tag: row.get(1)?,
                    max_duration_secs: row.get(2)?,
                })
            })?
            .filter_map(|r| r.ok())
            .collect();
        Ok(rules)
    }

    // Checks usage against limits and enforces blocks
    // pub fn enforce(&self) -> SqliteResult<()> {
    //     let limits = self.get_all_limits()?;
    //     let now = Local::now();
    //     let today_start = now.date_naive().and_hms_opt(0, 0, 0).unwrap();
    //     let today_start_str =
    //         DateTime::<Local>::from_naive_utc_and_offset(today_start, *now.offset()).to_rfc3339();

    //     for limit in limits {
    //         let usage = self.get_tag_usage_duration(&limit.tag, &today_start_str)?;

    //         let rule_name = format!("[LIMIT] {}", limit.tag);

    //         if usage >= limit.max_duration_secs {
    //             info!(
    //                 "Limit exceeded for tag '{}': current={}s max={}s. Blocking...",
    //                 limit.tag, usage, limit.max_duration_secs
    //             );

    //             // Add block rule if not already present
    //             let rules = self.policy.get_all_rules();
    //             let already_blocked = rules
    //                 .iter()
    //                 .any(|r| r.data.name.as_deref() == Some(&rule_name));

    //             if !already_blocked {
    //                 self.policy.insert_rule(RuleData {
    //                     priority: 10, // High priority for limits
    //                     action: Action::Block,
    //                     name: Some(rule_name),
    //                     domain: None,
    //                     tag: Some(limit.tag.clone()),
    //                     path_pattern: None,
    //                     client_ip: None,
    //                 })?;
    //             }
    //         } else {
    //             // Remove block rule if present
    //             self.policy.delete_rules_by_name(&rule_name)?;
    //         }
    //     }
    //     Ok(())
    // }

    // fn get_tag_usage_duration(&self, tag: &str, start_time_rfc3339: &str) -> SqliteResult<i64> {
    //     let conn = self.policy.get_connection();
    //     let conn = conn.lock().unwrap();

    //     // Sum durations from access_logs
    //     // duration = last_access - first_access
    //     // We use strftime/unixepoch to calculate difference in sqlite
    //     let mut stmt = conn.prepare(
    //         "SELECT SUM(
    //             (strftime('%s', last_access) - strftime('%s', first_access))
    //         ) FROM access_logs
    //         WHERE tag = ?1 AND last_access >= ?2",
    //     )?;

    //     let mut rows = stmt.query(params![tag, start_time_rfc3339])?;
    //     if let Some(row) = rows.next()? {
    //         let total: Option<i64> = row.get(0)?;
    //         Ok(total.unwrap_or(0))
    //     } else {
    //         Ok(0)
    //     }
    // }
}
