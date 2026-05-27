//! Access logging implementation using rusqlite
use crate::policy::Action;
use chrono::{DateTime, Local};
use rusqlite::{Connection, Result as SqliteResult, params};
use std::collections::HashMap;
use std::sync::{Arc, Mutex, RwLock};

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct AccessSession {
    pub device_ip: String,
    pub target_domain: String,
    /// If this session was aggregated by a tag, this holds the tag name.
    /// NULL-equivalent (None) means it was recorded by raw domain.
    pub tag: Option<String>,
    pub action: Action,
    pub first_access: DateTime<Local>,
    pub last_access: DateTime<Local>,
    pub request_count: i32,
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum LogStatus {
    Active,
    Persistent,
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct LogEntry {
    pub session: AccessSession,
    pub status: LogStatus,
}

pub struct AccessLogger {
    conn: Arc<Mutex<Connection>>,
    active_sessions: Arc<RwLock<HashMap<String, AccessSession>>>,
}

impl AccessLogger {
    pub fn new(conn: Arc<Mutex<Connection>>) -> SqliteResult<Self> {
        {
            let conn = conn.lock().unwrap();
            conn.execute(
                "CREATE TABLE IF NOT EXISTS access_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                device_ip TEXT NOT NULL,
                target_domain TEXT NOT NULL,
                tag TEXT,
                action TEXT NOT NULL,
                first_access TIMESTAMP,
                last_access TIMESTAMP,
                request_count INTEGER
            )",
                [],
            )?;
        }

        Ok(Self {
            conn,
            active_sessions: Arc::new(RwLock::new(HashMap::new())),
        })
    }

    pub fn record_access(
        &self,
        device_ip: &str,
        target_domain: &str,
        action: &Action,
        tag_name: Option<&str>,
    ) {
        let target_domain = target_domain.to_lowercase();

        // Key for sessionizing:
        // If tagged, use tag name as the aggregation key.
        // If not tagged, use the raw domain name.
        let (agg_key, session_tag) = match tag_name {
            Some(t) => (t.to_string(), Some(t.to_string())),
            None => (target_domain.to_string(), None),
        };

        let key = format!("{}|{}|{}", device_ip, agg_key, action.as_str());
        let now = Local::now();
        let mut sessions = self.active_sessions.write().unwrap();

        if let Some(session) = sessions.get_mut(&key) {
            session.last_access = now;
            session.request_count += 1;
        } else {
            sessions.insert(
                key,
                AccessSession {
                    device_ip: device_ip.to_string(),
                    target_domain: agg_key,
                    tag: session_tag,
                    action: action.clone(),
                    first_access: now,
                    last_access: now,
                    request_count: 1,
                },
            );
        }
    }

    pub fn sweep_sessions(&self, timeout_secs: i64) -> SqliteResult<()> {
        let now = Local::now();

        // Extract expired sessions
        let expired_sessions: Vec<_> = {
            let mut sessions = self.active_sessions.write().unwrap();
            let mut to_remove = Vec::new();

            for (key, session) in sessions.iter() {
                if (now - session.last_access).num_seconds() > timeout_secs {
                    to_remove.push(key.clone());
                }
            }

            to_remove
                .into_iter()
                .filter_map(|k| sessions.remove(&k))
                .collect()
        };

        if expired_sessions.is_empty() {
            return Ok(());
        }

        // Save to DB
        let conn = self.conn.lock().unwrap();

        for session in expired_sessions {
            conn.execute(
                "INSERT INTO access_logs (device_ip, target_domain, tag, action, first_access, last_access, request_count)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                params![
                    session.device_ip,
                    session.target_domain,
                    session.tag,
                    session.action.as_str(),
                    session.first_access.to_rfc3339(),
                    session.last_access.to_rfc3339(),
                    session.request_count
                ],
            )?;
        }
        Ok(())
    }

    pub fn get_access_logs(
        &self,
        limit: usize,
        ip_filter: Option<&str>,
        tag_filter: Option<bool>, // Some(true)=tagged only, Some(false)=untagged only, None=all
    ) -> SqliteResult<Vec<AccessSession>> {
        let conn = self.conn.lock().unwrap();

        let tag_clause = match tag_filter {
            Some(true) => " AND tag IS NOT NULL",
            Some(false) => " AND tag IS NULL",
            None => "",
        };

        let sql = if ip_filter.is_some() {
            format!(
                "SELECT device_ip, target_domain, tag, action, first_access, last_access, request_count
                 FROM access_logs WHERE device_ip = ?1{tag_clause}
                 ORDER BY last_access DESC LIMIT ?2"
            )
        } else {
            format!(
                "SELECT device_ip, target_domain, tag, action, first_access, last_access, request_count
                 FROM access_logs WHERE 1=1{tag_clause}
                 ORDER BY last_access DESC LIMIT ?1"
            )
        };

        let mut stmt = conn.prepare(&sql)?;

        let map_row = |row: &rusqlite::Row| {
            let action_str: String = row.get(3)?;
            let tag: Option<String> = row.get(2)?;
            Ok(AccessSession {
                device_ip: row.get(0)?,
                target_domain: row.get(1)?,
                tag,
                action: Action::from_str(&action_str),
                first_access: row
                    .get::<_, String>(4)
                    .ok()
                    .and_then(|s| chrono::DateTime::parse_from_rfc3339(&s).ok())
                    .map(|dt| dt.with_timezone(&Local))
                    .unwrap_or_else(Local::now),
                last_access: row
                    .get::<_, String>(5)
                    .ok()
                    .and_then(|s| chrono::DateTime::parse_from_rfc3339(&s).ok())
                    .map(|dt| dt.with_timezone(&Local))
                    .unwrap_or_else(Local::now),
                request_count: row.get(6)?,
            })
        };

        let rows: Vec<AccessSession> = if let Some(ip) = ip_filter {
            stmt.query_map(rusqlite::params![ip, limit as i64], map_row)?
                .filter_map(|r| r.ok())
                .collect()
        } else {
            stmt.query_map(rusqlite::params![limit as i64], map_row)?
                .filter_map(|r| r.ok())
                .collect()
        };

        Ok(rows)
    }

    pub fn get_combined_logs(&self, limit: usize) -> SqliteResult<Vec<LogEntry>> {
        let mut combined = Vec::new();

        // 1. Get active sessions
        {
            let sessions = self.active_sessions.read().unwrap();
            for session in sessions.values() {
                combined.push(LogEntry {
                    session: session.clone(),
                    status: LogStatus::Active,
                });
            }
        }

        // 2. Get persistent logs
        let db_logs = self.get_access_logs(limit, None, None)?;
        for log in db_logs {
            combined.push(LogEntry {
                session: log,
                status: LogStatus::Persistent,
            });
        }

        // Sort by last_access DESC
        combined.sort_by(|a, b| b.session.last_access.cmp(&a.session.last_access));

        // Limit results
        if combined.len() > limit {
            combined.truncate(limit);
        }

        Ok(combined)
    }

    pub fn clear_access_logs(&self) -> SqliteResult<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute("DELETE FROM access_logs", [])?;
        // Also clear memory sessions if we want a fresh start
        let mut sessions = self.active_sessions.write().unwrap();
        sessions.clear();
        Ok(())
    }

    pub fn get_active_sessions(&self) -> Vec<AccessSession> {
        let sessions = self.active_sessions.read().unwrap();
        sessions.values().cloned().collect()
    }

    pub fn get_connection(&self) -> Arc<Mutex<Connection>> {
        Arc::clone(&self.conn)
    }
}

impl Clone for AccessLogger {
    fn clone(&self) -> Self {
        Self {
            conn: Arc::clone(&self.conn),
            active_sessions: Arc::clone(&self.active_sessions),
        }
    }
}
