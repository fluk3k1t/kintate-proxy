//! Policy database implementation using rusqlite
use chrono::{DateTime, Local};
use regex::Regex;
use rusqlite::{Connection, Result as SqliteResult, params};
use std::collections::HashMap;
use std::sync::{Arc, Mutex, RwLock};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Action {
    Allow,
    Block,
}

impl Action {
    fn from_str(s: &str) -> Self {
        if s.eq_ignore_ascii_case("allow") {
            Action::Allow
        } else {
            Action::Block
        }
    }

    fn as_str(&self) -> &'static str {
        match self {
            Action::Allow => "Allow",
            Action::Block => "Block",
        }
    }
}

pub struct RuleData {
    pub priority: i32,
    pub action: Action,
    pub name: Option<String>,
    pub domain: Option<String>,
    pub path_pattern: Option<String>,
    pub client_ip: Option<String>,
    pub time_start: Option<String>, // HH:MM
    pub time_end: Option<String>,   // HH:MM
}

pub struct Rule {
    pub id: i64,
    pub data: RuleData,
    pub compiled_regex: Option<Regex>,
}

#[derive(Clone, Debug)]
pub struct AccessSession {
    pub device_ip: String,
    pub target_domain: String,
    pub action: Action,
    pub first_access: DateTime<Local>,
    pub last_access: DateTime<Local>,
    pub request_count: i32,
}

pub struct Policy {
    conn: Arc<Mutex<Connection>>,
    rules_cache: Arc<RwLock<Vec<Arc<Rule>>>>,
    active_sessions: Arc<RwLock<HashMap<String, AccessSession>>>,
}

impl Policy {
    pub fn new(db_path: &str) -> SqliteResult<Self> {
        let conn = Connection::open(db_path)?;

        // Drop the old table if it exists (As per plan)
        let _ = conn.execute("DROP TABLE IF EXISTS policies", []);

        conn.execute(
            "CREATE TABLE IF NOT EXISTS rules (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                priority INTEGER NOT NULL,
                action TEXT NOT NULL,
                name TEXT,
                domain TEXT,
                path_pattern TEXT,
                client_ip TEXT,
                time_start TEXT,
                time_end TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )",
            [],
        )?;

        conn.execute(
            "CREATE TABLE IF NOT EXISTS access_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                device_ip TEXT NOT NULL,
                target_domain TEXT NOT NULL,
                action TEXT NOT NULL,
                first_access TIMESTAMP,
                last_access TIMESTAMP,
                request_count INTEGER
            )",
            [],
        )?;

        let policy = Self {
            conn: Arc::new(Mutex::new(conn)),
            rules_cache: Arc::new(RwLock::new(Vec::new())),
            active_sessions: Arc::new(RwLock::new(HashMap::new())),
        };

        policy.reload_cache()?;
        Ok(policy)
    }

    /// Load all rules from database and update cache
    pub fn reload_cache(&self) -> SqliteResult<()> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT id, priority, action, name, domain, path_pattern, client_ip, time_start, time_end 
             FROM rules ORDER BY priority ASC",
        )?;

        let mut rules = Vec::new();
        let rows = stmt.query_map([], |row| {
            let id: i64 = row.get(0)?;
            let priority: i32 = row.get(1)?;
            let action_str: String = row.get(2)?;
            let name: Option<String> = row.get(3)?;
            let domain: Option<String> = row.get(4)?;
            let path_pattern: Option<String> = row.get(5)?;
            let client_ip: Option<String> = row.get(6)?;
            let time_start: Option<String> = row.get(7)?;
            let time_end: Option<String> = row.get(8)?;

            let action = Action::from_str(&action_str);
            let compiled_regex = path_pattern.as_ref().and_then(|p| Regex::new(p).ok());

            Ok(Arc::new(Rule {
                id,
                data: RuleData {
                    priority,
                    action,
                    name,
                    domain,
                    path_pattern,
                    client_ip,
                    time_start,
                    time_end,
                },
                compiled_regex,
            }))
        })?;

        for row in rows {
            if let Ok(rule) = row {
                rules.push(rule);
            }
        }

        let mut cache = self.rules_cache.write().unwrap();
        *cache = rules;
        Ok(())
    }

    pub fn insert_rule(&self, rule: RuleData) -> SqliteResult<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO rules (priority, action, name, domain, path_pattern, client_ip, time_start, time_end)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            params![
                rule.priority,
                rule.action.as_str(),
                rule.name,
                rule.domain,
                rule.path_pattern,
                rule.client_ip,
                rule.time_start,
                rule.time_end
            ],
        )?;
        drop(conn); // release lock before reloading cache
        self.reload_cache()?;
        Ok(())
    }

    pub fn delete_rule(&self, id: i64) -> SqliteResult<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute("DELETE FROM rules WHERE id = ?1", params![id])?;
        drop(conn);
        self.reload_cache()?;
        Ok(())
    }

    pub fn get_all_rules(&self) -> Vec<Arc<Rule>> {
        let cache = self.rules_cache.read().unwrap();
        cache.clone() // shallow copy of Arcs
    }

    pub fn record_access(&self, device_ip: &str, target_domain: &str, action: &Action) {
        let key = format!("{}|{}|{}", device_ip, target_domain, action.as_str());
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
                    target_domain: target_domain.to_string(),
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
            tracing::info!("Saving session: {:?}", session);

            conn.execute(
                "INSERT INTO access_logs (device_ip, target_domain, action, first_access, last_access, request_count)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                params![
                    session.device_ip,
                    session.target_domain,
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
    ) -> SqliteResult<Vec<AccessSession>> {
        let conn = self.conn.lock().unwrap();
        let sql = if ip_filter.is_some() {
            "SELECT device_ip, target_domain, action, first_access, last_access, request_count
             FROM access_logs WHERE device_ip = ?1
             ORDER BY last_access DESC LIMIT ?2"
        } else {
            "SELECT device_ip, target_domain, action, first_access, last_access, request_count
             FROM access_logs
             ORDER BY last_access DESC LIMIT ?1"
        };

        let mut stmt = conn.prepare(sql)?;

        let rows = if let Some(ip) = ip_filter {
            stmt.query_map(rusqlite::params![ip, limit as i64], |row| {
                let action_str: String = row.get(2)?;
                Ok(AccessSession {
                    device_ip: row.get(0)?,
                    target_domain: row.get(1)?,
                    action: Action::from_str(&action_str),
                    first_access: row
                        .get::<_, String>(3)
                        .ok()
                        .and_then(|s| chrono::DateTime::parse_from_rfc3339(&s).ok())
                        .map(|dt| dt.with_timezone(&Local))
                        .unwrap_or_else(Local::now),
                    last_access: row
                        .get::<_, String>(4)
                        .ok()
                        .and_then(|s| chrono::DateTime::parse_from_rfc3339(&s).ok())
                        .map(|dt| dt.with_timezone(&Local))
                        .unwrap_or_else(Local::now),
                    request_count: row.get(5)?,
                })
            })?
            .filter_map(|r| r.ok())
            .collect()
        } else {
            stmt.query_map(rusqlite::params![limit as i64], |row| {
                let action_str: String = row.get(2)?;
                Ok(AccessSession {
                    device_ip: row.get(0)?,
                    target_domain: row.get(1)?,
                    action: Action::from_str(&action_str),
                    first_access: row
                        .get::<_, String>(3)
                        .ok()
                        .and_then(|s| chrono::DateTime::parse_from_rfc3339(&s).ok())
                        .map(|dt| dt.with_timezone(&Local))
                        .unwrap_or_else(Local::now),
                    last_access: row
                        .get::<_, String>(4)
                        .ok()
                        .and_then(|s| chrono::DateTime::parse_from_rfc3339(&s).ok())
                        .map(|dt| dt.with_timezone(&Local))
                        .unwrap_or_else(Local::now),
                    request_count: row.get(5)?,
                })
            })?
            .filter_map(|r| r.ok())
            .collect()
        };

        Ok(rows)
    }

    /// Evaluates if a request is allowed based on the rules.
    /// Returns Action::Allow or Action::Block.
    pub fn evaluate(&self, domain: &str, path: &str, client_ip: Option<&str>) -> Action {
        let cache = self.rules_cache.read().unwrap();

        let now = Local::now().format("%H:%M").to_string();

        for rule in cache.iter() {
            // 1. Time Check
            if let (Some(start), Some(end)) = (&rule.data.time_start, &rule.data.time_end) {
                // simple lexicographical check for HH:MM
                let is_in_time = if start <= end {
                    &now >= start && &now <= end
                } else {
                    // wraps around midnight (e.g., 22:00 to 06:00)
                    &now >= start || &now <= end
                };
                if !is_in_time {
                    continue; // Skip this rule
                }
            }

            // 2. Client IP Check
            if let Some(target_ip) = &rule.data.client_ip {
                if let Some(ip) = client_ip {
                    // Remove port if present
                    let ip_only = ip.split(':').next().unwrap_or(ip);
                    if target_ip != ip_only {
                        continue; // Skip
                    }
                } else {
                    // Rule requires IP, but we couldn't get it, skip
                    continue;
                }
            }

            // 3. Domain Check
            if let Some(target_domain) = &rule.data.domain {
                // Suffix match (e.g. block "youtube.com" covers "www.youtube.com")
                if !domain.ends_with(target_domain) {
                    continue;
                }
            }

            // 4. Path Match Check
            if let Some(regex) = &rule.compiled_regex {
                if !regex.is_match(path) {
                    continue;
                }
            }

            // If we reach here, all rule conditions matched!
            return rule.data.action.clone();
        }

        // Default Action
        Action::Allow
    }
}

impl Clone for Policy {
    fn clone(&self) -> Self {
        Self {
            conn: Arc::clone(&self.conn),
            rules_cache: Arc::clone(&self.rules_cache),
            active_sessions: Arc::clone(&self.active_sessions),
        }
    }
}

pub fn extract_domain(url: &str) -> String {
    if let Ok(uri) = url.parse::<http::Uri>() {
        if let Some(host) = uri.host() {
            return host.to_string();
        }
    }

    let url = url
        .trim_start_matches("https://")
        .trim_start_matches("http://")
        .trim_start_matches("www.");

    let domain: String = url.chars().take_while(|&c| c != '/' && c != ':').collect();
    domain
}

pub fn extract_path(url: &str) -> String {
    if let Ok(uri) = url.parse::<http::Uri>() {
        if let Some(pq) = uri.path_and_query() {
            return pq.as_str().to_string();
        } else {
            return "/".to_string();
        }
    }
    "/".to_string()
}
