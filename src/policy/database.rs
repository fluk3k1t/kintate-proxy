//! Policy database implementation using rusqlite
use chrono::Local;
use regex::Regex;
use rusqlite::{Connection, Result as SqliteResult, params};
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

pub struct Policy {
    conn: Arc<Mutex<Connection>>,
    rules_cache: Arc<RwLock<Vec<Arc<Rule>>>>,
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

        let policy = Self {
            conn: Arc::new(Mutex::new(conn)),
            rules_cache: Arc::new(RwLock::new(Vec::new())),
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
