//! Policy database implementation using rusqlite
use regex::Regex;
use rusqlite::{Connection, Result as SqliteResult, params};
use std::collections::HashMap;
use std::sync::{Arc, Mutex, RwLock};

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum Action {
    Allow,
    Block,
}

impl Action {
    pub fn from_str(s: &str) -> Self {
        if s.eq_ignore_ascii_case("allow") {
            Action::Allow
        } else {
            Action::Block
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Action::Allow => "Allow",
            Action::Block => "Block",
        }
    }
}

#[derive(serde::Serialize, serde::Deserialize)]
pub struct RuleData {
    pub priority: i32,
    pub action: Action,
    pub name: Option<String>,
    pub domain: Option<String>,
    pub tag: Option<String>,
    pub path_pattern: Option<String>,
    pub client_ip: Option<String>,
}

#[derive(serde::Serialize)]
pub struct Rule {
    pub id: i64,
    pub data: RuleData,
    #[serde(skip)]
    pub compiled_regex: Option<Regex>,
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct DomainTag {
    pub id: i64,
    pub sld: String,
    pub tag: String,
}

pub struct Policy {
    conn: Arc<Mutex<Connection>>,
    rules_cache: Arc<RwLock<Vec<Arc<Rule>>>>,
    tag_cache: Arc<RwLock<HashMap<String, String>>>,
}

impl Policy {
    pub fn new(db_path: &str) -> SqliteResult<Self> {
        let conn = Connection::open(db_path)?;
        let conn = Arc::new(Mutex::new(conn));

        {
            let mut conn = conn.lock().unwrap();

            conn.execute(
                "CREATE TABLE IF NOT EXISTS rules (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                priority INTEGER NOT NULL,
                action TEXT NOT NULL,
                name TEXT,
                domain TEXT,
                tag TEXT,
                path_pattern TEXT,
                client_ip TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )",
                [],
            )?;

            conn.execute(
                "CREATE TABLE IF NOT EXISTS domain_tags (
                id   INTEGER PRIMARY KEY AUTOINCREMENT,
                sld  TEXT NOT NULL UNIQUE,
                tag  TEXT NOT NULL
            )",
                [],
            )?;
        }

        let policy = Self {
            conn: Arc::clone(&conn),
            rules_cache: Arc::new(RwLock::new(Vec::new())),
            tag_cache: Arc::new(RwLock::new(HashMap::new())),
        };

        policy.reload_cache()?;
        policy.reload_tag_cache()?;
        Ok(policy)
    }

    /// Load all rules from database and update cache
    pub fn reload_cache(&self) -> SqliteResult<()> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT id, priority, action, name, domain, tag, path_pattern, client_ip
             FROM rules ORDER BY priority ASC",
        )?;

        let mut rules = Vec::new();
        let rows = stmt.query_map([], |row| {
            let id: i64 = row.get(0)?;
            let priority: i32 = row.get(1)?;
            let action_str: String = row.get(2)?;
            let name: Option<String> = row.get(3)?;
            let domain: Option<String> = row.get(4)?;
            let tag: Option<String> = row.get(5)?;
            let path_pattern: Option<String> = row.get(6)?;
            let client_ip: Option<String> = row.get(7)?;

            let action = Action::from_str(&action_str);
            let compiled_regex = path_pattern.as_ref().and_then(|p| Regex::new(p).ok());

            Ok(Arc::new(Rule {
                id,
                data: RuleData {
                    priority,
                    action,
                    name,
                    domain,
                    tag,
                    path_pattern,
                    client_ip,
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

    pub fn get_tag(&self, sld: &str) -> Option<String> {
        let cache = self.tag_cache.read().unwrap();
        cache.get(sld).cloned()
    }

    pub fn insert_rule(&self, rule: RuleData) -> SqliteResult<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO rules (priority, action, name, domain, tag, path_pattern, client_ip)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                rule.priority,
                rule.action.as_str(),
                rule.name,
                rule.domain,
                rule.tag,
                rule.path_pattern,
                rule.client_ip,
            ],
        )?;
        drop(conn); // release lock before reloading cache
        self.reload_cache()?;
        Ok(())
    }

    pub fn update_rule(&self, id: i64, data: RuleData) -> SqliteResult<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "UPDATE rules SET priority = ?1, action = ?2, name = ?3, domain = ?4, tag = ?5, path_pattern = ?6, client_ip = ?7 WHERE id = ?8",
            params![
                data.priority,
                data.action.as_str(),
                data.name,
                data.domain,
                data.tag,
                data.path_pattern,
                data.client_ip,
                id,
            ],
        )?;
        drop(conn);
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

    /// Delete all rules that match a specific name pattern (used for dynamic blocks)
    pub fn delete_rules_by_name(&self, name_pattern: &str) -> SqliteResult<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "DELETE FROM rules WHERE name LIKE ?1",
            params![name_pattern],
        )?;
        drop(conn);
        self.reload_cache()?;
        Ok(())
    }

    pub fn get_all_rules(&self) -> Vec<Arc<Rule>> {
        let cache = self.rules_cache.read().unwrap();
        cache.clone() // shallow copy of Arcs
    }

    pub fn get_connection(&self) -> Arc<Mutex<Connection>> {
        Arc::clone(&self.conn)
    }

    pub fn reload_tag_cache(&self) -> SqliteResult<()> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare("SELECT sld, tag FROM domain_tags")?;
        let map: HashMap<String, String> = stmt
            .query_map([], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
            })?
            .filter_map(|r| r.ok())
            .collect();
        let mut cache = self.tag_cache.write().unwrap();
        *cache = map;
        Ok(())
    }

    pub fn add_domain_tag(&self, sld: &str, tag: &str) -> SqliteResult<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO domain_tags (sld, tag) VALUES (?1, ?2)
             ON CONFLICT(sld) DO UPDATE SET tag = excluded.tag",
            params![sld, tag],
        )?;
        drop(conn);
        self.reload_tag_cache()
    }

    pub fn delete_domain_tag(&self, sld: &str) -> SqliteResult<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute("DELETE FROM domain_tags WHERE sld = ?1", params![sld])?;
        drop(conn);
        self.reload_tag_cache()
    }

    pub fn get_all_domain_tags(&self) -> SqliteResult<Vec<DomainTag>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare("SELECT id, sld, tag FROM domain_tags ORDER BY tag, sld")?;
        let tags = stmt
            .query_map([], |row| {
                Ok(DomainTag {
                    id: row.get(0)?,
                    sld: row.get(1)?,
                    tag: row.get(2)?,
                })
            })?
            .filter_map(|r| r.ok())
            .collect();
        Ok(tags)
    }

    /// Evaluates if a request is allowed based on the rules.
    /// Returns Action::Allow or Action::Block.
    pub fn evaluate(&self, domain: &str, path: &str, client_ip: Option<&str>) -> Action {
        let sld = extract_sld(domain);
        let tag = {
            let cache = self.tag_cache.read().unwrap();
            cache.get(&sld).cloned()
        };

        let cache = self.rules_cache.read().unwrap();

        for rule in cache.iter() {
            // 1. Client IP Check
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

            // 2. Tag Check
            if let Some(target_tag) = &rule.data.tag {
                if let Some(current_tag) = &tag {
                    if target_tag != current_tag {
                        continue;
                    }
                } else {
                    // Rule requires a tag match, but this domain has no tag
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
            // active_sessions: Arc::clone(&self.active_sessions),
            tag_cache: Arc::clone(&self.tag_cache),
        }
    }
}

/// Extract the second-level domain from a full hostname.
/// e.g. "rr3---sn.googlevideo.com" -> "googlevideo"
/// e.g. "i.ytimg.com" -> "ytimg"
/// e.g. "www.google.co.jp" -> "google"
pub fn extract_sld(domain: &str) -> String {
    let parts: Vec<&str> = domain.split('.').collect();
    let n = parts.len();
    if n >= 3 {
        let tld = parts[n - 1];
        let sld_candidate = parts[n - 2];
        // Common two-part TLDs (co.jp, com.au, etc)
        // If the second-to-last part is short (<=3) and the TLD is 2-letter,
        // we treat it as a two-part TLD.
        if sld_candidate.len() <= 3 && tld.len() == 2 {
            if n >= 3 {
                return parts[n - 3].to_string();
            }
        }
        // Standard: return second-to-last before TLD
        return parts[n - 2].to_string();
    } else if n == 2 {
        return parts[0].to_string();
    }
    domain.to_string()
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
