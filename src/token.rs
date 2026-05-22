use rusqlite::{Connection, Result as SqliteResult};
use std::sync::Arc;
use std::sync::Mutex;

pub struct TokenManager {
    conn: Arc<Mutex<Connection>>,
}

impl TokenManager {
    pub fn new(db_path: impl AsRef<str>) -> SqliteResult<Self> {
        let conn = Connection::open(db_path.as_ref())?;

        conn.execute(
            "CREATE TABLE IF NOT EXISTS tokens (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                token TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )",
            [],
        )?;

        Ok(TokenManager {
            conn: Arc::new(Mutex::new(conn)),
        })
    }

    pub fn generate(&mut self) -> SqliteResult<String> {
        let random_code =
            random_string::generate_rng(23..24, random_string::charsets::ALPHANUMERIC);

        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO tokens (token) VALUES (?)",
            [random_code.to_owned()],
        )?;

        Ok(random_code)
    }

    pub fn verify(&self, token: &str) -> SqliteResult<bool> {
        let conn = self.conn.lock().unwrap();

        let tokens: SqliteResult<Vec<String>> = conn
            .prepare("SELECT * FROM tokens")?
            .query_map([], |row| Ok(row.get(1)?))?
            .into_iter()
            .collect();
        let tokens = tokens?;

        Ok(tokens.iter().any(|t| t == token))
    }
}
