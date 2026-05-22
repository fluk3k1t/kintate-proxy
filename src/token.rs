use std::sync::Arc;

use rusqlite::{Connection, Result as SqliteResult};
use tokio::sync::Mutex;

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
}
