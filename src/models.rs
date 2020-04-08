use sqlx::{FromRow, Row};

#[cfg(feature = "postgres")]
pub type DbRow = sqlx::postgres::PgRow;
#[cfg(feature = "mysql")]
pub type DbRow = sqlx::mysql::MySqlRow;

#[derive(Debug)]
pub(crate) struct CasbinRule {
    pub id: i32,
    pub ptype: String,
    pub v0: String,
    pub v1: String,
    pub v2: String,
    pub v3: String,
    pub v4: String,
    pub v5: String,
}

#[derive(Debug)]
pub(crate) struct NewCasbinRule<'a> {
    pub ptype: &'a str,
    pub v0: &'a str,
    pub v1: &'a str,
    pub v2: &'a str,
    pub v3: &'a str,
    pub v4: &'a str,
    pub v5: &'a str,
}

impl FromRow<DbRow> for CasbinRule {
    fn from_row(row: DbRow) -> CasbinRule {
        Self {
            id: Row::get(&row, "id"),
            ptype: Row::get(&row, "ptype"),
            v0: Row::get(&row, "v0"),
            v1: Row::get(&row, "v1"),
            v2: Row::get(&row, "v2"),
            v3: Row::get(&row, "v3"),
            v4: Row::get(&row, "v4"),
            v5: Row::get(&row, "v5"),
        }
    }
}
