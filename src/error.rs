use sqlx::error::Error as SqlxError;
use std::{error::Error as StdError, fmt};

#[derive(Debug)]
pub enum Error {
    SqlxError(SqlxError),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use Error::*;

        match self {
            SqlxError(sqlx_error) => sqlx_error.fmt(f),
        }
    }
}

impl StdError for Error {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        use Error::*;

        match self {
            SqlxError(sqlx_err) => Some(sqlx_err),
        }
    }
}

impl From<SqlxError> for Error {
    fn from(err: SqlxError) -> Self {
        Error::SqlxError(err)
    }
}