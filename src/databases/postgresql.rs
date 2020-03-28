use crate::Error;
use sqlx::row::Row;
use sqlx::{PgConnection, Pool};
use async_trait::async_trait;
use casbin::Result;

use std::error::Error as StdError;

use crate::adapter::TABLE_NAME;

pub type Connection = PgConnection;
type pool = Pool<Connection>;