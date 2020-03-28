use crate::Error;
use sqlx::row::Row;
use sqlx::{MySqlConnection, Pool};
use async_trait::async_trait;
use casbin::Result;

use std::error::Error as StdError;

use crate::adapter::TABLE_NAME;

pub type Connection = MySqlConnection;
type pool = Pool<Connection>;




