use async_trait::async_trait;
use casbin::{Adapter, Model, Result};
use sqlx::{Pool};

use std::error::Error as StdError;

use crate::{
    databases::mysql as adapter,
    databases::postgresql as adapter，
    error::*,
    models::*,
};

pub struct SqlxAdapter {
    pool: Pool<adapter::Connection>
}

pub const TABLE_NAME: &str = "casbin_rules";