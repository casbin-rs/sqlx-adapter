use async_trait::async_trait;
use casbin::{Adapter, Model, Result};
use sqlx::{Pool};

use crate::{error::*, models::*};

use std::error::Error as StdError;

#[cfg(feature = "mysql")]
use crate::databases::mysql as adapter;
#[cfg(feature = "postgres")]
use crate::databases::postgresql as adapter;

pub struct SqlxAdapter {
    pool: Pool<adapter::Connection>
}

pub const TABLE_NAME: &str = "casbin_rules";