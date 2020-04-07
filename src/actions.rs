use crate::Error;
use casbin::{error::AdapterError, Error as CasbinError, Result};
use sqlx::row::Row;
use sqlx::{pool::Pool, Error as SqlxError};

use crate::{
    adapter::TABLE_NAME,
    models::{CasbinRule, NewCasbinRule},
};

#[cfg(feature = "postgres")]
pub type Connection = sqlx::postgres::PgConnection;
#[cfg(feature = "mysql")]
pub type Connection = sqlx::mysql::MySqlConnection;

type ConnectionPool = Pool<Connection>;

#[cfg(feature = "postgres")]
pub fn new(conn: &ConnectionPool) -> Result<usize> {
    sqlx::query!(
        r#"CREATE TABLE IF NOT EXISTS ? (
                    id SERIAL PRIMARY KEY,
                    ptype VARCHAR NOT NULL,
                    v0 VARCHAR NOT NULL,
                    v1 VARCHAR NOT NULL,
                    v2 VARCHAR NOT NULL,
                    v3 VARCHAR NOT NULL,
                    v4 VARCHAR NOT NULL,
                    v5 VARCHAR NOT NULL,
                    CONSTRAINT unique_key UNIQUE(ptype, v0, v1, v2, v3, v4, v5)
                    );
        "#,
        TABLE_NAME
    )
        .execute(&mut &conn)
        .map_err(|err| AdapterError(Box::new(Error::SqlxError(err))).into())
}

#[cfg(feature = "mysql")]
pub fn new(conn: &ConnectionPool) -> Result<usize> {
    sqlx::query!(
        r#"CREATE TABLE IF NOT EXISTS {} (
                    id INT NOT NULL AUTO_INCREMENT,
                    ptype VARCHAR(12) NOT NULL,
                    v0 VARCHAR(128) NOT NULL,
                    v1 VARCHAR(128) NOT NULL,
                    v2 VARCHAR(128) NOT NULL,
                    v3 VARCHAR(128) NOT NULL,
                    v4 VARCHAR(128) NOT NULL,
                    v5 VARCHAR(128) NOT NULL,
                    PRIMARY KEY(id),
                    CONSTRAINT unique_key UNIQUE(ptype, v0, v1, v2, v3, v4, v5)
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8;"#,
        TABLE_NAME
    )
        .execute(&mut &conn)
        .map_err(|err| AdapterError(Box::new(Error::SqlxError(err))).into())
}

pub async fn remove_policy(conn: &ConnectionPool, pt: &str, rule: Vec<String>) -> Result<bool> {
    let rule = normalize_casbin_rule(rule, 0);
    sqlx::query!(
        r#"DELETE FROM {} WHERE
                    ptype = {} AND
                    v0 = {} AND
                    v1 = {} AND
                    v2 = {} AND
                    v3 = {} AND
                    v4 = {} AND
                    v5 = {}"#,
        TABLE_NAME,
        pt,
        rule[0],
        rule[1],
        rule[2],
        rule[3],
        rule[4],
        rule[5]
    )
        .execute(&mut &conn)
        .and_then(|n| {
            if n == 1 {
                Ok(true)
            } else {
                Err(SqlxError::RowNotFound)
            }
        })
        .map_err(|err| AdapterError(Box::new(Error::SqlxError(err))).into())
        .await
}

pub async fn remove_policies(
    conn: &ConnectionPool,
    pt: &str,
    rules: Vec<Vec<String>>,
) -> Result<bool> {
    let mut transaction = conn.begin().await.map_err(|err| CasbinError::from(AdapterError(Box::new(Error::SqlxError(err)))))?;
    for rule in rules {
        let rule = normalize_casbin_rule(rule, 0);
        sqlx::query!(
            r#"DELETE FROM {} WHERE
                    ptype = {} AND
                    v0 = {} AND
                    v1 = {} AND
                    v2 = {} AND
                    v3 = {} AND
                    v4 = {} AND
                    v5 = {}"#,
            TABLE_NAME,
            pt,
            rule[0],
            rule[1],
            rule[2],
            rule[3],
            rule[4],
            rule[5]
        )
            .execute(&mut &transaction)
            .map_err(|err| AdapterError(Box::new(Error::SqlxError(err))).into())
            .await?;
    }
    transaction.commit().await;
    Ok(true)
}

pub async fn remove_filtered_policy(
    conn: &ConnectionPool,
    pt: &str,
    field_index: usize,
    field_values: Vec<String>,
) -> Result<bool> {
    let field_values = normalize_casbin_rule(field_values, field_index);
    let boxed_query = if field_index == 5 {
        sqlx::query!(
            "DELETE FROM {} WHERE
                    ptype = {} AND
                    (v5 is NULL OR v5 = {})",
            TABLE_NAME,
            pt,
            field_values[5]
        )
            .into_boxed()
    } else if field_index == 4 {
        sqlx::query!(
            "DELETE FROM {} WHERE
                    ptype = {} AND
                    (v4 is NULL OR v4 = {}) AND
                    (v5 is NULL OR v5 = {})",
            TABLE_NAME,
            pt,
            field_values[4],
            field_values[5]
        )
            .into_boxed()
    } else if field_index == 3 {
        sqlx::query!(
            "DELETE FROM {} WHERE
                    ptype = {} AND
                    (v3 is NULL OR v3 = {}) AND
                    (v4 is NULL OR v4 = {}) AND
                    (v5 is NULL OR v5 = {})",
            TABLE_NAME,
            pt,
            field_values[3],
            field_values[4],
            field_values[5]
        )
            .into_boxed()
    } else if field_index == 2 {
        sqlx::query!(
            "DELETE FROM {} WHERE
                    ptype = {} AND
                    (v2 is NULL OR v2 = {}) AND
                    (v3 is NULL OR v3 = {}) AND
                    (v4 is NULL OR v4 = {}) AND
                    (v5 is NULL OR v5 = {})",
            TABLE_NAME,
            pt,
            field_values[2],
            field_values[3],
            field_values[4],
            field_values[5]
        )
            .into_boxed()
    } else if field_index == 1 {
        sqlx::query!(
            "DELETE FROM {} WHERE
                    ptype = {} AND
                    (v1 is NULL OR v1 = {}) AND
                    (v2 is NULL OR v2 = {}) AND
                    (v3 is NULL OR v3 = {}) AND
                    (v4 is NULL OR v4 = {}) AND
                    (v5 is NULL OR v5 = {})",
            TABLE_NAME,
            pt,
            field_values[1],
            field_values[2],
            field_values[3],
            field_values[4],
            field_values[5]
        )
            .into_boxed()
    } else {
        sqlx::query!(
            "DELETE FROM {} WHERE
                    ptype = {} AND
                    (v0 is NULL OR v0 = {}) AND
                    (v1 is NULL OR v1 = {}) AND
                    (v2 is NULL OR v2 = {}) AND
                    (v3 is NULL OR v3 = {}) AND
                    (v4 is NULL OR v4 = {}) AND
                    (v5 is NULL OR v5 = {})",
            TABLE_NAME,
            pt,
            field_values[0],
            field_values[1],
            field_values[2],
            field_values[3],
            field_values[4],
            field_values[5]
        )
            .into_boxed()
    };

    boxed_query
        .execute(&mut &conn)
        .map_err(|err| AdapterError(Box::new(Error::SqlxError(err))).into())
        .and_then(|n| {
            if n == 1 {
                Ok(true)
            } else {
                Err(AdapterError(Box::new(Error::SqlxError(SqlxError::RowNotFound))).into())
            }
        })
        .await
}

pub(crate) async fn load_policy(conn: &ConnectionPool) -> Result<Vec<CasbinRule>> {
    let rules = sqlx::query!(r#"SELECT id, ptype, v0, v1, v2, v3, v4, v5 FROM ?"#,TABLE_NAME)
        .fetch_all(&mut &conn)
        .map_err(|err| AdapterError(Box::new(Error::SqlxError(err))).into())
        .await;
    let CasbinRules = rules
        .into_iter()
        .map(|row| CasbinRule {
            id: row.get("id"),
            ptype: row.get("ptype"),
            v0: row.get("v0"),
            v1: row.get("v1"),
            v2: row.get("v2"),
            v3: row.get("v3"),
            v4: row.get("v4"),
            v5: row.get("v5"),
        })
        .collect();
    Ok(CasbinRules)
}

pub(crate) async fn save_policy(conn: &ConnectionPool, rules: Vec<NewCasbinRule>) -> Result<()> {
    let mut transaction = conn.begin().await.map_err(|err| CasbinError::from(AdapterError(Box::new(Error::SqlxError(err)))))?;
    sqlx::query!("DELETE * FROM {} ", TABLE_NAME)
        .execute(&mut &transaction)
        .map_err(|err| AdapterError(Box::new(Error::SqlxError(err))).into())
        .await?;
    for rule in rules {
        sqlx::query!(
            "INSERT INTO {} ( id, ptype, v0, v1, v2, v3, v4, v5 )
                 VALUES ( {}, {}, {}, {}, {}, {}, {}, {} )",
            TABLE_NAME,
            rule.id,
            rule.ptype,
            rule.v0,
            rule.v1,
            rule.v2,
            rule.v3,
            rule.v4,
            rule.v5
        )
            .execute(&mut &transaction)
            .map_err(|err| AdapterError(Box::new(Error::SqlxError(err))).into())
            .await;
    }
    transaction.commit().await;
    Ok(())
}

pub(crate) async fn add_policy(conn: &ConnectionPool, rule: NewCasbinRule) -> Result<bool> {
    sqlx::query!(
        "INSERT INTO {} ( ptype, v0, v1, v2, v3, v4, v5 )
                 VALUES ({}, {}, {}, {}, {}, {}, {})",
        TABLE_NAME,
        rule.ptype,
        rule.v0,
        rule.v1,
        rule.v2,
        rule.v3,
        rule.v4,
        rule.v5
    )
        .execute(&mut &conn)
        .map_err(|err| AdapterError(Box::new(Error::SqlxError(err))).into())
        .await;
    Ok(true)
}

pub(crate) async fn add_policies(conn: &ConnectionPool, rules: Vec<NewCasbinRule>) -> Result<bool> {
    let mut transaction = conn.begin().await.map_err(|err| CasbinError::from(AdapterError(Box::new(Error::SqlxError(err)))))?;
    for rule in rules {
        sqlx::query!(
            "INSERT INTO {} ( ptype, v0, v1, v2, v3, v4, v5 )
                 VALUES ({}, {}, {}, {}, {}, {}, {})",
            TABLE_NAME,
            rule.ptype,
            rule.v0,
            rule.v1,
            rule.v2,
            rule.v3,
            rule.v4,
            rule.v5
        )
            .execute(&mut &transaction)
            .map_err(|err| AdapterError(Box::new(Error::SqlxError(err))).into())
            .await;
    }
    transaction.commit().await;
    Ok(true)
}

fn normalize_casbin_rule(mut rule: Vec<String>, field_index: usize) -> Vec<String> {
    rule.resize(6 - field_index, String::from(""));
    rule
}
