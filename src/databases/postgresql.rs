use crate::Error;
use sqlx::row::Row;
use sqlx::{PgConnection, Pool};
use async_trait::async_trait;
use casbin::Result;

use std::error::Error as StdError;

use crate::adapter::TABLE_NAME;
use crate::models::*;

pub type Connection = PgConnection;
type pool = Pool<Connection>;

pub async fn new(conn: Result<ConnectionPool>) -> Result<usize> {
    sqlx::query!(r#"CREATE TABLE ? IF NOT EXISTS {} (
                    id INT NOT NULL AUTO_INCREMENT,
                    ptype VARCHAR(12) NOT NULL,
                    v0 VARCHAR(128) NOT NULL,
                    v1 VARCHAR(128) NOT NULL,
                    v2 VARCHAR(128) NOT NULL,
                    v3 VARCHAR(128) NOT NULL,
                    v4 VARCHAR(128) NOT NULL,
                    v5 VARCHAR(128) NOT NULL,
                    PRIMARY KEY(id),
                    CONSTRAINT unique_key UNIQUE(ptype, v0, v1, v2, v3, v4, v5)"#,TABLE_NAME)
        .execute(&mut &conn?)
        .map_err(|err| Box::new(Error::SqlxError(err) as Box<dyn StdError>))
        .await
}

pub async fn remove_policy(conn: ConnectionPool, pt: &str, rule: Vec<&str>) -> Result<bool> {
    let rule = normalize_casbin_rule(rule, 0);
    sqlx::query!(r#"DELETE FROM $1 WHERE
                    ptype = $2 AND
                    v0 = $3 AND
                    v1 = $4 AND
                    v2 = $5 AND
                    v3 = $6 AND
                    v4 = $7 AND
                    v5 = $8 AND"#,TABLE_NAME, pt, rule[0], rule[1], rule[2], rule[3], rule[4], rule[5])
        .execute(&mut &conn)
        .and_then(|n|{
            if n==1{
                Ok(true)
            } else {
                Err(SqlxError::NotFound)
            }
        })
        .map_err(|err| Box::new(Error::SqlxError(err)) as Box<dyn StdError>)
        .await
}

pub async fn remove_policies(conn: ConnectionPool, pt: &str, rules: Vec<Vec<&str>>) -> Result<bool> {
    let mut transaction = conn.begin().await?;
    for rule in rules {
        let rule = normalize_casbin_rule(rule, 0);
        sqlx::query!(r#"DELETE FROM $1 WHERE
                    ptype = $2 AND
                    v0 = $3 AND
                    v1 = $4 AND
                    v2 = $5 AND
                    v3 = $6 AND
                    v4 = $7 AND
                    v5 = $8 AND"#,TABLE_NAME, pt, rule[0], rule[1], rule[2], rule[3], rule[4], rule[5])
            .execute(&mut &transaction)
            .map_err(|err| Box::new(Error::SqlxError(err)) as Box<dyn StdError>)
            .await?;
    }
    transaction.commit().await?;
    Ok(true)
}

pub fn remove_filtered_policy(
    conn: ConnectionPool,
    pt: &str,
    field_index: usize,
    field_values: Vec<&str>,
) -> Result<bool> {
    let field_values = normalize_casbin_rule(field_values, field_index);
    let boxed_query = if field_index == 5 {
        sqlx::query!(r#"DELETE FROM $1 WHERE
                    ptype = $2 AND
                    (v5 is NULL OR v5 = $3)"#,TABLE_NAME, pt, field_values[5])
            .into_boxed()
    } else if field_index == 4 {
        sqlx::query!(r#"DELETE FROM $1 WHERE
                    ptype = $2 AND
                    (v4 is NULL OR v4 = $3) AND
                    (v5 is NULL OR v5 = $4)"#,TABLE_NAME, pt, field_values[4], field_values[5])
            .into_boxed()
    } else if field_index == 3 {
        sqlx::query!(r#"DELETE FROM $1 WHERE
                    ptype = $2 AND
                    (v3 is NULL OR v3 = $3) AND
                    (v4 is NULL OR v4 = $4) AND
                    (v5 is NULL OR v5 = $5)"#,TABLE_NAME, pt, field_values[3], field_values[4], field_values[5])
            .into_boxed()
    } else if field_index == 2 {
        sqlx::query!(r#"DELETE FROM $1 WHERE
                    ptype = $2 AND
                    (v2 is NULL OR v2 = $3) AND
                    (v3 is NULL OR v3 = $4) AND
                    (v4 is NULL OR v4 = $5) AND
                    (v5 is NULL OR v5 = $6)"#.,TABLE_NAME, pt, field_values[2], field_values[3], field_values[4], field_values[5])
            .into_boxed()
    } else if field_index == 1 {
        sqlx::query!(r#"DELETE FROM $1 WHERE
                    ptype = $2 AND
                    (v1 is NULL OR v1 = $3) AND
                    (v2 is NULL OR v2 = $4) AND
                    (v3 is NULL OR v3 = $5) AND
                    (v4 is NULL OR v4 = $6) AND
                    (v5 is NULL OR v5 = $7)"#,TABLE_NAME, pt, field_values[1], field_values[2], field_values[3], field_values[4], field_values[5])
            .into_boxed()
    } else {
        sqlx::query!(r#"DELETE FROM $1 WHERE
                    ptype = $2 AND
                    (v0 is NULL OR v0 = $3) AND
                    (v1 is NULL OR v1 = $4) AND
                    (v2 is NULL OR v2 = $5) AND
                    (v3 is NULL OR v3 = $6) AND
                    (v4 is NULL OR v4 = $7) AND
                    (v5 is NULL OR v5 = $8)"#,TABLE_NAME, pt, field_values[0], field_values[1], field_values[2], field_values[3], field_values[4], field_values[5])
            .into_boxed()
    };

    boxed_query
        .execute(&mut &conn)
        .map_err(|err| Box::new(Error::SqlxError(err)) as Box<dyn StdError>)
        .and_then(|n| {
            if n == 1 {
                Ok(true)
            } else {
                Err(Box::new(Error::DieselError(DieselError::NotFound)) as Box<dyn StdError>)
            }
        })
        .await
}

pub async fn load_policy(conn: ConnectionPool) -> Result<Vec<CasbinRule>> {
    let rules = sqlx::query("SELECT id, ptype, v0, v1, v2, v3, v4, v5 FROM ?")
        .bind(TABLE_NAME)
        .fetch_all(&mut &conn)
        .map_err(|err| Box::new(Error::SqlxError(err)) as Box<dyn StdError>)
        .await?;
    let CasbinRules = rules.into_iter().map(|row| CasbinRule {
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

pub async fn save_policy(conn: ConnectionPool, rules: Vec<CasbinRule>) -> Result<bool> {
    let mut transaction = conn.begin().await?;
    sqlx::query!(r#"DELETE * FROM $1 "#,TABLE_NAME)
        .execute(&mut &transaction)
        .map_err(|err| Box::new(Error::SqlxError(err)) as Box<dyn StdError>)
        .await?;
    for rule in rules {
        sqlx::query!(r#"INSERT INTO $1 ( id, ptype, v0, v1, v2, v3, v4, v5 )
                 VALUES ($2, $3, $4, $5, $6, $7, $8, $9)"#,
        TABLE_NAME, rule.id, rule.ptype, rule.v0, rule.v1, rule.v2, rule.v3, rule.v4, rule.v5)
            .execute(&mut &transaction)
            .map_err(|err| Box::new(Error::SqlxError(err) as Box<dyn StdError>)).await?;
    }
    transaction.commit().await?;
    Ok(true)
}

pub async fn add_policy(conn: ConnectionPool, rule: NewCasbinRule) -> Result<bool> {
    sqlx::query!(r#"INSERT INTO $1 ( ptype, v0, v1, v2, v3, v4, v5 )
                 VALUES ($2, $3, $4, $5, $6, $7, $8)"#,
        TABLE_NAME, rule.ptype, rule.v0, rule.v1, rule.v2, rule.v3, rule.v4, rule.v5)
        .execute(&mut &conn)
        .map_err(|err| Box::new(Error::SqlxError(err) as Box<dyn StdError>)).await?;
    Ok(true)
}

pub async fn add_policies(conn: ConnectionPool, rules: Vec<NewCasbinRule>) -> Result<bool> {
    let mut transaction = conn.begin().await?;
    for rule in rules {
        sqlx::query!(r#"INSERT INTO $1 ( ptype, v0, v1, v2, v3, v4, v5 )
                 VALUES ($2, $3, $4, $5, $6, $7, $8)"#,
        TABLE_NAME, rule.ptype, rule.v0, rule.v1, rule.v2, rule.v3, rule.v4, rule.v5)
            .execute(&mut &transaction)
            .map_err(|err| Box::new(Error::SqlxError(err) as Box<dyn StdError>)).await?;
    }
    transaction.commit().await?;
    Ok(true)
}

fn normalize_casbin_rule(mut rule: Vec<&str>, field_index: usize) -> Vec<&str> {
    rule.resize(6 - field_index, "");
    rule
}
