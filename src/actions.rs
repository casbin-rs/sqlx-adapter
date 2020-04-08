use crate::Error;
use casbin::{error::AdapterError, Error as CasbinError, Result};
use sqlx::{pool::Pool, Error as SqlxError};

use crate::models::{CasbinRule, NewCasbinRule};

#[cfg(feature = "postgres")]
pub type Connection = sqlx::PgConnection;
#[cfg(feature = "mysql")]
pub type Connection = sqlx::MySqlConnection;

type ConnectionPool = Pool<Connection>;

#[cfg(feature = "postgres")]
pub async fn new(mut conn: &ConnectionPool) -> Result<u64> {
    sqlx::query!(
        "CREATE TABLE IF NOT EXISTS casbin_rules (
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
        "
    )
    .execute(&mut conn)
    .await
    .map_err(|err| CasbinError::from(AdapterError(Box::new(Error::SqlxError(err)))))
}

#[cfg(feature = "mysql")]
pub async fn new(mut conn: &ConnectionPool) -> Result<u64> {
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS casbin_rules (
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
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8;",
    )
    .execute(&mut conn)
    .await
    .map_err(|err| CasbinError::from(AdapterError(Box::new(Error::SqlxError(err)))))
}

pub async fn remove_policy(mut conn: &ConnectionPool, pt: &str, rule: Vec<String>) -> Result<bool> {
    let rule = normalize_casbin_rule(rule, 0);
    sqlx::query(
        "DELETE FROM casbin_rules WHERE
                    ptype = $1 AND
                    v0 = $2 AND
                    v1 = $3 AND
                    v2 = $4 AND
                    v3 = $5 AND
                    v4 = $6 AND
                    v5 = $7",
    )
    .bind(pt)
    .bind(&rule[0])
    .bind(&rule[1])
    .bind(&rule[2])
    .bind(&rule[3])
    .bind(&rule[4])
    .bind(&rule[5])
    .execute(&mut conn)
    .await
    .and_then(|n| {
        if n == 1 {
            Ok(true)
        } else {
            Err(SqlxError::NotFound)
        }
    })
    .map_err(|err| CasbinError::from(AdapterError(Box::new(Error::SqlxError(err)))))
}

pub async fn remove_policies(
    conn: &ConnectionPool,
    pt: &str,
    rules: Vec<Vec<String>>,
) -> Result<bool> {
    let mut transaction = conn
        .begin()
        .await
        .map_err(|err| CasbinError::from(AdapterError(Box::new(Error::SqlxError(err)))))?;
    for rule in rules {
        let rule = normalize_casbin_rule(rule, 0);
        sqlx::query(
            "DELETE FROM casbin_rules WHERE
                    ptype = $1 AND
                    v0 = $2 AND
                    v1 = $3 AND
                    v2 = $4 AND
                    v3 = $5 AND
                    v4 = $6 AND
                    v5 = $7",
        )
        .bind(pt)
        .bind(&rule[0])
        .bind(&rule[1])
        .bind(&rule[2])
        .bind(&rule[3])
        .bind(&rule[4])
        .bind(&rule[5])
        .execute(&mut transaction)
        .await
        .and_then(|n| {
            if n == 1 {
                Ok(true)
            } else {
                Err(SqlxError::NotFound)
            }
        })
        .map_err(|err| CasbinError::from(AdapterError(Box::new(Error::SqlxError(err)))))?;
    }
    transaction
        .commit()
        .await
        .map_err(|err| CasbinError::from(AdapterError(Box::new(Error::SqlxError(err)))))?;
    Ok(true)
}

pub async fn remove_filtered_policy(
    mut conn: &ConnectionPool,
    pt: &str,
    field_index: usize,
    field_values: Vec<String>,
) -> Result<bool> {
    let field_values = normalize_casbin_rule(field_values, field_index);
    let boxed_query = if field_index == 5 {
        Box::new(
            sqlx::query(
                "DELETE FROM casbin_rules WHERE
                    ptype = $1 AND
                    (v5 is NULL OR v5 = $2)",
            )
            .bind(pt)
            .bind(&field_values[5]),
        )
    } else if field_index == 4 {
        Box::new(
            sqlx::query(
                "DELETE FROM casbin_rules WHERE
                    ptype = $1 AND
                    (v4 is NULL OR v4 = $2) AND
                    (v5 is NULL OR v5 = $3)",
            )
            .bind(pt)
            .bind(&field_values[4])
            .bind(&field_values[5]),
        )
    } else if field_index == 3 {
        Box::new(
            sqlx::query(
                "DELETE FROM casbin_rules WHERE
                    ptype = $1 AND
                    (v3 is NULL OR v3 = $2) AND
                    (v4 is NULL OR v4 = $3) AND
                    (v5 is NULL OR v5 = $4)",
            )
            .bind(pt)
            .bind(&field_values[3])
            .bind(&field_values[4])
            .bind(&field_values[5]),
        )
    } else if field_index == 2 {
        Box::new(
            sqlx::query(
                "DELETE FROM casbin_rules WHERE
                    ptype = $1 AND
                    (v2 is NULL OR v2 = $2) AND
                    (v3 is NULL OR v3 = $3) AND
                    (v4 is NULL OR v4 = $4) AND
                    (v5 is NULL OR v5 = $5)",
            )
            .bind(pt)
            .bind(&field_values[2])
            .bind(&field_values[3])
            .bind(&field_values[4])
            .bind(&field_values[5]),
        )
    } else if field_index == 1 {
        Box::new(
            sqlx::query(
                "DELETE FROM casbin_rules WHERE
                    ptype = $1 AND
                    (v1 is NULL OR v1 = $2) AND
                    (v2 is NULL OR v2 = $3) AND
                    (v3 is NULL OR v3 = $4) AND
                    (v4 is NULL OR v4 = $5) AND
                    (v5 is NULL OR v5 = $6)",
            )
            .bind(pt)
            .bind(&field_values[1])
            .bind(&field_values[2])
            .bind(&field_values[3])
            .bind(&field_values[4])
            .bind(&field_values[5]),
        )
    } else {
        Box::new(
            sqlx::query(
                "DELETE FROM casbin_rules WHERE
                    ptype = $1 AND
                    (v0 is NULL OR v0 = $2) AND
                    (v1 is NULL OR v1 = $3) AND
                    (v2 is NULL OR v2 = $4) AND
                    (v3 is NULL OR v3 = $5) AND
                    (v4 is NULL OR v4 = $6) AND
                    (v5 is NULL OR v5 = $7)",
            )
            .bind(pt)
            .bind(&field_values[0])
            .bind(&field_values[1])
            .bind(&field_values[2])
            .bind(&field_values[3])
            .bind(&field_values[4])
            .bind(&field_values[5]),
        )
    };

    boxed_query
        .execute(&mut conn)
        .await
        .and_then(|n| {
            if n == 1 {
                Ok(true)
            } else {
                Err(SqlxError::NotFound)
            }
        })
        .map_err(|err| CasbinError::from(AdapterError(Box::new(Error::SqlxError(err)))))
}

pub(crate) async fn load_policy(mut conn: &ConnectionPool) -> Result<Vec<CasbinRule>> {
    let rules: Vec<CasbinRule> = sqlx::query_as("SELECT * FROM casbin_rules")
        .fetch_all(&mut conn)
        .await
        .map_err(|err| CasbinError::from(AdapterError(Box::new(Error::SqlxError(err)))))?;

    Ok(rules)
}

pub(crate) async fn save_policy<'a>(
    conn: &ConnectionPool,
    rules: Vec<NewCasbinRule<'a>>,
) -> Result<()> {
    let mut transaction = conn
        .begin()
        .await
        .map_err(|err| CasbinError::from(AdapterError(Box::new(Error::SqlxError(err)))))?;
    sqlx::query("DELETE FROM casbin_rules")
        .execute(&mut transaction)
        .await
        .map_err(|err| CasbinError::from(AdapterError(Box::new(Error::SqlxError(err)))))?;
    for rule in rules {
        sqlx::query(
            "INSERT INTO casbin_rules ( ptype, v0, v1, v2, v3, v4, v5 )
                 VALUES ( $1, $2, $3, $4, $5, $6, $7 )",
        )
        .bind(rule.ptype)
        .bind(rule.v0)
        .bind(rule.v1)
        .bind(rule.v2)
        .bind(rule.v3)
        .bind(rule.v4)
        .bind(rule.v5)
        .execute(&mut transaction)
        .await
        .map_err(|err| CasbinError::from(AdapterError(Box::new(Error::SqlxError(err)))))?;
    }
    transaction
        .commit()
        .await
        .map_err(|err| CasbinError::from(AdapterError(Box::new(Error::SqlxError(err)))))?;
    Ok(())
}

pub(crate) async fn add_policy<'a>(
    mut conn: &ConnectionPool,
    rule: NewCasbinRule<'a>,
) -> Result<bool> {
    sqlx::query(
        "INSERT INTO casbin_rules ( ptype, v0, v1, v2, v3, v4, v5 )
                 VALUES ( $1, $2, $3, $4, $5, $6, $7 )",
    )
    .bind(rule.ptype)
    .bind(rule.v0)
    .bind(rule.v1)
    .bind(rule.v2)
    .bind(rule.v3)
    .bind(rule.v4)
    .bind(rule.v5)
    .execute(&mut conn)
    .await
    .map_err(|err| CasbinError::from(AdapterError(Box::new(Error::SqlxError(err)))))?;

    Ok(true)
}

pub(crate) async fn add_policies<'a>(
    conn: &ConnectionPool,
    rules: Vec<NewCasbinRule<'a>>,
) -> Result<bool> {
    let mut transaction = conn
        .begin()
        .await
        .map_err(|err| CasbinError::from(AdapterError(Box::new(Error::SqlxError(err)))))?;
    for rule in rules {
        sqlx::query(
            "INSERT INTO casbin_rules ( ptype, v0, v1, v2, v3, v4, v5 )
                 VALUES ( $1, $2, $3, $4, $5, $6, $7 )",
        )
        .bind(rule.ptype)
        .bind(rule.v0)
        .bind(rule.v1)
        .bind(rule.v2)
        .bind(rule.v3)
        .bind(rule.v4)
        .bind(rule.v5)
        .execute(&mut transaction)
        .await
        .map_err(|err| CasbinError::from(AdapterError(Box::new(Error::SqlxError(err)))))?;
    }
    transaction
        .commit()
        .await
        .map_err(|err| CasbinError::from(AdapterError(Box::new(Error::SqlxError(err)))))?;
    Ok(true)
}

fn normalize_casbin_rule(mut rule: Vec<String>, field_index: usize) -> Vec<String> {
    rule.resize(6 - field_index, String::from(""));
    rule
}
