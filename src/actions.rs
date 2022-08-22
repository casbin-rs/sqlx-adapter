#![allow(clippy::suspicious_else_formatting)]
#![allow(clippy::toplevel_ref_arg)]
use crate::Error;
use casbin::{error::AdapterError, Error as CasbinError, Filter, Result};
use sqlx::error::Error as SqlxError;

use crate::models::{CasbinRule, NewCasbinRule};

#[cfg(feature = "postgres")]
use sqlx::postgres::PgQueryResult;

#[cfg(feature = "mysql")]
use sqlx::mysql::MySqlQueryResult;

#[cfg(feature = "sqlite")]
use sqlx::sqlite::SqliteQueryResult;

#[cfg(feature = "postgres")]
pub type ConnectionPool = sqlx::PgPool;

#[cfg(feature = "mysql")]
pub type ConnectionPool = sqlx::MySqlPool;

#[cfg(feature = "sqlite")]
pub type ConnectionPool = sqlx::SqlitePool;

#[cfg(feature = "postgres")]
pub async fn new(conn: &ConnectionPool) -> Result<PgQueryResult> {
    sqlx::query!(
        "CREATE TABLE IF NOT EXISTS casbin_rule (
                    id SERIAL PRIMARY KEY,
                    ptype VARCHAR NOT NULL,
                    v0 VARCHAR NOT NULL,
                    v1 VARCHAR NOT NULL,
                    v2 VARCHAR NOT NULL,
                    v3 VARCHAR NOT NULL,
                    v4 VARCHAR NOT NULL,
                    v5 VARCHAR NOT NULL,
                    CONSTRAINT unique_key_sqlx_adapter UNIQUE(ptype, v0, v1, v2, v3, v4, v5)
                    );
        "
    )
    .execute(conn)
    .await
    .map_err(|err| CasbinError::from(AdapterError(Box::new(Error::SqlxError(err)))))
}

#[cfg(feature = "sqlite")]
pub async fn new(conn: &ConnectionPool) -> Result<SqliteQueryResult> {
    sqlx::query!(
        "CREATE TABLE IF NOT EXISTS casbin_rule (
                    id SERIAL PRIMARY KEY,
                    ptype VARCHAR NOT NULL,
                    v0 VARCHAR NOT NULL,
                    v1 VARCHAR NOT NULL,
                    v2 VARCHAR NOT NULL,
                    v3 VARCHAR NOT NULL,
                    v4 VARCHAR NOT NULL,
                    v5 VARCHAR NOT NULL,
                    CONSTRAINT unique_key_sqlx_adapter UNIQUE(ptype, v0, v1, v2, v3, v4, v5)
                    );
        "
    )
    .execute(conn)
    .await
    .map_err(|err| CasbinError::from(AdapterError(Box::new(Error::SqlxError(err)))))
}

#[cfg(feature = "mysql")]
pub async fn new(conn: &ConnectionPool) -> Result<MySqlQueryResult> {
    sqlx::query!(
        "CREATE TABLE IF NOT EXISTS casbin_rule (
                    id INT NOT NULL AUTO_INCREMENT,
                    ptype VARCHAR(12) NOT NULL,
                    v0 VARCHAR(128) NOT NULL,
                    v1 VARCHAR(128) NOT NULL,
                    v2 VARCHAR(128) NOT NULL,
                    v3 VARCHAR(128) NOT NULL,
                    v4 VARCHAR(128) NOT NULL,
                    v5 VARCHAR(128) NOT NULL,
                    PRIMARY KEY(id),
                    CONSTRAINT unique_key_sqlx_adapter UNIQUE(ptype, v0, v1, v2, v3, v4, v5)
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8;",
    )
    .execute(conn)
    .await
    .map_err(|err| CasbinError::from(AdapterError(Box::new(Error::SqlxError(err)))))
}

#[cfg(feature = "postgres")]
pub async fn remove_policy(conn: &ConnectionPool, pt: &str, rule: Vec<String>) -> Result<bool> {
    let rule = normalize_casbin_rule(rule);
    sqlx::query!(
        "DELETE FROM casbin_rule WHERE
                    ptype = $1 AND
                    v0 = $2 AND
                    v1 = $3 AND
                    v2 = $4 AND
                    v3 = $5 AND
                    v4 = $6 AND
                    v5 = $7",
        pt,
        rule[0],
        rule[1],
        rule[2],
        rule[3],
        rule[4],
        rule[5]
    )
    .execute(conn)
    .await
    .map(|n| PgQueryResult::rows_affected(&n) == 1)
    .map_err(|err| CasbinError::from(AdapterError(Box::new(Error::SqlxError(err)))))
}

#[cfg(feature = "sqlite")]
pub async fn remove_policy(conn: &ConnectionPool, pt: &str, rule: Vec<String>) -> Result<bool> {
    let rule = normalize_casbin_rule(rule);
    sqlx::query!(
        "DELETE FROM casbin_rule WHERE
                    ptype = ?1 AND
                    v0 = ?2 AND
                    v1 = ?3 AND
                    v2 = ?4 AND
                    v3 = ?5 AND
                    v4 = ?6 AND
                    v5 = ?7",
        pt,
        rule[0],
        rule[1],
        rule[2],
        rule[3],
        rule[4],
        rule[5]
    )
    .execute(conn)
    .await
    .map(|n| SqliteQueryResult::rows_affected(&n) == 1)
    .map_err(|err| CasbinError::from(AdapterError(Box::new(Error::SqlxError(err)))))
}

#[cfg(feature = "mysql")]
pub async fn remove_policy(conn: &ConnectionPool, pt: &str, rule: Vec<String>) -> Result<bool> {
    let rule = normalize_casbin_rule(rule);
    sqlx::query!(
        "DELETE FROM casbin_rule WHERE
                    ptype = ? AND
                    v0 = ? AND
                    v1 = ? AND
                    v2 = ? AND
                    v3 = ? AND
                    v4 = ? AND
                    v5 = ?",
        pt,
        rule[0],
        rule[1],
        rule[2],
        rule[3],
        rule[4],
        rule[5]
    )
    .execute(conn)
    .await
    .map(|n| MySqlQueryResult::rows_affected(&n) == 1)
    .map_err(|err| CasbinError::from(AdapterError(Box::new(Error::SqlxError(err)))))
}

#[cfg(feature = "postgres")]
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
        let rule = normalize_casbin_rule(rule);
        sqlx::query!(
            "DELETE FROM casbin_rule WHERE
                    ptype = $1 AND
                    v0 = $2 AND
                    v1 = $3 AND
                    v2 = $4 AND
                    v3 = $5 AND
                    v4 = $6 AND
                    v5 = $7",
            pt,
            rule[0],
            rule[1],
            rule[2],
            rule[3],
            rule[4],
            rule[5]
        )
        .execute(&mut transaction)
        .await
        .and_then(|n| {
            if PgQueryResult::rows_affected(&n) == 1 {
                Ok(true)
            } else {
                Err(SqlxError::RowNotFound)
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

#[cfg(feature = "sqlite")]
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
        let rule = normalize_casbin_rule(rule);
        sqlx::query!(
            "DELETE FROM casbin_rule WHERE
                    ptype = ?1 AND
                    v0 = ?2 AND
                    v1 = ?3 AND
                    v2 = ?4 AND
                    v3 = ?5 AND
                    v4 = ?6 AND
                    v5 = ?7",
            pt,
            rule[0],
            rule[1],
            rule[2],
            rule[3],
            rule[4],
            rule[5]
        )
        .execute(&mut transaction)
        .await
        .and_then(|n| {
            if SqliteQueryResult::rows_affected(&n) == 1 {
                Ok(true)
            } else {
                Err(SqlxError::RowNotFound)
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

#[cfg(feature = "mysql")]
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
        let rule = normalize_casbin_rule(rule);
        sqlx::query!(
            "DELETE FROM casbin_rule WHERE
                    ptype = ? AND
                    v0 = ? AND
                    v1 = ? AND
                    v2 = ? AND
                    v3 = ? AND
                    v4 = ? AND
                    v5 = ?",
            pt,
            rule[0],
            rule[1],
            rule[2],
            rule[3],
            rule[4],
            rule[5]
        )
        .execute(&mut transaction)
        .await
        .and_then(|n| {
            if MySqlQueryResult::rows_affected(&n) == 1 {
                Ok(true)
            } else {
                Err(SqlxError::RowNotFound)
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

#[cfg(feature = "postgres")]
pub async fn remove_filtered_policy(
    conn: &ConnectionPool,
    pt: &str,
    field_index: usize,
    field_values: Vec<String>,
) -> Result<bool> {
    let field_values = normalize_casbin_rule_option(field_values);
    let boxed_query = if field_index == 5 {
        Box::new(sqlx::query!(
            "DELETE FROM casbin_rule WHERE
                    ptype = $1 AND
                    (v5 is NULL OR v5 = COALESCE($2,v5))",
            pt.to_string(),
            field_values[0]
        ))
    } else if field_index == 4 {
        Box::new(sqlx::query!(
            "DELETE FROM casbin_rule WHERE
                    ptype = $1 AND
                    (v4 is NULL OR v4 = COALESCE($2,v4)) AND
                    (v5 is NULL OR v5 = COALESCE($3,v5))",
            pt,
            field_values[0],
            field_values[1]
        ))
    } else if field_index == 3 {
        Box::new(sqlx::query!(
            "DELETE FROM casbin_rule WHERE
                    ptype = $1 AND
                    (v3 is NULL OR v3 = COALESCE($2,v3)) AND
                    (v4 is NULL OR v4 = COALESCE($3,v4)) AND
                    (v5 is NULL OR v5 = COALESCE($4,v5))",
            pt,
            field_values[0],
            field_values[1],
            field_values[2]
        ))
    } else if field_index == 2 {
        Box::new(sqlx::query!(
            "DELETE FROM casbin_rule WHERE
                    ptype = $1 AND
                    (v2 is NULL OR v2 = COALESCE($2,v2)) AND
                    (v3 is NULL OR v3 = COALESCE($3,v3)) AND
                    (v4 is NULL OR v4 = COALESCE($4,v4)) AND
                    (v5 is NULL OR v5 = COALESCE($5,v5))",
            pt,
            field_values[0],
            field_values[1],
            field_values[2],
            field_values[3]
        ))
    } else if field_index == 1 {
        Box::new(sqlx::query!(
            "DELETE FROM casbin_rule WHERE
                    ptype = $1 AND
                    (v1 is NULL OR v1 = COALESCE($2,v1)) AND
                    (v2 is NULL OR v2 = COALESCE($3,v2)) AND
                    (v3 is NULL OR v3 = COALESCE($4,v3)) AND
                    (v4 is NULL OR v4 = COALESCE($5,v4)) AND
                    (v5 is NULL OR v5 = COALESCE($6,v5))",
            pt,
            field_values[0],
            field_values[1],
            field_values[2],
            field_values[3],
            field_values[4]
        ))
    } else {
        Box::new(sqlx::query!(
            "DELETE FROM casbin_rule WHERE
                    ptype = $1 AND
                    (v0 is NULL OR v0 = COALESCE($2,v0)) AND
                    (v1 is NULL OR v1 = COALESCE($3,v1)) AND
                    (v2 is NULL OR v2 = COALESCE($4,v2)) AND
                    (v3 is NULL OR v3 = COALESCE($5,v3)) AND
                    (v4 is NULL OR v4 = COALESCE($6,v4)) AND
                    (v5 is NULL OR v5 = COALESCE($7,v5))",
            pt,
            field_values[0],
            field_values[1],
            field_values[2],
            field_values[3],
            field_values[4],
            field_values[5]
        ))
    };

    boxed_query
        .execute(conn)
        .await
        .map(|n| PgQueryResult::rows_affected(&n) >= 1)
        .map_err(|err| CasbinError::from(AdapterError(Box::new(Error::SqlxError(err)))))
}

#[cfg(feature = "sqlite")]
pub async fn remove_filtered_policy(
    conn: &ConnectionPool,
    pt: &str,
    field_index: usize,
    field_values: Vec<String>,
) -> Result<bool> {
    let field_values = normalize_casbin_rule_option(field_values);
    let boxed_query = if field_index == 5 {
        Box::new(sqlx::query!(
            "DELETE FROM casbin_rule WHERE
                    ptype = $1 AND
                    (v5 is NULL OR v5 = COALESCE(?2,v5))",
            pt,
            field_values[0]
        ))
    } else if field_index == 4 {
        Box::new(sqlx::query!(
            "DELETE FROM casbin_rule WHERE
                    ptype = ?1 AND
                    (v4 is NULL OR v4 = COALESCE(?2,v4)) AND
                    (v5 is NULL OR v5 = COALESCE(?3,v5))",
            pt,
            field_values[0],
            field_values[1]
        ))
    } else if field_index == 3 {
        Box::new(sqlx::query!(
            "DELETE FROM casbin_rule WHERE
                    ptype = ?1 AND
                    (v3 is NULL OR v3 = COALESCE(?2,v3)) AND
                    (v4 is NULL OR v4 = COALESCE(?3,v4)) AND
                    (v5 is NULL OR v5 = COALESCE(?4,v5))",
            pt,
            field_values[0],
            field_values[1],
            field_values[2]
        ))
    } else if field_index == 2 {
        Box::new(sqlx::query!(
            "DELETE FROM casbin_rule WHERE
                    ptype = ?1 AND
                    (v2 is NULL OR v2 = COALESCE(?2,v2)) AND
                    (v3 is NULL OR v3 = COALESCE(?3,v3)) AND
                    (v4 is NULL OR v4 = COALESCE(?4,v4)) AND
                    (v5 is NULL OR v5 = COALESCE(?5,v5))",
            pt,
            field_values[0],
            field_values[1],
            field_values[2],
            field_values[3]
        ))
    } else if field_index == 1 {
        Box::new(sqlx::query!(
            "DELETE FROM casbin_rule WHERE
                    ptype = ?1 AND
                    (v1 is NULL OR v1 = COALESCE(?2,v1)) AND
                    (v2 is NULL OR v2 = COALESCE(?3,v2)) AND
                    (v3 is NULL OR v3 = COALESCE(?4,v3)) AND
                    (v4 is NULL OR v4 = COALESCE(?5,v4)) AND
                    (v5 is NULL OR v5 = COALESCE(?6,v5))",
            pt,
            field_values[0],
            field_values[1],
            field_values[2],
            field_values[3],
            field_values[4]
        ))
    } else {
        Box::new(sqlx::query!(
            "DELETE FROM casbin_rule WHERE
                    ptype = ?1 AND
                    (v0 is NULL OR v0 = COALESCE(?2,v0)) AND
                    (v1 is NULL OR v1 = COALESCE(?3,v1)) AND
                    (v2 is NULL OR v2 = COALESCE(?4,v2)) AND
                    (v3 is NULL OR v3 = COALESCE(?5,v3)) AND
                    (v4 is NULL OR v4 = COALESCE(?6,v4)) AND
                    (v5 is NULL OR v5 = COALESCE(?7,v5))",
            pt,
            field_values[0],
            field_values[1],
            field_values[2],
            field_values[3],
            field_values[4],
            field_values[5]
        ))
    };

    boxed_query
        .execute(conn)
        .await
        .map(|n| SqliteQueryResult::rows_affected(&n) >= 1)
        .map_err(|err| CasbinError::from(AdapterError(Box::new(Error::SqlxError(err)))))
}

#[cfg(feature = "mysql")]
pub async fn remove_filtered_policy(
    conn: &ConnectionPool,
    pt: &str,
    field_index: usize,
    field_values: Vec<String>,
) -> Result<bool> {
    let field_values = normalize_casbin_rule_option(field_values);
    let boxed_query = if field_index == 5 {
        Box::new(sqlx::query!(
            "DELETE FROM casbin_rule WHERE
                    ptype = ? AND
                    (v5 is NULL OR v5 = COALESCE(?,v5))",
            pt,
            field_values[0]
        ))
    } else if field_index == 4 {
        Box::new(sqlx::query!(
            "DELETE FROM casbin_rule WHERE
                    ptype = ? AND
                    (v4 is NULL OR v4 = COALESCE(?,v4)) AND
                    (v5 is NULL OR v5 = COALESCE(?,v5))",
            pt.to_string(),
            field_values[0],
            field_values[1]
        ))
    } else if field_index == 3 {
        Box::new(sqlx::query!(
            "DELETE FROM casbin_rule WHERE
                    ptype = ? AND
                    (v3 is NULL OR v3 = COALESCE(?,v3)) AND
                    (v4 is NULL OR v4 = COALESCE(?,v4)) AND
                    (v5 is NULL OR v5 = COALESCE(?,v5))",
            pt,
            field_values[0],
            field_values[1],
            field_values[2]
        ))
    } else if field_index == 2 {
        Box::new(sqlx::query!(
            "DELETE FROM casbin_rule WHERE
                    ptype = ? AND
                    (v2 is NULL OR v2 = COALESCE(?,v2)) AND
                    (v3 is NULL OR v3 = COALESCE(?,v3)) AND
                    (v4 is NULL OR v4 = COALESCE(?,v4)) AND
                    (v5 is NULL OR v5 = COALESCE(?,v5))",
            pt,
            field_values[0],
            field_values[1],
            field_values[2],
            field_values[3]
        ))
    } else if field_index == 1 {
        Box::new(sqlx::query!(
            "DELETE FROM casbin_rule WHERE
                    ptype = ? AND
                    (v1 is NULL OR v1 = COALESCE(?,v1)) AND
                    (v2 is NULL OR v2 = COALESCE(?,v2)) AND
                    (v3 is NULL OR v3 = COALESCE(?,v3)) AND
                    (v4 is NULL OR v4 = COALESCE(?,v4)) AND
                    (v5 is NULL OR v5 = COALESCE(?,v5))",
            pt,
            field_values[0],
            field_values[1],
            field_values[2],
            field_values[3],
            field_values[4]
        ))
    } else {
        Box::new(sqlx::query!(
            "DELETE FROM casbin_rule WHERE
                    ptype = ? AND
                    (v0 is NULL OR v0 = COALESCE(?,v0)) AND
                    (v1 is NULL OR v1 = COALESCE(?,v1)) AND
                    (v2 is NULL OR v2 = COALESCE(?,v2)) AND
                    (v3 is NULL OR v3 = COALESCE(?,v3)) AND
                    (v4 is NULL OR v4 = COALESCE(?,v4)) AND
                    (v5 is NULL OR v5 = COALESCE(?,v5))",
            pt,
            field_values[0],
            field_values[1],
            field_values[2],
            field_values[3],
            field_values[4],
            field_values[5]
        ))
    };

    boxed_query
        .execute(conn)
        .await
        .map(|n| MySqlQueryResult::rows_affected(&n) >= 1)
        .map_err(|err| CasbinError::from(AdapterError(Box::new(Error::SqlxError(err)))))
}

#[cfg(feature = "postgres")]
pub(crate) async fn load_policy(conn: &ConnectionPool) -> Result<Vec<CasbinRule>> {
    let casbin_rule: Vec<CasbinRule> = sqlx::query_as!(CasbinRule, "SELECT * FROM casbin_rule")
        .fetch_all(conn)
        .await
        .map_err(|err| CasbinError::from(AdapterError(Box::new(Error::SqlxError(err)))))?;

    Ok(casbin_rule)
}

#[cfg(feature = "sqlite")]
pub(crate) async fn load_policy(conn: &ConnectionPool) -> Result<Vec<CasbinRule>> {
    let casbin_rule: Vec<CasbinRule> = sqlx::query_as!(CasbinRule, "SELECT * FROM casbin_rule")
        .fetch_all(conn)
        .await
        .map_err(|err| CasbinError::from(AdapterError(Box::new(Error::SqlxError(err)))))?;

    Ok(casbin_rule)
}

#[cfg(feature = "mysql")]
pub(crate) async fn load_policy(conn: &ConnectionPool) -> Result<Vec<CasbinRule>> {
    let casbin_rule: Vec<CasbinRule> = sqlx::query_as!(CasbinRule, "SELECT * FROM casbin_rule")
        .fetch_all(conn)
        .await
        .map_err(|err| CasbinError::from(AdapterError(Box::new(Error::SqlxError(err)))))?;

    Ok(casbin_rule)
}

#[cfg(feature = "postgres")]
pub(crate) async fn load_filtered_policy<'a>(
    conn: &ConnectionPool,
    filter: &Filter<'_>,
) -> Result<Vec<CasbinRule>> {
    let (g_filter, p_filter) = filtered_where_values(filter);

    let casbin_rule: Vec<CasbinRule> = sqlx::query_as!(
        CasbinRule,
        "SELECT * from  casbin_rule WHERE (
            ptype LIKE 'g%' AND v0 LIKE $1 AND v1 LIKE $2 AND v2 LIKE $3 AND v3 LIKE $4 AND v4 LIKE $5 AND v5 LIKE $6 )
        OR (
            ptype LIKE 'p%' AND v0 LIKE $7 AND v1 LIKE $8 AND v2 LIKE $9 AND v3 LIKE $10 AND v4 LIKE $11 AND v5 LIKE $12 );
            ",
            g_filter[0], g_filter[1], g_filter[2], g_filter[3], g_filter[4], g_filter[5],
            p_filter[0], p_filter[1], p_filter[2], p_filter[3], p_filter[4], p_filter[5],)
    .fetch_all(conn)
    .await
    .map_err(|err| CasbinError::from(AdapterError(Box::new(Error::SqlxError(err)))))?;

    Ok(casbin_rule)
}

#[cfg(feature = "sqlite")]
pub(crate) async fn load_filtered_policy<'a>(
    conn: &ConnectionPool,
    filter: &Filter<'_>,
) -> Result<Vec<CasbinRule>> {
    let (g_filter, p_filter) = filtered_where_values(filter);

    let casbin_rule: Vec<CasbinRule> = sqlx::query_as!(
        CasbinRule,
        "SELECT * from  casbin_rule WHERE (
            ptype LIKE 'g%' AND v0 LIKE $1 AND v1 LIKE $2 AND v2 LIKE $3 AND v3 LIKE $4 AND v4 LIKE $5 AND v5 LIKE $6 )
        OR (
            ptype LIKE 'p%' AND v0 LIKE $7 AND v1 LIKE $8 AND v2 LIKE $9 AND v3 LIKE $10 AND v4 LIKE $11 AND v5 LIKE $12 );
            ",
            g_filter[0], g_filter[1], g_filter[2], g_filter[3], g_filter[4], g_filter[5],
            p_filter[0], p_filter[1], p_filter[2], p_filter[3], p_filter[4], p_filter[5],)
        .fetch_all(conn)
        .await
        .map_err(|err| CasbinError::from(AdapterError(Box::new(Error::SqlxError(err)))))?;

    Ok(casbin_rule)
}

#[cfg(feature = "mysql")]
pub(crate) async fn load_filtered_policy<'a>(
    conn: &ConnectionPool,
    filter: &Filter<'_>,
) -> Result<Vec<CasbinRule>> {
    let (g_filter, p_filter) = filtered_where_values(filter);

    let casbin_rule: Vec<CasbinRule> = sqlx::query_as!(
        CasbinRule,
        "SELECT * from  casbin_rule WHERE (
            ptype LIKE 'g%' AND v0 LIKE ? AND v1 LIKE ? AND v2 LIKE ? AND v3 LIKE ? AND v4 LIKE ? AND v5 LIKE ? )
        OR (
            ptype LIKE 'p%' AND v0 LIKE ? AND v1 LIKE ? AND v2 LIKE ? AND v3 LIKE ? AND v4 LIKE ? AND v5 LIKE ? );
            ",
            g_filter[0], g_filter[1], g_filter[2], g_filter[3], g_filter[4], g_filter[5],
            p_filter[0], p_filter[1], p_filter[2], p_filter[3], p_filter[4], p_filter[5],
    )
    .fetch_all(conn)
    .await
    .map_err(|err| CasbinError::from(AdapterError(Box::new(Error::SqlxError(err)))))?;

    Ok(casbin_rule)
}

fn filtered_where_values<'a>(filter: &Filter<'a>) -> ([&'a str; 6], [&'a str; 6]) {
    let mut g_filter: [&'a str; 6] = ["%", "%", "%", "%", "%", "%"];
    let mut p_filter: [&'a str; 6] = ["%", "%", "%", "%", "%", "%"];
    for (idx, val) in filter.g.iter().enumerate() {
        if val != &"" {
            g_filter[idx] = val;
        }
    }
    for (idx, val) in filter.p.iter().enumerate() {
        if val != &"" {
            p_filter[idx] = val;
        }
    }
    (g_filter, p_filter)
}

#[cfg(feature = "postgres")]
pub(crate) async fn save_policy(
    conn: &ConnectionPool,
    rules: Vec<NewCasbinRule<'_>>,
) -> Result<()> {
    let mut transaction = conn
        .begin()
        .await
        .map_err(|err| CasbinError::from(AdapterError(Box::new(Error::SqlxError(err)))))?;
    sqlx::query!("DELETE FROM casbin_rule")
        .execute(&mut transaction)
        .await
        .map_err(|err| CasbinError::from(AdapterError(Box::new(Error::SqlxError(err)))))?;
    for rule in rules {
        sqlx::query!(
            "INSERT INTO casbin_rule ( ptype, v0, v1, v2, v3, v4, v5 )
                 VALUES ( $1, $2, $3, $4, $5, $6, $7 )",
            rule.ptype,
            rule.v0,
            rule.v1,
            rule.v2,
            rule.v3,
            rule.v4,
            rule.v5
        )
        .execute(&mut transaction)
        .await
        .and_then(|n| {
            if PgQueryResult::rows_affected(&n) == 1 {
                Ok(true)
            } else {
                Err(SqlxError::RowNotFound)
            }
        })
        .map_err(|err| CasbinError::from(AdapterError(Box::new(Error::SqlxError(err)))))?;
    }
    transaction
        .commit()
        .await
        .map_err(|err| CasbinError::from(AdapterError(Box::new(Error::SqlxError(err)))))?;
    Ok(())
}

#[cfg(feature = "sqlite")]
pub(crate) async fn save_policy(
    conn: &ConnectionPool,
    rules: Vec<NewCasbinRule<'_>>,
) -> Result<()> {
    let mut transaction = conn
        .begin()
        .await
        .map_err(|err| CasbinError::from(AdapterError(Box::new(Error::SqlxError(err)))))?;
    sqlx::query!("DELETE FROM casbin_rule")
        .execute(&mut transaction)
        .await
        .map_err(|err| CasbinError::from(AdapterError(Box::new(Error::SqlxError(err)))))?;
    for rule in rules {
        sqlx::query!(
            "INSERT INTO casbin_rule ( ptype, v0, v1, v2, v3, v4, v5 )
                 VALUES ( $1, $2, $3, $4, $5, $6, $7 )",
            rule.ptype,
            rule.v0,
            rule.v1,
            rule.v2,
            rule.v3,
            rule.v4,
            rule.v5
        )
        .execute(&mut transaction)
        .await
        .and_then(|n| {
            if SqliteQueryResult::rows_affected(&n) == 1 {
                Ok(true)
            } else {
                Err(SqlxError::RowNotFound)
            }
        })
        .map_err(|err| CasbinError::from(AdapterError(Box::new(Error::SqlxError(err)))))?;
    }
    transaction
        .commit()
        .await
        .map_err(|err| CasbinError::from(AdapterError(Box::new(Error::SqlxError(err)))))?;
    Ok(())
}

#[cfg(feature = "mysql")]
pub(crate) async fn save_policy<'a>(
    conn: &ConnectionPool,
    rules: Vec<NewCasbinRule<'a>>,
) -> Result<()> {
    let mut transaction = conn
        .begin()
        .await
        .map_err(|err| CasbinError::from(AdapterError(Box::new(Error::SqlxError(err)))))?;
    sqlx::query!("DELETE FROM casbin_rule")
        .execute(&mut transaction)
        .await
        .map_err(|err| CasbinError::from(AdapterError(Box::new(Error::SqlxError(err)))))?;
    for rule in rules {
        sqlx::query!(
            "INSERT INTO casbin_rule ( ptype, v0, v1, v2, v3, v4, v5 )
                 VALUES ( ?, ?, ?, ?, ?, ?, ? )",
            rule.ptype,
            rule.v0,
            rule.v1,
            rule.v2,
            rule.v3,
            rule.v4,
            rule.v5
        )
        .execute(&mut transaction)
        .await
        .and_then(|n| {
            if MySqlQueryResult::rows_affected(&n) == 1 {
                Ok(true)
            } else {
                Err(SqlxError::RowNotFound)
            }
        })
        .map_err(|err| CasbinError::from(AdapterError(Box::new(Error::SqlxError(err)))))?;
    }
    transaction
        .commit()
        .await
        .map_err(|err| CasbinError::from(AdapterError(Box::new(Error::SqlxError(err)))))?;
    Ok(())
}

#[cfg(feature = "postgres")]
pub(crate) async fn add_policy(conn: &ConnectionPool, rule: NewCasbinRule<'_>) -> Result<bool> {
    sqlx::query!(
        "INSERT INTO casbin_rule ( ptype, v0, v1, v2, v3, v4, v5 )
                 VALUES ( $1, $2, $3, $4, $5, $6, $7 )",
        rule.ptype,
        rule.v0,
        rule.v1,
        rule.v2,
        rule.v3,
        rule.v4,
        rule.v5
    )
    .execute(conn)
    .await
    .map(|n| PgQueryResult::rows_affected(&n) == 1)
    .map_err(|err| CasbinError::from(AdapterError(Box::new(Error::SqlxError(err)))))?;

    Ok(true)
}

#[cfg(feature = "sqlite")]
pub(crate) async fn add_policy(conn: &ConnectionPool, rule: NewCasbinRule<'_>) -> Result<bool> {
    sqlx::query!(
        "INSERT INTO casbin_rule ( ptype, v0, v1, v2, v3, v4, v5 )
                 VALUES ( $1, $2, $3, $4, $5, $6, $7 )",
        rule.ptype,
        rule.v0,
        rule.v1,
        rule.v2,
        rule.v3,
        rule.v4,
        rule.v5
    )
    .execute(conn)
    .await
    .map(|n| SqliteQueryResult::rows_affected(&n) == 1)
    .map_err(|err| CasbinError::from(AdapterError(Box::new(Error::SqlxError(err)))))?;

    Ok(true)
}

#[cfg(feature = "mysql")]
pub(crate) async fn add_policy(conn: &ConnectionPool, rule: NewCasbinRule<'_>) -> Result<bool> {
    sqlx::query!(
        "INSERT INTO casbin_rule ( ptype, v0, v1, v2, v3, v4, v5 )
                 VALUES ( ?, ?, ?, ?, ?, ?, ? )",
        rule.ptype,
        rule.v0,
        rule.v1,
        rule.v2,
        rule.v3,
        rule.v4,
        rule.v5
    )
    .execute(conn)
    .await
    .map(|n| MySqlQueryResult::rows_affected(&n) == 1)
    .map_err(|err| CasbinError::from(AdapterError(Box::new(Error::SqlxError(err)))))?;

    Ok(true)
}

#[cfg(feature = "postgres")]
pub(crate) async fn add_policies(
    conn: &ConnectionPool,
    rules: Vec<NewCasbinRule<'_>>,
) -> Result<bool> {
    let mut transaction = conn
        .begin()
        .await
        .map_err(|err| CasbinError::from(AdapterError(Box::new(Error::SqlxError(err)))))?;
    for rule in rules {
        sqlx::query!(
            "INSERT INTO casbin_rule ( ptype, v0, v1, v2, v3, v4, v5 )
                 VALUES ( $1, $2, $3, $4, $5, $6, $7 )",
            rule.ptype,
            rule.v0,
            rule.v1,
            rule.v2,
            rule.v3,
            rule.v4,
            rule.v5
        )
        .execute(&mut transaction)
        .await
        .and_then(|n| {
            if PgQueryResult::rows_affected(&n) == 1 {
                Ok(true)
            } else {
                Err(SqlxError::RowNotFound)
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

#[cfg(feature = "sqlite")]
pub(crate) async fn add_policies(
    conn: &ConnectionPool,
    rules: Vec<NewCasbinRule<'_>>,
) -> Result<bool> {
    let mut transaction = conn
        .begin()
        .await
        .map_err(|err| CasbinError::from(AdapterError(Box::new(Error::SqlxError(err)))))?;
    for rule in rules {
        sqlx::query!(
            "INSERT INTO casbin_rule ( ptype, v0, v1, v2, v3, v4, v5 )
                 VALUES ( $1, $2, $3, $4, $5, $6, $7 )",
            rule.ptype,
            rule.v0,
            rule.v1,
            rule.v2,
            rule.v3,
            rule.v4,
            rule.v5
        )
        .execute(&mut transaction)
        .await
        .and_then(|n| {
            if SqliteQueryResult::rows_affected(&n) == 1 {
                Ok(true)
            } else {
                Err(SqlxError::RowNotFound)
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

#[cfg(feature = "mysql")]
pub(crate) async fn add_policies(
    conn: &ConnectionPool,
    rules: Vec<NewCasbinRule<'_>>,
) -> Result<bool> {
    let mut transaction = conn
        .begin()
        .await
        .map_err(|err| CasbinError::from(AdapterError(Box::new(Error::SqlxError(err)))))?;
    for rule in rules {
        sqlx::query!(
            "INSERT INTO casbin_rule ( ptype, v0, v1, v2, v3, v4, v5 )
                 VALUES ( ?, ?, ?, ?, ?, ?, ? )",
            rule.ptype,
            rule.v0,
            rule.v1,
            rule.v2,
            rule.v3,
            rule.v4,
            rule.v5
        )
        .execute(&mut transaction)
        .await
        .and_then(|n| {
            if MySqlQueryResult::rows_affected(&n) == 1 {
                Ok(true)
            } else {
                Err(SqlxError::RowNotFound)
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

#[cfg(feature = "postgres")]
pub(crate) async fn clear_policy(conn: &ConnectionPool) -> Result<()> {
    let mut transaction = conn
        .begin()
        .await
        .map_err(|err| CasbinError::from(AdapterError(Box::new(Error::SqlxError(err)))))?;
    sqlx::query!("DELETE FROM casbin_rule")
        .execute(&mut transaction)
        .await
        .map_err(|err| CasbinError::from(AdapterError(Box::new(Error::SqlxError(err)))))?;
    transaction
        .commit()
        .await
        .map_err(|err| CasbinError::from(AdapterError(Box::new(Error::SqlxError(err)))))?;
    Ok(())
}

#[cfg(feature = "sqlite")]
pub(crate) async fn clear_policy(conn: &ConnectionPool) -> Result<()> {
    let mut transaction = conn
        .begin()
        .await
        .map_err(|err| CasbinError::from(AdapterError(Box::new(Error::SqlxError(err)))))?;
    sqlx::query!("DELETE FROM casbin_rule")
        .execute(&mut transaction)
        .await
        .map_err(|err| CasbinError::from(AdapterError(Box::new(Error::SqlxError(err)))))?;
    transaction
        .commit()
        .await
        .map_err(|err| CasbinError::from(AdapterError(Box::new(Error::SqlxError(err)))))?;
    Ok(())
}

#[cfg(feature = "mysql")]
pub(crate) async fn clear_policy(conn: &ConnectionPool) -> Result<()> {
    let mut transaction = conn
        .begin()
        .await
        .map_err(|err| CasbinError::from(AdapterError(Box::new(Error::SqlxError(err)))))?;
    sqlx::query!("DELETE FROM casbin_rule")
        .execute(&mut transaction)
        .await
        .map_err(|err| CasbinError::from(AdapterError(Box::new(Error::SqlxError(err)))))?;
    transaction
        .commit()
        .await
        .map_err(|err| CasbinError::from(AdapterError(Box::new(Error::SqlxError(err)))))?;
    Ok(())
}

fn normalize_casbin_rule(mut rule: Vec<String>) -> Vec<String> {
    rule.resize(6, String::new());
    rule
}

fn normalize_casbin_rule_option(rule: Vec<String>) -> Vec<Option<String>> {
    let mut rule_with_option = rule
        .iter()
        .map(|x| Some(x.clone()))
        .collect::<Vec<Option<String>>>();
    rule_with_option.resize(6, None);
    rule_with_option
}
