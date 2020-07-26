use crate::Error;
use casbin::{error::AdapterError, Error as CasbinError, Filter, Result};
use sqlx::{error::Error as SqlxError, pool::Pool};

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
                    CONSTRAINT unique_key_sqlx_adapter UNIQUE(ptype, v0, v1, v2, v3, v4, v5)
                    );
        "
    )
    .execute(&mut conn)
    .await
    .map_err(|err| CasbinError::from(AdapterError(Box::new(Error::SqlxError(err)))))
}

#[cfg(feature = "mysql")]
pub async fn new(mut conn: &ConnectionPool) -> Result<u64> {
    sqlx::query!(
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
                    CONSTRAINT unique_key_sqlx_adapter UNIQUE(ptype, v0, v1, v2, v3, v4, v5)
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8;",
    )
    .execute(&mut conn)
    .await
    .map_err(|err| CasbinError::from(AdapterError(Box::new(Error::SqlxError(err)))))
}

#[cfg(feature = "postgres")]
pub async fn remove_policy(mut conn: &ConnectionPool, pt: &str, rule: Vec<String>) -> Result<bool> {
    let rule = normalize_casbin_rule(rule, 0);
    sqlx::query!(
        "DELETE FROM casbin_rules WHERE
                    ptype = $1 AND
                    v0 = $2 AND
                    v1 = $3 AND
                    v2 = $4 AND
                    v3 = $5 AND
                    v4 = $6 AND
                    v5 = $7",
        pt.to_string(),
        rule[0],
        rule[1],
        rule[2],
        rule[3],
        rule[4],
        rule[5]
    )
    .execute(&mut conn)
    .await
    .map(|n| n == 1)
    .map_err(|err| CasbinError::from(AdapterError(Box::new(Error::SqlxError(err)))))
}

#[cfg(feature = "mysql")]
pub async fn remove_policy(mut conn: &ConnectionPool, pt: &str, rule: Vec<String>) -> Result<bool> {
    let rule = normalize_casbin_rule(rule, 0);
    sqlx::query!(
        "DELETE FROM casbin_rules WHERE
                    ptype = ? AND
                    v0 = ? AND
                    v1 = ? AND
                    v2 = ? AND
                    v3 = ? AND
                    v4 = ? AND
                    v5 = ?",
        pt.to_string(),
        rule[0],
        rule[1],
        rule[2],
        rule[3],
        rule[4],
        rule[5]
    )
    .execute(&mut conn)
    .await
    .map(|n| n == 1)
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
        let rule = normalize_casbin_rule(rule, 0);
        sqlx::query!(
            "DELETE FROM casbin_rules WHERE
                    ptype = $1 AND
                    v0 = $2 AND
                    v1 = $3 AND
                    v2 = $4 AND
                    v3 = $5 AND
                    v4 = $6 AND
                    v5 = $7",
            pt.to_string(),
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
            if n == 1 {
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
        let rule = normalize_casbin_rule(rule, 0);
        sqlx::query!(
            "DELETE FROM casbin_rules WHERE
                    ptype = ? AND
                    v0 = ? AND
                    v1 = ? AND
                    v2 = ? AND
                    v3 = ? AND
                    v4 = ? AND
                    v5 = ?",
            pt.to_string(),
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
            if n == 1 {
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
    mut conn: &ConnectionPool,
    pt: &str,
    field_index: usize,
    field_values: Vec<String>,
) -> Result<bool> {
    let field_values = normalize_casbin_rule(field_values, field_index);
    let boxed_query = if field_index == 5 {
        Box::new(sqlx::query!(
            "DELETE FROM casbin_rules WHERE
                    ptype = $1 AND
                    (v5 is NULL OR v5 = $2)",
            pt.to_string(),
            field_values[5]
        ))
    } else if field_index == 4 {
        Box::new(sqlx::query!(
            "DELETE FROM casbin_rules WHERE
                    ptype = $1 AND
                    (v4 is NULL OR v4 = $2) AND
                    (v5 is NULL OR v5 = $3)",
            pt.to_string(),
            field_values[4],
            field_values[5]
        ))
    } else if field_index == 3 {
        Box::new(sqlx::query!(
            "DELETE FROM casbin_rules WHERE
                    ptype = $1 AND
                    (v3 is NULL OR v3 = $2) AND
                    (v4 is NULL OR v4 = $3) AND
                    (v5 is NULL OR v5 = $4)",
            pt.to_string(),
            field_values[3],
            field_values[4],
            field_values[5]
        ))
    } else if field_index == 2 {
        Box::new(sqlx::query!(
            "DELETE FROM casbin_rules WHERE
                    ptype = $1 AND
                    (v2 is NULL OR v2 = $2) AND
                    (v3 is NULL OR v3 = $3) AND
                    (v4 is NULL OR v4 = $4) AND
                    (v5 is NULL OR v5 = $5)",
            pt.to_string(),
            field_values[2],
            field_values[3],
            field_values[4],
            field_values[5]
        ))
    } else if field_index == 1 {
        Box::new(sqlx::query!(
            "DELETE FROM casbin_rules WHERE
                    ptype = $1 AND
                    (v1 is NULL OR v1 = $2) AND
                    (v2 is NULL OR v2 = $3) AND
                    (v3 is NULL OR v3 = $4) AND
                    (v4 is NULL OR v4 = $5) AND
                    (v5 is NULL OR v5 = $6)",
            pt.to_string(),
            field_values[1],
            field_values[2],
            field_values[3],
            field_values[4],
            field_values[5]
        ))
    } else {
        Box::new(sqlx::query!(
            "DELETE FROM casbin_rules WHERE
                    ptype = $1 AND
                    (v0 is NULL OR v0 = $2) AND
                    (v1 is NULL OR v1 = $3) AND
                    (v2 is NULL OR v2 = $4) AND
                    (v3 is NULL OR v3 = $5) AND
                    (v4 is NULL OR v4 = $6) AND
                    (v5 is NULL OR v5 = $7)",
            pt.to_string(),
            field_values[0],
            field_values[1],
            field_values[2],
            field_values[3],
            field_values[4],
            field_values[5]
        ))
    };

    boxed_query
        .execute(&mut conn)
        .await
        .map(|n| n >= 1)
        .map_err(|err| CasbinError::from(AdapterError(Box::new(Error::SqlxError(err)))))
}

#[cfg(feature = "mysql")]
pub async fn remove_filtered_policy(
    mut conn: &ConnectionPool,
    pt: &str,
    field_index: usize,
    field_values: Vec<String>,
) -> Result<bool> {
    let field_values = normalize_casbin_rule(field_values, field_index);
    let boxed_query = if field_index == 5 {
        Box::new(sqlx::query!(
            "DELETE FROM casbin_rules WHERE
                    ptype = ? AND
                    (v5 is NULL OR v5 = ?)",
            pt.to_string(),
            field_values[5]
        ))
    } else if field_index == 4 {
        Box::new(sqlx::query!(
            "DELETE FROM casbin_rules WHERE
                    ptype = ? AND
                    (v4 is NULL OR v4 = ?) AND
                    (v5 is NULL OR v5 = ?)",
            pt.to_string(),
            field_values[4],
            field_values[5]
        ))
    } else if field_index == 3 {
        Box::new(sqlx::query!(
            "DELETE FROM casbin_rules WHERE
                    ptype = ? AND
                    (v3 is NULL OR v3 = ?) AND
                    (v4 is NULL OR v4 = ?) AND
                    (v5 is NULL OR v5 = ?)",
            pt.to_string(),
            field_values[3],
            field_values[4],
            field_values[5]
        ))
    } else if field_index == 2 {
        Box::new(sqlx::query!(
            "DELETE FROM casbin_rules WHERE
                    ptype = ? AND
                    (v2 is NULL OR v2 = ?) AND
                    (v3 is NULL OR v3 = ?) AND
                    (v4 is NULL OR v4 = ?) AND
                    (v5 is NULL OR v5 = ?)",
            pt.to_string(),
            field_values[2],
            field_values[3],
            field_values[4],
            field_values[5]
        ))
    } else if field_index == 1 {
        Box::new(sqlx::query!(
            "DELETE FROM casbin_rules WHERE
                    ptype = ? AND
                    (v1 is NULL OR v1 = ?) AND
                    (v2 is NULL OR v2 = ?) AND
                    (v3 is NULL OR v3 = ?) AND
                    (v4 is NULL OR v4 = ?) AND
                    (v5 is NULL OR v5 = ?)",
            pt.to_string(),
            field_values[1],
            field_values[2],
            field_values[3],
            field_values[4],
            field_values[5]
        ))
    } else {
        Box::new(sqlx::query!(
            "DELETE FROM casbin_rules WHERE
                    ptype = ? AND
                    (v0 is NULL OR v0 = ?) AND
                    (v1 is NULL OR v1 = ?) AND
                    (v2 is NULL OR v2 = ?) AND
                    (v3 is NULL OR v3 = ?) AND
                    (v4 is NULL OR v4 = ?) AND
                    (v5 is NULL OR v5 = ?)",
            pt.to_string(),
            field_values[0],
            field_values[1],
            field_values[2],
            field_values[3],
            field_values[4],
            field_values[5]
        ))
    };

    boxed_query
        .execute(&mut conn)
        .await
        .map(|n| n >= 1)
        .map_err(|err| CasbinError::from(AdapterError(Box::new(Error::SqlxError(err)))))
}

#[cfg(feature = "postgres")]
pub(crate) async fn load_policy(mut conn: &ConnectionPool) -> Result<Vec<CasbinRule>> {
    let casbin_rules: Vec<CasbinRule> = sqlx::query_as!(CasbinRule, "SELECT * from  casbin_rules")
        .fetch_all(&mut conn)
        .await
        .map_err(|err| CasbinError::from(AdapterError(Box::new(Error::SqlxError(err)))))?;

    Ok(casbin_rules)
}

#[cfg(feature = "mysql")]
pub(crate) async fn load_policy(mut conn: &ConnectionPool) -> Result<Vec<CasbinRule>> {
    let casbin_rules: Vec<CasbinRule> = sqlx::query_as!(CasbinRule, "SELECT * from  casbin_rules")
        .fetch_all(&mut conn)
        .await
        .map_err(|err| CasbinError::from(AdapterError(Box::new(Error::SqlxError(err)))))?;

    Ok(casbin_rules)
}

#[cfg(feature = "postgres")]
pub(crate) async fn load_filtered_policy<'a>(
    mut conn: &ConnectionPool,
    filter: &Filter<'_>,
) -> Result<Vec<CasbinRule>> {
    let mut g_filter: [&str; 6] = ["%", "%", "%", "%", "%", "%"];
    let mut p_filter: [&str; 6] = ["%", "%", "%", "%", "%", "%"];
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

    let casbin_rules: Vec<CasbinRule> = sqlx::query_as!(
        CasbinRule,
        "SELECT * from  casbin_rules WHERE (
            ptype LIKE 'g%' AND v0 LIKE $1 AND v1 LIKE $2 AND v2 LIKE $3 AND v3 LIKE $4 AND v4 LIKE $5 AND v5 LIKE $6 )
        OR (
            ptype LIKE 'p%' AND v0 LIKE $7 AND v1 LIKE $8 AND v2 LIKE $9 AND v3 LIKE $10 AND v4 LIKE $11 AND v5 LIKE $12 );
            ",
            g_filter[0], g_filter[1], g_filter[2], g_filter[3], g_filter[4], g_filter[5],
            p_filter[0], p_filter[1], p_filter[2], p_filter[3], p_filter[4], p_filter[5],)
    .fetch_all(&mut conn)
    .await
    .map_err(|err| CasbinError::from(AdapterError(Box::new(Error::SqlxError(err)))))?;

    Ok(casbin_rules)
}

#[cfg(feature = "mysql")]
pub(crate) async fn load_filtered_policy<'a>(
    mut conn: &ConnectionPool,
    filter: &Filter<'_>,
) -> Result<Vec<CasbinRule>> {
    let mut g_filter: [&str; 6] = ["%", "%", "%", "%", "%", "%"];
    let mut p_filter: [&str; 6] = ["%", "%", "%", "%", "%", "%"];
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

    let casbin_rules: Vec<CasbinRule> = sqlx::query_as!(
        CasbinRule,
        "SELECT * from  casbin_rules WHERE (
            ptype LIKE 'g%' AND v0 LIKE ? AND v1 LIKE ? AND v2 LIKE ? AND v3 LIKE ? AND v4 LIKE ? AND v5 LIKE ? )
        OR (
            ptype LIKE 'p%' AND v0 LIKE ? AND v1 LIKE ? AND v2 LIKE ? AND v3 LIKE ? AND v4 LIKE ? AND v5 LIKE ? );
            ",
            g_filter[0], g_filter[1], g_filter[2], g_filter[3], g_filter[4], g_filter[5],
            p_filter[0], p_filter[1], p_filter[2], p_filter[3], p_filter[4], p_filter[5],
    )
    .fetch_all(&mut conn)
    .await
    .map_err(|err| CasbinError::from(AdapterError(Box::new(Error::SqlxError(err)))))?;

    Ok(casbin_rules)
}

#[cfg(feature = "postgres")]
pub(crate) async fn save_policy<'a>(
    conn: &ConnectionPool,
    rules: Vec<NewCasbinRule<'a>>,
) -> Result<()> {
    let mut transaction = conn
        .begin()
        .await
        .map_err(|err| CasbinError::from(AdapterError(Box::new(Error::SqlxError(err)))))?;
    sqlx::query!("DELETE FROM casbin_rules")
        .execute(&mut transaction)
        .await
        .map_err(|err| CasbinError::from(AdapterError(Box::new(Error::SqlxError(err)))))?;
    for rule in rules {
        sqlx::query!(
            "INSERT INTO casbin_rules ( ptype, v0, v1, v2, v3, v4, v5 )
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
            if n == 1 {
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
    sqlx::query!("DELETE FROM casbin_rules")
        .execute(&mut transaction)
        .await
        .map_err(|err| CasbinError::from(AdapterError(Box::new(Error::SqlxError(err)))))?;
    for rule in rules {
        sqlx::query!(
            "INSERT INTO casbin_rules ( ptype, v0, v1, v2, v3, v4, v5 )
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
            if n == 1 {
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
pub(crate) async fn add_policy(mut conn: &ConnectionPool, rule: NewCasbinRule<'_>) -> Result<bool> {
    sqlx::query!(
        "INSERT INTO casbin_rules ( ptype, v0, v1, v2, v3, v4, v5 )
                 VALUES ( $1, $2, $3, $4, $5, $6, $7 )",
        rule.ptype,
        rule.v0,
        rule.v1,
        rule.v2,
        rule.v3,
        rule.v4,
        rule.v5
    )
    .execute(&mut conn)
    .await
    .map(|n| n == 1)
    .map_err(|err| CasbinError::from(AdapterError(Box::new(Error::SqlxError(err)))))?;

    Ok(true)
}

#[cfg(feature = "mysql")]
pub(crate) async fn add_policy(mut conn: &ConnectionPool, rule: NewCasbinRule<'_>) -> Result<bool> {
    sqlx::query!(
        "INSERT INTO casbin_rules ( ptype, v0, v1, v2, v3, v4, v5 )
                 VALUES ( ?, ?, ?, ?, ?, ?, ? )",
        rule.ptype,
        rule.v0,
        rule.v1,
        rule.v2,
        rule.v3,
        rule.v4,
        rule.v5
    )
    .execute(&mut conn)
    .await
    .map(|n| n == 1)
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
            "INSERT INTO casbin_rules ( ptype, v0, v1, v2, v3, v4, v5 )
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
            if n == 1 {
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
            "INSERT INTO casbin_rules ( ptype, v0, v1, v2, v3, v4, v5 )
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
            if n == 1 {
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

fn normalize_casbin_rule(mut rule: Vec<String>, field_index: usize) -> Vec<String> {
    rule.resize(6 - field_index, String::from(""));
    rule
}
