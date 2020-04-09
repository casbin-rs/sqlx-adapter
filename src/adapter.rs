use async_trait::async_trait;
use casbin::{error::AdapterError, Adapter, Error as CasbinError, Model, Result};
use sqlx::pool::Pool;

use crate::{error::*, models::*};

use crate::actions as adapter;

pub struct SqlxAdapter {
    pool: Pool<adapter::Connection>,
}

//pub const TABLE_NAME: &str = "casbin_rules";

impl<'a> SqlxAdapter {
    pub async fn new() -> Result<Self> {
        dotenv::from_path(".env").ok();
        let database_url = std::env::var("DATABASE_URL").expect("DATABASE_URL is required");
        let pool_size: u32 = std::env::var("POOL_SIZE")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(8);

        let pool = Pool::builder()
            .max_size(pool_size)
            .build(&database_url)
            .await
            .map_err(|err| CasbinError::from(AdapterError(Box::new(Error::SqlxError(err)))))?;

        adapter::new(&pool).await.map(|_| Self { pool })
    }

    pub(crate) fn save_policy_line(
        &self,
        ptype: &'a str,
        rule: &'a [String],
    ) -> Option<NewCasbinRule<'a>> {
        if ptype.trim().is_empty() || rule.is_empty() {
            return None;
        }

        let mut new_rule = NewCasbinRule {
            ptype,
            v0: "",
            v1: "",
            v2: "",
            v3: "",
            v4: "",
            v5: "",
        };

        new_rule.v0 = &rule[0];

        if rule.len() > 1 {
            new_rule.v1 = &rule[1];
        }

        if rule.len() > 2 {
            new_rule.v2 = &rule[2];
        }

        if rule.len() > 3 {
            new_rule.v3 = &rule[3];
        }

        if rule.len() > 4 {
            new_rule.v4 = &rule[4];
        }

        if rule.len() > 5 {
            new_rule.v5 = &rule[5];
        }

        Some(new_rule)
    }

    pub(crate) fn load_policy_line(&self, casbin_rule: &CasbinRule) -> Option<Vec<String>> {
        if casbin_rule.ptype.chars().next().is_some() {
            return self.normalize_policy(casbin_rule);
        }

        None
    }

    fn normalize_policy(&self, casbin_rule: &CasbinRule) -> Option<Vec<String>> {
        let mut result = vec![
            &casbin_rule.v0,
            &casbin_rule.v1,
            &casbin_rule.v2,
            &casbin_rule.v3,
            &casbin_rule.v4,
            &casbin_rule.v5,
        ];

        while let Some(last) = result.last() {
            if last.is_empty() {
                result.pop();
            } else {
                break;
            }
        }

        if !result.is_empty() {
            return Some(result.iter().map(|&x| x.to_owned()).collect());
        }

        None
    }
}

#[async_trait]
impl Adapter for SqlxAdapter {
    async fn load_policy(&self, m: &mut dyn Model) -> Result<()> {
        let rules = adapter::load_policy(&self.pool).await?;

        for casbin_rule in &rules {
            let rule = self.load_policy_line(casbin_rule);

            if let Some(ref sec) = casbin_rule.ptype.chars().next().map(|x| x.to_string()) {
                if let Some(t1) = m.get_mut_model().get_mut(sec) {
                    if let Some(t2) = t1.get_mut(&casbin_rule.ptype) {
                        if let Some(rule) = rule {
                            t2.get_mut_policy().insert(rule);
                        }
                    }
                }
            }
        }

        Ok(())
    }

    async fn save_policy(&mut self, m: &mut dyn Model) -> Result<()> {
        let mut rules = vec![];

        if let Some(ast_map) = m.get_model().get("p") {
            for (ptype, ast) in ast_map {
                let new_rules = ast
                    .get_policy()
                    .into_iter()
                    .filter_map(|x| self.save_policy_line(ptype, x));

                rules.extend(new_rules);
            }
        }

        if let Some(ast_map) = m.get_model().get("g") {
            for (ptype, ast) in ast_map {
                let new_rules = ast
                    .get_policy()
                    .into_iter()
                    .filter_map(|x| self.save_policy_line(ptype, x));

                rules.extend(new_rules);
            }
        }
        adapter::save_policy(&self.pool, rules).await
    }

    async fn add_policy(&mut self, _sec: &str, ptype: &str, rule: Vec<String>) -> Result<bool> {
        if let Some(new_rule) = self.save_policy_line(ptype, rule.as_slice()) {
            return adapter::add_policy(&self.pool, new_rule).await;
        }

        Ok(false)
    }

    async fn add_policies(
        &mut self,
        _sec: &str,
        ptype: &str,
        rules: Vec<Vec<String>>,
    ) -> Result<bool> {
        let new_rules = rules
            .iter()
            .filter_map(|x| self.save_policy_line(ptype, x))
            .collect::<Vec<NewCasbinRule>>();

        adapter::add_policies(&self.pool, new_rules).await
    }

    async fn remove_policy(&mut self, _sec: &str, pt: &str, rule: Vec<String>) -> Result<bool> {
        adapter::remove_policy(&self.pool, pt, rule).await
    }

    async fn remove_policies(
        &mut self,
        _sec: &str,
        pt: &str,
        rules: Vec<Vec<String>>,
    ) -> Result<bool> {
        adapter::remove_policies(&self.pool, pt, rules).await
    }

    async fn remove_filtered_policy(
        &mut self,
        _sec: &str,
        pt: &str,
        field_index: usize,
        field_values: Vec<String>,
    ) -> Result<bool> {
        if field_index <= 5 && !field_values.is_empty() && field_values.len() >= 6 - field_index {
            adapter::remove_filtered_policy(&self.pool, pt, field_index, field_values).await
        } else {
            Ok(false)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn to_owned(v: Vec<&str>) -> Vec<String> {
        v.into_iter().map(|x| x.to_owned()).collect()
    }

    #[cfg_attr(feature = "runtime-async-std", async_std::test)]
    #[cfg_attr(feature = "runtime-tokio", tokio::test)]
    async fn test_create() {
        use casbin::prelude::*;

        let m = DefaultModel::from_file("examples/rbac_model.conf")
            .await
            .unwrap();

        let adapter = SqlxAdapter::new().await.unwrap();

        assert!(Enforcer::new(m, adapter).await.is_ok());
    }

    #[cfg_attr(feature = "runtime-async-std", async_std::test)]
    #[cfg_attr(feature = "runtime-tokio", tokio::test)]
    async fn test_adapter() {
        use casbin::prelude::*;

        let file_adapter = FileAdapter::new("examples/rbac_policy.csv");

        let m = DefaultModel::from_file("examples/rbac_model.conf")
            .await
            .unwrap();

        let mut e = Enforcer::new(m, file_adapter).await.unwrap();
        let mut adapter = SqlxAdapter::new().await.unwrap();

        assert!(adapter.save_policy(e.get_mut_model()).await.is_ok());

        assert!(adapter
            .remove_policy("", "p", to_owned(vec!["alice", "data1", "read"]))
            .await
            .is_ok());
        assert!(adapter
            .remove_policy("", "p", to_owned(vec!["bob", "data2", "write"]))
            .await
            .is_ok());
        assert!(adapter
            .remove_policy("", "p", to_owned(vec!["data2_admin", "data2", "read"]))
            .await
            .is_ok());
        assert!(adapter
            .remove_policy("", "p", to_owned(vec!["data2_admin", "data2", "write"]))
            .await
            .is_ok());
        assert!(adapter
            .remove_policy("", "g", to_owned(vec!["alice", "data2_admin"]))
            .await
            .is_ok());

        assert!(adapter
            .add_policy("", "p", to_owned(vec!["alice", "data1", "read"]))
            .await
            .is_ok());
        assert!(adapter
            .add_policy("", "p", to_owned(vec!["bob", "data2", "write"]))
            .await
            .is_ok());
        assert!(adapter
            .add_policy("", "p", to_owned(vec!["data2_admin", "data2", "read"]))
            .await
            .is_ok());
        assert!(adapter
            .add_policy("", "p", to_owned(vec!["data2_admin", "data2", "write"]))
            .await
            .is_ok());

        assert!(adapter
            .remove_policies(
                "",
                "p",
                vec![
                    to_owned(vec!["alice", "data1", "read"]),
                    to_owned(vec!["bob", "data2", "write"]),
                    to_owned(vec!["data2_admin", "data2", "read"]),
                    to_owned(vec!["data2_admin", "data2", "write"]),
                ]
            )
            .await
            .is_ok());

        assert!(adapter
            .add_policies(
                "",
                "p",
                vec![
                    to_owned(vec!["alice", "data1", "read"]),
                    to_owned(vec!["bob", "data2", "write"]),
                    to_owned(vec!["data2_admin", "data2", "read"]),
                    to_owned(vec!["data2_admin", "data2", "write"]),
                ]
            )
            .await
            .is_ok());

        assert!(adapter
            .add_policy("", "g", to_owned(vec!["alice", "data2_admin"]))
            .await
            .is_ok());

        assert!(adapter
            .remove_policy("", "p", to_owned(vec!["alice", "data1", "read"]))
            .await
            .is_ok());
        assert!(adapter
            .remove_policy("", "p", to_owned(vec!["bob", "data2", "write"]))
            .await
            .is_ok());
        assert!(adapter
            .remove_policy("", "p", to_owned(vec!["data2_admin", "data2", "read"]))
            .await
            .is_ok());
        assert!(adapter
            .remove_policy("", "p", to_owned(vec!["data2_admin", "data2", "write"]))
            .await
            .is_ok());
        assert!(adapter
            .remove_policy("", "g", to_owned(vec!["alice", "data2_admin"]))
            .await
            .is_ok());

        assert!(!adapter
            .remove_policy(
                "",
                "g",
                to_owned(vec!["alice", "data2_admin", "not_exists"])
            )
            .await
            .unwrap());

        assert!(adapter
            .add_policy("", "g", to_owned(vec!["alice", "data2_admin"]))
            .await
            .is_ok());
        assert!(adapter
            .add_policy("", "g", to_owned(vec!["alice", "data2_admin"]))
            .await
            .is_err());

        assert!(!adapter
            .remove_filtered_policy(
                "",
                "g",
                0,
                to_owned(vec!["alice", "data2_admin", "not_exists"]),
            )
            .await
            .unwrap());

        assert!(adapter
            .remove_filtered_policy("", "g", 0, to_owned(vec!["alice", "data2_admin"]))
            .await
            .is_ok());

        assert!(adapter
            .add_policy(
                "",
                "g",
                to_owned(vec!["alice", "data2_admin", "domain1", "domain2"]),
            )
            .await
            .is_ok());
        assert!(adapter
            .remove_filtered_policy(
                "",
                "g",
                1,
                to_owned(vec!["data2_admin", "domain1", "domain2"]),
            )
            .await
            .is_ok());
    }
}
