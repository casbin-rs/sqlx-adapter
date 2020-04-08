# sqlx-adapter

[![Build Status](https://travis-ci.org/casbin-rs/sqlx-adapter.svg?branch=master)](https://travis-ci.org/casbin-rs/sqlx-adapter)

An adapter designed to work with [casbin-rs](https://github.com/casbin/casbin-rs) which is fully `asynchronous`.


## Install

Add it to `Cargo.toml`

```rust
casbin = { version = "0.4.3" }
sqlx-adapter = { version = "0.1.0", features = ["postgres"] }
async-std = "1.5.0"
```

## Configure

create `.env` and put DATABASE_URL inside

```bash
DATABASE_URL=postgres://casbin_rs:casbin_rs@localhost:5432/casbin
POOL_SIZE=8
```


## Example

```rust
use casbin::prelude::*;
use sqlx_adapter::SqlxAdapter;

#[async_std::main]
async fn main() -> Result<()> {
    let m = DefaultModel::from_file("examples/rbac_model.conf").await?;
    
    let a = SqlxAdapter::new().await?;
    let mut e = Enforcer::new(m, a).await?;
    
    Ok(())
}

```

## Features

- `postgres`
- `mysql`

*Attention*: `postgres` and `mysql` are mutual exclusive which means that you can only activate one of them. Currently we don't have support for `sqlite`, it may be added in the near future.
