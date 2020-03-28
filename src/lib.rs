#[macro_use]
extern crate sqlx;

mod adapter;
mod error;

#[macro_use]
mod models;

mod databases;

pub use adapter::SqlxAdapter;
pub use error::Error;