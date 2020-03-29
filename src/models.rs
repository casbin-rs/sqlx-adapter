use serde::Serialize;

#[derive(Serialize, Debug)]
pub(crate) struct CasbinRule<'a> {
    pub id: &'a i32,
    pub ptype: &'a str,
    pub v0: &'a str,
    pub v1: &'a str,
    pub v2: &'a str,
    pub v3: &'a str,
    pub v4: &'a str,
    pub v5: &'a str,
}

#[derive(Serialize, Debug)]
pub(crate) struct NewCasbinRule<'a> {
    pub ptype: &'a str,
    pub v0: &'a str,
    pub v1: &'a str,
    pub v2: &'a str,
    pub v3: &'a str,
    pub v4: &'a str,
    pub v5: &'a str,
}