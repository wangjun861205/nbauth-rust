use crate::schema::account;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Deserialize, Serialize, Queryable)]
pub struct Account {
    pub id: String,
    pub phone: String,
    pub password: String,
    pub salt: String,
    pub login_error_count: i32,
    pub last_login_at: Option<i64>,
    pub last_error_at: Option<i64>,
    pub create_at: i64,
    pub update_at: Option<i64>,
}

#[derive(Debug, Clone, Deserialize, Serialize, Insertable)]
#[table_name = "account"]
pub struct AccountInsert {
    pub id: String,
    pub phone: String,
    pub password: String,
    pub salt: String,
    pub create_at: i64,
}

#[derive(Debug, Clone, Default)]
pub struct AccountQuery {
    pub id: Option<String>,
    pub phone: Option<String>,
}

#[derive(Debug, Clone, AsChangeset, Default)]
#[table_name = "account"]
pub struct AccountUpdate {
    pub password: Option<String>,
    pub login_error_count: Option<i32>,
    pub last_login_at: Option<i64>,
    pub last_error_at: Option<i64>,
}
