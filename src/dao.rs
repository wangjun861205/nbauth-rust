use crate::model::{Account, AccountInsert, AccountQuery, AccountUpdate};
use crate::schema::account;
use crate::schema::account::dsl::*;
use diesel::prelude::*;
use diesel::QueryResult;
use diesel::{mysql::MysqlConnection, RunQueryDsl};

pub fn insert_account(conn: &MysqlConnection, acct: AccountInsert) -> QueryResult<()> {
    diesel::insert_into(account::table)
        .values(acct)
        .execute(conn)
        .and(Ok(()))
}

pub fn update_account(
    conn: &MysqlConnection,
    q: AccountQuery,
    u: AccountUpdate,
) -> QueryResult<usize> {
    let mut update = diesel::update(account::table).set(u).into_boxed();
    if let Some(acct_id) = q.id {
        update = update.filter(id.eq(acct_id));
    }
    if let Some(acct_phone) = q.phone {
        update = update.filter(phone.eq(acct_phone));
    }
    update.execute(conn)
}

pub fn get_account(conn: &MysqlConnection, q: AccountQuery) -> QueryResult<Account> {
    let mut query = account::table.into_boxed();
    if let Some(acct_id) = q.id {
        query = query.filter(id.eq(acct_id));
    }
    if let Some(acct_phone) = q.phone {
        query = query.filter(phone.eq(acct_phone));
    }
    query.first(conn)
}
