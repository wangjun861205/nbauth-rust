use crate::handlers::Storer;
use crate::handlers::{StoreError, StoreResult};
use crate::model::{Account, AccountInsert, AccountQuery, AccountUpdate};
use crate::schema::account;
use crate::schema::account::dsl::*;
use diesel::prelude::*;
use diesel::r2d2::{ConnectionManager, Pool};
use diesel::{mysql::MysqlConnection, RunQueryDsl};

pub struct MysqlStore(pub Pool<ConnectionManager<MysqlConnection>>);

impl Storer for MysqlStore {
    fn insert_account(&self, acct: AccountInsert) -> StoreResult<usize> {
        let conn = self.0.get().or_else(|_| Err(StoreError::NetworkError))?;
        diesel::insert_into(account::table).values(acct).execute(&conn).or_else(|_| Err(StoreError::InternalError))
    }

    fn update_account(&self, q: AccountQuery, u: AccountUpdate) -> StoreResult<usize> {
        let conn = self.0.get().or_else(|_| Err(StoreError::NetworkError))?;
        let mut update = diesel::update(account::table).set(u).into_boxed();
        if let Some(acct_id) = q.id {
            update = update.filter(id.eq(acct_id));
        }
        if let Some(acct_phone) = q.phone {
            update = update.filter(phone.eq(acct_phone));
        }
        update.execute(&conn).or(Err(StoreError::InternalError))
    }

    fn get_account(&self, q: AccountQuery) -> StoreResult<Account> {
        let conn = self.0.get().or_else(|_| Err(StoreError::NetworkError))?;
        let mut query = account::table.into_boxed();
        if let Some(acct_id) = q.id {
            query = query.filter(id.eq(acct_id));
        }
        if let Some(acct_phone) = q.phone {
            query = query.filter(phone.eq(acct_phone));
        }
        query.first(&conn).or(Err(StoreError::InternalError))
    }
}
