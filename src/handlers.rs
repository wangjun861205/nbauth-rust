use super::request::{SignIn, SignUp, VerifyToken};
use crate::model::{Account, AccountInsert, AccountQuery, AccountUpdate};
use hmac::{Hmac, NewMac};
use jwt::{SignWithKey, VerifyWithKey};
use rand::distributions::Alphanumeric;
use rand::Rng;
use rocket::http::{Cookie, Cookies};

use crate::{ExpireDuration, JWTKey, RetryInterval, RetryLimit};
use rocket::http::Status;
use rocket::request::Request;
use rocket::response::{self, Responder};
use rocket::State;
use rocket_contrib::json::Json;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{convert::From, ops::Add};
use time::Duration;
use uuid::Uuid;

#[derive(Debug, PartialEq)]
pub enum StoreError {
    NotFoundError,
    NetworkError,
    InternalError,
}

pub type StoreResult<T> = std::result::Result<T, StoreError>;

pub trait Storer: Send + Sync {
    fn insert_account(&self, acct: AccountInsert) -> StoreResult<usize>;
    fn update_account(&self, q: AccountQuery, u: AccountUpdate) -> StoreResult<usize>;
    fn get_account(&self, q: AccountQuery) -> StoreResult<Account>;
}

#[derive(Debug)]
pub enum Error {
    DBError(StoreError),
    AuthError(Status),
}

impl<'r> Responder<'r> for Error {
    fn respond_to(self, _: &Request) -> response::Result<'r> {
        match self {
            Error::DBError(e) => {
                if e == StoreError::NotFoundError {
                    return Err(Status::NotFound);
                } else {
                    return Err(Status::InternalServerError);
                }
            }
            Error::AuthError(s) => {
                return Err(s);
            }
        }
    }
}

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Claim {
    id: String,
    phone: String,
    expiration: i64,
}

fn sign_jwt(id: String, phone: String, exp: ExpireDuration, jwt_key: &JWTKey) -> String {
    let key: Hmac<Sha256> = Hmac::new_varkey(jwt_key.as_bytes()).unwrap();
    Claim {
        id: id,
        phone: phone,
        expiration: chrono::Local::now().add(exp).timestamp(),
    }
    .sign_with_key(&key)
    .unwrap()
}

fn verify_jwt(token: String, jwt_key: &JWTKey) -> bool {
    let key: Hmac<Sha256> = Hmac::new_varkey(jwt_key.as_bytes()).unwrap();
    token
        .verify_with_key(&key)
        .map_or(false, |c: Claim| if c.expiration <= chrono::Local::now().timestamp() { false } else { true })
}

fn set_jwt_cookie(token: String, mut cookies: Cookies, exp: time::Duration) {
    let mut cookie = Cookie::new("JWT-Token", token);
    cookie.set_expires(time::now().add(exp));
    cookie.set_http_only(true);
    cookies.add(cookie);
}

#[post("/sign_up", format = "json", data = "<info>")]
pub fn sign_up(store: State<Box<dyn Storer>>, info: Json<SignUp>, cookies: Cookies, key: State<JWTKey>, exp: State<time::Duration>) -> Result<()> {
    let mut hasher = Sha256::new();
    let salt: String = rand::thread_rng().sample_iter(&Alphanumeric).take(16).map(char::from).collect();
    hasher.update(format!("{}{}", info.0.password, salt));
    let id = Uuid::new_v4().to_simple().to_string();
    let acct = AccountInsert {
        id: id.clone(),
        phone: info.0.phone.clone(),
        password: hasher.finalize().to_vec().iter().map(|c| format!("{:02X?}", c)).collect(),
        salt: salt,
        create_at: chrono::Local::now().timestamp(),
    };
    store.insert_account(acct).or_else(|e| Err(Error::DBError(e)))?;
    let jwt_token = sign_jwt(id.clone(), info.0.phone.clone(), *exp, &key);
    set_jwt_cookie(jwt_token, cookies, *exp);
    Ok(())
}

fn check_error_count(store: &Box<dyn Storer>, acct: &mut Account, limit: i32, interval: Duration) -> Result<()> {
    if acct.login_error_count >= limit {
        if acct.last_error_at.unwrap() + interval.num_seconds() > time::now().to_timespec().sec {
            return Err(Error::AuthError(Status::TooManyRequests));
        } else {
            store
                .update_account(
                    AccountQuery {
                        phone: Some(acct.phone.clone()),
                        ..Default::default()
                    },
                    AccountUpdate {
                        login_error_count: Some(0),
                        ..Default::default()
                    },
                )
                .or_else(|e| Err(Error::DBError(e)))?;
            acct.login_error_count = 0;
            return Ok(());
        }
    }
    Ok(())
}

fn check_password(store: &Box<dyn Storer>, acct: &mut Account, pass: String) -> Result<()> {
    let mut hasher = Sha256::new();
    hasher.update(format!("{}{}", pass, acct.salt));
    let h: String = hasher.finalize().as_slice().iter().map(|c| format!("{:02X?}", c)).collect();

    if h != acct.password {
        store
            .update_account(
                AccountQuery {
                    phone: Some(acct.phone.clone()),
                    ..Default::default()
                },
                AccountUpdate {
                    login_error_count: Some(acct.login_error_count + 1),
                    last_error_at: Some(time::now().to_timespec().sec),
                    ..Default::default()
                },
            )
            .or_else(|e| Err(Error::DBError(e)))?;
        return Err(Error::AuthError(Status::UnprocessableEntity));
    }
    Ok(())
}

#[post("/auth", format = "json", data = "<req>")]
pub fn auth(
    store: State<Box<dyn Storer>>,
    req: Json<SignIn>,
    cookies: Cookies,
    key: State<JWTKey>,
    exp: State<ExpireDuration>,
    retry_limit: State<RetryLimit>,
    retry_interval: State<RetryInterval>,
) -> Result<()> {
    let mut acct = store
        .get_account(AccountQuery {
            phone: Some(req.0.phone.clone()),
            ..Default::default()
        })
        .or_else(|e| {
            if e == StoreError::NotFoundError {
                Err(Error::AuthError(Status::UnprocessableEntity))
            } else {
                Err(Error::DBError(e))
            }
        })?;
    check_error_count(store.inner(), &mut acct, *retry_limit, **retry_interval)?;
    check_password(store.inner(), &mut acct, req.0.password.clone())?;
    store
        .update_account(
            AccountQuery {
                phone: Some(acct.phone.clone()),
                ..Default::default()
            },
            AccountUpdate {
                login_error_count: Some(0),
                last_login_at: Some(time::now().to_timespec().sec),
                ..Default::default()
            },
        )
        .or_else(|e| Err(Error::DBError(e)))?;
    let token = sign_jwt(acct.id, acct.phone, *exp, &key);
    set_jwt_cookie(token, cookies, *exp);
    Ok(())
}

#[post("/verify", format = "json", data = "<token>")]
pub fn verify_jwt_token(token: Json<VerifyToken>, key: State<JWTKey>) -> Result<()> {
    if verify_jwt((*token).0.clone(), &key) {
        Ok(())
    } else {
        Err(Error::AuthError(Status::UnprocessableEntity))
    }
}
