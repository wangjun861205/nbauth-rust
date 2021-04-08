#![feature(proc_macro_hygiene, decl_macro)]

extern crate chrono;
#[macro_use]
extern crate diesel;
extern crate r2d2;
#[macro_use]
extern crate rocket;
extern crate dotenv;
extern crate hmac;
extern crate jwt;
extern crate rand;
extern crate rocket_contrib;
extern crate serde;
extern crate sha2;
extern crate time;
extern crate uuid;

mod handlers;
mod model;
mod request;
mod schema;
mod store;
use diesel::mysql::MysqlConnection;
use diesel::r2d2::{ConnectionManager, Pool};
use handlers::Storer;
use std::env;
use std::ops::Deref;
use store::mysql::MysqlStore;
use time::Duration;

type JWTKey = String;
type ExpireDuration = Duration;
type RetryLimit = i32;
pub struct RetryInterval(Duration);

impl Deref for RetryInterval {
    type Target = Duration;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

fn main() {
    dotenv::dotenv().expect("读取环境变量失败");
    let dsn = env::var("DATABASE_URL").expect("读取mysql地址失败");
    let manager = ConnectionManager::<MysqlConnection>::new(&dsn);
    let pool = Pool::new(manager).unwrap();
    let jwt_key: JWTKey = env::var("JWT_KEY").expect("读取jwt key失败");
    let jwt_days = env::var("JWT_DAYS").expect("读取jwt有效时长失败");
    let expire_duration: ExpireDuration = Duration::days(jwt_days.parse().expect("非法的jwt有效时长"));
    let retry_limit: RetryLimit = env::var("RETRY_LIMIT").expect("读取重试次数限制失败").parse().expect("非法的重试次数限制");
    let retry_interval = RetryInterval(Duration::minutes(env::var("RETRY_INTERVAL").expect("读取重试间隔失败").parse().expect("非法的重试间隔")));
    rocket::ignite()
        .manage(Box::new(MysqlStore(pool)) as Box<dyn Storer>)
        .manage(jwt_key)
        .manage(expire_duration)
        .manage(retry_limit)
        .manage(retry_interval)
        .mount("/", routes![handlers::sign_up, handlers::auth, handlers::verify_jwt_token, handlers::logout])
        .launch();
}
