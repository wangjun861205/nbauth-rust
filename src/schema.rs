table! {
    account (id) {
        id -> Char,
        phone -> Char,
        password -> Varchar,
        salt -> Varchar,
        login_error_count -> Integer,
        last_login_at -> Nullable<Bigint>,
        last_error_at -> Nullable<Bigint>,
        create_at -> Bigint,
        update_at -> Nullable<Bigint>,
    }
}
