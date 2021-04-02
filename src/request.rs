use serde::Deserialize;
#[derive(Debug, Clone, Deserialize)]
pub struct SignUp {
    pub phone: String,
    pub password: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct SignIn {
    pub phone: String,
    pub password: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct VerifyToken(pub String);

#[derive(Debug, Clone, Deserialize)]
pub struct ChangePassword {
    pub phone: String,
    pub old_password: String,
    pub new_password: String,
}
