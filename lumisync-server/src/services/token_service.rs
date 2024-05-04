use std::error::Error;
use std::time::{SystemTime, UNIX_EPOCH};

use jsonwebtoken::{decode, DecodingKey, encode, EncodingKey, Header, TokenData, Validation};
use serde::{Deserialize, Serialize};

use crate::configs::settings::Auth;
use crate::models::user::User;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Token {
    pub token: String,
    pub iat: u64,
    pub exp: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenClaims {
    pub sub: String,
    pub email: String,
    pub role: String,
    pub iat: u64,
    pub exp: u64,
}

#[derive(Clone)]
pub struct TokenService {
    expiration: u64,
    secret: String,
}

impl TokenService {
    pub fn new(auth: Auth) -> Self {
        Self {
            expiration: auth.expiration,
            secret: auth.secret.clone(),
        }
    }

    pub fn retrieve_token_claims(&self, token: &str) -> Result<TokenData<TokenClaims>, Box<dyn Error>> {
        let data = decode::<TokenClaims>(
            token,
            &DecodingKey::from_secret(self.secret.as_ref()),
            &Validation::default()
        )?;

        Ok(data)
    }

    pub fn generate_token(&self, user: &User) -> Result<Token, Box<dyn Error>> {
        let iat = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("Time went backwards")
            .as_secs();
        let exp = iat + self.expiration;

        let claims = TokenClaims {
            sub: user.id.to_string(),
            email: user.email.to_string(),
            role: user.role.to_string(),
            iat,
            exp,
        };

        let encoding_key = EncodingKey::from_secret(self.secret.as_ref());

        let token = encode(&Header::default(), &claims, &encoding_key)?;

        Ok(Token { token, iat, exp })
    }
}
