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
    pub sub: i32,
    pub group_id: i32,
    pub role: String,
    pub iat: u64,
    pub exp: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenPayload {
    pub id: i32,
    pub group_id: i32,
    pub role: String,
}

impl From<User> for TokenPayload {
    fn from(user: User) -> Self {
        TokenPayload {
            id: user.id,
            group_id: user.group_id,
            role: user.role,
        }
    }
}

impl From<TokenClaims> for TokenPayload {
    fn from(token: TokenClaims) -> Self {
        TokenPayload {
            id: token.sub,
            group_id: token.group_id,
            role: token.role,
        }
    }
}

#[derive(Clone)]
pub struct TokenService {
    secret: String,
    expiration: u64,
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

    pub fn generate_token<T: Into<TokenPayload>>(&self, payload: T) -> Result<Token, Box<dyn Error>> {
        let iat = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("Time went backwards")
            .as_secs();
        let exp = iat + self.expiration;

        let token_payload = payload.into();

        let claims = TokenClaims {
            sub: token_payload.id,
            group_id: token_payload.group_id,
            role: token_payload.role,
            iat,
            exp,
        };

        let encoding_key = EncodingKey::from_secret(self.secret.as_ref());

        let token = encode(&Header::default(), &claims, &encoding_key)?;

        Ok(Token {
            token,
            iat,
            exp,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_and_retrieve_token() {
        let token_service = TokenService::new(Auth {
            secret: String::from("test"),
            expiration: 1000,
        });
        let user = User {
            id: 1,
            group_id: 1,
            email: String::from("test@test.com"),
            password: String::from("test"),
            role: String::from("test"),
        };

        let token = token_service.generate_token(user.to_owned()).unwrap();

        let claims = token_service.retrieve_token_claims(&token.token).unwrap().claims;

        assert_eq!(claims.sub, user.id);
        assert_eq!(claims.group_id, user.group_id);
        assert_eq!(claims.role, user.role);
    }
}
