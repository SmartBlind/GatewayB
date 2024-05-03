use std::sync::Arc;

use axum::http;
use axum::body::Body;
use axum::extract::State;
use axum::http::{Request, StatusCode};
use axum::middleware::Next;
use axum::response::IntoResponse;
use axum_extra::headers::{Authorization, Header};
use axum_extra::headers::authorization::Bearer;

use crate::configs::storage::Storage;
use crate::models::user::User;
use crate::services::token_service::TokenService;

#[derive(Clone)]
pub struct TokenState {
    pub token_service: Arc<TokenService>,
    pub storage: Arc<Storage>,
}

pub async fn auth(
    State(state): State<TokenState>,
    mut req: Request<Body>,
    next: Next,
) -> Result<impl IntoResponse, StatusCode> {
    let mut headers = req
        .headers_mut()
        .iter()
        .filter_map(|(header_name, header_value)| {
            if header_name == http::header::AUTHORIZATION {
                Some(header_value)
            } else {
                None
            }
        });

    let header: Authorization<Bearer> = Authorization::decode(&mut headers)
        .map_err(|_| StatusCode::BAD_REQUEST)?;

    let token = header.token();

    let token_data = state.token_service.retrieve_token_claims(token)
        .map_err(|_| StatusCode::BAD_REQUEST)?;

    let user: User = sqlx::query_as("SELECT * FROM users WHERE email = ?")
        .bind(&token_data.claims.email)
        .fetch_one(state.storage.get_pool())
        .await
        .map_err(|_| StatusCode::NOT_FOUND)?;

    req.extensions_mut().insert(user);
    Ok(next.run(req).await)
}