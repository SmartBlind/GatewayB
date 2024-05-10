use std::sync::Arc;

use axum::body::Body;
use axum::extract::State;
use axum::http::{header, Request, StatusCode};
use axum::middleware::Next;
use axum::response::IntoResponse;
use axum_extra::headers::{Authorization, Header};
use axum_extra::headers::authorization::Bearer;

use crate::configs::storage::Storage;
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
        .get_all(header::AUTHORIZATION)
        .iter();

    let header: Authorization<Bearer> = Authorization::decode(&mut headers)
        .map_err(|_| StatusCode::BAD_REQUEST)?;

    let token_data = state.token_service.retrieve_token_claims(header.token())
        .map_err(|_| StatusCode::UNAUTHORIZED)?;

    req.extensions_mut().insert(token_data.claims);

    Ok(next.run(req).await)
}
