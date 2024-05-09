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

    req.extensions_mut().insert(token_data);

    Ok(next.run(req).await)
}

#[cfg(test)]
mod tests {
    use axum::{Extension, middleware, Router, routing};
    use axum::body::to_bytes;
    use jsonwebtoken::TokenData;
    use tower::ServiceExt;

    use crate::configs::settings::{Auth, Database};
    use crate::models::user::User;
    use crate::services::token_service::TokenClaims;

    use super::*;

    struct App {
        router: Router,
        token_service: Arc<TokenService>,
    }

    async fn create_test_app() -> App {
        let storage = Arc::new(Storage::new(Database {
            migrate: None,
            clean: false,
            url: String::from("sqlite::memory:"),
        }).await.unwrap());
        let token_service = Arc::new(TokenService::new(Auth {
            secret: String::from("test"),
            expiration: 1000,
        }));

        let app = Router::new()
            .route("/test", routing::get(
                |Extension(token_data): Extension<TokenData<TokenClaims>>| async move {
                    format!("{:?}", token_data.claims)
                })
            )
            .layer(middleware::from_fn_with_state(TokenState {
                token_service: token_service.clone(),
                storage,
            }, auth));

        App {
            router: app,
            token_service,
        }
    }

    #[tokio::test]
    async fn test_auth_middleware() {
        let app = create_test_app().await;

        let user = User {
            id: 1,
            group_id: 1,
            email: String::from("test@test.com"),
            password: String::from("test"),
            role: String::from("test"),
        };

        let token = app.token_service.generate_token(&user).unwrap();

        let response = app
            .router
            .oneshot(
                Request::builder()
                    .uri("/test")
                    .header("Authorization", format!("Bearer {}", token.token))
                    .body(Body::empty())
                    .unwrap()
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let res_body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let res_body_str = String::from_utf8(res_body.to_vec()).unwrap();

        assert!(res_body_str.contains(&user.email));
    }

    #[tokio::test]
    async fn test_auth_middleware_with_bad_token() {
        let app = create_test_app().await;

        let response = app
            .router
            .oneshot(
                Request::builder()
                    .uri("/test")
                    .header("Authorization", "Bearer bad_token")
                    .body(Body::empty())
                    .unwrap()
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }
}