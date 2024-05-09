use std::sync::Arc;

use axum::extract::State;
use axum::http::StatusCode;
use axum::Json;
use axum::response::IntoResponse;
use serde::{Deserialize, Serialize};

use crate::configs::storage::Storage;
use crate::models::user::{Role, User};
use crate::services::auth_service::AuthService;
use crate::services::token_service::TokenService;

#[derive(Serialize, Deserialize, Clone)]
pub struct UserRegisterBody {
    group: String,
    email: String,
    password: String,
    role: String,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct UserAuthBody {
    email: String,
    password: String,
}

#[derive(Clone)]
pub struct UserState {
    pub auth_service: Arc<AuthService>,
    pub token_service: Arc<TokenService>,
    pub storage: Arc<Storage>,
}

pub async fn create_user(
    State(state): State<UserState>,
    Json(body): Json<UserRegisterBody>,
) -> Result<impl IntoResponse, StatusCode> {
    let hash_password = state.auth_service.hash(&body.password)
        .map_err(|_| StatusCode::FORBIDDEN)?;

    let user = sqlx::query_as::<_, User>(
        r#"
        INSERT INTO users (group_id, email, password, role)
            VALUES ((SELECT id FROM groups WHERE name = $1), $2, $3, $4)
            RETURNING *;
        "#
    )
        .bind(&body.group)
        .bind(&body.email)
        .bind(&hash_password)
        .bind(Role::User.to_string())
        .fetch_one(state.storage.get_pool())
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let token_data = state.token_service.generate_token(&user)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    Ok(token_data.token)
}

pub async fn authenticate_user(
    State(state): State<UserState>,
    Json(body): Json<UserAuthBody>,
) -> Result<impl IntoResponse, StatusCode> {
    let user: User = sqlx::query_as("SELECT * FROM users WHERE email = $1")
        .bind(&body.email)
        .fetch_one(state.storage.get_pool())
        .await
        .map_err(|_| StatusCode::NOT_FOUND)?;

    let result = state.auth_service.verify(&user, &body.password)
        .map_err(|_| StatusCode::BAD_REQUEST)?;

    if result {
        let token_data = state.token_service.generate_token(&user)
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

        Ok(token_data.token)
    } else {
        Err(StatusCode::BAD_REQUEST)
    }
}

#[cfg(test)]
mod tests {
    use axum::{http, Router};
    use axum::body::{Body, to_bytes};
    use axum::http::Request;
    use axum::routing::post;
    use tower::ServiceExt;

    use crate::configs::settings::{Auth, Database};

    use super::*;

    struct App {
        router: Router,
        storage: Arc<Storage>,
        token_service: Arc<TokenService>,
    }

    async fn create_test_app() -> App {
        let storage = Arc::new(Storage::new(Database {
            migrate: None,
            clean: false,
            url: String::from("sqlite::memory:"),
        }).await.unwrap());
        storage.create_tables().await.unwrap();

        let auth_service = Arc::new(AuthService::new());
        let token_service = Arc::new(TokenService::new(Auth {
            secret: String::from("test"),
            expiration: 1000,
        }));

        let app = Router::new()
            .route("/register", post(create_user))
            .route("/auth", post(authenticate_user))
            .with_state(UserState {
                auth_service: auth_service.clone(),
                token_service: token_service.clone(),
                storage: storage.clone(),
            });

        App {
            router: app,
            storage,
            token_service
        }
    }

    #[tokio::test]
    async fn test_create_user() {
        let app = create_test_app().await;

        sqlx::query("INSERT INTO groups (name) VALUES ('sample')")
            .execute(app.storage.get_pool())
            .await
            .unwrap();

        let req_body = serde_json::to_string(&UserRegisterBody {
            group: String::from("sample"),
            email: String::from("test@test.com"),
            password: String::from("test"),
            role: String::from("admin"),
        }).unwrap();

        let response = app
            .router
            .oneshot(
                Request::builder()
                    .method(http::Method::POST)
                    .header("Content-Type", "application/json")
                    .uri("/register")
                    .body(Body::from(req_body))
                    .unwrap()
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let res_body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let res_body_str = String::from_utf8(res_body.to_vec()).unwrap();
        let claims = app
            .token_service
            .retrieve_token_claims(&res_body_str)
            .unwrap()
            .claims;

        assert_eq!(claims.email, String::from("test@test.com"));
    }

    #[tokio::test]
    async fn test_authenticate_user() {
        let app = create_test_app().await;

        sqlx::query(
            r#"
            INSERT INTO groups (name) VALUES ('sample');
            INSERT INTO users (group_id, email, password, role)
                VALUES (
                    1,
                    'test@test.com',
                    '$argon2id$v=19$m=19456,t=2,p=1$zk5JmuovvG7B6vyGGmLxDQ$qoqCpKkqrgoVjeTGa5ewrqFpuPUisTCDnEiPz6Dh/oc',
                    'admin'
                );
            "#
        )
            .execute(app.storage.get_pool())
            .await
            .unwrap();

        let req_body = serde_json::to_string(&UserAuthBody {
            email: String::from("test@test.com"),
            password: String::from("test"),
        }).unwrap();

        let response = app
            .router
            .oneshot(
                Request::builder()
                    .method(http::Method::POST)
                    .uri("/auth")
                    .header("Content-Type", "application/json")
                    .body(Body::from(req_body))
                    .unwrap()
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let res_body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let res_body_str = String::from_utf8(res_body.to_vec()).unwrap();
        let claims = app
            .token_service
            .retrieve_token_claims(&res_body_str)
            .unwrap()
            .claims;

        assert_eq!(claims.email, String::from("test@test.com"));
    }
}