use std::time::Duration;

use axum::{Extension, http, middleware, Router};
use axum::body::{Body, to_bytes};
use axum::http::{Request, StatusCode};
use axum::routing::{delete, get, post, put};
use tower::ServiceExt;

use lumisync_server::handles::region_handle::{create_region, get_regions, RegionBody, RegionState};
use lumisync_server::handles::sensor_handle::{create_sensor, get_sensors, SensorBody, SensorState};
use lumisync_server::handles::user_handle::{authenticate_user, authorize_user, create_user, UserLoginBody, UserRegisterBody, UserState};
use lumisync_server::handles::window_handle::{create_window, delete_window, get_windows, update_window, WindowBody, WindowState};
use lumisync_server::middlewares::auth_middleware::{auth, TokenState};
use lumisync_server::models::user::User;
use lumisync_server::services::token_service::TokenClaims;

use crate::common::mock_app::MockApp;

mod common;

#[tokio::test]
async fn test_auth_middleware() {
    let app = MockApp::new().await;

    let test_router = Router::new()
        .route("/test", get(
            |Extension(token_data): Extension<TokenClaims>| async move {
                format!("{:?}", token_data)
            }),
        )
        .route_layer(middleware::from_fn_with_state(TokenState {
            token_service: app.token_service.clone(),
            storage: app.storage.clone(),
        }, auth));

    let user = User {
        id: 1,
        group_id: 1,
        email: String::from("test@test.com"),
        password: String::from("test"),
        role: String::from("test"),
    };

    let token = app.token_service.generate_token(user.to_owned()).unwrap();

    let response = test_router
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

    assert!(res_body_str.contains(&user.id.to_string()));
    assert!(res_body_str.contains(&user.role.to_string()));
}

#[tokio::test]
async fn test_auth_middleware_with_bad_token() {
    let app = MockApp::new().await;

    let test_router = Router::new()
        .route("/test", get(
            |Extension(token_data): Extension<TokenClaims>| async move {
                format!("{:?}", token_data)
            }),
        )
        .route_layer(middleware::from_fn_with_state(TokenState {
            token_service: app.token_service.clone(),
            storage: app.storage.clone(),
        }, auth));

    let response = test_router
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

#[tokio::test]
async fn test_user_register_router() {
    let app = MockApp::new().await;
    let group = app.create_test_group().await;

    let user_router = Router::new()
        .route("/register", post(create_user))
        .with_state(UserState {
            auth_service: app.auth_service.clone(),
            token_service: app.token_service.clone(),
            storage: app.storage.clone(),
        });

    let req_body = serde_json::to_string(&UserRegisterBody {
        group: group.name,
        email: String::from("test@test.com"),
        password: String::from("test"),
        role: String::from("admin"),
    }).unwrap();

    let response = user_router
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

    assert_eq!(claims.sub, 1);
    assert_eq!(claims.group_id, group.id);
    assert_eq!(claims.role, "admin");
}

#[tokio::test]
async fn test_user_authorize_router() {
    let app = MockApp::new().await;
    let group = app.create_test_group().await;
    let user = app.create_test_user().await;

    let user_router = Router::new()
        .route("/authorize", get(authorize_user))
        .route_layer(middleware::from_fn_with_state(TokenState {
            token_service: app.token_service.clone(),
            storage: app.storage.clone(),
        }, auth))
        .with_state(UserState {
            auth_service: app.auth_service.clone(),
            token_service: app.token_service.clone(),
            storage: app.storage.clone(),
        });

    let token = app.token_service.generate_token(user.to_owned()).unwrap();

    tokio::time::sleep(Duration::from_secs(1)).await;

    let response = user_router
        .oneshot(
            Request::builder()
                .method(http::Method::GET)
                .uri("/authorize")
                .header("Authorization", format!("Bearer {}", token.token))
                .body(Body::empty())
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

    assert_eq!(claims.sub, user.id);
    assert_eq!(claims.group_id, group.id);
    assert_eq!(claims.role, user.role);
    assert_ne!(res_body_str, token.token);
}

#[tokio::test]
async fn test_user_authenticate_router() {
    let app = MockApp::new().await;
    let group = app.create_test_group().await;
    let user = app.create_test_user().await;

    let user_router = Router::new()
        .route("/authenticate", post(authenticate_user))
        .with_state(UserState {
            auth_service: app.auth_service.clone(),
            token_service: app.token_service.clone(),
            storage: app.storage.clone(),
        });

    let req_body = serde_json::to_string(&UserLoginBody {
        email: user.email,
        password: String::from("test"),
    }).unwrap();

    let response = user_router
        .oneshot(
            Request::builder()
                .method(http::Method::POST)
                .uri("/authenticate")
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

    assert_eq!(claims.sub, user.id);
    assert_eq!(claims.group_id, group.id);
    assert_eq!(claims.role, user.role);
}

#[tokio::test]
async fn test_region_create_router() {
    let app = MockApp::new().await;
    app.create_test_group().await;
    let user = app.create_test_user().await;

    let region_router = Router::new()
        .route("/region", post(create_region))
        .route_layer(middleware::from_fn_with_state(TokenState {
            token_service: app.token_service.clone(),
            storage: app.storage.clone(),
        }, auth))
        .with_state(RegionState {
            storage: app.storage.clone(),
        });

    let token = app.token_service.generate_token(user.to_owned()).unwrap();

    let req_body = serde_json::to_string(&RegionBody {
        user_ids: vec![],
        name: String::from("Test Room"),
        light: 100,
        temperature: 25.0,
    }).unwrap();

    let response = region_router
        .oneshot(
            Request::builder()
                .method(http::Method::POST)
                .uri("/region")
                .header("Content-Type", "application/json")
                .header("Authorization", format!("Bearer {}", token.token))
                .body(Body::from(req_body))
                .unwrap()
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    let res_body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let res_body_str = String::from_utf8(res_body.to_vec()).unwrap();

    assert!(res_body_str.contains("Test Room"));
}

#[tokio::test]
async fn test_region_get_router() {
    let app = MockApp::new().await;
    app.create_test_group().await;
    let user = app.create_test_user().await;
    let region = app.create_test_region().await;

    let region_router = Router::new()
        .route("/region", get(get_regions))
        .route_layer(middleware::from_fn_with_state(TokenState {
            token_service: app.token_service.clone(),
            storage: app.storage.clone(),
        }, auth))
        .with_state(RegionState {
            storage: app.storage.clone(),
        });

    let token = app.token_service.generate_token(user.to_owned()).unwrap();

    let response = region_router
        .oneshot(
            Request::builder()
                .method(http::Method::GET)
                .uri("/region")
                .header("Authorization", format!("Bearer {}", token.token))
                .body(Body::empty())
                .unwrap()
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    let res_body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let res_body_str = String::from_utf8(res_body.to_vec()).unwrap();

    assert!(res_body_str.contains(&region.name));
}

#[tokio::test]
async fn test_window_create_router() {
    let app = MockApp::new().await;
    app.create_test_group().await;
    let user = app.create_test_user().await;
    let region = app.create_test_region().await;

    let window_router = Router::new()
        .route("/window", post(create_window))
        .with_state(WindowState {
            actuator_service: None,
            storage: app.storage.clone(),
        })
        .layer(middleware::from_fn_with_state(TokenState {
            token_service: app.token_service.clone(),
            storage: app.storage.clone(),
        }, auth));

    let token = app.token_service.generate_token(user.to_owned()).unwrap();

    let req_body = serde_json::to_string(&WindowBody {
        region_id: region.id,
        name: String::from("Test Window"),
        state: 0.5,
    }).unwrap();

    let response = window_router
        .oneshot(
            Request::builder()
                .method(http::Method::POST)
                .uri("/window")
                .header("Content-Type", "application/json")
                .header("Authorization", format!("Bearer {}", token.token))
                .body(Body::from(req_body))
                .unwrap()
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    let res_body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let res_body_str = String::from_utf8(res_body.to_vec()).unwrap();

    assert!(res_body_str.contains("Test Window"));
}

#[tokio::test]
async fn test_window_get_router() {
    let app = MockApp::new().await;
    app.create_test_group().await;
    let user = app.create_test_user().await;
    app.create_test_region().await;
    let window = app.create_test_window().await;

    let window_router = Router::new()
        .route("/window", get(get_windows))
        .with_state(WindowState {
            actuator_service: None,
            storage: app.storage.clone(),
        })
        .layer(middleware::from_fn_with_state(TokenState {
            token_service: app.token_service.clone(),
            storage: app.storage.clone(),
        }, auth));

    let token = app.token_service.generate_token(user.to_owned()).unwrap();

    let response = window_router
        .oneshot(
            Request::builder()
                .method(http::Method::GET)
                .uri("/window")
                .header("Authorization", format!("Bearer {}", token.token))
                .body(Body::empty())
                .unwrap()
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    let res_body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let res_body_str = String::from_utf8(res_body.to_vec()).unwrap();

    assert!(res_body_str.contains(&window.name));
}

#[tokio::test]
async fn test_window_update_router() {
    let app = MockApp::new().await;
    app.create_test_group().await;
    let user = app.create_test_user().await;
    let region = app.create_test_region().await;
    let window = app.create_test_window().await;

    let window_router = Router::new()
        .route("/window/:window_id", put(update_window))
        .with_state(WindowState {
            actuator_service: None,
            storage: app.storage.clone(),
        })
        .layer(middleware::from_fn_with_state(TokenState {
            token_service: app.token_service.clone(),
            storage: app.storage.clone(),
        }, auth));

    let token = app.token_service.generate_token(user.to_owned()).unwrap();

    let req_body = serde_json::to_string(&WindowBody {
        region_id: region.id,
        name: String::from("Test Update Window"),
        state: 0.8,
    }).unwrap();

    let response = window_router
        .oneshot(
            Request::builder()
                .method(http::Method::PUT)
                .uri(format!("/window/{}", window.id))
                .header("Content-Type", "application/json")
                .header("Authorization", format!("Bearer {}", token.token))
                .body(Body::from(req_body))
                .unwrap()
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    let res_body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let res_body_str = String::from_utf8(res_body.to_vec()).unwrap();

    assert!(res_body_str.contains("Test Update Window"));
}

#[tokio::test]
async fn test_window_delete_router() {
    let app = MockApp::new().await;
    app.create_test_group().await;
    let user = app.create_test_user().await;
    app.create_test_region().await;
    let window = app.create_test_window().await;

    let window_router = Router::new()
        .route("/window/:window_id", delete(delete_window))
        .with_state(WindowState {
            actuator_service: None,
            storage: app.storage.clone(),
        })
        .layer(middleware::from_fn_with_state(TokenState {
            token_service: app.token_service.clone(),
            storage: app.storage.clone(),
        }, auth));

    let token = app.token_service.generate_token(user.to_owned()).unwrap();

    let response = window_router
        .oneshot(
            Request::builder()
                .method(http::Method::DELETE)
                .uri(format!("/window/{}", window.id))
                .header("Authorization", format!("Bearer {}", token.token))
                .body(Body::empty())
                .unwrap()
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn test_sensor_create_router() {
    let app = MockApp::new().await;
    app.create_test_group().await;
    let user = app.create_test_user().await;
    app.create_test_region().await;
    app.create_test_window().await;

    let sensor_router = Router::new()
        .route("/sensor", post(create_sensor))
        .with_state(SensorState {
            storage: app.storage.clone(),
        })
        .layer(middleware::from_fn_with_state(TokenState {
            token_service: app.token_service.clone(),
            storage: app.storage.clone(),
        }, auth));

    let token = app.token_service.generate_token(user.to_owned()).unwrap();

    let req_body = serde_json::to_string(&SensorBody {
        region_id: 1,
        name: String::from("SENSOR-MOCK"),
    }).unwrap();

    let response = sensor_router
        .oneshot(
            Request::builder()
                .method(http::Method::POST)
                .uri("/sensor")
                .header("Content-Type", "application/json")
                .header("Authorization", format!("Bearer {}", token.token))
                .body(Body::from(req_body))
                .unwrap()
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    let res_body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let res_body_str = String::from_utf8(res_body.to_vec()).unwrap();

    assert!(res_body_str.contains("SENSOR-MOCK"));
}

#[tokio::test]
async fn test_sensor_get_router() {
    let app = MockApp::new().await;
    app.create_test_group().await;
    let user = app.create_test_user().await;
    app.create_test_region().await;
    app.create_test_window().await;
    app.create_test_sensor().await;

    let sensor_router = Router::new()
        .route("/sensor", get(get_sensors))
        .with_state(SensorState {
            storage: app.storage.clone(),
        })
        .layer(middleware::from_fn_with_state(TokenState {
            token_service: app.token_service.clone(),
            storage: app.storage.clone(),
        }, auth));

    let token = app.token_service.generate_token(user.to_owned()).unwrap();

    let response = sensor_router
        .oneshot(
            Request::builder()
                .method(http::Method::GET)
                .uri("/sensor")
                .header("Content-Type", "application/json")
                .header("Authorization", format!("Bearer {}", token.token))
                .body(Body::empty())
                .unwrap()
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
}
