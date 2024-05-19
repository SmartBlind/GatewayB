use std::time::Duration;

use axum::body::{Body, to_bytes};
use axum::http;
use axum::http::{Request, StatusCode};
use tower::ServiceExt;

use lumisync_server::handles::region_handle::RegionBody;
use lumisync_server::handles::sensor_handle::SensorBody;
use lumisync_server::handles::user_handle::{UserLoginBody, UserRegisterBody};
use lumisync_server::handles::window_handle::WindowBody;

use crate::common::mock_app::MockApp;

mod common;

#[tokio::test]
async fn test_auth_middleware_with_header() {
    let mut app = MockApp::new().await;
    app = app.with_auth_middleware().await;

    let response = app.router
        .oneshot(
            Request::builder()
                .uri("/check")
                .header("Authorization", format!("Bearer {}", app.token))
                .body(Body::empty())
                .unwrap()
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    let res_body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let res_body_str = String::from_utf8(res_body.to_vec()).unwrap();

    assert!(res_body_str.contains(&app.admin.id.to_string()));
    assert!(res_body_str.contains(&app.admin.role.to_string()));
}

#[tokio::test]
async fn test_auth_middleware_with_query() {
    let mut app = MockApp::new().await;
    app = app.with_auth_middleware().await;

    let response = app.router
        .oneshot(
            Request::builder()
                .uri(format!("/check?token={}", app.token))
                .body(Body::empty())
                .unwrap()
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    let res_body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let res_body_str = String::from_utf8(res_body.to_vec()).unwrap();

    assert!(res_body_str.contains(&app.admin.id.to_string()));
    assert!(res_body_str.contains(&app.admin.role.to_string()));
}

#[tokio::test]
async fn test_auth_middleware_with_bad_token() {
    let mut app = MockApp::new().await;
    app = app.with_auth_middleware().await;

    let response = app.router
        .oneshot(
            Request::builder()
                .uri("/check")
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
    let mut app = MockApp::new().await;
    app = app.with_user_handle().await;
    let group = app.create_test_group().await;

    let req_body = serde_json::to_string(&UserRegisterBody {
        group: group.name,
        email: String::from("test@test.com"),
        password: String::from("test"),
        role: String::from("admin"),
    }).unwrap();

    let response = app.router
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
async fn test_user_authenticate_router() {
    let mut app = MockApp::new().await;
    app = app.with_user_handle().await;
    let group = app.create_test_group().await;
    let user = app.create_test_user().await;

    let req_body = serde_json::to_string(&UserLoginBody {
        email: user.email,
        password: String::from("test"),
    }).unwrap();

    let response = app.router
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
async fn test_user_authorize_router() {
    let mut app = MockApp::new().await;
    app = app.with_user_handle().await;
    let group = app.create_test_group().await;
    let user = app.create_test_user().await;

    tokio::time::sleep(Duration::from_secs(1)).await;

    let response = app.router
        .oneshot(
            Request::builder()
                .method(http::Method::GET)
                .uri("/authorize")
                .header("Authorization", format!("Bearer {}", app.token))
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
    assert_ne!(res_body_str, app.token);
}

#[tokio::test]
async fn test_region_create_router() {
    let mut app = MockApp::new().await;
    app = app.with_region_handle().await;
    app.create_test_group().await;
    app.create_test_user().await;

    let req_body = serde_json::to_string(&RegionBody {
        user_ids: vec![],
        name: String::from("Test Room"),
        light: 200,
        temperature: 25.0,
    }).unwrap();

    let response = app.router
        .oneshot(
            Request::builder()
                .method(http::Method::POST)
                .uri("/region")
                .header("Content-Type", "application/json")
                .header("Authorization", format!("Bearer {}", app.token))
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
    let mut app = MockApp::new().await;
    app = app.with_region_handle().await;
    app.create_test_group().await;
    app.create_test_user().await;
    let region = app.create_test_region().await;

    let response = app.router
        .oneshot(
            Request::builder()
                .method(http::Method::GET)
                .uri("/region")
                .header("Authorization", format!("Bearer {}", app.token))
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
    let mut app = MockApp::new().await;
    app = app.with_window_handle().await;
    app.create_test_group().await;
    app.create_test_user().await;
    let region = app.create_test_region().await;

    let req_body = serde_json::to_string(&WindowBody {
        region_id: region.id,
        name: String::from("Test Window"),
        state: 0.5,
    }).unwrap();

    let response = app.router
        .oneshot(
            Request::builder()
                .method(http::Method::POST)
                .uri("/window")
                .header("Content-Type", "application/json")
                .header("Authorization", format!("Bearer {}", app.token))
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
    let mut app = MockApp::new().await;
    app = app.with_window_handle().await;
    app.create_test_group().await;
    app.create_test_user().await;
    app.create_test_region().await;
    let window = app.create_test_window().await;

    let response = app.router
        .oneshot(
            Request::builder()
                .method(http::Method::GET)
                .uri("/window")
                .header("Authorization", format!("Bearer {}", app.token))
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
async fn test_window_get_by_region_router() {
    let mut app = MockApp::new().await;
    app = app.with_window_handle().await;
    app.create_test_group().await;
    app.create_test_user().await;
    let region = app.create_test_region().await;
    let window = app.create_test_window().await;

    let response = app.router
        .oneshot(
            Request::builder()
                .method(http::Method::GET)
                .uri(format!("/window/region/{}", region.id))
                .header("Authorization", format!("Bearer {}", app.token))
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
    let mut app = MockApp::new().await;
    app = app.with_window_handle().await;
    app.create_test_group().await;
    app.create_test_user().await;
    let region = app.create_test_region().await;
    let window = app.create_test_window().await;

    let req_body = serde_json::to_string(&WindowBody {
        region_id: region.id,
        name: String::from("Test Update Window"),
        state: 0.8,
    }).unwrap();

    let response = app.router
        .oneshot(
            Request::builder()
                .method(http::Method::PUT)
                .uri(format!("/window/{}", window.id))
                .header("Content-Type", "application/json")
                .header("Authorization", format!("Bearer {}", app.token))
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
    let mut app = MockApp::new().await;
    app = app.with_window_handle().await;
    app.create_test_group().await;
    app.create_test_user().await;
    app.create_test_region().await;
    let window = app.create_test_window().await;

    let response = app.router
        .oneshot(
            Request::builder()
                .method(http::Method::DELETE)
                .uri(format!("/window/{}", window.id))
                .header("Authorization", format!("Bearer {}", app.token))
                .body(Body::empty())
                .unwrap()
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn test_sensor_create_router() {
    let mut app = MockApp::new().await;
    app = app.with_sensor_handle().await;
    app.create_test_group().await;
    app.create_test_user().await;
    app.create_test_region().await;

    let req_body = serde_json::to_string(&SensorBody {
        region_id: 1,
        name: String::from("SENSOR-MOCK"),
    }).unwrap();

    let response = app.router
        .oneshot(
            Request::builder()
                .method(http::Method::POST)
                .uri("/sensor")
                .header("Content-Type", "application/json")
                .header("Authorization", format!("Bearer {}", app.token))
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
    let mut app = MockApp::new().await;
    app = app.with_sensor_handle().await;
    app.create_test_group().await;
    app.create_test_user().await;
    app.create_test_region().await;
    let sensor = app.create_test_sensor().await;

    let response = app.router
        .oneshot(
            Request::builder()
                .method(http::Method::GET)
                .uri("/sensor")
                .header("Content-Type", "application/json")
                .header("Authorization", format!("Bearer {}", app.token))
                .body(Body::empty())
                .unwrap()
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    let res_body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let res_body_str = String::from_utf8(res_body.to_vec()).unwrap();

    assert!(res_body_str.contains(&sensor.name));
}

#[tokio::test]
async fn test_sensor_get_by_region_router() {
    let mut app = MockApp::new().await;
    app = app.with_sensor_handle().await;
    app.create_test_group().await;
    app.create_test_user().await;
    let region = app.create_test_region().await;
    let sensor = app.create_test_sensor().await;

    let response = app.router
        .oneshot(
            Request::builder()
                .method(http::Method::GET)
                .uri(format!("/sensor/region/{}", region.id))
                .header("Authorization", format!("Bearer {}", app.token))
                .body(Body::empty())
                .unwrap()
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    let res_body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let res_body_str = String::from_utf8(res_body.to_vec()).unwrap();

    assert!(res_body_str.contains(&sensor.name));
}
