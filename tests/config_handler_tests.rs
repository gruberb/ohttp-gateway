use axum::{body::to_bytes, extract::State, http::StatusCode};
use ohttp::KeyConfig;
use ohttp_gateway::{AppConfig, AppState, handlers::keys::get_ohttp_keys};

#[tokio::test]
async fn test_config_handler() {
    for (seed, cache_control) in [
        (None, "public, max-age=300"),
        (Some("42".repeat(32)), "public, max-age=86400"),
    ] {
        let config = AppConfig {
            seed_secret_key: seed,
            key_rotation_enabled: false,
            ..Default::default()
        };
        let state = AppState::new(config.clone()).await.unwrap();
        let response = get_ohttp_keys(State(state.clone())).await.unwrap();
        assert_eq!(state.metrics.key_requests_total.get(), 1.0);
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response.headers()["content-type"], "application/ohttp-keys");
        assert_eq!(response.headers()["cache-control"], cache_control);
        let body = to_bytes(response.into_body(), 1024).await.unwrap();
        assert_eq!(
            u16::from_be_bytes([body[0], body[1]]) as usize,
            body.len() - 2
        );
        KeyConfig::decode(&body[2..]).unwrap();
        assert_eq!(
            body.as_ref(),
            state.key_manager.get_encoded_config().await.unwrap()
        );

        if config.seed_secret_key.is_some() {
            let restarted = AppState::new(config).await.unwrap();
            assert_eq!(
                body.as_ref(),
                restarted.key_manager.get_encoded_config().await.unwrap()
            );
        }
    }
}
