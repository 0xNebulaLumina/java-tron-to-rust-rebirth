use std::time::Duration;
use axum::{body::Body,http::StatusCode};
use http_body_util::BodyExt;
use tron_apis::{http_filters::{ConcurrentLimiter,HttpControls,PermitLimiter,collect_limited_body,disabled_api_response,lite_api_response,process_error,rate_limit_response,with_rate_permits},http_server::{HttpAbort,with_deadline}};

#[tokio::test]
async fn body_connection_and_rate_limits_release_permits(){
    assert!(collect_limited_body(Body::from("1234"),4).await.is_ok());
    let response=collect_limited_body(Body::from("12345"),4).await.unwrap_err(); assert_eq!(response.status(),StatusCode::PAYLOAD_TOO_LARGE);
    let endpoint=ConcurrentLimiter::new(1);let global=ConcurrentLimiter::new(1);
    let value=with_rate_permits(Some(&endpoint),&global,async{9}).await.unwrap();assert_eq!(value,9);assert_eq!(endpoint.available(),1);assert_eq!(global.available(),1);
    let held=endpoint.try_acquire().unwrap();assert!(with_rate_permits(Some(&endpoint),&global,async{}).await.is_err());drop(held);assert_eq!(global.available(),1);
}

#[tokio::test]
async fn disabled_lite_errors_and_path_normalization_match_java(){
    let controls=HttpControls::new(["getaccount".to_string()]);assert!(controls.is_disabled("/wallet/../wallet/getaccount"));assert!(!controls.is_disabled("/wallet/getblock"));
    let disabled=disabled_api_response();assert_eq!(disabled.status(),StatusCode::NOT_FOUND);assert_eq!(body(disabled).await,"{\"Error\":\"this API is unavailable due to config\"}\n");
    assert_eq!(body(lite_api_response()).await,"this API is closed because this node is a lite fullnode");
    assert_eq!(body(process_error("class java.lang.IllegalArgumentException","bad input")).await,"{\"Error\":\"class java.lang.IllegalArgumentException : bad input\"}\n");
}

#[tokio::test]
async fn async_limiter_failures_keep_java_http_shape(){
    let exhausted=rate_limit_response(&tonic::Status::resource_exhausted("endpoint"));
    assert_eq!(body(exhausted).await,"{\"Error\":\"class java.lang.IllegalAccessException : lack of computing resources\"}\n");
    let deadline=rate_limit_response(&tonic::Status::deadline_exceeded("endpoint"));
    assert_eq!(body(deadline).await,"{\"Error\":\"java.util.concurrent.TimeoutException : lack of computing resources\"}\n");
}

#[tokio::test]
async fn deadline_and_cancellation_are_mandatory(){
    assert_eq!(with_deadline(Duration::from_millis(1),std::future::pending(),async{tokio::time::sleep(Duration::from_millis(20)).await}).await,Err(HttpAbort::Deadline));
    assert_eq!(with_deadline(Duration::from_secs(1),async{},std::future::pending::<()>()).await,Err(HttpAbort::Cancelled));
}

async fn body(response:axum::http::Response<Body>)->String{String::from_utf8(response.into_body().collect().await.unwrap().to_bytes().to_vec()).unwrap()}
