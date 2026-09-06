use tron_apis::http_router::validate_address_json;

#[test]
fn validate_address_matches_java_formats_and_messages() {
    assert_eq!(
        validate_address_json("410000000000000000000000000000000000000000"),
        r#"{"result":true,"message":"Hex string format"}"#,
    );
    assert_eq!(
        validate_address_json("T9yD14Nj9j7xAB4dbGeiX9h8unkKHxuWwb"),
        r#"{"result":true,"message":"Base58check format"}"#,
    );
    assert_eq!(
        validate_address_json("QQAAAAAAAAAAAAAAAAAAAAAAAAAA"),
        r#"{"result":true,"message":"Base64 format"}"#,
    );
    assert_eq!(
        validate_address_json("invalid_address"),
        r#"{"result":false,"message":"Length error"}"#,
    );
    assert_eq!(
        validate_address_json("400000000000000000000000000000000000000000"),
        r#"{"result":false,"message":"Invalid address"}"#,
    );
}
