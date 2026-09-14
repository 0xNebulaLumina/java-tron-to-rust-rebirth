use prost::Message;
use serde_json::Value;
use tron_apis::http_json::{ProtobufJson, decode_broadcast_hex, int64_as_string, parse_post_body, with_get_int64_as_string};

const ADDRESS_HEX:&str="410000000000000000000000000000000000000000";
const ADDRESS_58:&str="T9yD14Nj9j7xAB4dbGeiX9h8unkKHxuWwb";

#[test]
fn descriptor_codec_matches_visible_byte_rules_and_int64_scope(){
    let codec=ProtobufJson::default();
    let json=format!(r#"{{"owner_address":"{ADDRESS_58}","to_address":"{ADDRESS_58}","amount":9007199254740993,"unknown":{{"deep":[1,null]}},}}"#);
    let message=codec.parse("protocol.TransferContract",&json,true).unwrap();
    let visible:Value=serde_json::from_str(&codec.print(&message,true).unwrap()).unwrap();
    assert_eq!(visible["owner_address"],ADDRESS_58); assert_eq!(visible["amount"],9007199254740993_i64);
    let hidden:Value=serde_json::from_str(&codec.print(&message,false).unwrap()).unwrap();
    assert_eq!(hidden["owner_address"],ADDRESS_HEX);
    with_get_int64_as_string("GET",true,||{assert!(int64_as_string());let printed:Value=serde_json::from_str(&codec.print(&message,true).unwrap()).unwrap();assert_eq!(printed["amount"],"9007199254740993");});
    assert!(!int64_as_string());
    with_get_int64_as_string("POST",true,||assert!(!int64_as_string()));
}

#[test]
fn transaction_any_permission_extra_data_and_broadcasthex(){
    let codec=ProtobufJson::default();
    let input=format!(r#"{{"Permission_id":7,"extra_data":"memo","raw_data":{{"contract":[{{"type":"TransferContract","parameter":{{"value":{{"owner_address":"{ADDRESS_58}","to_address":"{ADDRESS_58}","amount":1}}}}}}]}}}}"#);
    let transaction=codec.parse_transaction(&input,true).unwrap();
    let bytes=transaction.encode_to_vec(); assert!(!bytes.is_empty());
    let output:Value=serde_json::from_str(&codec.print(&transaction,true).unwrap()).unwrap();
    assert_eq!(output["raw_data"]["contract"][0]["Permission_id"],7);
    assert_eq!(output["raw_data"]["data"],"6d656d6f");
    assert_eq!(output["raw_data"]["contract"][0]["parameter"]["value"]["owner_address"],ADDRESS_58);
    assert_eq!(decode_broadcast_hex(&format!(r#"{{"transaction":"{}"}}"#,hex(&bytes))).unwrap(),bytes);
}

#[test]
fn form_null_repeated_trailing_and_errors(){
    let (json,visible)=parse_post_body(b"visible=true&owner_address=T9yD14Nj9j7xAB4dbGeiX9h8unkKHxuWwb&tag=a&tag=b",Some("application/x-www-form-urlencoded")).unwrap();
    let value:Value=serde_json::from_str(&json).unwrap();assert!(visible);assert_eq!(value["tag"],serde_json::json!(["a","b"]));
    let codec=ProtobufJson::default();
    assert!(codec.parse("protocol.TransferContract",r#"{"owner_address":null,"amount":1,}"#,false).is_ok());
    assert!(codec.parse("protocol.TransferContract",r#"{"owner_address":{}}"#,false).is_err());
    assert!(codec.parse("protocol.TransferContract",r#"{"owner_address":"xyz"}"#,false).is_err());
}

#[test]
fn json_format_unknown_fields_repeated_shapes_and_trailing_commas() {
    let codec = ProtobufJson::default();

    let hello = codec.parse(
        "protocol.HelloMessage",
        r#"{"zzz":{"a":1,"b":[true,false,null,{"c":"d"}],"e":{"f":2}},"address":"61646472657373"}"#,
        false,
    ).unwrap();
    let hello: Value = serde_json::from_str(&codec.print(&hello, false).unwrap()).unwrap();
    assert_eq!(hello["address"], "61646472657373");

    let proposal = codec.parse("protocol.Proposal", r#"{"approvals":["00","01",]}"#, false).unwrap();
    let proposal: Value = serde_json::from_str(&codec.print(&proposal, false).unwrap()).unwrap();
    assert_eq!(proposal["approvals"], serde_json::json!(["00", "01"]));
    assert!(codec.parse("protocol.Proposal", r#"{"approvals":[["00"]]}"#, false).is_err());
    assert!(codec.parse("protocol.Block", r#"{"transactions":[[]]}"#, false).is_err());
    assert!(codec.parse("protocol.Entry", r#"{"outputs":[null]}"#, false).is_err());

    let parsed = codec.parse(
        "protocol.HelloMessage",
        r#"{"genesisBlockId":{"hash":"00","number":1,},"address":"61646472657373",}"#,
        false,
    ).unwrap();
    let parsed: Value = serde_json::from_str(&codec.print(&parsed, false).unwrap()).unwrap();
    assert_eq!(parsed["genesisBlockId"]["number"], 1);

    assert!(codec.parse("protocol.HelloMessage", r#"{"zzz":{"a":1,}}"#, false).is_err());
    assert!(codec.parse("protocol.HelloMessage", r#"{"zzz":[1,]}"#, false).is_err());
}

#[test]
fn json_format_raw_nesting_limit_precedes_unknown_field_skipping() {
    let codec = ProtobufJson::default();
    assert!(codec.parse("protocol.HelloMessage", &unknown_nested_object(10), false).is_ok());

    for input in [unknown_nested_object(21), unknown_nested_array(21)] {
        let error = codec.parse("protocol.HelloMessage", &input, false).unwrap_err();
        assert!(error.0.contains("Hit recursion limit."), "{error}");
    }

    for input in [unknown_nested_object(100_000), unknown_nested_array(100_000)] {
        let error = codec.parse("protocol.HelloMessage", &input, false).unwrap_err();
        assert!(error.0.contains("Hit recursion limit."), "{error}");
    }
}

#[test]
fn json_mapper_raw_token_limit_is_enforced_before_unknown_field_skip() {
    let codec = ProtobufJson::default();

    // Jackson counts START_OBJECT, FIELD_NAME, START_ARRAY, END_ARRAY, and END_OBJECT,
    // leaving 99,995 scalar slots at its inclusive 100,000-token boundary.
    assert!(codec.parse("protocol.HelloMessage", &unknown_array_values(99_995), false).is_ok());

    let boundary_error = codec.parse(
        "protocol.HelloMessage",
        &unknown_array_values(99_996),
        false,
    ).unwrap_err();
    assert!(boundary_error.0.contains("Token count (100001) exceeds the maximum allowed (100000)."));

    let oversized_error = codec.parse(
        "protocol.HelloMessage",
        &unknown_array_values(100_500),
        false,
    ).unwrap_err();
    assert!(oversized_error.0.contains("exceeds the maximum allowed (100000)."));
}

#[test]
fn production_parser_case() {
    let codec = ProtobufJson::default();
    let transfer = format!(r#"{{"owner_address":"{ADDRESS_58}","to_address":"{ADDRESS_58}","amount":9007199254740993,"unknown":{{"array":[1,true,null]}}}}"#);
    let parsed = codec.parse("protocol.TransferContract", &transfer, true).unwrap();
    let visible: Value = serde_json::from_str(&codec.print(&parsed, true).unwrap()).unwrap();
    assert_eq!(visible["owner_address"], ADDRESS_58);
    assert_eq!(visible["amount"], 9_007_199_254_740_993_i64);
    let hidden: Value = serde_json::from_str(&codec.print(&parsed, false).unwrap()).unwrap();
    assert_eq!(hidden["owner_address"], ADDRESS_HEX);
    with_get_int64_as_string("GET", true, || {
        let quoted: Value = serde_json::from_str(&codec.print(&parsed, true).unwrap()).unwrap();
        assert_eq!(quoted["amount"], "9007199254740993");
    });
    let transaction = codec.parse_transaction(
        &format!(r#"{{"raw_data":{{"contract":[{{"type":"TransferContract","parameter":{{"value":{{"owner_address":"{ADDRESS_58}","to_address":"{ADDRESS_58}","amount":1}}}}}}]}}}}"#),
        true,
    ).unwrap();
    let transaction_json: Value = serde_json::from_str(&codec.print(&transaction, true).unwrap()).unwrap();
    assert_eq!(transaction_json["raw_data"]["contract"][0]["type"], "TransferContract");
    assert!(codec.parse("protocol.Proposal", r#"{"approvals":[["00"]]}"#, false).is_err());
    assert!(codec.parse("protocol.HelloMessage", &unknown_nested_object(21), false).is_err());
}

#[test]
fn production_parser_accepts_java_json_leniency_without_changing_results() {
    fn body(input: &str) -> Value {
        let (json, _) = parse_post_body(input.as_bytes(), Some("application/json")).unwrap();
        serde_json::from_str(&json).unwrap()
    }

    assert_eq!(body("{a:1}")["a"], 1);
    assert_eq!(body("{a:1, a:2 }")["a"], 2);
    assert_eq!(body("{a:2, a:1 }")["a"], 1);
    assert_eq!(body("{'a':'1'}")["a"], "1");

    let numbers = body("{'a':+1,b:-2,c:.3,d:-.4,e:+.5,f:+6.,h:007}");
    assert_eq!(numbers, serde_json::json!({"a":1,"b":-2,"c":0.3,"d":-0.4,"e":0.5,"f":6.0,"h":7}));
    assert_eq!(body("{'a':'line1\n\tline2'}")["a"], "line1\n\tline2");
    assert_eq!(body("{\"a\":\"\u{1}\"}")["a"], "\u{1}");
    assert_eq!(body("{\"a\":1} \n\t // this is a comment")["a"], 1);
    assert_eq!(body("{/* comment */\"a\":1}")["a"], 1);
    assert_eq!(body("{\"a\":1} /* trailing comment */")["a"], 1);
}

#[test]
fn production_parser_rejects_java_malformed_leniency_variants() {
    for input in [
        "{c:'NULL',,,,,,}", "[1,,2]", "{\"a\":NaN}", "[1, NaN, 2]",
        "{outer:{inner:NaN}}", "{b:Infinity}", "{c:-Infinity}", "[Infinity]",
        "{\"a\":\"\\q\"}", "{\"a\":1} {\"b\":2}", "{\"a\":1} garbage",
        "{a:abc}", "{a:TRUE}", "{a:FALSE}", "{\"a\":NULL}", "NULL",
    ] {
        assert!(parse_post_body(input.as_bytes(), Some("application/json")).is_err(), "accepted {input:?}");
    }
}

fn unknown_nested_object(depth: usize) -> String {
    let mut json = String::with_capacity(depth * 8 + 16);
    json.push('{');
    for _ in 0..depth { json.push_str("\"zzz\":{"); }
    json.push_str("\"leaf\":1");
    for _ in 0..depth { json.push('}'); }
    json.push('}');
    json
}

fn unknown_nested_array(depth: usize) -> String {
    let mut json = String::with_capacity(depth * 2 + 16);
    json.push_str("{\"zzz\":");
    json.extend(std::iter::repeat_n('[', depth));
    json.push('1');
    json.extend(std::iter::repeat_n(']', depth));
    json.push('}');
    json
}

fn unknown_array_values(values: usize) -> String {
    let mut json = String::with_capacity(values * 2 + 12);
    json.push_str("{\"zzz\":[");
    for index in 0..values {
        if index != 0 { json.push(','); }
        json.push('0');
    }
    json.push_str("]}");
    json
}

fn hex(bytes:&[u8])->String{bytes.iter().map(|v|format!("{v:02x}")).collect()}
