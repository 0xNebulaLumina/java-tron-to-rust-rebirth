use prost::Message;
use serde_json::Value;
use tron_apis::http_json::{ProtobufJson, decode_broadcast_hex, int64_as_string, parse_post_body, with_get_int64_as_string};

const ADDRESS_HEX:&str="410000000000000000000000000000000000000000";
const ADDRESS_58:&str="T9yD14Nj9j7xAB4dbGeiX9h8unkKHxuWwb";

#[test]
fn descriptor_codec_matches_visible_byte_rules_and_int64_scope(){
    let codec=ProtobufJson::default();
    let json=format!(r#"{{"owner_address":"{ADDRESS_58}","to_address":"{ADDRESS_58}","amount":9007199254740993,"unknown":{{"deep":[1,null,],}},}}"#);
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

fn hex(bytes:&[u8])->String{bytes.iter().map(|v|format!("{v:02x}")).collect()}
