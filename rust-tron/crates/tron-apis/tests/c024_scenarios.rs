use serde_json::{json,Value};
use tron_apis::{JsonRpcBackend,JsonRpcError,JsonRpcLimits,JsonRpcProcessor};

struct FamilyBackend;
impl JsonRpcBackend for FamilyBackend {fn execute(&self,method:&str,params:&Value)->Result<Value,JsonRpcError>{match method{"block"|"state"|"call"|"transaction"|"receipt"|"filter"=>Ok(json!({"family":method,"checkpoint":params})),"slow"=>Err(JsonRpcError::exceed_limit("lack of computing resources")),_=>Err(JsonRpcError::method_not_found())}}}
fn decode(bytes:&[u8])->Value{serde_json::from_slice(bytes).unwrap()}

#[test]
fn representative_every_method_family_and_no_accidental_surface() {
    let rpc=JsonRpcProcessor::new(FamilyBackend,JsonRpcLimits::default());
    for family in ["block","state","call","transaction","receipt","filter"] {let request=json!({"jsonrpc":"2.0","method":family,"params":[{"head":17,"solidity":15,"pbft":14}],"id":family});let response=rpc.handle_post(&serde_json::to_vec(&request).unwrap());assert_eq!(decode(&response.body)["result"]["family"],family);}
    let response=rpc.handle_post(br#"{"jsonrpc":"2.0","method":"eth_feeHistory","id":1}"#);assert_eq!(decode(&response.body)["error"]["code"],-32601);
}

#[test]
fn batch_notifications_errors_and_exact_schedule() {
    let rpc=JsonRpcProcessor::new(FamilyBackend,JsonRpcLimits::default());
    let response=rpc.handle_post(br#"[{"jsonrpc":"2.0","method":"block","params":[1],"id":1},{"jsonrpc":"2.0","method":"state","params":[2]},false,{"jsonrpc":"2.0","method":"missing","id":"x"}]"#);
    assert_eq!(decode(&response.body),json!([{"jsonrpc":"2.0","result":{"family":"block","checkpoint":[1]},"id":1},{"jsonrpc":"2.0","error":{"code":-32600,"message":"Invalid Request"},"id":null},{"jsonrpc":"2.0","error":{"code":-32601,"message":"Method not found"},"id":"x"}]));
}

#[test]
fn request_response_batch_token_and_depth_limits_are_controlled() {
    let rpc=JsonRpcProcessor::new(FamilyBackend,JsonRpcLimits{max_request_bytes:64,..Default::default()});
    assert_eq!(decode(&rpc.handle_post(&vec![b' ';65]).body)["error"]["code"],-32005);
    let rpc=JsonRpcProcessor::new(FamilyBackend,JsonRpcLimits{max_batch_size:1,..Default::default()});
    assert_eq!(decode(&rpc.handle_post(br#"[{"jsonrpc":"2.0","method":"block","id":1},{"jsonrpc":"2.0","method":"block","id":2}]"#).body)[0]["error"]["code"],-32005);
    let rpc=JsonRpcProcessor::new(FamilyBackend,JsonRpcLimits{max_nesting_depth:3,max_token_count:8,..Default::default()});
    assert_eq!(decode(&rpc.handle_post(br#"{"jsonrpc":"2.0","method":"block","params":[[[0]]],"id":1}"#).body)["error"]["code"],-32700);
}
