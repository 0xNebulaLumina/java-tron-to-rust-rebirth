use std::{cell::Cell, collections::BTreeMap, fmt};

use prost::Message;
use prost_reflect::{DescriptorPool, DynamicMessage, FieldDescriptor, Kind, MapKey, MessageDescriptor, ReflectMessage, Value as ProtoValue};
use serde_json::{Map, Number, Value};
use tron_crypto::{decode_base58check, encode_base58check, CryptoEngine};
use tron_protocol::FILE_DESCRIPTOR_SET;

thread_local! { static INT64_AS_STRING: Cell<bool> = const { Cell::new(false) }; }

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct JsonError(pub String);
impl fmt::Display for JsonError { fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { f.write_str(&self.0) } }
impl std::error::Error for JsonError {}

#[derive(Clone)]
pub struct ProtobufJson {
    pool: DescriptorPool,
    engine: CryptoEngine,
}

impl Default for ProtobufJson {
    fn default() -> Self { Self::new(CryptoEngine::Secp256k1) }
}

impl ProtobufJson {
    #[must_use]
    pub fn new(engine: CryptoEngine) -> Self {
        Self { pool: DescriptorPool::decode(FILE_DESCRIPTOR_SET).expect("canonical descriptor set"), engine }
    }

    pub fn parse(&self, message_name: &str, input: &str, visible: bool) -> Result<DynamicMessage, JsonError> {
        let descriptor = self.pool.get_message_by_name(message_name)
            .ok_or_else(|| JsonError(format!("unknown message type: {message_name}")))?;
        validate_unknown_field_commas(input, &descriptor)?;
        let value = parse_lenient_json(input)?;
        self.parse_value(&descriptor, &value, visible)
    }

    pub fn parse_transaction(&self, input: &str, visible: bool) -> Result<DynamicMessage, JsonError> {
        let descriptor = self.pool.get_message_by_name("protocol.Transaction")
            .ok_or_else(|| JsonError("unknown message type: protocol.Transaction".into()))?;
        validate_unknown_field_commas(input, &descriptor)?;
        let mut value = parse_lenient_json(input)?;
        normalize_transaction_json(&mut value, visible);
        self.parse_value(&descriptor, &value, visible)
    }

    pub fn print(&self, message: &DynamicMessage, visible: bool) -> Result<String, JsonError> {
        serde_json::to_string(&self.message_json(message, visible)?)
            .map_err(|error| JsonError(error.to_string()))
    }

    pub fn print_pretty(&self, message: &DynamicMessage, visible: bool) -> Result<String, JsonError> {
        serde_json::to_string_pretty(&self.message_json(message, visible)?)
            .map_err(|error| JsonError(error.to_string()))
    }

    pub fn decode(&self, message_name: &str, bytes: &[u8]) -> Result<DynamicMessage, JsonError> {
        let descriptor = self.pool.get_message_by_name(message_name)
            .ok_or_else(|| JsonError(format!("unknown message type: {message_name}")))?;
        DynamicMessage::decode(descriptor, bytes).map_err(|error| JsonError(error.to_string()))
    }

    fn parse_value(&self, descriptor: &MessageDescriptor, value: &Value, visible: bool) -> Result<DynamicMessage, JsonError> {
        let object = value.as_object().ok_or_else(|| JsonError(format!("Expected object for {}.", descriptor.full_name())))?;
        let mut message = DynamicMessage::new(descriptor.clone());
        for (name, json) in object {
            if json.is_null() || name == "visible" || name == "txID" || name == "raw_data_hex" { continue; }
            let Some(field) = descriptor.get_field_by_name(name) else { continue; };
            let parsed = self.parse_field(&field, json, visible)?;
            message.set_field(&field, parsed);
        }
        Ok(message)
    }

    fn parse_field(&self, field: &FieldDescriptor, json: &Value, visible: bool) -> Result<ProtoValue, JsonError> {
        if field.is_list() {
            let values = json.as_array().ok_or_else(|| JsonError(format!("Expected array for {}.", field.full_name())))?;
            return values.iter().filter_map(|value| {
                if value.is_null() && !matches!(field.kind(), Kind::Message(_)) { None }
                else { Some(self.parse_scalar(field, value, visible)) }
            }).collect::<Result<Vec<_>, _>>().map(ProtoValue::List);
        }
        if field.is_map() {
            let object = json.as_object().ok_or_else(|| JsonError(format!("Expected object for {}.", field.full_name())))?;
            let kind = field.kind();
            let entry = kind.as_message().expect("map entry");
            let key_field = entry.get_field_by_name("key").expect("map key");
            let value_field = entry.get_field_by_name("value").expect("map value");
            let mut map = std::collections::HashMap::new();
            for (key, value) in object {
                let key = parse_map_key(&key_field, key)?;
                map.insert(key, self.parse_scalar(&value_field, value, visible)?);
            }
            return Ok(ProtoValue::Map(map));
        }
        self.parse_scalar(field, json, visible)
    }

    fn parse_scalar(&self, field: &FieldDescriptor, json: &Value, visible: bool) -> Result<ProtoValue, JsonError> {
        let error = || JsonError(format!("Invalid value for {}.", field.full_name()));
        Ok(match field.kind() {
            Kind::Bool => ProtoValue::Bool(json.as_bool().ok_or_else(error)?),
            Kind::Int32 | Kind::Sint32 | Kind::Sfixed32 => ProtoValue::I32(integer(json).and_then(|v| i32::try_from(v).ok()).ok_or_else(error)?),
            Kind::Int64 | Kind::Sint64 | Kind::Sfixed64 => ProtoValue::I64(integer(json).ok_or_else(error)?),
            Kind::Uint32 | Kind::Fixed32 => ProtoValue::U32(unsigned(json).and_then(|v| u32::try_from(v).ok()).ok_or_else(error)?),
            Kind::Uint64 | Kind::Fixed64 => ProtoValue::U64(unsigned(json).ok_or_else(error)?),
            Kind::Float => ProtoValue::F32(float(json).ok_or_else(error)? as f32),
            Kind::Double => ProtoValue::F64(float(json).ok_or_else(error)?),
            Kind::String => ProtoValue::String(json.as_str().ok_or_else(error)?.to_owned()),
            Kind::Bytes => {
                let text = json.as_str().ok_or_else(error)?;
                ProtoValue::Bytes(self.decode_bytes(field.full_name(), text, visible)?.into())
            }
            Kind::Enum(enumeration) => {
                let number = if let Some(number) = json.as_i64() { i32::try_from(number).ok() }
                    else { json.as_str().and_then(|name| enumeration.get_value_by_name(name).or_else(|| {
                        let mut chars = name.chars(); let first = chars.next()?.to_uppercase().collect::<String>();
                        enumeration.get_value_by_name(&(first + chars.as_str()))
                    })).map(|value| value.number()) };
                ProtoValue::EnumNumber(number.ok_or_else(error)?)
            }
            Kind::Message(descriptor) => {
                if descriptor.full_name() == "google.protobuf.Any" { ProtoValue::Message(self.parse_any(json, visible)?) }
                else { ProtoValue::Message(self.parse_value(&descriptor, json, visible)?) }
            }
        })
    }

    fn parse_any(&self, json: &Value, visible: bool) -> Result<DynamicMessage, JsonError> {
        let object = json.as_object().ok_or_else(|| JsonError("Expected object for google.protobuf.Any.".into()))?;
        let type_url = object.get("type_url").and_then(Value::as_str).ok_or_else(|| JsonError("Any type_url is required.".into()))?;
        let name = type_url.rsplit('/').next().unwrap_or(type_url);
        let descriptor = self.pool.get_message_by_name(name).or_else(|| self.pool.get_message_by_name(&format!("protocol.{name}")))
            .ok_or_else(|| JsonError(format!("unknown Any type: {name}")))?;
        let payload_json = object.get("value").ok_or_else(|| JsonError("Any value is required.".into()))?;
        let payload = if let Some(hex) = payload_json.as_str() { decode_hex(hex)? }
            else { self.parse_value(&descriptor, payload_json, visible)?.encode_to_vec() };
        let any_descriptor = self.pool.get_message_by_name("google.protobuf.Any").expect("Any descriptor");
        let mut any = DynamicMessage::new(any_descriptor);
        any.set_field_by_name("type_url", ProtoValue::String(type_url.to_owned()));
        any.set_field_by_name("value", ProtoValue::Bytes(payload.into()));
        Ok(any)
    }

    fn message_json(&self, message: &DynamicMessage, visible: bool) -> Result<Value, JsonError> {
        let mut object = Map::new();
        for field in message.descriptor().fields() {
            if !message.has_field(&field) { continue; }
            let value = message.get_field(&field);
            object.insert(field.name().to_owned(), self.value_json(&field, value.as_ref(), visible)?);
        }
        Ok(Value::Object(object))
    }

    fn value_json(&self, field: &FieldDescriptor, value: &ProtoValue, visible: bool) -> Result<Value, JsonError> {
        if let ProtoValue::List(values) = value { return Ok(Value::Array(values.iter().map(|v| self.scalar_json(field, v, visible)).collect::<Result<_,_>>()?)); }
        if let ProtoValue::Map(values) = value {
            let kind = field.kind();
            let entry = kind.as_message().expect("map entry");
            let value_field = entry.get_field_by_name("value").expect("map value");
            let mut ordered = BTreeMap::new();
            for (key, value) in values { ordered.insert(map_key_string(key), self.scalar_json(&value_field, value, visible)?); }
            return Ok(Value::Object(ordered.into_iter().collect()));
        }
        self.scalar_json(field, value, visible)
    }

    fn scalar_json(&self, field: &FieldDescriptor, value: &ProtoValue, visible: bool) -> Result<Value, JsonError> {
        Ok(match value {
            ProtoValue::Bool(v) => Value::Bool(*v),
            ProtoValue::I32(v) => Value::Number((*v).into()), ProtoValue::U32(v) => Value::Number((*v).into()),
            ProtoValue::I64(v) => int64_json(v.to_string(), *v), ProtoValue::U64(v) => uint64_json(v.to_string(), *v),
            ProtoValue::F32(v) => number(*v as f64)?, ProtoValue::F64(v) => number(*v)?,
            ProtoValue::String(v) => Value::String(v.clone()),
            ProtoValue::Bytes(v) => Value::String(self.encode_bytes(field.full_name(), v, visible)),
            ProtoValue::EnumNumber(number) => Value::String(field.kind().as_enum().and_then(|e| e.get_value(*number)).map(|v| v.name().to_owned()).unwrap_or_else(|| number.to_string())),
            ProtoValue::Message(message) => {
                if message.descriptor().full_name() == "google.protobuf.Any" { self.any_json(message, visible)? }
                else { self.message_json(message, visible)? }
            }
            ProtoValue::List(_) | ProtoValue::Map(_) => return Err(JsonError("nested collection value".into())),
        })
    }

    fn any_json(&self, any: &DynamicMessage, visible: bool) -> Result<Value, JsonError> {
        let type_url = any.get_field_by_name("type_url").and_then(|v| v.as_str().map(str::to_owned)).unwrap_or_default();
        let bytes = any.get_field_by_name("value").and_then(|v| v.as_bytes().map(|b| b.to_vec())).unwrap_or_default();
        let name = type_url.rsplit('/').next().unwrap_or(&type_url);
        let value = if let Some(descriptor) = self.pool.get_message_by_name(name).or_else(|| self.pool.get_message_by_name(&format!("protocol.{name}"))) {
            self.message_json(&DynamicMessage::decode(descriptor, bytes.as_slice()).map_err(|e| JsonError(e.to_string()))?, visible)?
        } else { Value::String(hex_encode(&bytes)) };
        Ok(Value::Object(Map::from_iter([("type_url".into(), Value::String(type_url)), ("value".into(), value)])))
    }

    fn decode_bytes(&self, field: &str, text: &str, visible: bool) -> Result<Vec<u8>, JsonError> {
        if visible && is_address_field(field) { return decode_base58check(self.engine, text).map_err(|_| JsonError(format!("invalid address for field: {field}"))); }
        if visible && is_name_field(field) { return Ok(text.as_bytes().to_vec()); }
        decode_hex(text)
    }
    fn encode_bytes(&self, field: &str, bytes: &[u8], visible: bool) -> String {
        if visible && is_address_field(field) { return encode_base58check(self.engine, bytes); }
        if visible && is_name_field(field) { return std::str::from_utf8(bytes).map(str::to_owned).unwrap_or_else(|_| hex_encode(bytes)); }
        hex_encode(bytes)
    }
}

pub struct Int64AsStringGuard { previous: bool }
impl Int64AsStringGuard { #[must_use] pub fn enter(enabled: bool) -> Self { let previous = INT64_AS_STRING.replace(enabled); Self { previous } } }
impl Drop for Int64AsStringGuard { fn drop(&mut self) { INT64_AS_STRING.set(self.previous); } }
#[must_use] pub fn int64_as_string() -> bool { INT64_AS_STRING.get() }

pub fn with_get_int64_as_string<T>(method: &str, enabled: bool, action: impl FnOnce() -> T) -> T {
    let _guard = Int64AsStringGuard::enter(method.eq_ignore_ascii_case("GET") && enabled);
    action()
}

pub fn parse_post_body(body: &[u8], content_type: Option<&str>) -> Result<(String, bool), JsonError> {
    let text = std::str::from_utf8(body).map_err(|e| JsonError(e.to_string()))?;
    let json = if content_type.map(|v| v.split(';').next().unwrap_or(v).trim().eq_ignore_ascii_case("application/x-www-form-urlencoded")).unwrap_or(false) && serde_json::from_str::<Value>(text).is_err() {
        let mut object = Map::new();
        for pair in text.split('&').filter(|v| !v.is_empty()) {
            let (key, value) = pair.split_once('=').unwrap_or((pair, ""));
            let key = percent_decode(key)?; let value = Value::String(percent_decode(value)?);
            match object.get_mut(&key) { Some(Value::Array(values)) => values.push(value), Some(existing) => { let old = std::mem::replace(existing, Value::Null); *existing = Value::Array(vec![old, value]); }, None => { object.insert(key, value); } }
        }
        Value::Object(object)
    } else { parse_lenient_json(text)? };
    let visible = json.get("visible").and_then(|v| if let Some(v)=v.as_bool(){Some(v)}else{v.as_str().map(|s| s.eq_ignore_ascii_case("true"))}).unwrap_or(false);
    Ok((serde_json::to_string(&json).map_err(|e| JsonError(e.to_string()))?, visible))
}

pub fn decode_broadcast_hex(input: &str) -> Result<Vec<u8>, JsonError> {
    let json = parse_lenient_json(input)?;
    decode_hex(json.get("transaction").and_then(Value::as_str).ok_or_else(|| JsonError("transaction is required".into()))?)
}

fn normalize_transaction_json(value: &mut Value, visible: bool) {
    let Some(root) = value.as_object_mut() else { return; };
    if let Some(extra) = root.remove("extra_data") {
        if let Some(raw)=root.get_mut("raw_data").and_then(Value::as_object_mut) {
            let extra=if visible { Value::String(hex_encode(extra.as_str().unwrap_or_default().as_bytes())) } else { extra };
            raw.insert("data".into(), extra);
        }
    }
    let top_permission = root.remove("Permission_id");
    let Some(contracts) = root.get_mut("raw_data").and_then(Value::as_object_mut).and_then(|r| r.get_mut("contract")).and_then(Value::as_array_mut) else { return; };
    if let (Some(permission), Some(first)) = (top_permission, contracts.first_mut().and_then(Value::as_object_mut)) { first.insert("Permission_id".into(), permission); }
    for contract in contracts {
        let Some(object)=contract.as_object_mut() else { continue; };
        if let Some(permission)=object.remove("permission_id") { object.insert("Permission_id".into(), permission); }
        let Some(kind)=object.get("type").and_then(Value::as_str).map(str::to_owned) else { continue; };
        if let Some(parameter)=object.get_mut("parameter").and_then(Value::as_object_mut) { parameter.entry("type_url").or_insert_with(|| Value::String(format!("type.googleapis.com/protocol.{kind}"))); }
    }
}


const MAX_PROTOBUF_JSON_NESTING: usize = 20;
const MAX_PROTOBUF_JSON_TOKENS: usize = 100_000;

fn parse_lenient_json(input: &str) -> Result<Value, JsonError> {
    validate_json_admission(input)?;
    let normalized = normalize_java_json(input)?;
    serde_json::from_str(&strip_trailing_commas(&normalized)).map_err(|e| JsonError(e.to_string()))
}

fn validate_json_admission(input: &str) -> Result<(), JsonError> {
    let mut depth = 0usize;
    let mut saw_root = false;
    let mut tokens = 0usize;
    let mut string = false;
    let mut escaped = false;
    let mut scalar = false;
    let mut line = 1usize;
    let mut column = 0usize;

    for byte in input.bytes() {
        if byte == b'\n' { line += 1; column = 0; } else { column += 1; }
        if string {
            if escaped { escaped = false; }
            else if byte == b'\\' { escaped = true; }
            else if byte == b'"' { string = false; }
            continue;
        }

        let starts_token = match byte {
            b'"' => { string = true; scalar = false; true }
            b'{' | b'[' => {
                scalar = false;
                if saw_root {
                    if depth >= MAX_PROTOBUF_JSON_NESTING {
                        return Err(JsonError(format!("{line}:{column}: Hit recursion limit.")));
                    }
                    depth += 1;
                } else {
                    saw_root = true;
                }
                true
            }
            b'}' | b']' => {
                scalar = false;
                if depth > 0 { depth -= 1; }
                true
            }
            b',' | b':' => { scalar = false; false }
            byte if byte.is_ascii_whitespace() => { scalar = false; false }
            _ if !scalar => { scalar = true; true }
            _ => false,
        };
        if starts_token {
            tokens += 1;
            if tokens > MAX_PROTOBUF_JSON_TOKENS {
                return Err(JsonError(format!(
                    "{line}:{column}: Token count ({tokens}) exceeds the maximum allowed ({MAX_PROTOBUF_JSON_TOKENS})."
                )));
            }
        }
    }
    Ok(())
}
fn validate_unknown_field_commas(input: &str, descriptor: &MessageDescriptor) -> Result<(), JsonError> {
    let bytes = input.as_bytes();
    let mut index = skip_space(bytes, 0);
    if bytes.get(index) != Some(&b'{') { return Ok(()); }
    index += 1;
    loop {
        index = skip_space(bytes, index);
        if bytes.get(index) == Some(&b'}') || index >= bytes.len() { return Ok(()); }
        let Some((name, after_name)) = json_string(input, index) else { return Ok(()); };
        index = skip_space(bytes, after_name);
        if bytes.get(index) != Some(&b':') { return Ok(()); }
        index = skip_space(bytes, index + 1);
        let end = json_value_end(bytes, index);
        if descriptor.get_field_by_name(&name).is_none() && has_container_trailing_comma(&input[index..end]) {
            return Err(JsonError("Expected identifier or string value after trailing comma in unknown field.".into()));
        }
        index = skip_space(bytes, end);
        if bytes.get(index) == Some(&b',') { index += 1; } else { return Ok(()); }
    }
}

fn skip_space(bytes: &[u8], mut index: usize) -> usize {
    while bytes.get(index).is_some_and(u8::is_ascii_whitespace) { index += 1; }
    index
}

fn json_string(input: &str, start: usize) -> Option<(String, usize)> {
    if input.as_bytes().get(start) != Some(&b'"') { return None; }
    let mut escaped = false;
    for index in start + 1..input.len() {
        match input.as_bytes()[index] {
            b'"' if !escaped => return serde_json::from_str(&input[start..=index]).ok().map(|value| (value, index + 1)),
            b'\\' if !escaped => escaped = true,
            _ => escaped = false,
        }
    }
    None
}

fn json_value_end(bytes: &[u8], start: usize) -> usize {
    let mut index = start;
    let mut depth = 0usize;
    let mut string = false;
    let mut escaped = false;
    while index < bytes.len() {
        let byte = bytes[index];
        if string {
            if escaped { escaped = false; }
            else if byte == b'\\' { escaped = true; }
            else if byte == b'"' { string = false; }
        } else {
            match byte {
                b'"' => string = true,
                b'{' | b'[' => depth += 1,
                b'}' | b']' if depth > 0 => depth -= 1,
                b',' | b'}' if depth == 0 => break,
                _ => {}
            }
        }
        index += 1;
    }
    index
}

fn has_container_trailing_comma(value: &str) -> bool {
    let bytes = value.as_bytes();
    let mut string = false;
    let mut escaped = false;
    for (index, &byte) in bytes.iter().enumerate() {
        if string {
            if escaped { escaped = false; }
            else if byte == b'\\' { escaped = true; }
            else if byte == b'"' { string = false; }
        } else if byte == b'"' { string = true; }
        else if matches!(byte, b'}' | b']') {
            let mut previous = index;
            while previous > 0 && bytes[previous - 1].is_ascii_whitespace() { previous -= 1; }
            if previous > 0 && bytes[previous - 1] == b',' { return true; }
        }
    }
    false
}


fn normalize_java_json(input: &str) -> Result<String, JsonError> {
    let bytes = input.as_bytes();
    let mut output = String::with_capacity(input.len());
    let mut index = 0usize;
    while index < bytes.len() {
        if bytes[index] == b'/' && bytes.get(index + 1) == Some(&b'/') {
            index += 2;
            while index < bytes.len() && bytes[index] != b'\n' { index += 1; }
            continue;
        }
        if bytes[index] == b'/' && bytes.get(index + 1) == Some(&b'*') {
            let start = index;
            index += 2;
            while index + 1 < bytes.len() && !(bytes[index] == b'*' && bytes[index + 1] == b'/') { index += 1; }
            if index + 1 >= bytes.len() { return Err(JsonError(format!("unterminated comment at byte {start}"))); }
            index += 2;
            continue;
        }
        if matches!(bytes[index], b'"' | b'\'') {
            let quote = bytes[index];
            output.push('"');
            index += 1;
            let mut escaped = false;
            let mut closed = false;
            while index < bytes.len() {
                let byte = bytes[index];
                index += 1;
                if escaped {
                    output.push('\\');
                    output.push(byte as char);
                    escaped = false;
                } else if byte == b'\\' {
                    escaped = true;
                } else if byte == quote {
                    output.push('"');
                    closed = true;
                    break;
                } else if byte == b'"' {
                    output.push_str("\\\"");
                } else if byte < 0x20 {
                    use std::fmt::Write as _;
                    let _ = write!(output, "\\u{byte:04x}");
                } else if byte >= 0x80 {
                    let character = input[index - 1..].chars().next().ok_or_else(|| JsonError("invalid UTF-8 JSON input".into()))?;
                    output.push(character);
                    index += character.len_utf8() - 1;
                } else {
                    output.push(byte as char);
                }
            }
            if !closed { return Err(JsonError("unterminated JSON string".into())); }
            continue;
        }
        if bytes[index].is_ascii_alphabetic() || bytes[index] == b'_' {
            let start = index;
            index += 1;
            while index < bytes.len() && (bytes[index].is_ascii_alphanumeric() || bytes[index] == b'_') { index += 1; }
            let word = &input[start..index];
            let next = skip_space(bytes, index);
            if bytes.get(next) == Some(&b':') { output.push('"'); output.push_str(word); output.push('"'); }
            else { output.push_str(word); }
            continue;
        }
        if matches!(bytes[index], b'+' | b'-' | b'.' | b'0'..=b'9') {
            let start = index;
            index += 1;
            while index < bytes.len() && !bytes[index].is_ascii_whitespace() && !matches!(bytes[index], b',' | b']' | b'}' | b':') { index += 1; }
            output.push_str(&normalize_java_number(&input[start..index]));
            continue;
        }
        if bytes[index] >= 0x80 {
            let character = input[index..].chars().next().ok_or_else(|| JsonError("invalid UTF-8 JSON input".into()))?;
            output.push(character);
            index += character.len_utf8();
        } else {
            output.push(bytes[index] as char);
            index += 1;
        }
    }
    Ok(output)
}

fn normalize_java_number(token: &str) -> String {
    let mut token = token;
    let negative = token.starts_with('-');
    if token.starts_with('+') || negative { token = &token[1..]; }
    if token.is_empty() || !token.bytes().all(|byte| byte.is_ascii_digit() || matches!(byte, b'.' | b'e' | b'E' | b'+' | b'-')) {
        return if negative { format!("-{token}") } else { token.to_owned() };
    }
    let mut number = token.to_owned();
    if number.starts_with('.') { number.insert(0, '0'); }
    if number.ends_with('.') { number.push('0'); }
    if !number.contains(['.', 'e', 'E']) {
        let trimmed = number.trim_start_matches('0');
        number = if trimmed.is_empty() { "0".into() } else { trimmed.into() };
    }
    if negative { number.insert(0, '-'); }
    number
}

fn strip_trailing_commas(input: &str) -> String { let mut out=String::with_capacity(input.len()); let mut chars=input.chars().peekable(); let mut string=false; let mut escaped=false; while let Some(c)=chars.next(){ if string { out.push(c); if escaped {escaped=false}else if c=='\\'{escaped=true}else if c=='"'{string=false} } else if c=='"'{string=true;out.push(c)} else if c==',' { let mut look=chars.clone(); while matches!(look.peek(),Some(c) if c.is_whitespace()){look.next();} if !matches!(look.peek(),Some(']')|Some('}')){out.push(c)} } else {out.push(c)} } out }
fn integer(v:&Value)->Option<i64>{v.as_i64().or_else(||v.as_str()?.parse().ok())} fn unsigned(v:&Value)->Option<u64>{v.as_u64().or_else(||v.as_str()?.parse().ok())} fn float(v:&Value)->Option<f64>{v.as_f64().or_else(||v.as_str()?.parse().ok())}
fn int64_json(text:String,value:i64)->Value{if int64_as_string(){Value::String(text)}else{Value::Number(value.into())}} fn uint64_json(text:String,value:u64)->Value{if int64_as_string(){Value::String(text)}else{Value::Number(value.into())}}
fn number(v:f64)->Result<Value,JsonError>{Number::from_f64(v).map(Value::Number).ok_or_else(||JsonError("non-finite JSON number".into()))}
fn decode_hex(text:&str)->Result<Vec<u8>,JsonError>{if text.len()%2!=0{return Err(JsonError("invalidate hex String".into()));}(0..text.len()).step_by(2).map(|i|u8::from_str_radix(&text[i..i+2],16).map_err(|_|JsonError("invalidate hex String".into()))).collect()}
fn hex_encode(bytes:&[u8])->String{const H:&[u8;16]=b"0123456789abcdef";let mut s=String::with_capacity(bytes.len()*2);for b in bytes{s.push(H[(b>>4)as usize]as char);s.push(H[(b&15)as usize]as char)}s}
fn percent_decode(text:&str)->Result<String,JsonError>{let replaced=text.replace('+'," ");percent_encoding::percent_decode_str(&replaced).decode_utf8().map(|v|v.into_owned()).map_err(|e|JsonError(e.to_string()))}
fn parse_map_key(field:&FieldDescriptor,text:&str)->Result<MapKey,JsonError>{Ok(match field.kind(){Kind::Bool=>MapKey::Bool(text.parse().map_err(|_|JsonError("invalid map key".into()))?),Kind::Int32|Kind::Sint32|Kind::Sfixed32=>MapKey::I32(text.parse().map_err(|_|JsonError("invalid map key".into()))?),Kind::Int64|Kind::Sint64|Kind::Sfixed64=>MapKey::I64(text.parse().map_err(|_|JsonError("invalid map key".into()))?),Kind::Uint32|Kind::Fixed32=>MapKey::U32(text.parse().map_err(|_|JsonError("invalid map key".into()))?),Kind::Uint64|Kind::Fixed64=>MapKey::U64(text.parse().map_err(|_|JsonError("invalid map key".into()))?),Kind::String=>MapKey::String(text.into()),_=>return Err(JsonError("invalid map key kind".into()))})}
fn map_key_string(key:&MapKey)->String{match key{MapKey::Bool(v)=>v.to_string(),MapKey::I32(v)=>v.to_string(),MapKey::I64(v)=>v.to_string(),MapKey::U32(v)=>v.to_string(),MapKey::U64(v)=>v.to_string(),MapKey::String(v)=>v.clone()}}
fn is_address_field(name:&str)->bool{matches!(name,"protocol.DelegatedResourceMessage.fromAddress"|"protocol.DelegatedResourceMessage.toAddress"|"protocol.TransactionSignWeight.approved_list"|"protocol.TransactionApprovedList.approved_list")||name.ends_with("owner_address")||name.ends_with("to_address")||name.ends_with("receiver_address")||name.ends_with("contract_address")||name.ends_with("witness_address")||name.ends_with("vote_address")||name.ends_with("proposer_address")||name.ends_with("creator_address")||name.ends_with("origin_address")||name.ends_with("caller_address")||name.ends_with("transferTo_address")||matches!(name,"protocol.Account.address"|"protocol.Key.address"|"protocol.Witness.address"|"protocol.Votes.address"|"protocol.AccountId.address"|"protocol.DelegatedResource.from"|"protocol.DelegatedResource.to")}
fn is_name_field(name:&str)->bool{matches!(name,"protocol.Return.message"|"protocol.Address.host"|"protocol.Note.memo"|"protocol.Account.account_name"|"protocol.Account.asset_issued_name"|"protocol.Account.asset_issued_ID"|"protocol.Account.account_id"|"protocol.AccountId.name"|"protocol.authority.permission_name"|"protocol.Transaction.Contract.ContractName"|"protocol.TransactionInfo.resMessage")||name.ends_with("account_name")||name.ends_with("account_id")||name.ends_with("asset_name")||name.ends_with("token_id")||name.ends_with("description")||name.ends_with("url")||name.ends_with("update_url")||name.ends_with(".name")||name.ends_with(".abbr")}
