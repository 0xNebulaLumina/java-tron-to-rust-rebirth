use std::{collections::{BTreeMap, BTreeSet}, fmt, sync::Arc};

use prost::Message;
use tron_protocol::protocol::transaction::result::Code;
use tron_state::{dynamic, OverlayStore, Session, SessionError, StoreEntry, StoreKind};

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ActuatorErrorKind { Contract, Store, Validation, Execution, Arithmetic }

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ActuatorError { pub kind: ActuatorErrorKind, pub message: String }
impl ActuatorError {
    pub fn validation(message: impl Into<String>) -> Self { Self { kind: ActuatorErrorKind::Validation, message: message.into() } }
    pub fn execution(message: impl Into<String>) -> Self { Self { kind: ActuatorErrorKind::Execution, message: message.into() } }
    pub fn arithmetic(message: impl Into<String>) -> Self { Self { kind: ActuatorErrorKind::Arithmetic, message: message.into() } }
}
impl fmt::Display for ActuatorError { fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { f.write_str(&self.message) } }
impl std::error::Error for ActuatorError {}
impl From<SessionError> for ActuatorError { fn from(value: SessionError) -> Self { Self { kind: ActuatorErrorKind::Store, message: value.to_string() } } }

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StateDelta { pub store: StoreKind, pub key: Vec<u8>, pub before: StoreEntry, pub after: StoreEntry }

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ActuatorResult {
    pub fee: i64,
    pub code: Code,
    pub message: Vec<u8>,
    pub asset_issue_id: Vec<u8>,
    pub deltas: Vec<StateDelta>,
}
impl Default for ActuatorResult { fn default() -> Self { Self { fee: 0, code: Code::Sucess, message: Vec::new(), asset_issue_id: Vec::new(), deltas: Vec::new() } } }

pub trait Actuator {
    fn owner_address(&self) -> Result<&[u8], ActuatorError>;
    fn validate(&self, context: &ValidationContext<'_>) -> Result<(), ActuatorError>;
    fn execute_in(&self, context: &mut ExecutionContext<'_>, result: &mut ActuatorResult) -> Result<(), ActuatorError>;
    fn declared_access(&self) -> Option<&DeclaredStoreAccess> { None }

    fn execute(&self, outer: &Session, result: Option<&mut ActuatorResult>, config: ExecutionConfig) -> Result<(), ActuatorError> {
        let result = result.ok_or_else(|| ActuatorError::execution("TransactionResultCapsule is null"))?;
        let mut child = outer.child()?;
        let mut temporary = ActuatorResult::default();
        let execution: Result<(), ActuatorError> = (|| {
            let access = self.declared_access().cloned();
            let validation = ValidationContext::new(&child, config.clone(), access.clone());
            self.validate(&validation)?;
            let mut context = ExecutionContext::new(&child, config, access);
            self.execute_in(&mut context, &mut temporary)?;
            temporary.deltas = context.deltas()?;
            child.merge()?;
            Ok(())
        })();
        match execution {
            Ok(()) => {
                *result = temporary;
                Ok(())
            }
            Err(error) => {
                let _ = child.revoke();
                *result = ActuatorResult { code: Code::Failed, message: error.message.as_bytes().to_vec(), ..ActuatorResult::default() };
                Err(error)
            }
        }
    }
}

pub trait RewardCallback: Send + Sync {
    fn withdraw_reward(&self, context: &mut ExecutionContext<'_>, address: &[u8]) -> Result<(), ActuatorError>;
}

#[derive(Clone)]
pub struct ExecutionConfig { pub blackhole_address: Vec<u8>, pub reward_callback: Option<Arc<dyn RewardCallback>> }
impl Default for ExecutionConfig {
    fn default() -> Self { Self { blackhole_address: vec![0x41; 21], reward_callback: None } }
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct DeclaredStoreAccess {
    pub readable: BTreeSet<StoreKind>,
    pub writable: BTreeSet<StoreKind>,
}

pub struct ValidationContext<'a> {
    inner: ExecutionContext<'a>,
}
impl<'a> ValidationContext<'a> {
    fn new(session: &'a Session, config: ExecutionConfig, allowed: Option<DeclaredStoreAccess>) -> Self { Self { inner: ExecutionContext::new(session, config, allowed) } }
}
impl<'a> core::ops::Deref for ValidationContext<'a> {
    type Target = ExecutionContext<'a>;
    fn deref(&self) -> &Self::Target { &self.inner }
}

pub struct ExecutionContext<'a> {
    session: &'a Session,
    config: ExecutionConfig,
    allowed: Option<DeclaredStoreAccess>,
    touched: BTreeMap<(StoreKind, Vec<u8>), StoreEntry>,
}
impl<'a> ExecutionContext<'a> {
    fn new(session: &'a Session, config: ExecutionConfig, allowed: Option<DeclaredStoreAccess>) -> Self {
        Self { session, config, allowed, touched: BTreeMap::new() }
    }
    fn store(&self, kind: StoreKind) -> OverlayStore { self.session.store(kind) }
    fn ensure_readable(&self, kind: StoreKind) -> Result<(), ActuatorError> {
        if self.allowed.as_ref().is_some_and(|allowed| !allowed.readable.contains(&kind)) {
            return Err(ActuatorError::execution(format!("extension read undeclared store {:?}", kind)));
        }
        Ok(())
    }
    fn ensure_writable(&self, kind: StoreKind) -> Result<(), ActuatorError> {
        if self.allowed.as_ref().is_some_and(|allowed| !allowed.writable.contains(&kind)) {
            return Err(ActuatorError::execution(format!("extension wrote undeclared store {:?}", kind)));
        }
        Ok(())
    }
    pub fn blackhole_address(&self) -> &[u8] { &self.config.blackhole_address }
    pub fn get(&self, kind: StoreKind, key: &[u8]) -> Result<Option<Vec<u8>>, ActuatorError> {
        self.ensure_readable(kind)?;
        Ok(self.store(kind).get(key))
    }
    pub fn decode<M: Message + Default>(&self, kind: StoreKind, key: &[u8], missing: &'static str) -> Result<M, ActuatorError> {
        let bytes = self.get(kind, key)?.ok_or_else(|| ActuatorError::validation(missing))?;
        M::decode(bytes.as_slice()).map_err(|error| ActuatorError::execution(error.to_string()))
    }
    pub fn delete(&mut self, kind: StoreKind, key: &[u8]) -> Result<(), ActuatorError> {
        self.ensure_writable(kind)?;
        if !self.touched.contains_key(&(kind, key.to_vec())) {
            let before = self.store(kind).entry(key);
            self.touched.insert((kind, key.to_vec()), before);
        }
        self.store(kind).delete(key)?;
        Ok(())
    }
    pub fn withdraw_reward(&mut self, address: &[u8]) -> Result<(), ActuatorError> {
        let callback = self.config.reward_callback.clone();
        if let Some(callback) = callback { callback.withdraw_reward(self, address)?; }
        Ok(())
    }
    pub fn put(&mut self, kind: StoreKind, key: &[u8], value: &[u8]) -> Result<(), ActuatorError> {
        self.ensure_writable(kind)?;
        if !self.touched.contains_key(&(kind, key.to_vec())) {
            let before = self.store(kind).entry(key);
            self.touched.insert((kind, key.to_vec()), before);
        }
        self.store(kind).put(key, value)?;
        Ok(())
    }
    pub fn put_message<M: Message>(&mut self, kind: StoreKind, key: &[u8], value: &M) -> Result<(), ActuatorError> { self.put(kind, key, &value.encode_to_vec()) }
    pub fn dynamic_long(&self, name: &str) -> Result<i64, ActuatorError> {
        let key = dynamic::key(name).ok_or_else(|| ActuatorError::execution(format!("unknown dynamic property {name}")))?;
        let bytes = self.get(StoreKind::DynamicProperties, key)?.ok_or_else(|| ActuatorError::execution(format!("missing dynamic property {name}")))?;
        let actual = bytes.len();
        let value: [u8; 8] = bytes.try_into().map_err(|_| ActuatorError::execution(format!("invalid dynamic property {name} length {actual}")))?;
        Ok(i64::from_be_bytes(value))
    }
    pub fn dynamic_int(&self, name: &str) -> Result<i32, ActuatorError> {
        let key = dynamic::key(name).ok_or_else(|| ActuatorError::execution(format!("unknown dynamic property {name}")))?;
        let bytes = self.get(StoreKind::DynamicProperties, key)?.ok_or_else(|| ActuatorError::execution(format!("missing dynamic property {name}")))?;
        let actual = bytes.len();
        let value: [u8; 4] = bytes.try_into().map_err(|_| ActuatorError::execution(format!("invalid dynamic property {name} length {actual}")))?;
        Ok(i32::from_be_bytes(value))
    }
    pub fn dynamic_raw(&self, name: &str) -> Result<Vec<u8>, ActuatorError> {
        let key = dynamic::key(name).ok_or_else(|| ActuatorError::execution(format!("unknown dynamic property {name}")))?;
        self.get(StoreKind::DynamicProperties, key)?.ok_or_else(|| ActuatorError::execution(format!("missing dynamic property {name}")))
    }
    pub fn put_dynamic_long(&mut self, name: &str, value: i64) -> Result<(), ActuatorError> {
        let key = dynamic::key(name).ok_or_else(|| ActuatorError::execution(format!("unknown dynamic property {name}")))?;
        self.put(StoreKind::DynamicProperties, key, &value.to_be_bytes())
    }
    pub fn account_asset_balance(&self, account: &tron_protocol::protocol::Account, asset: &[u8]) -> Result<i64, ActuatorError> {
        self.ensure_readable(StoreKind::AccountAsset)?;
        tron_state::account_asset::balance(account, asset, |key| self.store(StoreKind::AccountAsset).get(key)).map_err(|error| ActuatorError::execution(error.to_string()))
    }
    pub fn set_account_asset_balance(&mut self, account: &mut tron_protocol::protocol::Account, asset: &[u8], value: i64) -> Result<(), ActuatorError> {
        self.ensure_writable(StoreKind::AccountAsset)?;
        let name = core::str::from_utf8(asset).map_err(|_| ActuatorError::execution("asset key is not UTF-8"))?.to_owned();
        if account.asset_optimized {
            let address = tron_primitives::TronAddress21::validate_mainnet(&account.address).map_err(|error| ActuatorError::execution(error.to_string()))?;
            let key = tron_state::keys::external_asset_key(&address, asset).map_err(|error| ActuatorError::execution(error.to_string()))?;
            account.asset_v2.remove(&name);
            if value == 0 { self.delete(StoreKind::AccountAsset, &key) } else { self.put(StoreKind::AccountAsset, &key, &value.to_be_bytes()) }
        } else {
            if value == 0 { account.asset_v2.remove(&name); } else { account.asset_v2.insert(name, value); }
            Ok(())
        }
    }
    pub fn deltas(&self) -> Result<Vec<StateDelta>, ActuatorError> {
        Ok(self.touched.iter().map(|((store, key), before)| StateDelta {
            store: *store, key: key.clone(), before: before.clone(), after: self.store(*store).entry(key),
        }).collect())
    }
}

pub fn decode_typed_any<M: Message + Default>(any: &tron_protocol::google::protobuf::Any, full_name: &str) -> Result<M, ActuatorError> {
    let expected = format!("type.googleapis.com/{full_name}");
    if any.type_url != expected { return Err(ActuatorError::validation(format!("contract type error, expected type [{full_name}], real type[{}]", any.type_url))); }
    M::decode(any.value.as_slice()).map_err(|error| ActuatorError::validation(error.to_string()))
}

pub fn valid_address(address: &[u8]) -> bool { tron_crypto::validate_address(address).is_ok() }
pub fn checked_add(left: i64, right: i64) -> Result<i64, ActuatorError> { left.checked_add(right).ok_or_else(|| ActuatorError::arithmetic("long overflow")) }
pub fn checked_sub(left: i64, right: i64) -> Result<i64, ActuatorError> { left.checked_sub(right).ok_or_else(|| ActuatorError::arithmetic("long overflow")) }
