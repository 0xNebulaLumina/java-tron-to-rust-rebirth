use core::fmt;

use prost::Message;
use tron_protocol::protocol::{Votes, Witness};
use tron_state::{dynamic, value, OverlayStore, ReadView, Session, SessionError, StoreKind, ViewStore};

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum StateError {
    Session(SessionError),
    MissingDynamic(&'static str),
    InvalidDynamic { name: &'static str, expected: usize, actual: usize },
    InvalidSchedule(tron_state::value::CodecError),
    InvalidProtobuf { store: StoreKind, key: Vec<u8>, source: String },
    ArithmeticOverflow(&'static str),
    InvalidRewardPeriod(i64),
}
impl fmt::Display for StateError { fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { write!(f, "consensus state error: {self:?}") } }
impl std::error::Error for StateError {}
impl From<SessionError> for StateError { fn from(value: SessionError) -> Self { Self::Session(value) } }

pub trait ConsensusRead {
    fn witness(&self, address: &[u8]) -> Result<Option<Witness>, StateError>;
    fn witnesses(&self) -> Result<Vec<Witness>, StateError>;
    fn votes(&self) -> Result<Vec<(Vec<u8>, Votes)>, StateError>;
    fn active_witnesses(&self) -> Result<Vec<Vec<u8>>, StateError>;
    fn current_witnesses(&self) -> Result<Vec<Vec<u8>>, StateError>;
    fn dynamic_long(&self, name: &'static str) -> Result<i64, StateError>;
    fn dynamic_int(&self, name: &'static str) -> Result<i32, StateError>;
    fn dynamic_raw(&self, name: &'static str) -> Result<Vec<u8>, StateError>;
    fn delegation(&self, key: &[u8]) -> Option<Vec<u8>>;
}

#[derive(Clone)]
pub struct StateView { view: ReadView }
impl StateView { #[must_use] pub fn new(view: ReadView) -> Self { Self { view } } }

pub struct StateFacade<'a> { session: &'a Session }
impl<'a> StateFacade<'a> {
    #[must_use] pub fn new(session: &'a Session) -> Self { Self { session } }
    #[must_use] pub fn view(&self) -> StateView { StateView::new(self.session.view()) }
    pub fn child_session(&self) -> Result<Session, StateError> { self.session.child().map_err(Into::into) }
    pub fn save_witness(&self, witness: &Witness) -> Result<(), StateError> { self.session.store(StoreKind::Witness).put(&witness.address, &witness.encode_to_vec()).map_err(Into::into) }
    pub fn delete_votes(&self, key: &[u8]) -> Result<(), StateError> { self.session.store(StoreKind::Votes).delete(key).map_err(Into::into) }
    pub fn save_active_witnesses(&self, addresses: &[Vec<u8>]) -> Result<(), StateError> { save_schedule(&self.session.store(StoreKind::WitnessSchedule), value::ACTIVE_WITNESSES_KEY, addresses) }
    pub fn save_current_witnesses(&self, addresses: &[Vec<u8>]) -> Result<(), StateError> { save_schedule(&self.session.store(StoreKind::WitnessSchedule), value::CURRENT_SHUFFLED_WITNESSES_KEY, addresses) }
    pub fn save_dynamic_long(&self, name: &'static str, value: i64) -> Result<(), StateError> { save_dynamic(&self.session.store(StoreKind::DynamicProperties), name, &value.to_be_bytes()) }
    pub fn save_dynamic_int(&self, name: &'static str, value: i32) -> Result<(), StateError> { save_dynamic(&self.session.store(StoreKind::DynamicProperties), name, &value.to_be_bytes()) }
    pub fn save_dynamic_raw(&self, name: &'static str, value: &[u8]) -> Result<(), StateError> { save_dynamic(&self.session.store(StoreKind::DynamicProperties), name, value) }
    pub fn save_delegation(&self, key: &[u8], value: &[u8]) -> Result<(), StateError> { self.session.store(StoreKind::Delegation).put(key, value).map_err(Into::into) }
    #[must_use] pub fn store_get(&self, store: StoreKind, key: &[u8]) -> Option<Vec<u8>> { self.session.store(store).get(key) }
    pub fn store_put(&self, store: StoreKind, key: &[u8], value: &[u8]) -> Result<(), StateError> { self.session.store(store).put(key, value).map_err(Into::into) }
    pub fn store_delete(&self, store: StoreKind, key: &[u8]) -> Result<(), StateError> { self.session.store(store).delete(key).map_err(Into::into) }
    #[must_use] pub fn store_rows(&self, store: StoreKind) -> Vec<(Vec<u8>, Vec<u8>)> { self.session.store(store).prefix(&[]) }
}

trait StoreRead { fn get_value(&self, key: &[u8]) -> Option<Vec<u8>>; fn rows(&self) -> Vec<(Vec<u8>, Vec<u8>)>; }
impl StoreRead for ViewStore { fn get_value(&self, key: &[u8]) -> Option<Vec<u8>> { self.get(key) } fn rows(&self) -> Vec<(Vec<u8>, Vec<u8>)> { self.prefix(&[]) } }

fn decode_message<M: Message + Default>(store: StoreKind, key: &[u8], bytes: &[u8]) -> Result<M, StateError> {
    M::decode(bytes).map_err(|error| StateError::InvalidProtobuf { store, key: key.to_vec(), source: error.to_string() })
}
fn read_witness(store: &impl StoreRead, address: &[u8]) -> Result<Option<Witness>, StateError> { store.get_value(address).map(|bytes| decode_message(StoreKind::Witness, address, &bytes)).transpose() }
fn read_witnesses(store: &impl StoreRead) -> Result<Vec<Witness>, StateError> { store.rows().into_iter().map(|(key, bytes)| decode_message(StoreKind::Witness, &key, &bytes)).collect() }
fn read_votes(store: &impl StoreRead) -> Result<Vec<(Vec<u8>, Votes)>, StateError> { store.rows().into_iter().map(|(key, bytes)| decode_message(StoreKind::Votes, &key, &bytes).map(|votes| (key, votes))).collect() }
fn read_schedule(store: &impl StoreRead, key: &[u8]) -> Result<Vec<Vec<u8>>, StateError> { let bytes = store.get_value(key).unwrap_or_default(); value::decode_witness_schedule(&bytes).map(|rows| rows.into_iter().map(Vec::from).collect()).map_err(StateError::InvalidSchedule) }
fn read_sized<const N: usize>(store: &impl StoreRead, name: &'static str) -> Result<[u8; N], StateError> { let key = dynamic::key(name).ok_or(StateError::MissingDynamic(name))?; let bytes = store.get_value(key).ok_or(StateError::MissingDynamic(name))?; let actual = bytes.len(); bytes.try_into().map_err(|_| StateError::InvalidDynamic { name, expected: N, actual }) }

impl ConsensusRead for StateView {
    fn witness(&self, address: &[u8]) -> Result<Option<Witness>, StateError> { read_witness(&self.view.store(StoreKind::Witness), address) }
    fn witnesses(&self) -> Result<Vec<Witness>, StateError> { read_witnesses(&self.view.store(StoreKind::Witness)) }
    fn votes(&self) -> Result<Vec<(Vec<u8>, Votes)>, StateError> { read_votes(&self.view.store(StoreKind::Votes)) }
    fn active_witnesses(&self) -> Result<Vec<Vec<u8>>, StateError> { read_schedule(&self.view.store(StoreKind::WitnessSchedule), value::ACTIVE_WITNESSES_KEY) }
    fn current_witnesses(&self) -> Result<Vec<Vec<u8>>, StateError> { read_schedule(&self.view.store(StoreKind::WitnessSchedule), value::CURRENT_SHUFFLED_WITNESSES_KEY) }
    fn dynamic_long(&self, name: &'static str) -> Result<i64, StateError> { Ok(i64::from_be_bytes(read_sized(&self.view.store(StoreKind::DynamicProperties), name)?)) }
    fn dynamic_int(&self, name: &'static str) -> Result<i32, StateError> { Ok(i32::from_be_bytes(read_sized(&self.view.store(StoreKind::DynamicProperties), name)?)) }
    fn dynamic_raw(&self, name: &'static str) -> Result<Vec<u8>, StateError> { let key = dynamic::key(name).ok_or(StateError::MissingDynamic(name))?; self.view.store(StoreKind::DynamicProperties).get(key).ok_or(StateError::MissingDynamic(name)) }
    fn delegation(&self, key: &[u8]) -> Option<Vec<u8>> { self.view.store(StoreKind::Delegation).get(key) }
}
impl ConsensusRead for StateFacade<'_> { fn witness(&self,a:&[u8])->Result<Option<Witness>,StateError>{self.view().witness(a)} fn witnesses(&self)->Result<Vec<Witness>,StateError>{self.view().witnesses()} fn votes(&self)->Result<Vec<(Vec<u8>,Votes)>,StateError>{self.view().votes()} fn active_witnesses(&self)->Result<Vec<Vec<u8>>,StateError>{self.view().active_witnesses()} fn current_witnesses(&self)->Result<Vec<Vec<u8>>,StateError>{self.view().current_witnesses()} fn dynamic_long(&self,n:&'static str)->Result<i64,StateError>{self.view().dynamic_long(n)} fn dynamic_int(&self,n:&'static str)->Result<i32,StateError>{self.view().dynamic_int(n)} fn dynamic_raw(&self,n:&'static str)->Result<Vec<u8>,StateError>{self.view().dynamic_raw(n)} fn delegation(&self,k:&[u8])->Option<Vec<u8>>{self.view().delegation(k)} }

fn save_dynamic(store: &OverlayStore, name: &'static str, value: &[u8]) -> Result<(), StateError> { let key = dynamic::key(name).ok_or(StateError::MissingDynamic(name))?; store.put(key, value).map_err(Into::into) }
fn save_schedule(store: &OverlayStore, key: &[u8], addresses: &[Vec<u8>]) -> Result<(), StateError> { let mut bytes = Vec::with_capacity(addresses.len() * value::WITNESS_ADDRESS_LENGTH); for address in addresses { if address.len() != value::WITNESS_ADDRESS_LENGTH { return Err(StateError::InvalidSchedule(tron_state::value::CodecError::InvalidLength { kind: "witness address", expected: "21 bytes", actual: address.len() })); } bytes.extend_from_slice(address); } store.put(key, &bytes).map_err(Into::into) }

#[must_use] pub fn delegation_brokerage_key(cycle: i64, address: &[u8]) -> Vec<u8> { delegation_key(cycle, address, "brokerage") }
#[must_use] pub fn delegation_vote_key(cycle: i64, address: &[u8]) -> Vec<u8> { delegation_key(cycle, address, "vote") }
pub fn delegation_key(cycle: i64, address: &[u8], suffix: &str) -> Vec<u8> { let mut out = cycle.to_string(); out.push('-'); for byte in address { use core::fmt::Write; let _ = write!(out, "{byte:02x}"); } out.push('-'); out.push_str(suffix); out.into_bytes() }
