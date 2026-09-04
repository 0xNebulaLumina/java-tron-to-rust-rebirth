use std::{collections::{BTreeMap, BTreeSet}, panic::{catch_unwind, AssertUnwindSafe}, sync::Arc};

use prost::Message;
use tron_protocol::{
    extensions::{ExtensionDescriptor, ExtensionRegistry, RegisteredExtension, RegistrationError, EXTENSION_CONTRACT_TYPE_MAX, EXTENSION_CONTRACT_TYPE_MIN, MAX_EXTENSION_BATCH_COUNT},
    google::protobuf::Any,
    protocol::{self, transaction::{contract::ContractType, Contract}},
};
use tron_state::{Session, StoreKind};
use crate::{
    AccountCreateActuator, AccountPermissionUpdateActuator, AccountUpdateActuator, Actuator,
    ActuatorError, ActuatorResult, AssetIssueActuator, DeclaredStoreAccess,
    ExecutionConfig, ExecutionContext, ParticipateAssetIssueActuator, SetAccountIdActuator,
    TransferActuator, TransferAssetActuator, UnfreezeAssetActuator, UpdateAssetActuator,
    ValidationContext, VoteWitnessActuator, WitnessCreateActuator, WitnessUpdateActuator,
};

const TYPE_URL_PREFIX: &str = "type.googleapis.com/";
pub const MAX_EXTENSION_PAYLOAD_BYTES: usize = 1_048_576;
pub const MAX_EXTENSION_DECLARED_STORES: usize = 64;

macro_rules! builtin_contracts {
    ($(($variant:ident, $type_variant:ident, $message:ident, $full_name:literal, $owner:ident)),+ $(,)?) => {
        #[derive(Clone, Debug, PartialEq)]
        pub enum BuiltinContract { $( $variant(protocol::$message), )+ }

        impl BuiltinContract {
            pub fn contract_type(&self) -> ContractType {
                match self { $(Self::$variant(_) => ContractType::$type_variant,)+ }
            }
            pub fn full_name(&self) -> &'static str {
                match self { $(Self::$variant(_) => $full_name,)+ }
            }
            pub fn owner_address(&self) -> &[u8] {
                match self { $(Self::$variant(value) => &value.$owner,)+ }
            }
        }

        fn decode_builtin(kind: ContractType, any: &Any) -> Result<BuiltinContract, RegistryError> {
            match kind {
                $(ContractType::$type_variant => decode_generated::<protocol::$message>(any, $full_name).map(BuiltinContract::$variant),)+
                ContractType::CustomContract | ContractType::GetContract => Err(RegistryError::UnsupportedBuiltIn(kind)),
            }
        }
    };
}

builtin_contracts!(
    (AccountCreate, AccountCreateContract, AccountCreateContract, "protocol.AccountCreateContract", owner_address),
    (Transfer, TransferContract, TransferContract, "protocol.TransferContract", owner_address),
    (TransferAsset, TransferAssetContract, TransferAssetContract, "protocol.TransferAssetContract", owner_address),
    (VoteAsset, VoteAssetContract, VoteAssetContract, "protocol.VoteAssetContract", owner_address),
    (VoteWitness, VoteWitnessContract, VoteWitnessContract, "protocol.VoteWitnessContract", owner_address),
    (WitnessCreate, WitnessCreateContract, WitnessCreateContract, "protocol.WitnessCreateContract", owner_address),
    (AssetIssue, AssetIssueContract, AssetIssueContract, "protocol.AssetIssueContract", owner_address),
    (WitnessUpdate, WitnessUpdateContract, WitnessUpdateContract, "protocol.WitnessUpdateContract", owner_address),
    (ParticipateAssetIssue, ParticipateAssetIssueContract, ParticipateAssetIssueContract, "protocol.ParticipateAssetIssueContract", owner_address),
    (AccountUpdate, AccountUpdateContract, AccountUpdateContract, "protocol.AccountUpdateContract", owner_address),
    (FreezeBalance, FreezeBalanceContract, FreezeBalanceContract, "protocol.FreezeBalanceContract", owner_address),
    (UnfreezeBalance, UnfreezeBalanceContract, UnfreezeBalanceContract, "protocol.UnfreezeBalanceContract", owner_address),
    (WithdrawBalance, WithdrawBalanceContract, WithdrawBalanceContract, "protocol.WithdrawBalanceContract", owner_address),
    (UnfreezeAsset, UnfreezeAssetContract, UnfreezeAssetContract, "protocol.UnfreezeAssetContract", owner_address),
    (UpdateAsset, UpdateAssetContract, UpdateAssetContract, "protocol.UpdateAssetContract", owner_address),
    (ProposalCreate, ProposalCreateContract, ProposalCreateContract, "protocol.ProposalCreateContract", owner_address),
    (ProposalApprove, ProposalApproveContract, ProposalApproveContract, "protocol.ProposalApproveContract", owner_address),
    (ProposalDelete, ProposalDeleteContract, ProposalDeleteContract, "protocol.ProposalDeleteContract", owner_address),
    (SetAccountId, SetAccountIdContract, SetAccountIdContract, "protocol.SetAccountIdContract", owner_address),
    (CreateSmartContract, CreateSmartContract, CreateSmartContract, "protocol.CreateSmartContract", owner_address),
    (TriggerSmartContract, TriggerSmartContract, TriggerSmartContract, "protocol.TriggerSmartContract", owner_address),
    (UpdateSetting, UpdateSettingContract, UpdateSettingContract, "protocol.UpdateSettingContract", owner_address),
    (ExchangeCreate, ExchangeCreateContract, ExchangeCreateContract, "protocol.ExchangeCreateContract", owner_address),
    (ExchangeInject, ExchangeInjectContract, ExchangeInjectContract, "protocol.ExchangeInjectContract", owner_address),
    (ExchangeWithdraw, ExchangeWithdrawContract, ExchangeWithdrawContract, "protocol.ExchangeWithdrawContract", owner_address),
    (ExchangeTransaction, ExchangeTransactionContract, ExchangeTransactionContract, "protocol.ExchangeTransactionContract", owner_address),
    (UpdateEnergyLimit, UpdateEnergyLimitContract, UpdateEnergyLimitContract, "protocol.UpdateEnergyLimitContract", owner_address),
    (AccountPermissionUpdate, AccountPermissionUpdateContract, AccountPermissionUpdateContract, "protocol.AccountPermissionUpdateContract", owner_address),
    (ClearAbi, ClearAbiContract, ClearAbiContract, "protocol.ClearABIContract", owner_address),
    (UpdateBrokerage, UpdateBrokerageContract, UpdateBrokerageContract, "protocol.UpdateBrokerageContract", owner_address),
    (ShieldedTransfer, ShieldedTransferContract, ShieldedTransferContract, "protocol.ShieldedTransferContract", transparent_from_address),
    (MarketSellAsset, MarketSellAssetContract, MarketSellAssetContract, "protocol.MarketSellAssetContract", owner_address),
    (MarketCancelOrder, MarketCancelOrderContract, MarketCancelOrderContract, "protocol.MarketCancelOrderContract", owner_address),
    (FreezeBalanceV2, FreezeBalanceV2Contract, FreezeBalanceV2Contract, "protocol.FreezeBalanceV2Contract", owner_address),
    (UnfreezeBalanceV2, UnfreezeBalanceV2Contract, UnfreezeBalanceV2Contract, "protocol.UnfreezeBalanceV2Contract", owner_address),
    (WithdrawExpireUnfreeze, WithdrawExpireUnfreezeContract, WithdrawExpireUnfreezeContract, "protocol.WithdrawExpireUnfreezeContract", owner_address),
    (DelegateResource, DelegateResourceContract, DelegateResourceContract, "protocol.DelegateResourceContract", owner_address),
    (UnDelegateResource, UnDelegateResourceContract, UnDelegateResourceContract, "protocol.UnDelegateResourceContract", owner_address),
    (CancelAllUnfreezeV2, CancelAllUnfreezeV2Contract, CancelAllUnfreezeV2Contract, "protocol.CancelAllUnfreezeV2Contract", owner_address),
);

fn decode_generated<M: Message + Default>(any: &Any, full_name: &'static str) -> Result<M, RegistryError> {
    let expected = format!("{TYPE_URL_PREFIX}{full_name}");
    if any.type_url != expected {
        return Err(RegistryError::TypeUrlMismatch { expected, actual: any.type_url.clone() });
    }
    M::decode(any.value.as_slice()).map_err(|error| RegistryError::MalformedContract(error.to_string()))
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct ProviderCodeIdentity {
    pub provider_id: String,
    pub code_sha256: [u8; 32],
}

pub struct TrustedExtensionProvider {
    pub identity: ProviderCodeIdentity,
    pub provider: Arc<dyn ExtensionActuatorProvider>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StoreAccess {
    pub store: StoreKind,
    pub read: bool,
    pub write: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExtensionProviderMetadata {
    pub extension_id: String,
    pub priority: i32,
    pub message_full_name: String,
    pub contract_type: i32,
    pub max_payload_bytes: usize,
    pub state_access: Vec<StoreAccess>,
}

pub trait ExtensionActuatorProvider: Send + Sync {
    fn metadata(&self) -> ExtensionProviderMetadata;
    fn owner_address(&self, payload: &[u8]) -> Result<Vec<u8>, ActuatorError>;
    fn create_actuator(&self, payload: &[u8]) -> Result<Box<dyn Actuator>, ActuatorError>;
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RegistryError {
    Descriptor(RegistrationError),
    EmptyProviderId,
    ProviderCountLimitExceeded,
    ProviderCollision(String),
    ProviderMissing(String),
    DescriptorMissing(String),
    ProviderMetadataMismatch(String),
    ProviderNotAllowlisted(String),
    InvalidProviderPayloadLimit { extension_id: String, limit: usize },
    ProviderStateAccessLimitExceeded { extension_id: String, limit: usize, actual: usize },
    ProviderSensitiveStoreAccess { extension_id: String, store: StoreKind },
    ProviderInvalidStoreAccess { extension_id: String, store: StoreKind },
    InvalidContractType(i32),
    MissingParameter,
    TypeUrlMismatch { expected: String, actual: String },
    MalformedContract(String),
    UnsupportedBuiltIn(ContractType),
    UnsupportedBuiltInActuator(ContractType),
    PayloadLimitExceeded { extension_id: String, limit: usize, actual: usize },
    Provider(String),
    ProviderPanicked(String),
}

impl From<RegistrationError> for RegistryError {
    fn from(value: RegistrationError) -> Self { Self::Descriptor(value) }
}

pub enum DecodedContract {
    BuiltIn(BuiltinContract),
    Extension { registration: RegisteredExtension, payload: Vec<u8> },
}

struct RegisteredProvider {
    provider: Arc<dyn ExtensionActuatorProvider>,
    metadata: ExtensionProviderMetadata,
    access: DeclaredStoreAccess,
}

pub struct ActuatorRegistry {
    descriptors: ExtensionRegistry,
    providers: Vec<RegisteredProvider>,
    provider_by_type: BTreeMap<i32, usize>,
}

impl ActuatorRegistry {
    pub fn new(
        descriptors: impl IntoIterator<Item = ExtensionDescriptor>,
        providers: impl IntoIterator<Item = TrustedExtensionProvider>,
        allowlist: &BTreeSet<ProviderCodeIdentity>,
    ) -> Result<Self, RegistryError> {
        let descriptors = ExtensionRegistry::register(descriptors)?;
        let providers: Vec<_> = providers.into_iter().collect();
        if providers.len() > MAX_EXTENSION_BATCH_COUNT { return Err(RegistryError::ProviderCountLimitExceeded); }
        let providers = providers.into_iter().map(|loaded| {
            if !allowlist.contains(&loaded.identity) { return Err(RegistryError::ProviderNotAllowlisted(loaded.identity.provider_id)); }
            let metadata = catch_provider_panic(&loaded.identity.provider_id, || loaded.provider.metadata())?;
            if metadata.state_access.len() > MAX_EXTENSION_DECLARED_STORES {
                return Err(RegistryError::ProviderStateAccessLimitExceeded { extension_id: metadata.extension_id, limit: MAX_EXTENSION_DECLARED_STORES, actual: metadata.state_access.len() });
            }
            let mut access = DeclaredStoreAccess::default();
            for declaration in &metadata.state_access {
                if matches!(declaration.store, StoreKind::Common | StoreKind::Checkpoint | StoreKind::Temporary) {
                    return Err(RegistryError::ProviderSensitiveStoreAccess { extension_id: metadata.extension_id.clone(), store: declaration.store });
                }
                if !declaration.read && !declaration.write {
                    return Err(RegistryError::ProviderInvalidStoreAccess { extension_id: metadata.extension_id.clone(), store: declaration.store });
                }
                if declaration.read { access.readable.insert(declaration.store); }
                if declaration.write { access.writable.insert(declaration.store); }
            }
            Ok(RegisteredProvider { provider: loaded.provider, metadata, access })
        }).collect::<Result<Vec<_>, RegistryError>>()?;
        let mut providers = providers;
        providers.sort_by_key(|provider| (provider.metadata.priority, provider.metadata.extension_id.clone()));
        let mut provider_ids = BTreeSet::new();
        let mut provider_by_type = BTreeMap::new();
        for (index, provider) in providers.iter().enumerate() {
            let metadata = &provider.metadata;
            if metadata.extension_id.trim().is_empty() { return Err(RegistryError::EmptyProviderId); }
            if !provider_ids.insert(metadata.extension_id.clone()) || provider_by_type.insert(metadata.contract_type, index).is_some() {
                return Err(RegistryError::ProviderCollision(metadata.extension_id.clone()));
            }
            if metadata.max_payload_bytes == 0 || metadata.max_payload_bytes > MAX_EXTENSION_PAYLOAD_BYTES {
                return Err(RegistryError::InvalidProviderPayloadLimit { extension_id: metadata.extension_id.clone(), limit: metadata.max_payload_bytes });
            }
            let registration = descriptors.resolve_extension(&metadata.extension_id).ok_or_else(|| RegistryError::DescriptorMissing(metadata.extension_id.clone()))?;
            if metadata.priority != registration.priority || metadata.message_full_name != registration.message_full_name || metadata.contract_type != registration.contract_type {
                return Err(RegistryError::ProviderMetadataMismatch(metadata.extension_id.clone()));
            }
        }
        for registration in descriptors.registrations() {
            if !provider_ids.contains(&registration.extension_id) { return Err(RegistryError::ProviderMissing(registration.extension_id.clone())); }
        }
        Ok(Self { descriptors, providers, provider_by_type })
    }

    pub fn empty() -> Self { Self::new([], [], &BTreeSet::new()).expect("empty registry is valid") }
    pub fn descriptors(&self) -> &ExtensionRegistry { &self.descriptors }

    pub fn decode(&self, contract: &Contract) -> Result<DecodedContract, RegistryError> {
        let any = contract.parameter.as_ref().ok_or(RegistryError::MissingParameter)?;
        if let Ok(kind) = ContractType::try_from(contract.r#type) {
            return decode_builtin(kind, any).map(DecodedContract::BuiltIn);
        }
        let (&_, &index) = self.provider_by_type.get_key_value(&contract.r#type)
            .ok_or(RegistryError::InvalidContractType(contract.r#type))?;
        let registration = self.descriptors.registrations().iter()
            .find(|registration| registration.contract_type == contract.r#type)
            .expect("provider construction verifies the descriptor");
        if any.type_url != registration.type_url {
            return Err(RegistryError::TypeUrlMismatch { expected: registration.type_url.clone(), actual: any.type_url.clone() });
        }
        self.check_payload(index, any.value.len())?;
        Ok(DecodedContract::Extension { registration: registration.clone(), payload: any.value.clone() })
    }

    pub fn owner_address(&self, contract: &Contract) -> Result<Vec<u8>, RegistryError> {
        match self.decode(contract)? {
            DecodedContract::BuiltIn(contract) => Ok(contract.owner_address().to_vec()),
            DecodedContract::Extension { registration, payload } => {
                let index = self.provider_by_type[&registration.contract_type];
                catch_provider_panic(&registration.extension_id, || self.providers[index].provider.owner_address(&payload))?.map_err(provider_error)
            }
        }
    }

    pub fn actuator(&self, contract: &Contract) -> Result<Box<dyn Actuator>, RegistryError> {
        let any = contract.parameter.clone().ok_or(RegistryError::MissingParameter)?;
        if let Ok(kind) = ContractType::try_from(contract.r#type) {
            let actuator: Box<dyn Actuator> = match kind {
                ContractType::AccountCreateContract => Box::new(AccountCreateActuator::new(any).map_err(provider_error)?),
                ContractType::TransferContract => Box::new(TransferActuator::new(any).map_err(provider_error)?),
                ContractType::TransferAssetContract => Box::new(TransferAssetActuator::new(any).map_err(provider_error)?),
                ContractType::VoteWitnessContract => Box::new(VoteWitnessActuator::new(any).map_err(provider_error)?),
                ContractType::WitnessCreateContract => Box::new(WitnessCreateActuator::new(any).map_err(provider_error)?),
                ContractType::AssetIssueContract => Box::new(AssetIssueActuator::new(any).map_err(provider_error)?),
                ContractType::WitnessUpdateContract => Box::new(WitnessUpdateActuator::new(any).map_err(provider_error)?),
                ContractType::ParticipateAssetIssueContract => Box::new(ParticipateAssetIssueActuator::new(any).map_err(provider_error)?),
                ContractType::AccountUpdateContract => Box::new(AccountUpdateActuator::new(any).map_err(provider_error)?),
                ContractType::UnfreezeAssetContract => Box::new(UnfreezeAssetActuator::new(any).map_err(provider_error)?),
                ContractType::UpdateAssetContract => Box::new(UpdateAssetActuator::new(any).map_err(provider_error)?),
                ContractType::SetAccountIdContract => Box::new(SetAccountIdActuator::new(any).map_err(provider_error)?),
                ContractType::AccountPermissionUpdateContract => Box::new(AccountPermissionUpdateActuator::new(any).map_err(provider_error)?),
                _ => return Err(RegistryError::UnsupportedBuiltInActuator(kind)),
            };
            return Ok(actuator);
        }
        let index = *self.provider_by_type.get(&contract.r#type).ok_or(RegistryError::InvalidContractType(contract.r#type))?;
        let registration = self.descriptors.registrations().iter().find(|item| item.contract_type == contract.r#type).expect("verified registry");
        if any.type_url != registration.type_url { return Err(RegistryError::TypeUrlMismatch { expected: registration.type_url.clone(), actual: any.type_url }); }
        self.check_payload(index, any.value.len())?;
        let provider = &self.providers[index];
        let inner = catch_provider_panic(&provider.metadata.extension_id, || provider.provider.create_actuator(&any.value))?.map_err(provider_error)?;
        Ok(Box::new(DeclaredStateActuator { inner, allowed: provider.access.clone(), extension_id: provider.metadata.extension_id.clone() }))
    }

    pub fn execute(&self, contract: &Contract, session: &Session, result: Option<&mut ActuatorResult>, config: ExecutionConfig) -> Result<(), RegistryError> {
        self.actuator(contract)?.execute(session, result, config).map_err(provider_error)
    }

    fn check_payload(&self, index: usize, actual: usize) -> Result<(), RegistryError> {
        let metadata = &self.providers[index].metadata;
        if actual > metadata.max_payload_bytes {
            return Err(RegistryError::PayloadLimitExceeded { extension_id: metadata.extension_id.clone(), limit: metadata.max_payload_bytes, actual });
        }
        Ok(())
    }
}

struct DeclaredStateActuator {
    inner: Box<dyn Actuator>,
    allowed: DeclaredStoreAccess,
    extension_id: String,
}

impl Actuator for DeclaredStateActuator {
    fn owner_address(&self) -> Result<&[u8], ActuatorError> { catch_actuator_panic(&self.extension_id, || self.inner.owner_address())? }
    fn validate(&self, context: &ValidationContext<'_>) -> Result<(), ActuatorError> { catch_actuator_panic(&self.extension_id, || self.inner.validate(context))? }
    fn execute_in(&self, context: &mut ExecutionContext<'_>, result: &mut ActuatorResult) -> Result<(), ActuatorError> {
        catch_actuator_panic(&self.extension_id, || self.inner.execute_in(context, result))?
    }
    fn declared_access(&self) -> Option<&DeclaredStoreAccess> { Some(&self.allowed) }
}

fn provider_error(error: ActuatorError) -> RegistryError { RegistryError::Provider(error.message) }

fn catch_provider_panic<T>(extension_id: &str, call: impl FnOnce() -> T) -> Result<T, RegistryError> {
    catch_unwind(AssertUnwindSafe(call)).map_err(|_| RegistryError::ProviderPanicked(extension_id.to_owned()))
}

fn catch_actuator_panic<T>(extension_id: &str, call: impl FnOnce() -> T) -> Result<T, ActuatorError> {
    catch_unwind(AssertUnwindSafe(call)).map_err(|_| ActuatorError::execution(format!("extension provider {extension_id} panicked")))
}

pub fn is_extension_contract_type(value: i32) -> bool {
    (EXTENSION_CONTRACT_TYPE_MIN..=EXTENSION_CONTRACT_TYPE_MAX).contains(&value)
}
