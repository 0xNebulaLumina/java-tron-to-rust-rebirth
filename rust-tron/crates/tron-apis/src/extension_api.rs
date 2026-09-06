use std::sync::Arc;
use tron_execution::{ActuatorRegistry, RawWireTransaction, RegistryError};
use tron_protocol::{
    google::protobuf::Any,
    protocol::{Transaction, TransactionExtention, transaction::Contract},
};

use crate::{ApiError, WalletMutation};

pub const EXTENSION_API_DISABLED: &str = "wallet extension API is disabled";

#[derive(Clone)]
pub struct ExtensionApi {
    registry: Arc<ActuatorRegistry>,
    wallet: WalletMutation,
    enabled: bool,
}

impl ExtensionApi {
    #[must_use]
    pub fn new(registry: Arc<ActuatorRegistry>, wallet: WalletMutation, enabled: bool) -> Self {
        Self {
            registry,
            wallet,
            enabled,
        }
    }

    pub fn construct(
        &self,
        extension_id: &str,
        payload: Vec<u8>,
    ) -> Result<TransactionExtention, ApiError> {
        self.require_enabled()?;
        let registration = self
            .registry
            .descriptors()
            .resolve_extension(extension_id)
            .ok_or_else(|| {
                ApiError::InvalidArgument(format!("unknown extension {extension_id}"))
            })?;
        self.wallet
            .create_extension(registration.contract_type, &registration.type_url, payload)
    }

    pub fn owner_address(&self, transaction: &Transaction) -> Result<Vec<u8>, ApiError> {
        self.require_enabled()?;
        let contract = only_contract(transaction)?;
        self.registry
            .owner_address(contract)
            .map_err(registry_error)
    }
    pub fn broadcast(
        &self,
        raw_transaction: Vec<u8>,
        received_at: i64,
    ) -> Result<tron_protocol::protocol::Return, ApiError> {
        self.require_enabled()?;
        let wire = RawWireTransaction::decode(raw_transaction)
            .map_err(|error| ApiError::InvalidArgument(error.to_string()))?;
        self.registry
            .decode(only_contract(wire.message())?)
            .map_err(registry_error)?;
        Ok(self.wallet.broadcast_raw(wire.full_bytes().to_vec(), received_at, false))
    }

    pub fn decode_payload(
        &self,
        transaction: &Transaction,
    ) -> Result<prost_reflect::DynamicMessage, ApiError> {
        self.require_enabled()?;
        let contract = only_contract(transaction)?;
        let parameter = contract.parameter.as_ref().ok_or_else(|| {
            ApiError::InvalidArgument("extension contract parameter is missing".into())
        })?;
        let registration = self
            .registry
            .descriptors()
            .registrations()
            .iter()
            .find(|item| item.contract_type == contract.r#type)
            .ok_or_else(|| {
                ApiError::InvalidArgument(format!(
                    "unknown extension contract type {}",
                    contract.r#type
                ))
            })?;
        if parameter.type_url != registration.type_url {
            return Err(ApiError::InvalidArgument(format!(
                "extension type URL mismatch: expected {}, got {}",
                registration.type_url, parameter.type_url
            )));
        }
        self.registry
            .descriptors()
            .decode_message(&registration.message_full_name, &parameter.value)
            .map_err(|error| ApiError::InvalidArgument(error.to_string()))?
            .ok_or_else(|| {
                ApiError::InvalidArgument(format!(
                    "unknown extension message {}",
                    registration.message_full_name
                ))
            })
    }

    #[must_use]
    pub fn contract(extension_type: i32, type_url: String, payload: Vec<u8>) -> Contract {
        Contract {
            r#type: extension_type,
            parameter: Some(Any {
                type_url,
                value: payload,
            }),
            ..Default::default()
        }
    }

    fn require_enabled(&self) -> Result<(), ApiError> {
        if self.enabled {
            Ok(())
        } else {
            Err(ApiError::Unavailable(EXTENSION_API_DISABLED.into()))
        }
    }
}

fn only_contract(transaction: &Transaction) -> Result<&Contract, ApiError> {
    let contracts = transaction
        .raw_data
        .as_ref()
        .map_or(&[][..], |raw| raw.contract.as_slice());
    if contracts.len() != 1 {
        return Err(ApiError::InvalidArgument(
            "transaction must contain exactly one extension contract".into(),
        ));
    }
    Ok(&contracts[0])
}
fn registry_error(error: RegistryError) -> ApiError {
    ApiError::InvalidArgument(format!("{error:?}"))
}
