//! Descriptor-only custom-actuator registration boundary from DR-004.
//!
//! This module deliberately does not expose actuator construction, owner extraction, execution,
//! state access, admission, or API behavior. Those seams belong to later porting domains.

use std::{
    collections::{BTreeMap, BTreeSet},
    sync::Arc,
};

use prost::Message;
use prost_reflect::{DescriptorPool, DynamicMessage, FileDescriptor, MessageDescriptor};
use prost_types::{DescriptorProto, EnumDescriptorProto, FileDescriptorProto, FileDescriptorSet, ServiceDescriptorProto};
use sha2::{Digest, Sha256};

use crate::FILE_DESCRIPTOR_SET;

pub const TYPE_URL_PREFIX: &str = "type.googleapis.com/";
pub const EXTENSION_CONTRACT_TYPE_MIN: i32 = 1_000;
pub const EXTENSION_CONTRACT_TYPE_MAX: i32 = 1_999;
pub const MAX_EXTENSION_BATCH_COUNT: usize = 64;
pub const MAX_EXTENSION_DESCRIPTOR_BYTES: usize = 1_048_576;
pub const MAX_EXTENSION_DESCRIPTOR_FILES: usize = 128;
pub const MAX_EXTENSION_DESCRIPTOR_SYMBOLS: usize = 8_192;
pub const MAX_EXTENSION_MESSAGE_NESTING: usize = 32;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExtensionDescriptor {
    pub extension_id: String,
    pub priority: i32,
    pub descriptor_set: Vec<u8>,
    pub descriptor_sha256: [u8; 32],
    pub message_full_name: String,
    pub contract_type: i32,
}

impl ExtensionDescriptor {
    #[must_use]
    pub fn type_url(&self) -> String {
        canonical_type_url(&self.message_full_name)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RegisteredExtension {
    pub extension_id: String,
    pub priority: i32,
    pub descriptor_sha256: [u8; 32],
    pub message_full_name: String,
    pub type_url: String,
    pub contract_type: i32,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RegistrationError {
    EmptyExtensionId,
    InvalidMessageFullName(String),
    MalformedDescriptor,
    DescriptorDigestMismatch,
    InvalidDescriptorSemantics,
    BatchCountLimitExceeded,
    DescriptorBytesLimitExceeded,
    DescriptorFilesLimitExceeded,
    DescriptorSymbolsLimitExceeded,
    DescriptorNestingLimitExceeded,
    MessageMissing(String),
    ContractTypeOutOfRange(i32),
    BuiltInFullNameCollision(String),
    BuiltInContractTypeCollision(i32),
    ExtensionIdCollision(String),
    ExtensionFileNameCollision(String),
    ExtensionFullNameCollision(String),
    ExtensionSymbolCollision(String),
    ExtensionContractTypeCollision(i32),
}

#[derive(Debug)]
struct RetainedDescriptor {
    bytes: Arc<[u8]>,
    descriptor_set: FileDescriptorSet,
}

#[derive(Debug)]
pub struct ExtensionRegistry {
    registrations: Vec<RegisteredExtension>,
    registration_by_id: BTreeMap<String, usize>,
    retained_descriptors: Vec<RetainedDescriptor>,
    descriptor_pool: DescriptorPool,
}

impl ExtensionRegistry {
    /// Validates the complete batch before publishing any registration.
    pub fn register(
        descriptors: impl IntoIterator<Item = ExtensionDescriptor>,
    ) -> Result<Self, RegistrationError> {
        let canonical = FileDescriptorSet::decode(FILE_DESCRIPTOR_SET)
            .expect("the build verifies the embedded canonical descriptor");
        let canonical_inventory = descriptor_inventory(&canonical)
            .expect("the build verifies the embedded canonical descriptor structure");
        // Type URLs are canonical functions of full names, so they have no independent
        // collision identity.
        let built_in_contract_types = contract_type_numbers(&canonical);

        let mut bounded_descriptors: Vec<ExtensionDescriptor> = Vec::new();
        for descriptor in descriptors.into_iter() {
            if bounded_descriptors.len() == MAX_EXTENSION_BATCH_COUNT {
                return Err(RegistrationError::BatchCountLimitExceeded);
            }
            bounded_descriptors.push(descriptor);
        }
        bounded_descriptors.sort_by(|left, right| {
            (left.priority, left.extension_id.as_str())
                .cmp(&(right.priority, right.extension_id.as_str()))
        });

        let mut extension_ids = BTreeSet::new();
        let mut file_names = BTreeSet::new();
        let mut symbols = BTreeSet::new();
        let mut selected_names = BTreeSet::new();
        let mut contract_types = BTreeSet::new();
        let mut registrations = Vec::with_capacity(bounded_descriptors.len());
        let mut retained_descriptors = Vec::with_capacity(bounded_descriptors.len());
        let mut pooled_descriptor_set = canonical;

        for descriptor in bounded_descriptors {
            validate_identity(&descriptor)?;
            if descriptor.descriptor_set.len() > MAX_EXTENSION_DESCRIPTOR_BYTES {
                return Err(RegistrationError::DescriptorBytesLimitExceeded);
            }
            let digest: [u8; 32] = Sha256::digest(&descriptor.descriptor_set).into();
            if digest != descriptor.descriptor_sha256 {
                return Err(RegistrationError::DescriptorDigestMismatch);
            }
            let decoded = FileDescriptorSet::decode(descriptor.descriptor_set.as_slice())
                .map_err(|_| RegistrationError::MalformedDescriptor)?;
            let inventory = descriptor_inventory(&decoded)?;
            if !inventory.messages.contains(&descriptor.message_full_name) {
                return Err(RegistrationError::MessageMissing(descriptor.message_full_name));
            }
            let type_url = descriptor.type_url();

            if canonical_inventory.symbols.contains(&descriptor.message_full_name) {
                return Err(RegistrationError::BuiltInFullNameCollision(
                    descriptor.message_full_name,
                ));
            }
            if built_in_contract_types.contains(&descriptor.contract_type) {
                return Err(RegistrationError::BuiltInContractTypeCollision(
                    descriptor.contract_type,
                ));
            }
            if !(EXTENSION_CONTRACT_TYPE_MIN..=EXTENSION_CONTRACT_TYPE_MAX)
                .contains(&descriptor.contract_type)
            {
                return Err(RegistrationError::ContractTypeOutOfRange(
                    descriptor.contract_type,
                ));
            }
            if !extension_ids.insert(descriptor.extension_id.clone()) {
                return Err(RegistrationError::ExtensionIdCollision(
                    descriptor.extension_id,
                ));
            }
            if !selected_names.insert(descriptor.message_full_name.clone()) {
                return Err(RegistrationError::ExtensionFullNameCollision(
                    descriptor.message_full_name,
                ));
            }
            for file_name in inventory.files {
                if canonical_inventory.files.contains(&file_name)
                    || !file_names.insert(file_name.clone())
                {
                    return Err(RegistrationError::ExtensionFileNameCollision(file_name));
                }
            }
            for symbol in inventory.symbols {
                if canonical_inventory.symbols.contains(&symbol) {
                    return Err(RegistrationError::BuiltInFullNameCollision(symbol));
                }
                if !symbols.insert(symbol.clone()) {
                    return Err(RegistrationError::ExtensionSymbolCollision(symbol));
                }
            }
            if !contract_types.insert(descriptor.contract_type) {
                return Err(RegistrationError::ExtensionContractTypeCollision(
                    descriptor.contract_type,
                ));
            }

            pooled_descriptor_set.file.extend(decoded.file.iter().cloned());
            registrations.push(RegisteredExtension {
                extension_id: descriptor.extension_id,
                priority: descriptor.priority,
                descriptor_sha256: digest,
                message_full_name: descriptor.message_full_name,
                type_url,
                contract_type: descriptor.contract_type,
            });
            retained_descriptors.push(RetainedDescriptor {
                bytes: descriptor.descriptor_set.into(),
                descriptor_set: decoded,
            });
        }

        let descriptor_pool = DescriptorPool::from_file_descriptor_set(pooled_descriptor_set)
            .map_err(|_| RegistrationError::InvalidDescriptorSemantics)?;
        let registration_by_id = registrations
            .iter()
            .enumerate()
            .map(|(index, registration)| (registration.extension_id.clone(), index))
            .collect();

        Ok(Self {
            registrations,
            registration_by_id,
            retained_descriptors,
            descriptor_pool,
        })
    }

    #[must_use]
    pub fn registrations(&self) -> &[RegisteredExtension] {
        &self.registrations
    }

    #[must_use]
    pub fn resolve_extension(&self, extension_id: &str) -> Option<&RegisteredExtension> {
        self.registration_by_id
            .get(extension_id)
            .map(|&index| &self.registrations[index])
    }

    #[must_use]
    pub fn descriptor_bytes(&self, extension_id: &str) -> Option<&[u8]> {
        self.registration_by_id
            .get(extension_id)
            .map(|&index| self.retained_descriptors[index].bytes.as_ref())
    }

    #[must_use]
    pub fn descriptor_set(&self, extension_id: &str) -> Option<&FileDescriptorSet> {
        self.registration_by_id
            .get(extension_id)
            .map(|&index| &self.retained_descriptors[index].descriptor_set)
    }

    #[must_use]
    pub fn file_by_name(&self, name: &str) -> Option<FileDescriptor> {
        self.descriptor_pool.get_file_by_name(name)
    }

    #[must_use]
    pub fn message_by_name(&self, full_name: &str) -> Option<MessageDescriptor> {
        self.descriptor_pool.get_message_by_name(full_name)
    }

    pub fn decode_message(
        &self,
        full_name: &str,
        bytes: &[u8],
    ) -> Result<Option<DynamicMessage>, prost::DecodeError> {
        self.message_by_name(full_name)
            .map(|descriptor| DynamicMessage::decode(descriptor, bytes))
            .transpose()
    }
}

#[must_use]
pub fn canonical_type_url(message_full_name: &str) -> String {
    format!("{TYPE_URL_PREFIX}{message_full_name}")
}

fn validate_identity(descriptor: &ExtensionDescriptor) -> Result<(), RegistrationError> {
    if descriptor.extension_id.trim().is_empty() {
        return Err(RegistrationError::EmptyExtensionId);
    }
    if !is_full_name(&descriptor.message_full_name) {
        return Err(RegistrationError::InvalidMessageFullName(
            descriptor.message_full_name.clone(),
        ));
    }
    Ok(())
}

fn is_full_name(name: &str) -> bool {
    name.split('.').count() >= 2 && name.split('.').all(is_identifier)
}

fn is_identifier(name: &str) -> bool {
    !name.is_empty()
        && name.bytes().enumerate().all(|(index, byte)| {
            byte == b'_' || byte.is_ascii_alphanumeric() && (index > 0 || !byte.is_ascii_digit())
        })
}

#[derive(Debug)]
struct DescriptorInventory {
    files: BTreeSet<String>,
    symbols: BTreeSet<String>,
    messages: BTreeSet<String>,
}

fn descriptor_inventory(descriptor: &FileDescriptorSet) -> Result<DescriptorInventory, RegistrationError> {
    if descriptor.file.len() > MAX_EXTENSION_DESCRIPTOR_FILES {
        return Err(RegistrationError::DescriptorFilesLimitExceeded);
    }
    let mut inventory = DescriptorInventory {
        files: BTreeSet::new(),
        symbols: BTreeSet::new(),
        messages: BTreeSet::new(),
    };
    for file in &descriptor.file {
        let file_name = file.name.clone().ok_or(RegistrationError::MalformedDescriptor)?;
        if !inventory.files.insert(file_name.clone()) {
            return Err(RegistrationError::ExtensionFileNameCollision(file_name));
        }
        let package = file.package.as_deref().unwrap_or_default();
        for message in &file.message_type {
            collect_message_symbols(package, message, 1, &mut inventory)?;
        }
        for kind in &file.enum_type {
            collect_enum_symbols(package, kind, &mut inventory)?;
        }
        for service in &file.service {
            collect_service_symbols(package, service, &mut inventory)?;
        }
        for extension in &file.extension {
            insert_named_symbol(package, extension.name.as_deref(), &mut inventory.symbols)?;
        }
    }
    Ok(inventory)
}

fn collect_message_symbols(
    prefix: &str,
    message: &DescriptorProto,
    depth: usize,
    inventory: &mut DescriptorInventory,
) -> Result<(), RegistrationError> {
    if depth > MAX_EXTENSION_MESSAGE_NESTING {
        return Err(RegistrationError::DescriptorNestingLimitExceeded);
    }
    let full_name = insert_named_symbol(prefix, message.name.as_deref(), &mut inventory.symbols)?;
    inventory.messages.insert(full_name.clone());
    for field in &message.field {
        insert_named_symbol(&full_name, field.name.as_deref(), &mut inventory.symbols)?;
    }
    for extension in &message.extension {
        insert_named_symbol(&full_name, extension.name.as_deref(), &mut inventory.symbols)?;
    }
    for kind in &message.enum_type {
        collect_enum_symbols(&full_name, kind, inventory)?;
    }
    for nested in &message.nested_type {
        collect_message_symbols(&full_name, nested, depth + 1, inventory)?;
    }
    Ok(())
}

fn collect_enum_symbols(
    prefix: &str,
    kind: &EnumDescriptorProto,
    inventory: &mut DescriptorInventory,
) -> Result<(), RegistrationError> {
    insert_named_symbol(prefix, kind.name.as_deref(), &mut inventory.symbols)?;
    for value in &kind.value {
        insert_named_symbol(prefix, value.name.as_deref(), &mut inventory.symbols)?;
    }
    Ok(())
}

fn collect_service_symbols(
    prefix: &str,
    service: &ServiceDescriptorProto,
    inventory: &mut DescriptorInventory,
) -> Result<(), RegistrationError> {
    let full_name = insert_named_symbol(prefix, service.name.as_deref(), &mut inventory.symbols)?;
    for method in &service.method {
        insert_named_symbol(&full_name, method.name.as_deref(), &mut inventory.symbols)?;
    }
    Ok(())
}

fn insert_named_symbol(
    prefix: &str,
    name: Option<&str>,
    symbols: &mut BTreeSet<String>,
) -> Result<String, RegistrationError> {
    let name = name.ok_or(RegistrationError::MalformedDescriptor)?;
    if !is_identifier(name) {
        return Err(RegistrationError::InvalidDescriptorSemantics);
    }
    let full_name = if prefix.is_empty() { name.to_owned() } else { format!("{prefix}.{name}") };
    if symbols.len() == MAX_EXTENSION_DESCRIPTOR_SYMBOLS {
        return Err(RegistrationError::DescriptorSymbolsLimitExceeded);
    }
    if !symbols.insert(full_name.clone()) {
        return Err(RegistrationError::ExtensionSymbolCollision(full_name));
    }
    Ok(full_name)
}

fn contract_type_numbers(descriptor: &FileDescriptorSet) -> BTreeSet<i32> {
    let files: BTreeMap<_, _> = descriptor
        .file
        .iter()
        .filter_map(|file| file.name.as_deref().map(|name| (name, file)))
        .collect();
    files
        .get("core/Tron.proto")
        .and_then(|file| find_message(file, "Transaction"))
        .and_then(|transaction| find_nested_message(transaction, "Contract"))
        .and_then(|contract| contract.enum_type.iter().find(|item| item.name.as_deref() == Some("ContractType")))
        .into_iter()
        .flat_map(|kind| kind.value.iter().filter_map(|value| value.number))
        .collect()
}

fn find_message<'a>(file: &'a FileDescriptorProto, name: &str) -> Option<&'a DescriptorProto> {
    file.message_type
        .iter()
        .find(|message| message.name.as_deref() == Some(name))
}

fn find_nested_message<'a>(message: &'a DescriptorProto, name: &str) -> Option<&'a DescriptorProto> {
    message
        .nested_type
        .iter()
        .find(|nested| nested.name.as_deref() == Some(name))
}
