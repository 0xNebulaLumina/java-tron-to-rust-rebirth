use prost::Message;
use prost_types::{
    field_descriptor_proto::{Label, Type},
    DescriptorProto, FieldDescriptorProto, FileDescriptorProto, FileDescriptorSet,
};
use sha2::{Digest, Sha256};
use tron_protocol::extensions::{
    ExtensionDescriptor, ExtensionRegistry, RegistrationError, EXTENSION_CONTRACT_TYPE_MIN,
    MAX_EXTENSION_BATCH_COUNT, MAX_EXTENSION_DESCRIPTOR_BYTES, MAX_EXTENSION_DESCRIPTOR_FILES,
    MAX_EXTENSION_DESCRIPTOR_SYMBOLS, MAX_EXTENSION_MESSAGE_NESTING,
};

const EXAMPLE_DESCRIPTOR: &[u8] = include_bytes!("fixtures/extensions/example_actuator.pb");
const BUILTIN_COLLISION_DESCRIPTOR: &[u8] =
    include_bytes!("fixtures/extensions/builtin_name_collision.pb");
const MALFORMED_DESCRIPTOR: &[u8] = include_bytes!("fixtures/extensions/malformed_descriptor.bin");
const ALTERNATE_DESCRIPTOR: &[u8] = include_bytes!("fixtures/extensions/alternate_actuator.pb");
const UNIQUE_BUILTIN_COLLISION_DESCRIPTOR: &[u8] =
    include_bytes!("fixtures/extensions/unique_selected_builtin_collision.pb");
const CROSS_COLLISION_ONE: &[u8] = include_bytes!("fixtures/extensions/cross_collision_one.pb");
const CROSS_COLLISION_TWO: &[u8] = include_bytes!("fixtures/extensions/cross_collision_two.pb");

#[test]
fn registers_in_priority_then_extension_id_order_across_input_permutations() {
    let forward = [
        renamed("zeta", 0, 1_001),
        example("beta", 0, 1_000),
    ];
    let reverse = [
        example("beta", 0, 1_000),
        renamed("zeta", 0, 1_001),
    ];

    for descriptors in [forward, reverse] {
        let registry = ExtensionRegistry::register(descriptors).unwrap();
        assert_eq!(
            registry
                .registrations()
                .iter()
                .map(|item| item.extension_id.as_str())
                .collect::<Vec<_>>(),
            ["beta", "zeta"]
        );
        assert_eq!(
            registry.registrations()[0].type_url,
            "type.googleapis.com/org.tron.example.actuator.ExampleContract"
        );
        assert_eq!(
            registry.registrations()[0].contract_type,
            EXTENSION_CONTRACT_TYPE_MIN
        );
    }
}

#[test]
fn registers_resolves_and_dynamically_decodes_retained_descriptor() {
    let registry = ExtensionRegistry::register([example("runtime", 0, 1_000)]).unwrap();
    let registration = registry.resolve_extension("runtime").unwrap();
    assert_eq!(
        registration.message_full_name,
        "org.tron.example.actuator.ExampleContract"
    );
    assert_eq!(registry.descriptor_bytes("runtime"), Some(EXAMPLE_DESCRIPTOR));

    let retained = registry.descriptor_set("runtime").unwrap();
    let file_name = retained.file[0].name.as_deref().unwrap();
    assert_eq!(registry.file_by_name(file_name).unwrap().name(), file_name);
    assert!(registry
        .message_by_name(&registration.message_full_name)
        .is_some());

    let encoded = include_bytes!("fixtures/extensions/example_contract.bin");
    let decoded = registry
        .decode_message(&registration.message_full_name, encoded)
        .unwrap()
        .unwrap();
    assert_eq!(
        decoded
            .get_field_by_name("payload")
            .unwrap()
            .as_bytes()
            .map(|payload| payload.as_ref()),
        Some(&b"example"[..])
    );
}

#[test]
fn rejects_malformed_descriptor_semantics_before_publication() {
    let invalid_identifier = semantic_descriptor(|file| {
        file.message_type.push(DescriptorProto {
            name: Some("9Invalid".to_owned()),
            ..Default::default()
        });
    });
    assert_semantic_error(invalid_identifier);

    let empty_secondary_symbol = semantic_descriptor(|file| {
        file.message_type[0].field.push(FieldDescriptorProto {
            name: Some(String::new()),
            number: Some(1),
            label: Some(Label::Optional as i32),
            r#type: Some(Type::String as i32),
            ..Default::default()
        });
    });
    assert_semantic_error(empty_secondary_symbol);

    let missing_dependency = semantic_descriptor(|file| {
        file.dependency.push("missing.proto".to_owned());
    });
    assert_semantic_error(missing_dependency);

    let unresolved_reference = semantic_descriptor(|file| {
        file.message_type[0].field.push(FieldDescriptorProto {
            name: Some("missing".to_owned()),
            number: Some(1),
            label: Some(Label::Optional as i32),
            r#type: Some(Type::Message as i32),
            type_name: Some(".runtime.Missing".to_owned()),
            ..Default::default()
        });
    });
    assert_semantic_error(unresolved_reference);
}

#[test]
fn rejects_malformed_or_digest_mismatched_descriptors() {
    let mut malformed = example("malformed", 0, 1_000);
    malformed.descriptor_set = MALFORMED_DESCRIPTOR.to_vec();
    malformed.descriptor_sha256 = digest(MALFORMED_DESCRIPTOR);
    assert_eq!(
        ExtensionRegistry::register([malformed]).unwrap_err(),
        RegistrationError::MalformedDescriptor
    );

    let mut mismatch = example("digest", 0, 1_000);
    mismatch.descriptor_set = MALFORMED_DESCRIPTOR.to_vec();
    mismatch.descriptor_sha256 = [0; 32];
    assert_eq!(
        ExtensionRegistry::register([mismatch]).unwrap_err(),
        RegistrationError::DescriptorDigestMismatch
    );
}

#[test]
fn construction_is_all_or_error_when_a_late_entry_is_invalid() {
    let late_duplicate = synthetic_descriptor(
        "late.proto",
        &["org.tron.late.LateContract"],
        "org.tron.late.LateContract",
        1_001,
    );

    let result = ExtensionRegistry::register([
        example("accepted-first", 0, 1_000),
        renamed("accepted-second", 1, 1_001),
        late_duplicate,
    ]);

    assert_eq!(
        result.unwrap_err(),
        RegistrationError::ExtensionContractTypeCollision(1_001)
    );
}

#[test]
fn rejects_every_representable_collision_boundary() {
    let duplicate_id = [example("same", 0, 1_000), renamed("same", 1, 1_001)];
    assert_eq!(
        ExtensionRegistry::register(duplicate_id).unwrap_err(),
        RegistrationError::ExtensionIdCollision("same".to_owned())
    );

    let duplicate_name = [example("one", 0, 1_000), example("two", 1, 1_001)];
    assert_eq!(
        ExtensionRegistry::register(duplicate_name).unwrap_err(),
        RegistrationError::ExtensionFullNameCollision(
            "org.tron.example.actuator.ExampleContract".to_owned()
        )
    );

    let duplicate_number = [example("one", 0, 1_000), renamed("two", 1, 1_000)];
    assert_eq!(
        ExtensionRegistry::register(duplicate_number).unwrap_err(),
        RegistrationError::ExtensionContractTypeCollision(1_000)
    );

    let builtin_number = example("builtin-number", 0, 20);
    assert_eq!(
        ExtensionRegistry::register([builtin_number]).unwrap_err(),
        RegistrationError::BuiltInContractTypeCollision(20)
    );

    let out_of_range = example("out-of-range", 0, 999);
    assert_eq!(
        ExtensionRegistry::register([out_of_range]).unwrap_err(),
        RegistrationError::ContractTypeOutOfRange(999)
    );

    let builtin = ExtensionDescriptor {
        extension_id: "builtin-name".to_owned(),
        priority: 0,
        descriptor_set: BUILTIN_COLLISION_DESCRIPTOR.to_vec(),
        descriptor_sha256: digest(BUILTIN_COLLISION_DESCRIPTOR),
        message_full_name: "protocol.Account".to_owned(),
        contract_type: 1_000,
    };
    assert_eq!(
        ExtensionRegistry::register([builtin]).unwrap_err(),
        RegistrationError::BuiltInFullNameCollision("protocol.Account".to_owned())
    );
}

#[test]
fn rejects_secondary_symbols_even_when_selected_message_is_unique() {
    let builtin = fixture_descriptor(
        "secondary-builtin",
        UNIQUE_BUILTIN_COLLISION_DESCRIPTOR,
        "org.tron.extension.guard.UniqueSelectedContract",
        1_000,
    );
    assert_eq!(
        ExtensionRegistry::register([builtin]).unwrap_err(),
        RegistrationError::BuiltInFullNameCollision("protocol.Account".to_owned())
    );

    let first = fixture_descriptor(
        "cross-one",
        CROSS_COLLISION_ONE,
        "org.tron.extension.shared.FirstSelectedContract",
        1_000,
    );
    let second = fixture_descriptor(
        "cross-two",
        CROSS_COLLISION_TWO,
        "org.tron.extension.shared.SecondSelectedContract",
        1_001,
    );
    assert_eq!(
        ExtensionRegistry::register([first, second]).unwrap_err(),
        RegistrationError::ExtensionSymbolCollision(
            "org.tron.extension.shared.SecondaryCollision".to_owned()
        )
    );
}

#[test]
fn rejects_duplicate_file_names_with_distinct_selected_messages() {
    let first = synthetic_descriptor("duplicate.proto", &["pkg.First"], "pkg.First", 1_000);
    let second = synthetic_descriptor("duplicate.proto", &["pkg.Second"], "pkg.Second", 1_001);
    assert_eq!(
        ExtensionRegistry::register([first, second]).unwrap_err(),
        RegistrationError::ExtensionFileNameCollision("duplicate.proto".to_owned())
    );
}

#[test]
fn enforces_batch_and_descriptor_resource_boundaries() {
    let batch = (0..=MAX_EXTENSION_BATCH_COUNT).map(|index| {
        fixture_descriptor(
            &format!("batch-{index}"),
            EXAMPLE_DESCRIPTOR,
            "org.tron.example.actuator.ExampleContract",
            1_000,
        )
    });
    assert_eq!(
        ExtensionRegistry::register(batch).unwrap_err(),
        RegistrationError::BatchCountLimitExceeded
    );

    let mut oversized = example("oversized", 0, 1_000);
    oversized.descriptor_set = vec![0; MAX_EXTENSION_DESCRIPTOR_BYTES + 1];
    oversized.descriptor_sha256 = digest(&oversized.descriptor_set);
    assert_eq!(
        ExtensionRegistry::register([oversized]).unwrap_err(),
        RegistrationError::DescriptorBytesLimitExceeded
    );

    let files = FileDescriptorSet {
        file: (0..=MAX_EXTENSION_DESCRIPTOR_FILES)
            .map(|index| file(&format!("file-{index}.proto"), "pkg", &["Selected"]))
            .collect(),
    };
    assert_resource_error(files, RegistrationError::DescriptorFilesLimitExceeded);

    let names = (0..=MAX_EXTENSION_DESCRIPTOR_SYMBOLS)
        .map(|index| format!("Message{index}"))
        .collect::<Vec<_>>();
    let name_refs = names.iter().map(String::as_str).collect::<Vec<_>>();
    let symbols = FileDescriptorSet { file: vec![file("symbols.proto", "pkg", &name_refs)] };
    assert_resource_error(symbols, RegistrationError::DescriptorSymbolsLimitExceeded);

    let mut nested = DescriptorProto { name: Some(format!("Level{MAX_EXTENSION_MESSAGE_NESTING}")), ..Default::default() };
    for depth in (0..MAX_EXTENSION_MESSAGE_NESTING).rev() {
        nested = DescriptorProto {
            name: Some(format!("Level{depth}")),
            nested_type: vec![nested],
            ..Default::default()
        };
    }
    let nesting = FileDescriptorSet {
        file: vec![FileDescriptorProto {
            name: Some("nesting.proto".to_owned()),
            package: Some("pkg".to_owned()),
            message_type: vec![nested],
            ..Default::default()
        }],
    };
    assert_resource_error(nesting, RegistrationError::DescriptorNestingLimitExceeded);
}

#[test]
fn canonical_extension_bytes_are_stable() {
    assert_eq!(
        hex(include_bytes!("fixtures/extensions/example_contract.bin")),
        "0a1541111111111111111111111111111111111111111112076578616d706c65"
    );
    assert_eq!(
        hex(include_bytes!("fixtures/extensions/example_any.bin")),
        "0a3d747970652e676f6f676c65617069732e636f6d2f6f72672e74726f6e2e6578616d706c652e6163747561746f722e4578616d706c65436f6e747261637412200a1541111111111111111111111111111111111111111112076578616d706c65"
    );
    assert_eq!(
        hex(include_bytes!("fixtures/extensions/example_transaction_contract.bin")),
        "08e80712610a3d747970652e676f6f676c65617069732e636f6d2f6f72672e74726f6e2e6578616d706c652e6163747561746f722e4578616d706c65436f6e747261637412200a1541111111111111111111111111111111111111111112076578616d706c65"
    );
}

fn example(id: &str, priority: i32, contract_type: i32) -> ExtensionDescriptor {
    ExtensionDescriptor {
        extension_id: id.to_owned(),
        priority,
        descriptor_set: EXAMPLE_DESCRIPTOR.to_vec(),
        descriptor_sha256: digest(EXAMPLE_DESCRIPTOR),
        message_full_name: "org.tron.example.actuator.ExampleContract".to_owned(),
        contract_type,
    }
}

fn renamed(id: &str, priority: i32, contract_type: i32) -> ExtensionDescriptor {
    fixture_descriptor(
        id,
        ALTERNATE_DESCRIPTOR,
        "org.tron.example.alternate.AlternateContract",
        contract_type,
    )
    .with_priority(priority)
}

trait WithPriority {
    fn with_priority(self, priority: i32) -> Self;
}

impl WithPriority for ExtensionDescriptor {
    fn with_priority(mut self, priority: i32) -> Self {
        self.priority = priority;
        self
    }
}

fn fixture_descriptor(
    id: &str,
    bytes: &[u8],
    message_full_name: &str,
    contract_type: i32,
) -> ExtensionDescriptor {
    ExtensionDescriptor {
        extension_id: id.to_owned(),
        priority: 0,
        descriptor_set: bytes.to_vec(),
        descriptor_sha256: digest(bytes),
        message_full_name: message_full_name.to_owned(),
        contract_type,
    }
}

fn synthetic_descriptor(
    file_name: &str,
    messages: &[&str],
    selected: &str,
    contract_type: i32,
) -> ExtensionDescriptor {
    let (package, _) = selected.rsplit_once('.').unwrap();
    let set = FileDescriptorSet { file: vec![file(file_name, package, messages.iter().map(|name| name.rsplit_once('.').unwrap().1).collect::<Vec<_>>().as_slice())] };
    let bytes = set.encode_to_vec();
    fixture_descriptor(selected, &bytes, selected, contract_type)
}

fn file(name: &str, package: &str, messages: &[&str]) -> FileDescriptorProto {
    FileDescriptorProto {
        name: Some(name.to_owned()),
        package: Some(package.to_owned()),
        message_type: messages.iter().map(|name| DescriptorProto { name: Some((*name).to_owned()), ..Default::default() }).collect(),
        syntax: Some("proto3".to_owned()),
        ..Default::default()
    }
}

fn assert_resource_error(set: FileDescriptorSet, expected: RegistrationError) {
    let bytes = set.encode_to_vec();
    let descriptor = fixture_descriptor("resource", &bytes, "pkg.Selected", 1_000);
    assert_eq!(ExtensionRegistry::register([descriptor]).unwrap_err(), expected);
}

fn semantic_descriptor(mutate: impl FnOnce(&mut FileDescriptorProto)) -> ExtensionDescriptor {
    let mut descriptor_file = file("runtime.proto", "runtime", &["Selected"]);
    mutate(&mut descriptor_file);
    let bytes = FileDescriptorSet {
        file: vec![descriptor_file],
    }
    .encode_to_vec();
    fixture_descriptor("semantic", &bytes, "runtime.Selected", 1_000)
}

fn assert_semantic_error(descriptor: ExtensionDescriptor) {
    assert_eq!(
        ExtensionRegistry::register([descriptor]).unwrap_err(),
        RegistrationError::InvalidDescriptorSemantics
    );
}

fn digest(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}
