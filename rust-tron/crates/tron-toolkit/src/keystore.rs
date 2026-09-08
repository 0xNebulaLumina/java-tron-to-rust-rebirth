use crate::cli::{
    ImportKeystoreArgs, KeystoreCommand, ListKeystoreArgs, NewKeystoreArgs, UpdateKeystoreArgs,
};
use crate::error::{CommandOutput, ErrorCategory, ToolkitError};
use crate::io::{CommandContext, KeyProvider, SecretPrompt, SecretSource};
use rand_core::{CryptoRng, Error as RandomError, RngCore};
use std::path::Path;
use sha2::{Digest, Sha256};
use time::{OffsetDateTime, UtcOffset};
use tron_crypto::keystore::{password_valid, read_update_password_file};
use tron_crypto::keystore_store::{
    self, ListReport, StoreError, StoreWarning, StoredKeystore,
};
use tron_crypto::{
    CryptoEngine, PrivateKey, derive_address, encode_address_base58check,
};
use zeroize::{Zeroize, Zeroizing};

const ENTROPY_SEED_BYTES: usize = 32;

pub trait KeystoreServices {
    fn new_keystore(
        &mut self,
        destination: &Path,
        password: &str,
        key: &PrivateKey,
        checksum_engine: CryptoEngine,
        entropy: &mut OperationEntropy,
        warning_sink: &mut dyn FnMut(&StoreWarning),
    ) -> Result<StoredKeystore, StoreError>;

    fn import_keystore(
        &mut self,
        directory: &Path,
        destination: &Path,
        password: &str,
        key: &PrivateKey,
        checksum_engine: CryptoEngine,
        force_duplicate: bool,
        entropy: &mut OperationEntropy,
        warning_sink: &mut dyn FnMut(&StoreWarning),
    ) -> Result<StoredKeystore, StoreError>;

    fn list_keystores(&mut self, directory: &Path) -> Result<ListReport, StoreError>;

    fn update_keystore(
        &mut self,
        directory: &Path,
        address: &str,
        old_password: &str,
        new_password: &str,
        key_engine: CryptoEngine,
        checksum_engine: CryptoEngine,
        entropy: &mut OperationEntropy,
        warning_sink: &mut dyn FnMut(&StoreWarning),
    ) -> Result<StoredKeystore, StoreError>;
}

/// Production facade over the C005/C027 keystore seam. It contains no ambient
/// providers; all key material and randomness are supplied by the dispatcher.
#[derive(Default)]
pub struct CryptoKeystoreServices;

impl KeystoreServices for CryptoKeystoreServices {
    fn new_keystore(
        &mut self,
        destination: &Path,
        password: &str,
        key: &PrivateKey,
        checksum_engine: CryptoEngine,
        entropy: &mut OperationEntropy,
        warning_sink: &mut dyn FnMut(&StoreWarning),
    ) -> Result<StoredKeystore, StoreError> {
        keystore_store::new_keystore_reporting(
            destination,
            password,
            key,
            checksum_engine,
            false,
            entropy,
            warning_sink,
        )
    }

    fn import_keystore(
        &mut self,
        directory: &Path,
        destination: &Path,
        password: &str,
        key: &PrivateKey,
        checksum_engine: CryptoEngine,
        force_duplicate: bool,
        entropy: &mut OperationEntropy,
        warning_sink: &mut dyn FnMut(&StoreWarning),
    ) -> Result<StoredKeystore, StoreError> {
        keystore_store::import_keystore_reporting(
            directory,
            destination,
            password,
            key,
            checksum_engine,
            force_duplicate,
            false,
            entropy,
            warning_sink,
        )
    }

    fn list_keystores(&mut self, directory: &Path) -> Result<ListReport, StoreError> {
        keystore_store::list_keystores(directory)
    }

    fn update_keystore(
        &mut self,
        directory: &Path,
        address: &str,
        old_password: &str,
        new_password: &str,
        key_engine: CryptoEngine,
        checksum_engine: CryptoEngine,
        entropy: &mut OperationEntropy,
        warning_sink: &mut dyn FnMut(&StoreWarning),
    ) -> Result<StoredKeystore, StoreError> {
        keystore_store::update_keystore_reporting(
            directory,
            address,
            old_password,
            new_password,
            key_engine,
            checksum_engine,
            entropy,
            warning_sink,
        )
    }
}

pub fn dispatch(
    command: KeystoreCommand,
    context: &mut CommandContext<'_>,
    services: &mut dyn KeystoreServices,
) -> Result<CommandOutput, ToolkitError> {
    match command {
        KeystoreCommand::New(args) => dispatch_new(args, context, services),
        KeystoreCommand::Import(args) => dispatch_import(args, context, services),
        KeystoreCommand::List(args) => dispatch_list(args, context, services),
        KeystoreCommand::Update(args) => dispatch_update(args, context, services),
    }
}

fn dispatch_new(
    args: NewKeystoreArgs,
    context: &mut CommandContext<'_>,
    services: &mut dyn KeystoreServices,
) -> Result<CommandOutput, ToolkitError> {
    let password = read_text_secret(
        context,
        SecretPrompt::NewPassword,
        args.password_file.as_deref(),
    )?;
    require_password(&password, false)?;
    let engine = engine(args.sm2);
    let key = generated_key(context.keys, engine)?;
    let address = key_address(&key, engine);
    let file_name = utc_filename(context.clock.now_utc(), &address);
    let destination = args.keystore_dir.join(&file_name);
    let mut entropy = OperationEntropy::from_provider(context.keys)?;
    let mut warnings = Vec::new();
    let result = services.new_keystore(
        &destination,
        &password,
        &key,
        engine,
        &mut entropy,
        &mut |warning| warnings.push(warning.clone()),
    );
    let stored = service_result(result, &warnings)?;
    render_stored(
        "Your new key was generated",
        stored,
        args.json,
        warnings,
    )
}

fn dispatch_import(
    args: ImportKeystoreArgs,
    context: &mut CommandContext<'_>,
    services: &mut dyn KeystoreServices,
) -> Result<CommandOutput, ToolkitError> {
    let engine = engine(args.sm2);
    let key_bytes = context.io.read_secret(
        SecretPrompt::PrivateKey,
        args.key_file
            .as_deref()
            .map_or(SecretSource::Tty, SecretSource::File),
    )?;
    let key = parse_private_key(&key_bytes, engine)?;
    let address = key_address(&key, engine);
    let file_name = utc_filename(context.clock.now_utc(), &address);
    let destination = args.keystore_dir.join(&file_name);
    let password = read_text_secret(
        context,
        SecretPrompt::ImportPassword,
        args.password_file.as_deref(),
    )?;
    require_password(&password, false)?;
    let mut entropy = OperationEntropy::from_provider(context.keys)?;
    let mut warnings = Vec::new();
    let result = services.import_keystore(
        &args.keystore_dir,
        &destination,
        &password,
        &key,
        engine,
        args.force,
        &mut entropy,
        &mut |warning| warnings.push(warning.clone()),
    );
    let stored = service_result(result, &warnings)?;
    render_stored(
        "Imported keystore successfully",
        stored,
        args.json,
        warnings,
    )
}

fn dispatch_list(
    args: ListKeystoreArgs,
    context: &CommandContext<'_>,
    services: &mut dyn KeystoreServices,
) -> Result<CommandOutput, ToolkitError> {
    let report = services
        .list_keystores(&args.keystore_dir)
        .map_err(map_store_error)?;
    let stderr = render_warnings(&report.warnings);
    let stdout = if args.json {
        let entries = report
            .keystores
            .iter()
            .map(|entry| {
                serde_json::json!({
                    "address": entry.address,
                    "file": file_name(&entry.path),
                })
            })
            .collect::<Vec<_>>();
        json_line(serde_json::json!({ "keystores": entries }))?
    } else if report.keystores.is_empty() {
        format!(
            "No keystores found in: {}\n",
            absolute_display(&args.keystore_dir, context.cwd)
        )
        .into_bytes()
    } else {
        let mut output = String::new();
        for entry in report.keystores {
            output.push_str(&format!(
                "{:<45}{}\n",
                entry.address,
                file_name(&entry.path)
            ));
        }
        output.into_bytes()
    };
    Ok(CommandOutput {
        stdout,
        stderr,
        logical_exit: 0,
    })
}

fn dispatch_update(
    args: UpdateKeystoreArgs,
    context: &mut CommandContext<'_>,
    services: &mut dyn KeystoreServices,
) -> Result<CommandOutput, ToolkitError> {
    let (old_password, new_password) = if let Some(path) = args.password_file.as_deref() {
        let (old, new) = read_update_password_file(path).map_err(|error| {
            categorized(ErrorCategory::KeystoreInput, error.to_string())
        })?;
        (Zeroizing::new(old), Zeroizing::new(new))
    } else {
        (
            read_text_secret(context, SecretPrompt::OldPassword, None)?,
            read_text_secret(context, SecretPrompt::UpdatedPassword, None)?,
        )
    };
    require_password(&new_password, true)?;
    let engine = engine(args.sm2);
    let mut entropy = OperationEntropy::from_provider(context.keys)?;
    let mut warnings = Vec::new();
    let result = services.update_keystore(
        &args.keystore_dir,
        &args.address,
        &old_password,
        &new_password,
        engine,
        engine,
        &mut entropy,
        &mut |warning| warnings.push(warning.clone()),
    );
    let stderr = render_warnings(&warnings);
    let stored = match result {
        Err(error @ StoreError::Keystore(_)) => {
            return Err(decryption_error(error, &old_password, &warnings));
        }
        other => service_result(other, &warnings)?,
    };
    let address = stored.wallet.address.clone().unwrap_or(args.address);
    let stdout = if args.json {
        json_line(serde_json::json!({
            "address": address,
            "file": file_name(&stored.path),
            "status": "updated",
        }))?
    } else {
        format!("Password updated for: {address}\n").into_bytes()
    };
    Ok(CommandOutput {
        stdout,
        stderr,
        logical_exit: 0,
    })
}

fn render_stored(
    heading: &str,
    stored: StoredKeystore,
    json: bool,
    warnings: Vec<StoreWarning>,
) -> Result<CommandOutput, ToolkitError> {
    let address = stored.wallet.address.unwrap_or_default();
    let file = file_name(&stored.path);
    let stdout = if json {
        json_line(serde_json::json!({ "address": address, "file": file }))?
    } else {
        security_tips(heading, &address, &stored.path).into_bytes()
    };
    Ok(CommandOutput {
        stdout,
        stderr: render_warnings(&warnings),
        logical_exit: 0,
    })
}

fn read_text_secret(
    context: &mut CommandContext<'_>,
    prompt: SecretPrompt,
    file: Option<&Path>,
) -> Result<Zeroizing<String>, ToolkitError> {
    let bytes = context.io.read_secret(
        prompt,
        file.map_or(SecretSource::Tty, SecretSource::File),
    )?;
    Ok(Zeroizing::new(String::from_utf8_lossy(&bytes).into_owned()))
}

pub fn parse_private_key(
    input: &[u8],
    engine: CryptoEngine,
) -> Result<PrivateKey, ToolkitError> {
    let text = String::from_utf8_lossy(input);
    let trimmed = text.trim();
    let hex = trimmed
        .strip_prefix("0x")
        .or_else(|| trimmed.strip_prefix("0X"))
        .unwrap_or(trimmed);
    if hex.len() != 64 || !hex.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(ToolkitError::Parity {
            code: 1,
            stdout: Vec::new(),
            stderr: b"Invalid private key: must be 64 hex characters.\n".to_vec(),
        });
    }
    let mut decoded = Zeroizing::new([0u8; 32]);
    for (index, pair) in hex.as_bytes().chunks_exact(2).enumerate() {
        decoded[index] = (hex_nibble(pair[0]) << 4) | hex_nibble(pair[1]);
    }
    PrivateKey::from_bytes(engine, decoded.as_ref()).map_err(|_| ToolkitError::Parity {
        code: 1,
        stdout: Vec::new(),
        stderr: b"Invalid private key.\n".to_vec(),
    })
}

pub fn utc_filename(now: OffsetDateTime, address: &str) -> String {
    let now = now.to_offset(UtcOffset::UTC);
    format!(
        "UTC--{:04}-{:02}-{:02}T{:02}-{:02}-{:02}.{}Z--{address}.json",
        now.year(),
        u8::from(now.month()),
        now.day(),
        now.hour(),
        now.minute(),
        now.second(),
        now.nanosecond(),
    )
}

pub fn warning_line(warning: &StoreWarning) -> String {
    let (prefix, path) = match warning {
        StoreWarning::SkippedSymlink { path } => {
            ("Warning: skipping symbolic link: ", path)
        }
        StoreWarning::SkippedNonRegular { path } => {
            ("Warning: skipping non-regular file: ", path)
        }
        StoreWarning::SkippedOversized { path } => {
            ("Warning: skipping oversized file (>8192 bytes): ", path)
        }
        StoreWarning::SkippedUnreadable { path }
        | StoreWarning::SkippedInvalidJson { path } => {
            ("Warning: skipping unreadable file: ", path)
        }
        StoreWarning::DirectLoadFollowedSymlink { path }
        | StoreWarning::WindowsPermissionsBestEffort { path } => {
            ("Warning: skipping unreadable file: ", path)
        }
    };
    format!("{prefix}{}\n", file_name(path))
}

fn render_warnings(warnings: &[StoreWarning]) -> Vec<u8> {
    warnings
        .iter()
        .map(warning_line)
        .collect::<String>()
        .into_bytes()
}

fn security_tips(heading: &str, address: &str, path: &Path) -> String {
    format!(
        "{heading}\n\nPublic address of the key:   {address}\nPath of the secret key file: {}\n\n- You can share your public address with anyone. Others need it to interact with you.\n- You must NEVER share the secret key with anyone! The key controls access to your funds!\n- You must BACKUP your key file! Without the key, it's impossible to access account funds!\n- You must REMEMBER your password! Without the password, it's impossible to decrypt the key!\n",
        path.display()
    )
}

fn json_line(value: serde_json::Value) -> Result<Vec<u8>, ToolkitError> {
    serde_json::to_vec(&value)
        .map(|mut bytes| {
            bytes.push(b'\n');
            bytes
        })
        .map_err(|error| categorized(ErrorCategory::KeystoreInput, error.to_string()))
}

fn generated_key(
    provider: &mut dyn KeyProvider,
    engine: CryptoEngine,
) -> Result<PrivateKey, ToolkitError> {
    let bytes = provider.generate_private_key(engine)?;
    PrivateKey::from_bytes(engine, bytes.as_ref()).map_err(|_| {
        categorized(
            ErrorCategory::InvalidPrivateKey,
            "key provider returned an invalid private key",
        )
    })
}

fn key_address(key: &PrivateKey, engine: CryptoEngine) -> String {
    encode_address_base58check(engine, &derive_address(&key.public_key()))
}

fn engine(sm2: bool) -> CryptoEngine {
    if sm2 {
        CryptoEngine::Sm2
    } else {
        CryptoEngine::Secp256k1
    }
}

fn file_name(path: &Path) -> String {
    path.file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_else(|| path.to_string_lossy().into_owned())
}

fn absolute_display(path: &Path, cwd: &Path) -> String {
    if path.is_absolute() {
        path.display().to_string()
    } else {
        cwd.join(path).display().to_string()
    }
}

fn hex_nibble(byte: u8) -> u8 {
    match byte {
        b'0'..=b'9' => byte - b'0',
        b'a'..=b'f' => byte - b'a' + 10,
        b'A'..=b'F' => byte - b'A' + 10,
        _ => unreachable!("validated hexadecimal input"),
    }
}

fn map_store_error(error: StoreError) -> ToolkitError {
    let category = match error {
        StoreError::InsecurePermissions { .. }
        | StoreError::WrongOwner { .. }
        | StoreError::InsecureDirectory { .. }
        | StoreError::SymlinkRefused(_)
        | StoreError::ParentSymlink(_) => ErrorCategory::KeystoreSecurity,
        StoreError::AddressNotFound(_) => ErrorCategory::NotFound,
        _ => ErrorCategory::KeystoreInput,
    };
    categorized(category, error.to_string())
}

fn decryption_error(error: StoreError, old_password: &str, warnings: &[StoreWarning]) -> ToolkitError {
    let mut stderr = render_warnings(warnings);
    stderr.extend_from_slice(format!("Decryption failed: {error}\n").as_bytes());
    if old_password.chars().any(char::is_whitespace) {
        stderr.extend_from_slice(b"Tip: if this keystore was created with `FullNode.jar --keystore-factory` in non-TTY mode, the legacy code truncated the password at the first whitespace. Try re-running with only the first whitespace-separated word of your passphrase as the current password; you can then choose the full phrase as the new password.\n");
    }
    ToolkitError::Parity {
        code: 1,
        stdout: Vec::new(),
        stderr,
    }
}

fn service_result(
    result: Result<StoredKeystore, StoreError>,
    warnings: &[StoreWarning],
) -> Result<StoredKeystore, ToolkitError> {
    match result {
        Ok(stored) => Ok(stored),
        Err(error) if warnings.is_empty() => Err(map_store_error(error)),
        Err(error) => {
            let mapped = map_store_error(error);
            let mut stderr = render_warnings(warnings);
            match mapped {
                ToolkitError::Parity {
                    code,
                    stdout,
                    stderr: mut error_stderr,
                } => {
                    stderr.append(&mut error_stderr);
                    Err(ToolkitError::Parity { code, stdout, stderr })
                }
                ToolkitError::Categorized { category, detail } => {
                    stderr.extend_from_slice(
                        format!("error[{}]: {detail}\n", category_name(&category)).as_bytes(),
                    );
                    Err(ToolkitError::Parity {
                        code: 1,
                        stdout: Vec::new(),
                        stderr,
                    })
                }
            }
        }
    }
}

fn category_name(category: &ErrorCategory) -> &'static str {
    match category {
        ErrorCategory::KeystoreSecurity => "keystore_security",
        ErrorCategory::NotFound => "not_found",
        ErrorCategory::KeystoreInput => "keystore_input",
        _ => unreachable!("keystore service maps only keystore categories"),
    }
}

fn require_password(password: &str, update: bool) -> Result<(), ToolkitError> {
    if password_valid(Some(password)) {
        return Ok(());
    }
    let stderr = if update {
        b"Invalid new password: must be at least 6 characters.\n".to_vec()
    } else {
        b"Invalid password: must be at least 6 characters.\n".to_vec()
    };
    Err(ToolkitError::Parity { code: 1, stdout: Vec::new(), stderr })
}

fn categorized(category: ErrorCategory, detail: impl Into<String>) -> ToolkitError {
    ToolkitError::Categorized {
        category,
        detail: detail.into(),
    }
}

pub struct OperationEntropy {
    seed: Zeroizing<[u8; ENTROPY_SEED_BYTES]>,
    block: [u8; 32],
    block_offset: usize,
    counter: u64,
}

impl OperationEntropy {
    pub fn from_provider(provider: &mut dyn KeyProvider) -> Result<Self, ToolkitError> {
        let mut seed = Zeroizing::new([0u8; ENTROPY_SEED_BYTES]);
        provider.fill_entropy(seed.as_mut())?;
        Ok(Self { seed, block: [0; 32], block_offset: 32, counter: 0 })
    }

    fn refill(&mut self) {
        let mut hash = Sha256::new();
        hash.update(b"tron-toolkit/keystore-entropy-v1");
        hash.update(self.seed.as_ref());
        hash.update(self.counter.to_be_bytes());
        self.block.copy_from_slice(&hash.finalize());
        self.counter = self.counter.wrapping_add(1);
        self.block_offset = 0;
    }
}

impl Drop for OperationEntropy {
    fn drop(&mut self) { self.block.zeroize(); }
}

impl RngCore for OperationEntropy {
    fn next_u32(&mut self) -> u32 {
        let mut bytes = [0u8; 4];
        self.fill_bytes(&mut bytes);
        u32::from_le_bytes(bytes)
    }

    fn next_u64(&mut self) -> u64 {
        let mut bytes = [0u8; 8];
        self.fill_bytes(&mut bytes);
        u64::from_le_bytes(bytes)
    }

    fn fill_bytes(&mut self, mut destination: &mut [u8]) {
        while !destination.is_empty() {
            if self.block_offset == self.block.len() { self.refill(); }
            let count = destination.len().min(self.block.len() - self.block_offset);
            let (head, rest) = destination.split_at_mut(count);
            head.copy_from_slice(&self.block[self.block_offset..self.block_offset + count]);
            self.block[self.block_offset..self.block_offset + count].zeroize();
            self.block_offset += count;
            destination = rest;
        }
    }

    fn try_fill_bytes(&mut self, destination: &mut [u8]) -> Result<(), RandomError> {
        self.fill_bytes(destination);
        Ok(())
    }
}

impl CryptoRng for OperationEntropy {}
